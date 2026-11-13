/* SPDX-License-Identifier: GPL-2.0-or-later */
/* kpm_ptr_scan.c - 指针扫描与多级指针链 */
#include <ktypes.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <baselib.h>
#include <linux/string.h>
#include "LH_comm.h"
#include "LH_ptr_scan.h"
#include "LH_mem_scan.h"
#include "LH_syms.h"
#include "LH_mem_rw.h"
#include "LH_proc.h"
#include "LH_log.h"
#include "LH_utils.h"  /* kpm_spinlock_t 等 */

/* 当前指针扫描会话状态 */
static struct {
    int      active;
    pid_t    pid;
    kpm_ptr_result_t *results;
    int      result_count;
    int      result_capacity;
    uint64_t target_addr;
    uint64_t range;
} g_pscan;

/* ===== 会话互斥 =====
 * 与 kpm_mem_scan.c 相同的 busy 标志模式：
 *   - 锁内仅做 busy 检查/置位，禁止睡眠；
 *   - 扫描/拷贝等慢操作在锁外执行（busy 期间其他调用被拒绝）；
 *   - 并发进入返回 -KPM_E_BUSY，客户端重试。
 */
static kpm_spinlock_t g_pscan_lock = KPM_SPINLOCK_INIT;
static volatile int g_pscan_busy = 0;

static int pscan_enter(void)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_pscan_lock);
    if (g_pscan_busy) {
        kpm_spin_unlock_irqrestore(&g_pscan_lock, flags);
        return -1;
    }
    g_pscan_busy = 1;
    kpm_spin_unlock_irqrestore(&g_pscan_lock, flags);
    return 0;
}

static void pscan_leave(void)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_pscan_lock);
    g_pscan_busy = 0;
    kpm_spin_unlock_irqrestore(&g_pscan_lock, flags);
}

/* 无锁清理（调用方必须已取得 busy） */
static void pscan_clear_locked(void)
{
    if (g_pscan.results) {
        kf_vfree(g_pscan.results);
        g_pscan.results = NULL;
    }
    g_pscan.result_count = 0;
    g_pscan.result_capacity = 0;
    g_pscan.active = 0;
    g_pscan.pid = 0;
    g_pscan.target_addr = 0;
    g_pscan.range = 0;
}

/* 单次拷贝结果的最大条数（防止拷贝越界） */
#define KPM_PTR_SCAN_COPY_MAX 1024

/* 页缓冲区（用于批量读取，避免逐 8 字节调用 kpm_mem_rw_process） */
#define KPM_PTR_PAGE_BUF_SIZE 32768

long kpm_ptr_scan_init(void)
{
    g_pscan.active = 0;
    g_pscan.results = NULL;
    g_pscan.result_count = 0;
    g_pscan.result_capacity = 0;
    g_pscan.pid = 0;
    g_pscan.target_addr = 0;
    g_pscan.range = 0;
    g_pscan_busy = 0;   /* 锁静态初始化，busy 复位 */
    return 0;
}

void kpm_ptr_scan_exit(void)
{
    kpm_ptr_scan_clear();
}

/* 内部：追加一个结果，自动扩容 */
static int ptr_scan_append(uint64_t addr, uint64_t value)
{
    if (g_pscan.result_count >= g_pscan.result_capacity) {
        int new_cap = g_pscan.result_capacity * 2;
        kpm_ptr_result_t *new_buf;

        if (new_cap > KPM_PTR_SCAN_MAX_RESULTS)
            new_cap = KPM_PTR_SCAN_MAX_RESULTS;
        if (new_cap <= g_pscan.result_capacity)
            return -1;  /* 已达上限 */

        new_buf = kf_vmalloc(new_cap * sizeof(kpm_ptr_result_t));
        if (!new_buf) return -1;

        lib_memcpy(new_buf, g_pscan.results,
                   g_pscan.result_count * sizeof(kpm_ptr_result_t));
        kf_vfree(g_pscan.results);
        g_pscan.results = new_buf;
        g_pscan.result_capacity = new_cap;
    }

    g_pscan.results[g_pscan.result_count].addr = addr;
    g_pscan.results[g_pscan.result_count].value = value;
    g_pscan.result_count++;
    return 0;
}

/* 内部：检查 ptr_val 是否在 [target_min, target_max] 范围内
 * （target_addr - range 下溢保护） */
static int ptr_in_range(uint64_t ptr_val, uint64_t target_addr, uint64_t range)
{
    uint64_t lo, hi;
    if (range >= target_addr) {
        /* 下溢保护：range >= target_addr 时，下界为 0 */
        lo = 0;
    } else {
        lo = target_addr - range;
    }
    hi = target_addr + range;  /* uint64 加法，range 不大时不会溢出 */
    return (ptr_val >= lo && ptr_val <= hi);
}

long kpm_ptr_scan_start(pid_t pid, uint64_t target_addr, uint64_t range)
{
    kpm_map_entry_t *regions = NULL;
    int region_count, i;
    kpm_ptr_result_t *new_results;
    int capacity = 4096;
    uint8_t *page_buf = NULL;
    long page_ret;
    kpm_walk_ctx_t walk_ctx;
    void *ps_pid = NULL, *ps_task = NULL, *ps_mm = NULL;
    int page_shift;

    /* 会话互斥：拒绝与其他扫描操作并发（防 UAF） */
    if (pscan_enter() < 0)
        return -KPM_E_BUSY;

    /* 清除前一会话 */
    pscan_clear_locked();

    /* 用户页参数（T0SZ/TG0 探测） */
    kpm_detect_user_va_params();
    page_shift = g_kpm_user_page_shift;

    /* 使用 kpm_proc_maps_kernel 内核原生 VMA 遍历：所有操作纯内核完成，
     * 无任何用户态接口参与。循环分页全量拉取 VMA（步长 KPM_SCAN_MAPS_PAGE，
     * 上限 KPM_MEM_SCAN_MAX_REGIONS）。 */
    regions = (kpm_map_entry_t *)kf_vmalloc(KPM_MEM_SCAN_MAX_REGIONS *
                                            sizeof(kpm_map_entry_t));
    if (!regions) {
        pscan_leave();
        return -KPM_E_NOMEM;
    }

    region_count = 0;
    for (i = 0; i < KPM_MEM_SCAN_MAX_REGIONS; i += KPM_SCAN_MAPS_PAGE) {
        int n = kpm_proc_maps_kernel(pid, regions + region_count,
                                     KPM_SCAN_MAPS_PAGE, region_count, 0);
        if (n <= 0)
            break;
        region_count += n;
        if (n < KPM_SCAN_MAPS_PAGE)
            break;
        if (region_count >= KPM_MEM_SCAN_MAX_REGIONS)
            break;
    }
    if (region_count <= 0) {
        kf_vfree(regions);
        pscan_leave();
        return -KPM_E_NOTFOUND;
    }

    /* 分配结果缓冲区 */
    new_results = kf_vmalloc(capacity * sizeof(kpm_ptr_result_t));
    if (!new_results) {
        kf_vfree(regions);
        pscan_leave();
        return -KPM_E_NOMEM;
    }

    /* 页批量读取缓冲区（KPM_PTR_PAGE_BUF_SIZE），按页批量读取并扫描，
     * 避免逐 8 字节调用完整页表遍历。 */
    page_buf = (uint8_t *)kf_vmalloc(KPM_PTR_PAGE_BUF_SIZE);
    if (!page_buf) {
        kf_vfree(new_results);
        kf_vfree(regions);
        pscan_leave();
        return -KPM_E_NOMEM;
    }

    /* 会话级 mm/pgd 缓存 —— 避免每次批量读取重复 find_get_pid/get_task_mm，
     * 读取走 kpm_mem_read_batch（线性映射，消除每页 vmap/vunmap +
     * Device 逐字节读）。 */
    {
        uint64_t pgd_va = 0;
        int sret = kpm_mem_open_scan_session(pid, &ps_pid, &ps_task,
                                              &ps_mm, &pgd_va);
        if (sret < 0) {
            kf_vfree(page_buf);
            kf_vfree(new_results);
            kf_vfree(regions);
            pscan_leave();
            return sret;
        }
        memset(&walk_ctx, 0, sizeof(walk_ctx));
        walk_ctx.pgd_va = pgd_va;
    }

    g_pscan.results = new_results;
    g_pscan.result_capacity = capacity;
    g_pscan.result_count = 0;
    g_pscan.pid = pid;
    g_pscan.target_addr = target_addr;
    g_pscan.range = range;

    /* 扫描所有可读区域查找指针 */
    for (i = 0; i < region_count; i++) {
        uint64_t region_start = regions[i].start;
        uint64_t region_end = regions[i].end;

        /* 只扫描可读区域 (bit 0 = R) */
        if (!(regions[i].perms & 0x1))
            continue;

        /* 按页批量读取并扫描 */
        {
            uint64_t addr = region_start;
            while (addr < region_end) {
                uint64_t page_end = (addr & ~0x7FFFULL) + KPM_PTR_PAGE_BUF_SIZE;
                int chunk_len;
                int bytes_read;
                int off;
                uint64_t fail_map = 0;

                if (page_end > region_end)
                    page_end = region_end;
                chunk_len = (int)(page_end - addr);

                /* 会话级缓存批量线性读取（PTE 表缓存 + 大页块缓存）：
                 * 块内部分页失败不中断，失败页补零 + fail_map 标记，
                 * 扫描跳过失败页，完整覆盖可读页。 */
                page_ret = kpm_mem_read_batch(&walk_ctx, addr, page_buf,
                                              chunk_len, &fail_map);
                if (page_ret <= 0) {
                    addr = page_end;
                    /* 对齐到下一个 8 字节边界 */
                    addr = (addr + 7) & ~7ULL;
                    continue;
                }
                bytes_read = (int)page_ret;

                /* 在缓冲区中按 8 字节步长扫描指针 */
                for (off = 0; off + 8 <= bytes_read; off += 8) {
                    uint64_t ptr_val;

                    /* 跳过读取失败的页区间（补零数据不参与匹配，防假命中） */
                    if (fail_map & (1ULL << (off >> page_shift))) {
                        off = ((off >> page_shift) + 1) << page_shift;
                        off -= 8;
                        continue;
                    }

                    lib_memcpy(&ptr_val, page_buf + off, 8);

                    if (ptr_in_range(ptr_val, target_addr, range)) {
                        if (ptr_scan_append(addr + off, ptr_val) < 0)
                            goto scan_done;
                    }
                }

                addr = page_end;
                addr = (addr + 7) & ~7ULL;  /* 8 字节对齐 */
            }
        }
    }

scan_done:
    kf_vfree(page_buf);
    kf_vfree(regions);
    if (ps_mm)
        kpm_mem_close_scan_session(ps_pid, ps_task, ps_mm);

    kpm_log("ptrscan: found %d pointers to 0x%llx in pid %d\n",
            g_pscan.result_count, target_addr, pid);
    g_pscan.active = 1;
    pscan_leave();
    return 0;
}

/* 多级指针链扫描：
 *   第 1 级：扫描内存中所有指向 [target ± range] 的指针 P1
 *   第 2 级：读取 *P1 得到 A1，扫描所有指向 A1 的指针 P2
 *   ...
 *   第 depth 级：得到 base_addr（最外层指针地址）
 * 结果存储在 g_pscan.results 中，addr = 最外层指针地址，value = 中间值 */
long kpm_ptr_scan_chain(pid_t pid, uint64_t target_addr, int depth)
{
    uint64_t current_target;
    int level;
    kpm_map_entry_t *regions = NULL;
    kpm_ptr_result_t *new_results = NULL;
    int capacity = 4096;
    uint8_t *page_buf = NULL;
    int region_count, i;
    long page_ret;
    kpm_walk_ctx_t walk_ctx;
    void *ps_pid = NULL, *ps_task = NULL, *ps_mm = NULL;
    int page_shift;

    if (depth < 1 || depth > KPM_PTR_CHAIN_MAX_DEPTH)
        return -KPM_E_INVAL;

    /* 限制 depth=1 时退化为普通单级扫描（走 start 自带互斥，避免重复 enter） */
    if (depth == 1)
        return kpm_ptr_scan_start(pid, target_addr, 0);

    /* 会话互斥：拒绝与其他扫描操作并发（防 UAF） */
    if (pscan_enter() < 0)
        return -KPM_E_BUSY;

    pscan_clear_locked();

    /* 准备区域列表（VMA 遍历，无文件 IO），循环分页全量拉取 */
    regions = (kpm_map_entry_t *)kf_vmalloc(KPM_MEM_SCAN_MAX_REGIONS *
                                            sizeof(kpm_map_entry_t));
    if (!regions) {
        pscan_leave();
        return -KPM_E_NOMEM;
    }
    region_count = 0;
    for (i = 0; i < KPM_MEM_SCAN_MAX_REGIONS; i += KPM_SCAN_MAPS_PAGE) {
        int n = kpm_proc_maps_kernel(pid, regions + region_count,
                                     KPM_SCAN_MAPS_PAGE, region_count, 0);
        if (n <= 0)
            break;
        region_count += n;
        if (n < KPM_SCAN_MAPS_PAGE)
            break;
        if (region_count >= KPM_MEM_SCAN_MAX_REGIONS)
            break;
    }
    if (region_count <= 0) {
        kf_vfree(regions);
        pscan_leave();
        return -KPM_E_NOTFOUND;
    }

    new_results = kf_vmalloc(capacity * sizeof(kpm_ptr_result_t));
    if (!new_results) {
        kf_vfree(regions);
        pscan_leave();
        return -KPM_E_NOMEM;
    }

    page_buf = (uint8_t *)kf_vmalloc(KPM_PTR_PAGE_BUF_SIZE);
    if (!page_buf) {
        kf_vfree(new_results);
        kf_vfree(regions);
        pscan_leave();
        return -KPM_E_NOMEM;
    }

    /* 会话级 mm/pgd 缓存（多级链跨 level 复用一次进程查找） */
    {
        uint64_t pgd_va = 0;
        int sret = kpm_mem_open_scan_session(pid, &ps_pid, &ps_task,
                                              &ps_mm, &pgd_va);
        if (sret < 0) {
            kf_vfree(page_buf);
            kf_vfree(new_results);
            kf_vfree(regions);
            pscan_leave();
            return sret;
        }
        memset(&walk_ctx, 0, sizeof(walk_ctx));
        walk_ctx.pgd_va = pgd_va;
    }
    kpm_detect_user_va_params();
    page_shift = g_kpm_user_page_shift;

    g_pscan.results = new_results;
    g_pscan.result_capacity = capacity;
    g_pscan.result_count = 0;
    g_pscan.pid = pid;
    g_pscan.target_addr = target_addr;
    g_pscan.range = 0;

    /* 从最内层（target_addr）向外逐级扫描：
     * level=1: 找指向 target_addr 的指针 P1（保存 addr=P1_addr, value=target_addr）
     * level=2: 读取 *P1_addr 得到 A1，找指向 A1 的指针 P2
     * ...
     * 最终 results 中每项 addr = 最外层指针地址，value = 该指针指向的值 */
    current_target = target_addr;
    for (level = 1; level <= depth; level++) {
        int found_at_this_level = 0;
        int prev_count = g_pscan.result_count;

        /* 清空上一级结果（保留最外层） */
        if (level > 1) {
            g_pscan.result_count = 0;
        }

        for (i = 0; i < region_count; i++) {
            uint64_t addr = regions[i].start;
            uint64_t region_end = regions[i].end;

            if (!(regions[i].perms & 0x1))
                continue;

            while (addr < region_end) {
                uint64_t page_end = (addr & ~0x7FFFULL) + KPM_PTR_PAGE_BUF_SIZE;
                int chunk_len;
                int bytes_read, off;
                uint64_t fail_map = 0;

                if (page_end > region_end) page_end = region_end;
                chunk_len = (int)(page_end - addr);

                /* 会话级缓存批量线性读取（失败页补零+标记） */
                page_ret = kpm_mem_read_batch(&walk_ctx, addr, page_buf,
                                              chunk_len, &fail_map);
                if (page_ret <= 0) {
                    addr = (page_end + 7) & ~7ULL;
                    continue;
                }
                bytes_read = (int)page_ret;

                for (off = 0; off + 8 <= bytes_read; off += 8) {
                    uint64_t ptr_val;

                    /* 跳过读取失败的页区间（补零数据不参与匹配，防假命中） */
                    if (fail_map & (1ULL << (off >> page_shift))) {
                        off = ((off >> page_shift) + 1) << page_shift;
                        off -= 8;
                        continue;
                    }

                    lib_memcpy(&ptr_val, page_buf + off, 8);

                    /* 精确匹配当前层级目标（range=0） */
                    if (ptr_val == current_target) {
                        if (ptr_scan_append(addr + off, ptr_val) < 0)
                            goto chain_done;
                        found_at_this_level = 1;
                    }
                }
                addr = (page_end + 7) & ~7ULL;
            }
        }

        if (!found_at_this_level) {
            /* 本级未找到指针，链断裂 */
            kpm_log("ptrscan_chain: no pointer found at level %d "
                    "(target=0x%llx)\n", level, current_target);
            break;
        }

        /* 下一级目标 = 本级第一个结果的地址（即指向 current_target 的指针地址）。
         * 多级链中，外层指针的值应等于内层指针的地址。 */
        if (level < depth && g_pscan.result_count > 0) {
            current_target = g_pscan.results[0].addr;
        }
        (void)prev_count;
    }

chain_done:
    kf_vfree(page_buf);
    kf_vfree(regions);
    if (ps_mm)
        kpm_mem_close_scan_session(ps_pid, ps_task, ps_mm);

    kpm_log("ptrscan_chain: depth=%d found %d chain roots to 0x%llx in pid %d\n",
            depth, g_pscan.result_count, target_addr, pid);
    g_pscan.active = 1;
    pscan_leave();
    return 0;
}

long kpm_ptr_scan_copy_results(kpm_ptr_result_t *user_buf,
                               int max_count, int offset)
{
    int to_copy;
    long ret;

    if (!user_buf || max_count <= 0)
        return -KPM_E_INVAL;
    /* max_count 硬上限 */
    if (max_count > KPM_PTR_SCAN_COPY_MAX) max_count = KPM_PTR_SCAN_COPY_MAX;
    if (offset < 0) offset = 0;

    if (pscan_enter() < 0)
        return -KPM_E_BUSY;

    if (!g_pscan.active || !g_pscan.results) {
        pscan_leave();
        return -KPM_E_INVAL;
    }

    if (offset >= g_pscan.result_count) {
        pscan_leave();
        return 0;
    }

    to_copy = g_pscan.result_count - offset;
    if (to_copy > max_count)
        to_copy = max_count;

    ret = 0;
    if (kf_copy_to_user(user_buf, &g_pscan.results[offset],
                        to_copy * sizeof(kpm_ptr_result_t)))
        ret = -KPM_E_FAULT;
    else
        ret = to_copy;

    pscan_leave();
    return ret;
}

/* UDP 通道传入 resp_data（内核空间 g_resp_buf 的一部分），
 * kf_copy_to_user 对内核地址 access_ok 失败，导致 UDP 客户端无法获取结果。
 * 此函数使用 lib_memcpy 直接拷贝，仅供内核态调用方使用（如 UDP 处理）。 */
long kpm_ptr_scan_copy_results_kernel(kpm_ptr_result_t *kbuf,
                                      int max_count, int offset)
{
    int to_copy;
    long ret;

    if (!kbuf || max_count <= 0)
        return -KPM_E_INVAL;
    /* max_count 硬上限（UDP 层检查被绕过时的最终防线） */
    if (max_count > KPM_PTR_SCAN_COPY_MAX) max_count = KPM_PTR_SCAN_COPY_MAX;
    if (offset < 0) offset = 0;

    if (pscan_enter() < 0)
        return -KPM_E_BUSY;

    if (!g_pscan.active || !g_pscan.results) {
        pscan_leave();
        return -KPM_E_INVAL;
    }

    if (offset >= g_pscan.result_count) {
        pscan_leave();
        return 0;
    }

    to_copy = g_pscan.result_count - offset;
    if (to_copy > max_count)
        to_copy = max_count;

    lib_memcpy(kbuf, &g_pscan.results[offset],
               (size_t)to_copy * sizeof(kpm_ptr_result_t));
    ret = to_copy;

    pscan_leave();
    return ret;
}

long kpm_ptr_scan_clear(void)
{
    if (pscan_enter() < 0)
        return -KPM_E_BUSY;
    pscan_clear_locked();
    pscan_leave();
    return 0;
}
