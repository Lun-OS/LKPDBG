/* SPDX-License-Identifier: GPL-2.0-or-later */
/* kpm_mem_scan.c - 进程内存扫描器 */
#include <ktypes.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <baselib.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/string.h>
#include "LH_comm.h"
#include "LH_mem_scan.h"
#include "LH_syms.h"
#include "LH_mem_rw.h"
#include "LH_proc.h"
#include "LH_log.h"
#include "LH_utils.h"  /* kpm_spinlock_t 等 */

/* Current scan session state */
static struct {
    int      active;
    pid_t    pid;
    kpm_scan_result_t *results;
    int      result_count;
    int      result_capacity;
    /* regions 动态分配（上限 KPM_MEM_SCAN_MAX_REGIONS），支持大进程全量扫描。
     * 由 scan_clear_locked() 统一释放，scan_start() 内分配。 */
    kpm_mem_region_t *regions;
    int      region_count;
    uint64_t range;     /* for KPM_SCAN_MODE_RANGE: value in [value, value+range] */
    /* 会话级 mm/pgd 缓存：scan_start 一次性获取，scan_clear 释放，
     * 避免每次批量读取重复 find_get_pid → get_task_mm → read_mm_pgd 全套流程。 */
    void    *cached_pid_struct;
    void    *cached_task;
    void    *cached_mm;
    uint64_t cached_pgd_va;
    /* 结果缓冲满（KPM_MEM_SCAN_MAX_RESULTS）后置 truncated=1 并继续扫描
     * 剩余区域（仅统计）。客户端通过 KPM_CMD_MEM_SCAN_STATUS 感知"结果被截断"。 */
    int      truncated;
    uint64_t scanned_bytes;   /* 已扫描字节数（含失败页，失败页计为跳过） */
    uint64_t total_bytes;     /* 全部区域字节总数（进度 = scanned/total） */
    uint32_t failed_pages;    /* walk/读取失败页数（跳过，不产生假命中） */
    /* swap/zram 换出页数（read_batch2 的 swap_map 统计）。
     * 换出页 = 失败页中识别出的 swap 条目，客户端可 recover_swap 补读。 */
    uint32_t swap_pages;
    /* 内核线性映射扫描模式（KPM_CMD_MEM_SCAN_KERNEL_START）。
     * kernel_mode=1 时不拉 VMA/不开进程会话，直接 copy_from_kernel_nofault
     * 扫描 [kernel_start, kernel_start+range)。 */
    int      kernel_mode;
    uint64_t kernel_start;
    /* 卸载中止标志。kpm_mem_scan_abort() 置位，扫描主循环每 256KB 块检查后
     * 提前退出（返回部分结果），防 64GB 大范围扫描在 UDP workqueue 串行执行时
     * 阻塞卸载（flush_workqueue 等扫描完成导致卸载卡死）。
     * volatile + dmb 屏障（项目无 linux atomic 头，与 g_injecting 同模式）。 */
    volatile int cancel;
    /* 长 AOB 特征（>8B，KPM_CMD_MEM_SCAN_AOB_START）。
     * aob_len>0 时扫描用 aob_pattern 逐字节匹配（支持 mask 通配），
     * 否则用 8B value 打包路径。aob_mask[i]==0 表示第 i 字节为通配符（任意字节）。 */
    uint8_t  aob_pattern[KPM_SCAN_AOB_MAX];
    uint8_t  aob_mask[KPM_SCAN_AOB_MAX];
    int      aob_len;
    /* 会话级 walk 上下文：FirstScan 主循环跨 256KB 块保持 PTE 表缓存 + 大页块缓存，
     * 同 PTE 表（2MB）内无需重走 PGD/PUD/PMD；大页块内物理连续整块读。
     * scan_clear 时重置，scan_start 时设 pgd_va。 */
    kpm_walk_ctx_t walk_ctx;
} g_scan;

/* ===== 会话互斥 =====
 *
 * busy 标志模式：
 *   - 锁内仅做 busy 检查/置位（微秒级），禁止睡眠。
 *   - 扫描/拷贝等慢操作全部在锁外执行（busy 期间其他调用被拒绝）。
 *   - 并发进入的调用返回 -KPM_E_BUSY，客户端重试即可（调试工具场景）。
 */
static kpm_spinlock_t g_scan_lock = KPM_SPINLOCK_INIT;
static volatile int g_scan_busy = 0;

/* 尝试进入会话操作：成功返回 0 并置 busy，失败（已有会话操作进行中）返回 -1 */
static int scan_enter(void)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_scan_lock);
    if (g_scan_busy) {
        kpm_spin_unlock_irqrestore(&g_scan_lock, flags);
        return -1;
    }
    g_scan_busy = 1;
    kpm_spin_unlock_irqrestore(&g_scan_lock, flags);
    return 0;
}

/* 中止当前扫描（模块卸载时调用）。
 * 置 cancel 标志，扫描主循环检查后提前退出，返回部分结果。
 * 从任意上下文调用安全：volatile 单字节写 + dmb ish 屏障
 * （项目无 linux atomic 头，与 g_injecting 同模式），扫描侧
 * volatile 读检查，无锁无竞态。 */
void kpm_mem_scan_abort(void)
{
    g_scan.cancel = 1;
    asm volatile("dmb ish" ::: "memory");
}

/* 结束会话操作（清除 busy） */
static void scan_leave(void)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_scan_lock);
    g_scan_busy = 0;
    kpm_spin_unlock_irqrestore(&g_scan_lock, flags);
}

/* 无锁清理（调用方必须已取得 busy） */
static void scan_clear_locked(void)
{
    if (g_scan.results) {
        kf_vfree(g_scan.results);
        g_scan.results = NULL;
    }
    if (g_scan.regions) {
        kf_vfree(g_scan.regions);
        g_scan.regions = NULL;
    }
    /* 释放会话级 mm/pgd 缓存引用 */
    if (g_scan.cached_pid_struct || g_scan.cached_task || g_scan.cached_mm) {
        kpm_mem_close_scan_session(g_scan.cached_pid_struct,
                                    g_scan.cached_task,
                                    g_scan.cached_mm);
        g_scan.cached_pid_struct = NULL;
        g_scan.cached_task = NULL;
        g_scan.cached_mm = NULL;
    }
    g_scan.cached_pgd_va = 0;
    g_scan.result_count = 0;
    g_scan.result_capacity = 0;
    g_scan.region_count = 0;
    g_scan.active = 0;
    g_scan.pid = 0;
    g_scan.truncated = 0;
    g_scan.cancel = 0;   /* 新扫描重置中止标志 */
    g_scan.scanned_bytes = 0;
    g_scan.total_bytes = 0;
    g_scan.failed_pages = 0;
    g_scan.swap_pages = 0;
    g_scan.kernel_mode = 0;
    g_scan.kernel_start = 0;
    g_scan.aob_len = 0;   /* 长 AOB 特征失效 */
    memset(&g_scan.walk_ctx, 0, sizeof(g_scan.walk_ctx));
}

/* Get type size in bytes for scanning.
 * For BYTEARRAY/STRING, uses value_len (capped at 8). */
static int kpm_scan_type_size(int value_type, int value_len)
{
    switch (value_type) {
    case KPM_SCAN_TYPE_INT8:    return 1;
    case KPM_SCAN_TYPE_INT16:   return 2;
    case KPM_SCAN_TYPE_INT32:   return 4;
    case KPM_SCAN_TYPE_INT64:   return 8;
    case KPM_SCAN_TYPE_FLOAT:   return 4;
    case KPM_SCAN_TYPE_DOUBLE:  return 8;
    case KPM_SCAN_TYPE_BYTEARRAY:
    case KPM_SCAN_TYPE_STRING:
        if (value_len <= 0 || value_len > 8) return -1;
        return value_len;
    default: return 8;
    }
}

/* Read a value from a kernel buffer at given offset, interpret by type.
 * Used for page-batch scanning: the caller reads a full page via
 * kpm_mem_read_kernel, then this function extracts typed values
 * without per-address vmap overhead.
 * int16/32/64 先 memcpy 到局部变量再解引用，避免未对齐访问。 */
static uint64_t kpm_scan_read_from_buf(const uint8_t *buf, int type)
{
    switch (type) {
    case KPM_SCAN_TYPE_INT8:
        return (uint64_t)(int64_t)(int8_t)buf[0];
    case KPM_SCAN_TYPE_INT16: {
        int16_t v;
        lib_memcpy(&v, buf, 2);
        return (uint64_t)(int64_t)v;
    }
    case KPM_SCAN_TYPE_INT32: {
        int32_t v;
        lib_memcpy(&v, buf, 4);
        return (uint64_t)(int64_t)v;
    }
    case KPM_SCAN_TYPE_FLOAT: {
        /* FLOAT 独立分支，仅 memcpy 4 字节（type_size=4）：
         * 走 8 字节 default 分支会在扫描循环按 4 字节步进时越界读
         * （vmalloc 尾 guard 页无映射 → translation fault）。 */
        uint32_t v;
        lib_memcpy(&v, buf, 4);
        return (uint64_t)v;
    }
    case KPM_SCAN_TYPE_INT64:
    case KPM_SCAN_TYPE_DOUBLE:
    default: {
        uint64_t v;
        lib_memcpy(&v, buf, 8);
        return v;
    }
    }
}

/* Check if bytes at buf match target (for AOB/STRING types).
 * Target bytes are unpacked from uint64 in little-endian order.
 * For STRING: match up to null terminator or value_len, whichever comes first.
 * For BYTEARRAY: exact byte-by-byte comparison over value_len bytes. */
static int kpm_scan_match_bytes(const uint8_t *buf, uint64_t target,
                                int len, int type)
{
    uint8_t target_bytes[8];
    int i;

    if (len <= 0 || len > 8) return 0;

    /* Unpack target uint64 to bytes (little-endian, matching ARM64) */
    for (i = 0; i < len; i++)
        target_bytes[i] = (uint8_t)(target >> (i * 8));

    for (i = 0; i < len; i++) {
        if (buf[i] != target_bytes[i])
            return 0;
        /* STRING: stop at null terminator in target */
        if (type == KPM_SCAN_TYPE_STRING && target_bytes[i] == 0)
            return 1;
    }
    return 1;
}

/* 长 AOB 匹配（支持 >8 字节特征与通配掩码）。
 * 逐字节比较 pattern[0..len)，mask[i]==0 的位跳过（通配符 '?'，CE 风格）。
 * mask 为 NULL 时全精确匹配。 */
static int kpm_scan_match_aob(const uint8_t *buf, const uint8_t *pattern,
                              const uint8_t *mask, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        if (mask && mask[i] == 0)
            continue;   /* 通配符：任意字节 */
        if (buf[i] != pattern[i])
            return 0;
    }
    return 1;
}

/* Check if a value matches the scan criteria.
 * 溢出防护：
 *   - RANGE 用无符号差比较（防 target+range 加法溢出）；
 *   - 差值模式（INCREASED_BY/DECREASED_BY/GE）先取 uint64 无符号差，
 *     再按类型宽度截断为有符号差（type_size 1/2/4/8）——语义与 CE 一致：
 *     i32 从 3 到 -5 差值 = -8（decreased by 8），负值环绕不误判；
 *     8B 类型保持 int64 差。 */
static int kpm_scan_match_value(uint64_t curr_val, uint64_t prev_val,
                                uint64_t target_val, int mode, uint64_t range,
                                int type_size)
{
    /* 差值（uint64 无符号差 → 按类型宽度有符号截断） */
    int64_t diff_signed;
    switch (mode) {
    case KPM_SCAN_MODE_EXACT:
        return (curr_val == target_val) ? 1 : 0;
    case KPM_SCAN_MODE_RANGE:
        /* [target, target+range]：无符号差防 target+range 溢出 */
        return (curr_val >= target_val &&
                (curr_val - target_val) <= range) ? 1 : 0;
    case KPM_SCAN_MODE_CHANGED:
        return (curr_val != prev_val) ? 1 : 0;
    case KPM_SCAN_MODE_UNCHANGED:
        return (curr_val == prev_val) ? 1 : 0;
    case KPM_SCAN_MODE_INCREASED:
        return (curr_val > prev_val) ? 1 : 0;
    case KPM_SCAN_MODE_DECREASED:
        return (curr_val < prev_val) ? 1 : 0;
    case KPM_SCAN_MODE_NOT_EQUAL:
        return (curr_val != target_val) ? 1 : 0;
    case KPM_SCAN_MODE_INCREASED_BY:
    case KPM_SCAN_MODE_DECREASED_BY:
    case KPM_SCAN_MODE_INCREASED_GE:
    case KPM_SCAN_MODE_DECREASED_GE:
        /* 差值按类型宽度截断为有符号（防 2^64 环绕误判） */
        diff_signed = (int64_t)(curr_val - prev_val);
        if (type_size == 1) diff_signed = (int64_t)(int8_t)diff_signed;
        else if (type_size == 2) diff_signed = (int64_t)(int16_t)diff_signed;
        else if (type_size == 4) diff_signed = (int64_t)(int32_t)diff_signed;
        if (mode == KPM_SCAN_MODE_INCREASED_BY)
            return (diff_signed == (int64_t)target_val) ? 1 : 0;
        if (mode == KPM_SCAN_MODE_DECREASED_BY)
            return (-diff_signed == (int64_t)target_val) ? 1 : 0;
        if (mode == KPM_SCAN_MODE_INCREASED_GE)
            return (diff_signed >= (int64_t)target_val) ? 1 : 0;
        return (-diff_signed >= (int64_t)target_val) ? 1 : 0;
    default:
        return 0;
    }
}

long kpm_mem_scan_init(void)
{
    g_scan.active = 0;
    g_scan.results = NULL;
    g_scan.result_count = 0;
    g_scan.result_capacity = 0;
    g_scan.regions = NULL;
    g_scan.region_count = 0;
    g_scan.pid = 0;
    g_scan.cached_pid_struct = NULL;
    g_scan.cached_task = NULL;
    g_scan.cached_mm = NULL;
    g_scan.cached_pgd_va = 0;
    g_scan.truncated = 0;
    g_scan.scanned_bytes = 0;
    g_scan.total_bytes = 0;
    g_scan.failed_pages = 0;
    g_scan_busy = 0;   /* 锁静态初始化，busy 复位 */
    memset(&g_scan.walk_ctx, 0, sizeof(g_scan.walk_ctx));
    return 0;
}

void kpm_mem_scan_exit(void)
{
    kpm_mem_scan_clear();
}

/* 内核线性映射批量读取（copy_from_kernel_nofault，失败页补零 + fail_map 标记，
 * 等价 kpm_mem_read_batch 的容错语义）。线性映射地址物理连续，无需页表遍历；
 * 仅依赖 kf_copy_from_kernel_nofault（5.4+ 稳定 API）。返回 len（始终完整）。
 *
 * 大块快速路径：线性映射常态下有效内存连续，先按 64KB 一次读完，命中则
 * 显著减少调用次数；失败才回落到逐 4KB。取 64KB 而非整批 256KB 是权衡：
 * probe_kernel_read 内部 pagefault_disable()，单次调用期间不可抢占 ——
 * 64KB memcpy 约几 µs，256KB 会把不可抢占窗口拉到几十 µs（PREEMPT_RT 上不划算）。
 * 容错语义不变：失败页补零 + fail_map 置位（位号为批内页号 off>>12）。 */
#define KPM_SCAN_READ_FAST_CHUNK  65536

static long kpm_scan_read_kernel_batch(uint64_t va, void *kbuf, int len,
                                       uint64_t *fail_map)
{
    int off = 0;

    if (fail_map)
        *fail_map = 0;
    if (!kf_copy_from_kernel_nofault)
        return -KPM_E_INVAL;
    if (len <= 0 || len > KPM_SCAN_BATCH_MAX)
        return -KPM_E_INVAL;

    while (off < len) {
        uint32_t remain = (uint32_t)(len - off);
        uint32_t chunk = (remain > KPM_SCAN_READ_FAST_CHUNK)
                             ? KPM_SCAN_READ_FAST_CHUNK : remain;

        /* ---- 快速路径：整块一次 nofault（内存连续时命中） ---- */
        if (kf_copy_from_kernel_nofault((uint8_t *)kbuf + off,
                                        (const void *)(va + (uint64_t)off),
                                        (size_t)chunk) == 0) {
            off += (int)chunk;
            continue;
        }

        /* ---- 回落路径：块内逐 4KB 精读 ----
         * 大块读失败时缓冲区可能已被**部分写入**，故必须覆盖整块重读，
         * 不能只补失败页。 */
        {
            int stop = off + (int)chunk;
            while (off < stop) {
                uint64_t cur = va + (uint64_t)off;
                uint32_t piece = (uint32_t)(0x1000 - (cur & 0xFFF));
                uint32_t rem = (uint32_t)(stop - off);

                if (piece > rem)
                    piece = rem;
                if (kf_copy_from_kernel_nofault((uint8_t *)kbuf + off,
                                                (const void *)cur,
                                                (size_t)piece) != 0) {
                    if (fail_map)
                        *fail_map |= (uint64_t)(1ULL << (off >> 12));
                    lib_memset((uint8_t *)kbuf + off, 0, piece);
                }
                off += (int)piece;
            }
        }
    }
    return len;
}

/* 扫描主体（8B 打包路径与长 AOB 路径共用）。
 * type_size: 值宽度（数值类型固定 1/2/4/8；BYTEARRAY/STRING 为 value_len 或 AOB 长度）
 * is_bytes_type: 1 = 逐字节匹配（BYTEARRAY/STRING/AOB），0 = 数值匹配
 * aob_ptr/aob_len: 长特征（>8B）指针与长度；NULL/0 时走 value 打包匹配
 * kernel_mode=1 时扫描内核线性映射 [kernel_start, kernel_start+range)，
 * 不拉 VMA/不开进程会话，直接 copy_from_kernel_nofault 页级容错读取。 */
static long kpm_scan_run(pid_t pid, int value_type, int scan_mode,
                         uint64_t value, uint64_t range,
                         const uint8_t *aob_ptr, int aob_len,
                         int type_size, int is_bytes_type,
                         int kernel_mode, uint64_t kernel_start)
{
    kpm_map_entry_t *maps_buf = NULL;
    int maps_count = 0;
    kpm_scan_result_t *new_results;
    int capacity;
    int i;
    uint8_t *page_buf;

    /* 会话互斥：拒绝与其他扫描操作并发（防 UAF） */
    if (scan_enter() < 0)
        return -KPM_E_BUSY;

    /* Free previous session */
    scan_clear_locked();

    if (kernel_mode) {
        /* ===== 内核线性映射扫描：单区域直读 ===== */
        if (range == 0 || range > KPM_SCAN_KERNEL_MAX) {
            kpm_log("scan: invalid kernel range=%llu\n",
                    (unsigned long long)range);
            scan_leave();
            return -KPM_E_INVAL;
        }
        if (!kf_copy_from_kernel_nofault) {
            kpm_log("scan: kernel scan needs copy_from_kernel_nofault\n");
            scan_leave();
            return -KPM_E_INVAL;
        }
        g_scan.regions = (kpm_mem_region_t *)kf_vmalloc(
            sizeof(kpm_mem_region_t));
        if (!g_scan.regions) {
            scan_leave();
            return -KPM_E_NOMEM;
        }
        g_scan.regions[0].start = kernel_start;
        g_scan.regions[0].end   = kernel_start + range;
        g_scan.regions[0].flags = 0x1;   /* R */
        g_scan.region_count = 1;
        g_scan.total_bytes = range;
        g_scan.kernel_mode = 1;
        g_scan.kernel_start = kernel_start;
    } else {
        /* 使用 kpm_proc_maps_kernel 内核原生 VMA 遍历：所有操作纯内核完成，
         * 无任何用户态接口参与。该函数内部优先使用 find_vma + RCU +
         * get_task_mm，仅在符号缺失时回退到 filp_open（探测阶段已确保符号可用）。
         * 循环分页全量拉取 VMA（步长 KPM_SCAN_MAPS_PAGE，上限
         * KPM_MEM_SCAN_MAX_REGIONS），regions 表动态分配。 */
        g_scan.regions = (kpm_mem_region_t *)kf_vmalloc(
            KPM_MEM_SCAN_MAX_REGIONS * sizeof(kpm_mem_region_t));
        if (!g_scan.regions) {
            kpm_log("scan: failed to allocate regions buffer\n");
            scan_leave();
            return -KPM_E_NOMEM;
        }
        g_scan.region_count = 0;

        maps_buf = (kpm_map_entry_t *)kf_vmalloc(KPM_SCAN_MAPS_PAGE *
                                                 sizeof(kpm_map_entry_t));
        if (!maps_buf) {
            kf_vfree(g_scan.regions);
            g_scan.regions = NULL;
            kpm_log("scan: failed to allocate maps page buffer\n");
            scan_leave();
            return -KPM_E_NOMEM;
        }

        /* 循环分页拉取全部映射（offset 语义与 kpm_dump_begin 一致） */
        for (maps_count = 0;
             maps_count < KPM_MEM_SCAN_MAX_REGIONS;
             maps_count += KPM_SCAN_MAPS_PAGE) {
            int n = kpm_proc_maps_kernel(pid, maps_buf, KPM_SCAN_MAPS_PAGE, maps_count, 0);
            if (n <= 0)
                break;
            for (i = 0; i < n && g_scan.region_count < KPM_MEM_SCAN_MAX_REGIONS; i++) {
                g_scan.regions[g_scan.region_count].start = maps_buf[i].start;
                g_scan.regions[g_scan.region_count].end   = maps_buf[i].end;
                /* perms: bit0=r, bit1=w, bit2=x → flags 同义 */
                g_scan.regions[g_scan.region_count].flags = (uint32_t)maps_buf[i].perms;
                g_scan.region_count++;
            }
            if (n < KPM_SCAN_MAPS_PAGE)
                break;   /* 最后一页 */
        }
        kf_vfree(maps_buf);

        if (g_scan.region_count == 0) {
            kf_vfree(g_scan.regions);
            g_scan.regions = NULL;
            kpm_log("scan: no readable regions found for pid %d\n", pid);
            scan_leave();
            return -KPM_E_NOTFOUND;
        }
        kpm_log("scan: pid %d regions=%d\n", pid, g_scan.region_count);

        /* 统计全部区域字节总数（进度/完整性报告用） */
        {
            uint64_t tb = 0;
            for (i = 0; i < g_scan.region_count; i++)
                tb += g_scan.regions[i].end - g_scan.regions[i].start;
            g_scan.total_bytes = tb;
        }

        /* 会话级 mm/pgd 缓存：scan_start 一次性获取并缓存
         * pid_struct + task + mm + pgd_va，整个 FirstScan + NextScan 期间复用，
         * scan_clear 时释放。 */
        {
            int sret = kpm_mem_open_scan_session(pid,
                                                  &g_scan.cached_pid_struct,
                                                  &g_scan.cached_task,
                                                  &g_scan.cached_mm,
                                                  &g_scan.cached_pgd_va);
            if (sret < 0) {
                kpm_log("scan: open_scan_session failed pid=%d ret=%d\n", pid, sret);
                kf_vfree(g_scan.regions);
                g_scan.regions = NULL;
                g_scan.region_count = 0;
                scan_leave();
                return sret;
            }
            /* 初始化会话级 walk 上下文（PTE 表缓存 + 大页块缓存），
             * 主循环跨 256KB 块保持。g_kpm_user_page_shift 由 kpm_detect_user_va_params
             * 探测（T0SZ/TG0），主循环对齐/fail_map 使用。 */
            memset(&g_scan.walk_ctx, 0, sizeof(g_scan.walk_ctx));
            g_scan.walk_ctx.pgd_va = g_scan.cached_pgd_va;
            kpm_detect_user_va_params();
        }
    }

    /* 预分配最大结果缓冲（避免动态扩容的 vmalloc+memcpy+vfree）：
     * KPM_MEM_SCAN_MAX_RESULTS(1048576) × sizeof(kpm_scan_result_t=24B) ≈ 24MB
     * vmalloc。失败回退到 4096 条起步。 */
    capacity = KPM_MEM_SCAN_MAX_RESULTS;
    new_results = kf_vmalloc(capacity * sizeof(kpm_scan_result_t));
    if (!new_results) {
        /* 回退：4096 起步 */
        capacity = 4096;
        new_results = kf_vmalloc(capacity * sizeof(kpm_scan_result_t));
    }
    if (!new_results) {
        kpm_mem_close_scan_session(g_scan.cached_pid_struct,
                                    g_scan.cached_task,
                                    g_scan.cached_mm);
        g_scan.cached_pid_struct = NULL;
        g_scan.cached_task = NULL;
        g_scan.cached_mm = NULL;
        g_scan.cached_pgd_va = 0;
        kf_vfree(g_scan.regions);
        g_scan.regions = NULL;
        g_scan.region_count = 0;
        scan_leave();
        return -KPM_E_NOMEM;
    }

    /* 批量缓冲 256KB（KPM_SCAN_BATCH_MAX），单次读取上限；
     * vmalloc 256KB 安全（无连续物理内存压力）。 */
    page_buf = kf_vmalloc(KPM_SCAN_BATCH_MAX);
    if (!page_buf) {
        /* 回退到 KPM_SCAN_PAGE_BUF */
        page_buf = kf_vmalloc(KPM_SCAN_PAGE_BUF);
    }
    if (!page_buf) {
        kf_vfree(new_results);
        kpm_mem_close_scan_session(g_scan.cached_pid_struct,
                                    g_scan.cached_task,
                                    g_scan.cached_mm);
        g_scan.cached_pid_struct = NULL;
        g_scan.cached_task = NULL;
        g_scan.cached_mm = NULL;
        g_scan.cached_pgd_va = 0;
        kf_vfree(g_scan.regions);
        g_scan.regions = NULL;
        g_scan.region_count = 0;
        scan_leave();
        return -KPM_E_NOMEM;
    }

    g_scan.results = new_results;
    g_scan.result_capacity = capacity;
    g_scan.result_count = 0;
    g_scan.pid = pid;
    g_scan.range = range;
    g_scan.truncated = 0;
    g_scan.scanned_bytes = 0;
    g_scan.failed_pages = 0;

    /* First round: scan all regions in batches.
     *   - 会话级 walk_ctx：PTE 表缓存 + 大页块缓存跨 256KB 块保持
     *     （同 PTE 表 2MB 内无需重走 PGD/PUD/PMD）；
     *   - kpm_mem_read_batch 线性映射读取，消除每页 vmap/vunmap；
     *   - 数值类型对齐步进（step=type_size，CE 默认 aligned），
     *     BYTEARRAY/STRING/AOB 保持 step=1；
     *   - 结果缓冲满 → 剩余区域仅统计进度（scanned_bytes 继续累计）；
     *   - 大页（PMD/PUD 块映射 2MB/1GB）物理连续 → 整块一次线性读；
     *   - 页大小自动适配 4K/16K/64K（用户空间 T0SZ/TG0 探测），
     *     fail_map bit i = 第 i 个用户页。
     *
     * 页级容错读取：大块中部分页失败不中断整块，失败页补零并在 fail_map
     * 标记，扫描时跳过失败页区间。 */
    {
        int page_shift;
        uint64_t page_size;
        int scan_step = 1;

        if (kernel_mode) {
            /* 内核线性映射固定 4KB 页（copy_from_kernel_nofault 逐页） */
            page_shift = 12;
        } else {
            /* 防御：确保用户页参数已探测（T0SZ/TG0），探测失败回退 4KB */
            kpm_detect_user_va_params();
            page_shift = g_kpm_user_page_shift;
            if (page_shift <= 0)
                page_shift = 12;
        }
        page_size = 1ULL << page_shift;

        /* 数值类型对齐步进：i32/i64/float/double 按类型大小对齐（CE aligned 语义），
         * BYTEARRAY/STRING/AOB 保持 step=1（字节模式需全偏移匹配） */
        if (!is_bytes_type && type_size > 1)
            scan_step = type_size;

        for (i = 0; i < g_scan.region_count; i++) {
            uint64_t scan_pos = g_scan.regions[i].start;
            uint64_t region_end = g_scan.regions[i].end;

            /* 防御：区域起点对齐到用户页（mmap 区域本身页对齐，保证 fail_map 位序正确） */
            scan_pos = (scan_pos + page_size - 1) & ~(page_size - 1);

            while (scan_pos < region_end) {
                /* 批量缓冲 256KB（KPM_SCAN_BATCH_MAX）
                 * 原位对齐避免跨块边界：chunk_len 不超过 scan_pos 在 256KB 块内的剩余 */
                int batch_remaining = (int)(KPM_SCAN_BATCH_MAX - (scan_pos & (KPM_SCAN_BATCH_MAX - 1)));
                int chunk_len = batch_remaining;
                long bytes_read;
                uint64_t fail_map = 0;
                uint64_t swap_map = 0;   /* swap 换出页位图 */
                uint64_t full_mask;
                uint64_t pages_in_block;
                int pos;

                /* 结果缓冲满 → 剩余区域仅统计进度，快速完成。
                 * 截断语义：客户端通过 scan_status.truncated=1 感知。 */
                if (g_scan.result_count >= g_scan.result_capacity) {
                    if (!g_scan.truncated) {
                        g_scan.truncated = 1;
                        kpm_log("scan: results truncated at %d, skipping "
                                "remaining regions (progress only)\n",
                                g_scan.result_capacity);
                    }
                    g_scan.scanned_bytes += (uint64_t)chunk_len;
                    scan_pos += chunk_len;
                    continue;
                }

                if ((uint64_t)chunk_len > region_end - scan_pos)
                    chunk_len = (int)(region_end - scan_pos);

                /* 内核模式直读（copy_from_kernel_nofault 页级容错）；
                 * 用户模式走会话级批量线性读取 + swap 位图。 */
                if (kernel_mode)
                    bytes_read = kpm_scan_read_kernel_batch(scan_pos, page_buf,
                                                            chunk_len, &fail_map);
                else
                    bytes_read = kpm_mem_read_batch2(&g_scan.walk_ctx,
                                                     scan_pos, page_buf,
                                                     chunk_len, &fail_map,
                                                     &swap_map);
                if (bytes_read <= 0) {
                    scan_pos += chunk_len;
                    continue;
                }

                /* 进度统计 —— 已扫描字节 + 失败页计数 */
                g_scan.scanned_bytes += (uint64_t)chunk_len;
                if (fail_map) {
                    uint64_t fm = fail_map;
                    while (fm) { g_scan.failed_pages++; fm &= fm - 1; }  /* popcount */
                }
                /* swap 换出页统计（客户端 recover_swap 用） */
                if (swap_map) {
                    uint64_t sm = swap_map;
                    while (sm) { g_scan.swap_pages++; sm &= sm - 1; }
                }

                /* 整块全失败（补零数据不参与匹配）→ 直接跳过本块匹配 */
                pages_in_block = (uint64_t)((chunk_len + (int)page_size - 1) >> page_shift);
                full_mask = (pages_in_block >= 64) ? ~0ULL : ((1ULL << pages_in_block) - 1);
                if (fail_map && (fail_map & full_mask) == full_mask) {
                    scan_pos += chunk_len;
                    continue;
                }

                /* 对齐步进扫描：数值类型按 type_size 对齐，字节类型 step=1。
                 * 失败页区间跳过（补零数据不参与匹配，防假命中）。
                 * fail_map bit i = 第 i 个用户页。 */
                for (pos = 0; pos + type_size <= (int)bytes_read; pos += scan_step) {
                    uint64_t addr = scan_pos + pos;
                    uint64_t curr_val = 0;
                    int matched;

                    /* 跳过读取失败的页区间（补零数据不参与匹配，防假命中） */
                    if (fail_map & (1ULL << (pos >> page_shift))) {
                        pos = ((pos >> page_shift) + 1) << page_shift;  /* 跳到失败页之后 */
                        pos -= scan_step;
                        continue;
                    }

                    if (is_bytes_type) {
                        if (aob_ptr && aob_len > 0)
                            matched = kpm_scan_match_aob(page_buf + pos, aob_ptr,
                                                         g_scan.aob_mask, aob_len);
                        else
                            matched = kpm_scan_match_bytes(page_buf + pos, value,
                                                           type_size, value_type);
                        /* Store raw 8 bytes for display (zero-padded if near end) */
                        {
                            uint8_t tmp[8];
                            tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
                            tmp[4] = tmp[5] = tmp[6] = tmp[7] = 0;
                            lib_memcpy(tmp, page_buf + pos,
                                       (bytes_read - pos < 8) ? (int)(bytes_read - pos) : 8);
                            curr_val = *(uint64_t *)tmp;
                        }
                    } else if (scan_mode == KPM_SCAN_MODE_UNKNOWN) {
                        /* 未知初始值扫描——首轮恒真建集（值快照为基线） */
                        curr_val = kpm_scan_read_from_buf(page_buf + pos, value_type);
                        matched = 1;
                    } else {
                        curr_val = kpm_scan_read_from_buf(page_buf + pos, value_type);
                        matched = kpm_scan_match_value(curr_val, 0, value,
                                                       scan_mode, g_scan.range,
                                                       type_size);
                    }

                    if (!matched)
                        continue;

                    /* 结果缓冲满：置 truncated 标志并快速完成（块级判断的兜底，
                     * 4096 起步回退路径仍可能在此触达上限） */
                    if (g_scan.result_count >= g_scan.result_capacity) {
                        if (!g_scan.truncated) {
                            g_scan.truncated = 1;
                            kpm_log("scan: results truncated at %d\n",
                                    g_scan.result_capacity);
                        }
                        continue;
                    }

                    g_scan.results[g_scan.result_count].addr = addr;
                    g_scan.results[g_scan.result_count].value = curr_val;
                    g_scan.results[g_scan.result_count].prev_value = curr_val;
                    g_scan.result_count++;
                }

                scan_pos += chunk_len;

                /* 分片检查点 —— 卸载中止（kpm_mem_scan_abort）时提前退出，
                 * 返回部分结果，防 64GB 大范围扫描阻塞 UDP workqueue 卸载流程。 */
                if (g_scan.cancel)
                    goto scan_done;
            }
        }
    }

scan_done:
    kf_vfree(page_buf);
    kpm_log("scan: found %d results for pid %d\n", g_scan.result_count, pid);
    g_scan.active = 1;
    scan_leave();
    return 0;
}

/* ===== 8B 打包路径（兼容 prctl/UDP） ===== */
long kpm_mem_scan_start(pid_t pid, int value_type, int scan_mode,
                        uint64_t value, int value_len, uint64_t range)
{
    int type_size;
    int is_bytes_type;

    type_size = kpm_scan_type_size(value_type, value_len);
    if (type_size < 0) {
        kpm_log("scan: invalid type=%d len=%d\n", value_type, value_len);
        return -KPM_E_INVAL;
    }
    is_bytes_type = (value_type == KPM_SCAN_TYPE_BYTEARRAY ||
                     value_type == KPM_SCAN_TYPE_STRING);
    /* AOB/STRING only supports EXACT mode */
    if (is_bytes_type && scan_mode != KPM_SCAN_MODE_EXACT) {
        kpm_log("scan: bytes type only supports EXACT mode\n");
        return -KPM_E_INVAL;
    }
    /* UNKNOWN 只对数值类型有意义（已在字节类型分支拒绝） */
    return kpm_scan_run(pid, value_type, scan_mode, value, range,
                        NULL, 0, type_size, is_bytes_type,
                        0, 0);
}

/* ===== 长 AOB 特征扫描（>8B 特征） ===== */
long kpm_mem_scan_start_aob(pid_t pid, const uint8_t *pattern, int plen,
                            const uint8_t *mask,
                            int scan_mode, uint64_t range)
{
    if (!pattern || plen <= 0 || plen > KPM_SCAN_AOB_MAX) {
        kpm_log("scan: invalid aob len=%d\n", plen);
        return -KPM_E_INVAL;
    }
    if (scan_mode != KPM_SCAN_MODE_EXACT) {
        kpm_log("scan: aob only supports EXACT mode\n");
        return -KPM_E_INVAL;
    }
    /* 复制特征到会话缓冲：UDP g_recv_buf 会被后续请求复用，必须深拷贝。
     * mask 为 NULL 时全精确；否则复制 mask（0=通配）。 */
    lib_memcpy(g_scan.aob_pattern, pattern, plen);
    if (mask) {
        lib_memcpy(g_scan.aob_mask, mask, plen);
    } else {
        lib_memset(g_scan.aob_mask, 0xFF, plen);   /* 全精确 */
    }
    g_scan.aob_len = plen;
    return kpm_scan_run(pid, KPM_SCAN_TYPE_BYTEARRAY, scan_mode, 0,
                        range, g_scan.aob_pattern, plen, plen, 1,
                        0, 0);
}

/* ===== 内核线性映射范围扫描 =====
 * 扫描 [PAGE_OFFSET, PAGE_OFFSET+range) 内核地址空间。
 * 不拉 VMA、不开进程会话；copy_from_kernel_nofault 页级容错直读。
 * 隐蔽性：纯内核标准 API 读，无进程 fault 痕迹、无 VFS 痕迹。
 * 稳定性：页级容错（失败页补零+fail_map 跳过），不 panic。
 * 兼容性：仅依赖 kf_copy_from_kernel_nofault（5.4+，既有约束）+
 *         get_page_offset()（TCR_EL1 探测，39/48 位自动适配）。 */
long kpm_mem_scan_kernel_start(int value_type, int scan_mode,
                               uint64_t value, int value_len, uint64_t range)
{
    int type_size;
    int is_bytes_type;

    /* 首轮仅允许初始匹配模式：UNKNOWN（恒真建集）/EXACT/RANGE/NOT_EQUAL；
     * 过滤模式（CHANGED/±X 等）需要上一轮结果，首轮拒绝。 */
    if (scan_mode == KPM_SCAN_MODE_UNKNOWN) {
        /* UNKNOWN 首轮恒真建集在内核扫描同样支持（数值类型） */
    } else if (scan_mode == KPM_SCAN_MODE_CHANGED ||
               scan_mode == KPM_SCAN_MODE_UNCHANGED ||
               scan_mode == KPM_SCAN_MODE_INCREASED ||
               scan_mode == KPM_SCAN_MODE_DECREASED ||
               scan_mode == KPM_SCAN_MODE_INCREASED_BY ||
               scan_mode == KPM_SCAN_MODE_DECREASED_BY ||
               scan_mode == KPM_SCAN_MODE_INCREASED_GE ||
               scan_mode == KPM_SCAN_MODE_DECREASED_GE) {
        /* 过滤模式需上一轮结果（首轮无意义）——拒绝 */
        kpm_log("scan: kernel start: mode %d needs previous round\n",
                scan_mode);
        return -KPM_E_INVAL;
    }

    type_size = kpm_scan_type_size(value_type, value_len);
    if (type_size < 0) {
        kpm_log("scan: kernel start: invalid type=%d len=%d\n",
                value_type, value_len);
        return -KPM_E_INVAL;
    }
    is_bytes_type = (value_type == KPM_SCAN_TYPE_BYTEARRAY ||
                     value_type == KPM_SCAN_TYPE_STRING);
    if (is_bytes_type && scan_mode != KPM_SCAN_MODE_EXACT) {
        kpm_log("scan: kernel start: bytes type only EXACT\n");
        return -KPM_E_INVAL;
    }
    if (range == 0 || range > KPM_SCAN_KERNEL_MAX) {
        kpm_log("scan: kernel start: invalid range=%llu\n",
                (unsigned long long)range);
        return -KPM_E_INVAL;
    }

    /* 线性映射起始 = PAGE_OFFSET（对应物理地址 0 处；memstart 通常为 0，
     * 若 memstart>0，线性映射 [PAGE_OFFSET, +memstart) 为保留区，直读失败
     * 页会自动跳过，不影响后续 RAM 区）。 */
    return kpm_scan_run(0, value_type, scan_mode, value, range,
                        NULL, 0, type_size, is_bytes_type,
                        1, kpm_get_page_offset());
}

long kpm_mem_scan_next(int value_type, int scan_mode,
                       uint64_t value, int value_len, uint64_t range)
{
    int i;
    int write_pos = 0;
    uint8_t *page_buf;
    int type_size;
    int is_bytes_type;
    /* NextScan 批量块缓存读取（KPM_SCAN_PAGE_BUF=256KB）：
     * 使用 kpm_mem_read_batch + 会话级 walk_ctx
     * （PTE 表缓存 + 大页块缓存跨块保持），fail_map 按用户页大小索引。 */
    uint64_t cached_block_addr = 0;   /* 256KB 块对齐基址 */
    long cached_bytes_read = 0;
    uint64_t cached_fail_map = 0;
    int page_shift;

    /* 会话互斥：拒绝与其他扫描操作并发（防 UAF） */
    if (scan_enter() < 0)
        return -KPM_E_BUSY;

    if (!g_scan.active || !g_scan.results) {
        scan_leave();
        return -KPM_E_INVAL;
    }

    /* NextScan 必须在 scan_start 之后调用，会话级 walk 上下文可用。
     * 内核扫描模式（kernel_mode=1）无 walk_ctx，跳过此检查。 */
    if (!g_scan.kernel_mode && !g_scan.walk_ctx.pgd_va) {
        kpm_log("scan: next called without active session pgd\n");
        scan_leave();
        return -KPM_E_INVAL;
    }

    /* UNKNOWN 仅首轮建集，NextScan 拒绝 */
    if (scan_mode == KPM_SCAN_MODE_UNKNOWN) {
        kpm_log("scan: next cannot use UNKNOWN mode\n");
        scan_leave();
        return -KPM_E_INVAL;
    }

    /* 用户页参数（T0SZ/TG0 探测），失败回退 4KB；内核扫描固定 4KB。 */
    if (g_scan.kernel_mode) {
        page_shift = 12;
    } else {
        kpm_detect_user_va_params();
        page_shift = g_kpm_user_page_shift;
        if (page_shift <= 0)
            page_shift = 12;
    }

    /* 更新 range（NextScan 可能切换 mode 或调整 range） */
    g_scan.range = range;

    type_size = kpm_scan_type_size(value_type, value_len);
    if (type_size < 0) {
        scan_leave();
        return -KPM_E_INVAL;
    }

    is_bytes_type = (value_type == KPM_SCAN_TYPE_BYTEARRAY ||
                     value_type == KPM_SCAN_TYPE_STRING);

    if (is_bytes_type && scan_mode != KPM_SCAN_MODE_EXACT) {
        scan_leave();
        return -KPM_E_INVAL;
    }

    /* 批量缓冲 256KB（KPM_SCAN_PAGE_BUF = KPM_SCAN_BATCH_MAX），
     * 使用会话级 walk_ctx 复用进程查找。 */
    page_buf = kf_vmalloc(KPM_SCAN_PAGE_BUF);
    if (!page_buf) {
        scan_leave();
        return -KPM_E_NOMEM;
    }

    /* Iterate through existing results, filter in-place.
     * 256KB 块缓存 + 会话级 walk_ctx + fail_map 按用户页容错。 */
    for (i = 0; i < g_scan.result_count; i++) {
        /* 每 16K 条检查卸载中止（防海量结果过滤时阻塞卸载流程） */
        if ((i & 0x3FFF) == 0 && g_scan.cancel)
            break;
        uint64_t addr = g_scan.results[i].addr;
        uint64_t prev_val = g_scan.results[i].value;
        uint64_t block_addr = addr & ~((uint64_t)KPM_SCAN_PAGE_BUF - 1);  /* 256KB 对齐 */
        int block_offset = (int)(addr - block_addr);
        uint64_t curr_val = 0;
        int matched;

        /* 跨 256KB 块边界或首次调用：重新读取 256KB 块；
         * 内核模式走直读，用户模式走会话级批量读取。 */
        if (block_addr != cached_block_addr || cached_bytes_read <= 0) {
            if (g_scan.kernel_mode)
                cached_bytes_read = kpm_scan_read_kernel_batch(
                    block_addr, page_buf, KPM_SCAN_PAGE_BUF,
                    &cached_fail_map);
            else
                cached_bytes_read = kpm_mem_read_batch(
                    &g_scan.walk_ctx, block_addr, page_buf,
                    KPM_SCAN_PAGE_BUF, &cached_fail_map);
            cached_block_addr = block_addr;
        }

        if (cached_bytes_read <= 0 ||
            block_offset + type_size > cached_bytes_read)
            continue;

        /* 跳过失败页内的结果（补零数据不参与匹配） */
        if (cached_fail_map & (1ULL << (block_offset >> page_shift)))
            continue;

        if (is_bytes_type) {
            matched = kpm_scan_match_bytes(page_buf + block_offset, value,
                                           type_size, value_type);
            {
                uint8_t tmp[8];
                int copy_n = (cached_bytes_read - block_offset < 8)
                             ? (int)(cached_bytes_read - block_offset) : 8;
                tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
                tmp[4] = tmp[5] = tmp[6] = tmp[7] = 0;
                lib_memcpy(tmp, page_buf + block_offset, copy_n);
                curr_val = *(uint64_t *)tmp;
            }
        } else {
            curr_val = kpm_scan_read_from_buf(page_buf + block_offset, value_type);
            matched = kpm_scan_match_value(curr_val, prev_val, value,
                                           scan_mode, g_scan.range,
                                           type_size);
        }

        if (!matched)
            continue;

        /* Keep this result */
        if (write_pos != i) {
            g_scan.results[write_pos].addr = addr;
            g_scan.results[write_pos].prev_value = prev_val;
        }
        g_scan.results[write_pos].value = curr_val;
        write_pos++;
    }

    kf_vfree(page_buf);
    g_scan.result_count = write_pos;
    kpm_log("scan: next round: %d results remaining\n", g_scan.result_count);
    scan_leave();
    return 0;
}

long kpm_mem_scan_copy_results(kpm_scan_result_t *user_buf,
                               int max_count, int offset)
{
    int to_copy;
    long ret;

    if (!user_buf || max_count <= 0)
        return -KPM_E_INVAL;
    /* max_count 硬上限（防止拷贝超出调用方预期/越界） */
    if (max_count > KPM_SCAN_COPY_MAX) max_count = KPM_SCAN_COPY_MAX;
    if (offset < 0) offset = 0;

    if (scan_enter() < 0)
        return -KPM_E_BUSY;

    if (!g_scan.active || !g_scan.results) {
        scan_leave();
        return -KPM_E_INVAL;
    }

    if (offset >= g_scan.result_count) {
        scan_leave();
        return 0;
    }

    to_copy = g_scan.result_count - offset;
    if (to_copy > max_count)
        to_copy = max_count;

    ret = 0;
    if (kf_copy_to_user(user_buf, &g_scan.results[offset],
                        to_copy * sizeof(kpm_scan_result_t)))
        ret = -KPM_E_FAULT;
    else
        ret = to_copy;

    scan_leave();
    return ret;
}

/* UDP 通道传入 resp_data（内核空间），copy_to_user 失败。
 * 此函数使用 lib_memcpy，仅供内核态调用方使用（如 UDP 处理）。 */
long kpm_mem_scan_copy_results_kernel(kpm_scan_result_t *kbuf,
                                      int max_count, int offset)
{
    int to_copy;
    long ret;

    if (!kbuf || max_count <= 0)
        return -KPM_E_INVAL;
    /* max_count 硬上限（UDP 层检查被绕过时的最终防线） */
    if (max_count > KPM_SCAN_COPY_MAX) max_count = KPM_SCAN_COPY_MAX;
    if (offset < 0) offset = 0;

    if (scan_enter() < 0)
        return -KPM_E_BUSY;

    if (!g_scan.active || !g_scan.results) {
        scan_leave();
        return -KPM_E_INVAL;
    }

    if (offset >= g_scan.result_count) {
        scan_leave();
        return 0;
    }

    to_copy = g_scan.result_count - offset;
    if (to_copy > max_count)
        to_copy = max_count;

    lib_memcpy(kbuf, &g_scan.results[offset],
               (size_t)to_copy * sizeof(kpm_scan_result_t));
    ret = to_copy;

    scan_leave();
    return ret;
}

long kpm_mem_scan_status(kpm_scan_status_t *out)
{
    if (!out)
        return -KPM_E_INVAL;

    /* 读状态无需持有 busy：所有字段由 scan_start/scan_next 在锁外原子写入
     * （单写者，busy 互斥已保证无并发写），直接读取最新快照即可 */
    out->active          = g_scan.active;
    out->pid             = g_scan.pid;
    out->region_count    = g_scan.region_count;
    out->result_count    = g_scan.result_count;
    out->result_capacity = g_scan.result_capacity;
    out->truncated       = g_scan.truncated;
    out->scanned_bytes   = g_scan.scanned_bytes;
    out->total_bytes     = g_scan.total_bytes;
    out->failed_pages    = g_scan.failed_pages;
    out->swap_pages      = g_scan.swap_pages;
    return 0;
}

/* CLEAR 前置 abort：先置 cancel 标志让在途扫描提前退出（扫描主循环每
 * 256KB 块检查，退出延迟毫秒级），再有界等待 busy 归零（kpm_udelay_range
 * 任意上下文安全），拿到会话后 scan_clear_locked 重置 cancel；等待超时
 * （扫描侧异常卡死）才返回 -KPM_E_BUSY。 */
#define KPM_SCAN_CLEAR_WAIT_SPINS  1000   /* 1000 x (100~200us) ≈ 100~200ms */

long kpm_mem_scan_clear(void)
{
    int spins = 0;

    kpm_mem_scan_abort();   /* 前置置 cancel，在途扫描提前退出 */

    while (scan_enter() < 0) {
        if (++spins > KPM_SCAN_CLEAR_WAIT_SPINS) {
            kpm_log("mem_scan: clear wait timeout (scan still busy)\n");
            return -KPM_E_BUSY;
        }
        kpm_udelay_range(100, 200);
    }
    scan_clear_locked();
    scan_leave();
    return 0;
}