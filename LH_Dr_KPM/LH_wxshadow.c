/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_wxshadow.c - W^X shadow 无痕 hook（独立实现）
 *
 * 原理：
 *   1. 把目标用户代码页复制到内核 kmalloc 的 shadow 页，在 shadow 上
 *      写入自定义 patch 或 BRK 断点；
 *   2. 用户 PTE 改为 execute-only（AP=00 + UXN=0）指向 shadow；
 *      执行走 shadow，数据读取触发 permission fault → 切回原始页 r--，
 *      下次取指再切回 shadow --x。因此进程内读取/CRC 始终看到原始代码。
 *   3. BRK 命中：把 PTE 映射回原始页 r-x 并置 PSTATE.SS 单步执行原指令，
 *      步进回调再切回 shadow --x，继续执行后续指令。
 *
 * 限制：
 *   - 同一页不能同时读与执行；自读代码区不要设 BRK（会反复切换）；
 *   - patch 不能跨页；每页 32 个 BP / 8 个 patch，单 patch ≤256B；
 *   - 仅支持用户可执行页；block mapping 不支持；
 *   - GUP 跨进程读（/proc/pid/mem、process_vm_readv）未做隐藏。
 */
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <hook.h>
#include <pgtable.h>
#include <baselib.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <asm/ptrace.h>

#include "LH_comm.h"
#include "LH_wxshadow.h"
#include "LH_mem_rw.h"
#include "LH_syms.h"
#include "LH_log.h"
#include "LH_utils.h"

#ifndef GFP_KERNEL
#define GFP_KERNEL 0xcc0u
#endif

#define WX_PAGE_SIZE    4096ULL
#define WX_PAGE_MASK    (~(WX_PAGE_SIZE - 1))
#define WX_SLOT_SIZE    8192            /* 多分配一页用于 4K 对齐 */
#define WX_PHYS_MASK    0x0000FFFFFFFFF000ULL
#define WX_PC_OFF       256             /* pt_regs: regs[31]@0 sp@248 pc@256 pstate@264 */
#define WX_PSTATE_OFF   264
#define WX_SPSR_SS      (1ULL << 21)

/* 4.19 无 break_hook / step_hook 注册符号（static inline），统一 hook
 * do_debug_exception（BRK EC=0x3C / 软件单步 EC=0x32），跨 4.19~6.1 稳定。 */

typedef struct {
    uint16_t off;
    uint16_t len;
    uint8_t  data[KPM_WX_MAX_PATCH_LEN];
} wx_patch_t;

typedef struct {
    int      used;
    uint32_t id;
    pid_t    pid;
    void    *mm;
    uint64_t pgd;
    uint64_t page;
    uint64_t orig_pte;
    uint64_t orig_pfn;
    uint64_t shadow_pfn;
    void    *shadow_alloc;
    void    *shadow_kva;
    uint32_t state;             /* KPM_WX_ST_* */
    uint32_t fork_prev;         /* dup_mm 前的状态（fork 保护） */
    uint32_t nr_bps;
    uint32_t nr_patches;
    uint32_t hits;
    uint64_t last_pc;
    void    *stepping_task;
    kpm_wx_bp_t bps[KPM_WX_MAX_BPS];
    wx_patch_t patches[KPM_WX_MAX_PATCH];
} wx_page_t;

static wx_page_t g_wx[KPM_WX_MAX_PAGES];
static kpm_spinlock_t g_wx_lock = KPM_SPINLOCK_INIT;
static int g_wx_active;
static int g_wx_fault_hooked;
static int g_wx_exit_hooked;
static int g_wx_dbg_hooked;

/* ========== 基础工具 ========== */

static void *wx_cur_task(void)
{
    unsigned long cur;
    asm volatile("mrs %0, sp_el0" : "=r"(cur));
    if (cur < 0xFFFF000000000000ULL)
        return 0;
    return (void *)cur;
}

/* MDSCR_EL1.SS：硬件软件步进的全局开关（PSTATE.SS 是每任务触发位）。
 * 只置 PSTATE.SS 而不置 MDSCR.SS 时步进异常不会产生。 */
static inline void wx_mdscr_ss(int on)
{
    uint64_t v;
    asm volatile("mrs %0, mdscr_el1" : "=r"(v));
    v = on ? (v | 1ULL) : (v & ~1ULL);
    asm volatile("msr mdscr_el1, %0" :: "r"(v));
}

static void *wx_cur_mm(void)
{
    void *t = wx_cur_task();
    void *mm = 0;

    if (!t || g_mm_offset <= 0)
        return 0;
    lib_memcpy(&mm, (const char *)t + g_mm_offset, sizeof(mm));
    return mm;
}

/* 线性映射换算：不依赖 linear_voffset/kimage_voffset 符号
 * （它们未在 KernelPatch 导出表中，直接引用会导致 KPM 加载失败）。
 * linear_va = phys - memstart + PAGE_OFFSET */
static uint64_t wx_phys_to_virt(uint64_t pa)
{
    return pa - g_memstart_addr + kpm_get_page_offset();
}

static uint64_t wx_virt_to_phys(uint64_t va)
{
    return va - kpm_get_page_offset() + g_memstart_addr;
}

static void wx_flush_icache(void *start, unsigned long len)
{
    unsigned long a;

    if (kf_flush_icache_range) {
        ((void (*)(unsigned long, unsigned long))kf_flush_icache_range)
            ((unsigned long)start, (unsigned long)start + len);
        return;
    }
    for (a = (unsigned long)start; a < (unsigned long)start + len; a += 64)
        asm volatile("dc civac, %0" :: "r"(a) : "memory");
    asm volatile("ic iallu" ::: "memory");
    dsb(ish);
    isb();
}

static uint64_t wx_pte_pfn(uint64_t e, uint64_t pfn)
{
    e &= ~WX_PHYS_MASK;
    e |= (pfn << 12) & WX_PHYS_MASK;
    e |= PTE_VALID | PTE_TYPE_PAGE;
    return e;
}

/* shadow --x：AP=00（EL0 无数据访问）+ UXN=0（EL0 可执行） */
static uint64_t wx_pte_shadow_x(wx_page_t *e)
{
    uint64_t p = wx_pte_pfn(e->orig_pte, e->shadow_pfn);
    p &= ~(PTE_USER | PTE_RDONLY | PTE_DBM | PTE_CONT | PTE_UXN);
    return p;
}

/* 隐藏的原始页 r--：可读、不可写、不可执行 */
static uint64_t wx_pte_original(wx_page_t *e)
{
    uint64_t p = wx_pte_pfn(e->orig_pte, e->orig_pfn);
    p |= PTE_USER | PTE_RDONLY | PTE_UXN;
    p &= ~(PTE_DBM | PTE_CONT);
    return p;
}

/* 单步原始指令 r-x */
static uint64_t wx_pte_stepping(wx_page_t *e)
{
    uint64_t p = wx_pte_pfn(e->orig_pte, e->orig_pfn);
    p |= PTE_USER | PTE_RDONLY;
    p &= ~(PTE_UXN | PTE_DBM | PTE_CONT);
    return p;
}

static inline void wx_flush_tlb_va(uint64_t va)
{
    uint64_t arg = (va >> 12) & ((1ULL << 44) - 1);

    asm volatile("dsb ishst\n"
                 "tlbi vaae1is, %0\n"
                 "dsb ish\n"
                 "isb\n" :: "r"(arg) : "memory");
}

/* 写 PTE（持 g_wx_lock）。返回 0 成功；-2=映射已变（COW/munmap） */
static int wx_write_pte_locked(wx_page_t *e, uint64_t new_pte)
{
    uint64_t slot = 0;
    uint64_t cur, pfn;

    if (kpm_mem_get_pte_va(e->pgd, e->page, &slot) < 0)
        return -1;
    cur = *(volatile uint64_t *)slot;
    if (!(cur & PTE_VALID))
        return -1;
    pfn = (cur & WX_PHYS_MASK) >> 12;
    if (pfn != e->orig_pfn && pfn != e->shadow_pfn)
        return -2;
    *(volatile uint64_t *)slot = new_pte;
    /* 按 VA 失效（vaae1is，覆盖所有 ASID）：比 vmalle1is 全局刷新轻得多；
     * BRK 高频时全局刷新会把整机拖死。 */
    wx_flush_tlb_va(e->page);
    return 0;
}

static int wx_find_free_locked(void)
{
    int i;
    for (i = 0; i < KPM_WX_MAX_PAGES; i++)
        if (!g_wx[i].used)
            return i;
    return -1;
}

/* 卸载/释放前把 PTE 恢复到原始页，返回 0 表示 shadow 已不再被任何 PTE
 * 引用、可以安全 kfree。返回 -1 表示映射已变（COW/munmap）或无法确认，
 * 此时绝不能 free shadow：否则用户页表会残留 kernel 页 PFN，进程退出
 * unmap 时触发 Bad page map → kfree Oops。
 * 宁可泄漏一个 shadow 页，不可留下悬空 PTE。 */
static int wx_detach_locked(wx_page_t *e)
{
    uint64_t slot = 0;
    uint64_t cur, pfn;

    if (kpm_mem_get_pte_va(e->pgd, e->page, &slot) < 0)
        return -1;
    cur = *(volatile uint64_t *)slot;
    pfn = (cur & WX_PHYS_MASK) >> 12;
    if (pfn == e->shadow_pfn) {
        *(volatile uint64_t *)slot = e->orig_pte;
        wx_flush_tlb_va(e->page);
        return 0;
    }
    if (pfn == e->orig_pfn)
        return 0;              /* 已指向原始页，无需改 PTE */
    return -1;                 /* 映射已变，不可碰或 free */
}

static wx_page_t *wx_find_locked(void *mm, uint64_t page)
{
    int i;
    for (i = 0; i < KPM_WX_MAX_PAGES; i++) {
        wx_page_t *e = &g_wx[i];
        if (e->used && e->mm == mm && e->page == page)
            return e;
    }
    return 0;
}

/* 重新生成 shadow 内容：原始页副本 + patches + BRK */
static void wx_rebuild_shadow_locked(wx_page_t *e)
{
    void *src = (void *)(uintptr_t)wx_phys_to_virt(e->orig_pfn << 12);
    int i;

    if (!src || (uint64_t)src < 0xFFFF000000000000ULL)
        return;
    lib_memcpy(e->shadow_kva, src, WX_PAGE_SIZE);
    for (i = 0; i < KPM_WX_MAX_PATCH; i++) {
        wx_patch_t *p = &e->patches[i];
        if (p->len && p->off + p->len <= WX_PAGE_SIZE)
            lib_memcpy((char *)e->shadow_kva + p->off, p->data, p->len);
    }
    for (i = 0; i < KPM_WX_MAX_BPS; i++) {
        if (!(e->bps[i].flags & 1))
            continue;
        if ((e->bps[i].addr & WX_PAGE_MASK) != e->page)
            continue;
        *(uint32_t *)((char *)e->shadow_kva +
                      (e->bps[i].addr & 0xFFF)) = KPM_WX_BRK_INSN;
    }
    wx_flush_icache(e->shadow_kva, WX_PAGE_SIZE);
}

/* 在 shadow 已映射时安全重建：先把 PTE 临时切到原始 r-x，避免目标执行
 * 到半写入的 shadow（del_bp/patch 时目标正在跑该页会 SIGILL/SIGSEGV）。
 * 返回 0 成功，-1 暂停失败（不动）。 */
static int wx_rebuild_safe_locked(wx_page_t *e)
{
    uint32_t prev = e->state;
    int paused = 0;

    if (prev == KPM_WX_ST_SHADOW_X || prev == KPM_WX_ST_ORIGINAL) {
        if (wx_write_pte_locked(e, wx_pte_stepping(e)) != 0)
            return -1;
        paused = 1;
        e->state = KPM_WX_ST_STEPPING;
    }
    wx_rebuild_shadow_locked(e);
    if (paused) {
        if (prev == KPM_WX_ST_SHADOW_X) {
            if (wx_write_pte_locked(e, wx_pte_shadow_x(e)) == 0)
                e->state = KPM_WX_ST_SHADOW_X;
        } else {
            if (wx_write_pte_locked(e, wx_pte_original(e)) == 0)
                e->state = KPM_WX_ST_ORIGINAL;
        }
    }
    return 0;
}

static void wx_free_locked(wx_page_t *e)
{
    if (e->shadow_alloc && kf_kfree)
        kf_kfree(e->shadow_alloc);
    lib_memset(e, 0, sizeof(*e));
}

/* 新建 shadow 页并武装。返回 0 / 负错误码。 */
static long wx_arm_locked(pid_t pid, void *mm, uint64_t pgd, uint64_t page,
                          uint64_t orig_pte)
{
    int slot;
    wx_page_t *e;
    void *raw, *aligned;
    uint64_t pfn = (orig_pte & WX_PHYS_MASK) >> 12;

    if (!pfn || !kf_kmalloc)
        return -KPM_E_DISABLED;
    slot = wx_find_free_locked();
    if (slot < 0)
        return -KPM_E_NOMEM;
    raw = kf_kmalloc(WX_SLOT_SIZE, GFP_KERNEL);
    if (!raw)
        return -KPM_E_NOMEM;
    aligned = (void *)(((uint64_t)raw + WX_PAGE_SIZE - 1) & WX_PAGE_MASK);
    e = &g_wx[slot];
    lib_memset(e, 0, sizeof(*e));
    e->used = 1;
    e->id = (uint32_t)slot;
    e->pid = pid;
    e->mm = mm;
    e->pgd = pgd;
    e->page = page;
    e->orig_pte = orig_pte;
    e->orig_pfn = pfn;
    e->shadow_alloc = raw;
    e->shadow_kva = aligned;
    e->shadow_pfn = wx_virt_to_phys((uint64_t)aligned) >> 12;
    e->state = KPM_WX_ST_SHADOW_X;
    wx_rebuild_shadow_locked(e);
    if (e->orig_pfn == e->shadow_pfn ||
        wx_write_pte_locked(e, wx_pte_shadow_x(e)) < 0) {
        wx_free_locked(e);
        return -KPM_E_FAULT;
    }
    kpm_log_info("wx: arm id=%d pid=%d page=0x%llx orig=%llx shadow=%llx\n",
                 slot, pid, (unsigned long long)page,
                 (unsigned long long)e->orig_pfn,
                 (unsigned long long)e->shadow_pfn);
    return slot;
}

/* ========== fault / BRK / step 处理 ========== */

/* do_mem_abort before：读→原始 r--；取指→shadow --x */
static void wx_fault_before(hook_fargs4_t *fa, void *udata)
{
    unsigned long addr, esr;
    uint32_t ec, fsc;
    int wnr, handled = 0, i;
    void *mm;
    unsigned long flags;

    (void)udata;
    if (!fa)
        return;
    addr = (unsigned long)fa->args[0];
    esr = (unsigned long)fa->args[1];
    ec = (esr >> 26) & 0x3F;
    fsc = esr & 0x3F;
    wnr = (int)((esr >> 6) & 1);
    if (fsc < 0x0D || fsc > 0x0F)     /* 只处理 permission fault */
        return;
    mm = wx_cur_mm();
    if (!mm)
        return;

    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    for (i = 0; i < KPM_WX_MAX_PAGES; i++) {
        wx_page_t *e = &g_wx[i];
        if (!e->used || e->mm != mm || e->page != (addr & WX_PAGE_MASK))
            continue;
        if (ec == 0x20 || ec == 0x21) {          /* instruction abort */
            if (e->state == KPM_WX_ST_ORIGINAL &&
                wx_write_pte_locked(e, wx_pte_shadow_x(e)) == 0) {
                e->state = KPM_WX_ST_SHADOW_X;
                handled = 1;
            }
        } else if (ec == 0x24 || ec == 0x25) {   /* data abort */
            if (!wnr && e->state == KPM_WX_ST_SHADOW_X &&
                wx_write_pte_locked(e, wx_pte_original(e)) == 0) {
                e->state = KPM_WX_ST_ORIGINAL;
                handled = 1;
            }
        }
        break;
    }
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
    if (handled) {
        fa->ret = 0;
        fa->skip_origin = 1;
    }
}

/* BRK：应用寄存器改写 → 原始页 r-x + PSTATE.SS 单步原指令 */
static int wx_brk_fn(void *regsv, unsigned int esr)
{
    void *regs = regsv;
    void *mm;
    unsigned long flags;
    uint64_t pc;
    int i, j, found = 0;

    if ((esr & 0xFFFF) != KPM_WX_BRK_IMM || !regs)
        return 1;
    pc = ((uint64_t *)regs)[WX_PC_OFF / 8];
    mm = wx_cur_mm();
    if (!mm)
        return 1;

    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    for (i = 0; i < KPM_WX_MAX_PAGES; i++) {
        wx_page_t *e = &g_wx[i];
        if (!e->used || e->mm != mm || e->page != (pc & WX_PAGE_MASK))
            continue;
        if (e->state != KPM_WX_ST_SHADOW_X)
            break;
        for (j = 0; j < KPM_WX_MAX_BPS; j++) {
            if (!(e->bps[j].flags & 1) || e->bps[j].addr != pc)
                continue;
            if (e->bps[j].reg_idx <= 30)
                ((uint64_t *)regs)[e->bps[j].reg_idx] = e->bps[j].value;
            found = 1;
        }
        /* bp 被并发删除（del_bp 与命中竞态）：shadow 里仍是我们的 BRK 时
         * 仍接管，否则默认 SIGTRAP 会杀掉目标进程。 */
        if (!found) {
            uint32_t insn = 0;
            if (e->shadow_kva)
                lib_memcpy(&insn,
                           (char *)e->shadow_kva + (pc & 0xFFF), 4);
            if (insn != KPM_WX_BRK_INSN) {
                ((uint64_t *)regs)[WX_PC_OFF / 8] = pc + 4;
                kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
                return 0;   /* 跳过 BRK，保命 */
            }
        }
        if (wx_write_pte_locked(e, wx_pte_stepping(e)) < 0) {
            /* 无法切原始页：跳过 BRK 指令，避免无限 BRK/默认 SIGTRAP */
            ((uint64_t *)regs)[WX_PC_OFF / 8] = pc + 4;
            kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
            return 0;
        }
        e->state = KPM_WX_ST_STEPPING;
        e->stepping_task = wx_cur_task();
        e->hits++;
        e->last_pc = pc;
        wx_mdscr_ss(1);
        ((uint64_t *)regs)[WX_PSTATE_OFF / 8] |= WX_SPSR_SS;
        kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
        return 0;
    }
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
    /* 非本模块页面：放行给内核默认处理（绝不影响 init/其他进程） */
    return 1;
}

/* 单步完成：切回 shadow --x */
static int wx_step_fn(void *regsv, unsigned int esr)
{
    void *cur = wx_cur_task();
    unsigned long flags;
    int i;

    (void)regsv;
    (void)esr;
    if (!cur)
        return 1;
    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    for (i = 0; i < KPM_WX_MAX_PAGES; i++) {
        wx_page_t *e = &g_wx[i];
        if (!e->used || e->state != KPM_WX_ST_STEPPING ||
            e->stepping_task != cur)
            continue;
        e->stepping_task = 0;
        if (wx_write_pte_locked(e, wx_pte_shadow_x(e)) == 0)
            e->state = KPM_WX_ST_SHADOW_X;
        wx_mdscr_ss(0);
        kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
        return 0;
    }
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
    return 1;
}

/* do_debug_exception(addr, esr, regs) hook：BRK(0x3C) / 软件单步(0x32)。 */
static void wx_debug_before(hook_fargs4_t *fa, void *udata)
{
    unsigned long esr;
    void *regs;
    uint32_t ec;

    (void)udata;
    if (!fa)
        return;
    esr = (unsigned long)fa->args[1];
    regs = (void *)(uintptr_t)fa->args[2];
    ec = (esr >> 26) & 0x3F;
    if (ec == 0x3C) {           /* BRK in AArch64 */
        if (wx_brk_fn(regs, (unsigned int)esr) == 0) {
            fa->ret = 0;
            fa->skip_origin = 1;
        }
    } else if (ec == 0x32) {    /* Software Step from lower EL */
        if (wx_step_fn(regs, (unsigned int)esr) == 0) {
            fa->ret = 0;
            fa->skip_origin = 1;
        }
    }
}

/* exit_mmap：进程销毁前摘除该 mm 的 shadow（PTE 随 mm 一起销毁） */
static void wx_exit_mmap_before(hook_fargs1_t *fa, void *udata)
{
    void *mm = (void *)(uintptr_t)fa->args[0];
    unsigned long flags;
    int i;

    (void)udata;
    if (!mm)
        return;
    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    for (i = 0; i < KPM_WX_MAX_PAGES; i++) {
        wx_page_t *e = &g_wx[i];
        if (!e->used || e->mm != mm)
            continue;
        /* 必须先把 PTE 恢复回原始页，否则 mm 卸载时把 kernel 页当
         * 普通用户页 unmap → Bad page map / kfree Oops。 */
        if (wx_detach_locked(e) == 0)
            wx_free_locked(e);
        else
            e->state = KPM_WX_ST_DORMANT;   /* 泄漏 shadow，保命 */
    }
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
}

/* fork 保护不安装（不 hook dup_mm/copy_process）：hook copy_process 会介入
 * 内核 pid 引用管理路径。armed 后不要 fork，或在子进程创建后重新 WX_PATCH。 */

/* ========== 用户接口 ========== */

/* 打开目标会话并定位/创建 shadow 页。出参 e_id 供上层使用。 */
static long wx_get_page(pid_t pid, uint64_t addr, int create,
                        void **out_ps, void **out_task, void **out_mm,
                        uint64_t *out_pgd, int *out_id)
{
    void *ps = 0, *task = 0, *mm = 0;
    uint64_t pgd = 0, page = addr & WX_PAGE_MASK;
    uint64_t slot = 0, orig;
    unsigned long flags;
    long ret;
    int id = -1;

    if (pid <= 0 || !addr)
        return -KPM_E_INVAL;
    if (addr + 4 < addr)
        return -KPM_E_INVAL;
    ret = kpm_mem_open_scan_session(pid, &ps, &task, &mm, &pgd);
    if (ret)
        return ret;

    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    {
        wx_page_t *e = wx_find_locked(mm, page);
        if (e) {
            id = (int)e->id;
            kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
            goto out;
        }
    }
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);

    if (!create) {
        ret = -KPM_E_NOTFOUND;
        goto out_close;
    }

    if (kpm_mem_get_pte_va(pgd, page, &slot) < 0) {
        ret = -KPM_E_FAULT;
        goto out_close;
    }
    orig = *(volatile uint64_t *)slot;
    /* 必须是有效、用户、可执行的 4K 页（execute-only 切换前提） */
    if (!(orig & PTE_VALID) || !(orig & PTE_USER) || (orig & PTE_UXN) ||
        (orig & PTE_TYPE_MASK) != PTE_TYPE_PAGE) {
        ret = -KPM_E_PERM;
        goto out_close;
    }

    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    ret = wx_arm_locked(pid, mm, pgd, page, orig);
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
    if (ret < 0)
        goto out_close;
    id = (int)ret;
    ret = 0;

out:
    *out_ps = ps;
    *out_task = task;
    *out_mm = mm;
    *out_pgd = pgd;
    *out_id = id;
    return ret;

out_close:
    kpm_mem_close_scan_session(ps, task, mm);
    return ret;
}

long kpm_wx_patch(pid_t pid, uint64_t addr, const void *data, uint32_t len)
{
    void *ps = 0, *task = 0, *mm = 0;
    uint64_t pgd = 0;
    int id = -1, i, slot = -1;
    uint32_t off = (uint32_t)(addr & 0xFFF);
    unsigned long flags;
    long ret;

    if (!data || len == 0 || len > KPM_WX_MAX_PATCH_LEN ||
        off + len > WX_PAGE_SIZE)
        return -KPM_E_INVAL;
    ret = wx_get_page(pid, addr, 1, &ps, &task, &mm, &pgd, &id);
    if (ret)
        return ret;

    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    {
        wx_page_t *e = &g_wx[id];
        if (!e->used) {
            ret = -KPM_E_FAULT;
        } else {
            for (i = 0; i < KPM_WX_MAX_PATCH; i++) {
                if (e->patches[i].len == 0) {
                    slot = i;
                    break;
                }
            }
            if (slot < 0) {
                ret = -KPM_E_NOMEM;
            } else {
                e->patches[slot].off = (uint16_t)off;
                e->patches[slot].len = (uint16_t)len;
                lib_memcpy(e->patches[slot].data, data, len);
                e->nr_patches++;
                /* 已映射时先切原始 r-x 再重建，防目标执行半写入 shadow */
                if (wx_rebuild_safe_locked(e) != 0) {
                    e->patches[slot].len = 0;
                    lib_memset(e->patches[slot].data, 0, len);
                    if (e->nr_patches)
                        e->nr_patches--;
                    ret = -KPM_E_BUSY;
                } else {
                    ret = id;
                }
            }
        }
    }
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
    kpm_mem_close_scan_session(ps, task, mm);
    if (ret >= 0)
        kpm_log_info("wx: patch id=%d pid=%d addr=0x%llx len=%u\n",
                     id, pid, (unsigned long long)addr, len);
    return ret;
}

int kpm_wx_caps(void)
{
    int caps = 0;
    if (kf_do_mem_abort && kf_kmalloc && kf_kfree)
        caps |= 1;
    if ((caps & 1) && kf_do_debug_exception)
        caps |= 2;
    return caps;
}

long kpm_wx_set_bp(pid_t pid, uint64_t addr)
{
    void *ps = 0, *task = 0, *mm = 0;
    uint64_t pgd = 0;
    int id = -1, i, slot = -1;
    unsigned long flags;
    long ret;

    if (!(kpm_wx_caps() & 2))
        return -KPM_E_DISABLED;      /* 4.19 无 step hook 时 BP 不可用 */
    ret = wx_get_page(pid, addr, 1, &ps, &task, &mm, &pgd, &id);
    if (ret)
        return ret;

    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    {
        wx_page_t *e = &g_wx[id];
        for (i = 0; i < KPM_WX_MAX_BPS; i++) {
            if ((e->bps[i].flags & 1) && e->bps[i].addr == addr) {
                kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
                kpm_mem_close_scan_session(ps, task, mm);
                return -KPM_E_BUSY;
            }
            if (!(e->bps[i].flags & 1) && slot < 0)
                slot = i;
        }
        if (slot < 0) {
            ret = -KPM_E_NOMEM;
        } else {
            e->bps[slot].addr = addr;
            e->bps[slot].reg_idx = 0xFF;   /* 未配置寄存器改写 */
            e->bps[slot].value = 0;
            e->bps[slot].flags = 1;
            e->nr_bps++;
            if (wx_rebuild_safe_locked(e) != 0) {
                lib_memset(&e->bps[slot], 0, sizeof(e->bps[slot]));
                if (e->nr_bps)
                    e->nr_bps--;
                ret = -KPM_E_BUSY;
            } else {
                ret = id;
            }
        }
    }
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
    kpm_mem_close_scan_session(ps, task, mm);
    if (ret >= 0)
        kpm_log_info("wx: bp id=%d pid=%d addr=0x%llx\n",
                     id, pid, (unsigned long long)addr);
    return ret;
}

long kpm_wx_set_reg(pid_t pid, uint64_t addr, uint32_t reg_idx, uint64_t value)
{
    void *ps = 0, *task = 0, *mm = 0;
    uint64_t pgd = 0;
    int id = -1, i, found = 0;
    unsigned long flags;
    long ret;

    if (reg_idx > 30)
        return -KPM_E_INVAL;
    ret = wx_get_page(pid, addr, 0, &ps, &task, &mm, &pgd, &id);
    if (ret)
        return ret;
    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    {
        wx_page_t *e = &g_wx[id];
        for (i = 0; i < KPM_WX_MAX_BPS; i++) {
            if ((e->bps[i].flags & 1) && e->bps[i].addr == addr) {
                e->bps[i].reg_idx = reg_idx;
                e->bps[i].value = value;
                found = 1;
                break;
            }
        }
        ret = found ? 0 : -KPM_E_NOTFOUND;
    }
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
    kpm_mem_close_scan_session(ps, task, mm);
    return ret;
}

long kpm_wx_del_bp(pid_t pid, uint64_t addr)
{
    void *ps = 0, *task = 0, *mm = 0;
    uint64_t pgd = 0;
    int id = -1, i, n = 0;
    unsigned long flags;
    long ret;

    if (addr) {
        ret = wx_get_page(pid, addr, 0, &ps, &task, &mm, &pgd, &id);
        if (ret)
            return ret;
        flags = kpm_spin_lock_irqsave(&g_wx_lock);
        {
            wx_page_t *e = &g_wx[id];
            for (i = 0; i < KPM_WX_MAX_BPS; i++) {
                if ((e->bps[i].flags & 1) && e->bps[i].addr == addr) {
                    lib_memset(&e->bps[i], 0, sizeof(e->bps[i]));
                    if (e->nr_bps)
                        e->nr_bps--;
                    n++;
                }
            }
            if (n)
                (void)wx_rebuild_safe_locked(e);
        }
        kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
        kpm_mem_close_scan_session(ps, task, mm);
        return n ? 0 : -KPM_E_NOTFOUND;
    }

    /* addr=0：删除该 pid 的所有断点 */
    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    for (i = 0; i < KPM_WX_MAX_PAGES; i++) {
        wx_page_t *e = &g_wx[i];
        int j;
        if (!e->used || e->pid != pid)
            continue;
        for (j = 0; j < KPM_WX_MAX_BPS; j++) {
            if (e->bps[j].flags & 1) {
                lib_memset(&e->bps[j], 0, sizeof(e->bps[j]));
                n++;
            }
        }
        e->nr_bps = 0;
        (void)wx_rebuild_safe_locked(e);
    }
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
    return n ? 0 : -KPM_E_NOTFOUND;
}

long kpm_wx_release(pid_t pid, uint64_t addr)
{
    void *ps = 0, *task = 0, *mm = 0;
    uint64_t pgd = 0;
    int i, n = 0, busy = 0;
    unsigned long flags;

    if (pid <= 0)
        return -KPM_E_INVAL;
    if (kpm_mem_open_scan_session(pid, &ps, &task, &mm, &pgd) != 0)
        return -KPM_E_NOTFOUND;

    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    for (i = 0; i < KPM_WX_MAX_PAGES; i++) {
        wx_page_t *e = &g_wx[i];
        if (!e->used || e->mm != mm)
            continue;
        if (addr && e->page != (addr & WX_PAGE_MASK))
            continue;
        if (e->state == KPM_WX_ST_STEPPING) {
            busy++;
            continue;
        }
        if (wx_detach_locked(e) == 0) {
            wx_free_locked(e);
            n++;
        } else {
            busy++;
        }
    }
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
    kpm_mem_close_scan_session(ps, task, mm);
    if (busy && !n)
        return -KPM_E_BUSY;
    return n ? n : -KPM_E_NOTFOUND;
}

long kpm_wx_list(kpm_wx_page_info_t *out, int max_count)
{
    unsigned long flags;
    int i, n = 0;

    if (!out || max_count <= 0)
        return -KPM_E_INVAL;
    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    for (i = 0; i < KPM_WX_MAX_PAGES && n < max_count; i++) {
        wx_page_t *e = &g_wx[i];
        if (!e->used)
            continue;
        out[n].id = e->id;
        out[n].pid = e->pid;
        out[n].state = e->state;
        out[n].nr_bps = e->nr_bps;
        out[n].page = e->page;
        out[n].nr_patches = e->nr_patches;
        out[n].hits = e->hits;
        out[n].last_pc = e->last_pc;
        n++;
    }
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
    return n;
}

long kpm_wx_info(kpm_wx_info_t *out)
{
    unsigned long flags;
    int i;

    if (!out)
        return -KPM_E_INVAL;
    lib_memset(out, 0, sizeof(*out));
    out->active = g_wx_active ? 1 : 0;
    out->brk_ok = kf_do_debug_exception ? 1 : 0;
    out->step_ok = kf_do_debug_exception ? 1 : 0;
    out->fault_ok = kf_do_mem_abort ? 1 : 0;
    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    for (i = 0; i < KPM_WX_MAX_PAGES; i++) {
        if (!g_wx[i].used)
            continue;
        out->pages++;
        out->bps += g_wx[i].nr_bps;
        out->patches += g_wx[i].nr_patches;
    }
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
    return 0;
}

/* ========== 生命周期 ========== */

long kpm_wx_init(void)
{
    int caps;

    if (g_wx_active)
        return 0;
    caps = kpm_wx_caps();
    if (!(caps & 1))
        return -KPM_E_DISABLED;

    lib_memset(g_wx, 0, sizeof(g_wx));

    if (hook_wrap((void *)kf_do_mem_abort, 3, (void *)wx_fault_before, 0, 0)
        != HOOK_NO_ERR)
        return -KPM_E_FAULT;
    g_wx_fault_hooked = 1;

    if (kf_exit_mmap) {
        if (hook_wrap((void *)kf_exit_mmap, 1,
                      (void *)wx_exit_mmap_before, 0, 0) == HOOK_NO_ERR)
            g_wx_exit_hooked = 1;
    }

    if (caps & 2) {
        if (hook_wrap((void *)kf_do_debug_exception, 3,
                      (void *)wx_debug_before, 0, 0) == HOOK_NO_ERR)
            g_wx_dbg_hooked = 1;
    }

    g_wx_active = 1;
    kpm_log_info("wx: init caps=%d dbg=%d\n", caps, g_wx_dbg_hooked);
    return 0;
}

void kpm_wx_pre_exit(void)
{
    unsigned long flags;
    int i;

    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    for (i = 0; i < KPM_WX_MAX_PAGES; i++) {
        wx_page_t *e = &g_wx[i];
        if (!e->used)
            continue;
        if (wx_detach_locked(e) == 0) {
            if (e->state == KPM_WX_ST_SHADOW_X ||
                e->state == KPM_WX_ST_STEPPING)
                e->state = KPM_WX_ST_DORMANT;
        } else {
            kpm_log("wx: pre_exit detach failed id=%d (leak)\n", i);
        }
    }
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
}

void kpm_wx_exit(void)
{
    unsigned long flags;
    int i, guard;

    g_wx_active = 0;
    kpm_wx_pre_exit();

    /* 摘 hook / 注销 BRK/step 可能睡眠，不能在 RCU 读临界区执行。 */
    guard = kpm_rcu_exit_guard_acquire();
    if (guard < 0) {
        kpm_log("wx: SKIP teardown in RCU ctx (residual hooks)\n");
        return;
    }
    if (g_wx_exit_hooked && kf_exit_mmap) {
        hook_unwrap((void *)kf_exit_mmap, (void *)wx_exit_mmap_before, 0);
        g_wx_exit_hooked = 0;
    }
    if (g_wx_fault_hooked && kf_do_mem_abort) {
        hook_unwrap((void *)kf_do_mem_abort, (void *)wx_fault_before, 0);
        g_wx_fault_hooked = 0;
    }
    if (g_wx_dbg_hooked && kf_do_debug_exception) {
        hook_unwrap((void *)kf_do_debug_exception,
                    (void *)wx_debug_before, 0);
        g_wx_dbg_hooked = 0;
    }
    if (guard > 0)
        kpm_rcu_exit_guard_release();

    flags = kpm_spin_lock_irqsave(&g_wx_lock);
    for (i = 0; i < KPM_WX_MAX_PAGES; i++) {
        wx_page_t *e = &g_wx[i];
        if (!e->used)
            continue;
        if (wx_detach_locked(e) == 0)
            wx_free_locked(e);
        else
            kpm_log("wx: exit detach failed id=%d (leak)\n", i);
    }
    kpm_spin_unlock_irqrestore(&g_wx_lock, flags);
    kpm_log("wx: exit\n");
}
