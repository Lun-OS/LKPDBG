/* SPDX-License-Identifier: GPL-2.0-or-later */
/* LH_memwatch.c - PTE 内存断点（安全子集 + force 扩展） */
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <hook.h>
#include <pgtable.h>
#include <baselib.h>
#include <linux/string.h>

#include "LH_comm.h"
#include "LH_memwatch.h"
#include "LH_force.h"
#include "LH_mem_rw.h"
#include "LH_syms.h"
#include "LH_utils.h"
#include "LH_log.h"

#define KPM_PT_REGS_PC_OFF (31 * 8 + 8)   /* 256 */
#define KPM_MW_EVENT_MAX 512
#define KPM_MW_PERM_MASK (PTE_RDONLY | PTE_USER | PTE_UXN | PTE_DBM | PTE_CONT)

typedef struct {
    int      used;
    uint32_t id;
    pid_t    pid;
    uint64_t page;
    uint64_t addr;
    uint32_t mode;
    uint32_t flags;
    uint32_t state;
    uint32_t writable;
    uint64_t hits;
    uint64_t pgd_va;
    uint64_t pte_va;
    uint64_t orig_pte;
    void    *pid_struct;
    void    *task;
    void    *mm;
} kpm_mw_entry_t;

static kpm_mw_entry_t g_mw[KPM_MEMWATCH_MAX];
static kpm_spinlock_t g_mw_lock = KPM_SPINLOCK_INIT;
static volatile int g_mw_hook_installed;

static kpm_memwatch_event_t g_mevents[KPM_MW_EVENT_MAX];
static kpm_spinlock_t g_mevent_lock = KPM_SPINLOCK_INIT;
static uint32_t g_mev_head, g_mev_tail, g_mev_count;
static uint64_t g_mev_seq, g_mev_dropped;

static int mw_shift(void)
{
    int s = g_kpm_user_page_shift;
    if (s <= 0 || s > 20)
        s = 12;
    return s;
}

static uint64_t mw_page(uint64_t addr)
{
    return addr & ~((1ULL << mw_shift()) - 1);
}

static void *mw_current_mm(void)
{
    struct task_struct *t;
    unsigned long cur;
    void *mm = 0;

    asm volatile("mrs %0, sp_el0" : "=r"(cur));
    t = (struct task_struct *)cur;
    if (t && (uint64_t)t >= 0xFFFF000000000000ULL && g_mm_offset > 0)
        lib_memcpy(&mm, (const char *)t + g_mm_offset, sizeof(mm));
    return mm;
}

static int32_t mw_current_tid(void)
{
    struct task_struct *t;
    unsigned long cur;
    int32_t tid = 0;

    asm volatile("mrs %0, sp_el0" : "=r"(cur));
    t = (struct task_struct *)cur;
    if (t && (uint64_t)t >= 0xFFFF000000000000ULL && g_pid_offset > 0)
        lib_memcpy(&tid, (const char *)t + g_pid_offset, sizeof(tid));
    return tid;
}

static void mw_write_pte(uint64_t pte_va, uint64_t val)
{
    *(volatile uint64_t *)pte_va = val;
    dsb(ishst);
    flush_tlb_all();
    isb();
}

static uint64_t mw_apply(uint32_t mode, uint64_t pte)
{
    if (mode & KPM_MEMWATCH_MODE_WRITE) {
        /* ARMv8.1 DBM：仅置 AP[2] 不清 DBM 时硬件仍视为可写（DBM 优先，
         * 写不产生 fault → 内存断点永不命中）。
         * 同时清 CONT：连续块内单独改权限是 UNPREDICTABLE。 */
        pte |= PTE_RDONLY;
        pte &= ~PTE_DBM;
        pte &= ~PTE_CONT;
    }
    if (mode & KPM_MEMWATCH_MODE_READ)
        pte &= ~PTE_USER;
    if (mode & KPM_MEMWATCH_MODE_EXEC)
        pte |= PTE_UXN;
    return pte;
}

static uint64_t mw_restore_hit(uint32_t mode, uint64_t pte)
{
    if (mode & KPM_MEMWATCH_MODE_WRITE) {
        pte &= ~PTE_RDONLY;
        pte |= PTE_DBM;      /* 恢复可写（DBM=1 才是 arm64 的 writable） */
    }
    if (mode & KPM_MEMWATCH_MODE_READ)
        pte |= PTE_USER;
    if (mode & KPM_MEMWATCH_MODE_EXEC)
        pte &= ~PTE_UXN;
    return pte;
}

static uint64_t mw_perm_restore(uint64_t cur, uint64_t orig)
{
    return (cur & ~KPM_MW_PERM_MASK) | (orig & KPM_MW_PERM_MASK);
}

static void mw_event_push(const kpm_memwatch_event_t *ev)
{
    unsigned long flags;

    flags = kpm_spin_lock_irqsave(&g_mevent_lock);
    if (g_mev_count >= KPM_MW_EVENT_MAX) {
        g_mev_dropped++;
    } else {
        lib_memcpy(&g_mevents[g_mev_head], ev, sizeof(*ev));
        g_mevents[g_mev_head].seq = ++g_mev_seq;
        g_mev_head = (g_mev_head + 1) % KPM_MW_EVENT_MAX;
        g_mev_count++;
    }
    kpm_spin_unlock_irqrestore(&g_mevent_lock, flags);
}

/* do_mem_abort(addr, esr, regs) before 回调。
 * 只处理权限 fault（FSC 0x0D-0x0F）；命中后恢复 PTE 权限并 skip origin，
 * 让目标指令重试（one-shot；客户端 MEMWATCH_REARM 重新武装）。 */
static void mw_fault_before(hook_fargs4_t *fa, void *udata)
{
    unsigned long addr;
    unsigned int esr;
    void *regs;
    uint32_t ec, fsc, hit_mode = 0;
    int wnr;
    void *mm;
    uint64_t page;
    unsigned long flags;
    int i;
    kpm_memwatch_event_t ev;

    (void)udata;
    if (!fa)
        return;
    addr = (unsigned long)fa->args[0];
    esr = (unsigned int)fa->args[1];
    regs = (void *)fa->args[2];
    ec = (esr >> 26) & 0x3F;
    fsc = esr & 0x3F;
    wnr = (int)((esr >> 6) & 1);
    if (ec != 0x24 && ec != 0x20)
        return;
    if (fsc < 0x0D || fsc > 0x0F)
        return;
    mm = mw_current_mm();
    if (!mm)
        return;
    page = mw_page(addr);

    flags = kpm_spin_lock_irqsave(&g_mw_lock);
    for (i = 0; i < KPM_MEMWATCH_MAX; i++) {
        kpm_mw_entry_t *e = &g_mw[i];
        if (!e->used || e->state != KPM_MEMWATCH_ST_ARMED)
            continue;
        if (e->mm != mm || e->page != page)
            continue;
        if (ec == 0x20) {
            if (e->mode & KPM_MEMWATCH_MODE_EXEC)
                hit_mode = KPM_MEMWATCH_MODE_EXEC;
        } else if (wnr) {
            if (e->mode & KPM_MEMWATCH_MODE_WRITE)
                hit_mode = KPM_MEMWATCH_MODE_WRITE;
            else if ((e->mode & KPM_MEMWATCH_MODE_READ) && e->writable)
                hit_mode = 0;   /* 原本可写的页，写不记读命中，但需放行 */
            else
                continue;       /* 只读页写：交给原 handler（SIGSEGV/COW） */
        } else {
            if (e->mode & KPM_MEMWATCH_MODE_READ)
                hit_mode = KPM_MEMWATCH_MODE_READ;
        }
        if (hit_mode || (ec == 0x24 && wnr &&
                         (e->mode & KPM_MEMWATCH_MODE_READ) && e->writable)) {
            uint64_t cur = *(volatile uint64_t *)e->pte_va;
            uint64_t nw;
            lib_memset(&ev, 0, sizeof(ev));
            ev.ts = kf_ktime_get_ns ? kf_ktime_get_ns() : 0;
            ev.pid = e->pid;
            ev.tid = mw_current_tid();
            ev.addr = addr;
            ev.pc = regs ? ((uint64_t *)regs)[KPM_PT_REGS_PC_OFF / 8] : 0;
            ev.mode = hit_mode;
            if (hit_mode)
                e->hits++;
            ev.hits = e->hits;
            if ((cur & ~KPM_MW_PERM_MASK) != (e->orig_pte & ~KPM_MW_PERM_MASK)) {
                /* PTE 已变化（COW/munmap）：不再武装，恢复权限后放行 */
                nw = mw_perm_restore(cur, e->orig_pte);
                e->state = KPM_MEMWATCH_ST_DISABLED;
            } else {
                nw = mw_restore_hit(e->mode, cur);
                e->state = KPM_MEMWATCH_ST_HIT;   /* one-shot */
            }
            mw_write_pte(e->pte_va, nw);
            fa->skip_origin = 1;
            kpm_spin_unlock_irqrestore(&g_mw_lock, flags);
            if (hit_mode)
                mw_event_push(&ev);
            return;
        }
    }
    kpm_spin_unlock_irqrestore(&g_mw_lock, flags);
}

static int mw_hook_install(void)
{
    if (g_mw_hook_installed)
        return 0;
    if (!kf_do_mem_abort)
        return -KPM_E_DISABLED;
    if (hook_wrap((void *)kf_do_mem_abort, 3, (void *)mw_fault_before, 0, 0)
        != HOOK_NO_ERR)
        return -KPM_E_FAULT;
    g_mw_hook_installed = 1;
    kpm_log("memwatch: do_mem_abort hook installed\n");
    return 0;
}

static void mw_hook_uninstall(void)
{
    if (!g_mw_hook_installed)
        return;
    hook_unwrap((void *)kf_do_mem_abort, (void *)mw_fault_before, 0);
    g_mw_hook_installed = 0;
    kpm_log("memwatch: do_mem_abort hook removed\n");
}

static int mw_has_used(void)
{
    int i;
    for (i = 0; i < KPM_MEMWATCH_MAX; i++)
        if (g_mw[i].used)
            return 1;
    return 0;
}

long kpm_memwatch_set(pid_t pid, uint64_t addr, uint32_t mode,
                      uint32_t flags, uint32_t pages)
{
    void *pid_struct = 0, *task = 0, *mm = 0;
    uint64_t pgd = 0, page, pte;
    uint64_t *pte_va;
    uint32_t level = 0;
    uint64_t pte_addr = 0;
    long ret;
    int i, slot = -1;
    unsigned long lflags;
    int force = (flags & KPM_MEMWATCH_FLAG_FORCE) ||
                (flags & KPM_MEMWATCH_FLAG_RAW_COW) ||
                (flags & KPM_MEMWATCH_FLAG_COARSE);

    (void)pages;
    if (pid <= 0 || !addr || !mode)
        return -KPM_E_INVAL;
    if (mode & ~(KPM_MEMWATCH_MODE_WRITE | KPM_MEMWATCH_MODE_READ |
                 KPM_MEMWATCH_MODE_EXEC))
        return -KPM_E_INVAL;
    if (force && kpm_force_require(KPM_FORCE_MEMWATCH_UNSAFE) < 0)
        return -KPM_E_PERM;

    page = mw_page(addr);
    ret = kpm_mem_open_scan_session(pid, &pid_struct, &task, &mm, &pgd);
    if (ret)
        return ret;
    /* 直接由已持有的 pgd 走页定位 PTE 槽（不用框架 pgtable_entry，
     * 多符号回退：仅依赖 copy_from_kernel_nofault + koffsets）。 */
    ret = kpm_mem_get_pte_va(pgd, page, &pte_addr);
    if (ret < 0)
        goto out_close;
    pte_va = (uint64_t *)pte_addr;
    pte = *(volatile uint64_t *)pte_va;
    (void)level;
    if (!(pte & PTE_VALID) || (pte & PTE_TYPE_MASK) != PTE_TYPE_PAGE) {
        ret = force ? -KPM_E_FAULT : -KPM_E_PERM;
        goto out_close;
    }
    if (!(pte & PTE_USER)) {
        ret = force ? -KPM_E_FAULT : -KPM_E_PERM;
        goto out_close;
    }
    if ((mode & KPM_MEMWATCH_MODE_WRITE) && (pte & PTE_RDONLY) &&
        !(flags & KPM_MEMWATCH_FLAG_RAW_COW)) {
        ret = force ? -KPM_E_DISABLED : -KPM_E_PERM; /* 只读/COW 页写观察 */
        goto out_close;
    }
    if ((mode & KPM_MEMWATCH_MODE_READ) && (pte & PTE_RDONLY) && !force) {
        ret = -KPM_E_PERM;
        goto out_close;
    }
    if ((mode & KPM_MEMWATCH_MODE_EXEC) && (pte & PTE_UXN)) {
        ret = -KPM_E_PERM;
        goto out_close;
    }

    ret = mw_hook_install();
    if (ret < 0)
        goto out_close;

    lflags = kpm_spin_lock_irqsave(&g_mw_lock);
    for (i = 0; i < KPM_MEMWATCH_MAX; i++) {
        if (g_mw[i].used && g_mw[i].pid == pid && g_mw[i].page == page) {
            kpm_spin_unlock_irqrestore(&g_mw_lock, lflags);
            ret = -KPM_E_BUSY;
            goto maybe_unhook;
        }
        if (!g_mw[i].used && slot < 0)
            slot = i;
    }
    if (slot < 0) {
        kpm_spin_unlock_irqrestore(&g_mw_lock, lflags);
        ret = -KPM_E_NOMEM;
        goto maybe_unhook;
    }
    {
        kpm_mw_entry_t *e = &g_mw[slot];
        lib_memset(e, 0, sizeof(*e));
        e->used = 1;
        e->id = (uint32_t)slot;
        e->pid = pid;
        e->page = page;
        e->addr = addr;
        e->mode = mode;
        e->flags = flags;
        e->state = KPM_MEMWATCH_ST_ARMED;
        e->writable = (pte & PTE_RDONLY) ? 0 : 1;
        e->pgd_va = pgd;
        e->pte_va = (uint64_t)pte_va;
        e->orig_pte = pte;
        e->pid_struct = pid_struct;
        e->task = task;
        e->mm = mm;
        mw_write_pte(e->pte_va, mw_apply(mode, pte));
    }
    kpm_spin_unlock_irqrestore(&g_mw_lock, lflags);
    kpm_log("memwatch: set id=%d pid=%d page=0x%llx mode=0x%x flags=0x%x\n",
            slot, pid, (unsigned long long)page, mode, flags);
    return slot;

maybe_unhook:
    if (!mw_has_used())
        mw_hook_uninstall();
out_close:
    kpm_mem_close_scan_session(pid_struct, task, mm);
    return ret;
}

long kpm_memwatch_clear(uint32_t id)
{
    unsigned long flags;
    int i, n = 0;

    if (id == 0xFFFFFFFFu) {
        for (i = 0; i < KPM_MEMWATCH_MAX; i++)
            if (g_mw[i].used)
                n += (kpm_memwatch_clear((uint32_t)i) >= 0) ? 1 : 0;
        return n;
    }
    if (id >= KPM_MEMWATCH_MAX)
        return -KPM_E_INVAL;

    flags = kpm_spin_lock_irqsave(&g_mw_lock);
    if (!g_mw[id].used) {
        kpm_spin_unlock_irqrestore(&g_mw_lock, flags);
        return 0;
    }
    {
        kpm_mw_entry_t *e = &g_mw[id];
        void *ps = e->pid_struct, *tk = e->task, *mm = e->mm;
        if (e->pte_va) {
            uint64_t cur = *(volatile uint64_t *)e->pte_va;
            mw_write_pte(e->pte_va, mw_perm_restore(cur, e->orig_pte));
        }
        e->used = 0;
        e->state = KPM_MEMWATCH_ST_FREE;
        lib_memset(e, 0, sizeof(*e));
        kpm_spin_unlock_irqrestore(&g_mw_lock, flags);
        kpm_mem_close_scan_session(ps, tk, mm);
    }
    if (!mw_has_used())
        mw_hook_uninstall();
    kpm_log("memwatch: clear id=%u\n", id);
    return 0;
}

long kpm_memwatch_rearm(uint32_t id)
{
    unsigned long flags;
    int i, n = 0;

    if (id == 0xFFFFFFFFu) {
        for (i = 0; i < KPM_MEMWATCH_MAX; i++)
            if (g_mw[i].used)
                n += (kpm_memwatch_rearm((uint32_t)i) >= 0) ? 1 : 0;
        return n;
    }
    if (id >= KPM_MEMWATCH_MAX)
        return -KPM_E_INVAL;
    flags = kpm_spin_lock_irqsave(&g_mw_lock);
    if (!g_mw[id].used) {
        kpm_spin_unlock_irqrestore(&g_mw_lock, flags);
        return 0;
    }
    {
        kpm_mw_entry_t *e = &g_mw[id];
        uint64_t pte_addr = 0;
        uint64_t *pte_va;
        uint64_t cur;
        long wret = kpm_mem_get_pte_va(e->pgd_va, e->page, &pte_addr);
        if (wret < 0) {
            e->state = KPM_MEMWATCH_ST_DISABLED;
            kpm_spin_unlock_irqrestore(&g_mw_lock, flags);
            return wret;
        }
        pte_va = (uint64_t *)pte_addr;
        cur = *(volatile uint64_t *)pte_va;
        if (!(cur & PTE_VALID)) {
            e->state = KPM_MEMWATCH_ST_DISABLED;
            kpm_spin_unlock_irqrestore(&g_mw_lock, flags);
            return -KPM_E_FAULT;
        }
        e->pte_va = (uint64_t)pte_va;
        e->orig_pte = cur;
        e->writable = (cur & PTE_RDONLY) ? 0 : 1;
        mw_write_pte(e->pte_va, mw_apply(e->mode, cur));
        e->state = KPM_MEMWATCH_ST_ARMED;
    }
    kpm_spin_unlock_irqrestore(&g_mw_lock, flags);
    kpm_log("memwatch: rearm id=%u\n", id);
    return 0;
}

long kpm_memwatch_list(kpm_memwatch_entry_t *out, int max_count)
{
    unsigned long flags;
    int i, n = 0;

    if (!out || max_count <= 0)
        return -KPM_E_INVAL;
    flags = kpm_spin_lock_irqsave(&g_mw_lock);
    for (i = 0; i < KPM_MEMWATCH_MAX && n < max_count; i++) {
        kpm_mw_entry_t *e = &g_mw[i];
        if (!e->used)
            continue;
        out[n].id = e->id;
        out[n].pid = e->pid;
        out[n].page = e->page;
        out[n].addr = e->addr;
        out[n].mode = e->mode;
        out[n].state = e->state;
        out[n].hits = e->hits;
        out[n].flags = e->flags;
        out[n].reserved = 0;
        n++;
    }
    kpm_spin_unlock_irqrestore(&g_mw_lock, flags);
    return n;
}

long kpm_memwatch_fetch_kernel(void *dst, int max_count)
{
    unsigned long flags;
    int n, i;
    kpm_memwatch_event_t *out = (kpm_memwatch_event_t *)dst;

    if (!dst || max_count <= 0)
        return -KPM_E_INVAL;
    flags = kpm_spin_lock_irqsave(&g_mevent_lock);
    n = (int)g_mev_count;
    if (n > max_count)
        n = max_count;
    for (i = 0; i < n; i++) {
        lib_memcpy(&out[i], &g_mevents[g_mev_tail], sizeof(out[i]));
        g_mev_tail = (g_mev_tail + 1) % KPM_MW_EVENT_MAX;
    }
    g_mev_count -= (uint32_t)n;
    kpm_spin_unlock_irqrestore(&g_mevent_lock, flags);
    return n;
}

long kpm_memwatch_fetch_user(void *dst, int max_count)
{
    kpm_memwatch_event_t tmp[64];
    long n;

    if (!dst || max_count <= 0)
        return -KPM_E_INVAL;
    if (max_count > 64)
        max_count = 64;
    n = kpm_memwatch_fetch_kernel(tmp, max_count);
    if (n > 0) {
        if (!kf_copy_to_user ||
            kf_copy_to_user(dst, tmp,
                            (unsigned long)n * sizeof(kpm_memwatch_event_t)))
            return -KPM_E_FAULT;
    }
    return n;
}

void kpm_memwatch_stop_all(void)
{
    kpm_memwatch_clear(0xFFFFFFFFu);
}

void kpm_memwatch_init(void)
{
    lib_memset(g_mw, 0, sizeof(g_mw));
    lib_memset(g_mevents, 0, sizeof(g_mevents));
    g_mev_head = g_mev_tail = g_mev_count = 0;
    g_mev_seq = g_mev_dropped = 0;
    g_mw_hook_installed = 0;
}

void kpm_memwatch_exit(void)
{
    /* 先恢复全部 PTE（非睡眠），再处理 hook（hook_unwrap 可睡眠）。
     * 三态 RCU 门控：无法确认安全时跳过摘 hook。 */
    int guard;

    kpm_memwatch_stop_all();
    guard = kpm_rcu_exit_guard_acquire();
    if (guard < 0) {
        kpm_log("memwatch: SKIP unhook in RCU ctx (residual)\n");
    } else {
        mw_hook_uninstall();
        if (guard > 0)
            kpm_rcu_exit_guard_release();
    }
    kpm_memwatch_init();
    kpm_log("memwatch: exit\n");
}
