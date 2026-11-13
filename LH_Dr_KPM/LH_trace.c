/* SPDX-License-Identifier: GPL-2.0-or-later */
/* LH_trace.c - 全量 trace：通用 ring + 全 syscall + 内核函数 */
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <hook.h>
#include <pgtable.h>
#include <baselib.h>
#include <asm/ptrace.h>   /* struct pt_regs（tracepoint 回调签名） */
#include <linux/string.h>

#include "LH_comm.h"
#include "LH_trace.h"
#include "LH_force.h"
#include "LH_syms.h"
#include "LH_utils.h"
#include "LH_log.h"

#define KPM_TRACE_ENTER_SLOTS 128
#define KPM_TIF_SYSCALL_TRACEPOINT 10

typedef struct {
    int      used;
    int32_t  tid;
    uint64_t ts;
    uint32_t nr;
    uint64_t args[6];
} kpm_trace_enter_t;

typedef struct {
    int      used;
    kpm_trace_kfunc_cfg_t cfg;
} kpm_trace_kfunc_t;

static kpm_trace_event_t g_events[KPM_TRACE_MAX_EVENTS];
static kpm_spinlock_t g_trace_lock = KPM_SPINLOCK_INIT;
static uint32_t g_head, g_tail, g_count;
static uint64_t g_seq, g_dropped;
static volatile int g_sys_active;
static volatile int g_sys_ok;
static int32_t g_filter_pid;
static uint32_t g_filter_uid = 0xFFFFFFFFu;
static uint64_t g_filter_nrmask;
static kpm_trace_enter_t g_enter[KPM_TRACE_ENTER_SLOTS];
static kpm_trace_kfunc_t g_kfunc[KPM_TRACE_KT_FUNC_MAX];
static int g_kfunc_count;
static volatile int g_active_mode = -1;

static uint64_t trace_now_ns(void)
{
    if (kf_ktime_get_ns)
        return kf_ktime_get_ns();
    if (kf_jiffies)
        return (uint64_t)(*kf_jiffies) * 10000000ULL;
    return 0;
}

static void trace_identity(int32_t *tgid, int32_t *tid, uint32_t *uid)
{
    struct task_struct *t;
    unsigned long cur;

    asm volatile("mrs %0, sp_el0" : "=r"(cur));
    t = (struct task_struct *)cur;
    *tgid = 0;
    *tid = 0;
    *uid = (uint32_t)current_uid();
    if (t && (uint64_t)t >= 0xFFFF000000000000ULL) {
        if (g_tgid_offset > 0)
            lib_memcpy(tgid, (const char *)t + g_tgid_offset, sizeof(*tgid));
        if (g_pid_offset > 0)
            lib_memcpy(tid, (const char *)t + g_pid_offset, sizeof(*tid));
    }
}

void kpm_trace_push(const kpm_trace_event_t *ev)
{
    unsigned long flags;

    if (!ev)
        return;
    flags = kpm_spin_lock_irqsave(&g_trace_lock);
    if (g_count >= KPM_TRACE_MAX_EVENTS) {
        g_dropped++;
    } else {
        lib_memcpy(&g_events[g_head], ev, sizeof(*ev));
        if (g_events[g_head].seq == 0)
            g_events[g_head].seq = ++g_seq;
        g_head = (g_head + 1) % KPM_TRACE_MAX_EVENTS;
        g_count++;
    }
    kpm_spin_unlock_irqrestore(&g_trace_lock, flags);
}

static int trace_filter_ok(int32_t tgid, int32_t tid, uint32_t uid, uint32_t nr)
{
    if (g_filter_pid && tgid != g_filter_pid && tid != g_filter_pid)
        return 0;
    if (g_filter_uid != 0xFFFFFFFFu && uid != g_filter_uid)
        return 0;
    if (g_filter_nrmask && nr < 64 && !(g_filter_nrmask & (1ULL << nr)))
        return 0;
    return 1;
}

static void trace_enter_store(int32_t tid, uint32_t nr, const uint64_t *args)
{
    uint32_t start = (uint32_t)tid & (KPM_TRACE_ENTER_SLOTS - 1);
    int i;

    for (i = 0; i < KPM_TRACE_ENTER_SLOTS; i++) {
        kpm_trace_enter_t *s = &g_enter[(start + i) & (KPM_TRACE_ENTER_SLOTS - 1)];
        if (!s->used || s->tid == tid) {
            s->used = 1;
            s->tid = tid;
            s->ts = trace_now_ns();
            s->nr = nr;
            lib_memcpy(s->args, args, sizeof(s->args));
            return;
        }
    }
}

static int trace_enter_take(int32_t tid, kpm_trace_enter_t *out)
{
    uint32_t start = (uint32_t)tid & (KPM_TRACE_ENTER_SLOTS - 1);
    int i;

    for (i = 0; i < KPM_TRACE_ENTER_SLOTS; i++) {
        kpm_trace_enter_t *s = &g_enter[(start + i) & (KPM_TRACE_ENTER_SLOTS - 1)];
        if (s->used && s->tid == tid) {
            lib_memcpy(out, s, sizeof(*out));
            s->used = 0;
            return 0;
        }
    }
    return -1;
}

/* ===== sys_enter / sys_exit tracepoint ===== */
static void kpm_trace_sys_enter_cb(void *data, struct pt_regs *regs, long id)
{
    kpm_trace_event_t ev;
    int32_t tgid, tid;
    uint32_t uid;

    (void)data;
    if (!g_sys_active || !regs || id < 0)
        return;
    trace_identity(&tgid, &tid, &uid);
    if (!trace_filter_ok(tgid, tid, uid, (uint32_t)id))
        return;
    trace_enter_store(tid, (uint32_t)id, (const uint64_t *)regs);
    /* ENTER 即入环：不依赖 sys_exit tracepoint（4.19 上 exit 可能缺失），
     * 即使 syscall 不返回也能看到进入事件；退出事件带 ret 另成一条。 */
    lib_memset(&ev, 0, sizeof(ev));
    ev.ts = trace_now_ns();
    ev.type = KPM_TRACE_TYPE_SYSCALL;
    ev.pid = tgid;
    ev.tid = tid;
    ev.uid = uid;
    ev.nr = (uint32_t)id;
    ev.flags = KPM_TRACE_FLAG_ENTER;
    lib_memcpy(ev.args, regs, sizeof(ev.args));
    kpm_trace_push(&ev);
}

static void kpm_trace_sys_exit_cb(void *data, struct pt_regs *regs, long ret)
{
    kpm_trace_enter_t e;
    kpm_trace_event_t ev;
    int32_t tgid, tid;
    uint32_t uid;

    (void)data;
    if (!g_sys_active || !regs)
        return;
    trace_identity(&tgid, &tid, &uid);
    if (trace_enter_take(tid, &e) != 0)
        return;
    lib_memset(&ev, 0, sizeof(ev));
    ev.ts = trace_now_ns();
    ev.type = KPM_TRACE_TYPE_SYSCALL;
    ev.pid = tgid;
    ev.tid = tid;
    ev.uid = uid;
    ev.nr = e.nr;
    ev.flags = KPM_TRACE_FLAG_EXIT;
    lib_memcpy(ev.args, e.args, sizeof(ev.args));
    ev.ret = ret;
    kpm_trace_push(&ev);
}

static inline void trace_tif_set_bit(unsigned long *addr, int bit)
{
    unsigned long old;
    unsigned long mask = 1UL << bit;

    asm volatile(
        "1: ldxr %0, [%1]\n"
        "   orr  %0, %0, %2\n"
        "   stxr w2, %0, [%1]\n"
        "   cbnz w2, 1b\n"
        : "=&r"(old)
        : "r"(addr), "r"(mask)
        : "memory", "w2");
}

static void trace_tif_set_all(void)
{
    int pid, lim;

    if (!kpm_task_fetch_available())
        return;
    lim = kpm_pid_max();
    for (pid = 1; pid < lim; pid++) {
        struct task_struct *t;
        int needs_put = 0;
        if (kpm_task_acquire(pid, &t, &needs_put) != 0)
            continue;
        trace_tif_set_bit((unsigned long *)t, KPM_TIF_SYSCALL_TRACEPOINT);
        if (needs_put)
            kpm_put_task_struct(t);
        else
            kpm_task_end();
    }
}

static void kpm_trace_fork_cb(void *data, void *parent, void *child)
{
    (void)data;
    (void)parent;
    if (g_sys_active && child)
        trace_tif_set_bit((unsigned long *)child, KPM_TIF_SYSCALL_TRACEPOINT);
}

static long trace_sys_start(int32_t pid_filter, uint32_t uid_filter,
                            const kpm_trace_syscall_cfg_t *cfg)
{
    if (!kf_tp_sys_enter || !kf_tracepoint_probe_register ||
        !kf_tracepoint_probe_unregister)
        return -KPM_E_NOTFOUND;
    if (g_sys_active)
        return 0;

    g_filter_pid = pid_filter;
    g_filter_uid = (uid_filter == 0) ? 0xFFFFFFFFu : uid_filter;
    g_filter_nrmask = cfg ? cfg->nr_mask : 0;
    g_active_mode = KPM_TRACE_MODE_SYSCALL;
    g_sys_active = 1;
    g_sys_ok = 0;

    if (kf_tracepoint_probe_register(kf_tp_sys_enter,
                                     (void *)kpm_trace_sys_enter_cb,
                                     NULL) != 0) {
        g_sys_active = 0;
        return -KPM_E_NOTFOUND;
    }
    g_sys_ok = 1;
    if (kf_tp_sys_exit &&
        kf_tracepoint_probe_register(kf_tp_sys_exit,
                                     (void *)kpm_trace_sys_exit_cb,
                                     NULL) == 0)
        g_sys_ok = 2;
    if (kf_tp_sched_fork)
        kf_tracepoint_probe_register(kf_tp_sched_fork,
                                     (void *)kpm_trace_fork_cb, NULL);
    trace_tif_set_all();
    kpm_log("trace: syscall trace registered (enter=%d exit=%d)\n",
            !!(g_sys_ok & 1), g_sys_ok == 2);
    return 0;
}

static void trace_sys_stop(void)
{
    if (!g_sys_active)
        return;
    g_sys_active = 0;
    if (kf_tracepoint_probe_unregister) {
        if (kf_tp_sys_enter)
            kf_tracepoint_probe_unregister(kf_tp_sys_enter,
                                           (void *)kpm_trace_sys_enter_cb,
                                           NULL);
        if (kf_tp_sys_exit)
            kf_tracepoint_probe_unregister(kf_tp_sys_exit,
                                           (void *)kpm_trace_sys_exit_cb,
                                           NULL);
        if (kf_tp_sched_fork)
            kf_tracepoint_probe_unregister(kf_tp_sched_fork,
                                           (void *)kpm_trace_fork_cb, NULL);
        if (kf_tracepoint_synchronize_unregister)
            kf_tracepoint_synchronize_unregister();
    }
    lib_memset(g_enter, 0, sizeof(g_enter));
    g_sys_ok = 0;
    kpm_log("trace: syscall trace stopped\n");
}

/* ===== 内核函数 trace ===== */
static void kpm_trace_kfunc_before(void *fargs, void *udata)
{
    hook_fargs8_t *fa = (hook_fargs8_t *)fargs;
    kpm_trace_event_t ev;
    int id = (int)(uintptr_t)udata;
    int32_t tgid, tid;
    uint32_t uid;
    int j;

    if (id < 0 || id >= KPM_TRACE_KT_FUNC_MAX || !g_kfunc[id].used)
        return;
    trace_identity(&tgid, &tid, &uid);
    lib_memset(&ev, 0, sizeof(ev));
    ev.ts = trace_now_ns();
    ev.type = KPM_TRACE_TYPE_KFUNC;
    ev.pid = tgid;
    ev.tid = tid;
    ev.uid = uid;
    ev.nr = (uint32_t)id;
    ev.flags = KPM_TRACE_FLAG_ENTER;
    ev.aux = g_kfunc[id].cfg.func_addr;
    for (j = 0; j < g_kfunc[id].cfg.argno && j < 6; j++)
        ev.args[j] = fa->args[j];
    kpm_trace_push(&ev);
}

static void kpm_trace_kfunc_after(void *fargs, void *udata)
{
    hook_fargs8_t *fa = (hook_fargs8_t *)fargs;
    kpm_trace_event_t ev;
    int id = (int)(uintptr_t)udata;
    int32_t tgid, tid;
    uint32_t uid;

    if (id < 0 || id >= KPM_TRACE_KT_FUNC_MAX || !g_kfunc[id].used)
        return;
    trace_identity(&tgid, &tid, &uid);
    lib_memset(&ev, 0, sizeof(ev));
    ev.ts = trace_now_ns();
    ev.type = KPM_TRACE_TYPE_KFUNC;
    ev.pid = tgid;
    ev.tid = tid;
    ev.uid = uid;
    ev.nr = (uint32_t)id;
    ev.flags = KPM_TRACE_FLAG_EXIT;
    ev.aux = g_kfunc[id].cfg.func_addr;
    ev.ret = (int64_t)fa->ret;
    kpm_trace_push(&ev);
}

static long trace_kfunc_add(uint64_t func_addr, int argno, int force_hot)
{
    int i, id = -1;
    hook_err_t err;

    if (!func_addr || (func_addr & 0x3) || argno < 0 || argno > 6)
        return -KPM_E_INVAL;
    if (!is_kimg_range(func_addr))
        return -KPM_E_PERM;
    if (force_hot && kpm_force_require(KPM_FORCE_HOT_TRACE) < 0)
        return -KPM_E_PERM;
    for (i = 0; i < KPM_TRACE_KT_FUNC_MAX; i++) {
        if (g_kfunc[i].used && g_kfunc[i].cfg.func_addr == func_addr)
            return -KPM_E_BUSY;
        if (!g_kfunc[i].used && id < 0)
            id = i;
    }
    if (id < 0)
        return -KPM_E_NOMEM;
    g_kfunc[id].used = 1;
    g_kfunc[id].cfg.func_addr = func_addr;
    g_kfunc[id].cfg.argno = argno;
    g_kfunc[id].cfg.flags = force_hot ? 1u : 0u;
    g_kfunc[id].cfg.id = (uint32_t)id;
    err = hook_wrap((void *)(uintptr_t)func_addr, argno,
                    kpm_trace_kfunc_before, kpm_trace_kfunc_after,
                    (void *)(uintptr_t)id);
    if (err != HOOK_NO_ERR) {
        lib_memset(&g_kfunc[id], 0, sizeof(g_kfunc[id]));
        return -KPM_E_NOTFOUND;
    }
    g_kfunc_count++;
    g_active_mode = KPM_TRACE_MODE_KFUNC;
    kpm_log("trace: kfunc hook id=%d addr=0x%llx argno=%d\n",
            id, (unsigned long long)func_addr, argno);
    return id;
}

static void trace_kfunc_del(int id)
{
    if (id < 0 || id >= KPM_TRACE_KT_FUNC_MAX || !g_kfunc[id].used)
        return;
    hook_unwrap((void *)(uintptr_t)g_kfunc[id].cfg.func_addr,
                kpm_trace_kfunc_before, kpm_trace_kfunc_after);
    lib_memset(&g_kfunc[id], 0, sizeof(g_kfunc[id]));
    if (g_kfunc_count)
        g_kfunc_count--;
    kpm_log("trace: kfunc unhook id=%d\n", id);
}

static void trace_kfunc_stop_all(void)
{
    int i;
    for (i = 0; i < KPM_TRACE_KT_FUNC_MAX; i++)
        if (g_kfunc[i].used)
            trace_kfunc_del(i);
    g_kfunc_count = 0;
}

long kpm_trace_control(int op, int mode, int32_t pid_filter,
                       uint32_t uid_filter, uint64_t func_addr,
                       int argno, const void *cfg, uint32_t cfg_len,
                       int force_hot)
{
    if (op == KPM_TRACE_OP_CLEAR) {
        unsigned long flags = kpm_spin_lock_irqsave(&g_trace_lock);
        g_head = g_tail = g_count = 0;
        kpm_spin_unlock_irqrestore(&g_trace_lock, flags);
        lib_memset(g_enter, 0, sizeof(g_enter));
        return 0;
    }
    if (op == KPM_TRACE_OP_STOP) {
        if (mode == KPM_TRACE_MODE_SYSCALL || mode < 0)
            trace_sys_stop();
        if (mode == KPM_TRACE_MODE_KFUNC || mode < 0)
            trace_kfunc_stop_all();
        return 0;
    }
    if (op != KPM_TRACE_OP_SET)
        return -KPM_E_INVAL;

    if (mode == KPM_TRACE_MODE_SYSCALL) {
        kpm_trace_syscall_cfg_t sc;
        const kpm_trace_syscall_cfg_t *p = NULL;
        if (cfg && cfg_len >= sizeof(sc)) {
            lib_memcpy(&sc, cfg, sizeof(sc));
            p = &sc;
        }
        return trace_sys_start(pid_filter, uid_filter, p);
    }
    if (mode == KPM_TRACE_MODE_KFUNC) {
        if (cfg && cfg_len >= sizeof(kpm_trace_kfunc_cfg_t)) {
            kpm_trace_kfunc_cfg_t kc;
            lib_memcpy(&kc, cfg, sizeof(kc));
            func_addr = kc.func_addr;
            argno = kc.argno;
            force_hot = (kc.flags & 1) ? 1 : force_hot;
        }
        return trace_kfunc_add(func_addr, argno, force_hot);
    }
    return -KPM_E_INVAL;
}

long kpm_trace_fetch_kernel(void *dst, int max_count)
{
    unsigned long flags;
    int n, i;
    kpm_trace_event_t *out = (kpm_trace_event_t *)dst;

    if (!dst || max_count <= 0)
        return -KPM_E_INVAL;
    flags = kpm_spin_lock_irqsave(&g_trace_lock);
    n = (int)g_count;
    if (n > max_count)
        n = max_count;
    for (i = 0; i < n; i++) {
        lib_memcpy(&out[i], &g_events[g_tail], sizeof(out[i]));
        g_tail = (g_tail + 1) % KPM_TRACE_MAX_EVENTS;
    }
    g_count -= (uint32_t)n;
    kpm_spin_unlock_irqrestore(&g_trace_lock, flags);
    return n;
}

long kpm_trace_fetch_user(void *dst, int max_count)
{
    kpm_trace_event_t tmp[32];
    long n;

    if (!dst || max_count <= 0)
        return -KPM_E_INVAL;
    if (max_count > 32)
        max_count = 32;
    n = kpm_trace_fetch_kernel(tmp, max_count);
    if (n > 0) {
        if (!kf_copy_to_user ||
            kf_copy_to_user(dst, tmp,
                            (unsigned long)n * sizeof(kpm_trace_event_t)))
            return -KPM_E_FAULT;
    }
    return n;
}

long kpm_trace_info(kpm_trace_info_t *out)
{
    unsigned long flags;

    if (!out)
        return -KPM_E_INVAL;
    lib_memset(out, 0, sizeof(*out));
    flags = kpm_spin_lock_irqsave(&g_trace_lock);
    out->active = (g_sys_active || g_kfunc_count) ? 1 : 0;
    out->mode = (g_active_mode < 0) ? 0 : (uint32_t)g_active_mode;
    out->capacity = KPM_TRACE_MAX_EVENTS;
    out->events = g_count;
    out->dropped = g_dropped;
    out->kfunc_hooks = (uint32_t)g_kfunc_count;
    out->syscall_ok = (uint32_t)g_sys_ok;
    out->force_hot = (kpm_force_active() &&
                      (kpm_force_mask() & KPM_FORCE_HOT_TRACE)) ? 1 : 0;
    kpm_spin_unlock_irqrestore(&g_trace_lock, flags);
    return 0;
}

void kpm_trace_init(void)
{
    lib_memset(g_events, 0, sizeof(g_events));
    lib_memset(g_enter, 0, sizeof(g_enter));
    lib_memset(g_kfunc, 0, sizeof(g_kfunc));
    g_head = g_tail = g_count = 0;
    g_seq = g_dropped = 0;
    g_sys_active = 0;
    g_sys_ok = 0;
    g_kfunc_count = 0;
    g_active_mode = -1;
    g_filter_pid = 0;
    g_filter_uid = 0xFFFFFFFFu;
    g_filter_nrmask = 0;
}

void kpm_trace_exit(void)
{
    /* tracepoint_probe_unregister / hook_unwrap 可睡眠，exit 可能在 RCU
     * 读临界区内调用。三态门控：借出锁→可清理，确认不在临界区→可清理，
     * 无法确认→跳过（泄漏可接受，死锁不可接受）。 */
    int guard = kpm_rcu_exit_guard_acquire();

    if (guard < 0) {
        kpm_log("trace: SKIP teardown in RCU ctx (residual hooks)\n");
        return;
    }
    trace_sys_stop();
    trace_kfunc_stop_all();
    kpm_trace_init();
    if (guard > 0)
        kpm_rcu_exit_guard_release();
    kpm_log("trace: exit\n");
}
