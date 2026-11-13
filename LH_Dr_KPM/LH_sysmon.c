/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_sysmon.c - syscall/ioctl 监控与劫持实现
 */
#include <compiler.h>
#include <kpmodule.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <hook.h>
#include <linux/string.h>
#include <kputils.h>
#include <ksyms.h>
#include <baselib.h>
#include "LH_comm.h"
#include "LH_sysmon.h"
#include "LH_filter.h"
#include "LH_syms.h"
#include "LH_utils.h"
#include "LH_log.h"

#ifndef ENETUNREACH
#define ENETUNREACH 114
#endif

static const int k_mon_nr[] = {
    KPM_SYSMON_NR_IOCTL, KPM_SYSMON_NR_OPENAT, KPM_SYSMON_NR_SOCKET,
    KPM_SYSMON_NR_BIND, KPM_SYSMON_NR_CONNECT, KPM_SYSMON_NR_SENDTO,
    KPM_SYSMON_NR_RECVFROM, KPM_SYSMON_NR_SENDMSG, KPM_SYSMON_NR_RECVMSG,
    KPM_SYSMON_NR_EXECVE,
};
#define KPM_SYSMON_NR_COUNT ((int)(sizeof(k_mon_nr) / sizeof(k_mon_nr[0])))

/* 规则/事件结构定义在 LH_comm.h（与客户端共享），此处仅内核状态 */

static kpm_sysmon_rule_t g_rules[KPM_SYSMON_RULE_MAX];
static kpm_spinlock_t g_sysmon_lock = KPM_SPINLOCK_INIT;
static volatile int g_sysmon_installed = 0;
static volatile int g_sysmon_enabled = 0;
static volatile int g_sysmon_monitor = 0;
static volatile int g_sysmon_inflight = 0;
static volatile int g_sysmon_err_nr = 0;   /* 最近一次 init 失败的 syscall nr */
static uint64_t g_ev_seq = 0;
static volatile uint64_t g_ev_dropped = 0;
static kpm_sysmon_event_t g_ring[KPM_SYSMON_RING_MAX];
static volatile uint32_t g_ring_head;   /* 写入位（spinlock 保护） */

static long sysmon_errno(int mode)
{
    switch (mode) {
    case 1: return -EACCES;
    case 2: return -EPERM;
    default: return -ENETUNREACH;
    }
}

/* 规则匹配（持 g_sysmon_lock 调用）——返回命中的规则，0=无 */
static const kpm_sysmon_rule_t *sysmon_match(uint32_t nr, uint64_t a0,
                                             uint64_t a1)
{
    int i;
    for (i = 0; i < KPM_SYSMON_RULE_MAX; i++) {
        const kpm_sysmon_rule_t *r = &g_rules[i];
        if (!r->used)
            continue;
        if (r->nr != 0 && r->nr != nr)
            continue;
        if (r->cmd_match != 0 && r->cmd_match != a0 && r->cmd_match != a1)
            continue;
        return r;
    }
    return 0;
}

/* before 回调：所有受监控 syscall 共用，udata = 注册时的 syscall nr。
 * 热路径（未命中过滤器）：总开关读 + 位图测试 → 立即返回。 */
static void kpm_sysmon_before(void *fargs, void *udata)
{
    hook_fargs4_t *fa = (hook_fargs4_t *)fargs;
    uint64_t *sa;
    uint64_t a0 = 0, a1 = 0;
    const kpm_sysmon_rule_t *r;
    unsigned long flags;
    uint32_t nr = (uint32_t)(uintptr_t)udata;

    if (!g_sysmon_enabled)
        return;

    g_sysmon_inflight++;
    /* wrapped syscall：syscall_args 解包（写回即改 pt_regs，TAMPER 生效） */
    sa = syscall_args(fargs);
    a0 = sa[0];
    a1 = sa[1];

    if (!kpm_filter_hit())
        goto out;

    flags = kpm_spin_lock_irqsave(&g_sysmon_lock);
    r = sysmon_match(nr, a0, a1);
    if (!r) {
        kpm_spin_unlock_irqrestore(&g_sysmon_lock, flags);
        goto out;
    }
    switch (r->action) {
    case KPM_SYSMON_ACTION_DENY:
        fa->ret = (uint64_t)sysmon_errno((int)r->errno_mode);
        fa->skip_origin = 1;
        break;
    case KPM_SYSMON_ACTION_TAMPER:
        if (r->arg_idx < 6)
            sa[r->arg_idx] = r->arg_value;
        break;
    case KPM_SYSMON_ACTION_MONITOR:
    default: {
        struct task_struct *cur;
        pid_t tg = 0;
        kpm_sysmon_event_t ev;
        if (!g_sysmon_monitor)
            break;
        asm volatile("mrs %0, sp_el0" : "=r"(cur));
        if (cur && (uint64_t)cur >= 0xFFFF000000000000ULL &&
            g_tgid_offset > 0 && g_pid_offset_verified)
            lib_memcpy(&tg, (const void *)((unsigned long)cur + g_tgid_offset),
                       sizeof(tg));
        lib_memset(&ev, 0, sizeof(ev));
        ev.seq = ++g_ev_seq;
        ev.pid = tg;
        ev.uid = (uint32_t)current_uid();
        ev.nr = nr;
        ev.arg_idx_dump = 0xFF;
        ev.arg0 = a0;
        ev.arg1 = a1;
        ev.arg2 = sa[2];
        if (g_ring_head < KPM_SYSMON_RING_MAX) {
            g_ring[g_ring_head++] = ev;
        } else {
            g_ev_dropped++;
        }
        break;
    }
    }
    kpm_spin_unlock_irqrestore(&g_sysmon_lock, flags);

out:
    g_sysmon_inflight--;
}

long kpm_sysmon_init(void)
{
    int i, installed = 0;

    lib_memset(g_rules, 0, sizeof(g_rules));
    g_ring_head = 0;
    g_ev_dropped = 0;
    g_ev_seq = 0;
    g_sysmon_monitor = 0;
    g_sysmon_err_nr = 0;

    /* 共享 filter 的使用者登记（不清规则：netctl 可能已在用） */
    kpm_filter_user_register(KPM_FILTER_USER_SYSMON);

    for (i = 0; i < KPM_SYSMON_NR_COUNT; i++) {
        int err = (int)fp_hook_syscalln(k_mon_nr[i], 6,
                                        kpm_sysmon_before, 0, (void *)(uintptr_t)k_mon_nr[i]);
        if (err != HOOK_NO_ERR) {
            kpm_log("sysmon: hook nr=%d failed (%d)\n", k_mon_nr[i], err);
            g_sysmon_err_nr = k_mon_nr[i];
            for (--i; i >= 0; i--)
                fp_unhook_syscalln(k_mon_nr[i], kpm_sysmon_before, 0);
            kpm_filter_user_unregister(KPM_FILTER_USER_SYSMON);
            return -KPM_E_FAULT;
        }
        installed++;
    }
    g_sysmon_installed = 1;
    kpm_log("sysmon: %d syscalls hooked\n", installed);
    return 0;
}

int kpm_sysmon_last_err_nr(void)
{
    return g_sysmon_err_nr;
}

void kpm_sysmon_exit(void)
{
    int i;
    if (!g_sysmon_installed)
        return;
    g_sysmon_enabled = 0;
    {
        unsigned long spins = 0;
        while (g_sysmon_inflight > 0 && spins++ < 200000000UL)
            asm volatile("yield" ::: "memory");
    }
    for (i = 0; i < KPM_SYSMON_NR_COUNT; i++)
        fp_unhook_syscalln(k_mon_nr[i], kpm_sysmon_before, 0);
    g_sysmon_installed = 0;
    kpm_filter_request_on(KPM_FILTER_USER_SYSMON, 0);
    kpm_filter_user_unregister(KPM_FILTER_USER_SYSMON);
    kpm_log("sysmon: unhooked\n");
}

long kpm_sysmon_set(int enable, uint64_t flags)
{
    if (!g_sysmon_installed)
        return -KPM_E_DISABLED;
    if (enable != 0 && enable != 1)
        return -KPM_E_INVAL;
    g_sysmon_monitor = (flags & 1) ? 1 : 0;
    g_sysmon_enabled = enable ? 1 : 0;
    /* 按使用者请求总开关：netctl 同时开启时不会被本单元关掉 */
    kpm_filter_request_on(KPM_FILTER_USER_SYSMON, enable);
    return 0;
}

long kpm_sysmon_rule(int op, uint64_t packed, uint64_t cmd_match,
                     uint64_t arg_value)
{
    unsigned long flags;
    int i;
    uint32_t nr = (uint32_t)(packed & 0xFFFF);
    uint32_t action = (uint32_t)((packed >> 16) & 0xFF);
    uint32_t arg_idx = (uint32_t)((packed >> 24) & 0xF);
    uint32_t errno_mode = (uint32_t)((packed >> 28) & 0xF);

    if (!g_sysmon_installed)
        return -KPM_E_DISABLED;

    flags = kpm_spin_lock_irqsave(&g_sysmon_lock);
    switch (op) {
    case 0: /* add */
        for (i = 0; i < KPM_SYSMON_RULE_MAX; i++) {
            if (!g_rules[i].used) {
                g_rules[i].used = 1;
                g_rules[i].nr = nr;
                g_rules[i].action = action;
                g_rules[i].arg_idx = arg_idx;
                g_rules[i].errno_mode = errno_mode;
                g_rules[i].cmd_match = cmd_match;
                g_rules[i].arg_value = arg_value;
                kpm_spin_unlock_irqrestore(&g_sysmon_lock, flags);
                return i;
            }
        }
        kpm_spin_unlock_irqrestore(&g_sysmon_lock, flags);
        return -KPM_E_NOMEM;
    case 1: /* del（按槽位 id = arg_value） */
        i = (int)arg_value;
        if (i < 0 || i >= KPM_SYSMON_RULE_MAX || !g_rules[i].used) {
            kpm_spin_unlock_irqrestore(&g_sysmon_lock, flags);
            return -KPM_E_NOTFOUND;
        }
        lib_memset(&g_rules[i], 0, sizeof(g_rules[i]));
        kpm_spin_unlock_irqrestore(&g_sysmon_lock, flags);
        return 0;
    case 2: /* clear */
        lib_memset(g_rules, 0, sizeof(g_rules));
        kpm_spin_unlock_irqrestore(&g_sysmon_lock, flags);
        return 0;
    default:
        kpm_spin_unlock_irqrestore(&g_sysmon_lock, flags);
        return -KPM_E_INVAL;
    }
}

long kpm_sysmon_fetch_kernel(void *kbuf, int max_count, uint64_t *dropped)
{
    unsigned long flags;
    uint32_t n, i;
    kpm_sysmon_event_t *out = (kpm_sysmon_event_t *)kbuf;

    if (!kbuf || max_count <= 0)
        return -KPM_E_INVAL;
    if ((uint64_t)max_count * sizeof(kpm_sysmon_event_t) > 0x10000)
        max_count = 0x10000 / (int)sizeof(kpm_sysmon_event_t);

    flags = kpm_spin_lock_irqsave(&g_sysmon_lock);
    n = g_ring_head;
    if (n > (uint32_t)max_count)
        n = (uint32_t)max_count;
    for (i = 0; i < n; i++)
        out[i] = g_ring[i];
    /* 环压缩：取走前 n 条后左移 */
    for (i = 0; i + n < g_ring_head; i++)
        g_ring[i] = g_ring[i + n];
    g_ring_head -= n;
    if (dropped)
        *dropped = g_ev_dropped;
    kpm_spin_unlock_irqrestore(&g_sysmon_lock, flags);
    return (long)n;
}

long kpm_sysmon_fetch(void *user_buf, int max_count, uint64_t *dropped)
{
    kpm_sysmon_event_t arr[16];
    long n;

    if (!user_buf)
        return -KPM_E_INVAL;
    if (max_count > 16)
        max_count = 16;
    n = kpm_sysmon_fetch_kernel(arr, max_count, dropped);
    if (n > 0) {
        if (!kf_copy_to_user ||
            kf_copy_to_user(user_buf, arr,
                            (unsigned long)n * sizeof(kpm_sysmon_event_t)))
            return -KPM_E_FAULT;
    }
    return n;
}

long kpm_sysmon_rules_list_kernel(void *kbuf, int max_count)
{
    kpm_sysmon_rule_t out[KPM_SYSMON_RULE_MAX];
    unsigned long flags;
    int i, n = 0;

    if (!kbuf || max_count <= 0)
        return -KPM_E_INVAL;
    if (max_count > KPM_SYSMON_RULE_MAX)
        max_count = KPM_SYSMON_RULE_MAX;
    flags = kpm_spin_lock_irqsave(&g_sysmon_lock);
    for (i = 0; i < KPM_SYSMON_RULE_MAX && n < max_count; i++) {
        if (g_rules[i].used) {
            out[n++] = g_rules[i];
        }
    }
    kpm_spin_unlock_irqrestore(&g_sysmon_lock, flags);
    lib_memcpy(kbuf, out, (unsigned long)n * sizeof(kpm_sysmon_rule_t));
    return n;
}

long kpm_sysmon_rules_list(void *user_buf, int max_count)
{
    kpm_sysmon_rule_t out[KPM_SYSMON_RULE_MAX];
    long n;

    if (!user_buf)
        return -KPM_E_INVAL;
    n = kpm_sysmon_rules_list_kernel(out, max_count);
    if (n > 0) {
        if (!kf_copy_to_user ||
            kf_copy_to_user(user_buf, out,
                            (unsigned long)n * sizeof(kpm_sysmon_rule_t)))
            return -KPM_E_FAULT;
    }
    return n;
}
