/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_filter.c - uid/pid 快速过滤器实现（禁网 / sysmon 共用）
 * 详见 LH_filter.h。
 */
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/string.h>
#include <ksyms.h>
#include <baselib.h>
#include "LH_comm.h"
#include "LH_filter.h"
#include "LH_syms.h"
#include "LH_utils.h"
#include "LH_log.h"

typedef struct {
    kpm_spinlock_t lock;
    volatile int on;                                  /* 总开关（READ_ONCE 语义） */
    volatile uint32_t users;                          /* 已注册使用者位图 */
    volatile uint32_t on_mask;                        /* 请求 on 的使用者位图 */
    volatile int all_apps;                            /* 1=匹配全部 app uid */
    uint8_t uid_bits[KPM_FILTER_UID_RANGE / 8];       /* 1250B 位图 */
    volatile uint32_t uid_count;
    pid_t pids[KPM_FILTER_PID_MAX];
    volatile uint32_t pid_count;
} kpm_filter_t;

/* BSS 零初始化：locked=0（未锁）、on=0、users/on_mask=0。
 * 模块 init 时 kpm_filter_init() 再显式重置一次。 */
static kpm_filter_t g_filter;

long kpm_filter_init(void)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_filter.lock);
    lib_memset((void *)g_filter.uid_bits, 0, sizeof(g_filter.uid_bits));
    lib_memset((void *)g_filter.pids, 0, sizeof(g_filter.pids));
    g_filter.uid_count = 0;
    g_filter.pid_count = 0;
    g_filter.all_apps = 0;
    g_filter.on = 0;
    g_filter.users = 0;
    g_filter.on_mask = 0;
    kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
    return 0;
}

int kpm_filter_hit(void)
{
    kpm_filter_t *f = &g_filter;
    uint64_t uid;
    struct task_struct *cur;
    pid_t tg;
    uint32_t i;

    if (!f->on)
        return 0;                        /* 最快路径：一次读 */

    uid = current_uid();
    if (uid >= KPM_FILTER_UID_BASE && uid < KPM_FILTER_UID_BASE + KPM_FILTER_UID_RANGE) {
        if (f->all_apps)
            return 1;
        {
            uint32_t off = (uint32_t)(uid - KPM_FILTER_UID_BASE);
            if (f->uid_bits[off >> 3] & (1u << (off & 7)))
                return 1;
        }
    }

    /* pid/tgid 表：current 自身 task_struct 直接读（安全）；
     * 偏移未验证时不走该路径（稳定性红线：不盲读偏移） */
    if (g_tgid_offset > 0 && g_pid_offset_verified) {
        asm volatile("mrs %0, sp_el0" : "=r"(cur));
        if (cur && (uint64_t)cur >= 0xFFFF000000000000ULL) {
            lib_memcpy(&tg, (const void *)((unsigned long)cur + g_tgid_offset),
                       sizeof(tg));
            if (tg > 0 && f->pid_count) {
                for (i = 0; i < f->pid_count; i++)
                    if (f->pids[i] == tg)
                        return 1;
            }
        }
    }
    return 0;
}

long kpm_filter_uid_add(uint64_t uid)
{
    unsigned long flags;
    if (uid == 0) {
        flags = kpm_spin_lock_irqsave(&g_filter.lock);
        g_filter.all_apps = 1;
        kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
        return 0;
    }
    if (uid < KPM_FILTER_UID_BASE ||
        uid >= KPM_FILTER_UID_BASE + KPM_FILTER_UID_RANGE)
        return -KPM_E_INVAL;             /* 仅 app uid 段可操作（稳定性红线） */
    {
        uint32_t off = (uint32_t)(uid - KPM_FILTER_UID_BASE);
        flags = kpm_spin_lock_irqsave(&g_filter.lock);
        if (!(g_filter.uid_bits[off >> 3] & (1u << (off & 7)))) {
            g_filter.uid_bits[off >> 3] |= (1u << (off & 7));
            g_filter.uid_count++;
        }
        kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
    }
    return 0;
}

long kpm_filter_uid_del(uint64_t uid)
{
    unsigned long flags;
    if (uid == 0) {
        flags = kpm_spin_lock_irqsave(&g_filter.lock);
        g_filter.all_apps = 0;
        kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
        return 0;
    }
    if (uid < KPM_FILTER_UID_BASE ||
        uid >= KPM_FILTER_UID_BASE + KPM_FILTER_UID_RANGE)
        return -KPM_E_INVAL;
    {
        uint32_t off = (uint32_t)(uid - KPM_FILTER_UID_BASE);
        flags = kpm_spin_lock_irqsave(&g_filter.lock);
        if (g_filter.uid_bits[off >> 3] & (1u << (off & 7))) {
            g_filter.uid_bits[off >> 3] &= ~(1u << (off & 7));
            if (g_filter.uid_count)
                g_filter.uid_count--;
        }
        kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
    }
    return 0;
}

long kpm_filter_pid_add(uint64_t pid)
{
    unsigned long flags;
    uint32_t i;
    if (pid <= 0 || pid > 0x7FFFFFFF)
        return -KPM_E_INVAL;
    flags = kpm_spin_lock_irqsave(&g_filter.lock);
    for (i = 0; i < g_filter.pid_count; i++)
        if (g_filter.pids[i] == (pid_t)pid) {
            kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
            return 0;
        }
    if (g_filter.pid_count >= KPM_FILTER_PID_MAX) {
        kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
        return -KPM_E_NOMEM;
    }
    g_filter.pids[g_filter.pid_count++] = (pid_t)pid;
    kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
    return 0;
}

long kpm_filter_pid_del(uint64_t pid)
{
    unsigned long flags;
    uint32_t i, j;
    flags = kpm_spin_lock_irqsave(&g_filter.lock);
    for (i = 0; i < g_filter.pid_count; i++) {
        if (g_filter.pids[i] == (pid_t)pid) {
            for (j = i; j + 1 < g_filter.pid_count; j++)
                g_filter.pids[j] = g_filter.pids[j + 1];
            g_filter.pid_count--;
            break;
        }
    }
    kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
    return 0;
}

long kpm_filter_clear(void)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_filter.lock);
    lib_memset((void *)g_filter.uid_bits, 0, sizeof(g_filter.uid_bits));
    lib_memset((void *)g_filter.pids, 0, sizeof(g_filter.pids));
    g_filter.uid_count = 0;
    g_filter.pid_count = 0;
    g_filter.all_apps = 0;
    kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
    return 0;
}

long kpm_filter_rule(int op, int type, uint64_t value)
{
    switch (op) {
    case 0:
        if (type == 0) return kpm_filter_uid_add(value);
        if (type == 1) return kpm_filter_pid_add(value);
        if (type == 2) { kpm_filter_set_all_apps(1); return 0; }
        return -KPM_E_INVAL;
    case 1:
        if (type == 0) return kpm_filter_uid_del(value);
        if (type == 1) return kpm_filter_pid_del(value);
        if (type == 2) { kpm_filter_set_all_apps(0); return 0; }
        return -KPM_E_INVAL;
    case 2:
        return kpm_filter_clear();
    default:
        return -KPM_E_INVAL;
    }
}

void kpm_filter_set_all_apps(int on)
{
    g_filter.all_apps = on ? 1 : 0;
}

void kpm_filter_counts(uint32_t *uid_count, uint32_t *pid_count, int *all_apps)
{
    if (uid_count)
        *uid_count = g_filter.uid_count;
    if (pid_count)
        *pid_count = g_filter.pid_count;
    if (all_apps)
        *all_apps = g_filter.all_apps;
}

/* ===== 使用者生命周期（netctl/sysmon 共用）=====
 * register/unregister 只维护使用者位，不碰规则；最后一个使用者退出时
 * 才清规则并关总开关。这样 netctl 与 sysmon 同时启用时，任一方的
 * init/exit 不会清掉另一方的规则或把总开关关掉。 */
void kpm_filter_user_register(uint32_t user)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_filter.lock);
    g_filter.users |= user;
    kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
}

void kpm_filter_user_unregister(uint32_t user)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_filter.lock);
    g_filter.users &= ~user;
    g_filter.on_mask &= ~user;
    g_filter.on = (g_filter.on_mask != 0) ? 1 : 0;
    if (g_filter.users == 0) {
        /* 最后一个使用者退出：清规则，避免残留影响下一个使用者 */
        lib_memset((void *)g_filter.uid_bits, 0, sizeof(g_filter.uid_bits));
        lib_memset((void *)g_filter.pids, 0, sizeof(g_filter.pids));
        g_filter.uid_count = 0;
        g_filter.pid_count = 0;
        g_filter.all_apps = 0;
    }
    kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
}

/* 按使用者请求总开关：任一使用者 on → 热路径 on。 */
void kpm_filter_request_on(uint32_t user, int on)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_filter.lock);
    if (!(g_filter.users & user)) {
        kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
        return;   /* 未注册使用者（不应发生）：忽略，避免污染 on_mask */
    }
    if (on)
        g_filter.on_mask |= user;
    else
        g_filter.on_mask &= ~user;
    g_filter.on = (g_filter.on_mask != 0) ? 1 : 0;
    kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
}

int kpm_filter_get_on(void)
{
    return g_filter.on;
}

long kpm_filter_pids_copy(pid_t *out, int max)
{
    unsigned long flags;
    uint32_t i, n;

    if (!out || max <= 0)
        return -KPM_E_INVAL;
    flags = kpm_spin_lock_irqsave(&g_filter.lock);
    n = g_filter.pid_count;
    if (n > (uint32_t)max)
        n = (uint32_t)max;
    for (i = 0; i < n; i++)
        out[i] = g_filter.pids[i];
    kpm_spin_unlock_irqrestore(&g_filter.lock, flags);
    return (long)n;
}
