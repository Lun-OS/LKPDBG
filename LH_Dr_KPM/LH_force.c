/* SPDX-License-Identifier: GPL-2.0-or-later */
/* LH_force.c - 强制提权会话实现 */
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <hook.h>
#include <baselib.h>
#include <linux/string.h>

#include "LH_comm.h"
#include "LH_force.h"
#include "LH_syms.h"
#include "LH_utils.h"
#include "LH_log.h"

static kpm_spinlock_t g_force_lock = KPM_SPINLOCK_INIT;
static volatile uint64_t g_force_until_ns;   /* 0=未启用；~0=无限 */
static volatile uint32_t g_force_mask;
static int g_locked_hooked;

static uint64_t force_now_ns(void)
{
    if (kf_ktime_get_ns)
        return kf_ktime_get_ns();
    /* 无 ktime 时退回 jiffies（按 100Hz 近似，仅用于超时） */
    if (kf_jiffies)
        return (uint64_t)(*kf_jiffies) * 10000000ULL;
    return 0;
}

void kpm_force_init(void)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_force_lock);
    g_force_until_ns = 0;
    g_force_mask = 0;
    g_locked_hooked = 0;
    kpm_spin_unlock_irqrestore(&g_force_lock, flags);
    kpm_clear_state(KPM_STATE_FORCE);
}

/* security_locked_down(enum) -> int；force 下直接返回 0 */
static void kpm_force_locked_before(hook_fargs4_t *fa, void *udata)
{
    (void)udata;
    fa->ret = 0;
    fa->skip_origin = 1;
}

static uint32_t force_bypass_locked_down(void)
{
    uint32_t applied = 0;

    /* 变量可写：kernel_locked_down = 0 */
    if (kf_kernel_locked_down) {
        *(volatile int *)kf_kernel_locked_down = 0;
        applied |= KPM_FORCE_CFI;
        kpm_log("force: kernel_locked_down cleared\n");
    }
    /* 函数可 hook：security_locked_down() 恒 0 */
    if (kf_security_locked_down && !g_locked_hooked) {
        hook_err_t e = hook_wrap((void *)kf_security_locked_down, 1,
                                 kpm_force_locked_before, 0, 0);
        if (e == HOOK_NO_ERR) {
            g_locked_hooked = 1;
            applied |= KPM_FORCE_CFI;
            kpm_log("force: security_locked_down hooked\n");
        } else {
            kpm_log("force: security_locked_down hook failed (%d)\n", e);
        }
    }
    return applied;
}

uint32_t kpm_force_probe(void)
{
    uint32_t caps = 0;

    if (kf_register_wide_hw_bp || kf_perf_event_create_kernel_counter)
        caps |= KPM_FORCE_KERNEL_BP;
    if (kf_copy_to_kernel_nofault)
        caps |= KPM_FORCE_KERNEL_RW;
    if (kf_do_mem_abort)
        caps |= KPM_FORCE_MEMWATCH_UNSAFE;
    if (kf_register_user_step_hook)
        caps |= KPM_FORCE_STEP;
    caps |= KPM_FORCE_HOT_TRACE;   /* hook_wrap 由框架直接链接 */
    if (kf_kernel_locked_down || kf_security_locked_down)
        caps |= KPM_FORCE_CFI;
    /* ETM/Coresight 由 trace 模块 probe；此处不虚报 */
    return caps;
}

int kpm_force_active(void)
{
    uint64_t now, until;

    until = g_force_until_ns;
    if (until == 0)
        return 0;
    if (until == ~0ULL)
        return 1;
    now = force_now_ns();
    if (now == 0)
        return 1;   /* 无时间源：按有效处理，由 timeout 失效风险自负 */
    if (now >= until) {
        unsigned long flags = kpm_spin_lock_irqsave(&g_force_lock);
        if (g_force_until_ns == until) {
            g_force_until_ns = 0;
            g_force_mask = 0;
            kpm_clear_state(KPM_STATE_FORCE);
        }
        kpm_spin_unlock_irqrestore(&g_force_lock, flags);
        return 0;
    }
    return 1;
}

uint32_t kpm_force_mask(void)
{
    return kpm_force_active() ? g_force_mask : 0;
}

int kpm_force_require(uint32_t mask)
{
    if (!mask)
        return 0;
    if (!kpm_force_active())
        return -KPM_E_PERM;
    if ((g_force_mask & mask) != mask)
        return -KPM_E_PERM;
    return 0;
}

long kpm_force_control(int op, uint32_t timeout_ms, uint32_t magic,
                       uint32_t mask, kpm_force_info_t *out)
{
    unsigned long flags;

    if (op == KPM_FORCE_OP_UNLOCK) {
        uint64_t now, until;

        if (magic != KPM_FORCE_MAGIC)
            return -KPM_E_PERM;
        if (mask == 0)
            mask = KPM_FORCE_ALL;
        mask &= KPM_FORCE_ALL;
        if (timeout_ms == 0)
            timeout_ms = KPM_FORCE_DEFAULT_MS;
        if (timeout_ms != KPM_FORCE_INF && timeout_ms > KPM_FORCE_MAX_MS)
            timeout_ms = KPM_FORCE_MAX_MS;
        if (timeout_ms == KPM_FORCE_INF) {
            until = ~0ULL;
        } else {
            now = force_now_ns();
            if (!now)
                return -KPM_E_DISABLED;   /* 无时间源，无法安全计时 */
            until = now + (uint64_t)timeout_ms * 1000000ULL;
            if (until < now)
                until = ~0ULL;
        }
        flags = kpm_spin_lock_irqsave(&g_force_lock);
        g_force_until_ns = until;
        g_force_mask = mask;
        kpm_set_state(KPM_STATE_FORCE);
        kpm_spin_unlock_irqrestore(&g_force_lock, flags);
        kpm_log("force: unlocked mask=0x%x timeout=%u\n", mask, timeout_ms);
        if (out) {
            out->active = 1;
            out->mask = mask;
            out->remaining_ms = (timeout_ms == KPM_FORCE_INF) ?
                                KPM_FORCE_INF : timeout_ms;
            out->caps = kpm_force_probe();
        }
        return 0;
    }

    if (op == KPM_FORCE_OP_LOCK) {
        flags = kpm_spin_lock_irqsave(&g_force_lock);
        g_force_until_ns = 0;
        g_force_mask = 0;
        kpm_clear_state(KPM_STATE_FORCE);
        kpm_spin_unlock_irqrestore(&g_force_lock, flags);
        kpm_log("force: locked\n");
        return 0;
    }

    if (op == KPM_FORCE_OP_QUERY) {
        if (out) {
            uint32_t rem = 0;
            uint64_t until = g_force_until_ns;
            out->active = kpm_force_active();
            out->mask = out->active ? g_force_mask : 0;
            if (out->active) {
                if (until == ~0ULL) {
                    rem = KPM_FORCE_INF;
                } else {
                    uint64_t now = force_now_ns();
                    rem = (now && until > now) ?
                          (uint32_t)((until - now) / 1000000ULL) : 0;
                }
            }
            out->remaining_ms = rem;
            out->caps = kpm_force_probe();
        }
        return 0;
    }

    if (op == KPM_FORCE_OP_PROBE)
        return (long)kpm_force_probe();

    if (op == KPM_FORCE_OP_BYPASS) {
        if (kpm_force_require(KPM_FORCE_CFI) < 0)
            return -KPM_E_PERM;
        return (long)force_bypass_locked_down();
    }

    return -KPM_E_INVAL;
}

void kpm_force_exit(void)
{
    unsigned long flags;

    if (g_locked_hooked && kf_security_locked_down) {
        /* hook_unwrap 会改内核 text（可能睡眠）：不可在 RCU 读临界区内
         * 调用，须先借出 RCU 锁；无法确认安全时跳过 unhook。 */
        int guard = kpm_rcu_exit_guard_acquire();
        if (guard < 0) {
            kpm_log("force: SKIP unhook in RCU ctx (residual)\n");
        } else {
            hook_unwrap((void *)kf_security_locked_down,
                        kpm_force_locked_before, 0);
            g_locked_hooked = 0;
            if (guard > 0)
                kpm_rcu_exit_guard_release();
        }
    }
    flags = kpm_spin_lock_irqsave(&g_force_lock);
    g_force_until_ns = 0;
    g_force_mask = 0;
    kpm_spin_unlock_irqrestore(&g_force_lock, flags);
    kpm_clear_state(KPM_STATE_FORCE);
    kpm_log("force: exit\n");
}
