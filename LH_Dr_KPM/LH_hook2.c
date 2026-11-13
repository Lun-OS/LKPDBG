/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_hook2.c - hook 引擎双模式实现
 * 设计/风险注释见 LH_hook2.h。
 *
 * id 编址：0..KPM_HOOK2_MAX_STEALTH-1 = 无痕（BRP）；0x100+ = 普通（内核函数）。
 */
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/string.h>
#include <ksyms.h>
#include <baselib.h>
#include "LH_comm.h"
#include "LH_hook2.h"
#include "LH_syms.h"
#include "LH_utils.h"
#include "LH_log.h"

/* ===== 无痕（BRP 重定向） ===== */
static uint64_t g_st_args[8];   /* ARG_MOD 窗口（8×u64） */
static volatile int g_st_args_valid = 0;
static kpm_spinlock_t g_hook2_lock = KPM_SPINLOCK_INIT;
static volatile int g_st_count = 0;

/* 普通（内核函数 hook_wrap） */
typedef struct {
    int      used;
    int      idx;            /* 框架规则槽（=本条目下标，udata 传回） */
    uint64_t func_addr;
    uint32_t action;
    uint32_t arg_idx;
    uint32_t errno_mode;
    uint64_t value;
} kpm_hook2_krule_t;
static kpm_hook2_krule_t g_kr[KPM_HOOK2_MAX_KFUNC];
static volatile int g_kf_count = 0;
static volatile int g_kf_inflight = 0;

#ifndef EPERM
#define EPERM 1
#endif
#ifndef EACCES
#define EACCES 13
#endif

/* ===== 普通 hook：内核函数 before 回调 ===== */
static void kpm_hook2_kfunc_before(void *fargs, void *udata)
{
    int idx = (int)(uintptr_t)udata;
    kpm_hook2_krule_t *r;
    hook_fargs4_t *fa = (hook_fargs4_t *)fargs;

    if (idx < 0 || idx >= KPM_HOOK2_MAX_KFUNC)
        return;
    r = &g_kr[idx];
    if (!r->used)
        return;

    asm volatile("" ::: "memory");
    g_kf_inflight++;
    switch (r->action) {
    case KPM_HOOK_ACT_ARG_MOD:
        /* hook_fargs4_t.args[0..3] 写回即改原调用参数（框架语义） */
        if (r->arg_idx < 4)
            fa->args[r->arg_idx] = r->value;
        break;
    case KPM_HOOK_ACT_OBSERVE:
    default:
        break;
    }
    g_kf_inflight--;
}

/* ===== 无痕：安装/删除 ===== */
/* perf 安装/卸载与 hook_wrap/unwrap 会触发 IPI 或改写内核 text，
 * 不可在关中断自旋锁内调用（否则 panic）；一律放在 g_hook2_lock
 * 之外，锁内只做窗口快照与槽位登记。 */
static long st_set(pid_t pid, uint64_t func_addr, uint64_t packed, uint64_t aux)
{
    kpm_bp_hook_rule_t rule;
    uint64_t arg_mask = packed & 0xFF;
    int action = (int)((packed >> 16) & 0xFF);
    int auto_apply = (int)((packed >> 24) & 1);
    long idx;
    int j;

    if (action < KPM_HOOK_ACT_OBSERVE || action > KPM_HOOK_ACT_REDIRECT)
        return -KPM_E_INVAL;
    if (g_st_count >= KPM_HOOK2_MAX_STEALTH)
        return -KPM_E_NOMEM;   /* 宽松计数：硬上限由 debug 槽位保护 */

    /* ARG_MOD 值窗口（与同步断点 regmod 窗口同款两段式）。
     * 仅快照在锁内，安装调用全程锁外。 */
    lib_memset(&rule, 0, sizeof(rule));
    rule.action = action;
    rule.auto_apply = auto_apply;
    rule.arg_mask = arg_mask;
    rule.aux = aux;
    if (action == KPM_HOOK_ACT_ARG_MOD) {
        unsigned long f = kpm_spin_lock_irqsave(&g_hook2_lock);
        if (!g_st_args_valid) {
            kpm_spin_unlock_irqrestore(&g_hook2_lock, f);
            return -KPM_E_INVAL;   /* 先 HOOK2_ARGS 预置窗口 */
        }
        for (j = 0; j < 8; j++)
            rule.args[j] = g_st_args[j];
        g_st_args_valid = 0;
        kpm_spin_unlock_irqrestore(&g_hook2_lock, f);
    }

    if (auto_apply) {
        /* auto 模式：普通 bp + 命中即应用规则（不停靠）。
         * 不走 bp_set_sync——其置位的 sync 标志会触发规则互斥检查。 */
        idx = kpm_debug_bp_set(pid, KPM_BP_TYPE_HW_EXEC, func_addr, 4);
        if (idx < 0)
            return idx;
        {
            long r = kpm_debug_bp_hook_rule_set((int)idx, &rule);
            if (r != 0) {
                kpm_debug_bp_clear((int)idx);
                return r;
            }
        }
    } else {
        /* manual 模式：同步停靠语义（无规则，客户端 GET/SET/RESUME
         * 全权接管——规则与 sync 互斥，不设置） */
        idx = kpm_debug_bp_set_sync(pid, KPM_BP_TYPE_HW_EXEC, func_addr, 4,
                                    0 /* timeout 默认 2s */);
        if (idx < 0)
            return idx;
    }
    g_st_count++;
    kpm_log("hook2: stealth pid=%d addr=%llx act=%d auto=%d idx=%ld\n",
            pid, func_addr, action, auto_apply, idx);
    return idx;
}

long kpm_hook2_set_stealth(pid_t pid, uint64_t func_addr, uint64_t packed,
                           uint64_t aux)
{
    if (!func_addr || (uint64_t)func_addr < 0x1000)
        return -KPM_E_INVAL;
    /* 不持 g_hook2_lock：st_set 内的 perf 创建/规则挂载会发 IPI，
     * 在 irqsave 锁内调用会 panic。 */
    return st_set(pid, func_addr, packed, aux);
}

/* ===== 普通：安装/删除 ===== */
static long kf_set(uint64_t func_addr, uint64_t packed, uint64_t value)
{
    uint32_t action = (uint32_t)((packed >> 48) & 0xFF);
    uint32_t arg_idx = (uint32_t)((packed >> 40) & 0xFF);
    uint32_t errno_mode = (uint32_t)((packed >> 32) & 0xFF);
    int i;
    long id = -1;
    hook_err_t err;

    if (!func_addr || (uint64_t)func_addr < 0xFFFF000000000000ULL)
        return -KPM_E_INVAL;
    if (action > KPM_HOOK_ACT_ARG_MOD)
        return -KPM_E_INVAL;   /* kfunc 支持 OBSERVE/ARG_MOD（跳过函数无意义） */

    /* 锁内仅预留/登记槽位；hook_wrap（text patch + 可能的 IPI）
     * 在锁外执行。 */
    {
        unsigned long flags = kpm_spin_lock_irqsave(&g_hook2_lock);
        for (i = 0; i < KPM_HOOK2_MAX_KFUNC; i++) {
            if (!g_kr[i].used) {
                id = i;
                break;
            }
        }
        if (id < 0) {
            kpm_spin_unlock_irqrestore(&g_hook2_lock, flags);
            return -KPM_E_NOMEM;
        }
        g_kr[id].used = 1;
        g_kr[id].idx = id;
        g_kr[id].func_addr = func_addr;
        g_kr[id].action = action;
        g_kr[id].arg_idx = arg_idx;
        g_kr[id].errno_mode = errno_mode;
        g_kr[id].value = value;
        kpm_spin_unlock_irqrestore(&g_hook2_lock, flags);
    }

    err = hook_wrap((void *)(uintptr_t)func_addr, 4,
                    kpm_hook2_kfunc_before, 0, (void *)(uintptr_t)id);
    if (err != HOOK_NO_ERR) {
        unsigned long flags = kpm_spin_lock_irqsave(&g_hook2_lock);
        lib_memset(&g_kr[id], 0, sizeof(g_kr[id]));
        kpm_spin_unlock_irqrestore(&g_hook2_lock, flags);
        kpm_log("hook2: kfunc wrap %llx failed (%d)\n", func_addr, err);
        return -KPM_E_FAULT;
    }
    g_kf_count++;
    kpm_log("hook2: kfunc %llx act=%d id=%ld\n", func_addr, action, id);
    return 0x100 + id;
}

long kpm_hook2_set_kfunc(uint64_t func_addr, uint64_t packed, uint64_t value)
{
    unsigned long flags;
    long ret;

    flags = kpm_spin_lock_irqsave(&g_hook2_lock);
    ret = kf_set(func_addr, packed, value);
    kpm_spin_unlock_irqrestore(&g_hook2_lock, flags);
    return ret;
}

long kpm_hook2_args_window(const void *user_buf)
{
    uint64_t tmp[8];
    int j;
    unsigned long flags;

    if (!user_buf || !kf_copy_from_user)
        return -KPM_E_INVAL;
    if (kf_copy_from_user(tmp, user_buf, sizeof(tmp)))
        return -KPM_E_FAULT;
    flags = kpm_spin_lock_irqsave(&g_hook2_lock);
    for (j = 0; j < 8; j++)
        g_st_args[j] = tmp[j];
    g_st_args_valid = 1;
    kpm_spin_unlock_irqrestore(&g_hook2_lock, flags);
    return 0;
}

long kpm_hook2_args_window_kernel(const void *kbuf)
{
    unsigned long flags;

    if (!kbuf)
        return -KPM_E_INVAL;
    flags = kpm_spin_lock_irqsave(&g_hook2_lock);
    lib_memcpy(g_st_args, kbuf, sizeof(g_st_args));
    g_st_args_valid = 1;
    kpm_spin_unlock_irqrestore(&g_hook2_lock, flags);
    return 0;
}

long kpm_hook2_del(int id)
{
    /* kpm_debug_bp_clear（perf 注销 → IPI）与 hook_unwrap（text patch）
     * 不得在 g_hook2_lock 内调用。 */
    if (id >= 0 && id < KPM_HOOK2_MAX_STEALTH) {
        long ret;

        /* 计数依赖“确实存在”判定：空槽须保持 -NOTFOUND，
         * 否则重复 DEL 会把 g_st_count 减错。 */
        if (kpm_debug_bp_hook_state(id, 0, 0, 0, 0) != 1)
            return -KPM_E_NOTFOUND;
        ret = kpm_debug_bp_clear(id);
        if (ret == 0 && g_st_count)
            g_st_count--;
        return ret;
    }
    if (id >= 0x100 && id < 0x100 + KPM_HOOK2_MAX_KFUNC) {
        int i = id - 0x100;
        uint64_t fa;
        unsigned long flags;

        flags = kpm_spin_lock_irqsave(&g_hook2_lock);
        if (!g_kr[i].used) {
            kpm_spin_unlock_irqrestore(&g_hook2_lock, flags);
            return -KPM_E_NOTFOUND;
        }
        fa = g_kr[i].func_addr;
        g_kr[i].used = 0;   /* 先摘条目：unwrap 期间命中回调不再进入 */
        lib_memset(&g_kr[i], 0, sizeof(g_kr[i]));
        kpm_spin_unlock_irqrestore(&g_hook2_lock, flags);

        hook_unwrap((void *)(uintptr_t)fa, kpm_hook2_kfunc_before, 0);
        if (g_kf_count)
            g_kf_count--;
        return 0;
    }
    return -KPM_E_INVAL;
}

long kpm_hook2_list_kernel(void *kbuf, int max_count)
{
    kpm_hook2_entry_t arr[KPM_HOOK2_MAX_STEALTH + KPM_HOOK2_MAX_KFUNC];
    unsigned long flags;
    int i, n = 0;

    if (!kbuf || max_count <= 0)
        return -KPM_E_INVAL;
    if (max_count > KPM_HOOK2_MAX_STEALTH + KPM_HOOK2_MAX_KFUNC)
        max_count = KPM_HOOK2_MAX_STEALTH + KPM_HOOK2_MAX_KFUNC;

    flags = kpm_spin_lock_irqsave(&g_hook2_lock);
    for (i = 0; i < KPM_HOOK2_MAX_STEALTH && n < max_count; i++) {
        pid_t hpid;
        uint64_t haddr, hhits;
        int hact;
        if (kpm_debug_bp_hook_state(i, &hpid, &haddr, &hact, &hhits) == 1) {
            arr[n].id = (uint32_t)i;
            arr[n].mode = 1;   /* stealth */
            arr[n].pid = hpid;
            arr[n].addr = haddr;
            arr[n].action = (uint32_t)hact;
            arr[n].hit_count = hhits;
            n++;
        }
    }
    for (i = 0; i < KPM_HOOK2_MAX_KFUNC && n < max_count; i++) {
        if (g_kr[i].used) {
            arr[n].id = (uint32_t)(0x100 + i);
            arr[n].mode = 0;   /* normal (kfunc) */
            arr[n].pid = 0;
            arr[n].addr = g_kr[i].func_addr;
            arr[n].action = g_kr[i].action;
            arr[n].hit_count = 0;
            n++;
        }
    }
    kpm_spin_unlock_irqrestore(&g_hook2_lock, flags);
    lib_memcpy(kbuf, arr, (unsigned long)n * sizeof(kpm_hook2_entry_t));
    return n;
}

long kpm_hook2_list(void *user_buf, int max_count)
{
    kpm_hook2_entry_t arr[KPM_HOOK2_MAX_STEALTH + KPM_HOOK2_MAX_KFUNC];
    long n;

    if (!user_buf)
        return -KPM_E_INVAL;
    n = kpm_hook2_list_kernel(arr, max_count);
    if (n > 0) {
        if (!kf_copy_to_user ||
            kf_copy_to_user(user_buf, arr,
                            (unsigned long)n * sizeof(kpm_hook2_entry_t)))
            return -KPM_E_FAULT;
    }
    return n;
}

/* ===== 单元 init/exit ===== */
long kpm_hook2_init_stealth(void)
{
    /* 依赖 debug 单元的 perf 基础设施（dep_mask 已声明） */
    g_st_count = 0;
    g_st_args_valid = 0;
    return 0;
}

void kpm_hook2_exit_stealth(void)
{
    int i;
    for (i = 0; i < KPM_DEBUG_MAX_BREAKPOINTS; i++) {
        if (kpm_debug_bp_hook_state(i, 0, 0, 0, 0) == 1)
            kpm_debug_bp_clear(i);   /* 一并清规则（bp_clear 内） */
    }
    g_st_count = 0;
}

long kpm_hook2_init_kfunc(void)
{
    lib_memset(g_kr, 0, sizeof(g_kr));
    g_kf_count = 0;
    return 0;
}

void kpm_hook2_exit_kfunc(void)
{
    int i;
    g_kf_inflight = 0;
    for (i = 0; i < KPM_HOOK2_MAX_KFUNC; i++) {
        if (g_kr[i].used) {
            hook_unwrap((void *)(uintptr_t)g_kr[i].func_addr,
                        kpm_hook2_kfunc_before, 0);
            lib_memset(&g_kr[i], 0, sizeof(g_kr[i]));
        }
    }
    g_kf_count = 0;
}
