/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_resctl.c - CPU 亲和性/频率控制实现
 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>
#include <ksyms.h>
#include <baselib.h>
#include "LH_comm.h"
#include "LH_resctl.h"
#include "LH_syms.h"
#include "LH_utils.h"
#include "LH_log.h"

/* sched_attr（uapi 布局，离线可推导，无偏移探测）：
 * size@0 policy@4 flags@8 nice@16 pad runtime@24 deadline@32 period@40
 * util_min@48 util_max@56 —— uclamp 字段位置 4.19(如启用)/6.1 一致 */
typedef struct {
    uint32_t size;
    uint32_t policy;
    uint64_t flags;
    int32_t  nice;
    uint32_t pad;
    uint64_t runtime;
    uint64_t deadline;
    uint64_t period;
    uint32_t util_min;
    uint32_t util_max;
} kpm_sched_attr_t;           /* sizeof = 64 */

#define KPM_SCHED_FLAG_KEEP_POLICY     0x08
#define KPM_SCHED_FLAG_UTIL_CLAMP_MAX  0x40

static volatile int g_can_affinity = 0;
static volatile int g_can_uclamp = 0;
static kpm_spinlock_t g_resctl_lock = KPM_SPINLOCK_INIT;

/* cpumask 静态缓冲（4096 位上限，覆盖全部现实 NR_CPUS 配置；
 * 超出 nr_cpu_ids 的位被内核求交时忽略）。管理操作低频，串行化。 */
static uint8_t g_cpumask_buf[512];
static kpm_sched_attr_t g_attr;

long kpm_resctl_init(void)
{
    g_can_affinity = (kf_set_cpus_allowed_ptr != 0);
    /* uclamp 能力探测（6.1 有 sysctl_sched_uclamp_util_max 变量；
     * 4.19 无 → DEGRADED：仅亲和性） */
    g_can_uclamp = (kf_sched_setattr_nocheck &&
                    kf_sysctl_sched_uclamp_util_max) ? 1 : 0;
    kpm_log("resctl: init affinity=%d uclamp=%d\n",
            g_can_affinity, g_can_uclamp);
    return 0;
}

void kpm_resctl_exit(void)
{
    /* 规则恢复责任在客户端；模块卸载不做全局反向恢复
     * （亲和性/clamp 随进程生命周期自然生效/消失，无内核残留对象） */
}

/* ===== tgid/遍历：安全扫描 =====
 * 退出中任务 thread_pid 为 NULL，不得用 tasklist 正向遍历 +
 * __task_pid_nr_ns；须用 kpm_task_scan_by_pid（find_vpid→get_pid_task，
 * 任务来自已哈希 pid）。 */

struct resctl_scan_ctx {
    pid_t tgid;
    void **out;
    int n, max;
};

static long resctl_scan_cb(struct task_struct *t, pid_t nr, void *ud)
{
    struct resctl_scan_ctx *c = (struct resctl_scan_ctx *)ud;

    if (kpm_task_tgid(t) == c->tgid && c->n < c->max) {
        kpm_get_task_struct_safe(t);
        c->out[c->n++] = t;
    }
    return 0;
}

static int resctl_collect_tg(pid_t tgid, void **out, int max)
{
    struct resctl_scan_ctx ctx;
    long n;

    ctx.tgid = tgid;
    ctx.out = out;
    ctx.n = 0;
    ctx.max = max;
    n = kpm_task_scan_by_pid(resctl_scan_cb, &ctx);
    if (n < 0)
        return -1;
    return ctx.n;
}

static long resctl_apply_affinity_one(void *task, uint64_t cpu_mask)
{
    int i;

    lib_memset(g_cpumask_buf, 0, sizeof(g_cpumask_buf));
    for (i = 0; i < 64 && i < (int)(sizeof(g_cpumask_buf) * 8); i++)
        if (cpu_mask & (1ULL << i))
            g_cpumask_buf[i >> 3] |= (uint8_t)(1u << (i & 7));
    /* cpumask 本质是 unsigned long 位图数组——小端 ARM64 上按字节写位
     * 即正确；超出 nr_cpu_ids 的位被内核求交时忽略 */
    return kf_set_cpus_allowed_ptr((struct task_struct *)task,
                                   (const void *)g_cpumask_buf);
}

long kpm_resctl_affinity(pid_t tgid, uint64_t cpu_mask)
{
    void *tasks[16];
    unsigned long flags;
    int n, i;
    long ret = 0;

    if (!g_can_affinity)
        return -KPM_E_DISABLED;
    if (tgid <= 0)
        return -KPM_E_INVAL;

    flags = kpm_spin_lock_irqsave(&g_resctl_lock);
    n = resctl_collect_tg(tgid, tasks, 16);
    if (n <= 0) {
        kpm_spin_unlock_irqrestore(&g_resctl_lock, flags);
        return (n == 0) ? -KPM_E_NOTFOUND : -KPM_E_DISABLED;
    }
    for (i = 0; i < n; i++) {
        long r = resctl_apply_affinity_one(tasks[i], cpu_mask);
        if (r != 0 && ret == 0)
            ret = r;
        kpm_put_task_struct((struct task_struct *)tasks[i]);
    }
    kpm_spin_unlock_irqrestore(&g_resctl_lock, flags);
    kpm_log("resctl: affinity tgid=%d mask=%llx n=%d\n", tgid, cpu_mask, n);
    return ret;
}

long kpm_resctl_freq(pid_t tgid, uint64_t util_max)
{
    void *tasks[16];
    unsigned long flags;
    int n, i;
    long ret = 0;

    if (!g_can_uclamp)
        return -KPM_E_DISABLED;   /* 4.19：无 uclamp，DEGRADED（仅亲和性） */
    if (tgid <= 0)
        return -KPM_E_INVAL;
    if (util_max > 1024 && util_max != 0xFFFFFFFFULL)
        return -KPM_E_INVAL;

    flags = kpm_spin_lock_irqsave(&g_resctl_lock);
    n = resctl_collect_tg(tgid, tasks, 16);
    if (n <= 0) {
        kpm_spin_unlock_irqrestore(&g_resctl_lock, flags);
        return (n == 0) ? -KPM_E_NOTFOUND : -KPM_E_DISABLED;
    }
    for (i = 0; i < n; i++) {
        long r;
        lib_memset(&g_attr, 0, sizeof(g_attr));
        g_attr.size = (uint32_t)sizeof(g_attr);
        g_attr.flags = KPM_SCHED_FLAG_KEEP_POLICY | KPM_SCHED_FLAG_UTIL_CLAMP_MAX;
        g_attr.util_max = (util_max == 0xFFFFFFFFULL) ?
                          KPM_RESCTL_UTIL_MAX_DEFAULT : (uint32_t)util_max;
        r = kf_sched_setattr_nocheck((struct task_struct *)tasks[i], &g_attr);
        if (r != 0 && ret == 0)
            ret = r;
        kpm_put_task_struct((struct task_struct *)tasks[i]);
    }
    kpm_spin_unlock_irqrestore(&g_resctl_lock, flags);
    kpm_log("resctl: freq tgid=%d util_max=%llu n=%d\n", tgid, util_max, n);
    return ret;
}

struct resctl_global_ctx {
    uint64_t affinity_mask, util_max;
    int can_aff, can_uc, applied;
};

static long resctl_global_cb(struct task_struct *t, pid_t nr, void *ud)
{
    struct resctl_global_ctx *gc = (struct resctl_global_ctx *)ud;
    pid_t tg = kpm_task_tgid(t);

    if (tg < 10000 || tg > 0x7FFFFFFF)
        return 0;    /* 仅 app 进程（tgid 段过滤，内核线程除外） */
    if (gc->affinity_mask && gc->can_aff)
        resctl_apply_affinity_one(t, gc->affinity_mask);
    if (gc->util_max && gc->util_max != 0xFFFFFFFFULL && gc->can_uc) {
        lib_memset(&g_attr, 0, sizeof(g_attr));
        g_attr.size = (uint32_t)sizeof(g_attr);
        g_attr.flags = KPM_SCHED_FLAG_KEEP_POLICY |
                       KPM_SCHED_FLAG_UTIL_CLAMP_MAX;
        g_attr.util_max = (uint32_t)gc->util_max;
        kf_sched_setattr_nocheck(t, &g_attr);
    }
    gc->applied++;
    return 0;
}

long kpm_resctl_global(uint64_t affinity_mask, uint64_t util_max)
{
    /* 全局规则：遍历全部 app 进程（uid>=10000）逐线程应用（安全扫描）。
     * 频率限制在无 uclamp 设备上跳过。 */
    struct resctl_global_ctx gc;
    unsigned long flags;
    int applied = 0;

    if (affinity_mask == 0 && util_max == 0)
        return -KPM_E_INVAL;

    flags = kpm_spin_lock_irqsave(&g_resctl_lock);
    if (!kpm_task_scan_available()) {
        kpm_spin_unlock_irqrestore(&g_resctl_lock, flags);
        return -KPM_E_DISABLED;
    }
    gc.affinity_mask = affinity_mask;
    gc.util_max = util_max;
    gc.can_aff = g_can_affinity;
    gc.can_uc = g_can_uclamp;
    gc.applied = 0;
    kpm_task_scan_by_pid(resctl_global_cb, &gc);
    applied = gc.applied;
    kpm_spin_unlock_irqrestore(&g_resctl_lock, flags);
    kpm_log("resctl: global applied=%d\n", applied);
    return applied;
}

long kpm_resctl_caps(void)
{
    return (g_can_affinity ? 1 : 0) | (g_can_uclamp ? 2 : 0);
}
