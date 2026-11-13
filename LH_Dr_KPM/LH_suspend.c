/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_suspend.c - 进程挂起/恢复实现
 *
 * 工作项引用交接：
 *   线程收集时每线程 get_task_struct 一次；park 回调运行前用
 *   wk->flag 原子认领（0=排队 1=park 持有 3=resume 接管 2/4=已归还），
 *   恰好一方归还引用，无双释放/泄漏；ZOMBIE 态等待迟到回调归还
 *   工作项后记录才复用（防陈旧回调锚到新记录）。
 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/string.h>
#include <baselib.h>
#include "LH_comm.h"
#include "LH_suspend.h"
#include "LH_syms.h"
#include "LH_utils.h"
#include "LH_log.h"

/* task_work 队列项（struct callback_head ABI：16B 两指针） */
typedef struct {
    void *next;
    void (*func)(void *);
} kpm_suspend_head_t;

typedef struct {
    kpm_suspend_head_t work;      /* 必须首成员 */
    struct kpm_suspend_rec *rec;
    volatile int flag;            /* 0=排队 1=park 持有 3=resume 接管 2/4=已归还 */
} kpm_suspend_work_t;

typedef struct kpm_suspend_rec {
    kpm_spinlock_t lock;
    volatile int state;           /* KPM_SUSPEND_ST_* */
    pid_t tgid;
    int mode;                     /* 解析后的实际模式 */
    uint32_t timeout_ms;          /* 0=无限 */
    int nthreads;
    char name[24];
    void *leader;                 /* sigstop 模式：主线程引用 */
    kpm_suspend_work_t wk[KPM_SUSPEND_MAX_THREADS];
    void *tasks[KPM_SUSPEND_MAX_THREADS];   /* 收集时持有的引用 */
} kpm_suspend_rec_t;

static kpm_suspend_rec_t g_susp[KPM_SUSPEND_MAX];
static kpm_spinlock_t g_suspend_lock = KPM_SPINLOCK_INIT;
static volatile int g_suspend_busy = 0;
/* 能力位（init 时按符号自检判定） */
static volatile int g_can_park = 0;
static volatile int g_can_sig = 0;

/* ===== 线程组收集（安全扫描：pid 号空间正向遍历） =====
 * 退出中任务 thread_pid 为 NULL，不得用 tasklist 正向遍历 +
 * __task_pid_nr_ns；须用 kpm_task_scan_by_pid（find_vpid→get_pid_task，
 * 任务来自已哈希 pid）。引用：收集方对每个成员额外 +1，恢复时归还。 */
struct suspend_scan_ctx {
    pid_t tgid;
    void **out;
    int n, max;
};

static long suspend_scan_cb(struct task_struct *t, pid_t nr, void *ud)
{
    struct suspend_scan_ctx *c = (struct suspend_scan_ctx *)ud;

    if (kpm_task_tgid(t) == c->tgid && c->n < c->max) {
        kpm_get_task_struct_safe(t);
        c->out[c->n++] = t;
    }
    return 0;
}

static int suspend_collect_tg(pid_t tgid, void **out, int max)
{
    struct suspend_scan_ctx ctx;
    long n;

    ctx.tgid = tgid;
    ctx.out = out;
    ctx.n = 0;
    ctx.max = max;
    n = kpm_task_scan_by_pid(suspend_scan_cb, &ctx);
    if (n < 0)
        return -1;
    return ctx.n;
}

/* ===== trap-park 停靠回调（目标线程上下文，用户态边界，可睡眠） ===== */
static void kpm_suspend_park_run(void *arg)
{
    kpm_suspend_work_t *w = (kpm_suspend_work_t *)arg;
    kpm_suspend_rec_t *rec;
    unsigned long flags;
    uint64_t waited_ms = 0;
    int owned = 0, all_done = 1, i;

    if (!w)
        return;
    rec = w->rec;
    if (!rec)
        return;

    flags = kpm_spin_lock_irqsave(&rec->lock);
    if (w->flag == 0) {
        w->flag = 1;              /* 本回调持有引用与停靠职责 */
        owned = 1;
    }
    /* flag==3/2/4：resume 已接管/已归还——陈旧回调，直接退出 */
    kpm_spin_unlock_irqrestore(&rec->lock, flags);
    if (!owned)
        return;

    /* 停靠循环：恢复（state 离开 SUSPENDED）或超时后苏醒返回用户态。
     * /proc 显示 S；父进程零通知；目标信号队列零污染。 */
    while (rec->state == KPM_SUSPEND_ST_SUSPENDED) {
        if (rec->timeout_ms && waited_ms >= rec->timeout_ms)
            break;
        if (kf_schedule_timeout_interruptible && kf_msecs_to_jiffies)
            kf_schedule_timeout_interruptible(kf_msecs_to_jiffies(100));
        waited_ms += 100;
    }

    flags = kpm_spin_lock_irqsave(&rec->lock);
    w->flag = 2;
    if (rec->state == KPM_SUSPEND_ST_ZOMBIE) {
        for (i = 0; i < rec->nthreads; i++)
            if (rec->wk[i].flag != 2 && rec->wk[i].flag != 4) {
                all_done = 0;
                break;
            }
        if (all_done)
            rec->state = KPM_SUSPEND_ST_FREE;   /* 最后一个迟到回调归还记录 */
    }
    kpm_spin_unlock_irqrestore(&rec->lock, flags);
    /* current（本停靠线程）引用归还：ARM64 sp_el0 即 current task_struct */
    {
        struct task_struct *cur;
        asm volatile("mrs %0, sp_el0" : "=r"(cur));
        if (cur && (uint64_t)cur >= 0xFFFF000000000000ULL)
            kpm_put_task_struct(cur);
    }
}

/* ===== 模式可用性 ===== */
static int suspend_mode_ok(int mode)
{
    switch (mode) {
    case KPM_SUSPEND_MODE_PARK:    return g_can_park;
    case KPM_SUSPEND_MODE_SIGSTOP: return g_can_sig;
    case KPM_SUSPEND_MODE_FREEZER: return 0;   /* 预留：jobctl 偏移未验证 */
    default:                       return 0;
    }
}

long kpm_suspend_init(void)
{
    int i;
    lib_memset(g_susp, 0, sizeof(g_susp));
    for (i = 0; i < KPM_SUSPEND_MAX; i++)
        g_susp[i].lock = (kpm_spinlock_t)KPM_SPINLOCK_INIT;
    /* 引用计数能力（自适应）：原生 get_task_struct 或已标定 usage 偏移
     * （get/put 手动对偶，4.19 上 get_task_struct 无符号）。两者皆无 →
     * park 禁用——无引用下目标退出会使 RESUME 唤醒悬挂指针（UAF）。 */
    {
        int can_ref = kf_get_task_struct ||
                      (g_usage_offset > 0 && g_usage_offset_trusted);
        g_can_park = (kf_task_work_add && kf_schedule_timeout_interruptible &&
                      kf_msecs_to_jiffies && kf_wake_up_process &&
                      can_ref && kpm_task_scan_available()) ? 1 : 0;
    }
    /* sigstop 无引用需求（leader 引用经 kpm_put_task_struct 安全封装
     * 归还；无原生符号时退化为泄漏，不崩溃） */
    g_can_sig = (kf_do_send_sig_info && kf_find_get_pid && kf_get_pid_task) ? 1 : 0;
    kpm_log("suspend: init park=%d sig=%d\n", g_can_park, g_can_sig);
    return 0;
}

void kpm_suspend_exit(void)
{
    /* 注册表统一卸载序会先调 kpm_suspend_release_all；此处兜底幂等 */
    kpm_suspend_release_all();
}

long kpm_suspend_proc(pid_t tgid, int mode, uint32_t timeout_ms)
{
    kpm_suspend_rec_t *rec = 0;
    void *tasks[KPM_SUSPEND_MAX_THREADS];
    void *leader = 0;
    struct pid *pid_struct = 0;
    unsigned long flags;
    int i, n, free_idx = -1, actual;
    long ret;

    if (tgid <= 0)
        return -KPM_E_INVAL;

    /* AUTO：按可用性选最优（隐蔽性优先：trap-park > sigstop） */
    if (mode == KPM_SUSPEND_MODE_AUTO) {
        actual = g_can_park ? KPM_SUSPEND_MODE_PARK :
                 (g_can_sig ? KPM_SUSPEND_MODE_SIGSTOP : -1);
        if (actual < 0)
            return -KPM_E_DISABLED;
    } else {
        actual = mode;
        if (!suspend_mode_ok(actual))
            return -KPM_E_DISABLED;   /* 兼容性退回：机制不可用即拒绝 */
    }

    flags = kpm_spin_lock_irqsave(&g_suspend_lock);
    if (g_suspend_busy) {
        kpm_spin_unlock_irqrestore(&g_suspend_lock, flags);
        return -KPM_E_BUSY;
    }
    for (i = 0; i < KPM_SUSPEND_MAX; i++) {
        if (g_susp[i].state == KPM_SUSPEND_ST_SUSPENDED &&
            g_susp[i].tgid == tgid) {
            kpm_spin_unlock_irqrestore(&g_suspend_lock, flags);
            return -KPM_E_BUSY;   /* 已挂起 */
        }
        if (g_susp[i].state == KPM_SUSPEND_ST_FREE && free_idx < 0)
            free_idx = i;
    }
    if (free_idx < 0) {
        kpm_spin_unlock_irqrestore(&g_suspend_lock, flags);
        return -KPM_E_NOMEM;
    }
    g_suspend_busy = 1;
    kpm_spin_unlock_irqrestore(&g_suspend_lock, flags);

    /* 收集线程组（可睡眠路径，锁外） */
    if (actual == KPM_SUSPEND_MODE_PARK) {
        n = suspend_collect_tg(tgid, tasks, KPM_SUSPEND_MAX_THREADS);
        if (n <= 0) {
            ret = (n == 0) ? -KPM_E_NOTFOUND : -KPM_E_DISABLED;
            goto fail;
        }
        if (n >= KPM_SUSPEND_MAX_THREADS) {
            /* 超上限：整单拒绝（不半挂起——线程组只停一半更易被察觉） */
            for (i = 0; i < n; i++)
                kpm_put_task_struct((struct task_struct *)tasks[i]);
            ret = -KPM_E_NOMEM;
            goto fail;
        }
    } else {
        pid_struct = kf_find_get_pid(tgid);
        if (!pid_struct) {
            ret = -KPM_E_NOTFOUND;
            goto fail;
        }
        /* get_pid_task 自带 task 引用（内部 get_task_struct），不再叠加 */
        leader = kf_get_pid_task(pid_struct, 0 /* PIDTYPE_PID → 主线程 */);
        kf_put_pid(pid_struct);
        if (!leader) {
            ret = -KPM_E_NOTFOUND;
            goto fail;
        }
        tasks[0] = leader;
        n = 1;
    }

    /* 装载记录 */
    rec = &g_susp[free_idx];
    flags = kpm_spin_lock_irqsave(&rec->lock);
    lib_memset(rec->wk, 0, sizeof(rec->wk));
    rec->tgid = tgid;
    rec->mode = actual;
    rec->timeout_ms = timeout_ms;
    rec->nthreads = n;
    rec->name[0] = '\0';
    {
        struct task_struct *t0 = (struct task_struct *)tasks[0];
        if (kf_get_task_comm) {
            char comm[24];
            lib_memset(comm, 0, sizeof(comm));
            if (kf_get_task_comm(comm, sizeof(comm) - 1, t0) == 0)
                lib_strncpy(rec->name, comm, sizeof(rec->name) - 1);
        }
    }
    for (i = 0; i < n; i++)
        rec->tasks[i] = tasks[i];

    if (actual == KPM_SUSPEND_MODE_PARK) {
        /* 逐线程入队 task_work（运行中线程在下一个用户态边界停靠；
         * 已退出线程 add 返回非 0，跳过——最终 nthreads 记实际数） */
        int queued = 0;
        for (i = 0; i < n; i++) {
            struct task_struct *t = (struct task_struct *)tasks[i];
            rec->wk[i].rec = rec;
            rec->wk[i].flag = 0;
            rec->wk[i].work.next = 0;
            rec->wk[i].work.func = kpm_suspend_park_run;
            if (kf_task_work_add(t, &rec->wk[i].work, 1) == 0)
                queued++;
        }
        if (queued == 0) {
            for (i = 0; i < n; i++)
                kpm_put_task_struct((struct task_struct *)tasks[i]);
            rec->nthreads = 0;
            rec->state = KPM_SUSPEND_ST_FREE;
            kpm_spin_unlock_irqrestore(&rec->lock, flags);
            ret = -KPM_E_NOTFOUND;
            goto fail;
        }
        rec->nthreads = queued;
    } else {
        /* SIGSTOP：全组停（group=1）。风险：父进程收到通知。
         * do_send_sig_info 第 4 参：4.19~5.10 bool group=true=1；
         * 5.15+ enum pid_type PIDTYPE_TGID=1 —— 值恒 1 全版本兼容。 */
        if (kf_do_send_sig_info(19 /* SIGSTOP */, (void *)1 /* SEND_SIG_PRIV */,
                                (struct task_struct *)tasks[0], 1) != 0) {
            kpm_put_task_struct((struct task_struct *)tasks[0]);
            rec->nthreads = 0;
            rec->state = KPM_SUSPEND_ST_FREE;
            kpm_spin_unlock_irqrestore(&rec->lock, flags);
            ret = -KPM_E_FAULT;
            goto fail;
        }
    }
    rec->state = KPM_SUSPEND_ST_SUSPENDED;
    kpm_spin_unlock_irqrestore(&rec->lock, flags);

    g_suspend_busy = 0;
    kpm_log("suspend: tgid=%d mode=%d threads=%d\n", tgid, actual, rec->nthreads);
    return free_idx;

fail:
    g_suspend_busy = 0;
    return ret;
}

long kpm_suspend_resume(pid_t tgid)
{
    unsigned long flags;
    int i, k, cnt = 0;
    struct task_struct *wake[KPM_SUSPEND_MAX];
    void *put_refs[KPM_SUSPEND_MAX];
    int put_n = 0;

    flags = kpm_spin_lock_irqsave(&g_suspend_lock);
    for (i = 0; i < KPM_SUSPEND_MAX; i++) {
        kpm_suspend_rec_t *r = &g_susp[i];
        if (r->state != KPM_SUSPEND_ST_SUSPENDED)
            continue;
        if (tgid != 0 && r->tgid != tgid)
            continue;
        /* 记录锁内：状态切换 + 工作项认领交接 */
        {
            unsigned long f2 = kpm_spin_lock_irqsave(&r->lock);
            r->state = KPM_SUSPEND_ST_ZOMBIE;
            for (k = 0; k < r->nthreads; k++) {
                if (r->wk[k].flag == 0) {
                    r->wk[k].flag = 3;   /* resume 接管引用 */
                    if (put_n < KPM_SUSPEND_MAX)
                        put_refs[put_n++] = r->tasks[k];
                } else if (r->wk[k].flag == 1 && cnt < KPM_SUSPEND_MAX) {
                    wake[cnt++] = (struct task_struct *)r->tasks[k];
                }
            }
            if (r->mode == KPM_SUSPEND_MODE_SIGSTOP && r->leader) {
                /* SIGCONT（group=1）唤醒全组 */
                if (kf_do_send_sig_info)
                    kf_do_send_sig_info(18 /* SIGCONT */,
                                        (void *)1 /* SEND_SIG_PRIV */,
                                        (struct task_struct *)r->leader, 1);
                kpm_put_task_struct((struct task_struct *)r->leader);
                r->leader = 0;
                r->state = KPM_SUSPEND_ST_FREE;   /* sigstop 无迟到回调 */
            }
            kpm_spin_unlock_irqrestore(&r->lock, f2);
        }
    }
    kpm_spin_unlock_irqrestore(&g_suspend_lock, flags);

    for (i = 0; i < cnt; i++)
        if (wake[i] && kf_wake_up_process)
            kf_wake_up_process(wake[i]);
    for (i = 0; i < put_n; i++)
        if (put_refs[i])
            kpm_put_task_struct((struct task_struct *)put_refs[i]);

    kpm_log("suspend: resume tgid=%d records woken=%d\n", tgid, cnt + put_n);
    return cnt + put_n;
}

long kpm_suspend_list_kernel(void *kbuf, int max_count)
{
    kpm_suspend_entry_t arr[KPM_SUSPEND_MAX];
    unsigned long flags;
    int i, n = 0;

    if (!kbuf || max_count <= 0)
        return -KPM_E_INVAL;
    if (max_count > KPM_SUSPEND_MAX)
        max_count = KPM_SUSPEND_MAX;

    flags = kpm_spin_lock_irqsave(&g_suspend_lock);
    for (i = 0; i < KPM_SUSPEND_MAX && n < max_count; i++) {
        kpm_suspend_rec_t *r = &g_susp[i];
        if (r->state != KPM_SUSPEND_ST_SUSPENDED)
            continue;
        lib_memset(&arr[n], 0, sizeof(arr[n]));
        arr[n].rec_id = i;
        arr[n].tgid = r->tgid;
        arr[n].mode = (uint32_t)r->mode;
        arr[n].state = (uint32_t)r->state;
        arr[n].nthreads = (uint32_t)r->nthreads;
        lib_strncpy(arr[n].name, r->name, sizeof(arr[n].name) - 1);
        n++;
    }
    kpm_spin_unlock_irqrestore(&g_suspend_lock, flags);

    lib_memcpy(kbuf, arr, (unsigned long)n * sizeof(kpm_suspend_entry_t));
    return n;
}

long kpm_suspend_list(void *user_buf, int max_count)
{
    kpm_suspend_entry_t arr[KPM_SUSPEND_MAX];
    long n;

    if (!user_buf)
        return -KPM_E_INVAL;
    n = kpm_suspend_list_kernel(arr, max_count);
    if (n > 0) {
        if (!kf_copy_to_user ||
            kf_copy_to_user(user_buf, arr,
                            (unsigned long)n * sizeof(kpm_suspend_entry_t)))
            return -KPM_E_FAULT;
    }
    return n;
}

int kpm_suspend_release_all(void)
{
    /* 幂等：全恢复（tgid=0）。ZOMBIE 迟到回调自行归还记录，无需等待。 */
    kpm_suspend_resume(0);
    return 0;
}
