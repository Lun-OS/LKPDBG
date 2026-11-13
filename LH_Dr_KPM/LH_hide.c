/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_hide.c - 进程隐藏 / 反检测执行层
 *
 * 三个基本接口（对用户态进程隐藏）：
 *   1. HIDE_PROCESS    —— 从 pid namespace 登记表摘除目标**线程组全部成员**
 *                         条目（回退链 P0）
 *   2. RECOVER_PROCESS —— 恢复（原 struct pid 回填 + 兜底 hook 拆除）
 *   3. UN_HOOK         —— 运行时下线驱动自身全部用户态可见内核 hook（收尾）
 *   附带 HIDE_LIST（隐藏记录查询，含 conflict/exited/limited 状态）。
 *
 * ===== 回退链机制 =====
 * "隐藏效果最好、最难暴露"优先，逐级自动降级，绝不静默：
 *
 *   P0（首选，最难暴露）：纯数据级登记表摘除/回填
 *     ├─ 5.0+：pid_namespace.idr 摘除/回填（idr 为主流内核 ns 首成员偏移 0，
 *     │   运行时 pid1 双向自检门控；4.19- pid_hash 时代自检失败即禁用）
 *     └─ 效果：/proc 枚举(readdir/ps/getdents)、按 pid kill 全部"查无此进程"
 *
 *   P1（回退，/proc 直连兜底；默认关闭，需显式启用）：登记表不动，框架
 *     hook(proc_pid_lookup, stub, &backup)。proc_pid_lookup 是 4.19~6.12 VFS
 *     /proc 顶层数字目录 lookup 的唯一必经入口（与内核内部通道语义无关）。
 *     stub：从 dentry 解析目标名（struct qstr 布局恒定 {hash_len,name}，dentry
 *     内 d_name 偏移候选表 + 指针/长度/数字三重自校验，布局不同只会安全退化
 *     不会崩）→ pid 命中隐藏表返回 NULL（VFS 视为 ENOENT）；其余经 trampoline
 *     保真。生命周期与隐藏窗口严格绑定：RECOVER 清空生效记录即 unhook
 *     + inflight 排空。
 *     P1 默认关闭（g_hide_p1=0，hide 走纯 P0=枚举+防杀）；仅当客户端经
 *     KPM_CMD_HIDE_P1(0x1157) 显式启用才安装。主流内核 P0 已使直连 ENOENT，
 *     无需 P1；非标内核启用前须先在目标内核完成稳定性验证。
 *
 *   P2（降级，不静默）：P1 显式启用后若符号缺失或 hook 安装失败 → 该记录标记
 *     KPM_HIDE_STATE_LIMITED（= 仅枚举级，直连仍可能可达），HIDE_LIST 明示，
 *     客户端知情决策。
 *
 * 兼容性（跨 4.19~6.1+）：proc_pid_lookup 全版本导出、签名稳定（3 参）；
 * kallsyms 解析失败仅影响 P1 可用（P0 不变，记录降级为 limited 如实标注）。
 *
 * 实现要点（隐蔽性 / 稳定性）：
 *   - 隐蔽性 A 级为主：主流内核纯数据结构操作；hook 仅限"第二通道"异常内核、
 *     生命周期=隐藏窗口、命令驱动（客户端发 HIDE 才出现），RECOVER 即拆。
 *   - 记录持有 struct pid 引用（find_get_pid），退出竞态安全：进程隐藏中退出 →
 *     RECOVER 探测 get_pid_task 为空 → 仅清记录并放引用，free_pid 自然收尾。
 *   - pid 号被新进程复用（idr 槽非空）→ 绝不覆盖新条目，转 CONFLICT 保留引用。
 *   - 全局自旋锁 + busy 门闩串行化，锁内无睡眠；stub 入口/出口 inflight 计数，
 *     卸载先 unhook 恢复函数头、再 spin 排空在途调用（对齐 intercept 惯例）。
 *   - 已知边界：被隐藏进程自身的 /proc/self 类访问同样失效（同表查找 + stub）；
 *     负 pgid 组信号/遍历 tasklist 的检测不受本机制覆盖。勿隐藏依赖 /proc/self
 *     的关键进程。
 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <kputils.h>
#include <ksyms.h>
#include <kallsyms.h>
#include <baselib.h>
#include <hook.h>

#include "LH_comm.h"
#include "LH_hide.h"
#include "LH_syms.h"
#include "LH_utils.h"
#include "LH_log.h"
#include "LH_hooks.h"      /* UN_HOOK: prctl FP hook */
#include "LH_intercept.h"  /* UN_HOOK: input 捕获 hook */
#include "LH_gyro.h"       /* UN_HOOK: 传感器 uprobe/tp */
#include "LH_debug.h"      /* UN_HOOK: 硬件断点 */

/* GFP_KERNEL 在 KPM 框架的 gfp.h 中被注释掉，此处手动定义（同 LH_cmd.c） */
#ifndef GFP_KERNEL
#define GFP_KERNEL  0xcc0u
#endif

/* ===== 线程组整体摘除 =====
 * 隐藏时 RCU 遍历收集线程组全部成员（含组长），逐个 find_get_pid 持引用
 * 并摘除；恢复时以**原 struct pid 指针** idr_replace 回填（不重算 nr，
 * 保证 stat 的 pid 字段 == 目录名）。成员表上限 KPM_HIDE_MAX_MEMBERS；
 * 超限整槽拒绝，遍历基础设施缺失退化为 leader-only 并 state=LIMITED
 * 如实降级，绝不半隐藏。 */
#define KPM_HIDE_MAX_MEMBERS 256   /* 每槽成员上限；超出 → 整槽不摘除 +
                                    * limited 降级（宁可不隐藏，绝不半隐藏：
                                    * "leader 消失、线程还在"比不隐藏更易被
                                    * 交叉核对识破） */

/* 被摘成员：struct pid 引用（回填/释放用）+ nr（stub 匹配、回填 id 用）。
 * nr 在摘除时刻自 task->pid 快照，不解析 struct pid 内部布局（跨版本稳）。 */
typedef struct {
    struct pid *pid;
    pid_t       nr;
} kpm_hide_member_t;

/* ===== 隐藏记录槽 ===== */
typedef struct {
    uint8_t      used;      /* 槽位占用 */
    uint8_t      hidden;    /* 隐藏中 */
    uint8_t      conflict;  /* 原 pid 号被占用，不可恢复 */
    uint8_t      limited;   /* 降级：仅枚举级（P1 兜底不可用，直连可能仍可达） */
    pid_t        pid;       /* 隐藏的目标 tgid（宿主 /proc 视角编号） */
    struct pid  *holder;    /* 持有引用（find_get_pid），恢复/清理用 */
    uint8_t      swept;     /* 1 = 组长+全部线程成员已摘除（可完整回填） */
    uint8_t      mconf;     /* 1 = 恢复时成员号存在复用者（保守不回填） */
    uint16_t     nmembers;  /* 线程成员数（不含组长，组长走 pid/holder） */
    kpm_hide_member_t members[KPM_HIDE_MAX_MEMBERS];
    char         name[KPM_HIDE_NAME_MAX];
} kpm_hide_slot_t;

static kpm_hide_slot_t g_hide_slots[KPM_HIDE_MAX];
static kpm_spinlock_t  g_hide_lock = KPM_SPINLOCK_INIT;
static volatile int    g_hide_busy = 0;   /* 长临界区忙闩（可睡眠段串行化） */
static volatile int    g_hide_ready = 0;  /* 0=未初始化 1=可用 <0=失败原因 */

/* ===== 惰性解析的内核符号（不进入 LH_syms 主表，隔离新增符号面） ===== */
static void *g_hide_ns_idr = 0;      /* &init_pid_ns.idr（idr 为首成员，偏移 0，
                                      * 故该地址 == &init_pid_ns，stub 的 ns 判定
                                      * 与 probe 的 init_pid_ns 实参均用它） */
static void (*g_idr_remove)(void *idr, unsigned long id) = 0;
static int  (*g_idr_alloc)(void *idr, void *ptr, int start, int end,
                           unsigned int gfp) = 0;
static void *(*g_idr_replace)(void *idr, void *ptr, unsigned long id) = 0;
static void *(*g_idr_find)(void *idr, unsigned long id) = 0;

/* ===== P1 兜底引擎（/proc/<pid> 直连入口兜底；生命周期=隐藏窗口） =====
 * 不进入 LH_syms 主表，全部惰性 kallsyms 解析，隔离新增符号面。
 *
 * proc_pid_lookup 是全版本（4.19~6.12）VFS /proc 顶层数字目录 lookup 的
 * 唯一必经入口（proc_root_lookup → dir->i_op->lookup），与内核内部通道
 * 语义无关，跨版本稳定（符号 T 导出，kallsyms 可解析）。
 *
 * 判定逻辑：从 dentry 解析目标名。struct dentry 定义不随框架提供（KPM 剪裁），
 * d_name 偏移各内核不同（4.x~0x20、6.1 GKI~0x28）→ 用候选偏移表逐个读取，
 * 每个候选做【指针合法 + 长度 + ASCII 数字】三重校验，合法才参与 pid 比对：
 * 校验不过的候选直接跳过，绝不盲解引用 → 布局不同只会"解析不到"而安全走
 * backup（功能退化为 P0 级），不会崩溃。命中隐藏 pid → 返回 NULL（VFS 视为
 * ENOENT，与 proc_pid_lookup 找不到进程的原语义一致）；其余经 trampoline 保真。
 *
 * 生命周期：P1 默认关闭（g_hide_p1=0），仅客户端显式启用后 P0 成功隐藏
 * 时装；RECOVER 清空生效记录即 unhook。主流内核（P0 已使直连 ENOENT）
 * hook 只是多一跳+查表，行为零变化；hook 面由"仅隐藏窗口存在"对冲
 * （驱动平时依旧零 hook）。 */
static void *g_ppl_entry = 0;   /* proc_pid_lookup 内核原始入口 */
static void *(*g_ppl_backup)(void *dir, void *dentry, unsigned int flg) = 0;
                                  /* hook() 回填的 trampoline（原逻辑保真） */
static int g_hide_l2 = 0;         /* 1 = P1 stub 已安装 */
static int g_hide_p1 = 0;         /* P1 安装开关（默认 0=关闭；客户端显式开启） */
static volatile int g_hide_l2_inflight = 0;  /* stub 在途调用计数（卸载排空） */
/* 在途计数统一为**无锁原子加减**（LH_utils.h kpm_atomic_inc/dec_acq_rel
 * + kpm_inflight_final_zero）。本 stub 频率远低于 prctl/input（且 P1 默认
 * 关闭），**主要是一致性**：drain 的两段式（自旋 + 一次最终确认）必须与
 * 计数实现配套，见 hide_l2_uninstall 与 LH_utils.h 的推导注释。 */
#define KPM_HIDE_L2_DRAIN_TIMEOUT_LOOPS  100000000UL  /* ~10s @10M/s（同 intercept） */

/* struct dentry->d_name 候选偏移（覆盖 4.14~6.12 常见布局） */
#define KPM_HIDE_DNAME_OFF_MAX  5
static const int g_hide_dname_offs[KPM_HIDE_DNAME_OFF_MAX] = {
    0x18, 0x20, 0x28, 0x30, 0x38
};

/* 从 lookup 的 dentry 解析目标 pid；失败返回 <=0。
 * struct qstr（dentry->d_name）布局 4.x~6.x 恒定：{ u64 hash_len; const char
 * *name; } → name 指针在 qstr+8、len(u32) 在 qstr+4。dentry 内 d_name 偏移
 * 各内核不同（候选表覆盖），qstr 内部布局固定。三重校验：name 指针须在内核
 * 地址区（高 16 位全 1）、len 1..5、内容全数字。候选偏移读的是 dcache 已引用
 * 对象内的字段（不越界）；错位偏移读出的字段几乎必然过不了校验 → 保守跳过。
 * dentry 在 VFS lookup 期间被调用方持有，d_name 稳定（/proc 顶层数字目录无
 * rename），裸解引用安全。 */
static int hide_dentry_pid(void *dentry)
{
    unsigned long base = (unsigned long)dentry;
    int k;

    /* 入参硬门：非内核地址区（高 16 位 != 0xffff）入参一律返回 -1，
     * 由 stub 走 backup 保真 —— 本函数绝不裸解引用非内核地址。 */
    if (!dentry || (base >> 48) != 0xffffUL)
        return -1;
    for (k = 0; k < KPM_HIDE_DNAME_OFF_MAX; k++) {
        unsigned long np;
        unsigned int len, i;
        unsigned long pid = 0;

        np = *(volatile unsigned long *)(base + g_hide_dname_offs[k] + 8);
        if ((np >> 48) != 0xffffUL)
            continue;                       /* 非内核地址区（qstr.name） */
        len = *(volatile unsigned int *)(base + g_hide_dname_offs[k] + 4);
        if (len < 1 || len > 5)
            continue;                       /* pid 长度 1..32768(≤5位) */
        for (i = 0; i < len; i++) {
            unsigned int c = *(volatile unsigned char *)(np + i);
            if (c < '0' || c > '9')
                break;
            pid = pid * 10 + (c - '0');
        }
        if (i == len && pid > 0 && pid <= 0x7fffffffL)
            return (int)pid;                /* 全数字且位数吻合 → 命中 */
    }
    return -1;
}

/* stub：拦 /proc/<隐藏pid> 直连 lookup。inflight 计数独立短临界；
 * 表查询在 g_hide_lock 下（hide 流程锁内段不触发 proc lookup → 无锁序环）。
 * 匹配域为槽成员表（组长 + 全部线程）；非 sweep 槽成员表为空时仅匹配
 * 槽.pid（组长）。 */
static void *hide_ppl_stub(void *dir, void *dentry, unsigned int flg)
{
    unsigned long ifl;   /* g_hide_lock 用的 DAIF 保存值（在途计数已改无锁原子） */
    void *ret;
    int nr, i, k, hit = 0;

    /* 入参防御（与 hide_dentry_pid 硬门同源）：VFS lookup 实参恒为有效内核
     * 对象，任一参数非内核地址区（高 16 位 0xffff）即表明 hook 点/调用约定
     * 与目标内核不匹配。此情形不查表不解析，直接经 backup 保真返回；记录
     * 一次现场（dir/dentry/flg）供定性，不静默吞错也不刷屏。 */
    if (((unsigned long)dir >> 48) != 0xffffUL ||
        ((unsigned long)dentry >> 48) != 0xffffUL) {
        static int s_bad_arg_logged;   /* 模块数据段；重载自动清零 */
        if (!s_bad_arg_logged) {
            s_bad_arg_logged = 1;
            kpm_log("hide: P1 stub bad args dir=%p dentry=%p flg=%u "
                    "(bypass to backup)\n", dir, dentry, flg);
        }
        return g_ppl_backup ? g_ppl_backup(dir, dentry, flg) : NULL;
    }

    kpm_atomic_inc_acq_rel(&g_hide_l2_inflight);

    nr = hide_dentry_pid(dentry);
    if (nr > 0) {
        ifl = kpm_spin_lock_irqsave(&g_hide_lock);
        for (i = 0; i < KPM_HIDE_MAX; i++) {
            if (!g_hide_slots[i].used || !g_hide_slots[i].hidden ||
                g_hide_slots[i].conflict)
                continue;
            if (g_hide_slots[i].pid == nr) { hit = 1; break; }
            if (!g_hide_slots[i].swept)
                continue;
            for (k = 0; k < (int)g_hide_slots[i].nmembers; k++) {
                if (g_hide_slots[i].members[k].pid &&
                    g_hide_slots[i].members[k].nr == nr) { hit = 1; break; }
            }
            if (hit) break;
        }
        kpm_spin_unlock_irqrestore(&g_hide_lock, ifl);
        if (hit) {                          /* 命中隐藏表 → 直连视作查无 */
            ret = NULL;
            goto out;
        }
    }
    /* 未命中 / 非数字名：原逻辑保真（trampoline 由框架持有，unhook 后仍有效） */
    ret = g_ppl_backup ? g_ppl_backup(dir, dentry, flg) : NULL;
out:
    kpm_atomic_dec_acq_rel(&g_hide_l2_inflight);
    return ret;
}

/* ===== 线程组 sweep 基础设施 =====
 * tasklist RCU 遍历收集指定线程组的全部成员（含组长）。复用 LH_proc.c
 * 已验证的免引用遍历范式（kpm_next_task 自带内核地址双重校验 +
 * copy_from_kernel_nofault，任何一环缺失/失效只会"收不到"，不会崩）。
 * 收引用用 find_get_pid（RCU 安全，原子 inc，不睡眠）。
 * 返回：>=0 收集条数；-1 基础设施不可用（调用方退回 leader-only
 * 并如实 limited）；-2 成员数超上限（一个都不摘，宁缺勿半）。
 * out[] 由调用方栈/静态缓冲提供，收集阶段持引用；摘除失败或槽满回滚
 * 时由调用方逐个 put_pid。 */
struct hide_scan_ctx {
    pid_t leader;
    kpm_hide_member_t *out;
    int n, max;
};

static long hide_scan_cb(struct task_struct *t, pid_t nr, void *ud)
{
    struct hide_scan_ctx *c = (struct hide_scan_ctx *)ud;

    if (kpm_task_tgid(t) != c->leader)
        return 0;
    if (c->n >= c->max)
        return -2;                      /* 超上限：终止，调用方整槽放弃 */
    c->out[c->n].nr = nr;               /* 扫描自带的线程 nr（已哈希） */
    c->out[c->n].pid = kf_find_get_pid(nr);
    if (c->out[c->n].pid)
        c->n++;
    return 0;
}

static int hide_collect_tg(pid_t leader, kpm_hide_member_t *out, int max)
{
    /* 优先用 kpm_task_scan_by_pid 安全扫描（pid 号空间正向遍历，任务来自
     * 已哈希 pid，符号调用天然安全）；基础设施不可用时回退框架
     * tasks/pid/tgid 偏移的 tasklist 正向遍历。 */
    if (kpm_task_scan_available()) {
        struct hide_scan_ctx ctx;
        long n;

        if (!kf_find_get_pid || !kf_put_pid)
            return -1;
        ctx.leader = leader;
        ctx.out = out;
        ctx.n = 0;
        ctx.max = max;
        n = kpm_task_scan_by_pid(hide_scan_cb, &ctx);
        if (n == -2) {
            int k;
            for (k = 0; k < ctx.n; k++)
                if (kf_put_pid) kf_put_pid(ctx.out[k].pid);
            return -2;
        }
        if (ctx.n == 0)
            return -1;
        return ctx.n;
    }

    if (!(g_tasks_offset > 0 && g_pid_offset > 0 && g_tgid_offset > 0 &&
          kf_init_task && kf_rcu_read_lock && kf_rcu_read_unlock &&
          kf_copy_from_kernel_nofault && kf_find_get_pid))
        return -1;

    {
    struct task_struct *task, *first;
    int n = 0, iter = 0;
    const int MAX_ITER = 65536;

    KPM_RCU_READ_LOCK();
    first = KPM_NEXT_TASK(kf_init_task);
    task = first;
    if (!first) {
        KPM_RCU_READ_UNLOCK();
        return -1;
    }
    do {
        pid_t p = 0, tg = 0;
        struct pid *ps;

        if (++iter > MAX_ITER)
            break;
        if ((uint64_t)task < 0xFFFF000000000000ULL)
            goto next;
        if (kf_copy_from_kernel_nofault(&p,
                (void *)((unsigned long)task + g_pid_offset), 4) != 0)
            goto next;
        if (p <= 0 || p > kpm_pid_max())
            goto next;
        if (kf_copy_from_kernel_nofault(&tg,
                (void *)((unsigned long)task + g_tgid_offset), 4) != 0)
            goto next;
        if (tg != leader)
            goto next;

        if (n >= max) {                 /* 超上限：整槽放弃 sweep */
            KPM_RCU_READ_UNLOCK();
            for (iter = 0; iter < n; iter++)
                if (kf_put_pid) kf_put_pid(out[iter].pid);
            return -2;
        }
        ps = kf_find_get_pid(p);
        if (!ps)
            goto next;                  /* 极罕见竞态：本 tick 内已回收 */
        out[n].pid = ps;
        out[n].nr  = p;
        n++;
    next:
        task = KPM_NEXT_TASK(task);
    } while (task && task != first && task != kf_init_task);
    KPM_RCU_READ_UNLOCK();

    if (n == 0)
        return -1;                      /* 遍历失效（探测/链表读取失败） */
    return n;
    }
}

/* 摘除单个成员：idr_remove + 生效确认。成功 0；未生效 -1（条目还在）。 */
static int hide_member_remove(kpm_hide_member_t *m)
{
    g_idr_remove(g_hide_ns_idr, (unsigned long)m->nr);
    return (g_idr_find(g_hide_ns_idr, (unsigned long)m->nr) != NULL) ? -1 : 0;
}

/* 回填单个成员（隐藏失败回滚用）：idr_alloc 精确占位 + idr_replace 写回
 * 原 struct pid，**不动引用**（调用方统一 put）。号被占用（μs 级竞态）
 * 则跳过 —— 宁可挂一个引用，绝不覆盖新主人的条目。 */
static void hide_member_rollback(const kpm_hide_member_t *m)
{
    if (g_idr_find(g_hide_ns_idr, (unsigned long)m->nr) != NULL)
        return;
    if (g_idr_alloc(g_hide_ns_idr, NULL, (int)m->nr, (int)m->nr + 1,
                    GFP_KERNEL) == (int)m->nr)
        g_idr_replace(g_hide_ns_idr, (void *)m->pid, (unsigned long)m->nr);
}

/* 恢复单个成员（RECOVER 路径）。引用记账收口在本函数：
 *  0 = 已回填（原指针写回），引用已随回填交还内核（内部 put + m->pid 置 NULL）；
 *  1 = 号被复用/占位失败 —— 不动，引用保留（m->pid 原样），槽记 mconf 下轮重试；
 *  2 = 目标已退出且号空闲 —— 仅放引用自然收尾（free_pid 无条目可删，正确）。 */
static int hide_member_restore(kpm_hide_member_t *m)
{
    struct task_struct *t = 0;
    int alive;

    if (g_idr_find(g_hide_ns_idr, (unsigned long)m->nr) != NULL)
        return 1;

    /* 存在性探测（免引用优先；noref 不可用时保守按存活处理，走回填路径，
     * 回填后若目标确已退出，free_pid 会把这条目删掉，语义依旧自洽） */
    if (kpm_task_begin_pidref(m->pid, &t) == 0) {
        alive = (t != 0);
        kpm_task_end();
    } else {
        alive = -1;
    }

    if (alive == 0) {
        if (kf_put_pid) kf_put_pid(m->pid);
        m->pid = 0;
        return 2;
    }
    if (g_idr_alloc(g_hide_ns_idr, NULL, (int)m->nr, (int)m->nr + 1,
                    GFP_KERNEL) == (int)m->nr) {
        g_idr_replace(g_hide_ns_idr, (void *)m->pid, (unsigned long)m->nr);
        if (kf_put_pid) kf_put_pid(m->pid);   /* 与 leader 恢复记账一致 */
        m->pid = 0;
        return 0;
    }
    return 1;
}

/* 是否存在"生效中"的隐藏记录（used && hidden && !conflict；仅这类被 stub 拦） */
static int hide_has_active(void)
{
    unsigned long flags;
    int i, n = 0;
    flags = kpm_spin_lock_irqsave(&g_hide_lock);
    for (i = 0; i < KPM_HIDE_MAX; i++) {
        if (g_hide_slots[i].used && g_hide_slots[i].hidden &&
            !g_hide_slots[i].conflict)
            n++;
    }
    kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
    return n;
}

/* 安装 P1 stub（P0 成功隐藏后调用）。幂等。 */
static long hide_l2_install(void)
{
    hook_err_t err;

    if (g_hide_l2)
        return 0;
    if (!g_ppl_entry)
        return -KPM_E_NOTFOUND;
    err = hook(g_ppl_entry, (void *)hide_ppl_stub, (void **)&g_ppl_backup);
    if (err != HOOK_NO_ERR) {
        kpm_log("hide: P1 hook(proc_pid_lookup) failed: %d\n", (int)err);
        return -KPM_E_BUSY;
    }
    g_hide_l2 = 1;
    kpm_log("hide: P1 fallback active: direct /proc/<hidden-pid> now ENOENT\n");
    return 0;
}

/* 拆除 P1 stub：先 unhook 恢复函数头（新调用不再进 stub），再 spin 排空
 * 在途 stub（均短促，经 trampoline 退出；对齐 intercept hook_unwrap 惯例）。 */
static void hide_l2_uninstall(void)
{
    unsigned long spins = 0;
    int infl, confirm_tries = 0;

    if (!g_hide_l2)
        return;
    unhook(g_ppl_entry);
    g_hide_l2 = 0;
    for (;;) {
        /* 第一段：acquire 读自旋等归零（无附加延迟） */
        while ((infl = kpm_atomic_read_acquire(&g_hide_l2_inflight)) != 0) {
            if (++spins > KPM_HIDE_L2_DRAIN_TIMEOUT_LOOPS) {
                kpm_log("hide: P1 stub drain timeout (%d inflight)\n", infl);
                goto drained;
            }
            asm volatile("yield" ::: "memory");
        }
        /* 第二段：一次性最终确认（barrier + 有界等待 + 复读），
         * 关掉"inc 的 store 还在 store buffer"的窗口（LH_utils.h）。 */
        if (kpm_inflight_final_zero(&g_hide_l2_inflight))
            break;
        if (++confirm_tries >= 3) {
            kpm_log("hide: P1 stub inflight unstable after %d confirmations\n",
                    confirm_tries);
            break;
        }
    }
drained:
    g_ppl_backup = 0;
    kpm_log("hide: P1 fallback hook removed (proc_pid_lookup restored)\n");
}

/* 标记槽位为降级（P1 不可用 → 仅枚举级，直连可能仍可达） */
static void hide_mark_limited(int slot)
{
    unsigned long flags;
    flags = kpm_spin_lock_irqsave(&g_hide_lock);
    if (slot >= 0 && slot < KPM_HIDE_MAX)
        g_hide_slots[slot].limited = 1;
    kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
}

/* P0 隐藏成功后的 P1 兜底。P1 安装默认关闭（g_hide_p1==0 → 纯 P0 语义，
 * 稳定无 hook）；仅客户端显式启用后才解析并安装 stub。
 * proc_pid_lookup 全版本存在；解析/安装失败才降级 limited（如实告知）。
 * ⚠ 启用前请先在目标内核完成稳定性验证。 */
static void hide_l2_after_hide(int slot)
{
    if (!g_hide_p1)
        return;                       /* P1 未启用：保持纯 P0（稳定默认） */
    if (g_hide_l2)
        return;                       /* 已兜底，全表生效 */
    if (!g_ppl_entry) {
        g_ppl_entry = (void *)kallsyms_lookup_name("proc_pid_lookup");
        if (!g_ppl_entry) {
            kpm_log("hide: proc_pid_lookup unresolved, pid limited "
                    "(enumeration-only)\n");
            hide_mark_limited(slot);
            return;
        }
    }
    if (hide_l2_install()) {
        /* P1 装不上 → 如实降级（直连仍可见，HIDE_LIST state=LIMITED） */
        hide_mark_limited(slot);
    }
}

/* KPM_CMD_HIDE_P1：运行时开关 P1 兜底（0=关闭 1=启用）。
 * 关闭时若 stub 已装则立即拆除（含 RECOVER 全清语义）；启用仅置位，
 * 下一个 HIDE 生效。返回当前开关状态。 */
long kpm_hide_p1_set(int enable)
{
    if (enable < 0)
        return g_hide_p1;
    if (enable > 1)
        enable = 1;
    g_hide_p1 = enable;
    if (!enable)
        hide_l2_uninstall();          /* 关闭：立即拆 stub（幂等） */
    kpm_log("hide: P1 fallback %s (next HIDE will%s install proc_pid_lookup "
            "stub)\n", enable ? "ENABLED" : "DISABLED", enable ? "" : " NOT");
    return g_hide_p1;
}

/* ===== busy 门闩（可睡眠段互斥；操作间互斥即可，无需计数） ===== */
static int hide_busy_enter(void)
{
    unsigned long flags;
    flags = kpm_spin_lock_irqsave(&g_hide_lock);
    if (g_hide_busy) {
        kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
        return 0;
    }
    g_hide_busy = 1;
    kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
    return 1;
}

static void hide_busy_leave(void)
{
    unsigned long flags;
    flags = kpm_spin_lock_irqsave(&g_hide_lock);
    g_hide_busy = 0;
    kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
}

/* ===== 初始化：惰性符号解析 + idr@0 自检（首次 HIDE 命令触发） ===== */
long kpm_hide_init(void)
{
    unsigned long addr;

    if (g_hide_ready != 0)
        return (g_hide_ready > 0) ? 0 : (long)g_hide_ready;

    addr = kallsyms_lookup_name("init_pid_ns");
    if (!addr) {
        kpm_log("hide: init_pid_ns not found, process hiding disabled\n");
        g_hide_ready = -KPM_E_NOTFOUND;
        return (long)g_hide_ready;
    }
    g_hide_ns_idr = (void *)addr;   /* struct pid_namespace 首成员即 idr */

    g_idr_remove  = (void *)kallsyms_lookup_name("idr_remove");
    g_idr_alloc   = (void *)kallsyms_lookup_name("idr_alloc");
    g_idr_replace = (void *)kallsyms_lookup_name("idr_replace");
    g_idr_find    = (void *)kallsyms_lookup_name("idr_find");
    if (!g_idr_remove || !g_idr_alloc || !g_idr_replace || !g_idr_find) {
        kpm_log("hide: idr symbols missing (remove=%lx alloc=%lx replace=%lx "
                "find=%lx), disabled\n",
                (unsigned long)g_idr_remove, (unsigned long)g_idr_alloc,
                (unsigned long)g_idr_replace, (unsigned long)g_idr_find);
        g_hide_ready = -KPM_E_NOTFOUND;
        return (long)g_hide_ready;
    }

    /* 自检：&init_pid_ns == &init_pid_ns.idr（idr 首成员），
     * 且 pid 1 在 idr 中可经 idr_find 命中 find_get_pid 同一对象。 */
    if (kf_find_get_pid && kf_put_pid) {
        struct pid *p1 = kf_find_get_pid(1);
        if (p1) {
            if (g_idr_find(g_hide_ns_idr, 1) == (void *)p1) {
                kf_put_pid(p1);
                g_hide_ready = 1;
                kpm_log("hide: pid idr ready (ns_idr=0x%llx), "
                        "process hiding enabled\n",
                        (unsigned long long)(unsigned long)g_hide_ns_idr);
                return 0;
            }
            kpm_log("hide: idr self-test failed (pid1 mismatch), "
                    "kernel pid table not idr@0? disabled\n");
            kf_put_pid(p1);
        } else {
            kpm_log("hide: pid1 lookup failed, self-test aborted, disabled\n");
        }
    } else {
        kpm_log("hide: find_get_pid/put_pid unavailable, disabled\n");
    }
    g_hide_ready = -KPM_E_NOTFOUND;
    return (long)g_hide_ready;
}

/* ===== HIDE_PROCESS 执行层 ===== */
long kpm_hide_process(pid_t pid)
{
    struct pid *pidref;
    int slot = -1, i;
    unsigned long flags;
    long ret;
    char name[KPM_HIDE_NAME_MAX];

    if (pid <= 0)
        return -KPM_E_INVAL;
    ret = kpm_hide_init();
    if (ret)
        return ret;   /* 已记录原因 */
    if (!hide_busy_enter())
        return -KPM_E_BUSY;

    /* 幂等：已在隐藏列表 → 返回既有槽位 */
    flags = kpm_spin_lock_irqsave(&g_hide_lock);
    for (i = 0; i < KPM_HIDE_MAX; i++) {
        if (g_hide_slots[i].used && g_hide_slots[i].hidden &&
            !g_hide_slots[i].conflict && g_hide_slots[i].pid == pid) {
            slot = i + 1;
            break;
        }
    }
    if (slot > 0) {
        kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
        hide_busy_leave();
        return slot;
    }
    /* 找空槽（无空槽时先释放已退出进程的残留记录） */
    for (i = 0; i < KPM_HIDE_MAX; i++) {
        if (!g_hide_slots[i].used) { slot = i; break; }
    }
    kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
    if (slot < 0) {
        /* 尝试清理 exited 残留后再分配一次 */
        kpm_hide_recover(0);
        flags = kpm_spin_lock_irqsave(&g_hide_lock);
        for (i = 0; i < KPM_HIDE_MAX; i++) {
            if (!g_hide_slots[i].used) { slot = i; break; }
        }
        kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
        if (slot < 0) {
            kpm_log("hide: slot exhausted (max %d)\n", KPM_HIDE_MAX);
            hide_busy_leave();
            return -KPM_E_BUSY;
        }
    }

    /* 取引用 + 快照名称（可睡眠段，锁外执行） */
    pidref = kf_find_get_pid ? kf_find_get_pid(pid) : 0;
    if (!pidref) {
        kpm_log("hide: pid %d not found in current namespace\n", pid);
        hide_busy_leave();
        return -KPM_E_NOTFOUND;
    }
    name[0] = '\0';
    if (kf_get_task_comm) {
        /* 用免引用取 task（comm 读取不睡眠），不依赖 put_task_struct /
         * usage 偏移（取引用后归还在未标定内核上会泄漏）。*/
        struct task_struct *tsk = 0;
        int needs_put = 0;

        if (kpm_task_acquire(pid, &tsk, &needs_put) == 0) {
            lib_memset(name, 0, sizeof(name));
            if (kf_get_task_comm(name, sizeof(name) - 1, tsk))
                name[sizeof(name) - 1] = '\0';
            if (needs_put) kpm_put_task_struct(tsk); else kpm_task_end();
        }
    }

    /* ===== 线程组 sweep =====
     * 收集组长 + 全部线程并整组摘除：
     *   collect -1（遍历基础设施缺失）→ leader-only + limited 如实降级；
     *   collect -2（成员超上限）→ 整槽放弃，绝不半隐藏；
     *   单线程进程（成员表空）同样 collect_ok → 完整 sweep 语义。
     * members[] 不含组长（组长由 holder/slot.pid 既有语义独立管理）；
     * collect 对组长号另取的一份引用在压缩时统一归还。
     * 缓冲静态分配：busy 门闩已串行化 hide/recover，全局共用一把即可。 */
    {
        static kpm_hide_member_t s_collect[KPM_HIDE_MAX_MEMBERS + 1];
        kpm_hide_member_t lead;
        int nc, j, w = 0, nm = 0;
        int collect_ok = 0, swept = 0;

        lead.pid = pidref;
        lead.nr  = pid;

        nc = hide_collect_tg(pid, s_collect, KPM_HIDE_MAX_MEMBERS + 1);
        if (nc == -2) {
            kpm_log("hide: pid %d thread group exceeds %d members, "
                    "refuse (no half-hide)\n", pid, KPM_HIDE_MAX_MEMBERS);
            kf_put_pid(pidref);
            hide_busy_leave();
            return -KPM_E_BUSY;
        }
        if (nc >= 0) {
            collect_ok = 1;
            /* 压缩为"不含组长的成员表"（组长条目引用归还，外层 pidref
             * 是独立一份，由 slot.holder 持有） */
            for (j = 0; j < nc; j++) {
                if (s_collect[j].nr == pid) {
                    if (kf_put_pid) kf_put_pid(s_collect[j].pid);
                    continue;
                }
                s_collect[w++] = s_collect[j];
            }
            nc = w;
            if (nc > KPM_HIDE_MAX_MEMBERS) {   /* 防御（collect 上限已拦） */
                for (j = 0; j < nc; j++)
                    if (kf_put_pid) kf_put_pid(s_collect[j].pid);
                kf_put_pid(pidref);
                hide_busy_leave();
                return -KPM_E_BUSY;
            }
        } else {
            nc = 0;
            kpm_log("hide: pid %d sweep infra unavailable, "
                    "leader-only hide (limited)\n", pid);
        }

        /* 组长先摘（失败 = idr 布局非预期 → 整槽回滚） */
        if (hide_member_remove(&lead) != 0) {
            for (j = 0; j < nc; j++)
                if (kf_put_pid) kf_put_pid(s_collect[j].pid);
            kpm_log("hide: idr_remove(%d) failed to take effect, rollback\n",
                    pid);
            kf_put_pid(pidref);
            hide_busy_leave();
            return -KPM_E_BUSY;
        }

        /* 线程成员逐个摘；中途失败 → 已摘回填+放引用，未摘放引用，
         * 组长回填（引用仍由本函数统一放）——回到"什么都没发生" */
        for (nm = 0; nm < nc; nm++) {
            if (hide_member_remove(&s_collect[nm]) != 0)
                break;
        }
        if (nm < nc) {
            for (j = 0; j < nm; j++) {
                hide_member_rollback(&s_collect[j]);
                if (kf_put_pid) kf_put_pid(s_collect[j].pid);
            }
            for (j = nm; j < nc; j++)
                if (kf_put_pid) kf_put_pid(s_collect[j].pid);
            hide_member_rollback(&lead);
            kpm_log("hide: idr_remove failed mid-sweep at member %d, "
                    "rollback pid %d\n", s_collect[nm].nr, pid);
            kf_put_pid(pidref);
            hide_busy_leave();
            return -KPM_E_BUSY;
        }
        swept = collect_ok;   /* 整组摘除完成（含"仅组长"的单线程进程） */

        flags = kpm_spin_lock_irqsave(&g_hide_lock);
        g_hide_slots[slot].used     = 1;
        g_hide_slots[slot].hidden   = 1;
        g_hide_slots[slot].conflict = 0;
        g_hide_slots[slot].limited  = swept ? 0 : 1;  /* leader-only 如实降级 */
        g_hide_slots[slot].pid      = pid;
        g_hide_slots[slot].holder   = pidref;
        g_hide_slots[slot].swept    = (uint8_t)swept;
        g_hide_slots[slot].mconf    = 0;
        g_hide_slots[slot].nmembers = swept ? (uint16_t)nc : 0;
        if (swept && nc > 0)
            lib_memcpy(g_hide_slots[slot].members, s_collect,
                       (size_t)nc * sizeof(kpm_hide_member_t));
        lib_memcpy(g_hide_slots[slot].name, name, sizeof(name));
        kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
    }

    /* 回退链 P1：P0 摘除成功后装 proc_pid_lookup 兜底（stub 查表需此 slot
     * 已写入）。幂等 hide 已提前返回，不会走到这里。 */
    hide_l2_after_hide(slot);

    hide_busy_leave();
    kpm_log("hide: pid %d hidden (slot %d, name=%s)\n", pid, slot + 1, name);
    return slot + 1;
}

/* 恢复指定槽的全部线程成员（锁外调用；内部自取锁拷贝成员表）。
 * 每个成员独立判活回填（引用记账见 hide_member_restore 三态注释）。
 * 回填冲突（号被复用——struct pid 引用在手上时理论不可能，纯防御）的
 * 成员保留在槽内（mconf=1、nmembers=剩余数），下轮 recover 经 mconf
 * 通道重试；left==0 且 keep_slot==0 时整槽清空。返回残留成员数。 */
static int hide_restore_members(int scanned, int keep_slot)
{
    static kpm_hide_member_t s_mem[KPM_HIDE_MAX_MEMBERS];
    unsigned long flags;
    int nm, k, left = 0;

    flags = kpm_spin_lock_irqsave(&g_hide_lock);
    nm = (int)g_hide_slots[scanned].nmembers;
    if (nm > KPM_HIDE_MAX_MEMBERS)
        nm = KPM_HIDE_MAX_MEMBERS;
    if (nm > 0)
        lib_memcpy(s_mem, g_hide_slots[scanned].members,
                   (size_t)nm * sizeof(kpm_hide_member_t));
    kpm_spin_unlock_irqrestore(&g_hide_lock, flags);

    for (k = 0; k < nm; k++) {
        if (hide_member_restore(&s_mem[k]) == 1)
            s_mem[left++] = s_mem[k];     /* 冲突：引用与记录保留，下轮重试 */
    }

    flags = kpm_spin_lock_irqsave(&g_hide_lock);
    if (left == 0 && !keep_slot) {
        g_hide_slots[scanned].used     = 0;
        g_hide_slots[scanned].hidden   = 0;
        g_hide_slots[scanned].swept    = 0;
        g_hide_slots[scanned].mconf    = 0;
        g_hide_slots[scanned].nmembers = 0;
        g_hide_slots[scanned].holder   = 0;   /* 组长记账在调用方，先行收口 */
    } else {
        g_hide_slots[scanned].mconf    = (uint8_t)(left ? 1 : 0);
        g_hide_slots[scanned].nmembers = (uint16_t)left;
        if (left > 0)
            lib_memcpy(g_hide_slots[scanned].members, s_mem,
                       (size_t)left * sizeof(kpm_hide_member_t));
    }
    kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
    return left;
}

/* ===== RECOVER_PROCESS 执行层（pid<=0 恢复全部） ===== */
long kpm_hide_recover(pid_t pid)
{
    int recovered = 0, scanned;
    int have = 0, i;
    unsigned long flags;
    long ret;

    /* 先看有没有需要处理的记录：hidden 主路径 + mconf 成员残留重试通道
     * （conflict 槽 leader 号被占不可动，其成员同持引用一并原地保留） */
    flags = kpm_spin_lock_irqsave(&g_hide_lock);
    for (i = 0; i < KPM_HIDE_MAX; i++) {
        if (g_hide_slots[i].used &&
            ((g_hide_slots[i].hidden && !g_hide_slots[i].conflict) ||
             (!g_hide_slots[i].hidden && g_hide_slots[i].mconf)) &&
            (pid <= 0 || g_hide_slots[i].pid == pid)) {
            have = 1;
            break;
        }
    }
    kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
    if (!have)
        return 0;                       /* 无匹配隐藏记录 */

    ret = kpm_hide_init();
    if (ret)
        return ret;                     /* 原因已记录 */
    if (!hide_busy_enter())
        return -KPM_E_BUSY;

    for (scanned = 0; scanned < KPM_HIDE_MAX; scanned++) {
        struct pid *holder;
        pid_t tgid;
        unsigned long flags;
        int alive;
        void *cur;

        flags = kpm_spin_lock_irqsave(&g_hide_lock);
        if (!g_hide_slots[scanned].used) {
            kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
            continue;
        }
        if (pid > 0 && g_hide_slots[scanned].pid != pid) {
            kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
            continue;
        }
        if (!g_hide_slots[scanned].hidden || g_hide_slots[scanned].conflict) {
            /* 组长已收口、成员残留 → 纯重试通道（清空即释放槽）。
             * conflict：跳过（leader 与成员引用一并原地保留）。 */
            int is_retry = (g_hide_slots[scanned].mconf &&
                            !g_hide_slots[scanned].hidden &&
                            !g_hide_slots[scanned].conflict);
            kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
            if (is_retry) {
                if (hide_restore_members(scanned, 0) == 0)
                    recovered++;
            }
            continue;
        }
        holder = g_hide_slots[scanned].holder;
        tgid   = g_hide_slots[scanned].pid;
        kpm_spin_unlock_irqrestore(&g_hide_lock, flags);

        /* ---- 锁外长临界区（可睡眠） ----
         * 组长存在性探测（免引用看一眼 pid_task，不持引用；仅当免引用
         * 不可用时回退 get_pid_task 取引用路径）。 */
        {
            struct task_struct *t = 0;

            if (kpm_task_begin_pidref(holder, &t) == 0) {
                alive = (t != 0);
                kpm_task_end();               /* 免引用：看一眼即退 RCU */
            } else if (kf_get_pid_task) {
                t = kf_get_pid_task(holder, PIDTYPE_PID);
                alive = (t != 0);
                if (t)
                    kpm_put_task_struct(t);   /* 回退路径：取过引用才归还 */
            } else {
                alive = 0;
            }
        }

        if (!alive) {
            /* 组长已退出/回收：成员逐个收尾（各自判活；多数随组长已释放，
             * hide_member_restore 返回 2 = 确认退出且号空闲）。组长 idr
             * 号被复用时不放引用（防误删新进程条目），并把
             * 记录转为"leader 已清、成员按需重试"的残留态。 */
            int left;
            cur = g_idr_find(g_hide_ns_idr, (unsigned long)tgid);
            left = hide_restore_members(scanned, 1);
            flags = kpm_spin_lock_irqsave(&g_hide_lock);
            g_hide_slots[scanned].hidden = 0;
            g_hide_slots[scanned].holder = 0;
            if (left == 0) {
                /* 成员全部收尾 → 槽释放（无论组长号归属） */
                g_hide_slots[scanned].used     = 0;
                g_hide_slots[scanned].swept    = 0;
                g_hide_slots[scanned].mconf    = 0;
                g_hide_slots[scanned].nmembers = 0;
            }
            kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
            if (cur == NULL) {
                if (kf_put_pid) kf_put_pid(holder);
            } else {
                /* 号被占用（理论上持引用期间 alloc_pid 不会复用此号；命中
                 * 说明 idr 布局假设不成立等深层异常）：维持"宁漏勿滥"
                 * 语义——不放引用、不动条目，转日志留证。 */
                kpm_log("hide: pid %d reused while hidden(exited), "
                        "holder kept (nr clobber risk)\n", tgid);
            }
            if (left)
                kpm_log("hide: pid %d exited, %d member restore(s) deferred\n",
                        tgid, left);
            recovered++;
            continue;
        }

        cur = g_idr_find(g_hide_ns_idr, (unsigned long)tgid);
        if (cur != NULL) {
            /* 原号已被新进程占用：不可恢复，转 CONFLICT 记录（组长引用
             * 保留；线程成员各自持引用、号不被触碰，一并原地保留） */
            flags = kpm_spin_lock_irqsave(&g_hide_lock);
            g_hide_slots[scanned].conflict = 1;
            kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
            kpm_log("hide: pid %d slot occupied by another process, "
                    "cannot restore (conflict)\n", tgid);
            continue;
        }

        /* 恢复组长：同 alloc_pid 语义 —— idr_alloc 精确占位 + idr_replace
         * 回填**原 struct pid**（成员回填走同一语义，不重算 nr）。 */
        if (g_idr_alloc(g_hide_ns_idr, NULL, (int)tgid,
                        (int)tgid + 1, GFP_KERNEL) == (int)tgid) {
            int left;
            g_idr_replace(g_hide_ns_idr, (void *)holder,
                          (unsigned long)tgid);
            flags = kpm_spin_lock_irqsave(&g_hide_lock);
            g_hide_slots[scanned].hidden = 0;
            g_hide_slots[scanned].holder = 0;
            kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
            if (kf_put_pid) kf_put_pid(holder);

            left = hide_restore_members(scanned, 0);  /* 无残留即清空槽 */
            if (left)
                kpm_log("hide: pid %d leader restored, %d member "
                        "restore(s) deferred\n", tgid, left);
            recovered++;
            kpm_log("hide: pid %d restored to /proc\n", tgid);
        } else {
            kpm_log("hide: pid %d re-insert failed (ENOSPC), stays hidden\n",
                    tgid);
        }
    }

    /* 回退链生命周期：无任何"生效中"隐藏记录 → 拆除 P1 stub（若有），
     * 恢复 proc_pid_lookup 原函数，零残留。conflict 残留不拦任何 pid
     * （stub 判定排除 conflict），但保持已装 stub 无害；其随进程退出由
     * 后续 recover/exit 收尾时一并拆除。 */
    if (!hide_has_active())
        hide_l2_uninstall();
    hide_busy_leave();
    return recovered;
}

/* ===== HIDE_LIST 执行层 ===== */
long kpm_hide_list(kpm_hide_entry_t *entries, int max_count)
{
    int i, n = 0;
    unsigned long flags;

    if (!entries || max_count <= 0)
        return -KPM_E_INVAL;
    if (max_count > KPM_HIDE_MAX)
        max_count = KPM_HIDE_MAX;

    flags = kpm_spin_lock_irqsave(&g_hide_lock);
    for (i = 0; i < KPM_HIDE_MAX && n < max_count; i++) {
        kpm_hide_entry_t *e = &entries[n];
        const kpm_hide_slot_t *s = &g_hide_slots[i];
        lib_memset(e, 0, sizeof(*e));
        e->slot = i + 1;
        if (!s->used) {
            e->state = 0;
        } else if (s->hidden && s->conflict) {
            e->state = KPM_HIDE_STATE_CONFLICT;
        } else if (s->hidden && s->limited) {
            e->state = KPM_HIDE_STATE_LIMITED;   /* 仅枚举级（P1 不可用） */
        } else if (s->hidden) {
            e->state = KPM_HIDE_STATE_HIDDEN;
        } else {
            e->state = KPM_HIDE_STATE_EXITED;
        }
        if (s->used) {
            e->pid = s->pid;
            e->tid = s->pid;
            lib_memcpy(e->name, s->name, sizeof(e->name));
        }
        n++;
    }
    kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
    return n;
}

/* ===== UN_HOOK 执行层 ===== */
long kpm_hide_unhook(unsigned long mask, int from_prctl)
{
    int removed = 0;

    if (mask == 0)
        mask = KPM_UNHOOK_ALL;
    mask &= KPM_UNHOOK_ALL;

    if (mask & KPM_UNHOOK_PRCTL) {
        if (from_prctl) {
            kpm_log("hide: UN_HOOK prctl-bit must be sent via UDP "
                    "(would self-unhook inside callback)\n");
            return -KPM_E_BUSY;
        }
        if (kpm_hooks_active()) {
            kpm_hooks_exit();     /* 幂等（g_prctl_hooked 门控 + inflight 排空） */
            removed++;
        }
    }

    if (mask & KPM_UNHOOK_INPUT) {
        if (kpm_intercept_hook_active()) {
            kpm_intercept_hook_uninstall();   /* 幂等 */
            kpm_clear_state(KPM_STATE_INTERCEPT_OK);   /* 防 info 假可用 */
            removed++;
        } else {
            kpm_log("hide: unhook input: no capture hook installed\n");
        }
    }

    if (mask & KPM_UNHOOK_GYRO) {
        if (kpm_gyro_hook_active()) {
            kpm_gyro_exit();      /* 幂等：uprobe + sys_enter tp 全下线 */
            kpm_clear_state(KPM_STATE_GYRO_OK);   /* 防 info 假可用 */
            removed++;
        } else {
            kpm_log("hide: unhook gyro: no sensor hook installed\n");
        }
    }

    if (mask & KPM_UNHOOK_BP) {
        if (kpm_debug_bp_count_active() > 0) {
            kpm_debug_exit();     /* disarm 全部 + 停通知 + 销毁 bp wq（幂等） */
            removed++;
        } else {
            kpm_log("hide: unhook bp: no active breakpoint\n");
        }
    }

    kpm_log("hide: unhook mask=0x%lx removed %d hook class(es)\n",
            mask, removed);
    return removed;
}

/* ===== 退出：卸载前恢复全部隐藏进程 ===== */
void kpm_hide_exit(void)
{
    int i;

    if (g_hide_ready != 1) {
        /* 未启用隐藏：仍有记录（异常路径）也直接清理引用 */
        unsigned long flags;
        for (i = 0; i < KPM_HIDE_MAX; i++) {
            struct pid *h = NULL;
            flags = kpm_spin_lock_irqsave(&g_hide_lock);
            if (g_hide_slots[i].used && g_hide_slots[i].holder) {
                h = g_hide_slots[i].holder;
                g_hide_slots[i].used = 0;
                g_hide_slots[i].hidden = 0;
                g_hide_slots[i].holder = 0;
            }
            kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
            if (h && kf_put_pid)
                kf_put_pid(h);
        }
        return;
    }

    kpm_hide_recover(0);

    /* conflict 残留：记录在案，引用保留到进程自然退出（勿 put，防误删） */
    {
        int n = 0;
        unsigned long flags;
        flags = kpm_spin_lock_irqsave(&g_hide_lock);
        for (i = 0; i < KPM_HIDE_MAX; i++) {
            if (g_hide_slots[i].used && g_hide_slots[i].hidden)
                n++;
        }
        kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
        if (n)
            kpm_log("hide: exit with %d unresolvable hidden record(s) "
                    "(pid number reused, holder kept to prevent clobber)\n", n);
    }

    /* 成员残留（leader 已收口、mconf 置位、recover 重试未成）：模块 .text
     * 即将释放，无人再消费这些引用 —— 统一 put 收口，防 struct pid 泄漏。
     * hidden 槽若仍在（recover 未清）其 members 与 holder 同生命周期，
     * 上一段已按"引用保留防误删"处理，这里只清 !hidden 的残留记录。 */
    {
        static kpm_hide_member_t s_drain[KPM_HIDE_MAX_MEMBERS];
        unsigned long flags;
        int left;
        for (i = 0; i < KPM_HIDE_MAX; i++) {
            int k, nm;
            flags = kpm_spin_lock_irqsave(&g_hide_lock);
            if (g_hide_slots[i].used && !g_hide_slots[i].hidden &&
                g_hide_slots[i].nmembers > 0) {
                nm = (int)g_hide_slots[i].nmembers;
                if (nm > KPM_HIDE_MAX_MEMBERS)
                    nm = KPM_HIDE_MAX_MEMBERS;
                lib_memcpy(s_drain, g_hide_slots[i].members,
                           (size_t)nm * sizeof(kpm_hide_member_t));
                g_hide_slots[i].used     = 0;
                g_hide_slots[i].swept    = 0;
                g_hide_slots[i].mconf    = 0;
                g_hide_slots[i].nmembers = 0;
                left = 1;
            } else {
                nm = 0;
                left = 0;
            }
            kpm_spin_unlock_irqrestore(&g_hide_lock, flags);
            if (left) {
                for (k = 0; k < nm; k++)
                    if (s_drain[k].pid && kf_put_pid)
                        kf_put_pid(s_drain[k].pid);
                kpm_log("hide: exit released %d deferred member ref(s)\n", nm);
            }
        }
    }

    /* 兜底：无论上述路径如何，模块卸载前 P1 stub 必须拆除（防模块 .text
     * 释放后在途/后续调用取指 UAF）。recover(0) 已覆盖正常路径，此处幂等。 */
    hide_l2_uninstall();
}
