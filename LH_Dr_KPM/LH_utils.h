/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_UTILS_H_
#define _KPM_UTILS_H_

#include <ktypes.h>

/* ===== 工具函数 ===== */

/* 内核态不得使用 double 等浮点运算：内核不保存/恢复用户态 FP 上下文，
 * 会污染用户态 FPSIMD 状态。 */

/* 内核态伪随机数 [min, max]（纯整数实现，见 LH_utils.c） */
int kpm_rand_range(int min, int max);

/* 限制值在 [lo, hi] 范围内 */
static inline int kpm_clamp(int v, int lo, int hi)
{
    return v < lo ? lo : (v > hi ? hi : v);
}

/* 微秒延迟包装（原子上下文安全） */
void kpm_udelay_range(int min_us, int max_us);

/* 获取当前模块运行状态码 */
uint32_t kpm_get_state(void);

/* 设置状态标志 */
void kpm_set_state(uint32_t flags);

/* 清除状态标志 */
void kpm_clear_state(uint32_t flags);

/* 简单字符串包含查找（内核态无 strstr） */
char *kpm_strstr(const char *s1, const char *s2);

/* 获取当前 task_struct（ARM64: sp_el0 寄存器） */
struct task_struct *kpm_get_current_task(void);

/* ===== 通用会话自旋锁（AArch64 LDXR/STXR，IRQ 保存版） =====
 *
 * 用途：保护各子模块的全局会话状态（scan/pscan/freeze/debug 等）。
 * 约束：
 *   - 锁内只允许快速非睡眠操作（标志读写、指针快照）。
 *   - 禁止在持锁期间调用 vmalloc/kmalloc/copy_to_user 等可能睡眠的函数。
 *   - 慢操作（内存扫描、DMA、用户态拷贝）必须在锁外执行——
 *     通过"busy 标志"模式（见各模块 scan_enter/scan_leave）保证互斥。
 *
 * 实现与 kpm_log.c 的自旋锁一致：mrs/msr DAIF 保存禁用 IRQ，
 * LDXR/STXR 原子获取，WFE 降低功耗，dmb ish 保证顺序。
 * 不使用 __atomic_*（会生成 libgcc 辅助函数导致 KPM 加载失败）。
 */
typedef struct {
    volatile int locked;
} kpm_spinlock_t;

#define KPM_SPINLOCK_INIT { 0 }

/* 获取锁（同时禁用 IRQ，返回需保存的 DAIF 状态） */
static inline unsigned long kpm_spin_lock_irqsave(kpm_spinlock_t *l)
{
    unsigned long flags;
    int tmp;
    asm volatile("mrs %0, daif\n"
                 "msr daifset, #2\n"
                 : "=r"(flags)
                 :
                 : "memory");
    asm volatile(
        "1: ldxr %w0, [%1]\n"
        "   cbnz %w0, 2f\n"
        "   stxr %w0, %w2, [%1]\n"
        "   cbnz %w0, 1b\n"
        "   b 3f\n"
        "2: wfe\n"
        "   b 1b\n"
        "3:\n"
        : "=&r"(tmp)
        : "r"(&l->locked), "r"(1)
        : "memory");
    asm volatile("dmb ish" ::: "memory");
    return flags;
}

/* 释放锁（同时恢复 IRQ 状态） */
static inline void kpm_spin_unlock_irqrestore(kpm_spinlock_t *l, unsigned long flags)
{
    asm volatile("dmb ish" ::: "memory");
    l->locked = 0;
    asm volatile("sev");
    asm volatile("msr daif, %0" : : "r"(flags) : "memory");
}

/* 仅获取锁（不禁 IRQ；仅允许已确认不在 IRQ 上下文的调用方使用） */
static inline void kpm_spin_lock(kpm_spinlock_t *l)
{
    int tmp;
    asm volatile(
        "1: ldxr %w0, [%1]\n"
        "   cbnz %w0, 2f\n"
        "   stxr %w0, %w2, [%1]\n"
        "   cbnz %w0, 1b\n"
        "   b 3f\n"
        "2: wfe\n"
        "   b 1b\n"
        "3:\n"
        : "=&r"(tmp)
        : "r"(&l->locked), "r"(1)
        : "memory");
    asm volatile("dmb ish" ::: "memory");
}

/* 仅释放锁（配对 kpm_spin_lock） */
static inline void kpm_spin_unlock(kpm_spinlock_t *l)
{
    asm volatile("dmb ish" ::: "memory");
    l->locked = 0;
    asm volatile("sev");
}

/* ===== 无锁在途计数（LL/SC 原子加减 + acquire 读）=====
 * 用途：hook wrapper 的"在途回调"守卫 —— 回调入口 inc / 出口 dec，
 * 卸载侧等归零后才允许释放模块 .text（防取指 UAF）。
 * 使用者：LH_hooks.c（prctl 回调）、LH_intercept.c（input_handle_event 回调）。
 *
 * 为什么不用 kpm_spin_lock_irqsave：
 *   这套是**系统内每次 prctl（所有进程）** 与 **每个输入事件** 都要走两遍
 *   （入口 + 出口）的路径，而锁版本的每次加解锁包含 mrs/msr DAIF 两条
 *   序列化指令、一对 dmb ish、解锁还带一条 sev 广播。计数本身不需要临界区，
 *   只需要"原子性 + 与 drain 的 release/acquire 配对"，无锁即可。
 *
 * 顺序语义与锁版本**逐条对照**（不是"差不多"）：
 *   锁版本：inc 的 store 发生在 unlock(release) 之前，
 *           drain 的读发生在 lock(acquire) 之后 —— 靠锁字配对。
 *   本版本：inc/dec 自身就是 ldaxr(acquire) + stlxr(release)，
 *           drain 用 ldr + dmb ishld（acquire 读）—— 靠计数变量配对。
 *   即"看到 0 ⇒ 所有已完成 dec 的调用其执行对后续可见"这一性质不变。
 *
 * 不使用 __atomic_* / __sync_*（会生成 libgcc 辅助函数 → KPM 加载失败），
 * 与 kpm_atomic_fetch_sub_acq_rel（LH_syms.c）、kpm_gyro_count_inc（LH_gyro.c）
 * 同一手法。注意本组用于**安全守卫**，故用 ldaxr/stlxr 带顺序语义，
 * 而 kpm_gyro_count_inc 只是统计计数、用的是无顺序的 ldxr/stxr —— 别混用。 */

/* ++*p（acquire + release） */
static inline void kpm_atomic_inc_acq_rel(volatile int *p)
{
    int *q = (int *)p;
    int old, newv, ret;

    asm volatile(
        "1: ldaxr %w[old], %[mem]\n"
        "   add   %w[new], %w[old], #1\n"
        "   stlxr %w[ret], %w[new], %[mem]\n"
        "   cbnz  %w[ret], 1b\n"
        : [old] "=&r"(old), [new] "=&r"(newv), [ret] "=&r"(ret),
          [mem] "+Q"(*q)
        :
        : "memory");
}

/* --*p（acquire + release） */
static inline void kpm_atomic_dec_acq_rel(volatile int *p)
{
    int *q = (int *)p;
    int old, newv, ret;

    asm volatile(
        "1: ldaxr %w[old], %[mem]\n"
        "   sub   %w[new], %w[old], #1\n"
        "   stlxr %w[ret], %w[new], %[mem]\n"
        "   cbnz  %w[ret], 1b\n"
        : [old] "=&r"(old), [new] "=&r"(newv), [ret] "=&r"(ret),
          [mem] "+Q"(*q)
        :
        : "memory");
}

/* acquire 读（与上面的 release store 配对） */
static inline int kpm_atomic_read_acquire(volatile int *p)
{
    int *q = (int *)p;
    int v;

    asm volatile("ldr  %w[v], %[mem]\n"
                 "dmb  ishld\n"          /* 读屏障：后续访问不得上移到本读之前 */
                 : [v] "=r"(v)
                 : [mem] "Q"(*q)
                 : "memory");
    return v;
}

/* ===== 在途计数的"最终归零"确认（drain 自旋结束后的**一次性**复核）=====
 * ⚠ 只在 drain 自旋**退出后调用一次**，不要放进自旋循环条件里 ——
 *   本函数含 ~1ms 有界等待，放进循环会被放大成不可控的长等待。
 *
 * 为什么单次读 0 还不够：设 CPU0 刚执行完 inc 的 stlxr、正要进回调体，
 * 而该 store 还压在 store buffer 里；此时 CPU1（drain）读到 0 就会误判"安全"
 * 并释放模块 .text → 取指 UAF。
 * 锁版本之所以没这个窗口，是因为 inc 的 store 排在 unlock(release) 之前，
 * 而 drain 必须先 acquire 到锁字才能读 —— 那对 release/acquire 把窗口关掉了；
 * 换成无锁计数后，这个配对只剩"计数变量本身"，故在此显式补回来：
 *     读到 0 → dmb ish（让本核读完成）→ 有界等待（给对方 store buffer 排空）→ 再读
 * 两连 0 才判归零。代价只落在卸载路径，热路径不付。
 * 有界等待用 yield 自旋（不睡眠、任意上下文安全），量级取 ~1ms 上限。 */
static inline int kpm_inflight_final_zero(volatile int *p)
{
    int i;

    if (kpm_atomic_read_acquire(p) != 0)
        return 0;

    asm volatile("dmb ish" ::: "memory");
    for (i = 0; i < 10000; i++)
        asm volatile("yield" ::: "memory");

    return kpm_atomic_read_acquire(p) == 0;
}

#endif /* _KPM_UTILS_H_ */
