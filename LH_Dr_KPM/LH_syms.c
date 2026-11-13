/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/printk.h>
#include <linux/string.h>
#include <kallsyms.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <asm/current.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ktypes.h>
#include <linux/uaccess.h>
#include <linux/fs.h>

#include "LH_syms.h"
#include "LH_utils.h"
#include "LH_log.h"
#include <baselib.h>

/* GFP_KERNEL 在 KPM 框架的 gfp.h 中被注释掉，此处手动定义 */
#ifndef GFP_KERNEL
#define GFP_KERNEL  0xcc0u
#endif

/* mm->pgd 偏移探测的 PID 扫描上限（发现任一有效用户进程 mm 即止） */
#define KPM_PGD_PROBE_PID_MAX 512

/* 物理地址合理 RAM 上界（256GB，同 LH_mem_rw.c，用于 pgd 表项校验） */
#ifndef KPM_PHYS_MAX
#define KPM_PHYS_MAX 0x4000000000ULL
#endif

/* ===== 调试诊断宏 =====
 * KPM_DEBUG 由 Makefile 的 DEBUG=1 选项定义。
 * 启用后每个关键符号解析都会通过 printk 输出到 dmesg，
 * 配合 KPM_DEBUG_NO_DMESG_CLEAR 可保留完整加载日志供分析。
 *
 * 用法：make DEBUG=1 TARGET_COMPILE=aarch64-none-elf-
 */
#ifdef KPM_DEBUG
/* KPM_DBG 用运行时解析的 kf_printk 输出，避免编译期 printk 符号引用：
 * 6.1+ 内核 printk 为宏/已改名 _printk，且部分框架未 KP_EXPORT_SYMBOL(printk)，
 * 直接引用会生成 SHN_UNDEF 导致 KPM 加载器报 unknown symbol (ENOENT)。
 * kf_printk 由 kpm_syms_init 内 resolve_sym("printk"/"_printk") 解析，
 * 未解析时为 NULL 判空跳过。 */
#define KPM_DBG(fmt, ...)  do { \
    if (kf_printk) kf_printk("LH_syms_dbg: " fmt, ##__VA_ARGS__); \
} while (0)
/* 调试版同时禁用 dmesg 清除，确保日志可见 */
#ifndef KPM_DEBUG_NO_DMESG_CLEAR
#define KPM_DEBUG_NO_DMESG_CLEAR 1
#endif
#else
#define KPM_DBG(fmt, ...)  do {} while (0)
#endif

/* ===== 外部符号解析辅助函数 ===== */

/* 通过 kallsyms_lookup_name 查找符号地址（框架 KP_EXPORT_SYMBOL 导出） */
static unsigned long resolve_sym(const char *name)
{
    unsigned long addr = kallsyms_lookup_name(name);
#ifdef KPM_DEBUG
    /* 调试模式下打印每个符号的解析结果，便于定位缺失符号 */
    KPM_DBG("  resolve %s = 0x%lx %s\n",
            name, addr, addr ? "" : "(NOT FOUND)");
#else
    (void)name;
#endif
    return addr;
}

/* 安全读取内核变量（通过 kallsyms 找到地址后用 copy_from_kernel_nofault 读取）
 * 返回值: 变量的值（uint64_t），失败返回 0
 */
static uint64_t read_kernel_var(const char *name, uint64_t default_val)
{
    unsigned long addr;
    uint64_t val = 0;

    addr = resolve_sym(name);
    if (!addr) {
        kpm_log("LH_syms: variable %s not found, using default 0x%llx\n",
                name, (unsigned long long)default_val);
        return default_val;
    }

    if (kf_copy_from_kernel_nofault) {
        if (kf_copy_from_kernel_nofault(&val, (void *)addr, sizeof(val)) == 0) {
            kpm_log("LH_syms: %s = 0x%llx\n", name, (unsigned long long)val);
            return val;
        }
    }

    kpm_log("LH_syms: failed to read %s at 0x%lx, using default 0x%llx\n",
            name, addr, (unsigned long long)default_val);
    return default_val;
}

/* ===== 函数指针定义（仅框架未声明的符号） ===== */

/* 内存操作 —— ⑤静止态密文槽: .data 只存 addr^KEY, dump 不见明文指针 */
unsigned long kf_copy_from_user_slot = 0;
unsigned long kf_copy_to_user_slot = 0;
unsigned long kf_copy_from_kernel_nofault_slot = 0;
/* copy_to_kernel_nofault: 安全写入内核地址（不触发 fault）
 * 用于 write_via_wb 写入；copy_from_kernel_nofault 语义为读，勿混用 */
unsigned long kf_copy_to_kernel_nofault_slot = 0;

/* 物理内存映射 */
unsigned long kf_memremap_slot = 0;
unsigned long kf_memunmap_slot = 0;
unsigned long kf_ioremap_prot_slot = 0;
unsigned long kf_iounmap_slot = 0;

/* kallsyms 解析（由 KPM 框架 KP_EXPORT_SYMBOL 提供，无需本地定义） */

/* 内核常量 */
void *(*kf_kmalloc)(size_t size, gfp_t flags) = 0;
void (*kf_kfree)(const void *objp) = 0;

/* vmap Device-nGnRnE */
void *(*kf_vmap)(struct page **pages, unsigned int count, unsigned long flags, pgprot_t prot) = 0;
void (*kf_vunmap)(const void *addr) = 0;

/* 触摸子系统符号 */
void (*kf_input_handle_event)(void *dev, unsigned int type, unsigned int code, int value) = 0;
void (*kf_input_event)(void *dev, unsigned int type, unsigned int code, int value) = 0;
uint64_t kv_input_dev_list = 0;

/* vmalloc / scan 符号 */
void *(*kf_vmalloc)(unsigned long size) = 0;
void (*kf_vfree)(const void *addr) = 0;
struct page *(*kf_vmalloc_to_page)(const void *addr) = 0;
unsigned long long (*kf_simple_strtoull)(const char *cp, char **endp, unsigned int base) = 0;
int (*kf_snprintf)(char *buf, size_t size, const char *fmt, ...) = 0;

/* 内核常量 */
uint64_t g_vmemmap_base = 0;
uint64_t g_mm_pgd_offset = 0;
uint64_t g_memstart_addr = 0;
uint64_t g_phys_ram_base = 0;

/* ===== printk 兼容层 =====
 * Linux 6.1+ 将 printk 重命名为 _printk（printk 变为宏）。
 * KPM 模块通过 kpm_printk 宏调用，DEBUG 模式下需要解析正确符号。
 * RELEASE 模式下 kpm_printk 为空操作，kf_printk 不会被调用。 */
int (*kf_printk)(const char *fmt, ...) = 0;

/* ===== vsnprintf（框架声明但设备未导出） ===== */
int (*kf_vsnprintf)(char *buf, size_t size, const char *fmt, va_list args) = 0;

/* ===== kfunc_def 框架符号（设备上未导出，需本地定义 + 运行时解析） ===== */
struct mm_struct *(*kf_get_task_mm)(struct task_struct *task) = 0;
struct file *(*kf_filp_open)(const char *pathname, int flags, umode_t mode) = 0;
int (*kf_filp_close)(struct file *filp, void *id) = 0;
struct task_struct *(*kf_find_task_by_vpid)(pid_t nr) = 0;
struct task_struct *(*kf_get_pid_task)(struct pid *pid, enum pid_type type) = 0;
ssize_t (*kf_kernel_read)(struct file *file, void *buf, size_t count, loff_t *pos) = 0;
ssize_t (*kf_kernel_write)(struct file *file, const void *buf, size_t count, loff_t *pos) = 0;
const void *(*kf_override_creds)(const void *new) = 0;
void (*kf_revert_creds)(const void *old) = 0;
const void *kf_init_cred = 0;
kpm_kernel_read_iter_t kf_kernel_read_iter = 0;
void (*kf_mmput)(struct mm_struct *mm) = 0;
struct pid *(*kf_find_get_pid)(int nr) = 0;

/* ===== uprobe（libsensorservice hook） ===== */
int (*kf_uprobe_register)(struct inode *inode, long long offset, void *uc) = 0;
void (*kf_uprobe_unregister)(struct inode *inode, long long offset, void *uc) = 0;
int (*kf_kern_path)(const char *name, unsigned int flags, struct path *path) = 0;
struct inode *(*kf_igrab)(struct inode *inode) = 0;
void (*kf_iput)(struct inode *inode) = 0;
void (*kf_path_put)(struct path *path) = 0;

/* ===== sys_enter tracepoint ===== */
void *kf_tp_sys_enter = 0;   /* struct tracepoint *__tracepoint_sys_enter */
void *kf_tp_sys_exit = 0;    /* struct tracepoint *__tracepoint_sys_exit */
void *kf_tp_sched_fork = 0;  /* struct tracepoint *__tracepoint_sched_process_fork */
int (*kf_tracepoint_probe_register)(void *tp, void *probe, void *data) = 0;
int (*kf_tracepoint_probe_unregister)(void *tp, void *probe, void *data) = 0;
void (*kf_tracepoint_synchronize_unregister)(void) = 0;

/* ===== PID 引用管理 ===== */
void (*kf_put_pid)(struct pid *pid) = 0;

/* ===== 硬件断点 (perf_event) ===== */
void *(*kf_register_user_hw_bp)(void *attr, void *triggered,
                                 void *context, void *tsk) = 0;
void (*kf_unregister_hw_bp)(void *bp) = 0;
/* perf_event_enable/disable：注册（create_kernel_counter）只建立事件对象并挂到
 * task 的 ctx->inactive_list，硬件槽（DBGWVR/DBGWCR、MDSCR.SSM）编程发生在
 * 事件进入 active_list 之后。内核自身用法：arch/arm64/kernel/ptrace.c 建断点时
 * attr.disabled=1，随后经 modify_user_hw_breakpoint() 尾部
 * "if (!bp->attr.disabled) perf_event_enable(bp);" 才真正装载。
 * 因此 register_* 返回成功指针 ≠ 断点已生效，必须显式 enable。 */
void (*kf_perf_event_enable)(void *event) = 0;
void (*kf_perf_event_disable)(void *event) = 0;
/* 内核/宽断点（force 使用） */
void *(*kf_register_wide_hw_bp)(void *attr, void *handler, void *ctx) = 0;
void (*kf_unregister_wide_hw_bp)(void *pevents) = 0;
void *(*kf_perf_event_create_kernel_counter)(void *attr, int cpu, void *task,
                                             void *handler, void *ctx) = 0;
/* fault/时间/lockdown */
void (*kf_do_mem_abort)(unsigned long addr, unsigned int esr, void *regs) = 0;
uint64_t (*kf_ktime_get_ns)(void) = 0;
unsigned long *kf_jiffies = 0;
int *kf_kernel_locked_down = 0;
int (*kf_security_locked_down)(int what) = 0;
void *kf_patch_text = 0;
kf_insn_patch_text_t kf_aarch64_insn_patch_text = 0;
void *kf_set_memory_rw = 0;
void *kf_flush_icache_range = 0;

/* ===== 进程名称 ===== */
char *(*kf_get_task_comm)(char *buf, size_t buf_size, struct task_struct *tsk) = 0;

/* get_cmdline：直接读取进程完整 cmdline（内部处理 arg_start/arg_end + access_process_vm） */
int (*kf_get_cmdline)(struct task_struct *task, char *buffer, int buflen) = 0;

/* ===== task_struct 引用管理 ===== */
void (*kf_put_task_struct)(struct task_struct *tsk) = 0;

/* ===== 同步断点停靠符号（task_work 机制，缺失仅同步模式禁用） ===== */
int (*kf_task_work_add)(struct task_struct *task, void *work, int resume) = 0;
long (*kf_schedule_timeout_interruptible)(long timeout) = 0;
unsigned long (*kf_msecs_to_jiffies)(unsigned int m) = 0;
int (*kf_wake_up_process)(struct task_struct *tsk) = 0;
void (*kf_get_task_struct)(struct task_struct *tsk) = 0;
int (*kf_do_send_sig_info)(int sig, void *info, struct task_struct *t,
                           int group) = 0;
int (*kf_sched_setattr_nocheck)(struct task_struct *p, const void *attr) = 0;
void *kf_sysctl_sched_uclamp_util_max = 0;
int (*kf_set_cpus_allowed_ptr)(struct task_struct *p, const void *new_mask) = 0;
void (*kf_register_user_step_hook)(void *hook) = 0;
void (*kf_unregister_user_step_hook)(void *hook) = 0;
/* W^X shadow */
int (*kf_register_user_break_hook)(void *hook) = 0;
int (*kf_unregister_user_break_hook)(void *hook) = 0;
void (*kf_exit_mmap)(struct mm_struct *mm) = 0;
void *(*kf_dup_mm)(struct task_struct *tsk) = 0;
void (*kf_do_debug_exception)(unsigned long addr, unsigned int esr,
                              void *regs) = 0;
int (*kf_register_undef_hook)(void *hook) = 0;
int (*kf_unregister_undef_hook)(void *hook) = 0;
const char *kf_linux_banner = 0;   /* 内核版本判定（undef 探测门控） */
/* RCU 读临界区检测（kernel/rcu/update.c，EXPORT_SYMBOL_GPL，4.x-6.x 全版本）：
 * exit 路径防死锁用——若 exit 在 RCU 读临界区内执行，任何 synchronize_rcu/
 * 睡眠调用都会让 GP 永久等待自身读临界区 → 整机冻结。
 * 详见 LH_debug.c kpm_debug_exit。 */
int (*kf_rcu_read_lock_any_held)(void) = 0;

/* ===== put_task_struct 安全替代 =====
 * g_usage_offset: >0 = 已由行为学标定证明的 task_struct.usage 偏移；
 *                 -1 = 未标定/标定失败（手动递减被禁用，只接受泄漏）。 */
int g_usage_offset = -1;
int g_usage_offset_trusted = 0;
/* 标定状态：给 info 诊断说明「为什么手动 put 不可用」用（见 LH_syms.h 的 KPM_CALIB_*） */
int g_usage_calib_state = KPM_CALIB_NONE;
void (*kf___put_task_struct)(struct task_struct *tsk) = 0;
void (*kf_free_task)(struct task_struct *tsk) = 0;  /* 仅解析用于状态信息上报，不再调用 */

/* kpm_atomic_fetch_sub_acq_rel: AArch64 原子递减（ACQ_REL 语义）
 *
 * 用 LL/SC 内联汇编替代 GCC __atomic_fetch_sub，避免生成对
 * __aarch64_ldadd4_acq_rel（libgcc 辅助函数）的调用——该符号
 * 不在 KernelPatch 导出表内，会导致 KPM 加载失败。
 *
 * 等价语义：return old; *ptr = old - val;（原子，ACQUIRE+RELEASE）
 */
static inline int kpm_atomic_fetch_sub_acq_rel(int *ptr, int val)
{
    int old_val, new_val, ret;
    __asm__ __volatile__(
        "1: ldxr %w[old], %[mem]\n"            /* Load-exclusive (ACQUIRE) */
        "   sub %w[new], %w[old], %w[val]\n"   /* 计算新值 */
        "   stlxr %w[ret], %w[new], %[mem]\n"  /* Store-exclusive (RELEASE) */
        "   cbnz %w[ret], 1b\n"                 /* 失败重试 */
        : [old] "=&r"(old_val), [new] "=&r"(new_val),
          [ret] "=&r"(ret), [mem] "+Q"(*ptr)
        : [val] "r"(val)
        : "memory");
    return old_val;
}

/* kpm_put_task_struct: 安全替代 put_task_struct
 *
 * 优先级：
 *   1. 原生 put_task_struct 符号
 *   2. 手动实现：原子递减 usage + __put_task_struct
 *   3. 探测失败：跳过，接受引用泄漏（不崩溃）
 *
 * 手动实现逻辑等价于原生：
 *   static inline void put_task_struct(struct task_struct *t) {
 *       if (refcount_dec_and_test(&t->usage))  // 原子递减，为 0 返回 true
 *           __put_task_struct(t);              // 引用计数为 0 时释放
 *   }
 *
 * 用内联汇编 kpm_atomic_fetch_sub_acq_rel 替代 refcount_dec_and_test。
 * 返回递减前的旧值，旧值为 1 表示递减后为 0。
 */
/* get_task_struct 安全获取。4.19 上 get_task_struct 是 static
 * inline（refcount_inc(&t->usage)），kallsyms 无符号。
 * 原生符号优先；缺失时对已标定的 usage 偏移做原子 +1（与 put 侧手动
 * 递减严格配对：两边都没标定则 get/put 均为 no-op，一致地"无引用借用"，
 * 引用计数不受影响）。 */
void kpm_get_task_struct_safe(struct task_struct *task)
{
    if (!task)
        return;
    if (kf_get_task_struct) {
        kf_get_task_struct(task);
        return;
    }
    if (g_usage_offset > 0 && g_usage_offset_trusted) {
        /* fetch_sub(-1) == 原子 +1（复用既有 LL/SC 原语，无 libgcc 依赖） */
        kpm_atomic_fetch_sub_acq_rel(
            (int *)((char *)task + g_usage_offset), -1);
    }
    /* 偏移未标定：不增引用（宁缺勿错，与 put 侧 no-op 对称） */
}

void kpm_put_task_struct(struct task_struct *task)
{
    int old_val;

    if (!task)
        return;

    /* 优先用原生 put_task_struct */
    if (kf_put_task_struct) {
        kf_put_task_struct(task);
        return;
    }

    /* 手动实现：原子递减 usage 引用计数。
     * 门控：必须 g_usage_offset_trusted == 1 —— 即该偏移已由
     * get_pid_task() 的 "+1 引用指纹" 在 pid 1/2 上双向证明为 usage。
     * 未标定（=-1）时**绝不写内存**：宁可泄漏一个引用，也不冒写坏无关字段
     * 的风险。 */
    if (g_usage_offset > 0 && g_usage_offset_trusted && kf___put_task_struct) {
        old_val = kpm_atomic_fetch_sub_acq_rel(
            (int *)((char *)task + g_usage_offset), 1);
        if (old_val == 1) {
            /* 引用计数降为 0，释放 task_struct */
            kf___put_task_struct(task);
        }
        return;
    }

    /* 无原生符号且 usage 偏移未标定（或 __put_task_struct 缺失）：
     * 接受引用泄漏（不崩溃）。
     *
     * free_task 直接释放会跳过引用计数检查，存在双重释放（use-after-free）
     * 风险——若别处仍持有 task 指针，释放后再次访问即 UAF。泄漏虽然会
     * 缓慢消耗 task_struct_cachep 内存，但比 UAF/写坏内存更安全。
     * 这是本函数的**最后一道回退**：任何不确定都落到这里。 */
    (void)kf_free_task;  /* 仍解析该符号用于状态信息上报，但不再调用 */
    kpm_log("LH_put_task_struct: LEAKED task=%p (offset=%d trusted=%d native=%d)\n",
            task, g_usage_offset, g_usage_offset_trusted,
            kf___put_task_struct ? 1 : 0);
}

/* ===== 免引用 pid→task =====
 *
 * 只要"取引用就必须归还"，就迟早要面对"归还写哪个字段"的不确定性。
 * 做法是**根本不取引用**：RCU 读锁 + find_vpid + pid_task 得到 task 指针
 * 即可安全使用（task_struct 的释放走 RCU 回调，读临界区内不会被回收），
 * 全程不触碰 task->usage，因此与任何偏移探测结果无关。
 *
 * 框架头文件里 kfunc_def(pid_task) 声明的 kf_pid_task / kf_find_vpid /
 * kf___rcu_read_lock / kf___rcu_read_unlock 是 KernelPatch 模块内部指针，
 * 不导出给 KPM 模块；直接引用会产生 SHN_UNDEF 导致加载器拒绝整个模块。
 * 与其它内核函数一致，必须用模块内自定义指针 + 运行时 resolve_sym() 解析，
 * 因此这里用 kp_ 前缀的本地指针，绝不触碰框架的同名 extern 声明。
 *
 * 约束：kpm_task_end() / kpm_task_release() 之前不得睡眠。
 */

/* 免引用路径所需的四个内核函数指针（模块内部，运行时解析） */
static void (*kp_rcu_read_lock)(void) = 0;
static void (*kp_rcu_read_unlock)(void) = 0;
static struct pid *(*kp_find_vpid)(int nr) = 0;
static struct task_struct *(*kp_pid_task)(struct pid *pid, enum pid_type type) = 0;

/* 确保免引用所需符号就绪；返回 1 = 可用 */
int kpm_task_noref_available(void)
{
    if (!kp_rcu_read_lock) {
        kp_rcu_read_lock = (void *)resolve_sym("rcu_read_lock");
        if (!kp_rcu_read_lock)
            kp_rcu_read_lock = (void *)resolve_sym("__rcu_read_lock");
    }
    if (!kp_rcu_read_unlock) {
        kp_rcu_read_unlock = (void *)resolve_sym("rcu_read_unlock");
        if (!kp_rcu_read_unlock)
            kp_rcu_read_unlock = (void *)resolve_sym("__rcu_read_unlock");
    }
    if (!kp_find_vpid)
        kp_find_vpid = (void *)resolve_sym("find_vpid");
    if (!kp_pid_task)
        kp_pid_task = (void *)resolve_sym("pid_task");

    return (kp_rcu_read_lock && kp_rcu_read_unlock &&
            kp_find_vpid && kp_pid_task) ? 1 : 0;
}

/* 进入 RCU 读临界区并取 task（不取引用）。成功 0（须配对 kpm_task_end）。 */
int kpm_task_begin(pid_t pid, struct task_struct **out)
{
    struct task_struct *t;

    if (!out)
        return -1;
    *out = 0;
    if (!kpm_task_noref_available())
        return -1;

    kp_rcu_read_lock();
    t = kp_pid_task(kp_find_vpid(pid), PIDTYPE_PID);
    if (!t) {
        kp_rcu_read_unlock();
        return -1;
    }
    *out = t;
    return 0;
}

/* 退出 RCU 读临界区 */
void kpm_task_end(void)
{
    if (kp_rcu_read_unlock)
        kp_rcu_read_unlock();
}

/* ===== 安全任务扫描 =====
 * 正向遍历 tasklist 对任意任务调 __task_pid_nr_ns 会撞上退出中任务
 * （thread_pid 已被 detach_pid 置 NULL），该路径无有效空指针防护。
 * 本原语反转方向：遍历 pid 号空间 find_vpid(nr) → get_pid_task——任务
 * 来自已哈希 pid，其 thread_pid/group_leader 恒有效，符号调用天然安全。
 * cb 约定：t 持有临时引用（返回后失效，需保留须自行 kpm_get_task_struct_safe
 * 再 +1）；返回非 0 = 提前终止并把该值作为 scan 返回值。
 * 返回：成功遍历的任务数（或 cb 终止值）；-1 = 基础设施不可用。 */
int kpm_task_scan_available(void)
{
    return kpm_task_noref_available() && kf_get_pid_task ? 1 : 0;
}

long kpm_task_scan_by_pid(long (*cb)(struct task_struct *t, pid_t nr, void *ud),
                          void *ud)
{
    pid_t nr_max, nr;
    long n = 0;

    if (!cb || !kpm_task_scan_available())
        return -1;
    nr_max = (pid_t)kpm_pid_max();
    if (nr_max <= 0 || nr_max > 4194304)
        nr_max = 32768;

    kp_rcu_read_lock();
    for (nr = 1; nr <= nr_max; nr++) {
        struct pid *p = kp_find_vpid((int)nr);
        struct task_struct *t;
        long r;

        if (!p)
            continue;
        t = kf_get_pid_task(p, 0 /* PIDTYPE_PID，自带 +1 引用 */);
        if (!t)
            continue;
        r = cb(t, nr, ud);
        kpm_put_task_struct(t);
        if (r) {
            n = r;
            break;
        }
        n++;
    }
    kp_rcu_read_unlock();
    return n;
}

/* 免引用：由已持有的 struct pid* 取 task（只有 pidref 的调用点用，如隐藏模块
 * 持有 find_get_pid 引用做存在性探测）。成功 0 并持 RCU，须配对 kpm_task_end()。 */
int kpm_task_begin_pidref(struct pid *ps, struct task_struct **out)
{
    struct task_struct *t;

    if (!ps || !out)
        return -1;
    *out = 0;
    if (!kpm_task_noref_available())
        return -1;

    kp_rcu_read_lock();
    t = kp_pid_task(ps, PIDTYPE_PID);
    if (!t) {
        kp_rcu_read_unlock();
        return -1;
    }
    *out = t;
    return 0;
}

int kpm_task_acquire(pid_t pid, struct task_struct **out, int *needs_put)
{
    struct pid *ps;
    struct task_struct *t;

    if (!out || !needs_put)
        return -1;
    *out = 0;
    *needs_put = 0;

    /* 首选：免引用（零引用计数，与 usage 偏移完全无关） */
    if (kpm_task_begin(pid, out) == 0)
        return 0;

    /* 回退：取引用 + 归还。仅当能安全归还（原生符号或已标定偏移）时才用,
     * 否则走到了也只会泄漏——此时不如不取，直接放弃该 pid。 */
    if (!kpm_put_task_available() || !kf_find_get_pid || !kf_get_pid_task)
        return -1;

    ps = kf_find_get_pid(pid);
    if (!ps)
        return -1;
    t = kf_get_pid_task(ps, PIDTYPE_PID);
    if (kf_put_pid)
        kf_put_pid(ps);
    if (!t)
        return -1;

    *out = t;
    *needs_put = 1;
    return 0;
}

/* 与 kpm_task_acquire(*needs_put==0) 配对 */
void kpm_task_release(void)
{
    kpm_task_end();
}

/* ===== pid 扫描上限：运行时读内核 pid_max（禁止硬编码） =====
 * pid 分配是 1..pid_max 循环复用，开机一段时间后 pid 会涨到几万，
 * 写死上限会漏掉高 pid 的进程。
 * 取法：kallsyms 解析内核变量 `pid_max`（int，非导出但 kallsyms 可见），
 * copy_from_kernel_nofault 读值；失败回退 KPM_PID_MAX_FALLBACK。
 * 结果缓存（内核里 pid_max 只在显式写 /proc/sys/kernel/pid_max 时变化）。 */
static void *g_p_pid_max_sym = 0;   /* 内核 pid_max 变量地址 */
static int g_pid_max_cached = 0;

int kpm_pid_max(void)
{
    int v = 0;

    if (g_pid_max_cached > 0)
        return g_pid_max_cached;

    if (!g_p_pid_max_sym)
        g_p_pid_max_sym = (void *)resolve_sym("pid_max");

    if (g_p_pid_max_sym && kf_copy_from_kernel_nofault &&
        kf_copy_from_kernel_nofault(&v, g_p_pid_max_sym, sizeof(v)) == 0 &&
        v > 0) {
        if (v > KPM_PID_MAX_LIMIT)
            v = KPM_PID_MAX_LIMIT;
        if (v < 1024)
            v = 1024;
        g_pid_max_cached = v;
        kpm_log("LH_syms: pid_max=%d (read from kernel pid_max@0x%llx)\n",
                v, (unsigned long long)(uint64_t)g_p_pid_max_sym);
    } else {
        g_pid_max_cached = KPM_PID_MAX_FALLBACK;
        kpm_log("LH_syms: WARNING pid_max symbol unavailable (sym=0x%llx), "
                "fallback scan limit=%d\n",
                (unsigned long long)(uint64_t)g_p_pid_max_sym,
                KPM_PID_MAX_FALLBACK);
    }
    return g_pid_max_cached;
}

/* ===== PID/TGID 获取 ===== */
/* 类型必须与框架 sched.h 中 kfunc_def(__task_pid_nr_ns) 声明完全一致，
 * 否则编译报 conflicting types 错误。 */
pid_t (*kf___task_pid_nr_ns)(struct task_struct *task, enum pid_type type,
                             struct pid_namespace *ns) = 0;
/* 注：kf_find_task_by_vpid 已在上方 kfunc_def 区域定义 */

/* ===== tasklist 遍历符号 ===== */
/* 显式零初始化，防止 BSS 未被加载器清零时包含垃圾值 */
struct task_struct_offset kf_task_struct_offset = {0};
struct mm_struct_offset kf_mm_struct_offset = {0};
struct task_struct *kf_init_task = 0;

/* ===== mmap 读锁 ===== */
int (*kf_mmap_read_lock)(struct mm_struct *mm) = 0;
void (*kf_mmap_read_unlock)(struct mm_struct *mm) = 0;
/* 仅当 mmap_read_lock/mmap_read_unlock 原生符号双解析成功（5.12+）才为 1。
 * 为 0 时 kf_mmap_read_lock 可能是 down_read 回退填充值（签名不兼容，
 * 调用即内存损坏），必须经 kpm_mm_read_lock 适配层分流，禁止直接调用。 */
int g_mmap_read_lock_native = 0;

/* VMA 遍历统一加锁适配层。
 * 返回 1 = 已持原生 mmap 读锁；返回 0 = 持 RCU 读锁（或无 RCU 符号时
 * 无保护）。调用方必须以同一 mm 与返回值配对解锁。
 * 上下文要求：可睡眠（原生锁为 rwsem，down_read 可睡眠）；所有 VMA
 * 遍历调用点均位于可睡眠上下文，无 IRQ/原子上下文调用。 */
int kpm_mm_read_lock(struct mm_struct *mm)
{
    if (g_mmap_read_lock_native && kf_mmap_read_lock && kf_mmap_read_unlock) {
        kf_mmap_read_lock(mm);
        return 1;
    }
    KPM_RCU_READ_LOCK();
    return 0;
}

void kpm_mm_read_unlock(struct mm_struct *mm, int locked)
{
    if (locked)
        kf_mmap_read_unlock(mm);
    else
        KPM_RCU_READ_UNLOCK();
}

/* ===== VMA 遍历符号（高兼容性三级回退链） =====
 * 见 kpm_syms.h 中的详细注释 */
void *(*kf_find_vma)(struct mm_struct *mm, unsigned long addr) = 0;

/* mm_struct.mmap 偏移（回退路径 1 使用）
 * -1 = 未探测，>=0 = 探测到的偏移，-2 = 探测失败（6.1+ maple tree） */
int g_mm_mmap_offset = -1;

/* ===== RCU 读锁 ===== */
void (*kf_rcu_read_lock)(void) = 0;
void (*kf_rcu_read_unlock)(void) = 0;
/* 卸载排空 synchronize_rcu（回退 expedited） */
void (*kf_synchronize_rcu)(void) = 0;
/* RCU 读锁持有状态探测函数指针。
 * 框架仅 kfunc_def 定义变量、未 KP_EXPORT_SYMBOL 导出该符号，直接用 extern
 * 声明会产生 SHN_UNDEF 导致 KPM 加载器报 unknown symbol (ENOENT)。
 * 因此采用模块内定义，运行时 resolve_sym("rcu_read_lock_held") 经
 * kallsyms_lookup_name 解析（内核 EXPORT_SYMBOL 标准符号，全版本可解析）。
 * 解析失败时为 NULL，调用方（LH_gyro.c kpm_gyro_exit）判空跳过。 */
int (*kf_rcu_read_lock_held)(void) = 0;

/* ===== task_struct 偏移（运行时探测，0 表示未探测到） ===== */
int g_tasks_offset = 0;
int g_tgid_offset = 0;
int g_mm_offset = 0;
int g_pid_offset = 0;
/* 安全 tasklist：运行时推导的真实 tasks 偏移（-1=未推导/失败）。
 * 与 g_tasks_offset（框架/启发式）分离，详见 kpm_tasklist_verify。 */
int g_tasks_offset_verified = -1;
/* pid_offset 是否经 PID=2 交叉验证。0 = 只是启发式候选
 * （"tasks 之后第一个 1,1 对"），进程列表的 pid 列可能读错值；
 * 上报给 info/客户端，便于区分"功能可用"与"数据可能不准"。 */
int g_pid_offset_verified = 0;
int g_real_parent_offset = 0;   /* task_struct.real_parent 偏移 */
int g_arg_start_offset = 0;     /* mm_struct.arg_start 偏移 */
int g_arg_end_offset = 0;       /* mm_struct.arg_end 偏移 */
int g_total_vm_offset = 0;      /* mm_struct.total_vm 偏移（0=未探测） */

/* ===== vm_area_struct 偏移（运行时探测，0 表示未探测到） ===== */
int g_vm_start_offset = -1;  /* -1 = 未探测，0 = 合法偏移（vm_start 在结构体首位） */
int g_vm_end_offset = -1;
int g_vm_next_offset = -1;
int g_vm_flags_offset = -1;  /* vm_area_struct.vm_flags 偏移（VM_READ/WRITE/EXEC 位掩码） */

/* ===== 文件映射路径解析偏移（运行时探测，-1 = 未探测） =====
 * 用途：VMA 遍历时直接从 vm_area_struct.vm_file → struct file.f_path.dentry
 *       → struct dentry.d_name.name 解析文件名（纯内存，无 VFS/无 /proc）。
 * 背景：Android SELinux enforcing 下内核态 filp_open("/proc/<pid>/maps")
 *       被 ptrace_may_access 拒绝（root 也无法绕过），/proc 方案不可行。
 * 隐蔽性：A 级（纯 copy_from_kernel_nofault，无文件操作、无 audit 痕迹）。 */
int g_vm_file_offset = -1;      /* vm_area_struct.vm_file 偏移 */
int g_file_dentry_offset = -1;  /* struct file.f_path.dentry 偏移 */
int g_dentry_name_offset = -1;  /* struct dentry.d_name.name 偏移 */

/* ===== UDP 服务符号（运行时通过 kallsyms 解析） ===== */
#include "LH_udp.h"

int (*kf_sock_create_kern)(struct kpm_net *, int, int, int,
                            struct kpm_socket **) = 0;
/* sock_create 4 参数版本（无 net 参数，内部用 current->nsproxy->net_ns）：
 * 当 sock_create_kern 被厂商内核 static 化时的回退（兼容性增强） */
int (*kf_sock_create)(int, int, int, struct kpm_socket **) = 0;
void (*kf_sock_release)(struct kpm_socket *) = 0;
int (*kf_kernel_bind)(struct kpm_socket *, struct sockaddr *, int) = 0;
int (*kf_kernel_recvmsg)(struct kpm_socket *, struct msghdr *,
                         struct kpm_kvec *, unsigned int, size_t, int) = 0;
int (*kf_kernel_sendmsg)(struct kpm_socket *, struct msghdr *,
                         struct kpm_kvec *, unsigned int, size_t) = 0;
int (*kf_kernel_sock_shutdown)(struct kpm_socket *, int) = 0;
struct kpm_workqueue_struct *(*kf_alloc_workqueue)(const char *, int, int) = 0;
void (*kf_destroy_workqueue)(struct kpm_workqueue_struct *) = 0;
int (*kf_queue_work)(int cpu, struct kpm_workqueue_struct *, struct kpm_work_struct *) = 0;
void (*kf_flush_workqueue)(struct kpm_workqueue_struct *) = 0;
struct kpm_net *kf_init_net = 0;

/* ===== 4.19 的 alloc_workqueue 是宏，无独立符号 =====
 * 4.x 内核中 alloc_workqueue/create_workqueue 均为内联包装，底层唯一导出
 * 符号是 __alloc_workqueue_key(fmt, flags, max_active, key, lock_name, ...)。
 * 这里用包装函数经 __alloc_workqueue_key 兜底，避免 UDP 服务必需符号缺失。
 * lock_class_key：CONFIG_LOCKDEP=n 时被忽略；按 4.19 CONFIG_LOCKDEP=y 布局
 * （hlist_node 16B + 指针 8B）自包含定义，两态皆安全。 */
struct kpm_lock_class_key {
    uint64_t hash_entry[2];   /* struct hlist_node（两个指针） */
    uint64_t lock_class;      /* struct lock_class * */
};

static struct kpm_workqueue_struct *(*kf_alloc_workqueue_key)(
    const char *, unsigned int, int, struct kpm_lock_class_key *, const char *, ...) = 0;

static struct kpm_workqueue_struct *kpm_alloc_workqueue_fallback(
    const char *name, int flags, int max_active)
{
    static struct kpm_lock_class_key wq_key = {{0}, 0};

    if (!kf_alloc_workqueue_key)
        return 0;
    return kf_alloc_workqueue_key(name, (unsigned int)flags, max_active,
                                  &wq_key, name);
}

/* ===== pgtable.h 框架全局变量（设备上未导出） ===== */
uint64_t kernel_va = 0;
uint64_t kernel_pa = 0;
int64_t kernel_size = 0;
int64_t page_shift = 0;
int64_t va_bits = 0;
int64_t page_level = 0;
uint64_t pgd_va = 0;

/* ===== task_struct.usage 偏移标定（行为学指纹法） =====
 * 用途：put_task_struct 符号缺失时手动实现引用计数递减（见 kpm_put_task_struct
 *       的手动路径）。
 *
 * 判定依据（唯一充分证据）：唯一能证明"某 4 字节字段就是 usage"的行为学
 * 事实是 get_pid_task() 使该字段**恰好 +1**（usage 是它唯一递增的 task 字段）；
 * 值域打分只是必要特征而非充分证据，不足以判定 usage。
 * 标定步骤（pid 1 / pid 2 各做一次，两次得到的偏移必须一致）：
 *   1. 取 init_task 前 256B 作锚点快照（init_task.usage == 2）；
 *   2. 免引用取目标 pid 的 task 指针 t（不改任何字段）+ 256B 快照 A；
 *   3. 调 get_pid_task() 制造 +1（该引用故意不归还，接受一次泄漏）；
 *   4. 再取快照 B，逐 4B 比对：锚点==2 且 A 在 [1,1000] 且 B==A+1；
 *   5. 候选必须**全局唯一**（hits==1），否则视为不确定直接放弃；
 *   6. 回环自检：对候选原子递减一次，读回应等于 A 值，不等即放弃。
 * 任一步不满足 => g_usage_offset=-1 且 trusted=0，手动递减永久禁用
 * （宁可泄漏一个引用，也不写坏未知内存）。
 *
 * 兼容性：
 *   - Linux 4.x: usage 是 atomic_t（4 字节 int）
 *   - Linux 5.x+: usage 是 refcount_t（struct { atomic_t refs; }，仍为 4 字节 int）
 */
/* 标定扫描窗口：usage 在已知内核里都落在 task_struct 前 64B，但厂商改动/RT 补丁
 * 可能把它推后，故**自适应放大**（不要写死单一窗口）：
 *   先 256B；指纹不唯一或为空 → 512B → 1024B。符号缺失时不再放大。 */
#define USAGE_CAL_MIN   256
#define USAGE_CAL_MAX   1024

/* 标定幂等标志（标定只做一次，避免重复泄漏引用） */
static int g_usage_calib_done = 0;

/* 单个 pid 的 +1 指纹标定。win = 本次扫描窗口字节数（≤ USAGE_CAL_MAX）。
 * 成功返回 0 并把偏移写入 *out_off。 */
static int kpm_usage_calibrate_one(int pid, int *out_off, int win)
{
    uint32_t anchor[USAGE_CAL_MAX / 4];
    uint32_t snap_a[USAGE_CAL_MAX / 4];
    uint32_t snap_b[USAGE_CAL_MAX / 4];
    struct pid *ps = 0, *ps2 = 0;
    struct task_struct *t = 0;
    int i, hits = 0, cand = -1, base_val = 0, old = 0;
    int n = win / 4;

    if (!kf_init_task || !kf_copy_from_kernel_nofault) {
        g_usage_calib_state = KPM_CALIB_NOSYM;
        return -1;
    }
    /* 免引用取 task 用本地指针 kp_pid_task，先确保它已被 resolve_sym 解析。 */
    (void)kpm_task_noref_available();
    if (!kf_find_get_pid || !kf_get_pid_task || !kf_put_pid || !kp_pid_task) {
        g_usage_calib_state = KPM_CALIB_NOSYM;
        return -1;
    }

    ps = kf_find_get_pid(pid);
    if (!ps)
        return -1;
    t = kp_pid_task(ps, PIDTYPE_PID);      /* 不取引用 */
    if (!t) {
        kf_put_pid(ps);
        return -1;
    }

    if (kf_copy_from_kernel_nofault(anchor, (void *)kf_init_task, win) != 0 ||
        kf_copy_from_kernel_nofault(snap_a, t, win) != 0) {
        kf_put_pid(ps);
        return -1;
    }

    ps2 = kf_find_get_pid(pid);
    if (!ps2) {
        kf_put_pid(ps);
        return -1;
    }
    if (!kf_get_pid_task(ps2, PIDTYPE_PID)) {   /* usage +1 */
        kf_put_pid(ps2);
        kf_put_pid(ps);
        return -1;
    }
    if (kf_copy_from_kernel_nofault(snap_b, t, win) != 0) {
        kf_put_pid(ps2);
        kf_put_pid(ps);
        return -1;
    }
    kf_put_pid(ps2);
    kf_put_pid(ps);

    for (i = 0; i < n; i++) {
        if (anchor[i] != 2)
            continue;                            /* init_task.usage 锚点 */
        if (snap_a[i] < 1 || snap_a[i] > 1000)
            continue;                            /* 合理引用计数范围 */
        if (snap_b[i] != snap_a[i] + 1)
            continue;                            /* +1 指纹 */
        cand = i;
        hits++;
    }

    if (hits != 1) {
        g_usage_calib_state = KPM_CALIB_FAIL;
        kpm_log("LH_syms: usage calib(pid=%d win=%d): hits=%d (need exactly 1) -> "
                "reject (reference leaked intentionally)\n", pid, win, hits);
        return -1;
    }

    base_val = (int)snap_a[cand];
    old = kpm_atomic_fetch_sub_acq_rel((int *)((char *)t + cand * 4), 1);
    if (old != base_val + 1) {
        g_usage_calib_state = KPM_CALIB_FAIL;
        kpm_log("LH_syms: usage calib(pid=%d): roundtrip pre-check failed "
                "(old=%d expect=%d)\n", pid, old, base_val + 1);
        return -1;
    }
    if (kf_copy_from_kernel_nofault(snap_b, t, win) != 0 ||
        (int)snap_b[cand] != base_val) {
        g_usage_calib_state = KPM_CALIB_FAIL;
        kpm_log("LH_syms: usage calib(pid=%d): roundtrip mismatch -> reject\n", pid);
        return -1;
    }

    *out_off = cand * 4;
    return 0;
}

static void probe_usage_offset(void)
{
    int off1 = -1, off2 = -1;
    int win;

    /* 幂等：标定只做一次（失败也不重试，避免重复泄漏引用）。
     * 符号未就绪的早期调用不置位，留给符号就绪后的调用。 */
    if (g_usage_calib_done)
        return;
    if (!kf_init_task || !kf_copy_from_kernel_nofault)
        return;
    g_usage_calib_done = 1;

    g_usage_offset = -1;
    g_usage_offset_trusted = 0;

    /* 窗口自适应：256 → 512 → 1024。usage 在已知内核都位于前 64B，
     * 放大只是为了兼容厂商改动/RT 补丁把字段推后的内核。
     * 符号缺失（NOSYM）时放大窗口没意义，直接停。 */
    for (win = USAGE_CAL_MIN; win <= USAGE_CAL_MAX; win *= 2) {
        off1 = -1;
        off2 = -1;
        if (kpm_usage_calibrate_one(1, &off1, win) == 0 &&
            kpm_usage_calibrate_one(2, &off2, win) == 0 &&
            off1 > 0 && off1 == off2)
            goto verified;
        if (g_usage_calib_state == KPM_CALIB_NOSYM)
            break;
        kpm_log("LH_syms: usage calib window=%d not conclusive (off1=%d off2=%d), "
                "escalating\n", win, off1, off2);
    }

    if (g_usage_calib_state == KPM_CALIB_NONE)
        g_usage_calib_state = KPM_CALIB_FAIL;
    kpm_log("LH_syms: usage_offset NOT verified (off1=%d off2=%d state=%d) -> "
            "manual put DISABLED (leak-only, no memory write)\n",
            off1, off2, g_usage_calib_state);
    kpm_log("LH_syms:   -> 影响: 取引用的进程/maps 类接口需要免引用回退"
            "(kpm_task_acquire); 隐藏/断点探测的 task 引用只漏不收\n");
    kpm_printk("LH_syms: usage_offset NOT verified (state=%d) -> manual put disabled\n",
               g_usage_calib_state);
    return;

verified:
    g_usage_offset = off1;
    g_usage_offset_trusted = 1;
    g_usage_calib_state = KPM_CALIB_OK;
    kpm_log("LH_syms: usage_offset=%d VERIFIED by get_pid_task +1 fingerprint "
            "(pid 1 & pid 2, window=%d) -> manual put ENABLED\n", off1, win);
    kpm_printk("LH_syms: usage_offset=%d verified (+1 fingerprint, win=%d)\n",
               off1, win);
}

/* ===== task_struct 偏移运行时探测 =====
 * 通过 init_task 的 tasks 链表自洽性 + __task_pid_nr_ns 校验，
 * 自动探测 tasks_offset / pid_offset / tgid_offset / mm_offset。
 * 探测失败时保持 0，调用方需检查 > 0 才使用。
 *
 * 安全：所有内存读取用 copy_from_kernel_nofault，不会 panic。
 * 注意：PIDTYPE_PID/PIDTYPE_TGID 由 linux/pid.h 中的 enum pid_type 定义，
 * 无需本地宏定义，避免与框架枚举冲突。
 */
#define PROBE_SCAN_SIZE 2048

/* 安全版本 probe_task_struct_offsets
 *
 * 设计原则（隐蔽性 > 兼容性）：
 *   1. 绝不调用 __task_pid_nr_ns 于未验证的地址
 *   2. 仅通过链表自洽性验证偏移：
 *      - 候选 next 指针反推 candidate_task
 *      - 读 candidate_task+offset 处的 next 指针
 *      - 验证其反推的 task 不等于 candidate_task（非自环）
 *      - 验证 init_task 在链表中可达（next 链回到 init_addr）
 *   3. 不探测 pid/tgid/mm 偏移（依赖框架导出或保持 0）
 *   4. 所有读取通过 copy_from_kernel_nofault，不直接解引用
 */
static void probe_task_struct_offsets(void);

/* 前向声明：real_parent 偏移探测（在 probe_task_struct_offsets 末尾调用） */
static void probe_real_parent_offset(void);

static void probe_task_struct_offsets(void)
{
    uint64_t init_addr = (uint64_t)kf_init_task;
    uint64_t buf[PROBE_SCAN_SIZE / 8];
    int i;

    if (!kf_init_task || !kf_copy_from_kernel_nofault)
        return;

    /* 读取 init_task 前 2048 字节 */
    if (kf_copy_from_kernel_nofault(buf, (void *)init_addr, PROBE_SCAN_SIZE) != 0) {
        kpm_log("LH_syms: probe: failed to read init_task memory\n");
        return;
    }

    /* 探测 tasks_offset：扫描 list_head {next, prev} 结构
     * 安全验证：不调用 __task_pid_nr_ns，仅通过链表自洽性校验 */
    for (i = 0; i < PROBE_SCAN_SIZE / 8 - 1; i++) {
        uint64_t next_ptr = buf[i];
        uint64_t prev_ptr = buf[i + 1];
        uint64_t candidate_task;
        uint64_t verify_next = 0;
        uint64_t verify_prev = 0;

        /* 合法性检查：两个指针都必须是内核地址 */
        if (next_ptr < 0xFFFF000000000000ULL || prev_ptr < 0xFFFF000000000000ULL)
            continue;

        /* 反推 task_struct 地址 */
        candidate_task = next_ptr - (i * 8);
        if (candidate_task == init_addr)
            continue;
        /* 页对齐检查：task_struct 通常 slab 分配，至少 8 字节对齐 */
        if (candidate_task & 0x7)
            continue;

        /* 安全读取 candidate_task+offset 处的 list_head */
        if (kf_copy_from_kernel_nofault(&verify_next,
                (void *)(candidate_task + i * 8), 8) != 0)
            continue;
        if (kf_copy_from_kernel_nofault(&verify_prev,
                (void *)(candidate_task + i * 8 + 8), 8) != 0)
            continue;

        /* 自洽性校验 1：candidate 的 prev 应指向 init_task 的 tasks */
        if (prev_ptr - (i * 8) == init_addr) {
            /* init_task 是链表头，candidate 是第一个真实进程
             * candidate->prev 应指向 init_task */
        } else {
            /* 非首个节点，prev 也应反推为有效 task */
            uint64_t prev_task = prev_ptr - (i * 8);
            if (prev_task & 0x7)
                continue;
        }

        /* 自洽性校验 2：candidate->next 不应指向自身 */
        if (verify_next == next_ptr)
            continue;

        /* 自洽性校验 3：candidate->next 应是内核地址 */
        if (verify_next < 0xFFFF000000000000ULL)
            continue;

        /* 通过所有校验，确认 tasks_offset */
        g_tasks_offset = i * 8;
        kpm_log("LH_syms: probe: tasks_offset=%d (safe, no pid deref)\n", g_tasks_offset);
        break;
    }

    if (g_tasks_offset == 0) {
        kpm_log("LH_syms: probe: tasks_offset not found (safe probe)\n");
    }

    /* 探测 real_parent 偏移（依赖 tasks_offset 已确定） */
    probe_real_parent_offset();
}

/* ===== real_parent / arg_start / arg_end 偏移探测 =====
 *
 * real_parent 探测：
 *   init_task（PID 0，swapper）的 real_parent 指向自身（&init_task）。
 *   扫描 init_task 前 2048 字节，找到值等于 init_addr 的指针字段。
 *   排除 tasks 偏移附近（tasks 链表的 next/prev 可能也指向 init）。
 *
 * arg_start / arg_end 探测：
 *   惰性探测，在 kpm_proc_list_kernel 首次调用时执行。纯内存扫描
 *   mm_struct 找相邻 uint64_t 候选对，读取 [arg_start, arg_end) 验证为
 *   合法字符串；成功后缓存偏移，后续全部走 kpm_mem_read_kernel 纯内存路径。
 */

/* 探测 real_parent 偏移（在 probe_task_struct_offsets 中调用） */
static void probe_real_parent_offset(void)
{
    uint64_t init_addr = (uint64_t)kf_init_task;
    uint64_t buf[PROBE_SCAN_SIZE / 8];
    int i;
    int candidates[16];
    int num_candidates = 0;

    if (!kf_init_task || !kf_copy_from_kernel_nofault)
        return;

    if (kf_copy_from_kernel_nofault(buf, (void *)init_addr, PROBE_SCAN_SIZE) != 0)
        return;

    /* 扫描所有等于 init_addr 的字段（real_parent 指向自身） */
    for (i = 0; i < PROBE_SCAN_SIZE / 8; i++) {
        if (buf[i] == init_addr) {
            /* 排除 tasks 链表的 next/prev（偏移 tasks_offset 和 tasks_offset+8） */
            int off = i * 8;
            if (g_tasks_offset > 0 &&
                (off == g_tasks_offset || off == g_tasks_offset + 8))
                continue;
            if (num_candidates < 16)
                candidates[num_candidates++] = off;
        }
    }

    /* real_parent 通常在 tasks 之后、mm 之前
     * 取 tasks_offset 之后第一个候选 */
    if (g_tasks_offset > 0) {
        for (i = 0; i < num_candidates; i++) {
            if (candidates[i] > g_tasks_offset) {
                g_real_parent_offset = candidates[i];
                kpm_log("LH_syms: probe: real_parent_offset=%d\n",
                        g_real_parent_offset);
                return;
            }
        }
    }

    /* 回退：取第一个候选 */
    if (num_candidates > 0) {
        g_real_parent_offset = candidates[0];
        kpm_log("LH_syms: probe: real_parent_offset=%d (first candidate)\n",
                g_real_parent_offset);
    }
}

/* ===== 通用 task_struct 偏移探测（不依赖框架导出） =====
 *
 * 问题：KernelPatch 框架的 task_struct_offset 在部分设备上未填充（保持 -1），
 * 导致 tgid/pid/mm 偏移为 0，进程列表和内存读写功能级联失败。
 *
 * 方案：通过 find_get_pid + get_pid_task 获取已知 PID 的进程，
 * 结合 get_task_mm 获取 mm 指针，在 task_struct 中扫描特征值。
 * - mm_offset: 在 task_struct 中找等于 mm 指针的 8 字节字段（精确匹配）
 * - pid_offset: PID=1 的进程 pid=1/tgid=1，用 PID=2 交叉验证
 *
 * 隐蔽性: A 级（纯内核函数调用 + copy_from_kernel_nofault，无痕迹）
 * 兼容性: Linux 5.1+ 全版本（find_get_pid/get_pid_task/get_task_mm 均 EXPORT_SYMBOL）
 */
static void probe_task_struct_offsets_full(void)
{
    uint8_t *buf;
    uint64_t *fields64;
    uint32_t *fields32;
    struct pid *pid1_obj = NULL, *pid2_obj = NULL;
    struct task_struct *task1 = NULL, *task2 = NULL;
    struct mm_struct *mm1 = NULL;
    int i;
    int pid_candidates[32];
    int num_pid_candidates = 0;

    /* 全部已探测则跳过（usage 已不归本函数探测：见 kpm_usage_calibrate_one） */
    if (g_mm_offset > 0 && g_pid_offset > 0 && g_tgid_offset > 0)
        return;

    if (!kf_init_task || !kf_copy_from_kernel_nofault || !kf_kmalloc || !kf_kfree)
        return;

    buf = (uint8_t *)kf_kmalloc(PROBE_SCAN_SIZE, GFP_KERNEL);
    if (!buf) return;
    fields64 = (uint64_t *)buf;
    fields32 = (uint32_t *)buf;

    /* ===== 1. 探测 mm_offset 和 pid_offset（用 PID=1 的 init 进程） ===== */
    if ((g_mm_offset == 0 || g_pid_offset == 0) &&
        kf_find_get_pid && kf_get_pid_task && kf_get_task_mm && kf_mmput) {

        pid1_obj = kf_find_get_pid(1);
        if (!pid1_obj) goto cleanup;

        task1 = kf_get_pid_task(pid1_obj, PIDTYPE_PID);
        if (!task1) goto cleanup;

        mm1 = kf_get_task_mm(task1);

        if (kf_copy_from_kernel_nofault(buf, task1, PROBE_SCAN_SIZE) != 0) {
            kpm_log("LH_syms: probe: failed to read PID=1 task_struct\n");
            goto cleanup;
        }

        /* 探测 mm_offset: 8字节精确匹配 mm 指针 */
        if (g_mm_offset == 0 && mm1) {
            for (i = 0; i < PROBE_SCAN_SIZE / 8; i++) {
                if (fields64[i] == (uint64_t)mm1) {
                    g_mm_offset = i * 8;
                    kpm_log("LH_syms: probe: mm_offset=%d (mm=0x%llx)\n",
                            g_mm_offset, (uint64_t)mm1);
                    break;
                }
            }
        }

        /* 探测 pid_offset: PID=1 进程的 pid=1, tgid=1（相邻 pid_t） */
        if (g_pid_offset == 0) {
            for (i = 0; i < PROBE_SCAN_SIZE / 4 - 1; i++) {
                if (fields32[i] == 1 && fields32[i + 1] == 1) {
                    /* 排除 tasks 附近（避免误匹配链表指针低位） */
                    int off = i * 4;
                    if (g_tasks_offset > 0 &&
                        (off >= g_tasks_offset - 8 && off <= g_tasks_offset + 16))
                        continue;
                    if (num_pid_candidates < 32)
                        pid_candidates[num_pid_candidates++] = off;
                }
            }
        }
    }

    /* ===== 3. 用 PID=2 交叉验证 pid_offset =====
     * PID=2 的 kthreadd 进程 pid=2, tgid=2
     * 在相同偏移处值应为 2，验证候选正确性 */
    if (g_pid_offset == 0 && num_pid_candidates > 0 &&
        kf_find_get_pid && kf_get_pid_task) {

        pid2_obj = kf_find_get_pid(2);
        if (pid2_obj) {
            task2 = kf_get_pid_task(pid2_obj, PIDTYPE_PID);
            if (task2) {
                if (kf_copy_from_kernel_nofault(buf, task2, PROBE_SCAN_SIZE) == 0) {
                    for (i = 0; i < num_pid_candidates; i++) {
                        int off_idx = pid_candidates[i] / 4;
                        if (off_idx + 1 < PROBE_SCAN_SIZE / 4 &&
                            fields32[off_idx] == 2 &&
                            fields32[off_idx + 1] == 2) {
                            g_pid_offset = pid_candidates[i];
                            g_tgid_offset = pid_candidates[i] + 4;
                            g_pid_offset_verified = 1;
                            kpm_log("LH_syms: probe: pid_offset=%d tgid_offset=%d "
                                    "(verified with PID=2)\n",
                                    g_pid_offset, g_tgid_offset);
                            break;
                        }
                    }
                }
                kpm_put_task_struct(task2);
                task2 = NULL;
            }
            kf_put_pid(pid2_obj);
            pid2_obj = NULL;
        }
    }

    /* 验证失败时回退：取 tasks_offset 之后的第一个候选 */
    if (g_pid_offset == 0 && num_pid_candidates > 0) {
        for (i = 0; i < num_pid_candidates; i++) {
            if (g_tasks_offset == 0 || pid_candidates[i] > g_tasks_offset + 16) {
                g_pid_offset = pid_candidates[i];
                g_tgid_offset = pid_candidates[i] + 4;
                g_pid_offset_verified = 0;   /* 未验证：进程列表 pid 列可能不准 */
                kpm_log("LH_syms: probe: pid_offset=%d tgid_offset=%d "
                        "(UNVERIFIED, first after tasks - process list pid "
                        "column may be wrong)\n",
                        g_pid_offset, g_tgid_offset);
                break;
            }
        }
    }

cleanup:
    if (mm1) kf_mmput(mm1);
    if (task1) kpm_put_task_struct(task1);
    if (pid1_obj) kf_put_pid(pid1_obj);
    kf_kfree(buf);
}

/* ===== mm_struct.pgd 偏移运行时探测 =====
 * 框架未导出 mm_pgd_offset 时默认 56，但 5.1~6.x 实际偏移可能在 56~64 之间，
 * 错 8 字节会导致整条页表遍历路径失效（mem_rw 全部失败，功能降级）。
 *
 * 探测方法：取 PID 1 的 mm_struct，扫描其前 512 字节中的 8 字节字段：
 *   候选 = 内核地址（>= 0xFFFF000000000000）且 4K 对齐（pgd 页必须页对齐），
 *   验证该地址处首个 8 字节是有效页表项（bit0=1 且物理地址部分非零）。
 * mm_struct 中其它内核指针（mmap/vm 等）指向的 VMA 结构首个字段是
 * 用户地址（bit0 通常为 0），从而被排除。
 *
 * 安全性：所有读取用 copy_from_kernel_nofault，不会 panic。
 * 仅探测一次，成功则覆盖默认值。
 */
static int g_mm_pgd_offset_probed = 0;

/* 探测一个进程的 mm->pgd 偏移。返回 0 成功，-1 失败。
 *
 * 原理：mm_struct 中 pgd 字段指向顶层页表页（4KB，512 个 8 字节表项）。
 * 用户进程的顶层页表在"栈/库等高地址区"索引处存在有效表项（bit[1:0]=0x3，
 * 指向下一级或块映射）。真正的 pgd 页会有多个这类有效表项；而 mm_struct
 * 中其它内核指针（mmap/vm 树等）指向的数据结构首字段通常是用户地址
 * （bit0=0），被有效位校验排除。
 *
 * 兼容 39/48 位 VA：栈恒定位于用户空间顶部，对应顶层索引 >= 0xC0（48位）
 * 或 >= 0x1C0（39位），统一用 >= 0xC0 判定，两种位宽均覆盖。 */
static int probe_pgd_offset_one(struct mm_struct *mm)
{
    uint8_t buf[512];
    uint64_t *fields = (uint64_t *)buf;
    /* 采样的顶层索引：低区（代码/库）+ 高区（栈/堆） */
    static const int idxs[] = {
        0, 1, 2, 3, 4, 0x40, 0x80, 0xC0, 0x100, 0x140,
        0x180, 0x1C0, 0x1E0, 0x1F0, 0x1F8, 0x1FA, 0x1FC, 0x1FE, 0x1FF
    };
    int i, k;

    if (!mm || !kf_copy_from_kernel_nofault)
        return -1;
    if (kf_copy_from_kernel_nofault(buf, mm, sizeof(buf)) != 0)
        return -1;

    for (i = 0; i < (int)(sizeof(buf) / 8 - 1); i++) {
        uint64_t top = fields[i];
        uint64_t pgd_page[512];
        int hits = 0, high_hits = 0;

        /* 候选 pgd：4K 对齐的内核地址 */
        if (top < 0xFFFF000000000000ULL || (top & 0xFFF))
            continue;

        /* 读取整个顶层页表页（4KB，安全读取） */
        if (kf_copy_from_kernel_nofault(pgd_page, (void *)top,
                                        sizeof(pgd_page)) != 0)
            continue;

        /* 有效表项：bit[1:0]==0x3（表/块），物理地址在合理 RAM 范围 */
        for (k = 0; k < (int)(sizeof(idxs) / sizeof(idxs[0])); k++) {
            uint64_t e = pgd_page[idxs[k]];
            uint64_t phys = e & 0x0000FFFFFFFFF000ULL;
            if ((e & 0x3) == 0x3 && phys >= 0x40000000ULL &&
                phys < KPM_PHYS_MAX) {
                hits++;
                if (idxs[k] >= 0xC0)
                    high_hits++;
            }
        }
        /* 高区至少 1 个有效表项，且总命中 >= 2，才判定为真实 pgd */
        if (high_hits >= 1 && hits >= 2) {
            g_mm_pgd_offset = (uint64_t)(i * 8);
            kpm_log("LH_syms: probe mm_pgd_offset=%d (pgd=0x%llx "
                    "hits=%d high=%d)\n", i * 8,
                    (unsigned long long)top, hits, high_hits);
            return 0;
        }
    }
    return -1;
}

/* ===== task_struct.rcu_read_lock_nesting 偏移探测 =====
 * PREEMPT_RCU 下 rcu_read_lock 用 task_struct.rcu_read_lock_nesting(int)
 * 计数，内核无 rcu_read_lock_held 导出符号。
 * 模块 exit 由框架在 RCU 读临界区内调用时，需精确知道当前是否持有 RCU
 * 读锁，以便"借出"（unlock）让 synchronize_rcu 不再等待自己 → 自死锁解除。
 *
 * 探测方法（前后对照，唯一确定）：
 *   1. kpm_spin_lock_irqsave 关中断 + 持锁（消除探测窗口内中断/软中断对
 *      current->task_struct 的并发修改，防 preempt_count 等字段误判）；
 *   2. 快照 current->task_struct 前 PROBE_RCU_SCAN 字节（after 为持锁后）；
 *   3. 找 0→>=1 的 4 字节字段 → 即 rcu_read_lock_nesting 偏移；
 *   4. 解锁后再次快照确认 1→0（三重对照），防误判。
 * 探测失败（偏移仍 0）时 kpm_gyro_exit 跳过借出（不冒险）。
 */
#define PROBE_RCU_SCAN  0x800

int g_rcu_nesting_offset = 0;

static void probe_rcu_nesting_offset(void)
{
    static kpm_spinlock_t probe_lock = KPM_SPINLOCK_INIT;
    unsigned long flags;
    char buf0[PROBE_RCU_SCAN];
    char buf1[PROBE_RCU_SCAN];
    char buf2[PROBE_RCU_SCAN];
    int i, cand = -1;

    if (!kf_copy_from_kernel_nofault || !kf_rcu_read_lock || !kf_rcu_read_unlock)
        return;

    flags = kpm_spin_lock_irqsave(&probe_lock);

    /* 锁前快照 */
    if (kf_copy_from_kernel_nofault(buf0, (void *)current, PROBE_RCU_SCAN) != 0)
        goto out;
    /* 持锁（nesting 0→>=1） */
    kf_rcu_read_lock();
    if (kf_copy_from_kernel_nofault(buf1, (void *)current, PROBE_RCU_SCAN) != 0) {
        kf_rcu_read_unlock();
        goto out;
    }
    /* 解锁（nesting 回 0） */
    kf_rcu_read_unlock();
    if (kf_copy_from_kernel_nofault(buf2, (void *)current, PROBE_RCU_SCAN) != 0)
        goto out;

    /* 三重对照：buf0==0, buf1>=1, buf2==0 → 唯一确定 nesting 偏移 */
    for (i = 0; i + 4 <= PROBE_RCU_SCAN; i += 4) {
        int v0 = *(const int *)(buf0 + i);
        int v1 = *(const int *)(buf1 + i);
        int v2 = *(const int *)(buf2 + i);
        if (v0 == 0 && v1 >= 1 && v2 == 0) {
            cand = i;
            break;
        }
    }

out:
    kpm_spin_unlock_irqrestore(&probe_lock, flags);
    if (cand > 0) {
        g_rcu_nesting_offset = cand;
        kpm_log("LH_syms: rcu_read_lock_nesting offset=%d\n", cand);
    }
}

/* ===== exit 路径 RCU 读锁借出/还回（防 synchronize_rcu 自死锁） =====
 * exit 由框架在 RCU 读临界区内调用时，exit 里任何 synchronize_rcu/
 * 可睡眠调用（unregister_user_step_hook、perf release、
 * destroy_workqueue、tracepoint_synchronize_unregister、uprobe 注销）
 * 都会 GP 永久等待自身读临界区 → 整机冻结。
 * 借出模式：nesting>0 时 __rcu_read_unlock 脱离临界区 → 睡眠清理 →
 * __rcu_read_lock 还回，嵌套计数守恒。此处提取为公共 API 供全部 *_exit 使用。
 * 返回：
 *   1 = 已借出读锁 → 可安全执行睡眠清理，收尾【必须】调 release()
 *   0 = 确认不在 RCU 读临界区 → 可直接睡眠清理（无需 release）
 *  -1 = 无法确认安全（nesting 未标定且 any_held 报告在临界区，或双探测
 *       皆不可用）→ 【禁止】一切睡眠清理（跳过 + 残留警告；死锁代价
 *       整机冻结，泄漏代价可接受，两害取其轻） */
static int g_rcu_guard_held = 0;

int kpm_rcu_exit_guard_acquire(void)
{
    g_rcu_guard_held = 0;
    if (g_rcu_nesting_offset > 0) {
        int nest = *(volatile int *)
            ((const char *)current + g_rcu_nesting_offset);
        if (nest > 0) {
            if (!kf_rcu_read_unlock)
                return -1;
            kf_rcu_read_unlock();
            g_rcu_guard_held = 1;
            return 1;
        }
        return 0;        /* 标定偏移显示 nesting==0 → 真不在读临界区 */
    }
    if (kf_rcu_read_lock_any_held)
        return kf_rcu_read_lock_any_held() ? -1 : 0;
    return -1;           /* 双探测不可用：保守禁止 */
}

void kpm_rcu_exit_guard_release(void)
{
    if (g_rcu_guard_held) {
        if (kf_rcu_read_lock)
            kf_rcu_read_lock();
        g_rcu_guard_held = 0;
    }
}

static void probe_mm_pgd_offset(void)
{
    pid_t pid;

    if (g_mm_pgd_offset_probed)
        return;
    g_mm_pgd_offset_probed = 1;

    if (!kf_find_get_pid || !kf_get_pid_task || !kf_get_task_mm ||
        !kf_mmput || !kf_copy_from_kernel_nofault)
        return;

    /* 优先用 PID 1，失败则扫描后续进程找有正常用户 mm 的进程。
     * Android 上 init(1) 的 mm 可能异常；system_server 等用户进程
     * 的 pgd 页表项更可靠，覆盖错 8 字节导致整条页表遍历失效的情况。 */
    for (pid = 1; pid < KPM_PGD_PROBE_PID_MAX; pid++) {
        struct pid *pid_obj;
        struct task_struct *task;
        struct mm_struct *mm;

        pid_obj = kf_find_get_pid(pid);
        if (!pid_obj)
            continue;
        task = kf_get_pid_task(pid_obj, PIDTYPE_PID);
        kf_put_pid(pid_obj);
        if (!task)
            continue;
        mm = kf_get_task_mm(task);
        kpm_put_task_struct(task);
        if (!mm)
            continue;

        if (probe_pgd_offset_one(mm) == 0) {
            kf_mmput(mm);
            return;
        }
        kf_mmput(mm);
    }
    kpm_log("LH_syms: probe mm_pgd_offset FAILED (no valid pgd found)\n");
}

/* 探测 arg_start / arg_end 偏移（惰性调用，在 kpm_proc_list_kernel 中触发）
 * 返回 0 成功，负数失败 */
int kpm_probe_arg_offsets(void)
{
    /* 纯内存探测 arg_start/arg_end 偏移（不依赖 filp_open/kernel_read_iter）
     *
     * 探测原理：
     *   - arg_start/arg_end 是 mm_struct 中相邻的两个 uint64_t 字段
     *   - 值为用户态地址（< 0x0001000000000000）
     *   - arg_end > arg_start，差值 = cmdline 长度（通常 10~512 字节）
     *   - 读取 [arg_start, arg_end) 应得到合法字符串（包名/进程路径）
     *
     * 验证标准（不依赖 filp_open）：
     *   1. 长度在 [2, 4096]
     *   2. 首字节为可打印字符（字母，包名通常以 com./org./cn. 开头）
     *   3. 90% 字节为可打印 ASCII 或 \0
     *   4. 末尾为 \0
     *
     * 优势：完全无文件 I/O，无 kernel_read_iter 依赖，隐蔽性更高 */
    struct task_struct *task, *first;
    uint8_t mm_buf[1024];
    uint64_t *mm_fields = (uint64_t *)mm_buf;
    pid_t target_pid = 0;
    uint64_t mm_ptr = 0;
    int i, j;
    int found = 0;

    /* 已探测则跳过 */
    if (g_arg_start_offset > 0 && g_arg_end_offset > 0)
        return 0;

    /* 需要的符号全部就绪（纯内存路径，不需要 filp_open/kernel_read_iter）
     * RCU 锁可选：非 PREEMPT 内核不可解析，KPM_RCU_READ_LOCK 宏自动跳过 */
    if (g_tasks_offset == 0 || g_mm_offset == 0 || g_pid_offset == 0 ||
        !kf_init_task || !kf_copy_from_kernel_nofault)
        return -1;

    /* 1. RCU 锁内收集最多 8 个用户进程候选（pid + mm_ptr） */
    {
        struct { pid_t pid; uint64_t mm_ptr; } cand[8];
        int num_cand = 0;

        KPM_RCU_READ_LOCK();
        first = KPM_NEXT_TASK(kf_init_task);
        task = first;
        if (!task) { KPM_RCU_READ_UNLOCK(); return -1; }
        do {
            pid_t pid;
            uint64_t mm_val;
            int is_kthread;

            if (kf_copy_from_kernel_nofault(&pid,
                    (void *)((unsigned long)task + g_pid_offset), 4) != 0)
                goto next_pa;
            if (pid <= 0 || pid > 32768)
                goto next_pa;

            is_kthread = 1;
            if (kf_copy_from_kernel_nofault(&mm_val,
                    (void *)((unsigned long)task + g_mm_offset), 8) == 0)
                is_kthread = (mm_val == 0) ? 1 : 0;
            if (is_kthread)
                goto next_pa;

            if (num_cand < 8) {
                cand[num_cand].pid = pid;
                cand[num_cand].mm_ptr = mm_val;
                num_cand++;
            }
            if (num_cand >= 8)
                break;

        next_pa:
            task = KPM_NEXT_TASK(task);
        } while (task && task != first && task != kf_init_task);
        KPM_RCU_READ_UNLOCK();

        if (num_cand == 0)
            return -1;

        /* 2. 逐个候选验证：读 mm_struct + 扫描偏移 + 内存验证 */
        for (i = 0; i < num_cand && !found; i++) {
            int c;

            target_pid = cand[i].pid;
            mm_ptr = cand[i].mm_ptr;

            /* 读 mm_struct 前 1024 字节 */
            if (kf_copy_from_kernel_nofault(mm_buf, (void *)mm_ptr, sizeof(mm_buf)) != 0)
                continue;

            /* 扫描 mm_struct 找 arg_start/arg_end 候选对 */
            for (c = 0; c < (int)(sizeof(mm_buf) / 8 - 1); c++) {
                uint64_t a = mm_fields[c];
                uint64_t b = mm_fields[c + 1];
                uint64_t diff;
                char verify_buf[4096];
                long n;
                int printable_count = 0;
                int total;
                extern long kpm_mem_read_kernel(pid_t pid, uint64_t remote_addr,
                                                void *kbuf, int len);

                if (a == 0 || a >= 0x0001000000000000ULL)
                    continue;
                if (b == 0 || b >= 0x0001000000000000ULL)
                    continue;
                if (b <= a)
                    continue;
                diff = b - a;
                if (diff < 2 || diff > 4096)
                    continue;

                /* 内存验证：读取 [a, b) */
                n = kpm_mem_read_kernel(target_pid, a, verify_buf, (int)diff);
                if (n != (long)diff || n <= 0)
                    continue;

                /* 字符串特征验证（不依赖 filp_open）：
                 * - 末尾为 \0
                 * - 首字节为可打印字符
                 * - 90% 字节为可打印 ASCII 或 \0
                 * - 包含 '.' 或 '/' （包名/路径特征，大幅降低误判） */
                if (verify_buf[n - 1] != '\0')
                    continue;
                if (verify_buf[0] < 0x20 || verify_buf[0] > 0x7e)
                    continue;

                total = 0;
                for (j = 0; j < n; j++) {
                    unsigned char ch = (unsigned char)verify_buf[j];
                    if ((ch >= 0x20 && ch <= 0x7e) || ch == '\0')
                        printable_count++;
                    total++;
                }
                if (total == 0 || printable_count * 10 < total * 9)
                    continue;

                /* 检查是否包含 '.' 或 '/' （包名/路径特征）
                 * Android 应用包名格式：com.xxx.xxx / org.xxx.xxx / cn.xxx.xxx
                 * 进程路径格式：/system/bin/xxx */
                {
                    int has_dot_or_slash = 0;
                    for (j = 0; j < n; j++) {
                        if (verify_buf[j] == '.' || verify_buf[j] == '/') {
                            has_dot_or_slash = 1;
                            break;
                        }
                    }
                    if (!has_dot_or_slash)
                        continue;
                }

                /* 验证通过 */
                g_arg_start_offset = c * 8;
                g_arg_end_offset = (c + 1) * 8;
                kpm_log("LH_syms: probe: arg_start_offset=%d arg_end_offset=%d "
                        "(pid=%d len=%d)\n",
                        g_arg_start_offset, g_arg_end_offset,
                        target_pid, (int)diff);

                /* ===== 顺便探测 total_vm 偏移 =====
                 * total_vm 在 mm_struct 中位于 arg_start 之前，特征：
                 *   - total_vm 是 unsigned long (8 bytes)，非零
                 *   - 值范围: [1, 0x1000000]（1 页 ~ 64GB 页数）
                 *   - 后面紧跟 locked_vm=0, pinned_vm=0（大多数进程）
                 * 从 arg_start 位置往前扫描，找第一个符合 [非零, 0, 0] 模式的字段。
                 * mm_struct 字段顺序: ...total_vm, locked_vm, pinned_vm, data_vm,
                 *   exec_vm, stack_vm, start_code, end_code, start_data, end_data,
                 *   start_brk, brk, start_stack, arg_start, arg_end... */
                if (g_total_vm_offset == 0) {
                    int tc;
                    int arg_field_idx = c;  /* arg_start 在 mm_fields 中的索引 */
                    for (tc = arg_field_idx - 1; tc >= 2; tc--) {
                        uint64_t v = mm_fields[tc];
                        if (v >= 1 && v <= 0x1000000ULL &&
                            mm_fields[tc + 1] == 0 &&
                            mm_fields[tc + 2] == 0) {
                            g_total_vm_offset = tc * 8;
                            kpm_log("LH_syms: probe: total_vm_offset=%d "
                                    "(total_vm=%llu pages=%lluMB pid=%d)\n",
                                    g_total_vm_offset,
                                    (unsigned long long)v,
                                    (unsigned long long)(v * 4096 / 1024 / 1024),
                                    target_pid);
                            break;
                        }
                    }
                    if (g_total_vm_offset == 0)
                        kpm_log("LH_syms: probe: total_vm_offset not found\n");
                }

                found = 1;
                break;
            }
        }
    }

    return found ? 0 : -1;
}

/* ===== vm_area_struct 偏移运行时探测（惰性调用） =====
 * 在首次 kpm_proc_maps 调用时通过 find_vma(mm,0) 获取首个 VMA，
 * 扫描其内存特征自动探测 vm_start/vm_end/vm_next 偏移。
 *
 * 探测原理：
 * - vm_start 是 VMA 中第一个非零且小于后续 8 字节值的字段（虚拟地址递增）
 * - vm_end 紧跟 vm_start 之后
 * - vm_next 是 vm_end 之后第一个指向内核地址的指针字段
 *
 * 调用前需持有 mmap_read_lock（禁止睡眠），所有内存读取用 copy_from_kernel_nofault。
 * 返回 0 成功，负数失败。
 */
#define VMA_PROBE_SCAN_SIZE 256

int kpm_probe_vma_offsets(struct mm_struct *mm)
{
    uint8_t buf[VMA_PROBE_SCAN_SIZE];
    uint64_t *fields = (uint64_t *)buf;
    int i;
    void *first_vma;

    if (g_vm_start_offset != -1)
        return 0;  /* 已探测 */

    if (!mm || !kf_copy_from_kernel_nofault)
        return -1;
    /* find_vma 不可用时，回退路径需要 mm_mmap 偏移 + vm_next 偏移
     * 但探测 vm 偏移本身需要先找到一个 VMA，所以这里要求 find_vma 可用
     * 若 find_vma 不可用（极低概率），直接返回失败 */
    if (!kf_find_vma)
        return -1;

    first_vma = kpm_find_vma_next(mm, 0);
    if (!first_vma)
        return -1;

    if (kf_copy_from_kernel_nofault(buf, first_vma, VMA_PROBE_SCAN_SIZE) != 0)
        return -1;

    /* 1. 探测 vm_start/vm_end：
     * 扫描前 32 个 8 字节字段，找到第一个满足 start < end 且两者都非零的组合 */
    for (i = 0; i < VMA_PROBE_SCAN_SIZE / 8 - 1; i++) {
        uint64_t v0 = fields[i];
        uint64_t v1 = fields[i + 1];

        /* vm_start 和 vm_end 都是用户空间虚拟地址（通常在 0x0000... 到 0x7FFF...）
         * 且 vm_start < vm_end，两者都非零 */
        if (v0 == 0 || v1 == 0)
            continue;
        if (v0 >= v1)
            continue;
        /* 合法用户空间地址范围检查（排除内核指针） */
        if (v0 >= 0xFFFF000000000000ULL)
            continue;
        if (v1 - v0 > 0x100000000ULL)  /* 单个 VMA 不应超过 4GB */
            continue;

        /* 找到候选的 vm_start/vm_end，进一步用 vm_next 验证 */
        g_vm_start_offset = i * 8;
        g_vm_end_offset = (i + 1) * 8;

        /* 2. 探测 vm_next：在 vm_end 之后查找指向另一个 VMA 的内核指针字段
         * vm_next 指向另一个 vm_area_struct（内核地址或 NULL 表示末尾）。
         * 验证方法：目标地址 + g_vm_start_offset 处应是非零用户空间地址 */
        {
            int j;
            int null_candidate = -1;
            for (j = i + 2; j < VMA_PROBE_SCAN_SIZE / 8; j++) {
                uint64_t v = fields[j];
                if (v == 0) {
                    /* NULL 可能是链表末尾，记录但继续查找非零验证指针 */
                    if (null_candidate < 0)
                        null_candidate = j;
                    continue;
                }
                if (v >= 0xFFFF000000000000ULL) {
                    /* 内核指针，验证：目标 VMA 的 vm_start 也应是合法用户地址 */
                    uint64_t next_vma_start = 0;
                    uint64_t check_addr = v + g_vm_start_offset;
                    if (kf_copy_from_kernel_nofault(&next_vma_start,
                            (void *)check_addr, 8) == 0 &&
                        next_vma_start != 0 &&
                        next_vma_start < 0xFFFF000000000000ULL) {
                        g_vm_next_offset = j * 8;
                        break;
                    }
                }
            }
            /* 若未找到验证的非零指针，但有 NULL 候选，使用 NULL 候选
             * （首个 VMA 可能是唯一 VMA，vm_next == NULL） */
            if (g_vm_next_offset == 0 && null_candidate >= 0)
                g_vm_next_offset = null_candidate * 8;
        }

        /* 3. 探测 vm_flags：多条件 + 位合法性校验。
         * vm_flags 是 unsigned long（8 字节），标志位：
         *   VM_READ(0x1)|VM_WRITE(0x2)|VM_EXEC(0x4)|VM_SHARED(0x8)|
         *   VM_MAYREAD(0x10)|VM_MAYWRITE(0x20)|VM_MAYEXEC(0x40)|VM_MAYSHARE(0x80)|
         *   VM_GROWSDOWN(0x100)|VM_GROWSUP(0x200)|VM_SHM(0x400)|VM_DENYWRITE(0x800)...
         * 校验条件（标志位仅用低 32 位，权限位与 MAY 位必存其一）：
         *   a. 值高 32 位为 0
         *   b. 权限位必存其一: v & 0x7（READ/WRITE/EXEC）
         *   c. MAY 位必存其一: v & 0x70（MAYREAD/MAYWRITE/MAYEXEC）
         *   d. 值不超过 0xFFFF（含 GROWSDOWN 等扩展位）
         *   e. 取第一个满足 a-d 的字段
         * 失败（未找到）则保持 -1，perms 走默认 0x3，不崩溃。 */
        {
            int j;
            int flags_candidate = -1;
            for (j = i + 2; j < VMA_PROBE_SCAN_SIZE / 8; j++) {
                uint64_t v = fields[j];

                if (v == 0 || (v >> 32) != 0)
                    continue;
                if ((v & 0x7) == 0)        /* 权限位必存其一 */
                    continue;
                if ((v & 0x70) == 0)       /* MAY 位必存其一 */
                    continue;

                /* 同一字段值应在合法标志范围内（含 GROWSDOWN 等扩展位，放宽至 0xFFFF） */
                if (v > 0xFFFF)
                    continue;

                flags_candidate = j;
                break;
            }
            if (flags_candidate >= 0)
                g_vm_flags_offset = flags_candidate * 8;
        }

        kpm_log("LH_syms: probe vma: vm_start=%d vm_end=%d vm_next=%d vm_flags=%d\n",
                g_vm_start_offset, g_vm_end_offset, g_vm_next_offset,
                g_vm_flags_offset);

        /* VMA 偏移探测成功后，顺便探测 mm_struct.mmap 偏移（回退路径使用）
         * 5.x-6.0: 探测成功，激活 vm_next 链表遍历回退
         * 6.1+: 探测失败（mm->mmap 不存在），回退路径自动禁用 */
        kpm_probe_mm_mmap_offset(mm, first_vma);

        return 0;
    }

    kpm_log("LH_syms: probe vma: failed to find vm_start/vm_end pattern\n");
    return -1;
}

/* ===== vm_file / file.dentry / dentry.name 偏移探测（纯内存路径解析） =====
 * 用途：VMA 遍历时直接从 vm_area_struct.vm_file → struct file.f_path.dentry
 *       → struct dentry.d_name.name 解析文件名。
 * 背景：Android SELinux enforcing 下内核态 filp_open("/proc/<pid>/maps")
 *       被 ptrace_may_access 拒绝（root 也无法绕过），/proc 文件读取方案不可行。
 *       因此采用纯内存解析：无 VFS、无文件 IO、无 audit 痕迹，隐蔽性 A 级。
 * 兼容性：三个偏移全部运行时探测（扫描候选指针 + 字符串合法性验证 +
 *         跨 VMA 一致性确认），不硬编码任何版本布局。 */

/* 校验内核地址处字符串是否"像文件名"（可打印 ASCII，含字母，长度 2..255）
 * out_len 可空，带回 strlen 值（供 qstr len 交叉验证） */
static int kpm_probe_name_string_ok(uint64_t addr, int *out_len)
{
    uint8_t c;
    int len = 0;
    int has_alpha = 0;

    if (out_len)
        *out_len = 0;
    if (addr < 0xFFFF000000000000ULL)
        return 0;
    while (len < 255) {
        if (kf_copy_from_kernel_nofault(&c, (void *)(addr + len), 1) != 0)
            return 0;
        if (c == 0)
            break;
        if (c < 0x20 || c > 0x7E)      /* 非可打印 → 不是文件名 */
            return 0;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
            has_alpha = 1;
        len++;
    }
    if (out_len)
        *out_len = len;
    /* 至少 2 字符且含字母（排除纯数字短串/随机指针内容） */
    return (len >= 2 && has_alpha) ? 1 : 0;
}

/* 探测三个偏移。遍历最多 128 个 VMA，统计命中组合，取出现次数最多的组合。
 * 返回 0 成功，-1 失败（进程无文件映射 VMA 时失败，path 保持为空）。 */
int kpm_probe_vm_file_offsets(struct mm_struct *mm)
{
    /* 命中表：key = (vm_file_off<<16)|(dentry_off<<8)|name_off，count 为命中次数 */
    struct {
        int key;
        int count;
    } hits[64];
    int hit_count = 0;
    void *vma;
    int vma_idx;
    int scan_start, scan_end;
    int j, d_off, n_off;
    int best_key = -1, best_count = 0;
    int i;
    int vma_count = 0;   /* 诊断：实际遍历的 VMA 数 */

    if (g_vm_file_offset != -1)
        return 0;                       /* 已探测 */
    if (!mm || !kf_copy_from_kernel_nofault || !kf_find_vma)
        return -1;
    if (g_vm_end_offset < 0)
        return -1;

    lib_memset(hits, 0, sizeof(hits));

    /* 扫描起点：不依赖 g_vm_flags_offset，从 vm_end_offset+8 之后开始扫描，
     * 覆盖 vm_flags/anon_vma/vm_ops/vm_pgoff/vm_file 全部字段
     * （5.1-6.x 中 vm_file 一般在 vm_flags 之后 0x08..0x60 区间）。 */
    scan_start = (g_vm_end_offset >= 0) ? g_vm_end_offset + 8 : 0x10;
    scan_end = 0x110;

    vma = kpm_find_vma_next(mm, 0);
    for (vma_idx = 0; vma_idx < 128 && vma; vma_idx++) {
        uint64_t vma_end = 0;
        /* 每级诊断计数：p 合法指针 / 链到达字符串检查 / 字符串+qstr 双验证命中 */
        int n_pok = 0, n_chain = 0, n_strok = 0;

        if (kf_copy_from_kernel_nofault(&vma_end,
                (void *)((unsigned long)vma + g_vm_end_offset), 8) != 0)
            break;

        for (j = scan_start; j <= scan_end; j += 8) {
            uint64_t p = 0;
            if (kf_copy_from_kernel_nofault(&p,
                    (void *)((unsigned long)vma + j), 8) != 0)
                continue;
            if (p < 0xFFFF000000000000ULL)
                continue;               /* 匿名映射 vm_file==NULL */
            n_pok++;

            for (d_off = 0x08; d_off <= 0x28; d_off += 8) {
                uint64_t d = 0;
                if (kf_copy_from_kernel_nofault(&d, (void *)(p + d_off), 8) != 0)
                    continue;
                if (d < 0xFFFF000000000000ULL)
                    continue;

                for (n_off = 0x18; n_off <= 0x48; n_off += 8) {
                    uint64_t n = 0;
                    int key;
                    int found = 0;
                    int slen = 0;
                    uint32_t qlen = 0;
                    if (kf_copy_from_kernel_nofault(&n, (void *)(d + n_off), 8) != 0)
                        continue;
                    if (n < 0xFFFF000000000000ULL)
                        continue;
                    n_chain++;
                    if (!kpm_probe_name_string_ok(n, &slen))
                        continue;

                    /* qstr 交叉验证：qstr={hash(u32)@0,len(u32)@4,
                     * name(ptr)@8} 共 16 字节。len 在 name 指针前 **4** 字节。
                     * u32 len == strlen(name) 证明 d 是真实 dentry、n 是真实
                     * qstr——随机数据同时满足"指针→可打印字符串→前置 len 恰等于
                     * 串长"概率≈0。静态 ELF（.data 空 → RW 段匿名映射）全进程
                     * 可能只有 1 个文件映射 VMA，故单个有效命中即可接受。 */
                    if (kf_copy_from_kernel_nofault(&qlen,
                            (void *)(d + n_off - 4), 4) != 0)
                        continue;
                    if (qlen != (uint32_t)slen)
                        continue;
                    n_strok++;

                    key = (j << 16) | (d_off << 8) | n_off;
                    for (i = 0; i < hit_count; i++) {
                        if (hits[i].key == key) {
                            hits[i].count++;
                            found = 1;
                            break;
                        }
                    }
                    if (!found && hit_count < 64) {
                        hits[hit_count].key = key;
                        hits[hit_count].count = 1;
                        hit_count++;
                    }
                }
            }
        }
        vma_count++;
        /* 诊断（前 3 个 VMA 明细 + 总数）：定位链条在哪一级断裂 */
        if (vma_count <= 3)
            kpm_log("LH_syms: probe vm_file: vma#%d end=0x%llx kptr_j=%d "
                    "chain=%d strok=%d\n",
                    vma_count, (unsigned long long)vma_end,
                    n_pok, n_chain, n_strok);
        vma = kpm_find_vma_next(mm, vma_end);
    }

    /* 取命中次数最多的组合（同一组偏移应在所有文件映射 VMA 上反复命中） */
    for (i = 0; i < hit_count; i++) {
        if (hits[i].count > best_count) {
            best_count = hits[i].count;
            best_key = hits[i].key;
        }
    }

    /* 接受阈值为 1——qstr len 交叉验证已保证命中的真实性
     * （字符串 + 前置 len 双重一致），单文件映射进程合法存在。 */
    if (best_key < 0) {
        kpm_log("LH_syms: probe vm_file: not found (vmas=%d, hits=%d, best=%d)\n",
                vma_count, hit_count, best_count);
        return -1;
    }

    g_vm_file_offset = (best_key >> 16) & 0xFF;
    g_file_dentry_offset = (best_key >> 8) & 0xFF;
    g_dentry_name_offset = best_key & 0xFF;
    kpm_log("LH_syms: probe vm_file: vm_file_off=%d dentry_off=%d name_off=%d "
            "(vmas=%d, hits=%d, best=%d)\n",
            g_vm_file_offset, g_file_dentry_offset, g_dentry_name_offset,
            vma_count, hit_count, best_count);
    return 0;
}

/* 从 VMA 指针解析文件名到 out（纯内存，无 VFS）。
 * 返回 0 成功（out 非空），-1 失败（匿名映射/偏移未探测/解析失败）。 */
int kpm_vma_get_path(void *vma, char *out, int out_size)
{
    uint64_t file_ptr = 0, dentry_ptr = 0, name_ptr = 0;
    int i;

    if (!vma || !out || out_size <= 1)
        return -1;
    if (g_vm_file_offset < 0 || g_file_dentry_offset < 0 ||
        g_dentry_name_offset < 0)
        return -1;
    if (!kf_copy_from_kernel_nofault)
        return -1;

    if (kf_copy_from_kernel_nofault(&file_ptr,
            (void *)((unsigned long)vma + g_vm_file_offset), 8) != 0)
        return -1;
    if (file_ptr == 0 || file_ptr < 0xFFFF000000000000ULL)
        return -1;                      /* 匿名映射 */

    if (kf_copy_from_kernel_nofault(&dentry_ptr,
            (void *)(file_ptr + g_file_dentry_offset), 8) != 0)
        return -1;
    if (dentry_ptr == 0 || dentry_ptr < 0xFFFF000000000000ULL)
        return -1;

    if (kf_copy_from_kernel_nofault(&name_ptr,
            (void *)(dentry_ptr + g_dentry_name_offset), 8) != 0)
        return -1;
    if (name_ptr == 0 || name_ptr < 0xFFFF000000000000ULL)
        return -1;

    for (i = 0; i < out_size - 1; i++) {
        uint8_t c;
        if (kf_copy_from_kernel_nofault(&c, (void *)(name_ptr + i), 1) != 0)
            break;
        if (c == 0)
            break;
        out[i] = (char)c;
    }
    out[i] = '\0';
    return (i > 0) ? 0 : -1;
}

/* 从 VMA 解析文件完整路径（沿 dentry.d_parent 链向上拼接，纯内存）。
 * 背景：kpm_vma_get_path 只返回 basename（dentry.d_name.name），
 *       文件回退 dump 需要完整路径才能 filp_open 读取磁盘文件。
 * 原理：dentry 结构在 5.1-6.x ARM64 标准布局中：
 *         d_flags(0x00) d_seq(0x04) d_hash(0x08,16B) d_parent(0x18) d_name(0x20)
 *       qstr={hash(u32),len(u32),name(ptr)} 共 16 字节，d_parent 偏移 =
 *       g_dentry_name_offset - 0x10。为兼容性，运行时验证 d_parent 指向的
 *       dentry 其 d_name.name 可读。
 * 返回值：0 成功（out 为完整路径），-1 失败。路径以 '/' 开头（如
 *         /system/lib64/libxxx.so）；根目录或异常时回退 basename。 */
int kpm_vma_get_fullpath(void *vma, char *out, int out_size)
{
    /* 组件栈：最多 16 层（足够 /system/lib64/xxx.so 等常规路径） */
    char comps[16][64];
    int ncomp = 0;
    uint64_t dentry_ptr = 0;
    uint64_t file_ptr = 0;
    uint64_t name_ptr = 0;
    int d_parent_off;
    int i, total = 0;
    int guard = 0;

    if (!vma || !out || out_size <= 1)
        return -1;
    if (g_vm_file_offset < 0 || g_file_dentry_offset < 0 ||
        g_dentry_name_offset < 0)
        return -1;
    if (!kf_copy_from_kernel_nofault)
        return -1;

    /* vm_file -> f_path.dentry */
    if (kf_copy_from_kernel_nofault(&file_ptr,
            (void *)((unsigned long)vma + g_vm_file_offset), 8) != 0)
        return -1;
    if (file_ptr == 0 || file_ptr < 0xFFFF000000000000ULL)
        return -1;                      /* 匿名映射 */
    if (kf_copy_from_kernel_nofault(&dentry_ptr,
            (void *)(file_ptr + g_file_dentry_offset), 8) != 0)
        return -1;
    if (dentry_ptr == 0 || dentry_ptr < 0xFFFF000000000000ULL)
        return -1;

    /* d_parent 偏移 = name 字段偏移 - 0x10（qstr 共 16 字节） */
    d_parent_off = g_dentry_name_offset - 0x10;

    /* 沿 d_parent 链收集组件名（从叶子到根） */
    while (dentry_ptr >= 0xFFFF000000000000ULL && guard++ < 32) {
        uint64_t parent = 0;
        int len = 0;

        /* 读 d_name.name */
        if (kf_copy_from_kernel_nofault(&name_ptr,
                (void *)(dentry_ptr + g_dentry_name_offset), 8) != 0)
            break;
        if (name_ptr < 0xFFFF000000000000ULL)
            break;

        /* 拷贝组件名（最多 63 字节） */
        len = 0;
        while (len < 63) {
            uint8_t ch;
            if (kf_copy_from_kernel_nofault(&ch, (void *)(name_ptr + len), 1) != 0)
                break;
            if (ch == 0)
                break;
            comps[ncomp][len] = (char)ch;
            len++;
        }
        comps[ncomp][len] = '\0';
        ncomp++;
        if (ncomp >= 16)
            break;

        /* 读 d_parent */
        if (kf_copy_from_kernel_nofault(&parent,
                (void *)(dentry_ptr + d_parent_off), 8) != 0)
            break;
        if (parent == dentry_ptr)
            break;                       /* 根目录自指 */
        dentry_ptr = parent;
    }

    if (ncomp == 0)
        return -1;

    /* 拼接：从根到叶子 */
    for (i = ncomp - 1; i >= 0; i--) {
        int need = (int)lib_strlen(comps[i]) + 1;   /* 含 '/' */
        if (i == ncomp - 1 && comps[i][0] != '/') {
            /* 最顶层（根）组件前补 '/'；组件本身是 "/" 时跳过 */
            if (lib_strcmp(comps[i], "/") != 0)
                need++;                  /* 补前导 '/' */
        }
        if (total + need >= out_size - 1)
            break;
        if (i == ncomp - 1 && comps[i][0] != '/' && lib_strcmp(comps[i], "/") != 0) {
            out[total++] = '/';
        }
        {
            int k;
            for (k = 0; comps[i][k] && total < out_size - 1; k++)
                out[total++] = comps[i][k];
        }
        if (i > 0 && total < out_size - 1)
            out[total++] = '/';
    }
    out[total] = '\0';

    /* 校验：路径非空且不含非法控制字符 */
    if (total < 1)
        return -1;
    for (i = 0; i < total; i++) {
        if ((uint8_t)out[i] < 0x20)
            return -1;
    }
    return 0;
}

/* ===== mm_struct.mmap 偏移运行时探测（回退路径使用） =====
 * 扫描 mm_struct 内存查找指向已知 VMA 的指针字段。
 *
 * 探测原理：
 *   - 5.x-6.0: mm->mmap 是 VMA 链表头，指向第一个 VMA
 *   - 通过 find_vma(mm, 0) 已知首个 VMA 地址，在 mm_struct 中扫描
 *     找到值等于 first_vma 的 8 字节字段，即为 mm->mmap 偏移
 *   - 6.1+: maple tree 取代链表，mm_struct 中不存在此字段，探测失败
 *
 * 隐蔽性: A 级
 *   - 仅 copy_from_kernel_nofault 读取，不触发任何 hook
 *   - 无 VFS、无文件 IO
 *
 * 安全性:
 *   - 扫描范围限制 1024 字节（mm_struct 通常 < 1KB）
 *   - 找到第一个匹配即停止，避免误匹配
 *   - 探测结果缓存，仅首次调用执行
 *
 * @mm: 目标进程 mm_struct
 * @first_vma: 已知的首个 VMA 地址（通过 find_vma(mm,0) 获取）
 * 返回 0 成功，负数失败。
 */
#define MM_PROBE_SCAN_SIZE 1024

int kpm_probe_mm_mmap_offset(struct mm_struct *mm, void *first_vma)
{
    uint8_t buf[MM_PROBE_SCAN_SIZE];
    uint64_t *fields = (uint64_t *)buf;
    int i;
    uint64_t target = (uint64_t)first_vma;

    if (g_mm_mmap_offset != -1)
        return 0;  /* 已探测 */

    if (!mm || !first_vma || !kf_copy_from_kernel_nofault)
        return -1;

    /* 验证 first_vma 是合法内核地址 */
    if (target < 0xFFFF000000000000ULL)
        return -1;

    if (kf_copy_from_kernel_nofault(buf, mm, MM_PROBE_SCAN_SIZE) != 0)
        return -1;

    /* 扫描 mm_struct 中的字段，查找值等于 first_vma 的字段 */
    for (i = 0; i < MM_PROBE_SCAN_SIZE / 8; i++) {
        if (fields[i] == target) {
            g_mm_mmap_offset = i * 8;
            kpm_log("LH_syms: probe mm_mmap: offset=%d (first_vma=0x%llx)\n",
                    g_mm_mmap_offset, (unsigned long long)target);
            return 0;
        }
    }

    /* 6.1+ maple tree 模式下，mm->mmap 字段不存在 */
    g_mm_mmap_offset = -2;  /* 标记探测失败，避免重复探测 */
    kpm_log("LH_syms: probe mm_mmap: not found (likely 6.1+ maple tree)\n");
    return -1;
}

/* ===== 统一的 VMA 查找辅助函数（高兼容性三级回退链） =====
 * kpm_find_vma_next - 查找 mm 中第一个 vm_end > addr 的 VMA
 * @mm: 目标进程的 mm_struct
 * @addr: 起始查找地址（传入 0 获取首个 VMA，传入当前 VMA 的 vm_end 获取下一个）
 *
 * 回退链（按优先级）：
 *   1. find_vma（原生锁主路径）: g_mmap_read_lock_native=1（5.12+），
 *      调用方经 kpm_mm_read_lock 持原生 mmap 读锁，契约满足
 *   2. vm_next 链表遍历（无锁主路径）: 4.14/5.4/5.10 等，
 *      全 copy_from_kernel_nofault 读，无裸解引用（防 panic）
 *      需要 g_mm_mmap_offset 和 g_vm_next_offset 已探测成功
 *   3. find_vma + RCU（兜底）: 偏移探测引导期首次调用，或
 *      6.1 无原生锁符号（罕见），功能不回退
 *
 * 隐蔽性: A 级
 *   - 路径 1: 纯内核函数调用，无任何可观测痕迹
 *   - 路径 2: 仅 copy_from_kernel_nofault 读取，不触发任何 hook
 *   - 所有路径无 VFS、无文件 IO、无用户态参与
 */
void *kpm_find_vma_next(struct mm_struct *mm, uint64_t addr)
{
    if (!mm) return NULL;

    /* find_vma 为全版本主路径（5.1+ EXPORT_SYMBOL，rbtree O(log n)）。
     * 锁语义由调用方 kpm_mm_read_lock 适配层保证：5.12+ 持原生 mmap 读锁
     * （契约满足）；4.14~5.11 持 RCU 读锁 + find_vma 裸 rbtree 读。
     * vm_next 链表遍历为 O(n) 线性扫描，仅作 find_vma 不可用时的回退。 */
    if (kf_find_vma)
        return kf_find_vma(mm, (unsigned long)addr);

    /* 路径 2: vm_next 链表遍历（find_vma 不可用时的回退，5.x-6.0 链表模式）
     * 需要 g_mm_mmap_offset >= 0 和 g_vm_next_offset >= 0
     * 6.1+ maple tree 下 g_mm_mmap_offset == -2，自动跳过 */
    if (g_mm_mmap_offset >= 0 && g_vm_next_offset >= 0 &&
        kf_copy_from_kernel_nofault) {
        uint64_t cur_vma = 0;
        const int MAX_VMA_WALK = 65536;  /* 安全上限，防止死循环 */
        int iter = 0;

        /* 读取 mm->mmap 链表头 */
        if (kf_copy_from_kernel_nofault(&cur_vma,
                (void *)((unsigned long)mm + g_mm_mmap_offset), 8) != 0)
            return NULL;

        /* 遍历链表查找 vm_end > addr 的第一个 VMA */
        while (cur_vma && iter++ < MAX_VMA_WALK) {
            uint64_t vm_end = 0;
            /* 验证指针合法性 */
            if (cur_vma < 0xFFFF000000000000ULL)
                return NULL;  /* 非法内核地址 */

            /* 读取 vm_end */
            if (kf_copy_from_kernel_nofault(&vm_end,
                    (void *)(cur_vma + g_vm_end_offset), 8) != 0)
                return NULL;

            /* 找到 vm_end > addr 的 VMA */
            if (vm_end > addr)
                return (void *)cur_vma;

            /* 移动到下一个 VMA */
            if (kf_copy_from_kernel_nofault(&cur_vma,
                    (void *)(cur_vma + g_vm_next_offset), 8) != 0)
                return NULL;
        }
        return NULL;
    }

    /* 路径 3: 引导期（偏移未探测，需 find_vma 完成首次定位）或
     * 6.1 无原生锁符号的兜底（find_vma + 调用方 RCU 锁） */
    if (kf_find_vma)
        return kf_find_vma(mm, (unsigned long)addr);

    /* 全部回退失败，功能禁用 */
    return NULL;
}

/* ===== 进程名（comm）偏移扫描兜底 =====
 * 若 `__get_task_comm` 与 `get_task_comm` **双双缺失**（老 4.x 未回填该符号的
 * 内核），进程名就没有任何来源 → 进程列表 / maps / 隐藏上报的 name 全空。
 * 兜底思路：**扫描**而不是要符号 —— init_task.comm 是已知常量串
 * （"swapper/0"，老内核 "swapper"），在 init_task 前 4KB 里找它即可定位
 * `task_struct.comm` 偏移，然后自实现等价读取函数**填进 kf_get_task_comm**，
 * 调用点零改动。纯 nofault 读，无符号依赖、无硬编码偏移。 */
#define KPM_COMM_SCAN_SIZE   4096
#define KPM_COMM_LEN         16      /* TASK_COMM_LEN */
static int g_comm_offset = -1;

static int kpm_probe_comm_offset(void)
{
    uint8_t buf[KPM_COMM_SCAN_SIZE];
    int i, j;

    if (g_comm_offset >= 0)
        return 0;
    if (!kf_init_task || !kf_copy_from_kernel_nofault)
        return -1;
    if (kf_copy_from_kernel_nofault(buf, (void *)kf_init_task,
                                    KPM_COMM_SCAN_SIZE) != 0)
        return -1;

    for (i = 0; i + KPM_COMM_LEN < KPM_COMM_SCAN_SIZE; i++) {
        if (!(buf[i] == 's' && buf[i + 1] == 'w' && buf[i + 2] == 'a' &&
              buf[i + 3] == 'p' && buf[i + 4] == 'p' && buf[i + 5] == 'e' &&
              buf[i + 6] == 'r'))
            continue;
        if (buf[i + 7] != '/' && buf[i + 7] != 0)
            continue;                      /* "swapper/0" 或 "swapper" */
        for (j = i + 7; j < i + KPM_COMM_LEN; j++)
            if (buf[j] == 0)
                break;
        if (j >= i + KPM_COMM_LEN)
            continue;                      /* 不是 16 字节 comm 窗口内的短串 */
        g_comm_offset = i;
        break;
    }

    if (g_comm_offset < 0) {
        kpm_log("LH_syms: comm offset NOT found in init_task (scan=%d)\n",
                KPM_COMM_SCAN_SIZE);
        return -1;
    }
    kpm_log("LH_syms: comm offset=%d (scanned init_task \"swapper\")\n",
            g_comm_offset);
    return 0;
}

/* 与 __get_task_comm(buf, buf_size, tsk) 语义等价的兜底实现 */
static char *kpm_get_task_comm_fb(char *buf, size_t buf_size,
                                  struct task_struct *tsk)
{
    int n, i;

    if (!buf || buf_size == 0)
        return buf;
    buf[0] = '\0';
    if (!tsk || kpm_probe_comm_offset() != 0)
        return buf;

    n = (int)(buf_size < KPM_COMM_LEN ? buf_size : KPM_COMM_LEN);
    for (i = 0; i < n - 1; i++) {
        uint8_t c = 0;
        if (kf_copy_from_kernel_nofault(&c,
                (void *)((unsigned long)tsk + g_comm_offset + i), 1) != 0 ||
            c == 0)
            break;
        buf[i] = (char)c;
    }
    buf[i] = '\0';
    return buf;
}

/* ===== 符号初始化 ===== */

/* 一次性符号解析初始化: 置于 .kpm.once, init 末尾由 kpm_armor_seal() 整段抹零。
 * 仅 LH_main.c init 调用, 无运行期其他调用者, 抹零不影响功能。 */
__attribute__((section(".kpm.once")))
int kpm_syms_init(void)
{
    /* kallsyms_lookup_name 由 KPM 框架通过 KP_EXPORT_SYMBOL 导出，模块加载时自动解析 */
    KPM_DBG("=== kpm_syms_init begin ===\n");

    /* ===== 内核版本检测（利用框架导出的 kver 全局变量） =====
     * kver 格式: VERSION(major, minor, patch) = (major << 16) | (minor << 8) | patch
     * 用于条件性符号解析和兼容性分支决策。
     * 框架导出点: KernelPatch_temp/kernel/base/start.c:66
     */
    {
        extern uint32_t kver;  /* 框架导出 */
        uint32_t major = (kver >> 16) & 0xFF;
        uint32_t minor = (kver >> 8) & 0xFF;
        uint32_t patch = kver & 0xFF;
        kpm_log("LH_syms: kernel version %d.%d.%d (kver=0x%x)\n",
                major, minor, patch, kver);
        KPM_DBG("  kernel version: %d.%d.%d\n", major, minor, patch);
    }

    /* 内存操作 - copy_to_user/copy_from_user 可能是内联函数，尝试下划线和 __arch_ 版本
     * GKI 6.1 MTK 内核导出的是 __arch_copy_to_user / __arch_copy_from_user
     */
    KPM_DBG("[1/9] resolving copy_from_user/copy_to_user...\n");
    kp_ptr_set(&kf_copy_from_user_slot, (void *)resolve_sym("copy_from_user"));
    if (!kf_copy_from_user) kp_ptr_set(&kf_copy_from_user_slot, (void *)resolve_sym("_copy_from_user"));
    if (!kf_copy_from_user) kp_ptr_set(&kf_copy_from_user_slot, (void *)resolve_sym("__arch_copy_from_user"));
    kp_ptr_set(&kf_copy_to_user_slot, (void *)resolve_sym("copy_to_user"));
    if (!kf_copy_to_user) kp_ptr_set(&kf_copy_to_user_slot, (void *)resolve_sym("_copy_to_user"));
    if (!kf_copy_to_user) kp_ptr_set(&kf_copy_to_user_slot, (void *)resolve_sym("__arch_copy_to_user"));
    kp_ptr_set(&kf_copy_from_kernel_nofault_slot, (void *)resolve_sym("copy_from_kernel_nofault"));
    /* 回退：Linux < 5.8 使用 probe_kernel_read（同名函数重命名）
     * 兼容 3.18 - 5.7 内核，避免符号解析失败导致 mem_rw/touch 禁用
     * 回退链（兼容性增强）：copy_from_kernel_nofault(5.8+) → probe_kernel_read(5.8 前)
     * → __probe_kernel_read(最旧内核，4.x/5.0-5.1 均有) */
    if (!kf_copy_from_kernel_nofault)
        kp_ptr_set(&kf_copy_from_kernel_nofault_slot, (void *)resolve_sym("probe_kernel_read"));
    if (!kf_copy_from_kernel_nofault)
        kp_ptr_set(&kf_copy_from_kernel_nofault_slot, (void *)resolve_sym("__probe_kernel_read"));
    /* copy_to_kernel_nofault: 安全写入内核地址（不触发 fault）
     * 回退链: copy_to_kernel_nofault(5.8+) → probe_kernel_write → __probe_kernel_write
     * 用于 write_via_wb 写入；copy_from_kernel_nofault 语义为读，勿混用 */
    kp_ptr_set(&kf_copy_to_kernel_nofault_slot, (void *)resolve_sym("copy_to_kernel_nofault"));
    if (!kf_copy_to_kernel_nofault)
        kp_ptr_set(&kf_copy_to_kernel_nofault_slot, (void *)resolve_sym("probe_kernel_write"));
    if (!kf_copy_to_kernel_nofault)
        kp_ptr_set(&kf_copy_to_kernel_nofault_slot, (void *)resolve_sym("__probe_kernel_write"));
    if (kf_copy_to_kernel_nofault)
        kpm_log("LH_syms: copy_to_kernel_nofault resolved = 0x%llx\n",
                (uint64_t)kf_copy_to_kernel_nofault);
    else
        kpm_log("LH_syms: copy_to_kernel_nofault not found, write_via_wb will use direct memcpy\n");
    KPM_DBG("  cfu=%llx ctu=%llx cfkn=%llx ctkn=%llx\n",
            (uint64_t)kf_copy_from_user, (uint64_t)kf_copy_to_user,
            (uint64_t)kf_copy_from_kernel_nofault, (uint64_t)kf_copy_to_kernel_nofault);

    /* 物理内存映射 */
    KPM_DBG("[2/9] resolving memremap/ioremap...\n");
    /* memremap: 物理地址映射（WB/WC/WT 模式）
     * 回退链：
     *   memremap: 5.1(t) / 6.1(t) 均存在
     *   ioremap_cache: 5.1(T) 存在，6.1 不存在
     *   ioremap_prot: 5.1 不存在，6.1(T) 存在
     *   ioremap: 全版本（最通用回退，兼容性增强）
     * 覆盖 4.1/4.9/5.1/6.1/6.6 全版本 */
    kp_ptr_set(&kf_memremap_slot, (void *)resolve_sym("memremap"));
    if (!kf_memremap) {
        kp_ptr_set(&kf_memremap_slot, (void *)resolve_sym("ioremap_cache"));
        if (kf_memremap)
            kpm_log("LH_syms: memremap not found, using ioremap_cache\n");
    }
    if (!kf_memremap) {
        kp_ptr_set(&kf_memremap_slot, (void *)resolve_sym("ioremap_prot"));
        if (kf_memremap)
            kpm_log("LH_syms: memremap not found, using ioremap_prot\n");
    }
    if (!kf_memremap) {
        kp_ptr_set(&kf_memremap_slot, (void *)resolve_sym("ioremap"));
        if (kf_memremap)
            kpm_log("LH_syms: memremap not found, using ioremap\n");
    }
    kp_ptr_set(&kf_memunmap_slot, (void *)resolve_sym("memunmap"));
    if (!kf_memunmap) {
        kp_ptr_set(&kf_memunmap_slot, (void *)resolve_sym("iounmap"));
        if (kf_memunmap)
            kpm_log("LH_syms: memunmap not found, using iounmap\n");
    }

    /* ioremap - 用于高位物理地址映射（memremap 无法映射的地址）
     * 兼容性增强：ioremap_prot(6.x) 缺失时回退 ioremap（全版本导出） */
    kp_ptr_set(&kf_ioremap_prot_slot, (void *)resolve_sym("ioremap_prot"));
    if (!kf_ioremap_prot)
        kp_ptr_set(&kf_ioremap_prot_slot, (void *)resolve_sym("ioremap"));
    kp_ptr_set(&kf_iounmap_slot, (void *)resolve_sym("iounmap"));
    KPM_DBG("  memremap=%llx ioremap_prot=%llx\n",
            (uint64_t)kf_memremap, (uint64_t)kf_ioremap_prot);

    /* ===== 框架已声明的符号（通过 kfunc_def 宏） =====
     * 这些符号声明在框架头文件中（pid.h, sched.h, vmalloc.h, slab.h, kernel.h），
     * 我们直接用 resolve_sym 赋值即可，无需 extern 声明。
     */
    /* find_get_pid: pid → struct pid*（带引用计数）
     * 回退 find_vpid: vpid → struct pid*（namespace 感知版本，Linux 2.6.26+）
     * 语义差异：find_get_pid 接受全局 PID，find_vpid 接受当前 namespace PID
     * 对于 Android 单 namespace 场景两者等价 */
    kf_find_get_pid = (void *)resolve_sym("find_get_pid");
    if (!kf_find_get_pid) {
        kf_find_get_pid = (void *)resolve_sym("find_vpid");
        if (kf_find_get_pid)
            kpm_log("LH_syms: find_get_pid not found, using find_vpid\n");
    }

    /* get_pid_task: struct pid* → struct task_struct*（带引用计数）
     * 回退 pid_task: 同功能，部分内核版本仅导出此名 */
    kf_get_pid_task = (void *)resolve_sym("get_pid_task");
    if (!kf_get_pid_task) {
        kf_get_pid_task = (void *)resolve_sym("pid_task");
        if (kf_get_pid_task)
            kpm_log("LH_syms: get_pid_task not found, using pid_task\n");
    }

    /* find_task_by_vpid：通过 PID 命名空间查找任务
     * Linux 4.x+ 全版本存在，无符号级回退。
     * 若不可用，依赖 find_get_pid + get_pid_task 组合作为等价替代（kpm_proc.c 已实现）。 */
    kf_find_task_by_vpid = (void *)resolve_sym("find_task_by_vpid");
    if (!kf_find_task_by_vpid)
        kpm_log("LH_syms: WARNING find_task_by_vpid not found "
                "(will use find_get_pid+get_pid_task fallback)\n");

    /* get_task_mm: 获取进程 mm_struct（带引用计数）
     * 注意：mm_access 不可作为回退——签名不同(mm_access 需要 mode 参数)，
     * 通过 kf_get_task_mm(task) 调用时第二个参数为垃圾值 */
    kf_get_task_mm = (void *)resolve_sym("get_task_mm");

    /* mmput: 释放 mm_struct 引用计数
     * 回退 _mmput: 部分内核仅导出下划线版本 */
    kf_mmput = (void *)resolve_sym("mmput");
    if (!kf_mmput) {
        kf_mmput = (void *)resolve_sym("_mmput");
        if (kf_mmput)
            kpm_log("LH_syms: mmput not found, using _mmput\n");
    }
    KPM_DBG("[3/9] resolving kmalloc/vmap/vsnprintf...\n");
    kf_kmalloc = (void *)resolve_sym("__kmalloc");
    if (!kf_kmalloc) kf_kmalloc = (void *)resolve_sym("kmalloc");
    kf_kfree = (void *)resolve_sym("kfree");
    kf_vmap = (void *)resolve_sym("vmap");
    kf_vunmap = (void *)resolve_sym("vunmap");
    kf_vsnprintf = (void *)resolve_sym("vsnprintf");
    KPM_DBG("  vmap=%llx vunmap=%llx vsnprintf=%llx (vmap is CRITICAL for mem_rw DMA path)\n",
            (uint64_t)kf_vmap, (uint64_t)kf_vunmap, (uint64_t)kf_vsnprintf);

    /* ===== 触摸子系统符号 =====
     * input_handle_event: hook 目标
     *   6.1+ : EXPORT_SYMBOL，kallsyms_lookup_name 可解析
     *   <6.1 : local(t)，kallsyms_lookup_name 仍可解析（非 exported 但在 kallsyms 表）
     *   若解析失败，触摸 hook 功能不可用，但不影响其他模块
     *
     * input_event: 虚拟触摸注入入口
     *   全版本 EXPORT_SYMBOL，自动获取 dev->event_lock
     *   用于 touch_create/move/up 在 process context 中注入事件
     *   签名: void input_event(struct input_dev *, unsigned int, unsigned int, int) */
    kf_input_handle_event = (void *)resolve_sym("input_handle_event");
    kf_input_event = (void *)resolve_sym("input_event");
    /* kv_input_dev_list 存储 &input_dev_list（变量地址），不读取值
     * 原因：read_kernel_var 依赖 copy_from_kernel_nofault，若该函数不可靠
     * 或地址未映射会触发 panic。因此存储变量地址，由 kpm_touch.c
     * 通过 safe_list_next 安全读取 list_head.next 字段。
     * 兼容性：input_dev_list 在所有 Linux 内核均存在（drivers/input/input.c）。 */
    kv_input_dev_list = resolve_sym("input_dev_list");

    /* ===== vmalloc / scan 符号 ===== */
    kf_vmalloc = (void *)resolve_sym("vmalloc");
    if (!kf_vmalloc) kf_vmalloc = (void *)resolve_sym("__vmalloc");
    kf_vfree = (void *)resolve_sym("vfree");
    /* vmalloc_to_page（EXPORT_SYMBOL，全版本）。
     * 缺失非致命：kpm_is_safe_kern_addr 在 vmalloc 区校验时降级为拒绝
     * （触摸设备名匹配可能降级，但绝不触发 DEVAPC 崩溃）。 */
    kf_vmalloc_to_page = (void *)resolve_sym("vmalloc_to_page");
    kf_simple_strtoull = (void *)resolve_sym("simple_strtoull");
    /* 兼容性增强：snprintf 缺失（极少数内核未导出）时回退 scnprintf
     * （lib/vsprintf.c 导出，签名一致，仅返回值语义略有差异：scnprintf
     * 返回实际写入长度（不含 '\0'），本模块所有调用均按此使用） */
    kf_snprintf = (void *)resolve_sym("snprintf");
    if (!kf_snprintf)
        kf_snprintf = (void *)resolve_sym("scnprintf");

    /* printk 兼容：6.1+ 重命名为 _printk */
    kf_printk = (void *)resolve_sym("printk");
    if (!kf_printk) {
        kf_printk = (void *)resolve_sym("_printk");
        if (kf_printk)
            kpm_log("LH_syms: printk not found, using _printk\n");
    }

    /* ===== 补充 kfunc_def 符号（框架未导出，需本地定义） ===== */
    KPM_DBG("[4/9] resolving filp_open/kernel_write (CRITICAL for kpm_debug_mark)...\n");
    kf_filp_open = (void *)resolve_sym("filp_open");
    kf_filp_close = (void *)resolve_sym("filp_close");
    /* 注意：kf_get_pid_task 和 kf_find_get_pid 已在上方带回退链解析，此处不重复 */
    /* kernel_read/kernel_write: 文件读写（kpm_debug_mark 使用）
     * 回退 __kernel_read/__kernel_write: Linux 5.10+ 部分内核导出下划线版本 */
    kf_kernel_read = (void *)resolve_sym("kernel_read");
    if (!kf_kernel_read) {
        kf_kernel_read = (void *)resolve_sym("__kernel_read");
    }
    kf_kernel_write = (void *)resolve_sym("kernel_write");
    if (!kf_kernel_write) {
        kf_kernel_write = (void *)resolve_sym("__kernel_write");
        if (kf_kernel_write)
            kpm_log("LH_syms: kernel_write not found, using __kernel_write\n");
    }
    kf_kernel_read_iter = (void *)resolve_sym("kernel_read_iter");
    KPM_DBG("  filp_open=%llx kernel_write=%llx filp_close=%llx\n"
            "  (if filp_open/kernel_write=0, kpm_debug.log will NOT be written!)\n",
            (uint64_t)kf_filp_open, (uint64_t)kf_kernel_write,
            (uint64_t)kf_filp_close);

    /* ===== uprobe（libsensorservice hook） =====
     * 上游 ABI 分界：
     *   ≤6.11 : int  uprobe_register(inode, offset, uc)                    3 参
     *           void uprobe_unregister(inode, offset, uc)                  3 参
     *           struct uprobe_consumer { handler, ret_handler,
     *                                    filter(self, ctx, mm), next }
     *   ≥6.12 : struct uprobe *uprobe_register(inode, offset, ref_ctr, uc)  4 参
     *           void uprobe_unregister_nosync(uprobe, uc) + uprobe_unregister_sync()
     *           —— uprobe_register_refctr 与 uprobe_unregister **两个符号都被删除**；
     *           struct uprobe_consumer 布局也变（filter 少 ctx 参数、next→cons_node）
     * 6.12+ 按 3 参签名调用的后果：uc 被当成 ref_ctr_offset（非 0 → 走 ref-counter
     * 分支），真正的 uc 落在第 4 个参数寄存器，内核按 struct uprobe_consumer*
     * 解引用该残留值 → 大概率 oops。
     * 对策：按 kver 显式置 0（双保险——6.12+ 本来也解析不到 uprobe_unregister），
     * gyro 自动退回 sys_enter tracepoint，功能不归零。 */
    kf_uprobe_register = (void *)resolve_sym("uprobe_register");
    kf_uprobe_unregister = (void *)resolve_sym("uprobe_unregister");
    {
        extern uint32_t kver;
        if (kver >= 0x00060C00u) {
            kpm_log("LH_syms: kver=%u.%u.%u -> uprobe API changed at 6.12 "
                    "(4-arg register, uprobe_unregister removed); uprobe path "
                    "disabled, gyro falls back to sys_enter tracepoint\n",
                    (kver >> 16) & 0xFFu, (kver >> 8) & 0xFFu, kver & 0xFFu);
            kf_uprobe_register = 0;
            kf_uprobe_unregister = 0;
        }
    }
    kf_kern_path = (void *)resolve_sym("kern_path");
    kf_igrab = (void *)resolve_sym("igrab");
    kf_iput = (void *)resolve_sym("iput");
    kf_path_put = (void *)resolve_sym("path_put");
    if (!kf_uprobe_register || !kf_uprobe_unregister || !kf_kern_path ||
        !kf_igrab || !kf_iput || !kf_path_put)
        kpm_log("LH_syms: uprobe syms missing (uprobe_reg=%llx unreg=%llx "
                "kern_path=%llx igrab=%llx iput=%llx path_put=%llx) - gyro "
                "uprobe will be disabled\n",
                (uint64_t)kf_uprobe_register, (uint64_t)kf_uprobe_unregister,
                (uint64_t)kf_kern_path, (uint64_t)kf_igrab, (uint64_t)kf_iput,
                (uint64_t)kf_path_put);

    /* ===== sys_enter tracepoint =====
     * kallsyms 解析 __tracepoint_sys_enter +
     * tracepoint_probe_register 注册 sys_enter probe，拦截 read/pread64 读
     * 传感器事件数组（sensors_event_t 104B）——uprobe 失效时的
     * 兼容性主路径。全版本 EXPORT，kallsyms 可解析。 */
    kf_tp_sys_enter = (void *)resolve_sym("__tracepoint_sys_enter");
    kf_tp_sys_exit = (void *)resolve_sym("__tracepoint_sys_exit");
    kf_tracepoint_probe_register =
        (void *)resolve_sym("tracepoint_probe_register");
    kf_tracepoint_probe_unregister =
        (void *)resolve_sym("tracepoint_probe_unregister");
    kf_tracepoint_synchronize_unregister =
        (void *)resolve_sym("tracepoint_synchronize_unregister");
    if (!kf_tp_sys_enter || !kf_tracepoint_probe_register ||
        !kf_tracepoint_probe_unregister || !kf_tracepoint_synchronize_unregister)
        kpm_log("LH_syms: tracepoint syms missing (tp_sys_enter=%llx "
                "probe_reg=%llx probe_unreg=%llx sync_unreg=%llx) - gyro "
                "tracepoint will be disabled\n",
                (uint64_t)kf_tp_sys_enter,
                (uint64_t)kf_tracepoint_probe_register,
                (uint64_t)kf_tracepoint_probe_unregister,
                (uint64_t)kf_tracepoint_synchronize_unregister);

    /* ===== sched_process_fork tracepoint =====
     * fork 时对新 task 置位 TIF_SYSCALL_TRACEPOINT，覆盖模块加载后启动的
     * 进程（kpm_gyro_tp_set_tif 只覆盖加载时已存在的任务，晚启动进程若
     * TIF 继承在该内核不可靠则拦截失效）。
     * __tracepoint_sched_process_fork 全版本导出，kallsyms 可解析。 */
    kf_tp_sched_fork =
        (void *)resolve_sym("__tracepoint_sched_process_fork");
    if (!kf_tp_sched_fork)
        kpm_log("LH_syms: sched_fork tp missing - late-start task "
                "coverage disabled (G-B)\n");

    /* ===== 凭证切换（SELinux Enforcing 下读块设备用） ===== */
    kf_override_creds = (void *)resolve_sym("override_creds");
    kf_revert_creds = (void *)resolve_sym("revert_creds");
    kf_init_cred = (const void *)resolve_sym("init_cred");
    if (!kf_override_creds || !kf_revert_creds || !kf_init_cred)
        kpm_log("LH_syms: creds syms missing (override=%llx revert=%llx "
                "init_cred=%llx) - READ_FILE on SELinux-restricted dev may fail\n",
                (uint64_t)kf_override_creds, (uint64_t)kf_revert_creds,
                (uint64_t)kf_init_cred);

    /* ===== PID 引用管理 ===== */
    kf_put_pid = (void *)resolve_sym("put_pid");

    /* ===== 硬件断点 (perf_event) ===== */
    kf_register_user_hw_bp = (void *)resolve_sym("register_user_hw_breakpoint");
    kf_unregister_hw_bp = (void *)resolve_sym("unregister_hw_breakpoint");
    kf_perf_event_enable = (void *)resolve_sym("perf_event_enable");
    kf_perf_event_disable = (void *)resolve_sym("perf_event_disable");
    /* 宽/内核断点 + fault + 时间 + lockdown */
    kf_register_wide_hw_bp = (void *)resolve_sym("register_wide_hw_breakpoint");
    kf_unregister_wide_hw_bp = (void *)resolve_sym("unregister_wide_hw_breakpoint");
    kf_perf_event_create_kernel_counter =
        (void *)resolve_sym("perf_event_create_kernel_counter");
    kf_do_mem_abort = (void *)resolve_sym("do_mem_abort");
    /* ktime 多级回退（4.19 无 ktime_get_ns 符号，但 ktime_get /
     * ktime_get_mono_fast_ns 存在；ABI 均为返回 64 位纳秒）：
     *   ktime_get_ns → ktime_get_mono_fast_ns → ktime_get → sched_clock */
    kf_ktime_get_ns = (void *)resolve_sym("ktime_get_ns");
    if (!kf_ktime_get_ns)
        kf_ktime_get_ns =
            (void *)resolve_sym("ktime_get_mono_fast_ns");
    if (!kf_ktime_get_ns)
        kf_ktime_get_ns = (void *)resolve_sym("ktime_get");
    if (!kf_ktime_get_ns)
        kf_ktime_get_ns = (void *)resolve_sym("sched_clock");
    kf_jiffies = (unsigned long *)resolve_sym("jiffies");
    kf_kernel_locked_down = (int *)resolve_sym("kernel_locked_down");
    kf_security_locked_down = (void *)resolve_sym("security_locked_down");
    kf_patch_text = (void *)resolve_sym("patch_text");
    kf_aarch64_insn_patch_text =
        (kf_insn_patch_text_t)resolve_sym("aarch64_insn_patch_text");
    kf_set_memory_rw = (void *)resolve_sym("set_memory_rw");
    kf_flush_icache_range = (void *)resolve_sym("flush_icache_range");
    kpm_log("LH_syms: v1.6 dbg syms wide_bp=%d kern_bp=%d fault=%d ktime=%d "
            "lockdown=%d patch=%d\n",
            !!kf_register_wide_hw_bp, !!kf_perf_event_create_kernel_counter,
            !!kf_do_mem_abort, !!kf_ktime_get_ns,
            !!kf_kernel_locked_down || !!kf_security_locked_down,
            !!kf_patch_text);
    if (!kf_perf_event_enable)
        kpm_log("LH_syms: perf_event_enable not found - HW breakpoints cannot "
                "be armed (register alone leaves event inactive) and will be "
                "reported unavailable\n");

    /* ===== 进程名称 =====
     * __get_task_comm：Linux 5.x+ 导出（get_task_comm 是宏，调用 __get_task_comm）
     * get_task_comm：Linux 4.x 直接导出（无下划线版本）
     * 兜底：两者都缺时**扫描** init_task 的 "swapper" 定位
     *   task_struct.comm 偏移，用本模块自实现的等价函数顶上 ——
     *   进程名功能不再依赖该符号是否存在（老 4.x/厂商 static 化内核同样可用）。 */
    kf_get_task_comm = (void *)resolve_sym("__get_task_comm");
    if (!kf_get_task_comm)
        kf_get_task_comm = (void *)resolve_sym("get_task_comm");
    if (!kf_get_task_comm) {
        kf_get_task_comm = kpm_get_task_comm_fb;
        kpm_log("LH_syms: __get_task_comm/get_task_comm missing -> "
                "using scanned-comm fallback (offset probed lazily)\n");
    }

    /* get_cmdline：直接读取完整 cmdline（内部处理 arg_start/arg_end + access_process_vm）
     * Linux 4.x+ 全版本存在（kernel/sys.c），但部分厂商内核（Samsung Knox）可能 static 化。
     * 无符号级回退（无替代品），但 kpm_proc_list_kernel 会用 kpm_mem_read_kernel
     * 纯内存读取 arg_start~arg_end 作为主路径，get_cmdline 仅作兼容性回退。 */
    kf_get_cmdline = (void *)resolve_sym("get_cmdline");
    if (!kf_get_cmdline)
        kpm_log("LH_syms: WARNING get_cmdline not found "
                "(will use kpm_mem_read_kernel pure-memory path)\n");

    /* ===== task_struct 引用管理 ===== */
    /* 必须解析 put_task_struct（inline 副本），它会先 refcount_dec_and_test(&t->usage)
     * 递减引用计数，仅在计数降为 0 时才调用 __put_task_struct 释放。
     *
     * put_task_struct 在内核中是 static inline，多个编译单元有副本（kallsyms 中
     * 标记为 t），kallsyms_lookup_name 返回第一个副本，逻辑一致。
     */
    kf_put_task_struct = (void *)resolve_sym("put_task_struct");
    if (!kf_put_task_struct) {
        /* put_task_struct 是 static inline，部分内核未导出。
         * 解析 __put_task_struct（4.19 有导出），手动实现等价的引用计数递减。
         * 注：usage 偏移标定**不在这里做** —— 它要读 init_task 作锚点，而
         * kf_init_task 要到本函数下方才解析（见 "usage 偏移标定" 注释）。 */
        kf___put_task_struct = (void *)resolve_sym("__put_task_struct");
        /* free_task: Linux 6.1 中负责 task_struct 释放的底层函数
         * 注意：该路径因 UAF 风险已禁用，仅解析用于状态上报 */
        kf_free_task = (void *)resolve_sym("free_task");
        if (!kf___put_task_struct) {
            if (kf_free_task) {
                kpm_log("LH_syms: put_task_struct and __put_task_struct missing, "
                        "free_task fallback DISABLED (UAF risk) -> refs will leak\n");
            } else {
                kpm_log("LH_syms: WARNING put_task_struct, __put_task_struct, and "
                        "free_task ALL missing, task_struct refs will leak\n");
            }
        }
    }

    /* ===== 同步断点停靠符号（缺失仅同步模式禁用，非致命） =====
     * 注意：不用 schedule_timeout 回退——它不设置任务状态，缺
     * schedule_timeout_interruptible 时睡眠停靠无安全实现，直接禁用同步
     * 模式（兼容性退回：async 断点不受影响）。 */
    kf_task_work_add = (void *)resolve_sym("task_work_add");
    kf_schedule_timeout_interruptible =
        (void *)resolve_sym("schedule_timeout_interruptible");
    kf_msecs_to_jiffies = (void *)resolve_sym("msecs_to_jiffies");
    if (!kf_msecs_to_jiffies) {
        /* 5.4+ msecs_to_jiffies 变为 static inline，导出符号为
         * __msecs_to_jiffies */
        kf_msecs_to_jiffies = (void *)resolve_sym("__msecs_to_jiffies");
    }
    kf_wake_up_process = (void *)resolve_sym("wake_up_process");
    kf_get_task_struct = (void *)resolve_sym("get_task_struct");
    kf_do_send_sig_info = (void *)resolve_sym("do_send_sig_info");
    /* 资源控制（set_cpus_allowed_ptr 框架亦导出，kallsyms 兜底） */
    kf_sched_setattr_nocheck = (void *)resolve_sym("sched_setattr_nocheck");
    kf_sysctl_sched_uclamp_util_max =
        (void *)resolve_sym("sysctl_sched_uclamp_util_max");
    kf_set_cpus_allowed_ptr = (void *)resolve_sym("set_cpus_allowed_ptr");
    /* 软件单步舞步（缺失 → 步进语义禁用，回退 PC+4） */
    kf_register_user_step_hook = (void *)resolve_sym("register_user_step_hook");
    kf_unregister_user_step_hook =
        (void *)resolve_sym("unregister_user_step_hook");
    /* W^X shadow：BRK 钩子 + exit_mmap（kallsyms 解析，缺失时
     * BP 降级；PATCH 不依赖 BRK） */
    kf_register_user_break_hook =
        (void *)resolve_sym("register_user_break_hook");
    kf_unregister_user_break_hook =
        (void *)resolve_sym("unregister_user_break_hook");
    kf_exit_mmap = (void *)resolve_sym("exit_mmap");
    kf_dup_mm = (void *)resolve_sym("dup_mm");
    /* 4.19 无 dup_mm 符号（内联/静态）；copy_process 为 local 符号可解析，
     * fork 保护退而 hook copy_process（current 仍为父进程）。 */
    if (!kf_dup_mm)
        kf_dup_mm = (void *)resolve_sym("copy_process");
    kf_do_debug_exception =
        (void *)resolve_sym("do_debug_exception");
    kf_register_undef_hook = (void *)resolve_sym("register_undef_hook");
    kf_unregister_undef_hook = (void *)resolve_sym("unregister_undef_hook");
    kf_linux_banner = (const char *)resolve_sym("linux_banner");
    kf_rcu_read_lock_any_held =
        (void *)resolve_sym("rcu_read_lock_any_held");

    /* ===== tasklist 遍历符号 ===== */
    /* task_struct_offset 是 KernelPatch 框架通过 KP_EXPORT_SYMBOL 导出的符号，
     * kallsyms_lookup_name 无法查找 KP 导出符号（不在内核 kallsyms 表中）。
     * 因此直接使用框架头文件中声明的 extern 变量 task_struct_offset，
     * 模块加载时由 KPM 框架自动解析重定位。
     * tasks_offset 应有合理范围（> 100 且 < 10000），超出则视为无效。 */
    {
        /* 直接使用框架导出的 extern 变量（ sched.h 中声明） */
        kf_task_struct_offset = task_struct_offset;
        if (kf_task_struct_offset.tasks_offset > 0) {
            kpm_log("LH_syms: task_struct_offset.tasks=%d tgid=%d pid=%d mm=%d comm=%d\n",
                kf_task_struct_offset.tasks_offset,
                kf_task_struct_offset.tgid_offset,
                kf_task_struct_offset.pid_offset,
                kf_task_struct_offset.mm_offset,
                kf_task_struct_offset.comm_offset);
            /* 合理性检查: tasks_offset 应在合理范围内，否则清零 */
            if (kf_task_struct_offset.tasks_offset < 100 ||
                kf_task_struct_offset.tasks_offset > 10000) {
                kpm_log("LH_syms: WARNING task_struct_offset.tasks=%d out of range, "
                        "zeroing struct\n", kf_task_struct_offset.tasks_offset);
                lib_memset(&kf_task_struct_offset, 0,
                           sizeof(kf_task_struct_offset));
            } else {
                /* 从框架导出的 task_struct_offset 填充全局偏移变量 */
                if (g_tasks_offset == 0)
                    g_tasks_offset = kf_task_struct_offset.tasks_offset;
                if (g_tgid_offset == 0)
                    g_tgid_offset = kf_task_struct_offset.tgid_offset;
                if (g_pid_offset == 0 && kf_task_struct_offset.pid_offset > 0)
                    g_pid_offset = kf_task_struct_offset.pid_offset;
                if (g_mm_offset == 0 && kf_task_struct_offset.mm_offset > 0)
                    g_mm_offset = kf_task_struct_offset.mm_offset;
                kpm_log("LH_syms: offsets from framework: tasks=%d tgid=%d pid=%d mm=%d\n",
                    g_tasks_offset, g_tgid_offset, g_pid_offset, g_mm_offset);
            }
        } else {
            kpm_log("LH_syms: WARNING task_struct_offset not available from framework, "
                    "keeping zero-initialized\n");
        }
    }
    /* init_task 是内核标准导出符号，地址即 struct task_struct 的地址 */
    kf_init_task = (struct task_struct *)resolve_sym("init_task");
    if (!kf_init_task)
        kpm_log("LH_syms: WARNING init_task not found\n");

    /* ===== usage 偏移标定（必须在 init_task 就绪之后） =====
     * 标定要读 init_task 作锚点，故置于 init_task 解析之后，且只在
     * "无原生符号 + 有 __put_task_struct"时执行。 */
    if (!kf_put_task_struct && kf___put_task_struct) {
        probe_usage_offset();
        if (g_usage_offset > 0) {
            kpm_log("LH_syms: put_task_struct missing, using manual impl "
                    "(usage_offset=%d, __put_task_struct=0x%llx)\n",
                    g_usage_offset, (uint64_t)kf___put_task_struct);
        } else {
            kpm_log("LH_syms: WARNING put_task_struct missing and usage_offset "
                    "calib state=%d -> task_struct refs will leak\n",
                    g_usage_calib_state);
        }
    }

    /* ===== mm 读锁（双路径适配） =====
     * 路径 A（5.12+）：mmap_read_lock/mmap_read_unlock 为 mm/mmap_lock.c
     *   真实符号（5.8-5.11 为头文件 static inline，kallsyms 无符号）。
     *   双符号齐备时置 g_mmap_read_lock_native=1，VMA 遍历
     *   （kpm_mm_read_lock 包装）持原生锁走 find_vma 主路径。
     * 路径 B（4.14/5.4/5.10 等）：无原生锁。down_read/up_read 回退
     *   签名不兼容（需 &mm->mmap_sem 偏移，无可靠探测，误判即 panic），
     *   仅解析记录供 state_info 位图，严禁调用。VMA 遍历持 RCU 读锁
     *   走 find_vma 主路径。
     *
     * 页表遍历（kpm_mem_rw.c walk_page_table）不受影响，仍走其自有
     * RCU 适配层（kpm_mmap_read_lock/unlock in LH_mem_rw.c）。 */
    kf_mmap_read_lock = (void *)resolve_sym("mmap_read_lock");
    kf_mmap_read_unlock = (void *)resolve_sym("mmap_read_unlock");
    if (kf_mmap_read_lock && kf_mmap_read_unlock) {
        g_mmap_read_lock_native = 1;
        kpm_log("LH_syms: native mmap_read_lock available "
                "(VMA traversal lock-protected)\n");
    } else {
        g_mmap_read_lock_native = 0;
        /* down_read/up_read 回退（签名不兼容，仅解析记录，禁止调用） */
        kf_mmap_read_lock = (void *)resolve_sym("down_read");
        kf_mmap_read_unlock = (void *)resolve_sym("up_read");
        kpm_log("LH_syms: native mmap_read_lock unavailable, VMA traversal "
                "via RCU + find_vma (legacy semantics, verified on 4.19)\n");
    }

    /* ===== VMA 遍历符号（高兼容性方案） =====
     * find_vma: Linux 5.1+ 全版本 EXPORT_SYMBOL，100% 可解析
     *   - 5.1+ 全版本定义在 mm/mmap.c，EXPORT_SYMBOL(find_vma)
     *   - v6.12 拆分出 mm/vma.c 但 find_vma 仍在 mm/mmap.c
     *   - 通过 kallsyms_lookup_name 解析，不依赖 EXPORT_SYMBOL 链接
     *
     * 回退路径（vm_next 链表遍历）不依赖任何符号，仅用 copy_from_kernel_nofault
     * 读取 mm->mmap 和 vm_next 指针，5.x-6.0 全版本兼容。
     *
     * 注意: find_vma_intersection 是 static inline 函数（include/linux/mm.h），
     *       编译后无独立符号，kallsyms_lookup_name 永远返回 0。
     *
     * 隐蔽性: A 级
     *   - find_vma 调用不产生任何可观测痕迹
     *   - 回退路径仅 copy_from_kernel_nofault 读取，不触发任何 hook */
    kf_find_vma = (void *)resolve_sym("find_vma");
    if (!kf_find_vma) {
        /* 极低概率：find_vma 在 5.1+ 全版本 EXPORT，理论上不会失败
         * 若失败则依赖 vm_next 链表遍历回退（需偏移探测成功） */
        kpm_log("LH_syms: WARNING find_vma not found, "
                "will try vm_next list traversal fallback\n");
    }

    /* ===== RCU 读锁（替代 mmap_read_lock） =====
     * 全版本导出，与 copy_from_kernel_nofault 配合实现零 panic 兼容
     * 适配层 kpm_mmap_read_lock/unlock 统一调用此符号 */
    /* __rcu_read_lock: Linux 4.20+ 导出符号，RCU 读锁的内核实现。
     * rcu_read_lock（无下划线）在所有版本均不存在，无回退。 */
    kf_rcu_read_lock = (void *)resolve_sym("__rcu_read_lock");
    kf_rcu_read_unlock = (void *)resolve_sym("__rcu_read_unlock");
    if (!kf_rcu_read_lock || !kf_rcu_read_unlock)
        kpm_log("LH_syms: WARNING __rcu_read_lock/unlock not found (mem_rw disabled)\n");

    /* 卸载排空在途 hook 回调。
     * synchronize_rcu 全版本导出（4.x~6.x）；synchronize_rcu_expedited 兜底
     * （PREEMPT_RCU/RT 下可能未导出，故顺序探测）。进程上下文（KPM_EXIT）
     * 调用，可睡眠等待宽限期，安全。 */
    kf_synchronize_rcu = (void *)resolve_sym("synchronize_rcu");
    if (!kf_synchronize_rcu)
        kf_synchronize_rcu = (void *)resolve_sym("synchronize_rcu_expedited");
    if (!kf_synchronize_rcu)
        kpm_log("LH_syms: WARNING synchronize_rcu not found (hook unload race unprotected)\n");

    /* 探测 RCU 读锁持有状态。
     * KPM 框架 unload_module 在 rcu_read_lock 临界区内调用模块 exit，
     * 而 uprobe_unregister 内部 synchronize_rcu 等待读临界区退出 → 自死锁。
     * 探测失败时 kpm_gyro_exit 跳过该防护。 */
    kf_rcu_read_lock_held = (void *)resolve_sym("rcu_read_lock_held");
    if (!kf_rcu_read_lock_held)
        kpm_log("LH_syms: WARNING rcu_read_lock_held not found (gyro unload deadlock guard inactive)\n");

    /* ===== PID/TGID 获取函数 ===== */
    kf___task_pid_nr_ns = (void *)resolve_sym("__task_pid_nr_ns");
    if (!kf___task_pid_nr_ns)
        kpm_log("LH_syms: WARNING __task_pid_nr_ns not found\n");

    /* 注：kf_find_task_by_vpid 已在上方解析（resolve_sym("find_task_by_vpid")） */

    /* ===== task_struct 偏移运行时探测 =====
     * probe_task_struct_offsets() 仅通过 tasks 链表自洽性验证偏移，
     * 绝不调用 __task_pid_nr_ns 于未验证的地址（该调用会直接解引用
     * task_struct 的 pids[] 成员，地址误判即访问垃圾指针触发 Oops）。
     * 所有内存读取用 copy_from_kernel_nofault，不会 panic。
     * 调用方需检查 g_tasks_offset > 0 才使用 tasklist 遍历路径。
     */
    probe_task_struct_offsets();

    /* 通用偏移探测：当框架 task_struct_offset 未导出时，独立探测 mm/pid/tgid/usage
     * 通过 find_get_pid(1)+get_pid_task+get_task_mm 获取已知进程，扫描特征值。
     * 不依赖框架导出，兼容所有 Linux 5.1+ 内核。 */
    if (g_mm_offset == 0 || g_pid_offset == 0 || g_tgid_offset == 0) {
        probe_task_struct_offsets_full();
        kpm_log("LH_syms: full probe result: mm=%d pid=%d tgid=%d usage=%d\n",
                g_mm_offset, g_pid_offset, g_tgid_offset, g_usage_offset);
    }

    /* ===== pgtable.h 框架全局变量 =====
     * 这些变量由 KernelPatch 框架在启动时通过 kallsyms 解析并写入自身 BSS。
     * kpm 模块需通过 kallsyms_lookup_name 找到框架变量地址，再用
     * copy_from_kernel_nofault 读取其值。
     *
     * vmemmap / memstart_addr / page_shift / va_bits 是 vmap DMA 路径的关键依赖：
     *   - vmemmap: struct page 数组基地址，pfn_to_page 依赖此值
     *   - memstart_addr: 物理内存起始地址，pa->va 线性映射依赖此值
     *   - page_shift/va_bits: 页表遍历参数
     * 若这些变量解析失败（返回 0），vmap 会因 struct page 指针错误而触发
     * mm/vmalloc.c:493 的 __vmap_pages_range_noflush WARNING。
     */
    KPM_DBG("[5/9] resolving pgtable.h framework vars (CRITICAL for vmap)...\n");
    kernel_va = read_kernel_var("kernel_va", 0);
    kernel_pa = read_kernel_var("kernel_pa", 0);
    kernel_size = read_kernel_var("kernel_size", 0);
    page_shift = read_kernel_var("page_shift", 0);
    va_bits = read_kernel_var("va_bits", 0);
    page_level = read_kernel_var("page_level", 0);
    pgd_va = read_kernel_var("pgd_va", 0);

    /* ===== KP 框架变量未注入时的推导 =====
     * 框架未注入 kernel_va/kernel_pa/page_shift/va_bits/page_level/pgd_va
     * 等 KP_EXPORT_SYMBOL 变量时，read_kernel_var 全部回退 0，mem_rw 线性
     * 映射/页表遍历参数缺失。回退：从内核自身符号（CONFIG_KALLSYMS_ALL）
     * + TCR_EL1 推导，不依赖框架：
     *   - va_bits/page_shift/page_level: TCR_EL1 探测（T1SZ/TG1）
     *   - kernel_va: 内核镜像基址 _text / _stext（kallsyms 可查）
     *   - kernel_pa: kernel_va - kimage_voffset（kimage_voffset 内核导出）
     *   - pgd_va: 内核页表基址 swapper_pg_dir（若存在）
     * 仅在框架值缺失（==0）时启用，已注入的框架值优先。 */
    if (kernel_va == 0 || va_bits == 0 || page_shift == 0) {
        uint64_t tcr;
        int t1sz, tg1, vb, ps;

        asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
        t1sz = (int)((tcr >> 16) & 0x3F);
        vb = 64 - t1sz;
        tg1 = (int)((tcr >> 30) & 0x3);
        /* TG1 编码：00=4KB, 01=16KB, 10=64KB。TG1=2(64KB) 在多厂商 4.19
         * 平台为 EL2 hypervisor 干扰误判，实际 4KB —— 与 LH_mem_rw.c 的
         * 强制回退一致。 */
        ps = 12;
        if (tg1 == 1) ps = 14;        /* 16KB */
        else if (tg1 == 2) ps = 12;   /* 64KB 误判保守回退 4KB */

        if (va_bits == 0)      va_bits = vb;
        if (page_shift == 0)   page_shift = ps;
        if (page_level == 0 && page_shift > 3)
            page_level = (va_bits - 4) / (page_shift - 3);

        if (kernel_va == 0) {
            unsigned long text = resolve_sym("_text");
            if (!text) text = resolve_sym("_stext");
            if (text) {
                kernel_va = text;
                kpm_log("LH_syms: kernel_va derived from _text = 0x%llx\n",
                        (unsigned long long)kernel_va);
            }
        }
        if (kernel_pa == 0 && kernel_va != 0) {
            uint64_t voff = read_kernel_var("kimage_voffset", 0);
            if (voff && kernel_va > voff) {
                kernel_pa = kernel_va - voff;
                kpm_log("LH_syms: kernel_pa derived = 0x%llx (voffset=0x%llx)\n",
                        (unsigned long long)kernel_pa, (unsigned long long)voff);
            }
        }
        if (kernel_size <= 0 && kernel_va != 0) {
            /* 保守取 64MB：目标设备内核镜像（text+rodata+data+bss）均 < 64MB。
             * _etext/_end 为链接期绝对值，KASLR 下 resolve 返回可能是未重定位值，
             * 直接固定 64MB 裕量比 _etext 差值更稳，足够覆盖 .rodata 字符串字面量。 */
            kernel_size = 0x4000000ULL;
            kpm_log("LH_syms: kernel_size fallback = 0x4000000 (64MB)\n");
        }
        if (pgd_va == 0) {
            unsigned long spgd = resolve_sym("swapper_pg_dir");
            if (spgd) {
                pgd_va = spgd;
                kpm_log("LH_syms: pgd_va derived from swapper_pg_dir = 0x%llx\n",
                        (unsigned long long)pgd_va);
            }
        }
        kpm_log("LH_syms: derived va_bits=%lld page_shift=%lld page_level=%lld "
                "kernel_va=0x%llx kernel_pa=0x%llx pgd_va=0x%llx\n",
                (long long)va_bits, (long long)page_shift, (long long)page_level,
                (unsigned long long)kernel_va, (unsigned long long)kernel_pa,
                (unsigned long long)pgd_va);
    }

    /* ===== 内核常量 ===== */
    /* vmemmap: struct page 数组基地址（ARM64 上用于 pfn_to_page 计算）
     * 多符号名回退 + 推算，确保 DMA Device-nGnRnE 路径可用 */
    g_vmemmap_base = read_kernel_var("vmemmap", 0);
    if (!g_vmemmap_base) {
        /* 部分内核导出 vmemmap_base 而非 vmemmap */
        g_vmemmap_base = read_kernel_var("vmemmap_base", 0);
    }
    if (!g_vmemmap_base) {
        /* VMEMMAP_START 公式随内核版本变化：
         *   <5.4: VMEMMAP_SIZE = 1 << (VA - PAGE_SHIFT - 1 + 6)
         *         VMEMMAP_START = PAGE_OFFSET - VMEMMAP_SIZE
         *   5.4~6.0: VMEMMAP_SIZE = ((PAGE_END - PAGE_OFFSET) >> (PAGE_SHIFT-6))
         *         PAGE_END = -(1 << (VA_MIN-1)); VMEMMAP_START = -VMEMMAP_SIZE - 2MB
         *   6.1+: VMEMMAP_SHIFT = PAGE_SHIFT - 6
         *         VMEMMAP_START = -(1 << (VA_BITS - VMEMMAP_SHIFT))
         * PAGE_OFFSET 同版本分支：<5.4 = -(1<<(VA-1))；>=5.4 = -(1<<VA)。
         * 运行时用框架导出的 kver 分支。 */
        extern int64_t va_bits;
        extern int64_t page_shift;
        extern uint32_t kver;    /* major<<16|minor<<8|patch */
        uint32_t major = (kver >> 16) & 0xFF;
        uint32_t minor = (kver >> 8) & 0xFF;
        int vab = (int)va_bits;
        int ps  = (int)page_shift;
        int new_layout = 0;   /* PAGE_OFFSET=-(1<<VA) */
        uint64_t page_offset, vmemmap_size, vmemmap_start;

        if (vab <= 0) vab = 39;          /* 保守默认 39-bit（两目标设备均 39） */
        if (ps <= 0) ps = 12;

        if (major > 5 || (major == 5 && minor >= 4)) new_layout = 1;
        if (new_layout)
            page_offset = -(1ULL << vab);          /* 5.4+ */
        else
            page_offset = -(1ULL << (vab - 1));    /* <5.4 */

        if (major > 6 || (major == 6 && minor >= 1)) {
            /* 6.1+：VMEMMAP_SHIFT = PAGE_SHIFT - 6 */
            vmemmap_start = -(1ULL << (vab - (ps - 6)));
        } else if (new_layout) {
            /* 5.4~6.0：VMEMMAP_SIZE = ((PAGE_END - PAGE_OFFSET) >> (PS-6)) */
            uint64_t page_end = -(1ULL << (vab - 1));  /* VA_MIN = VA (<=48) */
            vmemmap_size = (page_end - page_offset) >> (ps - 6);
            vmemmap_start = (0ULL - vmemmap_size) - (2ULL << 20);
        } else {
            /* <5.4：VMEMMAP_SIZE = 1 << (VA - PS - 1 + 6) */
            vmemmap_size = 1ULL << (vab - ps - 1 + 6);
            vmemmap_start = page_offset - vmemmap_size;
        }
        g_vmemmap_base = vmemmap_start;
        kpm_log("LH_syms: vmemmap not found, derived 0x%llx "
                "(kver=%u.%u va_bits=%d page_shift=%d)\n",
                (unsigned long long)g_vmemmap_base,
                major, minor, vab, ps);
    }

    /* mm_pgd_offset: mm_struct 中 pgd 字段偏移。
     * 优先级：框架导出的 mm_struct_offset.pgd_offset（权威，加载时重定位）
     *         > 内核符号 mm_pgd_offset > 运行时探测 > 默认 56。
     *
     * mm_struct_offset 是 KernelPatch 框架 .kp.symbol 段导出的变量，
     * 编译期 UND 引用在框架未导出时会导致 KPM 加载器 simplify_symbols 报
     * unknown symbol (ENOENT)、模块整体加载失败。这里采用运行时先侦测：
     *   - resolve_sym("mm_struct_offset") 命中（框架注册进 kallsyms）→ 取权威值；
     *   - 未命中（框架未导出）→ 不拷贝结构体，kf_mm_struct_offset 保持 {0}，
     *     pgd_offset==0 自然落入下方 fallback（read_kernel_var + probe）。 */
    {
        unsigned long mm_off_addr = resolve_sym("mm_struct_offset");
        if (mm_off_addr) {
            kf_mm_struct_offset = *(const struct mm_struct_offset *)mm_off_addr;
        } else {
            /* 框架未导出该变量：显式清零，避免残留 BSS 垃圾值 */
            memset(&kf_mm_struct_offset, 0, sizeof(kf_mm_struct_offset));
            kpm_log("LH_syms: mm_struct_offset not exported by framework, "
                    "use fallback probe\n");
        }
    }
    if (kf_mm_struct_offset.pgd_offset > 0) {
        g_mm_pgd_offset = (uint64_t)kf_mm_struct_offset.pgd_offset;
        kpm_log("LH_syms: mm_struct_offset.pgd=%d (framework)\n",
                kf_mm_struct_offset.pgd_offset);
    } else {
        g_mm_pgd_offset = read_kernel_var("mm_pgd_offset", 56);
        if (g_mm_pgd_offset == 0)
            g_mm_pgd_offset = 56;
        /* 运行时探测真实 pgd 偏移（默认 56 在部分内核为 64），
         * 探测成功则覆盖默认值，消除页表遍历失效风险 */
        probe_mm_pgd_offset();
    }
    /* 探测 rcu_read_lock_nesting 偏移（卸载借出用）。
     * 必须在 __rcu_read_lock/__rcu_read_unlock 解析之后（上方已解析）。 */
    probe_rcu_nesting_offset();
    /* swapper_pg_dir 可能未进 kallsyms。arm64 内核页表根 = init_mm.pgd，
     * init_mm 是 D 型数据符号可稳定解析，用 mm_struct 的 pgd 字段偏移
     * 读出真正的内核页表根。 */
    if (pgd_va == 0) {
        unsigned long imm = resolve_sym("init_mm");
        if (imm && g_mm_pgd_offset) {
            uint64_t p = 0;
            if (kf_copy_from_kernel_nofault(&p, (void *)(imm + g_mm_pgd_offset), 8) == 0
                && p) {
                pgd_va = p;
                kpm_log("LH_syms: pgd_va derived = 0x%llx (init_mm.pgd)\n",
                        (unsigned long long)p);
            } else {
                kpm_log("LH_syms: init_mm.pgd read failed (imm=0x%lx off=0x%llx)\n",
                        imm, (unsigned long long)g_mm_pgd_offset);
            }
        }
    }
    g_memstart_addr = read_kernel_var("memstart_addr", 0);
    /* 4.19 CONFIG_RANDOMIZE_BASE 会随机化线性映射，memstart_addr 实际存储
     * 带符号 PHYS_OFFSET（可为负/超大值），并非物理 RAM 基址。VA↔PA 换算
     * (addr - PAGE_OFFSET + memstart) 依赖该语义且换算本身正确；但 DEVAPC
     * 物理域守卫需要真实 RAM 下界，故单独推导 g_phys_ram_base，不改
     * g_memstart_addr（否则 VA↔PA 换算立即失效）。 */
    if ((int64_t)g_memstart_addr >= 0 &&
        g_memstart_addr < 0x4000000000ULL) {
        g_phys_ram_base = g_memstart_addr;
    } else if (kernel_pa) {
        g_phys_ram_base = kernel_pa & ~0x3fffffffULL; /* 1GB 对齐的 RAM 基址 */
        if (!g_phys_ram_base)
            g_phys_ram_base = 0x80000000ULL;
        kpm_log("LH_syms: memstart relaxed, phys_ram_base=0x%llx (from kernel_pa)\n",
                (unsigned long long)g_phys_ram_base);
    }
    KPM_DBG("  kernel_va=0x%llx kernel_pa=0x%llx page_shift=%lld va_bits=%lld\n",
            (uint64_t)kernel_va, (uint64_t)kernel_pa,
            (long long)page_shift, (long long)va_bits);
    KPM_DBG("  vmemmap=0x%llx memstart_addr=0x%llx pgd_va=0x%llx mm_pgd_off=%lld\n",
            (unsigned long long)g_vmemmap_base,
            (unsigned long long)g_memstart_addr,
            (uint64_t)pgd_va, (long long)g_mm_pgd_offset);
    KPM_DBG("  (if vmemmap=0 or memstart_addr=0, vmap DMA path WILL FAIL with WARNING!)\n");

    /* ===== 打印关键符号状态 ===== */
    if (!kf_copy_from_user || !kf_copy_to_user) {
        kpm_log("LH_syms: copy_to/from_user not found (critical)\n");
        return -1;
    }

    if (!kf_memremap || !kf_memunmap) {
        kpm_log("LH_syms: memremap/memunmap not found (WB path disabled)\n");
    }

    if (!kf_vmap || !kf_vunmap) {
        kpm_log("LH_syms: vmap/vunmap not found (DMA path disabled)\n");
    }

    if (!kf_find_get_pid || !kf_get_pid_task || !kf_get_task_mm || !kf_mmput) {
        kpm_log("LH_syms: process access symbols not found (mem_rw disabled)\n");
    }

    if (!kf_copy_from_kernel_nofault) {
        kpm_log("LH_syms: copy_from_kernel_nofault not found\n");
    }

    /* UDP 服务符号解析（非致命：失败时 UDP 不可用，prctl 仍可工作） */
    KPM_DBG("[6/9] resolving UDP symbols...\n");
    kf_sock_create_kern = (void *)resolve_sym("sock_create_kern");
    if (!kf_sock_create_kern)
        kf_sock_create_kern = (void *)resolve_sym("__sock_create_kern");
    /* 兼容性增强：部分内核（5.x 早期/厂商）将 sock_create_kern static 化。
     * sock_create 是 4 参数版本（无 net 参数，内部用 current->nsproxy->net_ns），
     * 签名不同，单独解析并由 kpm_udp_init 分支调用。 */
    if (!kf_sock_create_kern)
        kf_sock_create = (void *)resolve_sym("sock_create");
    kf_sock_release = (void *)resolve_sym("sock_release");
    kf_kernel_bind = (void *)resolve_sym("kernel_bind");
    kf_kernel_recvmsg = (void *)resolve_sym("kernel_recvmsg");
    kf_kernel_sendmsg = (void *)resolve_sym("kernel_sendmsg");
    kf_kernel_sock_shutdown = (void *)resolve_sym("kernel_sock_shutdown");
    kf_alloc_workqueue = (void *)resolve_sym("alloc_workqueue");
    /* 兼容性增强：alloc_workqueue(5.1+) 缺失时回退 create_workqueue
     * （老版本名，部分 5.x 厂商内核仍导出） */
    if (!kf_alloc_workqueue)
        kf_alloc_workqueue = (void *)resolve_sym("create_workqueue");
    /* 4.x 内核 alloc_workqueue/create_workqueue 均为宏，
     * 底层导出 __alloc_workqueue_key → 用包装函数兜底（否则 UDP 无法启动）。 */
    if (!kf_alloc_workqueue) {
        kf_alloc_workqueue_key = (struct kpm_workqueue_struct *(*)(const char *,
                                  unsigned int, int, struct kpm_lock_class_key *,
                                  const char *, ...))resolve_sym("__alloc_workqueue_key");
        if (kf_alloc_workqueue_key) {
            kf_alloc_workqueue = kpm_alloc_workqueue_fallback;
            kpm_log("LH_syms: alloc_workqueue via __alloc_workqueue_key fallback\n");
        }
    }
    kf_destroy_workqueue = (void *)resolve_sym("destroy_workqueue");
    /* queue_work 是宏，kallsyms 中不存在。回退到 queue_work_on */
    kf_queue_work = (void *)resolve_sym("queue_work");
    if (!kf_queue_work) {
        KPM_DBG("  queue_work not found, trying queue_work_on (macro fallback)\n");
        kf_queue_work = (void *)resolve_sym("queue_work_on");
    }
    /* flush_workqueue 仅退出时用，可选。回退到 __flush_workqueue（部分内核不导出 flush_workqueue） */
    kf_flush_workqueue = (void *)resolve_sym("flush_workqueue");
    if (!kf_flush_workqueue)
        kf_flush_workqueue = (void *)resolve_sym("__flush_workqueue");
    /* init_net 缺失时回退 current->nsproxy->net_ns（kpm_udp_init 内处理） */
    kf_init_net = (void *)resolve_sym("init_net");

    if (!kf_sock_create_kern || !kf_alloc_workqueue || !kf_init_net || !kf_queue_work) {
        kpm_log("LH_syms: UDP symbols missing "
                "(sock_create=%p wq=%p init_net=%p), UDP disabled\n",
                kf_sock_create_kern, kf_alloc_workqueue, kf_init_net);
    } else {
        kpm_log("LH_syms: UDP symbols resolved "
                "(sock_create=%p bind=%p recv=%p send=%p shutdown=%p)\n",
                kf_sock_create_kern, kf_kernel_bind, kf_kernel_recvmsg,
                kf_kernel_sendmsg, kf_kernel_sock_shutdown);
    }
    KPM_DBG("  sock_create=%llx wq=%llx init_net=%llx\n",
            (uint64_t)kf_sock_create_kern, (uint64_t)kf_alloc_workqueue,
            (uint64_t)kf_init_net);

    kpm_log("LH_syms: init done. memremap=%llx vmap=%llx vmemmap=%llx pgd_off=%llx\n",
            (uint64_t)kf_memremap, (uint64_t)kf_vmap,
            (unsigned long long)g_vmemmap_base, (unsigned long long)g_mm_pgd_offset);

    /* ===== 调试版完整诊断报告 =====
     * 汇总所有关键符号状态，便于一次性定位缺失符号。
     * 仅 KPM_DEBUG 构建输出，不影响正式版。
     */
    KPM_DBG("[7/9] === SYMBOL RESOLUTION SUMMARY ===\n");
    KPM_DBG("  copy_from_user=%llx copy_to_user=%llx copy_from_kernel_nofault=%llx\n",
            (uint64_t)kf_copy_from_user, (uint64_t)kf_copy_to_user,
            (uint64_t)kf_copy_from_kernel_nofault);
    KPM_DBG("  memremap=%llx memunmap=%llx ioremap_prot=%llx iounmap=%llx\n",
            (uint64_t)kf_memremap, (uint64_t)kf_memunmap,
            (uint64_t)kf_ioremap_prot, (uint64_t)kf_iounmap);
    KPM_DBG("  kmalloc=%llx kfree=%llx vmalloc=%llx vfree=%llx\n",
            (uint64_t)kf_kmalloc, (uint64_t)kf_kfree,
            (uint64_t)kf_vmalloc, (uint64_t)kf_vfree);
    KPM_DBG("  vmap=%llx vunmap=%llx vsnprintf=%llx snprintf=%llx\n",
            (uint64_t)kf_vmap, (uint64_t)kf_vunmap,
            (uint64_t)kf_vsnprintf, (uint64_t)kf_snprintf);
    KPM_DBG("  filp_open=%llx filp_close=%llx kernel_read=%llx kernel_write=%llx\n",
            (uint64_t)kf_filp_open, (uint64_t)kf_filp_close,
            (uint64_t)kf_kernel_read, (uint64_t)kf_kernel_write);
    KPM_DBG("  find_get_pid=%llx get_pid_task=%llx find_task_by_vpid=%llx\n",
            (uint64_t)kf_find_get_pid, (uint64_t)kf_get_pid_task,
            (uint64_t)kf_find_task_by_vpid);
    KPM_DBG("  get_task_mm=%llx mmput=%llx put_pid=%llx put_task_struct=%llx\n",
            (uint64_t)kf_get_task_mm, (uint64_t)kf_mmput,
            (uint64_t)kf_put_pid, (uint64_t)kf_put_task_struct);
    KPM_DBG("  mmap_read_lock=%llx mmap_read_unlock=%llx find_vma=%llx\n",
            (uint64_t)kf_mmap_read_lock, (uint64_t)kf_mmap_read_unlock,
            (uint64_t)kf_find_vma);
    KPM_DBG("  rcu_read_lock=%llx rcu_read_unlock=%llx __task_pid_nr_ns=%llx\n",
            (uint64_t)kf_rcu_read_lock, (uint64_t)kf_rcu_read_unlock,
            (uint64_t)kf___task_pid_nr_ns);
    KPM_DBG("  init_task=%llx get_task_comm=%llx\n",
            (uint64_t)kf_init_task, (uint64_t)kf_get_task_comm);
    KPM_DBG("[8/9] === PGTABLE VARS (vmap deps) ===\n");
    KPM_DBG("  vmemmap=0x%llx memstart_addr=0x%llx page_shift=%lld va_bits=%lld page_level=%lld\n",
            (unsigned long long)g_vmemmap_base,
            (unsigned long long)g_memstart_addr,
            (long long)page_shift, (long long)va_bits, (long long)page_level);
    KPM_DBG("  kernel_va=0x%llx kernel_pa=0x%llx kernel_size=%lld pgd_va=0x%llx\n",
            (uint64_t)kernel_va, (uint64_t)kernel_pa,
            (long long)kernel_size, (uint64_t)pgd_va);
    KPM_DBG("  tasks_off=%d tgid_off=%d pid_off=%d mm_off=%d\n",
            g_tasks_offset, g_tgid_offset, g_pid_offset, g_mm_offset);
    KPM_DBG("[9/9] === END SUMMARY (ret=0 means init OK, check 0x0 entries above for missing syms) ===\n");

    /* 安全 tasklist：双锚点推导真实 tasks 偏移（失败仅降级相关
     * 功能，不致命——suspend park/resctl 遍历在 ready==0 时拒服务） */
    kpm_tasklist_verify();

    return 0;
}

/* ===== 安全 tasklist 基础设施（见 LH_syms.h） ===== */

long kpm_tasklist_verify(void)
{
    struct pid *ps;
    struct task_struct *anchor1, *anchor2;   /* pid1(init)、pid2(kthreadd) */
    unsigned long O;
    uint64_t v, pv;
    int steps;
    struct task_struct *t;
    pid_t pid_check;

    if (g_tasks_offset_verified > 0)
        return g_tasks_offset_verified;
    if (!kf_init_task || !kf_find_get_pid || !kf_get_pid_task ||
        !kf_put_pid || !kf_copy_from_kernel_nofault || !kf___task_pid_nr_ns) {
        kpm_printk("LH_syms: tasklist verify skip deps: init=%d fgp=%d gpt=%d "
                   "ppid=%d nofault=%d nrns=%d\n",
                   !!kf_init_task, !!kf_find_get_pid, !!kf_get_pid_task,
                   !!kf_put_pid, !!kf_copy_from_kernel_nofault,
                   !!kf___task_pid_nr_ns);
        return -1;
    }

    /* 锚点 1：pid 1（init，init_task 之后第一个 fork 的首领）
     * 锚点 2：pid 2（kthreadd）——tasks 链上紧随其后 */
    ps = kf_find_get_pid(1);
    if (!ps)
        return -1;
    anchor1 = kf_get_pid_task(ps, 0 /* PIDTYPE_PID */);
    kf_put_pid(ps);
    if (!anchor1 || (uint64_t)anchor1 < 0xFFFF000000000000ULL)
        return -1;
    ps = kf_find_get_pid(2);
    if (!ps) {
        kpm_put_task_struct(anchor1);
        return -1;
    }
    anchor2 = kf_get_pid_task(ps, 0);
    kf_put_pid(ps);
    if (!anchor2 || (uint64_t)anchor2 < 0xFFFF000000000000ULL) {
        kpm_put_task_struct(anchor1);
        return -1;
    }

    for (O = 16; O <= 16384; O += 8) {
        /* 链式一致性：init_task →(O) anchor1 →(O) anchor2，双向边都验 */
        if (kf_copy_from_kernel_nofault(&v,
                (void *)((unsigned long)kf_init_task + O), 8) != 0)
            continue;
        if (v != (uint64_t)((unsigned long)anchor1 + O))
            continue;
        if (kf_copy_from_kernel_nofault(&pv,
                (void *)((unsigned long)anchor1 + O + 8), 8) != 0)
            continue;
        if (pv != (uint64_t)((unsigned long)kf_init_task + O))
            continue;
        if (kf_copy_from_kernel_nofault(&v,
                (void *)((unsigned long)anchor1 + O), 8) != 0)
            continue;
        if (v != (uint64_t)((unsigned long)anchor2 + O))
            continue;
        if (kf_copy_from_kernel_nofault(&pv,
                (void *)((unsigned long)anchor2 + O + 8), 8) != 0)
            continue;
        if (pv != (uint64_t)((unsigned long)anchor1 + O))
            continue;

        /* 链长判别：tasks 链含全部线程组首领（Android 上数百个），
         * children/sibling 链只有 2 节点——沿 O 走到回到 init_task，
         * 节点数 ≥5 才接受（排除同 fork 序的 children/sibling 链）。 */
        steps = 0;
        t = anchor2;
        while (steps++ < 4096) {
            uint64_t next_ptr;
            if (kf_copy_from_kernel_nofault(&next_ptr,
                    (void *)((unsigned long)t + O), 8) != 0)
                break;
            if (next_ptr < 0xFFFF000000000000ULL)
                break;
            if (next_ptr == (uint64_t)((unsigned long)kf_init_task + O)) {
                /* 回到表头；此前的节点上取一个验 pid（须 >2，证明不是
                 * children/sibling 的 wrap） */
                if (steps >= 5) {
                    g_tasks_offset_verified = (int)O;
                    kpm_log("syms: tasklist offset verified = %d "
                            "(chain=%d, framework=%d)\n",
                            (int)O, steps, g_tasks_offset);
                    kpm_put_task_struct(anchor1);
                    kpm_put_task_struct(anchor2);
                    return O;
                }
                break;
            }
            /* 每步双向校验：next.prev == 当前节点 */
            if (kf_copy_from_kernel_nofault(&pv,
                    (void *)(next_ptr + 8), 8) != 0)
                break;
            if (pv != (uint64_t)((unsigned long)t + O))
                break;
            t = (struct task_struct *)(next_ptr - O);
            if (steps == 8) {
                /* 第 8 个节点验 pid>2（判别 tasks/children） */
                if (kf_copy_from_kernel_nofault(&pid_check,
                        (void *)((unsigned long)t + g_pid_offset), 4) != 0)
                    break;
                if (pid_check <= 2)
                    break;
            }
        }
    }
    kpm_put_task_struct(anchor1);
    kpm_put_task_struct(anchor2);
    kpm_log("syms: tasklist offset derivation FAILED (framework=%d unusable)\n",
            g_tasks_offset);
    return -1;
}

struct task_struct *kpm_tasklist_next(struct task_struct *pos)
{
    uint64_t next_ptr = 0, pv = 0;
    unsigned long O = (unsigned long)g_tasks_offset_verified;

    if (O == 0 || O > 16384 || !pos ||
        (uint64_t)pos < 0xFFFF000000000000ULL)
        return NULL;
    if (kf_copy_from_kernel_nofault(&next_ptr,
            (void *)((unsigned long)pos + O), 8) != 0)
        return NULL;
    if (next_ptr < 0xFFFF000000000000ULL)
        return NULL;
    /* 双向一致性：next.prev 必须指回本节点（防链表损坏/垃圾指针） */
    if (kf_copy_from_kernel_nofault(&pv, (void *)(next_ptr + 8), 8) != 0)
        return NULL;
    if (pv != (uint64_t)((unsigned long)pos + O))
        return NULL;
    return (struct task_struct *)(next_ptr - O);
}

pid_t kpm_task_tgid(struct task_struct *t)
{
    pid_t tg = -1;
    extern uint32_t kver;   /* 框架导出：(major<<16)|(minor<<8)|patch */

    if (!t || (uint64_t)t < 0xFFFF000000000000ULL)
        return -1;
    /* 5.9+：enum pid_type 含 PIDTYPE_TGID=1 */
    if (kf___task_pid_nr_ns && kver >= 0x050900)
        return (pid_t)kf___task_pid_nr_ns(t, 1 /* PIDTYPE_TGID */, 0);
    /* 4.19~5.8：无 PIDTYPE_TGID 枚举。tasklist 只含线程组首领——
     * 遍历语境下 thread pid == tgid，用 PIDTYPE_PID(0) 等价取值
     * （调用方 suspend/resctl 收集器均满足该不变量）。 */
    if (kf___task_pid_nr_ns)
        return (pid_t)kf___task_pid_nr_ns(t, 0 /* PIDTYPE_PID */, 0);
    if (g_tgid_offset > 0 && kf_copy_from_kernel_nofault(
            &tg, (void *)((unsigned long)t + g_tgid_offset), 4) == 0)
        return tg;
    return -1;
}

pid_t kpm_task_pid(struct task_struct *t)
{
    if (!t || (uint64_t)t < 0xFFFF000000000000ULL || !kf___task_pid_nr_ns)
        return -1;
    /* PIDTYPE_PID=0 全版本一致（hide 成员收集需线程级 nr） */
    return (pid_t)kf___task_pid_nr_ns(t, 0, 0);
}

int kpm_tasklist_ready(void)
{
    return g_tasks_offset_verified > 0 ? 1 : 0;
}

void kpm_syms_exit(void)
{
    kf_copy_from_user_slot = 0;
    kf_copy_to_user_slot = 0;
    g_tasks_offset_verified = -1;
    kf_copy_from_kernel_nofault_slot = 0;
    kf_copy_to_kernel_nofault_slot = 0;
    kf_memremap_slot = 0;
    kf_memunmap_slot = 0;
    kf_ioremap_prot_slot = 0;
    kf_iounmap_slot = 0;
    kf_kmalloc = 0;
    kf_kfree = 0;
    kf_vmap = 0;
    kf_vunmap = 0;
    kf_input_handle_event = 0;
    kf_input_event = 0;
    kv_input_dev_list = 0;
    kf_vmalloc = 0;
    kf_vfree = 0;
    kf_vmalloc_to_page = 0;
    kf_simple_strtoull = 0;
    kf_snprintf = 0;
    kf_printk = 0;
    kf_get_task_mm = 0;
    kf_filp_open = 0;
    kf_filp_close = 0;
    kf_find_task_by_vpid = 0;
    kf_get_pid_task = 0;
    kf_kernel_read = 0;
    kf_kernel_write = 0;
    kf_kernel_read_iter = 0;
    kf_mmput = 0;
    kf_find_get_pid = 0;
    kf_vsnprintf = 0;
    kf_put_pid = 0;
    kf_register_user_hw_bp = 0;
    kf_unregister_hw_bp = 0;
    kf_perf_event_enable = 0;
    kf_perf_event_disable = 0;
    kf_uprobe_register = 0;
    kf_uprobe_unregister = 0;
    kf_kern_path = 0;
    kf_igrab = 0;
    kf_iput = 0;
    kf_path_put = 0;
    kf_tp_sys_enter = 0;
    kf_tp_sched_fork = 0;
    kf_tracepoint_probe_register = 0;
    kf_tracepoint_probe_unregister = 0;
    kf_tracepoint_synchronize_unregister = 0;
    kf_get_task_comm = 0;
    kf_get_cmdline = 0;
    kf_put_task_struct = 0;
    kf_task_work_add = 0;
    kf_schedule_timeout_interruptible = 0;
    kf_msecs_to_jiffies = 0;
    kf_wake_up_process = 0;
    kf_get_task_struct = 0;
    kf_do_send_sig_info = 0;
    kf_sched_setattr_nocheck = 0;
    kf_sysctl_sched_uclamp_util_max = 0;
    kf_set_cpus_allowed_ptr = 0;
    kf_register_user_step_hook = 0;
    kf_unregister_user_step_hook = 0;
    kf_register_user_break_hook = 0;
    kf_unregister_user_break_hook = 0;
    kf_exit_mmap = 0;
    kf_dup_mm = 0;
    kf_do_debug_exception = 0;
    kf_register_undef_hook = 0;
    kf_unregister_undef_hook = 0;
    kf_linux_banner = 0;
    kf_rcu_read_lock_any_held = 0;
    kf___put_task_struct = 0;
    kf_free_task = 0;
    g_usage_offset = -1;
    g_usage_offset_trusted = 0;
    g_usage_calib_state = KPM_CALIB_NONE;
    g_usage_calib_done = 0;
    g_p_pid_max_sym = 0;
    g_pid_max_cached = 0;
    g_comm_offset = -1;
    kernel_va = 0;
    kernel_pa = 0;
    kernel_size = 0;
    page_shift = 0;
    va_bits = 0;
    page_level = 0;
    pgd_va = 0;
    g_vmemmap_base = 0;
    g_mm_pgd_offset = 0;
    g_memstart_addr = 0;
    kf_mmap_read_lock = 0;
    kf_mmap_read_unlock = 0;
    kf_find_vma = 0;
    g_mm_mmap_offset = -1;
    kf_rcu_read_lock = 0;
    kf_rcu_read_unlock = 0;
    kf_synchronize_rcu = 0;
    kf_rcu_read_lock_held = 0;
    kf___task_pid_nr_ns = 0;
    kf_init_task = 0;
    lib_memset(&kf_task_struct_offset, 0, sizeof(kf_task_struct_offset));
    g_tasks_offset = 0;
    g_tgid_offset = 0;
    g_mm_offset = 0;
    g_pid_offset = 0;
    g_real_parent_offset = 0;
    g_arg_start_offset = 0;
    g_arg_end_offset = 0;
    g_total_vm_offset = 0;
    g_vm_start_offset = -1;
    g_vm_end_offset = -1;
    g_vm_next_offset = -1;
    g_vm_flags_offset = -1;
    /* UDP 符号清零（kpm_udp_exit 已先执行 socket/workqueue 释放） */
    kf_sock_create_kern = 0;
    kf_sock_create = 0;
    kf_sock_release = 0;
    kf_kernel_bind = 0;
    kf_kernel_recvmsg = 0;
    kf_kernel_sendmsg = 0;
    kf_kernel_sock_shutdown = 0;
    kf_alloc_workqueue = 0;
    kf_destroy_workqueue = 0;
    kf_queue_work = 0;
    kf_flush_workqueue = 0;
    kf_init_net = 0;
}