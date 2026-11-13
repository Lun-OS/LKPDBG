#ifndef KPM_SYMS_H
#define KPM_SYMS_H

#include <ktypes.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <stdarg.h>  /* va_list (for kf_vsnprintf 声明) */

/* ⑤关键指针密文访问器宏 (kp_ptr_dec/enc/set) 所在; 含 include guard, 可安全前置于本头 */
#include "LH_armor.h"

/* pgprot_t 定义（来自 linux/vmalloc.h，此处仅声明所需类型） */
#ifndef __pgprot_t_defined
#define __pgprot_t_defined
typedef size_t pgprot_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ===== 框架未声明的符号 ===== */

/* 内存操作 */
typedef long (*kf_copy_from_user_t)(void *to, const void *from, unsigned long n);
extern unsigned long kf_copy_from_user_slot;
#define kf_copy_from_user ((kf_copy_from_user_t)kp_ptr_dec(kf_copy_from_user_slot))
typedef long (*kf_copy_to_user_t)(void *to, const void *from, unsigned long n);
extern unsigned long kf_copy_to_user_slot;
#define kf_copy_to_user ((kf_copy_to_user_t)kp_ptr_dec(kf_copy_to_user_slot))
typedef long (*kf_copy_from_kernel_nofault_t)(void *dst, const void *src, size_t size);
extern unsigned long kf_copy_from_kernel_nofault_slot;
#define kf_copy_from_kernel_nofault ((kf_copy_from_kernel_nofault_t)kp_ptr_dec(kf_copy_from_kernel_nofault_slot))
/* copy_to_kernel_nofault: 安全写入内核地址（不触发 fault）
 * Linux 5.8+ 由 copy_from_kernel_nofault 的"写入兄弟"导出（实为 probe_kernel_write 别名）
 * 签名: long copy_to_kernel_nofault(void *dst, const void *src, size_t size)
 * 回退链: copy_to_kernel_nofault → probe_kernel_write → __probe_kernel_write
 * 用于 write_via_wb 写入线性映射地址（copy_from_kernel_nofault 语义为读，勿混用） */
typedef long (*kf_copy_to_kernel_nofault_t)(void *dst, const void *src, size_t size);
extern unsigned long kf_copy_to_kernel_nofault_slot;
#define kf_copy_to_kernel_nofault ((kf_copy_to_kernel_nofault_t)kp_ptr_dec(kf_copy_to_kernel_nofault_slot))

/* 物理内存映射（memremap，非 vmap） */
typedef void *(*kf_memremap_t)(uint64_t offset, unsigned long size, unsigned long flags);
extern unsigned long kf_memremap_slot;
#define kf_memremap ((kf_memremap_t)kp_ptr_dec(kf_memremap_slot))
typedef void (*kf_memunmap_t)(const void *addr);
extern unsigned long kf_memunmap_slot;
#define kf_memunmap ((kf_memunmap_t)kp_ptr_dec(kf_memunmap_slot))

/* ioremap 映射（用于高位物理地址，memremap 无法映射的地址） */
typedef void *(*kf_ioremap_prot_t)(uint64_t phys_addr, unsigned long size, unsigned long prot);
extern unsigned long kf_ioremap_prot_slot;
#define kf_ioremap_prot ((kf_ioremap_prot_t)kp_ptr_dec(kf_ioremap_prot_slot))
typedef void (*kf_iounmap_t)(const void *addr);
extern unsigned long kf_iounmap_slot;
#define kf_iounmap ((kf_iounmap_t)kp_ptr_dec(kf_iounmap_slot))

/* ===== 内核常量 ===== */
extern void *(*kf_kmalloc)(size_t size, gfp_t flags);
extern void (*kf_kfree)(const void *objp);

/* ===== vmap Device-nGnRnE ===== */
extern void *(*kf_vmap)(struct page **pages, unsigned int count, unsigned long flags, pgprot_t prot);
extern void (*kf_vunmap)(const void *addr);

/* ===== 触摸子系统符号 =====
 * input_handle_event: hook 目标（6.1 导出，<6.1 通过 kallsyms_lookup_name 解析）
 *   签名: void input_handle_event(struct input_dev *dev, unsigned int type,
 *                                 unsigned int code, int value)
 *   注意: 不获取 event_lock（lockdep_assert_held），由调用者 input_event 持有
 *
 * input_event: 虚拟触摸注入入口（全版本 EXPORT_SYMBOL，自动获取 event_lock）
 *   签名: void input_event(struct input_dev *dev, unsigned int type,
 *                          unsigned int code, int value)
 *   优势: 全版本兼容，自动锁管理，process context 安全调用
 */
extern void (*kf_input_handle_event)(void *dev, unsigned int type, unsigned int code, int value);
extern void (*kf_input_event)(void *dev, unsigned int type, unsigned int code, int value);
extern uint64_t kv_input_dev_list;

/* ===== vmalloc / scan 符号 ===== */
extern void *(*kf_vmalloc)(unsigned long size);
extern void (*kf_vfree)(const void *addr);
/* vmalloc_to_page —— 校验地址是否为 vmalloc
 * 分配页（模块/驱动数据），对 VM_IOREMAP（设备映射）返回 NULL。
 * 供 kpm_is_safe_kern_addr 区分"安全 vmalloc 内存"与"ioremap 设备映射"
 * （读取后者可能触发 MTK DEVAPC IRQ30 → HW_Reboot）。 */
struct page;
extern struct page *(*kf_vmalloc_to_page)(const void *addr);
extern unsigned long long (*kf_simple_strtoull)(const char *cp, char **endp, unsigned int base);
extern int (*kf_snprintf)(char *buf, size_t size, const char *fmt, ...);
extern int (*kf_vsnprintf)(char *buf, size_t size, const char *fmt, va_list args);
extern int (*kf_printk)(const char *fmt, ...);

/* ===== 进程内存管理符号（kpm_syms.c 定义，非 kfunc_def） ===== */
extern struct mm_struct *(*kf_get_task_mm)(struct task_struct *task);
extern void (*kf_mmput)(struct mm_struct *mm);

/* ===== 文件操作 ===== */
extern struct file *(*kf_filp_open)(const char *pathname, int flags, umode_t mode);
extern int (*kf_filp_close)(struct file *filp, void *id);
extern ssize_t (*kf_kernel_read)(struct file *file, void *buf, size_t count, loff_t *pos);
extern ssize_t (*kf_kernel_write)(struct file *file, const void *buf, size_t count, loff_t *pos);

/* ===== 凭证切换符号（保留解析，不调用） ===== */
extern const void *(*kf_override_creds)(const void *new);
extern void (*kf_revert_creds)(const void *old);
extern const void *kf_init_cred;

/* kernel_read_iter: Linux 5.10+ 替代 kernel_read 的接口，通过 iov_iter 调用 read_iter，
 * 可读取 procfs seq_file (cmdline/maps 等)。
 * 签名: ssize_t kernel_read_iter(struct file *file, loff_t *pos, struct iov_iter *iter, size_t count)
 * 注意: iov_iter 需调用方构造，布局见 kpm_proc.c 中的 kpm_read_file_iter() */
typedef ssize_t (*kpm_kernel_read_iter_t)(struct file *file, loff_t *pos, void *iter, size_t count);
extern kpm_kernel_read_iter_t kf_kernel_read_iter;

/* ===== PID 引用管理 ===== */
extern void (*kf_put_pid)(struct pid *pid);

/* ===== 硬件断点 (perf_event) =====
 * 真实原型（kernel/events/hw_breakpoint.c）：
 *   struct perf_event *register_user_hw_breakpoint(
 *       struct perf_event_attr *attr,
 *       perf_overflow_handler_t triggered,   - 溢出回调（断点异常上下文）
 *       void *context,                       - 存入 event->overflow_handler_context
 *       struct task_struct *tsk)             - 目标进程（perf_event 内部持有引用）
 * 兼容性：4.x-6.x 全版本导出（EXPORT_SYMBOL_GPL，kallsyms 可解析） */
extern void *(*kf_register_user_hw_bp)(void *attr, void *triggered,
                                        void *context, void *tsk);
extern void (*kf_unregister_hw_bp)(void *bp);
extern void (*kf_perf_event_enable)(void *event);
extern void (*kf_perf_event_disable)(void *event);
/* 内核/宽断点（force 使用） */
extern void *(*kf_register_wide_hw_bp)(void *attr, void *handler, void *ctx);
extern void (*kf_unregister_wide_hw_bp)(void *pevents);
extern void *(*kf_perf_event_create_kernel_counter)(void *attr, int cpu,
                                                     void *task,
                                                     void *handler,
                                                     void *ctx);

/* ===== fault / 时间 / lockdown ===== */
extern void (*kf_do_mem_abort)(unsigned long addr, unsigned int esr,
                               void *regs);
extern uint64_t (*kf_ktime_get_ns)(void);
extern unsigned long *kf_jiffies;
extern int *kf_kernel_locked_down;
extern int (*kf_security_locked_down)(int what);
/* 只作能力探测，不在未验证前调用 */
extern void *kf_patch_text;
/* aarch64_insn_patch_text(void *addrs[], u32 insns[], int cnt)：
 * 内核镜像 text 写入的官方接口（含 flush_icache_range）。仅 force 路径调用。 */
typedef int (*kf_insn_patch_text_t)(void *addrs[], uint32_t insns[], int cnt);
extern kf_insn_patch_text_t kf_aarch64_insn_patch_text;
extern void *kf_set_memory_rw;
extern void *kf_flush_icache_range;

/* ===== uprobe（libsensorservice hook） =====
 * 通过 kallsyms_lookup_name 解析内核 uprobe 接口。
 * 这里声明的是 **≤6.11 的 3 参 ABI**：
 *   int uprobe_register(struct inode *inode, loff_t offset,
 *                       struct uprobe_consumer *uc)
 *   void uprobe_unregister(struct inode *inode, loff_t offset,
 *                          struct uprobe_consumer *uc)
 * v6.12 起 ABI 不兼容变更（register 变 4 参、uprobe_unregister 被删除、
 * struct uprobe_consumer 布局也变），kpm_syms_init() 会在 kver>=6.12 时把
 * 下面两个指针置 0 —— 所以**任何调用点都必须先判非空**。
 * inode 通过 kern_path + igrab 获取 libsensorservice.so 的 inode，
 * offset 为 convertToSensorEvent 在文件内的 ELF 符号偏移。
 * （struct inode/struct path 仅作指针传递，不访问成员，前向声明即可） */
struct inode;
struct path;
struct dentry;
extern int (*kf_uprobe_register)(struct inode *inode, long long offset,
                                 void *uc);
extern void (*kf_uprobe_unregister)(struct inode *inode, long long offset,
                                    void *uc);
extern int (*kf_kern_path)(const char *name, unsigned int flags,
                           struct path *path);
extern struct inode *(*kf_igrab)(struct inode *inode);
extern void (*kf_iput)(struct inode *inode);
extern void (*kf_path_put)(struct path *path);

/* ===== sys_enter tracepoint =====
 * kallsyms 解析 __tracepoint_sys_enter +
 * tracepoint_probe_register，注册 sys_enter probe 拦截 read(206)/pread64(211)
 * 读传感器事件数组（sensors_event_t，104B）——与 sensorservice 内部实现解耦，
 * 跨 Android 版本兼容（uprobe 失效时 tracepoint 仍有效）。
 * 全版本内核 EXPORT_SYMBOL/EXPORT_TRACEPOINT_SYMBOL，kallsyms 可解析。 */
extern void *kf_tp_sys_enter;   /* struct tracepoint *__tracepoint_sys_enter */
/* sys_exit tracepoint（全版本 EXPORT_TRACEPOINT_SYMBOL） */
extern void *kf_tp_sys_exit;
/* sched_process_fork tracepoint——fork 时对新子进程置位
 * TIF_SYSCALL_TRACEPOINT，覆盖模块加载后启动的进程。
 * 符号 __tracepoint_sched_process_fork 全版本导出（EXPORT_TRACEPOINT_SYMBOL），
 * probe 签名: (void *data, struct task_struct *parent, struct task_struct *child) */
extern void *kf_tp_sched_fork;  /* struct tracepoint *__tracepoint_sched_process_fork */
extern int (*kf_tracepoint_probe_register)(void *tp, void *probe, void *data);
extern int (*kf_tracepoint_probe_unregister)(void *tp, void *probe, void *data);
extern void (*kf_tracepoint_synchronize_unregister)(void);

/* ===== 进程名称 ===== */
/* __get_task_comm 签名: char *__get_task_comm(char *buf, size_t buf_size, struct task_struct *tsk)
 * 注意: 内核中导出的是 __get_task_comm（双下划线），get_task_comm 是 inline 包装未导出。 */
extern char *(*kf_get_task_comm)(char *buf, size_t buf_size, struct task_struct *tsk);

/* ===== task_struct 引用管理 ===== */
extern void (*kf_put_task_struct)(struct task_struct *tsk);

/* ===== 同步断点停靠符号（task_work 机制） =====
 * 缺失时仅同步断点模式禁用（bp_set_sync 返回 -KPM_E_DISABLED），
 * async 断点不受影响，非致命。
 * task_work_add 第三参数版本差异：
 *   4.19~5.8: bool resume —— true=1，返回用户态时运行（置 TIF_NOTIFY_RESUME）
 *   5.9+   : enum task_work_notify_mode —— TWA_RESUME=1 同语义
 * 两种 ABI 第三参数值恰好同为 1，传字面量 1 全版本兼容，零偏移探测。
 * schedule_timeout_interruptible 免 task->state 偏移探测（版本间
 * __state/state 字段名与位置有差，自实现 set_current_state 需偏移）。 */
extern int (*kf_task_work_add)(struct task_struct *task, void *work, int resume);
extern long (*kf_schedule_timeout_interruptible)(long timeout);
extern unsigned long (*kf_msecs_to_jiffies)(unsigned int m);
extern int (*kf_wake_up_process)(struct task_struct *tsk);
extern void (*kf_get_task_struct)(struct task_struct *tsk);
/* SIGSTOP 兜底挂起。第 4 参版本差异：4.19~5.10 bool group
 * （true=1）；5.15+ enum pid_type（PIDTYPE_TGID=1）—— 值恒 1 全版本兼容。
 * 第 2 参 SEND_SIG_PRIV = (struct kernel_siginfo *)1（内核私有发送者）。 */
extern int (*kf_do_send_sig_info)(int sig, void *info, struct task_struct *t,
                                  int group);
/* ===== CPU 亲和性/频率控制 =====
 * sched_setattr_nocheck = __sched_setscheduler(force=true) 免权限检查。
 * sysctl_sched_uclamp_util_max 为变量（6.1 有、4.19 无）——仅作 uclamp
 * 能力探测用，不读写内容。 */
extern int (*kf_sched_setattr_nocheck)(struct task_struct *p,
                                       const void *attr);
extern void *kf_sysctl_sched_uclamp_util_max;
extern int (*kf_set_cpus_allowed_ptr)(struct task_struct *p,
                                      const void *new_mask);

/* ===== get_cmdline（直接读取进程完整 cmdline） =====
 * int get_cmdline(struct task_struct *task, char *buffer, int buflen);
 * 内部实现：get_task_mm + 读取 mm->arg_start~arg_end + access_process_vm
 * 优势：无需手动探测 arg_start/arg_end 偏移，无需 filp_open/kernel_read_iter
 * 内核已导出（T get_cmdline），kallsyms 可解析。 */
extern int (*kf_get_cmdline)(struct task_struct *task, char *buffer, int buflen);

/* ===== put_task_struct 安全替代 =====
 * 部分内核上 put_task_struct（static inline）未导出，需手动实现等价逻辑：
 *   1. 原子递减 task->usage 引用计数
 *   2. 引用计数降为 0 时调用 __put_task_struct 释放
 *
 * g_usage_offset: task_struct.usage 字段偏移，运行时行为学标定（非启发式）；
 *                 未标定/标定失败时为 -1，手动递减被禁用（只接受引用泄漏）
 * g_usage_offset_trusted: 1 = 偏移已由 get_pid_task +1 指纹证明为 usage
 * kf___put_task_struct: __put_task_struct 符号
 * kpm_put_task_struct: 安全替代函数，优先用原生符号，缺失时手动实现
 */
extern int g_usage_offset;
extern int g_usage_offset_trusted;

/* usage 标定状态（g_usage_calib_state）——供 info 诊断说明"手动 put 为什么不可用" */
#define KPM_CALIB_NONE   0   /* 未尝试（正常：有原生 put_task_struct 时不需要标定） */
#define KPM_CALIB_OK     1   /* 已由 get_pid_task +1 指纹证明 */
#define KPM_CALIB_FAIL   2   /* 指纹不唯一 / pid1≠pid2 / 往返校验失败 */
#define KPM_CALIB_NOSYM  3   /* 标定所需符号缺失（init_task/copy_nofault/find_get_pid/get_pid_task/put_pid/pid_task） */
extern int g_usage_calib_state;

extern void (*kf___put_task_struct)(struct task_struct *tsk);
void kpm_put_task_struct(struct task_struct *task);
/* get 侧安全封装（4.19 get_task_struct 为 static inline 无符号；
 * 用已标定 usage 偏移原子 +1，与 put 侧手动递减严格配对） */
void kpm_get_task_struct_safe(struct task_struct *task);

/* ===== 软件单步舞步符号（debug-monitors.c 官方扩展点） =====
 * register_user_step_hook 把 hook 挂入 EL0 Software Step 异常处理链
 * （call_step_hook 按 user_mode 分链），hook 返回 0=接管（不发 SIGTRAP）。
 * 缺失时步进语义整体禁用（fail-closed，回退 PC+4 跳过）。4.19/6.1 均有。 */
extern void (*kf_register_user_step_hook)(void *hook);
extern void (*kf_unregister_user_step_hook)(void *hook);
/* 用户 BRK 断点钩子（W^X shadow BP 用；4.19/6.1 均有） */
extern int (*kf_register_user_break_hook)(void *hook);
extern int (*kf_unregister_user_break_hook)(void *hook);
/* 进程退出清理 shadow 页（mm 销毁前摘链） */
extern void (*kf_exit_mmap)(struct mm_struct *mm);
/* fork 时 dup_mm（子进程不应继承 shadow 映射） */
extern void *(*kf_dup_mm)(struct task_struct *tsk);
/* 用户调试异常入口（BRK/单步的通用 hook 点；4.19 无
 * register_user_break_hook/register_user_step_hook 符号） */
extern void (*kf_do_debug_exception)(unsigned long addr, unsigned int esr,
                                     void *regs);
/* 未定义指令恢复钩子（探测调试寄存器真实上限用——MTK 等 EL2 虚报
 * ID_AA64DFR0，直读未实现槽位 = UNDEFINED，需官方 undef_hook 兜底） */
extern int (*kf_register_undef_hook)(void *hook);
extern int (*kf_unregister_undef_hook)(void *hook);
/* 内核版本字符串（"Linux version X.Y.Z-..."），undef 探测版本门控用 */
extern const char *kf_linux_banner;
/* RCU 读临界区检测（非 0 = 当前任务处于任意 RCU 读临界区）。
 * exit/清理路径防自死锁：检测到在 RCU 读临界区内必须跳过一切
 * synchronize_rcu / 可睡眠内核调用（perf release、destroy_workqueue 等）。
 * 解析失败（返回 NULL 函数指针）时调用方按"不在临界区"处理——
 * 该符号 EXPORT_SYMBOL_GPL 全版本可解析，失败概率极低。 */
extern int (*kf_rcu_read_lock_any_held)(void);

/* ===== 免引用 pid→task =====
 * RCU 读锁 + find_vpid + pid_task，全程不触碰 task->usage。
 * kpm_task_acquire: 首选免引用，回退取引用。needs_put=0 时配对 kpm_task_end()。 */
int kpm_task_noref_available(void);
int kpm_task_begin(pid_t pid, struct task_struct **out);
/* 免引用：由**已持有的 struct pid\*** 直接取 task（供只有 pidref 的调用点用）。
 * 成功 0 并持 RCU（须配对 kpm_task_end()），失败 -1（应回退 kf_get_pid_task）。 */
int kpm_task_begin_pidref(struct pid *ps, struct task_struct **out);
void kpm_task_end(void);
int kpm_task_acquire(pid_t pid, struct task_struct **out, int *needs_put);
void kpm_task_release(void);

/* kpm_put_task_available: 判断能否安全释放 task_struct（原生符号或手动回退）。
 * 4.19 等内核 put_task_struct（static inline）未导出时 kf_put_task_struct 为 NULL，
 * 但 __put_task_struct + usage 偏移**已标定**（g_usage_offset_trusted）才可走
 * kpm_put_task_struct 手动路径——未标定时递减会写坏未知字段，宁可泄漏引用；
 * 各模块的可用性条件必须用本函数而非裸 kf_put_task_struct，否则进程枚举/maps
 * 等功能在 put_task_struct 未导出的内核上整体禁用。 */
static inline int kpm_put_task_available(void)
{
    return (kf_put_task_struct != 0) ||
           (g_usage_offset > 0 && g_usage_offset_trusted && kf___put_task_struct != 0);
}

/* kpm_task_fetch_available: 判断"能否安全取到一个 task_struct 指针"。
 * = 免引用路径可用（RCU + find_vpid + pid_task，零引用计数）
 *   或 取引用路径可归还（kpm_put_task_available）。
 * **优先用免引用**——它不碰 usage、不需要 __put_task_struct，
 * 是"更多设备可用"的关键：哪怕整台机器都没有 put_task_struct / __put_task_struct，
 * 只要 pid_task 在 kallsyms 里就能枚举进程。
 * ⚠ 免引用路径期间**不得睡眠**（调用方若在临界区内要 mmap_read_lock/
 * kernel_read/access_process_vm 等可睡眠操作，必须先把 mm 取好、退出临界区）。 */
static inline int kpm_task_fetch_available(void)
{
    return kpm_task_noref_available() || kpm_put_task_available();
}

/* ===== pid 扫描上限：运行时读内核 pid_max，禁止硬编码 =====
 * pid 分配随开机时间增长，pid_max 可被厂商调到 4194304，写死上限会漏掉
 * 高 pid 进程。kpm_pid_max() 从 kallsyms 解析内核 `pid_max` 变量读真值
 * （失败回退 32768）。 */
#define KPM_PID_MAX_FALLBACK   32768
#define KPM_PID_MAX_LIMIT      4194304     /* 内核 PID_MAX_LIMIT */
int kpm_pid_max(void);

/* put_task 释放路径枚举（= kpm_state_info_t.put_task_path，三处上报共用本函数，
 * 数值与 docs / PC 端 udp_test_mem.py 的 put_task 字典严格一致）：
 *   0 原生 put_task_struct
 *   1 手动递减 usage + __put_task_struct（已标定，与原生语义等价）
 *   2 free_task（已禁用，不再出现）
 *   3 泄漏：__put_task_struct 也缺 → 无任何安全释放手段
 *   4 泄漏：usage 标定未执行（init_task/时序）
 *   5 泄漏：usage 标定失败（+1 指纹不唯一 / pid1≠pid2 / 往返校验不过）
 *   6 泄漏：标定所需符号缺失（find_get_pid/get_pid_task/put_pid/pid_task） */
static inline uint8_t kpm_put_task_path(void)
{
    if (kf_put_task_struct)
        return 0;
    if (g_usage_offset > 0 && g_usage_offset_trusted && kf___put_task_struct)
        return 1;
    if (!kf___put_task_struct)
        return 3;
    switch (g_usage_calib_state) {
    case KPM_CALIB_NOSYM: return 6;
    case KPM_CALIB_FAIL:  return 5;
    default:              return 4;   /* NONE：标定没跑成 */
    }
}

/* ===== PID/TGID 获取（无需偏移，通过内核函数） ===== */
/* 注意：kf___task_pid_nr_ns 已由框架 sched.h 通过 kfunc_def 声明，
 * 签名为 pid_t (*)(struct task_struct *, enum pid_type, struct pid_namespace *)。
 * 此处无需重复声明，仅 kpm_syms.c 中定义存储即可。
 * 用法：kf___task_pid_nr_ns(task, PIDTYPE_PID, NULL) 返回 PID
 *       kf___task_pid_nr_ns(task, PIDTYPE_TGID, NULL) 返回 TGID
 */

/* ===== find_task_by_vpid（RCU 下使用，不增引用计数） ===== */
/* 已由框架 sched.h 通过 kfunc_def 声明，无需重复声明 */

/* ===== 内核常量 ===== */
extern uint64_t g_vmemmap_base;  /* struct page 数组基地址 */
extern uint64_t g_mm_pgd_offset; /* mm_struct 中 pgd 字段偏移 */
extern uint64_t g_memstart_addr; /* PHYS_OFFSET / memstart_addr */
extern uint64_t g_phys_ram_base; /* 真实物理 RAM 基址（DEVAPC 守卫下界） */
extern uint64_t kernel_va;       /* 内核镜像起始虚拟地址（_text） */
extern int64_t kernel_size;      /* 内核镜像尺寸（用于 is_kimg_range） */

/* ===== tasklist 遍历符号（由 KernelPatch 框架导出） ===== */
/* task_struct 中关键字段相对于结构体首地址的偏移量 */
extern struct task_struct_offset kf_task_struct_offset;
/* mm_struct 关键字段偏移（KernelPatch 框架导出，权威值，KPM 加载时重定位） */
extern struct mm_struct_offset kf_mm_struct_offset;
/* init_task 指针，指向内核的 init_task 结构体，用于 tasklist 遍历 */
extern struct task_struct *kf_init_task;

/* ===== mm 读锁（双路径适配层） =====
 * 路径 A（5.12+）：mmap_read_lock/mmap_read_unlock 为 mm/mmap_lock.c 真实
 *   符号，VMA 遍历统一经 kpm_mm_read_lock 持原生 mmap 读锁，满足
 *   find_vma 的持锁契约（上游要求 mmap_read_lock），消除并发 munmap
 *   下 rbtree/maple tree 半更新状态的 UAF panic 风险。
 * 路径 B（4.14/5.4/5.10 等，符号为 static inline 或尚名 mmap_sem）：
 *   无原生锁可用（down_read 回退签名不兼容——需 &mm->mmap_sem 偏移，
 *   无可靠探测手段，误判即 panic，禁止调用）。VMA 遍历保持 RCU 读锁，
 *   kpm_find_vma_next 仍走 find_vma 主路径（find_vma 不可用时才回退到
 *   nofault vm_next 链表遍历，全 copy_from_kernel_nofault 读，绝不裸解引用）。
 * 页表遍历（kpm_mem_rw.c walk_page_table）不受影响，仍走其自有
 * RCU 适配层（kpm_mmap_read_lock/unlock in LH_mem_rw.c）。
 * 详见 LH_syms.c 中 kpm_mm_read_lock/unlock 实现与解析注释 */
extern int (*kf_mmap_read_lock)(struct mm_struct *mm);
extern void (*kf_mmap_read_unlock)(struct mm_struct *mm);
/* 原生 mmap_read_lock/unlock 双符号均可解析时为 1（5.12+ 真符号，
 * 注意区别于 down_read/up_read 回退填充值——后者不可调用） */
extern int g_mmap_read_lock_native;

/* VMA 遍历统一加锁入口：
 * 返回 1 = 已持原生 mmap 读锁（调用方以 (mm,1) 配对解锁）；
 * 返回 0 = 未加锁，RCU 读锁已持有（调用方以 (mm,0) 配对解锁）。
 * 仅允许可睡眠上下文调用（prctl 回调 / UDP work / init）——所有现存
 * VMA 遍历调用点均已核实满足。锁内禁止睡眠之外无其它约束。 */
int  kpm_mm_read_lock(struct mm_struct *mm);
void kpm_mm_read_unlock(struct mm_struct *mm, int locked);

/* ===== VMA 遍历符号（高兼容性三级回退链） =====
 *
 * 回退链（按优先级）：
 *   1. find_vma（主路径）: Linux 5.1+ 全版本 EXPORT_SYMBOL
 *      - 5.1+ 全版本定义在 mm/mmap.c（v6.12 拆分出 mm/vma.c 但 find_vma 仍在 mmap.c）
 *      - 通过 kallsyms_lookup_name 100% 可解析
 *      - A 级隐蔽性：纯内核函数调用，无任何痕迹
 *   2. vm_next 链表遍历（回退 1）: 5.x-6.0 链表模式
 *      - 通过 g_mm_mmap_offset 直接读 mm_struct->mmap 链表头
 *      - 通过 g_vm_next_offset 顺序遍历 vm_area_struct.vm_next
 *      - A 级隐蔽性：纯内存读取，不依赖任何符号
 *      - 限制: 6.1+ maple tree 模式下 vm_next 已移除，此路径失效
 *   3. NULL（功能禁用）: 6.1+ 且 find_vma 不可用时
 *      - 极低概率：find_vma 在 5.1+ 全版本 EXPORT，此分支实际不可达
 *
 * 注意: find_vma_intersection 是 static inline 函数（include/linux/mm.h），
 *       编译后无独立符号，kallsyms_lookup_name 永远返回 0。
 *
 * 隐蔽性总评: A 级
 *   - 所有路径均为纯内核操作（无 VFS、无文件 IO、无用户态参与）
 *   - find_vma 调用不产生任何可观测痕迹
 *   - vm_next 链表遍历仅用 copy_from_kernel_nofault，不触发任何 hook
 *   - RCU 读锁是 Linux 原生同步原语，非 root 程序无法检测
 */
extern void *(*kf_find_vma)(struct mm_struct *mm, unsigned long addr);

/* mm_struct.mmap 偏移（回退路径 1 使用）
 * 5.x-6.0: mm_struct 的 mmap 字段是 VMA 链表头
 * 6.1+: maple tree 取代链表，此字段已移除
 * -1 = 未探测，>=0 = 探测到的偏移，-2 = 探测失败（6.1+ 自动失败） */
extern int g_mm_mmap_offset;

/* ===== RCU 读锁（链表遍历，不增加引用计数） =====
 *
 * __rcu_read_lock 的 kallsyms 可解析性取决于 CONFIG_PREEMPT_RCU：
 *   - PREEMPT / PREEMPT_RT 内核（大多数 Android 内核）: EXPORT_SYMBOL_GPL(__rcu_read_lock)，可解析 ✅
 *   - PREEMPT_NONE / PREEMPT_VOLUNTARY 内核（服务器/stock）: static inline，kallsyms 无此符号 ❌
 *
 * 兼容性处理：RCU 锁为可选，不可用时跳过（依赖 copy_from_kernel_nofault 的 fault 处理）
 *   - 实际安全性：VMA 释放前会从数据结构移除，最坏情况读到旧数据，不会 panic
 *   - 隐蔽性不变：跳过 RCU 锁不会产生任何可观测痕迹
 *
 * 调用方应使用 KPM_RCU_READ_LOCK() / KPM_RCU_READ_UNLOCK() 宏，自动处理 NULL */
extern void (*kf_rcu_read_lock)(void);
extern void (*kf_rcu_read_unlock)(void);
/* 卸载侧 RCU 宽限期等待（排空在途 hook 回调）。
 * synchronize_rcu 全版本导出（EXPORT_SYMBOL_GPL，KPM kallsyms 不受 GPL 限制） */
extern void (*kf_synchronize_rcu)(void);
/* RCU 读锁持有状态探测：返回当前任务是否处于 RCU 读临界区。
 * 用于卸载时临时释放框架持有的 RCU 读锁，规避 uprobe_unregister 内部
 * synchronize_rcu 自死锁（RCU stall → 系统崩溃）。 */
extern int (*kf_rcu_read_lock_held)(void);

/* 安全调用宏：RCU 锁不可用时自动跳过（非 PREEMPT 内核兼容） */
#define KPM_RCU_READ_LOCK()   do { if (kf_rcu_read_lock) kf_rcu_read_lock(); } while (0)
#define KPM_RCU_READ_UNLOCK() do { if (kf_rcu_read_unlock) kf_rcu_read_unlock(); } while (0)
/* 卸载排空宏：等待所有在途 RCU 读临界区退出（无符号时降级为无操作） */
#define KPM_RCU_SYNC()        do { if (kf_synchronize_rcu) kf_synchronize_rcu(); } while (0)

/* ===== task_struct 偏移（运行时探测） ===== */
/* 探测到的 task_struct 字段偏移，0 表示未探测到 */
extern int g_tasks_offset;        /* task_struct.tasks 偏移 */
extern int g_tgid_offset;         /* task_struct.tgid 偏移 */
extern int g_mm_offset;           /* task_struct.mm 偏移 */
extern int g_pid_offset;          /* task_struct.pid 偏移 */
extern int g_pid_offset_verified; /* pid/tgid 偏移是否经 PID=2 交叉验证（0=启发式候选） */
extern int g_rcu_nesting_offset;  /* task_struct.rcu_read_lock_nesting 偏移（PREEMPT_RCU） */
extern int g_real_parent_offset;  /* task_struct.real_parent 偏移 */
extern int g_arg_start_offset;    /* mm_struct.arg_start 偏移 */
extern int g_arg_end_offset;      /* mm_struct.arg_end 偏移 */
extern int g_total_vm_offset;     /* mm_struct.total_vm 偏移（进程虚拟内存总大小，单位页） */

/* RCU 任务链表遍历（使用运行时探测的 g_tasks_offset）
 * 注意：必须在使用前验证 g_tasks_offset > 0，且必须在 RCU 读锁保护下调用
 * 安全实现：通过 copy_from_kernel_nofault 读取 next 指针，禁止直接解引用
 * 失败时返回 NULL，调用方需检查返回值
 *
 * 指针校验：next_ptr 必须在 ARM64 内核虚拟地址范围
 *   (>= 0xFFFF000000000000)，否则视为链表损坏，返回 NULL。
 *   这防止 corrupted list_head 导致后续 kf_get_task_comm 等函数
 *   直接解引用无效指针（如 0x540001887100cac7）引发 translation fault。 */
static inline struct task_struct *kpm_next_task(struct task_struct *pos)
{
    uint64_t next_ptr = 0;
    unsigned long addr = (unsigned long)pos + g_tasks_offset;
    struct task_struct *task_ptr;

    if (kf_copy_from_kernel_nofault(&next_ptr, (void *)addr, 8) != 0)
        return NULL;
    /* 校验 next_ptr 是有效的内核地址（ARM64 kernel VA >= 0xFFFF000000000000） */
    if (next_ptr < 0xFFFF000000000000ULL)
        return NULL;
    task_ptr = (struct task_struct *)(next_ptr - g_tasks_offset);
    /* 二次校验：计算出的 task_struct 指针也必须在内核地址范围 */
    if ((uint64_t)task_ptr < 0xFFFF000000000000ULL)
        return NULL;
    return task_ptr;
}
#define KPM_NEXT_TASK(pos) kpm_next_task(pos)

/* ===== 安全 tasklist 基础设施 =====
 * 框架导出的 g_tasks_offset 可能错误，基于它的遍历产生垃圾指针，而
 * 垃圾指针传入内核函数（__task_pid_nr_ns）会 translation fault → panic。
 * 本组函数运行时推导真实 tasks 偏移并逐步校验，任何一步不过即降级：
 *   1) kpm_tasklist_verify：双锚点（init_task→pid1→pid2 fork 序链）
 *      扫描候选偏移，再以"链长 ≥5 个首领后回到表头"判别 tasks 链
 *      （children/sibling 链只有 2 节点，被排除）；
 *   2) kpm_tasklist_next：每步 nofault + next.prev==node 双向校验；
 *   3) kpm_task_tgid：5.9+ 用 __task_pid_nr_ns(PIDTYPE_TGID)（kver 门控，
 *      4.19 无该枚举）。
 * 使用前提：调用方持 RCU 读锁；kpm_tasklist_verify 已成功。 */
extern int g_tasks_offset_verified;   /* 推导的真实 tasks 偏移（-1=失败） */
long kpm_tasklist_verify(void);
struct task_struct *kpm_tasklist_next(struct task_struct *pos);
pid_t kpm_task_tgid(struct task_struct *t);
pid_t kpm_task_pid(struct task_struct *t);   /* 线程 pid（PIDTYPE_PID） */
int kpm_tasklist_ready(void);

/* ===== 安全任务扫描（见 LH_syms.c 注释） =====
 * 遍历 pid 号空间（find_vpid→get_pid_task），对每个活跃任务调 cb。
 * cb(t, nr, ud)：t 持临时引用（需保留自行 get+1）；返回非 0 提前终止。
 * 返回遍历任务数 / cb 终止值 / -1 基础设施不可用。 */
int  kpm_task_scan_available(void);
long kpm_task_scan_by_pid(long (*cb)(struct task_struct *t, pid_t nr, void *ud),
                          void *ud);

/* ===== vm_area_struct 偏移（运行时探测） ===== */
/* 探测到的 vm_area_struct 字段偏移，0 表示未探测到
 * 通过 find_vma(mm,0) 获取首个 VMA 后扫描其内存特征：
 * vm_start 是第一个非零且小于后续 8 字节值的字段 */
extern int g_vm_start_offset;  /* vm_area_struct.vm_start 偏移 */
extern int g_vm_end_offset;    /* vm_area_struct.vm_end 偏移 */
extern int g_vm_next_offset;   /* vm_area_struct.vm_next 偏移 */
extern int g_vm_flags_offset;  /* vm_area_struct.vm_flags 偏移 (VM_READ/WRITE/EXEC 位掩码) */

/* ===== 文件映射路径解析偏移（运行时探测） =====
 * 从 VMA 直接解析文件名（vm_file → file.f_path.dentry → dentry.d_name.name）
 * 纯内存方案，替代被 SELinux enforcing 拒绝的 /proc/<pid>/maps 读取 */
extern int g_vm_file_offset;      /* vm_area_struct.vm_file 偏移（-1=未探测） */
extern int g_file_dentry_offset;  /* struct file.f_path.dentry 偏移 */
extern int g_dentry_name_offset;  /* struct dentry.d_name.name 偏移 */

/* 探测 vm_file/dentry/name 三个偏移（跨 VMA 一致性统计，兼容 5.1-6.x）
 * 返回 0 成功，-1 失败（无文件映射 VMA 时 path 保持为空） */
int kpm_probe_vm_file_offsets(struct mm_struct *mm);

/* 从 VMA 指针解析文件名到 out（纯内存，无 VFS）。返回 0 成功，-1 失败 */
int kpm_vma_get_path(void *vma, char *out, int out_size);

/* 从 VMA 解析文件完整路径（沿 d_parent 链拼接，如 /system/lib64/libx.so）。
 * 用于文件回退 dump（filp_open 读取磁盘上未驻留的页）。返回 0 成功 */
int kpm_vma_get_fullpath(void *vma, char *out, int out_size);

/* 统一的 VMA 查找辅助函数（高兼容性三级回退链）
 * 查找 mm 中第一个 vm_end > addr 的 VMA。
 * @mm: 目标进程 mm_struct
 * @addr: 查找起始地址（0 = 首个 VMA，ve = 下一个 VMA）
 * Returns: VMA 指针，或 NULL（无更多 VMA / 全部回退失败）
 *
 * 回退顺序：
 *   1. find_vma(mm, addr) — 主路径，5.1+ 全版本兼容
 *   2. vm_next 链表遍历 — 回退路径，5.x-6.5 兼容（需已探测偏移）
 *   3. 返回 NULL — 功能禁用
 *
 * 隐蔽性: A 级（所有路径纯内核操作，无 VFS 痕迹） */
void *kpm_find_vma_next(struct mm_struct *mm, uint64_t addr);

/* ===== 符号初始化 ===== */
int kpm_syms_init(void);
void kpm_syms_exit(void);

/* ===== exit 路径 RCU 读锁借出/还回（防 synchronize_rcu 自死锁） =====
 * 框架在 RCU 读临界区内调用模块 exit 时，exit 里 synchronize_rcu /
 * 可睡眠内核调用会 GP 永久等待自身 → 整机冻结。
 * acquire 返回：1=已借出（收尾必须 release）；0=确认不在读临界区（直接
 * 清理）；-1=无法确认安全（禁止一切睡眠清理，跳过+残留警告）。 */
int kpm_rcu_exit_guard_acquire(void);
void kpm_rcu_exit_guard_release(void);

/* ===== VMA 偏移运行时探测（惰性调用） =====
 * 在首次 kpm_proc_maps 调用时通过 find_vma(mm,0) 获取首个 VMA，
 * 扫描其内存特征自动探测 vm_start/vm_end/vm_next 偏移。
 * 调用前需持有 mmap_read_lock（自旋锁语义，禁止睡眠）。
 * 返回 0 成功，负数失败。mm 必须是有效的进程 mm_struct。 */
int kpm_probe_vma_offsets(struct mm_struct *mm);

/* ===== mm_struct.mmap 偏移运行时探测（回退路径使用） =====
 * 扫描 mm_struct 内存查找指向已知 VMA 的指针字段。
 * 成功条件: mm_struct 中存在一个 8 字节字段，其值等于已知的 VMA 地址
 * 5.x-6.0: mm->mmap 是 VMA 链表头（指向第一个 VMA）
 * 6.1+: maple tree 取代链表，此字段不存在，探测自动失败
 * 调用前需持有 RCU 读锁。mm 必须有效，first_vma 必须是 find_vma(mm,0) 的结果。
 * 返回 0 成功，负数失败。 */
int kpm_probe_mm_mmap_offset(struct mm_struct *mm, void *first_vma);

/* ===== arg_start / arg_end 偏移惰性探测 =====
 * 在首次 kpm_proc_list_kernel 调用时触发。
 * 纯内存扫描 mm_struct 找 arg_start/arg_end 候选对，并读取
 * [arg_start, arg_end) 验证为合法字符串（不依赖 filp_open）。
 * 探测成功后缓存，后续全部走纯内存路径。返回 0 成功，负数失败。 */
int kpm_probe_arg_offsets(void);

#ifdef __cplusplus
}
#endif

#endif /* KPM_SYMS_H */