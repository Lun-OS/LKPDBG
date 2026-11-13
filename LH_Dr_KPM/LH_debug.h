/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_DEBUG_H_
#define _KPM_DEBUG_H_

#include <ktypes.h>
#include <stdint.h>
#include "LH_comm.h"

/* ===== Debug & Breakpoint System =====
 * Memory breakpoints (page read-only), hardware breakpoints (ARM64 debug regs),
 * and single-step support.
 */

#define KPM_DEBUG_MAX_BREAKPOINTS 16
#define KPM_DEBUG_MAX_WATCHPOINTS 8

/* Breakpoint types */
#define KPM_BP_TYPE_SOFTWARE    0   /* software breakpoint (BKPT instruction) */
#define KPM_BP_TYPE_HW_EXEC     1   /* hardware execution breakpoint (ARM64 debug regs) */
#define KPM_BP_TYPE_HW_WRITE    2   /* hardware write watchpoint */
#define KPM_BP_TYPE_HW_RW       3   /* hardware read/write watchpoint */
#define KPM_BP_TYPE_MEMORY      4   /* memory breakpoint (PTE read-only) */

/* A single breakpoint/watchpoint entry */
typedef struct {
    int      enabled;
    pid_t    pid;
    uint64_t addr;
    uint64_t size;       /* watch size: 1/2/4/8 bytes (hardware) or page (memory) */
    int      type;       /* KPM_BP_TYPE_* */
    int      hit_count;
    uint32_t saved_orig; /* software bp: saved original instruction */
    uint64_t saved_pte;  /* memory bp: saved original PTE */
    uint64_t saved_pgd;  /* memory bp: page table root */
    uint64_t perf_event; /* hw bp: perf_event pointer (opaque) */
    int      hw_reg_idx;  /* hw bp: hardware register index; always -1 (no direct-register path). BRP/WRP slot limits are determined by runtime probing. */
    int      notify;      /* 命中时 UDP 通知客户端（1=启用） */
} kpm_breakpoint_t;

/* Breakpoint hit info (returned to userspace) */
typedef struct {
    int      bp_index;   /* which breakpoint was hit */
    pid_t    pid;        /* target process PID */
    uint64_t addr;       /* address that triggered the hit */
    uint64_t pc;         /* program counter at hit */
    uint64_t value;      /* value being written (write bp) */
} kpm_bp_hit_t;

/* Initialize debug module */
long kpm_debug_init(void);

/* ===== 能力查询（FEAT 降级上报） =====
 * hwbp_status: 0=未探测 1=可用 2=不可用；sync_ok: 同步停靠基础设施；
 * wq_ok: 命中通知工作队列。任一缺失时 DEBUG 单元应上报 DEGRADED。 */
int kpm_debug_hwbp_status(void);
int kpm_debug_sync_ok(void);
int kpm_debug_wq_ok(void);

/* KPM_FEAT_DEBUG 降级原因位（FEAT_LIST.reason） */
#define KPM_DEBUG_DEG_HWBP  0x1u   /* PMU 探测失败/符号缺失，硬件断点不可用 */
#define KPM_DEBUG_DEG_WQ    0x2u   /* 通知 workqueue 不可用（异步通知缺失） */
#define KPM_DEBUG_DEG_SYNC  0x4u   /* 同步停靠基础设施缺失（仅 async） */

/* Exit debug module (clear all breakpoints) */
void kpm_debug_exit(void);

/* Set a breakpoint/watchpoint.
 * pid: target process PID (0 = kernel)
 * type: KPM_BP_TYPE_*
 * addr: target address
 * size: watch size (for hardware watchpoints: 1/2/4/8; for memory: page-aligned)
 * Returns breakpoint index >= 0, or negative on error */
long kpm_debug_bp_set(pid_t pid, int type, uint64_t addr, uint64_t size);

/* 内核/宽硬件断点（force）。仅 W/RW 数据观察安全；
 * X 内核执行断点无安全 PC 推进，返回 -KPM_E_DISABLED。 */
long kpm_debug_bp_set_kernel(uint64_t addr, int type, uint64_t size,
                             uint64_t flags);
int  kpm_debug_bp_limits(int *brp, int *wrp);

/* 带 flags 的用户断点（增强调试）。
 * size_flags = size | (flags16 << 32)，flags16 = 低 8 位 flags +
 * bit8-15 MAX_HITS（见 KPM_BP_FLAG_*）。
 * AUTO_CLEAR / MAX_HITS 在命中后由工作队列延迟拆点（异常上下文不能
 * unregister）。EXEC_INST（真执行不跳 PC）需要 force STEP：非 force
 * 返回 -KPM_E_PERM；硬件/单步不可用时 -KPM_E_DISABLED。 */
long kpm_debug_bp_set_flags(pid_t pid, int type, uint64_t addr,
                            uint64_t size_flags);
/* 断点能力/容量查询（BRP/WRP、已用槽位、step/sync 可用性） */
long kpm_debug_bp_info(kpm_bp_caps_t *out);

/* 用户单步 / 指令级 step trace（依赖 register_user_step_hook）。
 * STEP_TRACE(pid, tid, count)：在目标返回用户态时置 PSTATE.SS，逐条记录
 * 34 个寄存器快照（最多 KPM_STEP_RING_MAX=256 条），返回槽位 id。
 * 单步基础设施不可用（<5.10）→ -KPM_E_DISABLED。
 * STEP_FETCH：拉取快照环（kpm_trap_regs_t，272B/条），返回条数。
 * kpm_debug_step_stop：提前结束对应 tid 的步进（CONTINUE 调用）。 */
long kpm_debug_step_trace(pid_t pid, pid_t tid, uint32_t count);
long kpm_debug_step_fetch_kernel(void *dst, int max_count);
long kpm_debug_step_fetch_user(void *dst, int max_count);
long kpm_debug_step_stop(pid_t tid);

/* ===== 断点命中寄存器篡改 =====
 * 在 kpm_debug_bp_set 基础上附加"命中后篡改寄存器"规则：
 *   reg_mask:   bit i (0-30) = 篡改 X0-X30；bit31=SP；bit32=PC；bit33=PSTATE
 *   fp_mask:    bit i (0-31) = 篡改 V0-V31（fpsimd_state，受门控，见下）
 *   regs_to_set_user: 用户态寄存器快照指针，
 *     仅拷贝 mask 对应字段；NULL 则使用全 0 值
 *   命中时（perf overflow 异常上下文）按规则改写目标线程 pt_regs，
 *   异常返回后生效。
 *
 *   FP/SIMD 篡改门控：ARM64 下需访问 current->thread.uw.fpsimd_state.vregs，
 *   偏移随内核版本变化，需按目标内核验证后由编译宏或运行时探测确认；
 *   g_fpsimd_vregs_offset 未确认（0）时 fp_mask 被忽略
 *   （仅 GP/SP/PC/PSTATE 生效），防偏移错误在异常上下文写坏
 *   task_struct（稳定性红线）。
 *
 *   命令层使用「regmod 窗口」模式（prctl 标量参数无法携带结构体）：
 *     kpm_debug_bp_regmod_set() 预置窗口 → kpm_debug_bp_set_ex()/modify() 消费 */
long kpm_debug_bp_regmod_set(uint64_t reg_mask, uint64_t fp_mask,
                             const void *regs_to_set_user);

/* 安装断点 + 应用窗口篡改规则（窗口无效则等同普通 bp_set）。
 * 返回断点 index >= 0，或负错误码。 */
long kpm_debug_bp_set_ex(pid_t pid, int type, uint64_t addr, uint64_t size);

/* 用窗口规则动态更新断点篡改 */
long kpm_debug_bp_modify(int index);

/* 读取单断点命中计数。
 * total: 自安装以来累计命中；pending: 保留（转换层按 last_read 计算） */
long kpm_debug_bp_get_hit_count(int index, uint64_t *total, uint64_t *pending);

/* Clear a breakpoint by index.
 * Returns 0 on success, negative on error */
long kpm_debug_bp_clear(int index);

/* Copy breakpoint list to user buffer.
 * Returns number of entries, or negative on error */
long kpm_debug_bp_copy_list(kpm_breakpoint_t *user_buf, int max_count);

/* UDP 通道版（resp_data 为内核缓冲，不能用 copy_to_user） */
long kpm_debug_bp_copy_list_kernel(void *kbuf, int max_count);

/* Copy breakpoint hit info to user buffer.
 * Returns 0 on success, negative on error */
long kpm_debug_bp_copy_hit(kpm_bp_hit_t *user_buf);

/* 当前启用断点数（UN_HOOK 用） */
int kpm_debug_bp_count_active(void);

/* UDP 通道版（resp_data 为内核缓冲，不能用 copy_to_user） */
long kpm_debug_bp_copy_hit_kernel(void *kbuf);

/* 断点命中通知开关。
 * enable: 1=启用 0=停用。client_addr 非空时记录为通知目标（UDP 通道
 * 传 recvfrom 源地址）；prctl 通道可传 NULL 复用上次记录的地址。
 * 启用后任何 notify=1 的断点命中都会异步推送 UDP 通知给目标地址。 */
long kpm_debug_bp_notify_set(int enable, void *client_addr, int port);

/* Single step a thread (ARM64: set MDSCR_EL1.SS bit).
 * pid: target process PID
 * tid: target thread TID
 * Returns 0 on success, negative on error */
long kpm_debug_single_step(pid_t pid, pid_t tid);

/* Continue execution (clear single-step flag).
 * pid: target process PID
 * tid: target thread TID
 * Returns 0 on success, negative on error */
long kpm_debug_continue(pid_t pid, pid_t tid);

/* ===== 同步断点（命中停靠 + GET/SET/RESUME 闭环） =====
 * 机制：EL0 命中 → 异常上下文保存 34×u64 快照 →
 * task_work_add（TIF_NOTIFY_RESUME）→ 目标线程在返回用户态边界
 * （进程上下文，可睡眠）停靠等待；异常返回前【不执行任何用户指令】。
 * 停靠循环：schedule_timeout_interruptible(100ms) 轮询放行标志/超时/
 * 客户端 RESUME 唤醒（wake_up_process，放行延迟=立即，100ms 只影响
 * 超时精度）。放行时把 SET_CONTEXT 的修改写入停靠点 pt_regs，
 * PC 未被改写则 +4 跳过命中指令（与 async 语义一致）。
 *
 * 兼容性退回：task_work_add/schedule_timeout_interruptible/
 * msecs_to_jiffies/wake_up_process 任一缺失 →
 * g_sync_ok=0，SET_SYNC 返回 -KPM_E_DISABLED，async 路径不受影响；
 * 停靠槽满/任务已退出（task_work_add 返回非 0）→ 该次命中自动落回
 * async 语义，功能不丢失。
 * 安全性：仅 EL0 命中停靠（pstate M[3:0]==0 门控，与 regmod 一致）；
 * 停靠点 pt_regs 指针在目标线程自身内核栈上，停靠期间恒有效。 */
long kpm_debug_bp_set_sync(pid_t pid, int type, uint64_t addr, uint64_t size,
                           uint32_t timeout_ms);
long kpm_sync_trap_get(int trap_id, void *user_buf);          /* prctl 通道 */
long kpm_sync_trap_get_kernel(void *kbuf, int trap_id);       /* UDP 通道 */
long kpm_sync_trap_set(int trap_id, uint64_t reg_mask, const void *user_buf);
long kpm_sync_trap_set_kernel(int trap_id, uint64_t reg_mask, const void *kbuf);
long kpm_sync_trap_resume(int trap_id, uint64_t flags);  /* 0xFFFFFFFF=全部；flags bit0=EXEC_INST */
long kpm_sync_trap_list(kpm_trap_info_t *user_buf, int max_count);
long kpm_sync_trap_list_kernel(void *kbuf, int max_count);
int  kpm_sync_trap_release_all(void);    /* 卸载/清断点：放行全部停靠 */
int  kpm_sync_available(void);           /* 能力查询：1=同步模式可用 */

/* ===== 无痕 hook（BRP 重定向）命中规则 =====
 * 原语（内核态命中处理器执行，代码零修改）：
 *   OBSERVE  仅统计/通知（KBPN 异步推送）
 *   ARG_MOD  改写 X0-X7（arg_mask 选中项 = args[]）
 *   RET_MOD  跳过函数：x0=aux、pc=lr（x30）——调用方拿到伪返回值
 *   REDIRECT 跳转：pc=aux（客户端预先写入目标进程的 trampoline 地址；
 *            trampoline 执行后如何回到原函数由客户端布局——原函数
 *            未被修改，直接调用原入口会再次命中本断点，需客户端
 *            在 trampoline 内处理（如跳原函数+4 并自拟序言补偿））
 * auto_apply=1：命中即应用 + PC 语义处理（未改 PC 则 +4 跳过）+ 异步
 *   通知，目标不停靠（µs 级开销）——适合 ARG_MOD/RET_MOD/REDIRECT。
 * auto_apply=0：走同步停靠，客户端 GET/SET/RESUME
 *   完全接管——适合观察后人工决策。
 * 风险注释：命中时序 µs 级可被高精度计时侧信道察觉；EL0 无法读取
 * 调试寄存器，代码零修改不可被完整性校验发现。 */
#define KPM_HOOK_ACT_OBSERVE   0
#define KPM_HOOK_ACT_ARG_MOD   1
#define KPM_HOOK_ACT_RET_MOD   2
#define KPM_HOOK_ACT_REDIRECT  3

typedef struct {
    int      active;
    int      auto_apply;
    int      action;      /* KPM_HOOK_ACT_* */
    uint64_t arg_mask;    /* ARG_MOD：bit i = 改写 Xi（0-7） */
    uint64_t args[8];     /* ARG_MOD：X0-X7 新值 */
    uint64_t aux;         /* RET_MOD：x0 伪返回值；REDIRECT：目标地址 */
} kpm_bp_hook_rule_t;

/* 设置/清除断点上的 hook 规则（index 为 bp_set 返回的槽位）。
 * 规则与同步模式互斥：设置规则前 bp 必须存在且未开启 sync 停靠语义
 * （auto_apply=1 时命中走自动路径；=0 时等同同步断点）。 */
long kpm_debug_bp_hook_rule_set(int index, const kpm_bp_hook_rule_t *r);

/* hook 规则状态查询（hook2 引擎 LIST/卸载用）：1=active 0=inactive */
int kpm_debug_bp_hook_state(int index, pid_t *pid, uint64_t *addr,
                            int *action, uint64_t *hit_count);

#endif /* _KPM_DEBUG_H_ */