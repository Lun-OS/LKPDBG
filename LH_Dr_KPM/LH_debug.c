/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_debug.c - Complete debug/breakpoint system
 *
 * Breakpoint types:
 *   KPM_BP_TYPE_SOFTWARE (0)  - Software BKPT instruction (ARM64: 0xD4200000)
 *   KPM_BP_TYPE_HW_EXEC  (1)  - Hardware execution breakpoint (ARM64 debug regs)
 *   KPM_BP_TYPE_HW_WRITE (2)  - Hardware write watchpoint
 *   KPM_BP_TYPE_HW_RW    (3)  - Hardware read/write watchpoint
 *   KPM_BP_TYPE_MEMORY   (4)  - Memory breakpoint (PTE write-protect)
 *
 * Software BKPT: this path is disabled — sw_bp_set() returns -KPM_E_INVAL.
 *   Writing 0xD4200000 into the target .text would break code integrity
 *   and raise a Debug exception the module has no handler for. Use hardware
 *   breakpoints (KPM_BP_TYPE_HW_EXEC) instead.
 *
 * Hardware breakpoint: uses kernel perf_event API (register_user_hw_breakpoint)
 *   if available. Falls back to note that HW BP is unavailable.
 *
 * Memory breakpoint: walks target process page table, clears PTE write bit
 *   to make the page read-only, saving original PTE for restore.
 *
 * Stealth: all operations use kpm_log (internal buffer). No dmesg/printk.
 *          No new /proc or sysfs entries. Debug register operations are
 *          atomic and leave no persistent state visible to userspace.
 *
 * IMPORTANT: Hardware breakpoints set via register_user_hw_breakpoint() are
 * bound to the target task_struct. If the target process exits before the
 * breakpoint is explicitly cleared via kpm_debug_bp_clear(), the perf_event
 * will be leaked — the kernel holds a reference to the task, preventing
 * full cleanup. Users MUST explicitly clear all breakpoints before the
 * target process exits. On module unload, kpm_debug_exit() clears all
 * remaining breakpoints.
 */
#include <ktypes.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <baselib.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <asm/ptrace.h>
#include <asm/processor.h>   /* task_pt_regs（自由单步返回现场） */

#include "LH_comm.h"
#include "LH_debug.h"
#include "LH_trace.h"
#include "LH_force.h"   /* force 能力校验（增强断点） */
#include "LH_syms.h"
#include "LH_mem_rw.h"
#include "LH_log.h"
#include "LH_udp.h"     /* kpm_udp_notify_send（断点命中通知） */
#include "LH_utils.h"  /* kpm_spinlock_t 等 */

/* ARM64 BKPT #0 instruction: 0xD4200000 (little-endian) */
#define ARM64_BKPT_INSN  0xD4200000

/* ===== perf_event_attr（uapi 稳定布局子集） =====
 * 用于 register_user_hw_breakpoint（真实签名 (attr,triggered,context,tsk)）。
 * 布局取自 include/uapi/linux/perf_event.h 64 位版本（4.x-6.x 稳定）。
 * 本地结构体为 128B（PERF_ATTR_SIZE_VER5）；attr.size 字段由 init 探测
 * 变体填入 72（VER2）或 128（VER5），内核按 size 截断使用。
 * 关键字段：type=PERF_TYPE_BREAKPOINT(5)、bp_type=HW_BREAKPOINT_X(4)/
 * R(1)/W(2)/RW(3)、bp_addr=用户 VA、bp_len=1（执行断点强制 1）、
 * flags.exclude_kernel=1（只监控用户态）、
 * sample_period 必须非 0（见下方 KPM_BP_SAMPLE_PERIOD 注释）。
 * uapi enum hw_breakpoint_hw_type：EMPTY=0, R=1, W=2, RW=3, X=4。 */
#define KPM_PERF_TYPE_BREAKPOINT  5
#define KPM_HW_BREAKPOINT_EMPTY   0
#define KPM_HW_BREAKPOINT_R       1
#define KPM_HW_BREAKPOINT_W       2
#define KPM_HW_BREAKPOINT_RW      3
#define KPM_HW_BREAKPOINT_X       4
#define KPM_PERF_ATTR_SIZE        72

/* overflow 回调门控：sample_period 必须非 0，否则 overflow_handler 不触发。
 * __perf_event_overflow() 开头即
 *   if (unlikely(!is_sampling_event(event))) return 0;
 * hw_breakpoint_add() 也只在 is_sampling_event(bp) 时装载周期；
 * is_sampling_event() 等价于 sample_period != 0。
 * sample_period 为 0 时 register 与 perf_event_enable 均成功、硬件也触发
 * 调试异常，但 kpm_debug_bp_on_hit 永不被调用（hit_count 恒 0、无通知、
 * regmod 失效）。取 1 表示每次命中都回调，与单步/改寄存器语义一致。 */
#define KPM_BP_SAMPLE_PERIOD      1
#define KPM_PERF_SAMPLE_IP        (1ULL << 3)

struct kpm_perf_event_attr {
    uint32_t type;          /* +0  */
    uint32_t size;          /* +4  */
    uint64_t config;        /* +8  */
    uint64_t sample_period; /* +16 */
    uint64_t sample_type;   /* +24 */
    uint64_t read_format;   /* +32 */
    uint64_t flags;         /* +40 （位域：disabled=bit0, exclude_kernel=bit5,
                                     exclude_hv=bit6, exclude_user=bit4） */
    uint32_t wakeup_events; /* +48 */
    uint32_t bp_type;       /* +52 */
    uint64_t bp_addr;       /* +56 */
    uint64_t bp_len;        /* +64 */
    uint64_t branch_sample_type; /* +72 （断点事件必须为
                                   PERF_SAMPLE_BRANCH_NO_SAMPLE，否则
                                   hw_breakpoint_event_init 返回 -EOPNOTSUPP） */
    uint64_t sample_regs_user;   /* +80 */
    uint32_t sample_stack_user;  /* +88 */
    int32_t  clockid;            /* +92 */
    uint64_t sample_regs_intr;   /* +96 */
    uint32_t aux_watermark;      /* +104 */
    uint16_t sample_max_stack;   /* +108 */
    uint16_t __reserved_2;       /* +110 */
    uint32_t aux_sample_size;    /* +112 */
    uint32_t __reserved_3;       /* +116 */
    uint64_t sig_data;           /* +120 */
};  /* sizeof = 128 = PERF_ATTR_SIZE_VER5 */

/* 断点命中通知（UDP 推送，独立事件流，非流式协议）
 * 格式：32 字节定长，客户端按此解析。 */
typedef struct {
    uint32_t magic;     /* 'KBPN' = 0x4B504E */
    uint32_t bp_index;  /* 断点槽位 */
    pid_t    pid;       /* 目标进程 */
    uint64_t addr;      /* 命中地址 */
    uint64_t hit_count; /* 累计命中数 */
} kpm_bp_notify_t;

/* ===== 断点命中通知机制 =====
 * 命中回调（IRQ/异常上下文）→ 置 pending + queue_work（复用 tvpush 模式，
 * IRQ 安全，无 sleep）→ work 打包 kpm_bp_notify_t → kpm_udp_notify_send。 */
static volatile int g_bp_notify_enabled = 0;
static volatile int g_bp_notify_pending = 0;
/* 通知 work 在途标记：queue 前置 1、work 退出置 0。
 * kpm_debug_exit 以非睡眠有界自旋等待其归零，不能用 flush_workqueue
 * （wait_for_completion 可睡眠，在 RCU 读临界区卸载会触发
 * rcu_note_context_switch WARNING）。 */
static volatile int g_bp_work_live = 0;
static struct kpm_sockaddr_in g_bp_notify_client;
static kpm_breakpoint_t g_bps[KPM_DEBUG_MAX_BREAKPOINTS];
static int g_bp_kind[KPM_DEBUG_MAX_BREAKPOINTS];  /* 0=user, 1=wide kernel */
/* 每槽 flags / MAX_HITS / 延迟拆点标记 */
static uint32_t g_bp_flags[KPM_DEBUG_MAX_BREAKPOINTS];
static uint32_t g_bp_maxhits[KPM_DEBUG_MAX_BREAKPOINTS];
static volatile uint8_t g_bp_clear_pending[KPM_DEBUG_MAX_BREAKPOINTS];
static kpm_bp_hit_t g_bp_hit;
static kpm_spinlock_t g_debug_lock = KPM_SPINLOCK_INIT;
static volatile int g_debug_busy = 0;
static struct kpm_work_struct g_bp_work;
static struct kpm_workqueue_struct *g_bp_wq = 0;
/* breakpoint PMU 运行时探测结果（0=未探测 1=可用 2=不可用） */
static volatile int g_hwbp_pmu_status = 0;
/* 探测成功的 attr 组合（BP_SET 复用，见 kpm_debug_init） */
static struct kpm_perf_event_attr g_hwbp_attr;

/* ===== 断点命中寄存器篡改规则 =====
 * 内核私有扩展表（不进 BP_LIST 输出，不影响现有协议/客户端）。
 * 命中回调（异常上下文）直接读本表改写 pt_regs，不访问用户内存。 */
typedef struct {
    uint32_t active;          /* 1 = 存在篡改规则 */
    uint64_t reg_mask;        /* bit i(0-30)=X0-X30；bit31=SP；bit32=PC；bit33=PSTATE */
    uint64_t fp_mask;         /* bit i(0-31)=V0-V31（受 g_fpsimd_vregs_offset 门控） */
    uint64_t regs[31];        /* X0-X30 篡改值 */
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
    uint8_t  vregs[32][16];   /* 浮点篡改值（仅 fp_mask 对应项有效） */
} kpm_bp_regmod_t;
static kpm_bp_regmod_t g_bp_regmod[KPM_DEBUG_MAX_BREAKPOINTS];

/* fpsimd_state.vregs 相对 task_struct 偏移（ARM64：MRS SP_EL0 = current）。
 * 0 = 未确认（禁用 FP 篡改）。偏移随内核版本变化，需按目标内核验证后
 * 通过编译宏或运行时探测启用（防异常上下文写坏 task_struct）。 */
#ifndef KPM_FPSIMD_VREGS_OFFSET
#define KPM_FPSIMD_VREGS_OFFSET  0
#endif
static int g_fpsimd_vregs_offset = KPM_FPSIMD_VREGS_OFFSET;

/* pt_regs 关键偏移（ARM64 ABI，perf overflow 回调 regs 参数） */
#define KPM_PT_REGS_SP_OFF      (31 * 8)    /* 248 */
#define KPM_PT_REGS_PC_OFF      (31 * 8 + 8) /* 256 */
#define KPM_PT_REGS_PSTATE_OFF  (31 * 8 + 16)/* 264 */
/* 寄存器掩码位 */
#define KPM_REG_MODIFY_SP       (1ULL << 31)
#define KPM_REG_MODIFY_PC       (1ULL << 32)
#define KPM_REG_MODIFY_PSTATE   (1ULL << 33)
/* 用户寄存器快照字段偏移 */
#define KPM_UREGS_SP_OFF        248
#define KPM_UREGS_PC_OFF        256
#define KPM_UREGS_PSTATE_OFF    264
#define KPM_UREGS_VREGS_OFF     288

/* 应用寄存器篡改（前向声明，实现在 kpm_debug_bp_on_hit 之后） */
static void kpm_debug_bp_apply_regmod(int idx, void *regs);

/* ===== 同步断点停靠 =====
 * 命中 → 快照 + task_work 入队 → 目标线程在用户态边界（进程上下文）
 * 停靠 → 客户端 GET/SET/RESUME → 放行（写回 pt_regs + PC+4 skip）。
 * 目标线程停靠期间不执行任何用户指令；/proc 显示 S（可睡眠边界）。
 * 必然暴露面：停靠窗口线程冻结（超时可配兜底）、
 * 命中时序 µs 级可侧信道感知。 */
typedef struct {
    void *next;                 /* struct callback_head ABI（16B，两指针） */
    void (*func)(void *);
} kpm_callback_head_t;

typedef struct {
    kpm_callback_head_t work;   /* 必须为首成员：head 指针即槽位指针 */
    volatile int state;         /* KPM_TRAP_ST_* */
    int      bp_index;
    pid_t    pid;
    void    *task;              /* 停靠线程（持 task_struct 引用，放行时归还） */
    void    *live_regs;         /* 停靠点 pt_regs（目标线程内核栈顶，停靠期恒有效） */
    uint64_t regs[KPM_TRAP_REGS_LEN];  /* 命中快照：regs[31]/sp/pc/pstate */
    uint64_t mod[KPM_TRAP_REGS_LEN];   /* SET_CONTEXT 待应用值（同布局） */
    uint64_t mod_mask;
    uint64_t addr;
    uint64_t hit_count;
    uint32_t timeout_ms;
    uint32_t exec_inst;   /* RESUME flags bit0=单步执行命中指令 */
} kpm_sync_trap_t;

static kpm_sync_trap_t g_traps[KPM_SYNC_TRAP_MAX];
static volatile int g_sync_ok = 0;          /* 基础设施自检结论（init 时判定） */
/* 每断点同步属性（内核私有并行表——kpm_breakpoint_t 是 72B 协议结构，
 * 加字段会改 ABI，客户端不兼容，故不并入） */
static uint8_t  g_bp_sync[KPM_DEBUG_MAX_BREAKPOINTS];
static uint32_t g_bp_timeout[KPM_DEBUG_MAX_BREAKPOINTS];
/* 无痕 hook 规则（与 sync 互斥，bp_clear 一并清除） */
static kpm_bp_hook_rule_t g_bp_hook[KPM_DEBUG_MAX_BREAKPOINTS];
/* 同步命中通知：复用 bp 通知 workqueue，'KBPT' 48B 数据报带 trap_id。
 * g_bp_work_live 在途时不再排队（work 单发），客户端以 TRAP_LIST 兜底发现。 */
typedef struct {
    uint32_t magic;         /* 'KBPT' = 0x4B5054 */
    uint32_t trap_id;
    int32_t  bp_index;
    pid_t    pid;
    uint64_t addr;
    uint64_t hit_count;
    uint64_t pc;
    uint64_t timeout_ms;
} kpm_trap_notify_t;        /* 48B */
static volatile int g_trap_notify_pending;
static volatile int g_trap_notify_slot;

static void kpm_sync_trap_run(void *arg);            /* task_work 回调 */
static int  kpm_sync_trap_arm(int bp_idx, void *regs); /* 持 g_debug_lock 调用 */

/* ===== 软件单步舞步（真执行语义） =====
 * ARM64 BRP 在指令执行【前】触发——"观察/改参后继续"只有两条路：
 *   ① PC+4 跳过（指令不提交），语义有损；
 *   ② 软件单步：命中处理器内 SPSR.SS=1 + MDSCR.SS=1 → eret → 指令
 *      【真正执行】→ Software Step 异常（仅本任务，官方
 *      register_user_step_hook 链）→ 本模块回调恢复原状。
 * 步进异常由每任务私有的 PSTATE.SS 触发（随异常保存/恢复），MDSCR
 * 置位窗口内其他任务（PSTATE.SS=0）不受影响；内核态运行时 PSTATE.D
 * 掩蔽一切调试异常。single_step_handler 对 user 步进走 user_step_hook
 * 链，hook 返回 DBG_HOOK_HANDLED(0) 即不发 SIGTRAP。
 * 摘武装/恢复武装直查 DBGBCR/DBGDVR 寄存器对（MRS/MSR，无符号依赖，
 * 按 DBGDVR==命中地址匹配；关中断自旋锁内不得调用会触发 IPI 或改写
 * 内核 text 的接口，故不用 perf API）。 */
typedef struct {
    void *next, *prev;                       /* list_head（内核覆写） */
    long (*fn)(void *regs, unsigned long esr);
} kpm_step_hook_t;

typedef struct {
    void *task;       /* 武装时的 current（值比较，不持引用） */
    void *regs;       /* 武装时的 pt_regs（退出兜底清 SS 位用，nofault） */
    int   bp_idx;     /* 来源断点 */
    int   is_wrp;     /* 摘的是观察点(1)还是断点(0) */
    uint64_t saved_cr;/* 摘武装时的 DBGxCR 原值（恢复用） */
    int   active;
} kpm_dbg_step_t;

#define KPM_DBG_STEP_MAX   8
#define KPM_DBG_SPSR_SS    (1ULL << 21)
#define KPM_DBG_MDSCR_SS   (1ULL << 0)
#define KPM_DBG_HOOK_HANDLED 0
#define KPM_DBG_HOOK_ERROR   1

static kpm_step_hook_t g_step_hook = { 0, 0, 0 };
static kpm_dbg_step_t g_steps[KPM_DBG_STEP_MAX];
static volatile int g_step_ok = 0;           /* register_user_step_hook 可用 */

/* ===== 自由单步 / 指令级 step trace =====
 * 与断点步进（g_steps）分离：无断点槽位，由 task_work 在目标返回用户态时
 * 设置 PSTATE.SS，每次硬件单步异常在 kpm_dbg_step_cb 记录 34 寄存器快照
 * 并重新置 SS，直到 count 用完。快照环独立锁，命令上下文拉取。 */
#define KPM_FREESTEP_MAX 4
typedef struct {
    int      active;
    pid_t    tid;
    struct task_struct *task;
    kpm_callback_head_t work;   /* task_work ABI（非 workqueue） */
    uint32_t remain;
    uint32_t recs;
} kpm_freestep_t;

static kpm_freestep_t g_freestep[KPM_FREESTEP_MAX];
static kpm_trap_regs_t g_step_ring[KPM_STEP_RING_MAX];
static kpm_spinlock_t g_step_ring_lock = KPM_SPINLOCK_INIT;
static uint32_t g_step_ring_head, g_step_ring_tail, g_step_ring_count;
static uint64_t g_step_ring_dropped;

static void kpm_freestep_run(void *work);

static long kpm_dbg_step_cb(void *regs, unsigned long esr);
static int  kpm_dbg_hw_disarm_by_addr(uint64_t addr, int *is_wrp,
                                      uint64_t *saved_cr, int *saved_slot);
static void kpm_dbg_hw_rearm(uint64_t addr, int is_wrp, uint64_t saved_cr);

static inline void kpm_dbg_mdscr_ss(int on)
{
    uint64_t v;
    asm volatile("mrs %0, mdscr_el1" : "=r"(v));
    v = on ? (v | KPM_DBG_MDSCR_SS) : (v & ~KPM_DBG_MDSCR_SS);
    asm volatile("msr mdscr_el1, %0" :: "r"(v));
}

static inline int kpm_dbg_hw_brp_count(void)
{
    uint64_t dfr;
    asm volatile("mrs %0, id_aa64dfr0_el1" : "=r"(dfr));
    return (int)((dfr >> 4) & 0xF) + 1;      /* BRPs 字段 bits[7:4] */
}

static inline int kpm_dbg_hw_wrp_count(void)
{
    uint64_t dfr;
    asm volatile("mrs %0, id_aa64dfr0_el1" : "=r"(dfr));
    return (int)((dfr >> 12) & 0xF) + 1;     /* WRPs 字段 bits[15:12] */
}

/* ===== 调试寄存器真实上限探测 =====
 * ID_AA64DFR0 报告的 WP 数可能与实际实现不符（EL2 虚报），直读未实现
 * 槽位会触发 UNDEFINED 异常且 EL1 无恢复手段。故 debug init 时用内核
 * 官方 undef_hook（按指令值匹配 MRS + PC 范围二次确认）带恢复地逐槽
 * 探测 BRP/WRP 真实上限并缓存；运行时扫描永不越界。 */
/* struct undef_hook 官方布局（5.9+ 一致）：
 * {node; u32 instr_mask; u32 instr_val; u64 pstate_mask; u64 pstate_val; fn}。
 * call_undef_hook 在偏移 40 读 fn，并做 (pstate & pstate_mask)==
 * pstate_val 匹配；布局不符会导致 hook 永不命中、探测 MRS 直接 SIGILL。 */
typedef struct {
    void *next, *prev;
    uint32_t instr_mask;
    uint32_t instr_val;
    uint64_t pstate_mask;   /* 0 = 任意 PSTATE（内核态/用户态均匹配） */
    uint64_t pstate_val;
    int (*fn)(void *regs, uint32_t instr);
} kpm_undef_hook_t;

static kpm_undef_hook_t g_uhook;
static volatile int g_undef_hit;
static volatile uint64_t g_undef_pc_lo, g_undef_pc_hi;
static int g_hw_brp_limit = 0;   /* 探测到的真实上限（0=未探测） */
static int g_hw_wrp_limit = 0;

/* 返回值语义：fn 返回 0 = 已处理（do_undefinstr 见 0 即正常返回，
 * PC 由本函数自行推进 +4）；非 0 = 未处理 → 内核态
 * die("Oops - Undefined instruction") panic。 */
static int kpm_dbg_undef_fn(void *regs_v, uint32_t instr)
{
    uint64_t *r = (uint64_t *)regs_v;
    uint64_t pc = r[KPM_PT_REGS_PC_OFF / 8];

    (void)instr;
    if (pc >= g_undef_pc_lo && pc < g_undef_pc_hi) {
        r[KPM_PT_REGS_PC_OFF / 8] = pc + 4;   /* 跳过未实现的 MRS */
        g_undef_hit = 1;
        kpm_printk("LH_dbg: undef handled pc=%llx\n", pc);
        return 0;   /* 0 = 已处理 */
    }
    kpm_printk("LH_dbg: undef PASS pc=%llx win=%llx-%llx\n",
               pc, g_undef_pc_lo, g_undef_pc_hi);
    return 1;   /* 非 0 = 未处理 → 内核默认路径 */
}

/* undef 探测版本门控：仅内核 ≥ 5.10 启用。
 * 5.10/6.1 call_undef_hook 对内核态 undef 用 get_kernel_nofault 读
 * 指令后咨询 hook 链；4.19 对内核态 undef 直接 return 1（不咨询
 * hook），探测 MRS 必 panic → 4.x 必须 fail-closed 禁用探测（step 同禁）。 */
static int kpm_dbg_kver_ge_5_10(void)
{
    static const char pfx[] = "Linux version ";
    const char *b = kf_linux_banner;
    int a = 0, m = 0;
    int i;

    if (!b)
        return 0;
    for (i = 0; pfx[i]; i++)
        if (b[i] != pfx[i])
            return 0;
    b += i;
    while (*b >= '0' && *b <= '9') a = a * 10 + (*b++ - '0');
    if (*b++ != '.')
        return 0;
    while (*b >= '0' && *b <= '9') m = m * 10 + (*b++ - '0');
    return (a > 5) || (a == 5 && m >= 10);
}

/* 调试寄存器编码（generic 语法，binutils 不认 dbgdvr 命名）：
 *   DBGBVR<n>_EL1 = s2_0_c0_c<n>_4   DBGBCR<n>_EL1 = s2_0_c0_c<n>_5
 *   DBGWVR<n>_EL1  = s2_0_c0_c<n>_6   DBGWCR<n>_EL1 = s2_0_c0_c<n>_7 */
#define KPM_DBG_RD(_n, _op2, _val)                                   \
    asm volatile("mrs %0, s2_0_c0_c" #_n "_" #_op2 : "=r"(_val))
#define KPM_DBG_WR(_n, _op2, _val)                                   \
    asm volatile("msr s2_0_c0_c" #_n "_" #_op2 ", %0" :: "r"(_val))

#define KPM_DBG_PROBE_FN(_name, _op2)                                   \
    static uint64_t __attribute__((noinline)) _name(int n)                               \
    {                                                                   \
        uint64_t v = 0;                                                 \
        switch (n) {                                                    \
        case 0:  KPM_DBG_RD(0, _op2, v); break;                         \
        case 1:  KPM_DBG_RD(1, _op2, v); break;                         \
        case 2:  KPM_DBG_RD(2, _op2, v); break;                         \
        case 3:  KPM_DBG_RD(3, _op2, v); break;                         \
        case 4:  KPM_DBG_RD(4, _op2, v); break;                         \
        case 5:  KPM_DBG_RD(5, _op2, v); break;                         \
        case 6:  KPM_DBG_RD(6, _op2, v); break;                         \
        case 7:  KPM_DBG_RD(7, _op2, v); break;                         \
        case 8:  KPM_DBG_RD(8, _op2, v); break;                         \
        case 9:  KPM_DBG_RD(9, _op2, v); break;                         \
        case 10: KPM_DBG_RD(10, _op2, v); break;                        \
        case 11: KPM_DBG_RD(11, _op2, v); break;                        \
        case 12: KPM_DBG_RD(12, _op2, v); break;                        \
        case 13: KPM_DBG_RD(13, _op2, v); break;                        \
        case 14: KPM_DBG_RD(14, _op2, v); break;                        \
        case 15: KPM_DBG_RD(15, _op2, v); break;                        \
        }                                                               \
        return v;                                                       \
    }

KPM_DBG_PROBE_FN(kpm_dbg_probe_rd_bvr, 4)
KPM_DBG_PROBE_FN(kpm_dbg_probe_rd_wvr, 6)

typedef uint64_t (*kpm_dbg_probe_fn_t)(int n);

/* 逐槽探测：触发 UNDEF 时 undef_hook 跳过指令并置标记 → 该槽不存在。
 * PC 窗口 = 探测函数自身代码范围。必须经 volatile 指针间接调用——
 * 直接调用会被 GCC constprop 克隆（克隆地址不在窗口内 → undef_fn
 * PC 检查失败 → panic）。 */
static kpm_dbg_probe_fn_t volatile g_probe_fn_cur;

static int kpm_dbg_probe_limit(kpm_dbg_probe_fn_t fn)
{
    int i;

    g_probe_fn_cur = fn;
    g_undef_pc_lo = (uint64_t)fn;
    g_undef_pc_hi = g_undef_pc_lo + 0x800;   /* 探测函数代码窗 */
    asm volatile("dsb ish" ::: "memory");
    for (i = 0; i < 16; i++) {
        g_undef_hit = 0;
        g_probe_fn_cur(i);
        if (g_undef_hit)
            return i;
    }
    return 16;
}

/* 按 DBGDVR/DBGWVR==addr 摘武装（清 E 位），保存原 CR 供恢复。
 * 返回 0=已摘；-1=未找到（可能已 disarm，调用方回退 PC+4）。 */
static int kpm_dbg_hw_disarm_by_addr(uint64_t addr, int *is_wrp,
                                     uint64_t *saved_cr, int *saved_slot)
{
    int i, n;

    n = g_hw_brp_limit;                     /* 探测上限（勿信 DFR0 虚报） */
    for (i = 0; i < n && i < 16; i++) {
        uint64_t vr = 0, cr = 0;
        switch (i) {
        case 0:  KPM_DBG_RD(0, 4, vr); break;
        case 1:  KPM_DBG_RD(1, 4, vr); break;
        case 2:  KPM_DBG_RD(2, 4, vr); break;
        case 3:  KPM_DBG_RD(3, 4, vr); break;
        case 4:  KPM_DBG_RD(4, 4, vr); break;
        case 5:  KPM_DBG_RD(5, 4, vr); break;
        case 6:  KPM_DBG_RD(6, 4, vr); break;
        case 7:  KPM_DBG_RD(7, 4, vr); break;
        case 8:  KPM_DBG_RD(8, 4, vr); break;
        case 9:  KPM_DBG_RD(9, 4, vr); break;
        case 10: KPM_DBG_RD(10, 4, vr); break;
        case 11: KPM_DBG_RD(11, 4, vr); break;
        case 12: KPM_DBG_RD(12, 4, vr); break;
        case 13: KPM_DBG_RD(13, 4, vr); break;
        case 14: KPM_DBG_RD(14, 4, vr); break;
        case 15: KPM_DBG_RD(15, 4, vr); break;
        }
        if (vr != addr)
            continue;
        switch (i) {
        case 0:  KPM_DBG_RD(0, 5, cr); break;
        case 1:  KPM_DBG_RD(1, 5, cr); break;
        case 2:  KPM_DBG_RD(2, 5, cr); break;
        case 3:  KPM_DBG_RD(3, 5, cr); break;
        case 4:  KPM_DBG_RD(4, 5, cr); break;
        case 5:  KPM_DBG_RD(5, 5, cr); break;
        case 6:  KPM_DBG_RD(6, 5, cr); break;
        case 7:  KPM_DBG_RD(7, 5, cr); break;
        case 8:  KPM_DBG_RD(8, 5, cr); break;
        case 9:  KPM_DBG_RD(9, 5, cr); break;
        case 10: KPM_DBG_RD(10, 5, cr); break;
        case 11: KPM_DBG_RD(11, 5, cr); break;
        case 12: KPM_DBG_RD(12, 5, cr); break;
        case 13: KPM_DBG_RD(13, 5, cr); break;
        case 14: KPM_DBG_RD(14, 5, cr); break;
        case 15: KPM_DBG_RD(15, 5, cr); break;
        }
        if (!(cr & 1))
            continue;                            /* 未武装 */
        *saved_cr = cr;
        *saved_slot = i;
        *is_wrp = 0;
        switch (i) {                             /* 清 E 位 */
        case 0:  KPM_DBG_WR(0, 5, cr & ~1ULL); break;
        case 1:  KPM_DBG_WR(1, 5, cr & ~1ULL); break;
        case 2:  KPM_DBG_WR(2, 5, cr & ~1ULL); break;
        case 3:  KPM_DBG_WR(3, 5, cr & ~1ULL); break;
        case 4:  KPM_DBG_WR(4, 5, cr & ~1ULL); break;
        case 5:  KPM_DBG_WR(5, 5, cr & ~1ULL); break;
        case 6:  KPM_DBG_WR(6, 5, cr & ~1ULL); break;
        case 7:  KPM_DBG_WR(7, 5, cr & ~1ULL); break;
        case 8:  KPM_DBG_WR(8, 5, cr & ~1ULL); break;
        case 9:  KPM_DBG_WR(9, 5, cr & ~1ULL); break;
        case 10: KPM_DBG_WR(10, 5, cr & ~1ULL); break;
        case 11: KPM_DBG_WR(11, 5, cr & ~1ULL); break;
        case 12: KPM_DBG_WR(12, 5, cr & ~1ULL); break;
        case 13: KPM_DBG_WR(13, 5, cr & ~1ULL); break;
        case 14: KPM_DBG_WR(14, 5, cr & ~1ULL); break;
        case 15: KPM_DBG_WR(15, 5, cr & ~1ULL); break;
        }
        return 0;
    }
    /* 观察点（写/读写型）同理 */
    n = g_hw_wrp_limit;
    for (i = 0; i < n && i < 16; i++) {
        uint64_t vr = 0, cr = 0;
        switch (i) {
        case 0:  KPM_DBG_RD(0, 6, vr); break;
        case 1:  KPM_DBG_RD(1, 6, vr); break;
        case 2:  KPM_DBG_RD(2, 6, vr); break;
        case 3:  KPM_DBG_RD(3, 6, vr); break;
        case 4:  KPM_DBG_RD(4, 6, vr); break;
        case 5:  KPM_DBG_RD(5, 6, vr); break;
        case 6:  KPM_DBG_RD(6, 6, vr); break;
        case 7:  KPM_DBG_RD(7, 6, vr); break;
        case 8:  KPM_DBG_RD(8, 6, vr); break;
        case 9:  KPM_DBG_RD(9, 6, vr); break;
        case 10: KPM_DBG_RD(10, 6, vr); break;
        case 11: KPM_DBG_RD(11, 6, vr); break;
        case 12: KPM_DBG_RD(12, 6, vr); break;
        case 13: KPM_DBG_RD(13, 6, vr); break;
        case 14: KPM_DBG_RD(14, 6, vr); break;
        case 15: KPM_DBG_RD(15, 6, vr); break;
        }
        if (vr != addr)
            continue;
        switch (i) {
        case 0:  KPM_DBG_RD(0, 7, cr); break;
        case 1:  KPM_DBG_RD(1, 7, cr); break;
        case 2:  KPM_DBG_RD(2, 7, cr); break;
        case 3:  KPM_DBG_RD(3, 7, cr); break;
        case 4:  KPM_DBG_RD(4, 7, cr); break;
        case 5:  KPM_DBG_RD(5, 7, cr); break;
        case 6:  KPM_DBG_RD(6, 7, cr); break;
        case 7:  KPM_DBG_RD(7, 7, cr); break;
        case 8:  KPM_DBG_RD(8, 7, cr); break;
        case 9:  KPM_DBG_RD(9, 7, cr); break;
        case 10: KPM_DBG_RD(10, 7, cr); break;
        case 11: KPM_DBG_RD(11, 7, cr); break;
        case 12: KPM_DBG_RD(12, 7, cr); break;
        case 13: KPM_DBG_RD(13, 7, cr); break;
        case 14: KPM_DBG_RD(14, 7, cr); break;
        case 15: KPM_DBG_RD(15, 7, cr); break;
        }
        if (!(cr & 1))
            continue;
        *saved_cr = cr;
        *saved_slot = i;
        *is_wrp = 1;
        switch (i) {
        case 0:  KPM_DBG_WR(0, 7, cr & ~1ULL); break;
        case 1:  KPM_DBG_WR(1, 7, cr & ~1ULL); break;
        case 2:  KPM_DBG_WR(2, 7, cr & ~1ULL); break;
        case 3:  KPM_DBG_WR(3, 7, cr & ~1ULL); break;
        case 4:  KPM_DBG_WR(4, 7, cr & ~1ULL); break;
        case 5:  KPM_DBG_WR(5, 7, cr & ~1ULL); break;
        case 6:  KPM_DBG_WR(6, 7, cr & ~1ULL); break;
        case 7:  KPM_DBG_WR(7, 7, cr & ~1ULL); break;
        case 8:  KPM_DBG_WR(8, 7, cr & ~1ULL); break;
        case 9:  KPM_DBG_WR(9, 7, cr & ~1ULL); break;
        case 10: KPM_DBG_WR(10, 7, cr & ~1ULL); break;
        case 11: KPM_DBG_WR(11, 7, cr & ~1ULL); break;
        case 12: KPM_DBG_WR(12, 7, cr & ~1ULL); break;
        case 13: KPM_DBG_WR(13, 7, cr & ~1ULL); break;
        case 14: KPM_DBG_WR(14, 7, cr & ~1ULL); break;
        case 15: KPM_DBG_WR(15, 7, cr & ~1ULL); break;
        }
        return 0;
    }
    return -1;
}

/* 恢复武装：仅当该槽位仍是我们摘的那个（VR 未被重分配、CR 未被改动） */
static void kpm_dbg_hw_rearm(uint64_t addr, int is_wrp, uint64_t saved_cr)
{
    int i, n;

    if (is_wrp) {
        n = g_hw_wrp_limit;
        for (i = 0; i < n && i < 16; i++) {
            uint64_t vr = 0, cr = 0;
            switch (i) {
            case 0:  KPM_DBG_RD(0, 6, vr); break;
            case 1:  KPM_DBG_RD(1, 6, vr); break;
            case 2:  KPM_DBG_RD(2, 6, vr); break;
            case 3:  KPM_DBG_RD(3, 6, vr); break;
            case 4:  KPM_DBG_RD(4, 6, vr); break;
            case 5:  KPM_DBG_RD(5, 6, vr); break;
            case 6:  KPM_DBG_RD(6, 6, vr); break;
            case 7:  KPM_DBG_RD(7, 6, vr); break;
            case 8:  KPM_DBG_RD(8, 6, vr); break;
            case 9:  KPM_DBG_RD(9, 6, vr); break;
            case 10: KPM_DBG_RD(10, 6, vr); break;
            case 11: KPM_DBG_RD(11, 6, vr); break;
            case 12: KPM_DBG_RD(12, 6, vr); break;
            case 13: KPM_DBG_RD(13, 6, vr); break;
            case 14: KPM_DBG_RD(14, 6, vr); break;
            case 15: KPM_DBG_RD(15, 6, vr); break;
            }
            if (vr != addr)
                continue;
            switch (i) {
            case 0:  KPM_DBG_RD(0, 7, cr); break;
            case 1:  KPM_DBG_RD(1, 7, cr); break;
            case 2:  KPM_DBG_RD(2, 7, cr); break;
            case 3:  KPM_DBG_RD(3, 7, cr); break;
            case 4:  KPM_DBG_RD(4, 7, cr); break;
            case 5:  KPM_DBG_RD(5, 7, cr); break;
            case 6:  KPM_DBG_RD(6, 7, cr); break;
            case 7:  KPM_DBG_RD(7, 7, cr); break;
            case 8:  KPM_DBG_RD(8, 7, cr); break;
            case 9:  KPM_DBG_RD(9, 7, cr); break;
            case 10: KPM_DBG_RD(10, 7, cr); break;
            case 11: KPM_DBG_RD(11, 7, cr); break;
            case 12: KPM_DBG_RD(12, 7, cr); break;
            case 13: KPM_DBG_RD(13, 7, cr); break;
            case 14: KPM_DBG_RD(14, 7, cr); break;
            case 15: KPM_DBG_RD(15, 7, cr); break;
            }
            if (cr != (saved_cr & ~1ULL))
                continue;                    /* 已被 perf 重排/重武装 */
            switch (i) {
            case 0:  KPM_DBG_WR(0, 7, saved_cr); break;
            case 1:  KPM_DBG_WR(1, 7, saved_cr); break;
            case 2:  KPM_DBG_WR(2, 7, saved_cr); break;
            case 3:  KPM_DBG_WR(3, 7, saved_cr); break;
            case 4:  KPM_DBG_WR(4, 7, saved_cr); break;
            case 5:  KPM_DBG_WR(5, 7, saved_cr); break;
            case 6:  KPM_DBG_WR(6, 7, saved_cr); break;
            case 7:  KPM_DBG_WR(7, 7, saved_cr); break;
            case 8:  KPM_DBG_WR(8, 7, saved_cr); break;
            case 9:  KPM_DBG_WR(9, 7, saved_cr); break;
            case 10: KPM_DBG_WR(10, 7, saved_cr); break;
            case 11: KPM_DBG_WR(11, 7, saved_cr); break;
            case 12: KPM_DBG_WR(12, 7, saved_cr); break;
            case 13: KPM_DBG_WR(13, 7, saved_cr); break;
            case 14: KPM_DBG_WR(14, 7, saved_cr); break;
            case 15: KPM_DBG_WR(15, 7, saved_cr); break;
            }
            return;
        }
        return;
    }
    n = g_hw_brp_limit;
    for (i = 0; i < n && i < 16; i++) {
        uint64_t vr = 0, cr = 0;
        switch (i) {
        case 0:  KPM_DBG_RD(0, 4, vr); break;
        case 1:  KPM_DBG_RD(1, 4, vr); break;
        case 2:  KPM_DBG_RD(2, 4, vr); break;
        case 3:  KPM_DBG_RD(3, 4, vr); break;
        case 4:  KPM_DBG_RD(4, 4, vr); break;
        case 5:  KPM_DBG_RD(5, 4, vr); break;
        case 6:  KPM_DBG_RD(6, 4, vr); break;
        case 7:  KPM_DBG_RD(7, 4, vr); break;
        case 8:  KPM_DBG_RD(8, 4, vr); break;
        case 9:  KPM_DBG_RD(9, 4, vr); break;
        case 10: KPM_DBG_RD(10, 4, vr); break;
        case 11: KPM_DBG_RD(11, 4, vr); break;
        case 12: KPM_DBG_RD(12, 4, vr); break;
        case 13: KPM_DBG_RD(13, 4, vr); break;
        case 14: KPM_DBG_RD(14, 4, vr); break;
        case 15: KPM_DBG_RD(15, 4, vr); break;
        }
        if (vr != addr)
            continue;
        switch (i) {
        case 0:  KPM_DBG_RD(0, 5, cr); break;
        case 1:  KPM_DBG_RD(1, 5, cr); break;
        case 2:  KPM_DBG_RD(2, 5, cr); break;
        case 3:  KPM_DBG_RD(3, 5, cr); break;
        case 4:  KPM_DBG_RD(4, 5, cr); break;
        case 5:  KPM_DBG_RD(5, 5, cr); break;
        case 6:  KPM_DBG_RD(6, 5, cr); break;
        case 7:  KPM_DBG_RD(7, 5, cr); break;
        case 8:  KPM_DBG_RD(8, 5, cr); break;
        case 9:  KPM_DBG_RD(9, 5, cr); break;
        case 10: KPM_DBG_RD(10, 5, cr); break;
        case 11: KPM_DBG_RD(11, 5, cr); break;
        case 12: KPM_DBG_RD(12, 5, cr); break;
        case 13: KPM_DBG_RD(13, 5, cr); break;
        case 14: KPM_DBG_RD(14, 5, cr); break;
        case 15: KPM_DBG_RD(15, 5, cr); break;
        }
        if (cr != (saved_cr & ~1ULL))
            continue;
        switch (i) {
        case 0:  KPM_DBG_WR(0, 5, saved_cr); break;
        case 1:  KPM_DBG_WR(1, 5, saved_cr); break;
        case 2:  KPM_DBG_WR(2, 5, saved_cr); break;
        case 3:  KPM_DBG_WR(3, 5, saved_cr); break;
        case 4:  KPM_DBG_WR(4, 5, saved_cr); break;
        case 5:  KPM_DBG_WR(5, 5, saved_cr); break;
        case 6:  KPM_DBG_WR(6, 5, saved_cr); break;
        case 7:  KPM_DBG_WR(7, 5, saved_cr); break;
        case 8:  KPM_DBG_WR(8, 5, saved_cr); break;
        case 9:  KPM_DBG_WR(9, 5, saved_cr); break;
        case 10: KPM_DBG_WR(10, 5, saved_cr); break;
        case 11: KPM_DBG_WR(11, 5, saved_cr); break;
        case 12: KPM_DBG_WR(12, 5, saved_cr); break;
        case 13: KPM_DBG_WR(13, 5, saved_cr); break;
        case 14: KPM_DBG_WR(14, 5, saved_cr); break;
        case 15: KPM_DBG_WR(15, 5, saved_cr); break;
        }
        return;
    }
}

/* 占一个步进槽并摘断点武装（命中处理器/停靠放行路径调用，持
 * g_debug_lock）。整体成功返回 0；失败自动回滚（不武装 → 调用方走
 * PC+4 兜底）。 */
static int kpm_dbg_step_claim(int bp_idx, void *task, void *regs, uint64_t addr)
{
    int i, rc;
    int is_wrp = 0, saved_slot = 0;
    uint64_t saved_cr = 0;

    rc = kpm_dbg_hw_disarm_by_addr(addr, &is_wrp, &saved_cr, &saved_slot);
    if (rc != 0)
        return -1;                           /* 已 disarm/未找到 → 兜底 */
    for (i = 0; i < KPM_DBG_STEP_MAX; i++) {
        if (!g_steps[i].active) {
            g_steps[i].task = task;
            g_steps[i].regs = regs;
            g_steps[i].bp_idx = bp_idx;
            g_steps[i].is_wrp = is_wrp;
            g_steps[i].saved_cr = saved_cr;
            g_steps[i].active = 1;
            return 0;
        }
    }
    /* 槽满：回滚摘武装 */
    kpm_dbg_hw_rearm(addr, is_wrp, saved_cr);
    return -1;
}

/* 软件步进回调（EL0，user_step_hook 链）：本模块武装的步进 → 接管。
 * 到达时点：被监视指令【已执行】，PC=addr+4。职责：关 MDSCR.SS、
 * 恢复断点武装、清槽。返回 DBG_HOOK_HANDLED 抑制默认 SIGTRAP。 */
static long kpm_dbg_step_cb(void *regs, unsigned long esr)
{
    struct task_struct *cur;
    unsigned long flags;
    int i;

    (void)esr;
    asm volatile("mrs %0, sp_el0" : "=r"(cur));
    if (!cur || (uint64_t)cur < 0xFFFF000000000000ULL)
        return KPM_DBG_HOOK_ERROR;

    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    /* 自由单步 / step trace——先于断点步进槽处理。
     * 记录快照（34×u64），未到条数则重新置 PSTATE.SS 继续。
     * task 引用不在异常上下文释放（留到命令/exit 上下文）。 */
    for (i = 0; i < KPM_FREESTEP_MAX; i++) {
        kpm_freestep_t *fs = &g_freestep[i];
        unsigned long f2;
        if (!fs->active || fs->task != cur)
            continue;
        f2 = kpm_spin_lock_irqsave(&g_step_ring_lock);
        if (g_step_ring_count < KPM_STEP_RING_MAX) {
            lib_memcpy(&g_step_ring[g_step_ring_head], regs, 34 * 8);
            g_step_ring_head = (g_step_ring_head + 1) % KPM_STEP_RING_MAX;
            g_step_ring_count++;
        } else {
            g_step_ring_dropped++;
        }
        kpm_spin_unlock_irqrestore(&g_step_ring_lock, f2);
        fs->recs++;
        if (fs->remain > 1 && regs) {
            fs->remain--;
            ((uint64_t *)regs)[KPM_PT_REGS_PSTATE_OFF / 8] |= KPM_DBG_SPSR_SS;
            kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
            return KPM_DBG_HOOK_HANDLED;
        }
        fs->active = 0;
        fs->remain = 0;
        kpm_dbg_mdscr_ss(0);
        kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
        return KPM_DBG_HOOK_HANDLED;
    }
    for (i = 0; i < KPM_DBG_STEP_MAX; i++) {
        if (g_steps[i].active && g_steps[i].task == cur) {
            kpm_dbg_mdscr_ss(0);
            if (g_steps[i].bp_idx >= 0 &&
                g_steps[i].bp_idx < KPM_DEBUG_MAX_BREAKPOINTS)
                kpm_dbg_hw_rearm(g_bps[g_steps[i].bp_idx].addr,
                                 g_steps[i].is_wrp, g_steps[i].saved_cr);
            g_steps[i].active = 0;
            kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
            return KPM_DBG_HOOK_HANDLED;
        }
    }
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
    return KPM_DBG_HOOK_ERROR;   /* 非本模块步进（ptrace 等）→ 放行 */
}

/* task_work 回调——目标返回用户态前设置 PSTATE.SS + MDSCR.SS。
 * 只在目标自身上下文执行。pt_regs 地址用已验证导出自行计算
 * （task->stack + thread_size - sizeof(pt_regs)），不依赖 _task_pt_reg；
 * 多符号回退：thread_size/task_struct_offset/kver 均为已验证导出。 */
static struct pt_regs *kpm_freestep_regs(struct task_struct *task)
{
    unsigned long stack = 0;
    unsigned long addr;

    if (!task || thread_size <= 0 ||
        kf_task_struct_offset.stack_offset <= 0)
        return 0;
    lib_memcpy(&stack, (const char *)task + kf_task_struct_offset.stack_offset,
               sizeof(stack));
    if (!stack)
        return 0;
    addr = stack + (unsigned long)thread_size;
    if (kver >= 0x050A00)
        addr -= 0x150;
    else if (kver >= 0x050000)
        addr -= 0x140;
    else if (kver >= 0x040E00)
        addr -= 0x130;
    else
        addr -= 0x120;
    return (struct pt_regs *)addr;
}

static void kpm_freestep_run(void *work)
{
    struct task_struct *cur;
    struct pt_regs *regs;
    unsigned long flags;
    int i, hit = -1;

    asm volatile("mrs %0, sp_el0" : "=r"(cur));
    if (!cur || (uint64_t)cur < 0xFFFF000000000000ULL)
        return;
    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    for (i = 0; i < KPM_FREESTEP_MAX; i++) {
        if (g_freestep[i].active && &g_freestep[i].work == work &&
            g_freestep[i].task == cur) {
            hit = i;
            break;
        }
    }
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
    if (hit < 0)
        return;
    regs = kpm_freestep_regs(cur);
    if (!regs) {
        flags = kpm_spin_lock_irqsave(&g_debug_lock);
        g_freestep[hit].active = 0;
        g_freestep[hit].remain = 0;
        kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
        return;
    }
    ((uint64_t *)regs)[KPM_PT_REGS_PSTATE_OFF / 8] |= KPM_DBG_SPSR_SS;
    kpm_dbg_mdscr_ss(1);
}

/* 释放自由单步槽的 task 引用（只允许进程上下文调用） */
static void kpm_freestep_release(int i)
{
    struct task_struct *tk = 0;
    unsigned long flags;

    if (i < 0 || i >= KPM_FREESTEP_MAX)
        return;
    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    tk = g_freestep[i].task;
    g_freestep[i].task = 0;
    g_freestep[i].active = 0;
    g_freestep[i].remain = 0;
    g_freestep[i].tid = 0;
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
    if (tk)
        kpm_put_task_struct(tk);
}

/* 启动用户单步 / step trace */
long kpm_debug_step_trace(pid_t pid, pid_t tid, uint32_t count)
{
    struct pid *ps;
    struct task_struct *task;
    unsigned long flags;
    int i, slot = -1, rc;

    (void)pid;
    if (!g_step_ok || !kf_task_work_add)
        return -KPM_E_DISABLED;   /* <5.10 无 user_step_hook，不能抑制 SIGTRAP */
    if (tid <= 0 || count == 0 || count > KPM_STEP_RING_MAX)
        return -KPM_E_INVAL;
    if (!kf_find_get_pid || !kf_get_pid_task || !kf_put_pid ||
        !kpm_put_task_available())
        return -KPM_E_DISABLED;

    ps = kf_find_get_pid(tid);
    if (!ps)
        return -KPM_E_NOTFOUND;
    task = kf_get_pid_task(ps, PIDTYPE_PID);
    kf_put_pid(ps);
    if (!task)
        return -KPM_E_NOTFOUND;

    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    for (i = 0; i < KPM_FREESTEP_MAX; i++) {
        if (g_freestep[i].active && g_freestep[i].task == task) {
            kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
            kpm_put_task_struct(task);
            return -KPM_E_BUSY;
        }
        if (!g_freestep[i].active && slot < 0)
            slot = i;
    }
    if (slot < 0) {
        kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
        kpm_put_task_struct(task);
        return -KPM_E_NOMEM;
    }
    /* 旧槽可能残留已结束 trace 的 task 引用：先摘出，锁外释放 */
    {
        struct task_struct *old = g_freestep[slot].task;
        g_freestep[slot].task = 0;
        g_freestep[slot].active = 0;
        if (old && old != task) {
            kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
            kpm_put_task_struct(old);
            flags = kpm_spin_lock_irqsave(&g_debug_lock);
        }
    }
    g_freestep[slot].active = 1;
    g_freestep[slot].tid = tid;
    g_freestep[slot].task = task;
    g_freestep[slot].remain = count;
    g_freestep[slot].recs = 0;
    g_freestep[slot].work.next = 0;
    g_freestep[slot].work.func = kpm_freestep_run;
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);

    /* 清空快照环：一次 trace 对应一次 FETCH */
    flags = kpm_spin_lock_irqsave(&g_step_ring_lock);
    g_step_ring_head = g_step_ring_tail = g_step_ring_count = 0;
    g_step_ring_dropped = 0;
    kpm_spin_unlock_irqrestore(&g_step_ring_lock, flags);

    rc = kf_task_work_add(task, &g_freestep[slot].work, 1);
    if (rc != 0) {
        kpm_freestep_release(slot);
        return -KPM_E_FAULT;
    }
    kpm_log("debug: step trace slot=%d tid=%d count=%u\n", slot, tid, count);
    return slot;
}

/* 拉取 step trace 快照（内核缓冲） */
long kpm_debug_step_fetch_kernel(void *dst, int max_count)
{
    unsigned long flags;
    int n, i;
    kpm_trap_regs_t *out = (kpm_trap_regs_t *)dst;

    if (!dst || max_count <= 0)
        return -KPM_E_INVAL;
    flags = kpm_spin_lock_irqsave(&g_step_ring_lock);
    n = (int)g_step_ring_count;
    if (n > max_count)
        n = max_count;
    for (i = 0; i < n; i++) {
        lib_memcpy(&out[i], &g_step_ring[g_step_ring_tail], sizeof(out[i]));
        g_step_ring_tail = (g_step_ring_tail + 1) % KPM_STEP_RING_MAX;
    }
    g_step_ring_count -= (uint32_t)n;
    kpm_spin_unlock_irqrestore(&g_step_ring_lock, flags);
    return n;
}

long kpm_debug_step_fetch_user(void *dst, int max_count)
{
    kpm_trap_regs_t tmp[8];
    long n;

    if (!dst || max_count <= 0)
        return -KPM_E_INVAL;
    if (max_count > 8)
        max_count = 8;   /* 8×272B 栈缓冲；客户端循环拉取 */
    n = kpm_debug_step_fetch_kernel(tmp, max_count);
    if (n > 0) {
        if (!kf_copy_to_user ||
            kf_copy_to_user(dst, tmp, (unsigned long)n * sizeof(tmp[0])))
            return -KPM_E_FAULT;
    }
    return n;
}

/* 提前结束某线程的步进（CONTINUE 调用，进程上下文） */
long kpm_debug_step_stop(pid_t tid)
{
    unsigned long flags;
    int i, found = -1;

    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    for (i = 0; i < KPM_FREESTEP_MAX; i++) {
        if (g_freestep[i].active && (tid <= 0 || g_freestep[i].tid == tid)) {
            found = i;
            break;
        }
    }
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
    if (found < 0)
        return -KPM_E_NOTFOUND;
    kpm_freestep_release(found);
    return 0;
}

/* 会话互斥（定义在文件后部，此处前向声明供增强接口使用） */
static int debug_enter(void);
static void debug_leave(void);

/* 命中回调：断点异常上下文（IRQ/异常），禁止睡眠。
 * event: perf_event 指针（仅做值比较，不解引用——断点可能刚被 unregister，
 *        比较旧指针值不会访问已释放内存）。
 * 只更新 hit_count / 记录 hit / 置通知 pending / 应用寄存器篡改，全部在 spinlock 内。 */
static void kpm_debug_bp_on_hit(void *event, void *data, void *regs)
{
    unsigned long flags;
    int i, idx = -1;
    kpm_breakpoint_t *bpd = (kpm_breakpoint_t *)data;

    if (bpd >= &g_bps[0] && bpd < &g_bps[KPM_DEBUG_MAX_BREAKPOINTS])
        idx = (int)(bpd - g_bps);

    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    for (i = 0; i < KPM_DEBUG_MAX_BREAKPOINTS; i++) {
        if (g_bps[i].enabled &&
            ((idx >= 0 && i == idx) ||
             (idx < 0 && g_bps[i].perf_event == (uint64_t)event))) {
            uint64_t *r;
            uint64_t pc0, pc1, pstate;

            g_bps[i].hit_count++;
            /* AUTO_CLEAR / MAX_HITS → 标记延迟拆点（异常上下文
             * 不能 unregister，由 g_bp_work 在进程上下文完成）。 */
            if ((g_bp_flags[i] & KPM_BP_FLAG_AUTO_CLEAR) ||
                (g_bp_maxhits[i] &&
                 (uint32_t)g_bps[i].hit_count >= g_bp_maxhits[i]))
                g_bp_clear_pending[i] = 1;
            {
                kpm_trace_event_t tev;
                lib_memset(&tev, 0, sizeof(tev));
                tev.ts = kf_ktime_get_ns ? kf_ktime_get_ns() : 0;
                tev.type = KPM_TRACE_TYPE_BP;
                tev.pid = g_bps[i].pid;
                tev.nr = (uint32_t)i;
                tev.args[0] = g_bps[i].addr;
                tev.ret = (int64_t)g_bps[i].hit_count;
                kpm_trace_push(&tev);
            }
            g_bp_hit.bp_index = i;
            g_bp_hit.pid = g_bps[i].pid;
            g_bp_hit.addr = g_bps[i].addr;
            /* 无痕 hook 自动规则（µs 级命中即应用，不停靠）。
             * 与同步停靠互斥（规则设置时校验）；EL0 门控与 regmod 一致。 */
            if (g_bp_hook[i].active &&
                regs && (uint64_t)regs >= 0xFFFF000000000000ULL) {
                uint64_t *rh = (uint64_t *)regs;
                if ((rh[KPM_PT_REGS_PSTATE_OFF / 8] & 0xFULL) == 0) {
                    int pc_touched = 0;
                    switch (g_bp_hook[i].action) {
                    case KPM_HOOK_ACT_ARG_MOD: {
                        int j;
                        for (j = 0; j < 8; j++)
                            if (g_bp_hook[i].arg_mask & (1ULL << j))
                                rh[j] = g_bp_hook[i].args[j];
                        break;
                    }
                    case KPM_HOOK_ACT_RET_MOD:
                        rh[0] = g_bp_hook[i].aux;
                        rh[KPM_PT_REGS_PC_OFF / 8] = rh[30];   /* pc = lr(x30) */
                        pc_touched = 1;
                        break;
                    case KPM_HOOK_ACT_REDIRECT:
                        rh[KPM_PT_REGS_PC_OFF / 8] = g_bp_hook[i].aux;
                        pc_touched = 1;
                        break;
                    case KPM_HOOK_ACT_OBSERVE:
                    default:
                        break;
                    }
                    if (!pc_touched) {
                        /* 未改写 PC 时统一 PC+4 跳过（与 async regmod/
                         * pc-skip 路径一致）：命中指令不提交，ARG_MOD
                         * 参数改写在跳过前生效（拦截语义）。软件单步
                         * 舞步（disarm BCR → MDSCR.SS=1 → SPSR.SS=1 →
                         * step 异常 rearm）在高命中频率下与 perf 框架的
                         * per-cpu BRP 调度竞态，断点/单步状态会泄漏到
                         * 非目标进程；未认领的单步异常放行后内核强制
                         * SIGTRAP，故不采用。 */
                        rh[KPM_PT_REGS_PC_OFF / 8] += 4;
                    }
                    /* 通知走既有 KBPN 异步路径（客户端可感知命中） */
                    if (g_bp_notify_enabled && g_bps[i].notify &&
                        !g_bp_notify_pending && !g_trap_notify_pending &&
                        kf_queue_work && g_bp_wq) {
                        g_bp_notify_pending = 1;
                        asm volatile("dmb ish" ::: "memory");
                        g_bp_work_live = 1;
                        kf_queue_work(0, g_bp_wq, &g_bp_work);
                    }
                    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
                    return;
                }
            }
            /* 同步停靠分支——
             * 仅 EL0 命中 + 该断点 sync 模式 + 基础设施自检通过。
             * 走停靠路径时【不做 PC+4、不做 regmod、不做 async 通知】：
             * 命中指令保持未提交（eret 未发生），客户端经
             * GET_CONTEXT → SET_CONTEXT → RESUME 读-改-写闭环。
             * 入队失败/槽满 → 落回下方 async 路径（兼容性退回）。 */
            if (g_bp_sync[i]) {
                static int sync_cond_logged = 0;
                if (!sync_cond_logged) {
                    sync_cond_logged = 1;
                    kpm_printk("LH_debug: sync cond i=%d sync_ok=%d twa=%d "
                               "regs_ok=%d pstate_el0=%d\n",
                               i, g_sync_ok, !!kf_task_work_add,
                               regs ? (int)((uint64_t)regs >> 60) : -1,
                               regs ? (int)(((uint64_t *)regs)[KPM_PT_REGS_PSTATE_OFF / 8] & 0xF) : -1);
                }
            }
            if (g_bp_sync[i] && g_sync_ok && kf_task_work_add &&
                regs && (uint64_t)regs >= 0xFFFF000000000000ULL) {
                uint64_t *rh = (uint64_t *)regs;
                if ((rh[KPM_PT_REGS_PSTATE_OFF / 8] & 0xFULL) == 0) {
                    static int arm_dbg_logged = 0;
                    int arm_rc;
                    if (!arm_dbg_logged) {
                        arm_dbg_logged = 1;
                        kpm_printk("LH_debug: sync arm attempt i=%d\n", i);
                    }
                    arm_rc = kpm_sync_trap_arm(i, regs);
                    if (arm_rc == 0) {
                        if (g_bp_notify_enabled && g_bps[i].notify &&
                            !g_trap_notify_pending && !g_bp_notify_pending &&
                            kf_queue_work && g_bp_wq) {
                            g_trap_notify_slot = i;
                            g_trap_notify_pending = 1;
                            asm volatile("dmb ish" ::: "memory");
                            g_bp_work_live = 1;
                            kf_queue_work(0, g_bp_wq, &g_bp_work);
                        }
                        kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
                        return;
                    }
                    {
                        static int arm_fail_logged = 0;
                        if (!arm_fail_logged) {
                            arm_fail_logged = 1;
                            kpm_printk("LH_debug: sync arm FAILED rc=%d "
                                       "(fall back async)\n", arm_rc);
                        }
                    }
                }
            }
            /* 应用寄存器篡改规则：纯内存写（pt_regs + 可选 fpsimd），
             * 异常上下文安全。 */
            r = (uint64_t *)regs;
            pc0 = (regs && (uint64_t)regs >= 0xFFFF000000000000ULL) ?
                  r[KPM_PT_REGS_PC_OFF / 8] : 0;
            kpm_debug_bp_apply_regmod(i, regs);
            /* PC-skip：EL0 命中且 regmod 未改写 PC 时，regs->pc += 4
             * （A64 指令恒 4B）跳过命中指令。breakpoint_handler/
             * watchpoint_handler 只对默认 overflow handler 做"关 WP→
             * 单步跨指令→重武装"舞步；本模块经 perf_event_create_
             * kernel_counter 挂自定义回调，内核不做舞步，eret 回原 PC
             * 且 WCR/BCR 仍 armed 会导致无限异常循环。PC+4 后 WCR 保持
             * armed 也不会再触发同一指令，无需内核单步机制、零符号/
             * 结构体偏移依赖。语义：命中指令本身不提交（watch 的
             * load/store 不落内存、EXEC 的入口指令不执行），用 regmod
             * 补偿所需效果。内核态命中（pstate 非 EL0t）不 skip。 */
            if (regs && (uint64_t)regs >= 0xFFFF000000000000ULL) {
                pstate = r[KPM_PT_REGS_PSTATE_OFF / 8];
                pc1 = r[KPM_PT_REGS_PC_OFF / 8];
                if ((pstate & 0xFULL) == 0) {
                    int step_armed = 0;
                    /* EXEC_INST：真执行不跳 PC——命中指令需先摘武装、
                     * 置 PSTATE.SS 单步，步进回调里重新武装（force 已在
                     * 安装时校验）。单步不可用/槽满 → 退回 PC+4。 */
                    if ((g_bp_flags[i] & KPM_BP_FLAG_EXEC_INST) &&
                        g_bps[i].type == KPM_BP_TYPE_HW_EXEC &&
                        g_step_ok && pc1 == pc0) {
                        struct task_struct *cur;
                        asm volatile("mrs %0, sp_el0" : "=r"(cur));
                        if (cur &&
                            kpm_dbg_step_claim(i, cur, regs,
                                               g_bps[i].addr) == 0) {
                            kpm_dbg_mdscr_ss(1);
                            r[KPM_PT_REGS_PSTATE_OFF / 8] =
                                pstate | KPM_DBG_SPSR_SS;
                            step_armed = 1;
                        }
                    }
                    if (!step_armed && pc1 == pc0) {
                        r[KPM_PT_REGS_PC_OFF / 8] = pc0 + 4;
                        {
                            static int pc_skip_logged = 0;
                            if (!pc_skip_logged) {
                                pc_skip_logged = 1;
                                kpm_log("debug: bp pc-skip applied "
                                        "pc=0x%llx -> 0x%llx\n",
                                        (unsigned long long)pc0,
                                        (unsigned long long)(pc0 + 4));
                            }
                        }
                    }
                } else if (g_bp_kind[i] == 1) {
                    /* 内核宽断点：perf 自定义 handler 没有内核默认的
                     * “关断点→单步→重装”舞步，回原 PC 重试会无限异常风暴。
                     * 必须跳过命中指令（该次内核存取被丢弃，force 语义）。
                     * 同时标记延迟拆点：内核观察默认 one-shot，避免持续
                     * 丢弃内核写。 */
                    r[KPM_PT_REGS_PC_OFF / 8] = pc1 + 4;
                    g_bp_clear_pending[i] = 1;
                    {
                        static int kskip_logged = 0;
                        if (!kskip_logged) {
                            kskip_logged = 1;
                            kpm_log("debug: kernel bp hit skipped "
                                    "pc=0x%llx (store dropped)\n",
                                    (unsigned long long)pc1);
                        }
                    }
                }
            }
            /* AUTO_CLEAR / MAX_HITS 延迟拆点入队 */
            if (g_bp_clear_pending[i] && kf_queue_work && g_bp_wq &&
                !g_bp_work_live) {
                asm volatile("dmb ish" ::: "memory");
                g_bp_work_live = 1;
                kf_queue_work(0, g_bp_wq, &g_bp_work);
            }
            if (g_bp_notify_enabled && g_bps[i].notify &&
                !g_bp_notify_pending && kf_queue_work && g_bp_wq) {
                g_bp_notify_pending = 1;
                /* 先置 live 再 queue——若 queue 后置位，work 可能
                 * 在置位前跑完退出，live 卡 1 导致退出自旋空转超时。 */
                asm volatile("dmb ish" ::: "memory");
                g_bp_work_live = 1;
                kf_queue_work(0, g_bp_wq, &g_bp_work);
            }
            break;
        }
    }
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
}

/* ===== 寄存器篡改应用 =====
 * 断点异常上下文调用（perf overflow handler 的 regs = 异常现场 pt_regs）：
 *   - GP/SP/PC/PSTATE：直接改写 pt_regs（异常返回 eret 恢复时生效）
 *   - FP/SIMD：改写 current->thread.uw.fpsimd_state.vregs（MRS SP_EL0=current，
 *     偏移 g_fpsimd_vregs_offset 门控；未确认时忽略 fp_mask）
 * 安全约束：纯内存写，无睡眠；regs 必须是内核地址（防脏指针）。 */
static void kpm_debug_bp_apply_regmod(int idx, void *regs)
{
    kpm_bp_regmod_t *rm;
    uint64_t mask;
    int i;
    uint64_t *r;
    uint64_t pstate;

    if (idx < 0 || idx >= KPM_DEBUG_MAX_BREAKPOINTS)
        return;
    if (!g_bp_regmod[idx].active)
        return;
    /* regs 必须为内核地址（ARM64 kernel VA >= 0xFFFF000000000000） */
    if (!regs || (uint64_t)regs < 0xFFFF000000000000ULL)
        return;

    /* EL0 门控：regmod 仅对【用户态异常现场】生效。若探测成功的 attr
     * 变体未置 exclude_kernel（flags=0），断点可能在内核态触发（如内核
     * copy_to_user 写中被观察的用户地址）——此时 perf 回调收到的
     * pt_regs 是【内核现场】，改写 PC/Xn 会重定向内核执行流 → 直接
     * panic。pstate M[3:0]==0 即 EL0t（用户态）；EL1h=0x5, EL1t=0x4,
     * EL0t=0x0。 */
    r = (uint64_t *)regs;   /* pt_regs->regs[0] */
    pstate = r[KPM_PT_REGS_PSTATE_OFF / 8];
    if ((pstate & 0xFULL) != 0) {
        static int el1_skip_logged = 0;
        if (!el1_skip_logged) {
            el1_skip_logged = 1;
            kpm_log("debug: bp regmod skipped - exception not from EL0 "
                    "(kernel-mode bp hit, pstate=%llx)\n",
                    (unsigned long long)pstate);
        }
        return;
    }

    rm = &g_bp_regmod[idx];
    mask = rm->reg_mask;

    /* X0-X30 */
    for (i = 0; i < 31; i++) {
        if (mask & (1ULL << i))
            r[i] = rm->regs[i];
    }
    /* SP / PC / PSTATE（pt_regs 布局：regs[31] 后接 sp/pc/pstate） */
    if (mask & KPM_REG_MODIFY_SP)
        r[KPM_PT_REGS_SP_OFF / 8] = rm->sp;
    if (mask & KPM_REG_MODIFY_PC)
        r[KPM_PT_REGS_PC_OFF / 8] = rm->pc;
    if (mask & KPM_REG_MODIFY_PSTATE)
        r[KPM_PT_REGS_PSTATE_OFF / 8] = rm->pstate;

    /* FP/SIMD（门控：偏移未确认时跳过，防写坏 task_struct）
     * current 获取：ARM64 MRS SP_EL0，不引用 kpm_get_current_task
     * （头文件声明但全项目无定义，引用即产生 UNDEF → KPM 加载
     * unknown symbol 拒载）。
     * 双写策略：
     *   ① 内存副本（thread...fpsimd_state.vregs）：权威存储。上下文切入
     *      重载（fpsimd_load）/ ptrace 读取时生效。内核 ptrace 写 FP 的
     *      标准做法即"写内存 + fpsimd_flush_task_state"（fpr_set）——但
     *      那只对【非运行态】目标（ptrace 停止的任务）有效；
     *   ② CPU 活跃 q 寄存器：断点异常来自 EL0（上方已门控）→
     *      do_debug_exception → perf_bp_event → 本回调为同步直调，
     *      中途无 kernel_neon 区域 → CPU q 寄存器此刻就是该任务的
     *      【用户态活跃值】。直接 ldr 覆盖 = 返回用户态立即生效，
     *      无需等下一次上下文切换重载。只写内存不写 q 寄存器时：任务
     *      返回用户态直接用 CPU 旧值（看不到篡改）；下次切出时
     *      fpsimd_save 把 CPU 旧值回写内存 → 覆盖 ① 的写入 → 切入
     *      重载又是旧值，篡改永久丢失，故必须双写。
     * 双写一致性：切出 save（q→内存）与切入 load（内存→q）读到的都是
     * 新值，两条路径收敛。
     * SVE 任务（TIF_SVE）：V 是 Z 的低 128 位，写 V 即改 Z 低段；
     * 场景纯 NEON，不受影响。
     * 汇编约束：-mgeneral-regs-only 下编译器永不分配 FP 寄存器，显式
     * 寄存器名（q0-q31）写在指令文本内、无 clobber 声明，安全。
     * ldr qN 立即偏移（0..496，16 的倍数）在 A64 unsigned-offset 编码
     * 范围（imm12×16）内。 */
    if (rm->fp_mask && g_fpsimd_vregs_offset > 0) {
        struct task_struct *cur;
        uint8_t *vregs_base;
        uint64_t fm = rm->fp_mask;
        asm volatile("mrs %0, sp_el0" : "=r"(cur));
        if (cur && (uint64_t)cur >= 0xFFFF000000000000ULL) {
            vregs_base = (uint8_t *)cur + g_fpsimd_vregs_offset;
            for (i = 0; i < 32; i++) {
                if (fm & (1ULL << i))
                    lib_memcpy(vregs_base + (size_t)i * 16, rm->vregs[i], 16);
            }
            /* ② 写活跃 q 寄存器（仅掩码位）；dmb 保证内存写先行可见 */
            asm volatile("dmb ish" ::: "memory");
            if (fm & (1ULL << 0))  asm volatile("ldr q0, [%0, #0]"    :: "r"(vregs_base));
            if (fm & (1ULL << 1))  asm volatile("ldr q1, [%0, #16]"   :: "r"(vregs_base));
            if (fm & (1ULL << 2))  asm volatile("ldr q2, [%0, #32]"   :: "r"(vregs_base));
            if (fm & (1ULL << 3))  asm volatile("ldr q3, [%0, #48]"   :: "r"(vregs_base));
            if (fm & (1ULL << 4))  asm volatile("ldr q4, [%0, #64]"   :: "r"(vregs_base));
            if (fm & (1ULL << 5))  asm volatile("ldr q5, [%0, #80]"   :: "r"(vregs_base));
            if (fm & (1ULL << 6))  asm volatile("ldr q6, [%0, #96]"   :: "r"(vregs_base));
            if (fm & (1ULL << 7))  asm volatile("ldr q7, [%0, #112]"  :: "r"(vregs_base));
            if (fm & (1ULL << 8))  asm volatile("ldr q8, [%0, #128]"  :: "r"(vregs_base));
            if (fm & (1ULL << 9))  asm volatile("ldr q9, [%0, #144]"  :: "r"(vregs_base));
            if (fm & (1ULL << 10)) asm volatile("ldr q10, [%0, #160]" :: "r"(vregs_base));
            if (fm & (1ULL << 11)) asm volatile("ldr q11, [%0, #176]" :: "r"(vregs_base));
            if (fm & (1ULL << 12)) asm volatile("ldr q12, [%0, #192]" :: "r"(vregs_base));
            if (fm & (1ULL << 13)) asm volatile("ldr q13, [%0, #208]" :: "r"(vregs_base));
            if (fm & (1ULL << 14)) asm volatile("ldr q14, [%0, #224]" :: "r"(vregs_base));
            if (fm & (1ULL << 15)) asm volatile("ldr q15, [%0, #240]" :: "r"(vregs_base));
            if (fm & (1ULL << 16)) asm volatile("ldr q16, [%0, #256]" :: "r"(vregs_base));
            if (fm & (1ULL << 17)) asm volatile("ldr q17, [%0, #272]" :: "r"(vregs_base));
            if (fm & (1ULL << 18)) asm volatile("ldr q18, [%0, #288]" :: "r"(vregs_base));
            if (fm & (1ULL << 19)) asm volatile("ldr q19, [%0, #304]" :: "r"(vregs_base));
            if (fm & (1ULL << 20)) asm volatile("ldr q20, [%0, #320]" :: "r"(vregs_base));
            if (fm & (1ULL << 21)) asm volatile("ldr q21, [%0, #336]" :: "r"(vregs_base));
            if (fm & (1ULL << 22)) asm volatile("ldr q22, [%0, #352]" :: "r"(vregs_base));
            if (fm & (1ULL << 23)) asm volatile("ldr q23, [%0, #368]" :: "r"(vregs_base));
            if (fm & (1ULL << 24)) asm volatile("ldr q24, [%0, #384]" :: "r"(vregs_base));
            if (fm & (1ULL << 25)) asm volatile("ldr q25, [%0, #400]" :: "r"(vregs_base));
            if (fm & (1ULL << 26)) asm volatile("ldr q26, [%0, #416]" :: "r"(vregs_base));
            if (fm & (1ULL << 27)) asm volatile("ldr q27, [%0, #432]" :: "r"(vregs_base));
            if (fm & (1ULL << 28)) asm volatile("ldr q28, [%0, #448]" :: "r"(vregs_base));
            if (fm & (1ULL << 29)) asm volatile("ldr q29, [%0, #464]" :: "r"(vregs_base));
            if (fm & (1ULL << 30)) asm volatile("ldr q30, [%0, #480]" :: "r"(vregs_base));
            if (fm & (1ULL << 31)) asm volatile("ldr q31, [%0, #496]" :: "r"(vregs_base));
        }
    }
}

/* ===== regmod 窗口（转换桥命令层使用） =====
 * 预置规则（regmod_set）→ set_ex/modify 消费；消费后清空防串扰。 */
static kpm_bp_regmod_t g_bp_regmod_win;
static int g_bp_regmod_win_valid = 0;

/* 从用户寄存器快照构造 regmod（process 上下文；regs_to_set_user 可空） */
static long kpm_bp_regmod_build(kpm_bp_regmod_t *rm, uint64_t reg_mask,
                                uint64_t fp_mask,
                                const void *regs_to_set_user)
{
    lib_memset(rm, 0, sizeof(*rm));
    rm->reg_mask = reg_mask;
    rm->fp_mask = fp_mask;

    if (regs_to_set_user && kf_copy_from_user) {
        /* 拷贝掩码对应字段 */
        if (reg_mask & 0x7FFFFFFFULL) {   /* X0-X30 */
            if (kf_copy_from_user(rm->regs, regs_to_set_user,
                                  sizeof(rm->regs)) != 0)
                return -KPM_E_FAULT;
        }
        if (reg_mask & (KPM_REG_MODIFY_SP | KPM_REG_MODIFY_PC |
                        KPM_REG_MODIFY_PSTATE)) {
            uint64_t vals[3];
            if (kf_copy_from_user(vals,
                                  (const uint8_t *)regs_to_set_user +
                                      KPM_UREGS_SP_OFF,
                                  sizeof(vals)) != 0)
                return -KPM_E_FAULT;
            rm->sp = vals[0];
            rm->pc = vals[1];
            rm->pstate = vals[2];
        }
        if (fp_mask) {
            if (kf_copy_from_user(rm->vregs,
                                  (const uint8_t *)regs_to_set_user +
                                      KPM_UREGS_VREGS_OFF,
                                  sizeof(rm->vregs)) != 0)
                return -KPM_E_FAULT;
        }
    } else if (regs_to_set_user && !kf_copy_from_user) {
        return -KPM_E_NOTFOUND;
    }

    rm->active = (reg_mask || fp_mask) ? 1 : 0;
    return 0;
}

/* 存储/更新断点篡改规则（process 上下文；regs_to_set_user 为用户指针可空） */
static long kpm_debug_bp_regmod_store(int idx, uint64_t reg_mask,
                                      uint64_t fp_mask,
                                      const void *regs_to_set_user)
{
    kpm_bp_regmod_t rm;
    unsigned long flags;
    long ret;

    if (idx < 0 || idx >= KPM_DEBUG_MAX_BREAKPOINTS)
        return -KPM_E_INVAL;

    ret = kpm_bp_regmod_build(&rm, reg_mask, fp_mask, regs_to_set_user);
    if (ret)
        return ret;

    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    /* 大结构体复制必须用 lib_memcpy（直接赋值 -O0 降级 memcpy → UNDEF 加载失败） */
    lib_memcpy(&g_bp_regmod[idx], &rm, sizeof(kpm_bp_regmod_t));
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
    return 0;
}

/* ===== 断点增强接口 ===== */
long kpm_debug_bp_regmod_set(uint64_t reg_mask, uint64_t fp_mask,
                             const void *regs_to_set_user)
{
    kpm_bp_regmod_t rm;
    unsigned long flags;
    long ret;

    ret = kpm_bp_regmod_build(&rm, reg_mask, fp_mask, regs_to_set_user);
    if (ret)
        return ret;

    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    lib_memcpy(&g_bp_regmod_win, &rm, sizeof(kpm_bp_regmod_t));
    g_bp_regmod_win_valid = rm.active;
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
    return 0;
}

long kpm_debug_bp_set_ex(pid_t pid, int type, uint64_t addr, uint64_t size)
{
    long idx;
    long ret;
    kpm_bp_regmod_t win;
    unsigned long flags;
    int win_valid;

    idx = kpm_debug_bp_set(pid, type, addr, size);
    if (idx < 0)
        return idx;

    /* 消费窗口规则（大结构体复制用 lib_memcpy，防 memcpy UNDEF） */
    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    lib_memcpy(&win, &g_bp_regmod_win, sizeof(kpm_bp_regmod_t));
    win_valid = g_bp_regmod_win_valid;
    g_bp_regmod_win_valid = 0;
    lib_memset(&g_bp_regmod_win, 0, sizeof(g_bp_regmod_win));
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);

    if (win_valid) {
        flags = kpm_spin_lock_irqsave(&g_debug_lock);
        lib_memcpy(&g_bp_regmod[idx], &win, sizeof(kpm_bp_regmod_t));
        kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
    }
    kpm_log("debug: bp set_ex idx=%d pid=%d addr=0x%llx win=%d\n",
            (int)idx, pid, (unsigned long long)addr, win_valid);
    return idx;
}

long kpm_debug_bp_modify(int index)
{
    kpm_bp_regmod_t win;
    unsigned long flags;
    int win_valid;
    long ret = 0;

    if (index < 0 || index >= KPM_DEBUG_MAX_BREAKPOINTS)
        return -KPM_E_INVAL;

    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    if (!g_bps[index].enabled) {
        kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
        return -KPM_E_NOTFOUND;
    }
    lib_memcpy(&win, &g_bp_regmod_win, sizeof(kpm_bp_regmod_t));
    win_valid = g_bp_regmod_win_valid;
    g_bp_regmod_win_valid = 0;
    lib_memset(&g_bp_regmod_win, 0, sizeof(g_bp_regmod_win));
    if (win_valid)
        lib_memcpy(&g_bp_regmod[index], &win, sizeof(kpm_bp_regmod_t));
    else
        lib_memset(&g_bp_regmod[index], 0, sizeof(kpm_bp_regmod_t));
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
    (void)ret;
    return 0;
}

long kpm_debug_bp_get_hit_count(int index, uint64_t *total, uint64_t *pending)
{
    if (index < 0 || index >= KPM_DEBUG_MAX_BREAKPOINTS)
        return -KPM_E_INVAL;
    if (debug_enter() < 0)
        return -KPM_E_BUSY;
    if (!g_bps[index].enabled) {
        if (total)
            *total = 0;
        if (pending)
            *pending = 0;
        debug_leave();
        return 0;   /* 空槽返回 0（累计命中 = 0） */
    }
    if (total)
        *total = g_bps[index].hit_count;
    if (pending)
        *pending = 0;   /* 转换层按 last_read 差值计算 */
    debug_leave();
    return 0;
}

/* 通知 work：同步停靠通知（'KBPT'）优先 → 命中通知（'KBPN'） → 清 pending */
static void kpm_debug_bp_work(struct kpm_work_struct *work)
{
    kpm_bp_notify_t n;
    unsigned long flags;

    (void)work;
    /* AUTO_CLEAR / MAX_HITS —— 异常上下文不能 unregister，
     * 在 work 进程上下文安全拆点；与客户端命令互斥失败则保留待重试。 */
    {
        int i;
        for (i = 0; i < KPM_DEBUG_MAX_BREAKPOINTS; i++) {
            if (!g_bp_clear_pending[i])
                continue;
            g_bp_clear_pending[i] = 0;
            if (kpm_debug_bp_clear(i) == -KPM_E_BUSY)
                g_bp_clear_pending[i] = 1;
        }
    }
    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    /* 同步停靠通知优先——客户端需要 trap_id 才能发 GET/SET/RESUME */
    if (g_trap_notify_pending) {
        kpm_trap_notify_t tn;
        int slot = g_trap_notify_slot;
        g_trap_notify_pending = 0;
        if (slot >= 0 && slot < KPM_SYNC_TRAP_MAX) {
            kpm_sync_trap_t *t = &g_traps[slot];
            tn.magic = 0x4B5054;    /* 'KBPT' */
            tn.trap_id = (uint32_t)slot;
            tn.bp_index = t->bp_index;
            tn.pid = t->pid;
            tn.addr = t->addr;
            tn.hit_count = t->hit_count;
            tn.pc = t->regs[32];    /* 快照 PC（regs[31]=sp, [32]=pc, [33]=pstate） */
            tn.timeout_ms = t->timeout_ms;
        } else {
            lib_memset(&tn, 0, sizeof(tn));
            tn.magic = 0x4B5054;
            tn.trap_id = 0xFFFFFFFFu;
        }
        kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
        kpm_udp_notify_send(&g_bp_notify_client, &tn, (int)sizeof(tn));
        asm volatile("dmb ish" ::: "memory");
        g_bp_work_live = 0;
        return;
    }
    if (!g_bp_notify_enabled || g_bp_notify_pending == 0) {
        g_bp_notify_pending = 0;
        kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
        asm volatile("dmb ish" ::: "memory");
        g_bp_work_live = 0;     /* work 退出清在途标记 */
        return;
    }
    if (g_bp_hit.bp_index >= 0 && g_bp_hit.bp_index < KPM_DEBUG_MAX_BREAKPOINTS) {
        n.magic = 0x4B504E; /* 'KBPN' */
        n.bp_index = (uint32_t)g_bp_hit.bp_index;
        n.pid = g_bp_hit.pid;
        n.addr = g_bp_hit.addr;
        n.hit_count = (uint64_t)g_bps[g_bp_hit.bp_index].hit_count;
    } else {
        n.magic = 0x4B504E;
        n.bp_index = 0xFFFFFFFFu;
        n.pid = 0;
        n.addr = 0;
        n.hit_count = 0;
    }
    g_bp_notify_pending = 0;
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);

    kpm_udp_notify_send(&g_bp_notify_client, &n, (int)sizeof(n));

    asm volatile("dmb ish" ::: "memory");
    g_bp_work_live = 0;         /* work 退出清在途标记 */
}

/* INIT_WORK 等效实现（kpm_udp.c 的 kpm_init_work 为 static，此处复制，
 * 匹配内核 work_struct ABI） */
static void kpm_bp_init_work(struct kpm_work_struct *work,
                             void (*func)(struct kpm_work_struct *))
{
    work->data = 0;
    INIT_LIST_HEAD(&work->entry);
    work->func = func;
}

/* ===== Breakpoint storage ===== */

/* ===== 会话互斥 =====
 * busy 标志模式：
 *   - bp_set/clear/copy_list/copy_hit 互斥；
 *   - 防止 bp_set 半初始化条目被并发 bp_clear 读取，防止 copy_list
 *     拷贝过程中条目被 memset 清空。
 */

static int debug_enter(void)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_debug_lock);
    if (g_debug_busy) {
        kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
        return -1;
    }
    g_debug_busy = 1;
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
    return 0;
}

static void debug_leave(void)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_debug_lock);
    g_debug_busy = 0;
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
}

/* ===== Initialization & Exit ===== */

long kpm_debug_init(void)
{
    lib_memset(g_bps, 0, sizeof(g_bps));
    lib_memset(g_bp_kind, 0, sizeof(g_bp_kind));
    lib_memset(g_bp_flags, 0, sizeof(g_bp_flags));
    lib_memset(g_bp_maxhits, 0, sizeof(g_bp_maxhits));
    lib_memset((void *)g_bp_clear_pending, 0, sizeof(g_bp_clear_pending));
    lib_memset(g_freestep, 0, sizeof(g_freestep));
    g_step_ring_head = g_step_ring_tail = g_step_ring_count = 0;
    g_step_ring_dropped = 0;
    lib_memset(&g_bp_hit, 0, sizeof(g_bp_hit));
    lib_memset(g_bp_regmod, 0, sizeof(g_bp_regmod));
    lib_memset(g_traps, 0, sizeof(g_traps));
    lib_memset(g_bp_sync, 0, sizeof(g_bp_sync));
    lib_memset(g_bp_timeout, 0, sizeof(g_bp_timeout));
    g_trap_notify_pending = 0;
    g_trap_notify_slot = -1;
    /* 软件单步基础设施自检（fail-closed）。
     * register_user_step_hook 缺失或内核 < 5.10（4.x 内核态 undef 不咨询
     * hook，探测路线必 panic）→ 步进语义禁用，命中走 PC+4 跳过兼容回退。 */
    g_step_ok = (kf_register_user_step_hook &&
                 kf_unregister_user_step_hook &&
                 kf_register_undef_hook && kf_unregister_undef_hook &&
                 kpm_dbg_kver_ge_5_10()) ? 1 : 0;
    if (g_step_ok) {
        lib_memset(g_steps, 0, sizeof(g_steps));
        g_step_hook.fn = kpm_dbg_step_cb;
        /* 先探测调试寄存器真实上限（undef_hook 带恢复——DFR0 可能虚报，
         * 直读越界槽位会 UNDEF panic），探测失败 fail-closed */
        g_uhook.next = 0;
        g_uhook.prev = 0;
        g_uhook.instr_mask = 0xFFF00000U;    /* 任意 MRS（op0=2） */
        g_uhook.instr_val = 0xD5300000U;
        g_uhook.pstate_mask = 0;             /* 任意 PSTATE */
        g_uhook.pstate_val = 0;
        g_uhook.fn = kpm_dbg_undef_fn;
        kf_register_undef_hook(&g_uhook);
        kpm_printk("LH_dbg: undef hook registered\n");
        g_hw_brp_limit = kpm_dbg_probe_limit(kpm_dbg_probe_rd_bvr);
        kpm_printk("LH_dbg: brp_limit=%d\n", g_hw_brp_limit);
        g_hw_wrp_limit = kpm_dbg_probe_limit(kpm_dbg_probe_rd_wvr);
        kpm_printk("LH_dbg: wrp_limit=%d\n", g_hw_wrp_limit);
        kf_unregister_undef_hook(&g_uhook);
        if (g_hw_brp_limit == 0 || g_hw_wrp_limit == 0) {
            g_step_ok = 0;
            kpm_log("debug: hw reg probe FAILED (brp=%d wrp=%d), step disabled\n",
                    g_hw_brp_limit, g_hw_wrp_limit);
        }
    }
    if (g_step_ok)
        kf_register_user_step_hook(&g_step_hook);
    /* 同步停靠基础设施自检（兼容性退回：任一符号缺失 → 仅 sync 模式
     * 禁用，SET_SYNC 返回 -KPM_E_DISABLED；async 断点不受影响）。
     * get_task_struct 自适应：4.19 无符号（static inline），由
     * kpm_get_task_struct_safe 走标定 usage 偏移对偶实现，不作为门控项。 */
    g_sync_ok = (kf_task_work_add && kf_schedule_timeout_interruptible &&
                 kf_msecs_to_jiffies && kf_wake_up_process) ? 1 : 0;
    kpm_log("debug: sync trap %s (task_work=%d sched_to=%d ms2j=%d wake=%d ref=%d) step=%d\n",
            g_sync_ok ? "available" : "unavailable (async only)",
            !!kf_task_work_add, !!kf_schedule_timeout_interruptible,
            !!kf_msecs_to_jiffies, !!kf_wake_up_process,
            kf_get_task_struct || (g_usage_offset > 0 && g_usage_offset_trusted),
            g_step_ok);
    g_debug_busy = 0;   /* 锁静态初始化，busy 复位 */
    /* 通知 workqueue（断点命中通知用，独立 wq 避免阻塞） */
    g_bp_notify_enabled = 0;
    g_bp_notify_pending = 0;
    if (kf_alloc_workqueue && kf_destroy_workqueue) {
        g_bp_wq = kf_alloc_workqueue("LH_bp", 0, 1);
        if (g_bp_wq)
            kpm_bp_init_work(&g_bp_work, kpm_debug_bp_work);
        else
            g_bp_wq = 0;
    }

    /* breakpoint 可用性 attr 变体探测：init 时逐变体注册并打印 errno，
     * 成功组合存入 g_hwbp_attr（BP_SET 复用）。-EOPNOTSUPP 的可能原因：
     *   a) exclude_kernel/exclude_hv 与 PMU 能力冲突
     *   b) branch_sample_type 非 0 触发 has_branch_stack() → -EOPNOTSUPP
     *   c) attr.size / bp_addr / bp_len 组合不满足 arch_validate
     * 探测 attr 必须与真实使用 attr 完全同形（含 sample_period），
     * 否则会出现"探测成功但零命中"的假可用。 */
    g_hwbp_pmu_status = 0;   /* 0=未探测 1=可用(含成功变体) 2=全部失败 */
    lib_memset(&g_hwbp_attr, 0, sizeof(g_hwbp_attr));
    /* 探测同时要求 perf_event_enable 符号可用——注册成功但无法启用的
     * 断点是"假可用"（0 命中），在此处判定不可用并给出原因。 */
    if (kf_register_user_hw_bp && kf_unregister_hw_bp && kf_perf_event_enable) {
        struct kpm_perf_event_attr pa;
        static const struct {
            const char *name;
            uint64_t flags;     /* exclude_kernel/hv 位 */
            uint64_t branch;    /* branch_sample_type */
            uint64_t addr;
            uint64_t len;
            uint32_t bptype;
            uint32_t size;
        } variants[] = {
            { "v1-drv-ek-ehv", (1ULL<<5)|(1ULL<<6), 0,          0x1000,     1, 4, 72 },
            { "v2-no-excl",    0,                   0,          0x1000,     1, 4, 72 },
            { "v3-branch128",  (1ULL<<5)|(1ULL<<6), 1ULL<<7,    0x1000,     1, 4, 72 },
            { "v4-branch1M",   (1ULL<<5)|(1ULL<<6), 1ULL<<20,   0x1000,     1, 4, 72 },
            { "v5-noex-br128", 0,                   1ULL<<7,    0x1000,     1, 4, 72 },
            { "v6-usr-addr",   (1ULL<<5)|(1ULL<<6), 0,          0x40000000, 1, 4, 72 },
            { "v7-sz128",      (1ULL<<5)|(1ULL<<6), 0,          0x1000,     1, 4, 128 },
            { "v8-all-clean",  0,                   1ULL<<7,    0x40000000, 4, 4, 128 },
        };
        int i;
        struct task_struct *ptask = 0;
        struct pid *ppid;

        /* per-task 断点必须传非 NULL tsk——find_get_context 对
         * task==NULL && cpu==-1 返回 -EINVAL(-22)。用 pid 1 (init)
         * 的 task_struct 探测（最稳定长存进程）。 */
        ppid = kf_find_get_pid(1);
        if (ppid) {
            ptask = kf_get_pid_task(ppid, PIDTYPE_PID);
            kf_put_pid(ppid);
        }
        if (!ptask)
            kpm_printk("LH_debug: hwbp probe no init task (probe skipped)\n");
        for (i = 0; i < (int)(sizeof(variants)/sizeof(variants[0])); i++) {
            long evt;
            lib_memset(&pa, 0, sizeof(pa));
            pa.type = KPM_PERF_TYPE_BREAKPOINT;
            pa.size = variants[i].size;
            /* sample_period 必须为 0 以外的值，否则 is_sampling_event()
             * 为假，hw_breakpoint_add() 不装载周期、__perf_event_overflow()
             * 直接 return 0，overflow_handler 永不执行。 */
            pa.sample_period = KPM_BP_SAMPLE_PERIOD;
            pa.sample_type = KPM_PERF_SAMPLE_IP;
            pa.bp_type = variants[i].bptype;
            pa.bp_addr = variants[i].addr;
            pa.bp_len = variants[i].len;
            pa.flags = variants[i].flags | (1ULL << 0);  /* disabled=bit0 */
            pa.branch_sample_type = variants[i].branch;
            evt = (long)kf_register_user_hw_bp(&pa, (void *)kpm_debug_bp_on_hit,
                                               (void *)0, (void *)ptask);
            kpm_log("debug: hwbp probe %s -> %s (%ld)\n", variants[i].name,
                    evt < -4095 ? "OK" : "FAIL", evt);
            kpm_printk("LH_debug: hwbp probe %s -> %s (%ld)\n",
                       variants[i].name, evt < -4095 ? "OK" : "FAIL", evt);
            /* 成功时返回 perf_event 内核指针，64 位下 long 为负，不能用
             * evt>0 判断；标准 ERR_PTR 值域 [-4095,-1]，
             * evt < -4095 为有效内核指针。 */
            if (evt < -4095) {
                /* 成功：保存该变体供 BP_SET 复用，并清理 */
                kf_unregister_hw_bp((void *)evt);
                g_hwbp_pmu_status = 1;
                g_hwbp_attr = pa;   /* 记录成功组合（含 disabled 位） */
                break;
            }
        }
        if (ptask)
            kpm_put_task_struct(ptask);
        if (g_hwbp_pmu_status != 1) {
            g_hwbp_pmu_status = 2;  /* 全部变体失败 */
            kpm_log("debug: hwbp ALL variants failed (last err=%ld)\n",
                    (long)kf_register_user_hw_bp(&pa, (void *)kpm_debug_bp_on_hit,
                                                 (void *)0, (void *)0));
            kpm_printk("LH_debug: hwbp ALL variants failed\n");
        }
    }

    kpm_log("debug: init (%d sw bp, %d hw bp, %d mem bp slots, notify %s, pmu=%d)\n",
            KPM_DEBUG_MAX_BREAKPOINTS, 6, KPM_DEBUG_MAX_BREAKPOINTS,
            g_bp_wq ? "wq" : "no-wq", g_hwbp_pmu_status);
    return 0;
}

/* ===== 能力查询（FEAT 降级上报用） =====
 * kpm_debug_init 内部完成 PMU 探测/工作队列/同步停靠基础设施自检；
 * 单元状态不能一律报 OK，否则会出现"硬件断点不可用但 feat state=1"
 * 的假成功。 */
int kpm_debug_hwbp_status(void)
{
    return g_hwbp_pmu_status;   /* 0=未探测 1=可用 2=不可用 */
}

int kpm_debug_sync_ok(void)
{
    return g_sync_ok ? 1 : 0;
}

int kpm_debug_wq_ok(void)
{
    return g_bp_wq ? 1 : 0;
}

/* 当前启用断点数（UN_HOOK 用） */
int kpm_debug_bp_count_active(void)
{
    int i, c = 0;
    for (i = 0; i < KPM_DEBUG_MAX_BREAKPOINTS; i++)
        if (g_bps[i].enabled)
            c++;
    return c;
}


void kpm_debug_exit(void)
{
    int i;
    /* ===== RCU 读临界区防自死锁 =====
     * 某些框架把 mod->exit() 放在 rcu_read_lock 内执行，此时调用
     * synchronize_rcu 会永久挂死（GP 等自身读临界区）。纪律：exit 里
     * 禁止一切可睡眠内核调用（synchronize_rcu / perf release /
     * destroy_workqueue）。检测到 RCU 读临界区 → 跳过这些调用并打残留
     * 警告（泄漏可接受，死锁不可接受）；正常上下文保持完整清理。三颗雷：
     *   ① kf_unregister_user_step_hook（内部 synchronize_rcu）
     *   ② kpm_debug_bp_clear → kf_unregister_hw_bp（perf_remove_from_context
     *      + event_function_call，需进程上下文可睡眠）
     *   ③ kf_destroy_workqueue（wait_for_completion 可睡眠）
     * 统一走 kpm_rcu_exit_guard_acquire 三态：借出成功(1)/确认不在临界区(0)
     * → 睡眠清理照常执行（借出时收尾 release 还回）；无法确认(-1) →
     * 跳过睡眠清理 + 残留警告。正常流程（先 FEAT_DISABLE 幂等预清理再
     * unload）下 exit 到达时已无残留。 */
    int guard = kpm_rcu_exit_guard_acquire();
    int rcu_ctx = (guard < 0) ? 1 : 0;
    if (rcu_ctx)
        kpm_log("debug: exit in RCU read-side, skip sleeping cleanups\n");
    /* 先放行全部同步停靠（RESUME + 唤醒 + 有界非睡眠等
     * 全部退出）——停靠回调还活在目标线程栈上，必须在 disarm/wq 销毁
     * 前收干，否则模块 .text 释放后回调取指 = UAF。（非睡眠设计，安全） */
    kpm_sync_trap_release_all();
    /* 步进槽收干（在途步进窗口=一条指令，常态纳秒级；有界自旋兜底。
     * 超时残留：目标在其 1 指令窗口被抢占且长期不调度——极端边角，
     * 步进异常最终触发时默认 SIGTRAP 落到该任务（进程级崩溃，
     * 非内核风险））。 */
    {
        unsigned long spins = 0;
        int busy;
        for (;;) {
            busy = 0;
            asm volatile("dmb ish" ::: "memory");
            for (i = 0; i < KPM_DBG_STEP_MAX; i++)
                if (g_steps[i].active)
                    busy = 1;
            if (!busy)
                break;
            if (spins++ > 200000000UL)
                break;
            asm volatile("yield" ::: "memory");
        }
        if (busy)
            kpm_log("debug: step slots not drained in time (residual)\n");
        kpm_dbg_mdscr_ss(0);   /* 全局 SS 位兜底清零 */
        /* 雷①：unregister_user_step_hook 内部 synchronize_rcu——RCU 读临界区
         * 内调用 = GP 永久等自身 → 死锁。残留后果：
         * step hook 回调地址随模块释放，此后任何 EL0 SS 异常触发 UAF——
         * 仅在"活跃 SS 调试中直接 unload"时可达，正常流程先 FEAT_DISABLE。 */
        if (g_step_ok && kf_unregister_user_step_hook) {
            if (rcu_ctx) {
                kpm_log("debug: SKIP unregister step hook in RCU ctx "
                        "(hook residual, UAF if SS hits later)\n");
            } else {
                kf_unregister_user_step_hook(&g_step_hook);
                g_step_ok = 0;
            }
        }
    }
    /* 自由单步 / step trace 槽收干（非 RCU 上下文释放 task 引用） */
    for (i = 0; i < KPM_FREESTEP_MAX; i++) {
        if (!g_freestep[i].active && !g_freestep[i].task)
            continue;
        if (rcu_ctx) {
            g_freestep[i].active = 0;   /* 引用泄漏（可接受） */
        } else {
            kpm_freestep_release(i);
        }
    }
    kpm_dbg_mdscr_ss(0);
    /* Clear all remaining breakpoints on module unload.
     * This prevents perf_event leaks for any breakpoints that were not
     * explicitly cleared by userspace before the target process exited. */
    {
        int n_skip = 0;
        for (i = 0; i < KPM_DEBUG_MAX_BREAKPOINTS; i++) {
            if (!g_bps[i].enabled)
                continue;
            /* 雷②：perf unregister 可睡眠（perf_remove_from_context +
             * event_function_call）。RCU 临界区内跳过，计数告警。 */
            if (rcu_ctx) {
                n_skip++;
                continue;
            }
            kpm_debug_bp_clear(i);
        }
        if (n_skip)
            kpm_log("debug: SKIP %d perf bp clear(s) in RCU ctx (leak)\n",
                    n_skip);
    }
    /* 停通知 + 销毁 workqueue（先 flush 等 work 退出） */
    g_bp_notify_enabled = 0;
    g_bp_notify_pending = 0;
    /* flush_workqueue 内部 wait_for_completion 可睡眠，在 RCU 读临界区
     * 内卸载会触发 rcu_note_context_switch WARNING。改为非睡眠有界
     * 自旋等 g_bp_work_live 归零（断点已全部 disarm，work 只做一次
     * UDP 发送，微秒级完成；~2s 上限仅防挂死兜底）。 */
    {
        unsigned long spins = 0;
        asm volatile("dmb ish" ::: "memory");
        while (g_bp_work_live && spins++ < 200000000UL)
            asm volatile("yield" ::: "memory");
        if (g_bp_work_live)
            kpm_log("debug: bp notify work not drained in time (leak)\n");
    }
    /* destroy_workqueue 内部可睡眠（等待 worker 线程退出）——此时 work
     * 已确认退出（live=0），destroy 几乎立即完成（需释放 wq 内存）。
     * 雷③：RCU 读临界区内跳过（wait_for_completion 可睡眠），
     * 残留 wq 内存泄漏可接受于死锁。 */
    if (g_bp_wq && kf_destroy_workqueue) {
        if (rcu_ctx) {
            kpm_log("debug: SKIP destroy workqueue in RCU ctx (leak)\n");
        } else {
            kf_destroy_workqueue(g_bp_wq);
            g_bp_wq = 0;
        }
    }
    if (guard > 0)
        kpm_rcu_exit_guard_release();   /* 借出模式：还回框架 RCU 读锁 */
    kpm_log("debug: exit\n");
}

/* ===== Find free slot in breakpoint array ===== */

static int find_free_slot(void)
{
    int i;
    for (i = 0; i < KPM_DEBUG_MAX_BREAKPOINTS; i++) {
        if (!g_bps[i].enabled)
            return i;
    }
    return -1;
}

/* ===== Software Breakpoint: BKPT instruction ===== */

static long sw_bp_set(pid_t pid, uint64_t addr, int idx)
{
    /* 软件断点（BKPT 指令改写目标 .text）已禁用：
     *   1. .text 字节被改写，代码段哈希/完整性检测必中（与隐蔽目标冲突）
     *   2. 目标进程执行到 BKPT 时触发 Debug 异常，本项目未实现 debug
     *      异常处理，进程将 SIGTRAP 崩溃
     * 监控请用硬件断点（KPM_BP_TYPE_HW_EXEC=1，零内存改动）。 */
    (void)pid;
    (void)addr;
    (void)idx;
    kpm_log("debug: sw bp DISABLED (BKPT alters .text + no debug handler)\n");
    return -KPM_E_INVAL;
}

static long sw_bp_clear(pid_t pid, uint64_t addr, uint32_t saved_orig)
{
    int ret;

    if (saved_orig == 0 || saved_orig == ARM64_BKPT_INSN) {
        kpm_log("debug: sw bp clear skip (no valid orig) addr=0x%llx\n", addr);
        return 0;
    }

    ret = kpm_mem_write_kernel(pid, addr, &saved_orig, 4);
    if (ret < 0) {
        kpm_log("debug: sw bp restore failed pid=%d addr=0x%llx ret=%d\n",
                pid, addr, ret);
        return ret;
    }

    kpm_log("debug: sw bp cleared pid=%d addr=0x%llx\n", pid, addr);
    return 0;
}

/* ===== Hardware Breakpoint: ARM64 debug registers =====
 *
 * Strategy: ARM64 debug registers are per-CPU. The kernel saves/restores
 * them on context switch via task->thread.debug. Since we're in the prctl
 * handler (running in kpmctl's context, not the target), we can't directly
 * set the target's debug registers.
 *
 * We use the kernel perf_event API:
 *   register_user_hw_breakpoint() - sets up a HW breakpoint for a task.
 *   This is the proper kernel interface and survives context switches.
 */

static long hw_bp_set(pid_t pid, int type, uint64_t addr, uint64_t size, int idx)
{
    long reg_err = 0;   /* register_user_hw_breakpoint 的 ERR_PTR（0=未失败） */

    /* Try perf_event API first */
    if (kf_register_user_hw_bp && kf_unregister_hw_bp) {
        struct task_struct *task;
        struct pid *pid_struct;
        struct kpm_perf_event_attr attr;
        int bp_type;
        int len;

        pid_struct = kf_find_get_pid(pid);
        if (!pid_struct)
            return -KPM_E_NOTFOUND;

        task = kf_get_pid_task(pid_struct, PIDTYPE_PID);
        if (!task) {
            kf_put_pid(pid_struct);
            return -KPM_E_NOTFOUND;
        }

        /* Map our type to perf_event HW_BREAKPOINT type */
        switch (type) {
        case KPM_BP_TYPE_HW_EXEC:  bp_type = KPM_HW_BREAKPOINT_X; break;
        case KPM_BP_TYPE_HW_WRITE: bp_type = KPM_HW_BREAKPOINT_W; break;
        case KPM_BP_TYPE_HW_RW:    bp_type = KPM_HW_BREAKPOINT_RW; break;
        default: bp_type = KPM_HW_BREAKPOINT_X; break;
        }

        /* Map size to len (1/2/4/8 bytes)；执行断点强制 1 */
        if (bp_type == KPM_HW_BREAKPOINT_X) {
            len = 1;
        } else if (size <= 1) {
            len = 1;
        } else if (size <= 2) {
            len = 2;
        } else if (size <= 4) {
            len = 4;
        } else {
            len = 8;
        }

        /* 构造 perf_event_attr：以探测成功组合 g_hwbp_attr 为基底（init
         * 时已定位可用 flags/branch/size），此处仅替换地址/长度/类型、
         * 清 disabled 位。清 disabled 位 ≠ 事件被启用：
         * register_user_hw_breakpoint 仅创建事件（停在 ctx->inactive_list），
         * 硬件槽（DBGWVR/DBGWCR）与 MDSCR.SSM 只在事件进入 active_list
         * 时编程，故注册成功后必须显式 perf_event_enable()，否则永远
         * 0 命中。若探测全部失败（pmu_status=2）或 perf_event_enable
         * 符号缺失，明确报错。 */
        if (g_hwbp_pmu_status != 1 || !kf_perf_event_enable) {
            kf_put_pid(pid_struct);
            kpm_put_task_struct(task);
            kpm_log("debug: hw bp unavailable (probe status=%d, enable sym=%s)\n",
                    g_hwbp_pmu_status, kf_perf_event_enable ? "ok" : "missing");
            /* 能力缺失不是瞬态忙——用 DISABLED 让客户端区分
             * “功能未就绪”与“插槽/会话忙”，不要统一报 BUSY。 */
            return -KPM_E_DISABLED;
        }
        lib_memset(&attr, 0, sizeof(attr));
        attr = g_hwbp_attr;
        attr.bp_type = (uint32_t)bp_type;
        attr.bp_addr = addr;
        attr.bp_len = (uint64_t)len;
        /* sample_period 必须非 0，否则事件不是 sampling event，内核在
         * __perf_event_overflow() 入口即 return 0，kpm_debug_bp_on_hit
         * 永不被调用；此处显式赋值，不依赖探测基底。 */
        attr.sample_period = KPM_BP_SAMPLE_PERIOD;
        attr.sample_type = KPM_PERF_SAMPLE_IP;
        attr.flags &= ~(1ULL << 0);   /* 清 disabled 位（enable 仍需显式调用） */

        g_bps[idx].perf_event = (uint64_t)kf_register_user_hw_bp(
            &attr, (void *)kpm_debug_bp_on_hit, (void *)&g_bps[idx], task);

        kf_put_pid(pid_struct);
        kpm_put_task_struct(task);
        /* 注：perf_event 内部持有自己的 task 引用，unregister 时释放；
         * 注册后我们 put 自己的引用，event 引用由我们（槽位）持有到
         * unregister —— 内核引用计数保证进程退出不释放 event，
         * unregister 恒安全（无 UAF）。 */

        /* register_user_hw_breakpoint 失败时返回 ERR_PTR（内核错误指针，
         * 值域 [-4095,-1]），如 -EOPNOTSUPP(-95)。不能用非空判断，否则
         * ERR_PTR 存入槽位后 BP_CLEAR 的 unregister 会解引用野指针
         * （perf_event_release_kernel NULL deref）。必须用 IS_ERR_VALUE
         * 语义识别错误指针。 */
        if (g_bps[idx].perf_event &&
            (long)g_bps[idx].perf_event >= -4095) {
            reg_err = (long)g_bps[idx].perf_event;
            kpm_log("debug: hw bp register failed err=%ld pid=%d addr=0x%llx\n",
                    reg_err, pid, addr);
            kpm_printk("LH_debug: HWBP register err=%ld pid=%d addr=0x%llx size=%u type=%u\n",
                       reg_err, pid, addr,
                       (unsigned int)attr.size, (unsigned int)attr.bp_type);
            g_bps[idx].perf_event = 0;
        }

        /* 注册只是建立事件对象，必须显式启用才会装入硬件。
         * perf_event_enable 内部 perf_remove_from_context + event_function_call，
         * 需要进程上下文（可睡眠）——本函数由 prctl/UDP 命令进入，满足约束。 */
        if (g_bps[idx].perf_event) {
            kf_perf_event_enable((void *)g_bps[idx].perf_event);
            /* 诊断字段含 sample_period：为 0 即代表回调被内核门控 */
            kpm_printk("LH_debug: HWBP enabled idx=%d evt=0x%llx pid=%d addr=0x%llx len=%u type=%d flags=0x%llx period=%llu\n",
                       idx, g_bps[idx].perf_event, pid, addr,
                       (unsigned int)attr.bp_len, (unsigned int)attr.bp_type,
                       attr.flags, (unsigned long long)attr.sample_period);
        }

        if (g_bps[idx].perf_event) {
            kpm_log("debug: hw bp set %d pid=%d addr=0x%llx type=%d (perf)\n",
                    idx, pid, addr, type);
            return 0;
        }
        kpm_log("debug: hw bp perf_event failed, trying direct regs\n");
    }

    /* Fallback: 直接操作 ARM64 调试寄存器 —— 已禁用。
     *
     * 原因：DBGBVR/DBGBCR（断点）与 DBGWVR/DBGWCR（观察点）是 per-CPU 全局
     * 寄存器。在 prctl 上下文写入后：
     *   1. 影响当前 CPU 上运行的所有进程（任何进程匹配地址都触发 Debug 异常）
     *   2. 目标进程被调度到其他 CPU 后断点立即失效
     * 这两点都可能造成系统级 Debug exception（oops/panic）。
     * 仅保留 register_user_hw_breakpoint()（per-task，内核托管）路径。 */
    kpm_log("debug: hw bp perf_event failed and direct-register fallback "
            "is DISABLED (global breakpoint risk)\n");
    /* 区分"能力缺失"与"瞬时失败"——ENOSPC（硬件槽满）
     * 是瞬态，报 BUSY/NOMEM 让客户端可重试；EOPNOTSUPP 报 DISABLED。 */
    if (reg_err) {
        if (reg_err == -28)   /* -ENOSPC：BRP/WRP 槽位耗尽 */
            return -KPM_E_NOMEM;
        if (reg_err == -22)   /* -EINVAL：地址/长度/上下文非法 */
            return -KPM_E_INVAL;
        if (reg_err == -95)   /* -EOPNOTSUPP：内核/PMU 不支持该组合 */
            return -KPM_E_DISABLED;
        return -KPM_E_BUSY;
    }
    return -KPM_E_DISABLED;   /* perf 符号缺失，直写寄存器回退已禁用 */
}

static long hw_bp_clear(int idx)
{
    pid_t pid = g_bps[idx].pid;
    int type = g_bps[idx].type;
    uint64_t addr = g_bps[idx].addr;

    /* 宽内核断点 */
    if (g_bp_kind[idx] == 1) {
        if (kf_unregister_wide_hw_bp && g_bps[idx].perf_event)
            kf_unregister_wide_hw_bp((void *)g_bps[idx].perf_event);
        g_bps[idx].perf_event = 0;
        g_bp_kind[idx] = 0;
        kpm_log("debug: wide bp cleared addr=0x%llx\n",
                (unsigned long long)addr);
        return 0;
    }

    /* If perf_event was used, unregister it */
    if (kf_unregister_hw_bp && g_bps[idx].perf_event) {
        /* ERR_PTR 值域 [-4095,-1] 不可能是合法 perf_event——若槽位出现
         * 错误指针，直接跳过 unregister（unregister 野指针 = NULL
         * deref 崩溃）。 */
        if ((long)g_bps[idx].perf_event >= -4095) {
            kpm_log("debug: hw bp clear skip ERR_PTR=%ld addr=0x%llx\n",
                    (long)g_bps[idx].perf_event, addr);
            g_bps[idx].perf_event = 0;
            return 0;
        }
        kf_unregister_hw_bp((void *)g_bps[idx].perf_event);
        g_bps[idx].perf_event = 0;
        kpm_log("debug: hw bp cleared pid=%d addr=0x%llx (perf)\n", pid, addr);
        return 0;
    }

    /* direct-register 路径已禁用，hw_reg_idx 恒为 -1 */
    (void)type;
    kpm_log("debug: hw bp clear not found addr=0x%llx\n", addr);
    return 0;
}

/* ===== Memory Breakpoint (page-aligned address recording only) ===== */

static long mem_bp_set(pid_t pid, uint64_t addr, uint64_t size, int idx)
{
    /* For memory breakpoints, only the page-aligned address is recorded
     * (saved_pte stays 0); no PTE is modified. The PTE write bit is
     * ARM64: PTE_WRITE = bit 6 in descriptor.
     */
    (void)size;

    /* Page-align the address */
    g_bps[idx].addr = addr & ~(uint64_t)0xFFF;
    g_bps[idx].saved_pte = 0; /* Will store PTE when fully implemented */
    g_bps[idx].saved_pgd = 0;

    kpm_log("debug: mem bp set %d pid=%d page=0x%llx (addr=0x%llx)\n",
            idx, pid, g_bps[idx].addr, addr);
    return 0;
}

static long mem_bp_clear(int idx)
{
    /* Placeholder: no PTE was modified, nothing to restore. */
    kpm_log("debug: mem bp cleared %d page=0x%llx\n", idx, g_bps[idx].addr);
    return 0;
}

/* ===== 同步断点实现 ===== */

/* task_work 回调：目标线程上下文（用户态边界，进程上下文，可睡眠）。
 * 到达时机：命中异常返回路径检查 TIF_NOTIFY_RESUME → task_work_run，
 * 此时 eret 尚未发生，live_regs（命中现场 pt_regs）保持完整、无用户
 * 指令执行——"指令未提交"语义与命中瞬间一致。 */
static void kpm_sync_trap_run(void *arg)
{
    kpm_sync_trap_t *t = (kpm_sync_trap_t *)arg;
    uint64_t *r;
    uint64_t waited_ms = 0;
    uint64_t mask;
    int j;

    if (!t || t->state != KPM_TRAP_ST_TRAPPED || !t->live_regs)
        return;
    r = (uint64_t *)t->live_regs;

    /* 停靠循环：100ms 粒度轮询放行/超时；RESUME 的 wake_up_process
     * 立即打断睡眠（放行延迟≈唤醒延迟，100ms 仅影响超时精度）。
     * 兼容性退回：timeout_ms=KPM_TRAP_TIMEOUT_INF 时无限等待（客户端
     * 显式指定，永久卡死风险已在协议注释标注）；默认超时自动放行。 */
    for (;;) {
        if (t->state == KPM_TRAP_ST_RELEASE)
            break;
        if (t->timeout_ms != KPM_TRAP_TIMEOUT_INF && waited_ms >= t->timeout_ms)
            break;
        if (kf_schedule_timeout_interruptible && kf_msecs_to_jiffies)
            kf_schedule_timeout_interruptible(kf_msecs_to_jiffies(100));
        waited_ms += 100;
    }

    /* 放行：SET_CONTEXT 的修改写入停靠点 pt_regs；PC 未被改写时按
     * exec_inst 标志二选一：
     *   exec_inst=1：软件单步舞步——指令【真正执行】（客户端改的寄存器
     *     直接作为指令输入，x0=0x4141 → add → 0x4142，与 Frida
     *     onEnter→modify→continue 语义一致）；
     *   exec_inst=0：PC+4 跳过命中指令（命中指令不提交，客户端自行补偿）。
     * 布局：mod[0..30]=X0-X30，mod[31]=SP，mod[32]=PC，mod[33]=PSTATE。 */
    mask = t->mod_mask;
    for (j = 0; j < 31; j++)
        if (mask & (1ULL << j))
            r[j] = t->mod[j];
    if (mask & KPM_REG_MODIFY_SP)
        r[KPM_PT_REGS_SP_OFF / 8] = t->mod[31];
    if (mask & KPM_REG_MODIFY_PC)
        r[KPM_PT_REGS_PC_OFF / 8] = t->mod[32];
    if (mask & KPM_REG_MODIFY_PSTATE)
        r[KPM_PT_REGS_PSTATE_OFF / 8] = t->mod[33];
    if (!(mask & KPM_REG_MODIFY_PC)) {
        struct task_struct *cur;
        int stepped = 0;

        if (t->exec_inst && g_step_ok) {
            asm volatile("mrs %0, sp_el0" : "=r"(cur));
            if (cur && (uint64_t)cur >= 0xFFFF000000000000ULL &&
                kpm_dbg_step_claim(t->bp_index, cur, t->live_regs,
                                   t->addr) == 0) {
                kpm_dbg_mdscr_ss(1);
                r[KPM_PT_REGS_PSTATE_OFF / 8] |= KPM_DBG_SPSR_SS;
                stepped = 1;
            }
        }
        if (!stepped)
            r[KPM_PT_REGS_PC_OFF / 8] += 4;
    }

    t->live_regs = 0;
    t->state = KPM_TRAP_ST_FREE;
    if (t->task) {
        kpm_put_task_struct((struct task_struct *)t->task);
        t->task = 0;
    }
}

/* 命中时认领停靠槽位并 task_work 入队。调用约束：持 g_debug_lock
 * （IRQ/异常上下文）；task==current（perf overflow 与命中异常同 CPU
 * 同步），task_work_add 走 current 快速路径，IRQ 安全。
 * 返回 0=已停靠（调用方走同步路径）；非 0=调用方落回 async 路径。 */
static int kpm_sync_trap_arm(int bp_idx, void *regs)
{
    kpm_sync_trap_t *t = 0;
    struct task_struct *cur;
    uint64_t *r = (uint64_t *)regs;
    int i, rc;

    asm volatile("mrs %0, sp_el0" : "=r"(cur));
    if (!cur || (uint64_t)cur < 0xFFFF000000000000ULL)
        return -KPM_E_FAULT;


    for (i = 0; i < KPM_SYNC_TRAP_MAX; i++) {
        if (g_traps[i].state == KPM_TRAP_ST_FREE) {
            t = &g_traps[i];
            break;
        }
    }
    if (!t)
        return -KPM_E_BUSY;      /* 槽满 → 兼容性退回 async */

    kpm_get_task_struct_safe(cur);
    t->state = KPM_TRAP_ST_TRAPPED;
    t->bp_index = bp_idx;
    t->pid = g_bps[bp_idx].pid;
    t->task = cur;
    t->live_regs = regs;
    lib_memcpy(t->regs, r, sizeof(t->regs));
    lib_memset(t->mod, 0, sizeof(t->mod));
    t->mod_mask = 0;
    t->addr = g_bps[bp_idx].addr;
    t->hit_count = g_bps[bp_idx].hit_count;
    t->timeout_ms = g_bp_timeout[bp_idx] ? g_bp_timeout[bp_idx]
                                         : KPM_TRAP_TIMEOUT_DEFAULT;

    t->work.next = 0;
    t->work.func = kpm_sync_trap_run;
    rc = kf_task_work_add(cur, &t->work, 1);
    if (rc != 0) {
        /* 任务已退出等：回滚槽位，调用方落回 async */
        t->task = 0;
        t->live_regs = 0;
        t->state = KPM_TRAP_ST_FREE;
        kpm_put_task_struct(cur);
        return -KPM_E_FAULT;
    }
    return 0;
}

int kpm_sync_available(void)
{
    return g_sync_ok;
}

long kpm_sync_trap_get_kernel(void *kbuf, int trap_id)
{
    kpm_trap_regs_t out;
    unsigned long flags;
    kpm_sync_trap_t *t;
    uint64_t mask;
    int j;

    if (!kbuf || trap_id < 0 || trap_id >= KPM_SYNC_TRAP_MAX)
        return -KPM_E_INVAL;

    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    t = &g_traps[trap_id];
    if (t->state != KPM_TRAP_ST_TRAPPED && t->state != KPM_TRAP_ST_RELEASE) {
        kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
        return -KPM_E_NOTFOUND;
    }
    lib_memcpy(&out, t->regs, sizeof(out));
    mask = t->mod_mask;
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);

    /* 快照 + 已有 SET 覆盖 = 客户端"读-改-写"闭环中的"读" */
    for (j = 0; j < 31; j++)
        if (mask & (1ULL << j))
            out.regs[j] = t->mod[j];
    if (mask & KPM_REG_MODIFY_SP)
        out.sp = t->mod[31];
    if (mask & KPM_REG_MODIFY_PC)
        out.pc = t->mod[32];
    if (mask & KPM_REG_MODIFY_PSTATE)
        out.pstate = t->mod[33];

    lib_memcpy(kbuf, &out, sizeof(out));
    return 0;
}

long kpm_sync_trap_get(int trap_id, void *user_buf)
{
    kpm_trap_regs_t out;
    long ret;

    if (!user_buf)
        return -KPM_E_INVAL;
    ret = kpm_sync_trap_get_kernel(&out, trap_id);
    if (ret == 0) {
        if (!kf_copy_to_user ||
            kf_copy_to_user(user_buf, &out, sizeof(out)))
            return -KPM_E_FAULT;
    }
    return ret;
}

long kpm_sync_trap_set_kernel(int trap_id, uint64_t reg_mask, const void *kbuf)
{
    kpm_trap_regs_t in;
    unsigned long flags;
    kpm_sync_trap_t *t;
    uint64_t mask;
    int j;

    if (!kbuf || trap_id < 0 || trap_id >= KPM_SYNC_TRAP_MAX)
        return -KPM_E_INVAL;
    lib_memcpy(&in, kbuf, sizeof(in));
    mask = reg_mask & ((1ULL << 34) - 1);   /* 仅 0-33 位合法 */

    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    t = &g_traps[trap_id];
    if (t->state != KPM_TRAP_ST_TRAPPED) {
        /* RELEASE 后拒绝——放行路径即将消费，晚写造成不可预期结果 */
        kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
        return -KPM_E_NOTFOUND;
    }
    for (j = 0; j < 31; j++)
        if (mask & (1ULL << j))
            t->mod[j] = in.regs[j];
    if (mask & KPM_REG_MODIFY_SP)
        t->mod[31] = in.sp;
    if (mask & KPM_REG_MODIFY_PC)
        t->mod[32] = in.pc;
    if (mask & KPM_REG_MODIFY_PSTATE)
        t->mod[33] = in.pstate;
    t->mod_mask = mask;   /* 覆盖语义：SET 以最后一次为准 */
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
    return 0;
}

long kpm_sync_trap_set(int trap_id, uint64_t reg_mask, const void *user_buf)
{
    kpm_trap_regs_t in;

    if (!user_buf || !kf_copy_from_user)
        return -KPM_E_INVAL;
    if (kf_copy_from_user(&in, user_buf, sizeof(in)))
        return -KPM_E_FAULT;
    return kpm_sync_trap_set_kernel(trap_id, reg_mask, &in);
}

long kpm_sync_trap_resume(int trap_id, uint64_t flags)
{
    unsigned long flags_;
    struct task_struct *wake[KPM_SYNC_TRAP_MAX];
    int n = 0, i;

    flags_ = kpm_spin_lock_irqsave(&g_debug_lock);
    for (i = 0; i < KPM_SYNC_TRAP_MAX; i++) {
        if (g_traps[i].state == KPM_TRAP_ST_TRAPPED &&
            (trap_id == 0xFFFFFFFF || i == (int)trap_id)) {
            /* flags bit0=EXEC_INST——放行时单步执行命中
             * 指令（客户端改的寄存器作为指令输入，Frida 语义） */
            g_traps[i].exec_inst = (uint32_t)(flags & 1);
            g_traps[i].state = KPM_TRAP_ST_RELEASE;
            wake[n++] = (struct task_struct *)g_traps[i].task;
        }
    }
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags_);

    for (i = 0; i < n; i++)
        if (wake[i] && kf_wake_up_process)
            kf_wake_up_process(wake[i]);
    /* 唤醒与停靠循环的检查-睡眠竞态窗口 ≤100ms 粒度（见 run 注释），
     * RESUME 常态延迟 = 立即。n==0 且非全放行 → idempotent 成功。 */
    return 0;
}

long kpm_sync_trap_list_kernel(void *kbuf, int max_count)
{
    kpm_trap_info_t arr[KPM_SYNC_TRAP_MAX];
    unsigned long flags;
    int i, n = 0;

    if (!kbuf || max_count <= 0)
        return -KPM_E_INVAL;
    if (max_count > KPM_SYNC_TRAP_MAX)
        max_count = KPM_SYNC_TRAP_MAX;

    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    for (i = 0; i < KPM_SYNC_TRAP_MAX && n < max_count; i++) {
        if (g_traps[i].state == KPM_TRAP_ST_FREE)
            continue;
        arr[n].trap_id = (uint32_t)i;
        arr[n].state = (uint32_t)g_traps[i].state;
        arr[n].bp_index = g_traps[i].bp_index;
        arr[n].pid = g_traps[i].pid;
        arr[n].addr = g_traps[i].addr;
        arr[n].pc = g_traps[i].regs[32];
        arr[n].hit_count = g_traps[i].hit_count;
        n++;
    }
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);

    lib_memcpy(kbuf, arr, (unsigned long)n * sizeof(kpm_trap_info_t));
    return n;
}

long kpm_sync_trap_list(kpm_trap_info_t *user_buf, int max_count)
{
    kpm_trap_info_t arr[KPM_SYNC_TRAP_MAX];
    long n;

    if (!user_buf)
        return -KPM_E_INVAL;
    n = kpm_sync_trap_list_kernel(arr, max_count);
    if (n > 0) {
        if (!kf_copy_to_user ||
            kf_copy_to_user(user_buf, arr,
                            (unsigned long)n * sizeof(kpm_trap_info_t)))
            return -KPM_E_FAULT;
    }
    return n;
}

/* 卸载/清除断点路径：放行全部停靠并等待退出（有界非睡眠自旋，
 * 与 g_bp_work_live 排空同模式）。返回 0=全部退出。 */
int kpm_sync_trap_release_all(void)
{
    unsigned long flags;
    struct task_struct *wake[KPM_SYNC_TRAP_MAX];
    unsigned long spins = 0;
    int n = 0, i, busy;

    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    for (i = 0; i < KPM_SYNC_TRAP_MAX; i++) {
        if (g_traps[i].state == KPM_TRAP_ST_TRAPPED) {
            g_traps[i].state = KPM_TRAP_ST_RELEASE;
            wake[n++] = (struct task_struct *)g_traps[i].task;
        }
    }
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);

    for (i = 0; i < n; i++)
        if (wake[i] && kf_wake_up_process)
            kf_wake_up_process(wake[i]);

    for (;;) {
        busy = 0;
        asm volatile("dmb ish" ::: "memory");
        for (i = 0; i < KPM_SYNC_TRAP_MAX; i++)
            if (g_traps[i].state != KPM_TRAP_ST_FREE)
                busy = 1;
        if (!busy)
            return 0;
        if (spins++ > 200000000UL)
            break;
        asm volatile("yield" ::: "memory");
    }
    /* 超时兜底：唤醒已发出、任务必然在 100ms 粒度内退出循环；若仍
     * 未退出说明调度异常——继续卸载有 UAF 风险，显式记录（不静默）。 */
    kpm_log("sync: traps not drained in time (unload risk)\n");
    return -KPM_E_BUSY;
}

long kpm_debug_bp_set_sync(pid_t pid, int type, uint64_t addr, uint64_t size,
                           uint32_t timeout_ms)
{
    long idx;

    /* 同步模式仅对硬件断点/观察点有意义（SW/MEM 类型本身不可用或
     * 无命中回调） */
    if (type != KPM_BP_TYPE_HW_EXEC && type != KPM_BP_TYPE_HW_WRITE &&
        type != KPM_BP_TYPE_HW_RW)
        return -KPM_E_INVAL;
    if (!g_sync_ok)
        return -KPM_E_DISABLED;   /* 基础设施缺失：兼容性退回为不可用 */

    idx = kpm_debug_bp_set(pid, type, addr, size);
    if (idx < 0)
        return idx;

    g_bp_sync[idx] = 1;
    /* timeout_ms: 0=默认 2s；KPM_TRAP_TIMEOUT_INF=无限（永久卡死风险，
     * 客户端显式指定） */
    g_bp_timeout[idx] = timeout_ms ? timeout_ms : KPM_TRAP_TIMEOUT_DEFAULT;
    return idx;
}

long kpm_debug_bp_hook_rule_set(int index, const kpm_bp_hook_rule_t *r)
{
    unsigned long flags;

    if (index < 0 || index >= KPM_DEBUG_MAX_BREAKPOINTS)
        return -KPM_E_INVAL;
    if (r && r->action > KPM_HOOK_ACT_REDIRECT)
        return -KPM_E_INVAL;

    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    if (!g_bps[index].enabled) {
        kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
        return -KPM_E_NOTFOUND;
    }
    if (r) {
        /* 与同步停靠互斥：规则挂到已开 sync 的断点上语义冲突 */
        if (g_bp_sync[index]) {
            kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
            return -KPM_E_BUSY;
        }
        g_bp_hook[index] = *r;
        g_bp_hook[index].active = 1;
        g_bp_hook[index].arg_mask &= 0xFF;   /* 仅 X0-X7 */
    } else {
        lib_memset(&g_bp_hook[index], 0, sizeof(g_bp_hook[index]));
    }
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
    return 0;
}

int kpm_debug_bp_hook_state(int index, pid_t *pid, uint64_t *addr,
                            int *action, uint64_t *hit_count)
{
    unsigned long flags;
    int active;

    if (index < 0 || index >= KPM_DEBUG_MAX_BREAKPOINTS)
        return -KPM_E_INVAL;
    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    active = (g_bps[index].enabled && g_bp_hook[index].active) ? 1 : 0;
    if (active) {
        if (pid) *pid = g_bps[index].pid;
        if (addr) *addr = g_bps[index].addr;
        if (action) *action = g_bp_hook[index].action;
        if (hit_count) *hit_count = g_bps[index].hit_count;
    }
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);
    return active;
}

/* ===== Public API ===== */

long kpm_debug_bp_set(pid_t pid, int type, uint64_t addr, uint64_t size)
{
    int idx;
    long ret;

    if (size == 0)
        size = 4; /* default */

    if (pid <= 0)
        return -KPM_E_INVAL;

    /* addr=0 校验：0 不是合法断点/观察点地址，所有类型统一拒绝（fail-fast）。 */
    if (addr == 0)
        return -KPM_E_INVAL;

    /* 尺寸/对齐前置校验（HW 类型）。X 断点忽略 size，地址
     * 按 4 字节指令对齐；W/RW 观察点 size 仅 1/2/4/8，且地址按 size
     * 对齐。提前返回具体 INVAL，避免 perf 内部笼统错误。 */
    if (type == KPM_BP_TYPE_HW_EXEC) {
        if (addr & 0x3) {
            kpm_log("debug: hw exec bp addr misaligned 0x%llx\n", addr);
            return -KPM_E_INVAL;
        }
    } else if (type == KPM_BP_TYPE_HW_WRITE || type == KPM_BP_TYPE_HW_RW) {
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            kpm_log("debug: hw bp bad size %llu\n", size);
            return -KPM_E_INVAL;
        }
        if (addr & (size - 1)) {
            kpm_log("debug: hw bp addr 0x%llx not aligned to %llu\n",
                    addr, size);
            return -KPM_E_INVAL;
        }
    }

    /* 会话互斥：防止 bp_set 半初始化时被并发 bp_clear/copy_list 访问 */
    if (debug_enter() < 0)
        return -KPM_E_BUSY;

    /* Find empty slot */
    idx = find_free_slot();
    if (idx < 0) {
        debug_leave();
        return -KPM_E_NOMEM;
    }

    /* Initialize entry */
    g_bps[idx].pid = pid;
    g_bps[idx].addr = addr;
    g_bps[idx].size = size;
    g_bps[idx].type = type;
    g_bps[idx].hit_count = 0;
    g_bps[idx].saved_orig = 0;
    g_bps[idx].saved_pte = 0;
    g_bps[idx].saved_pgd = 0;
    g_bps[idx].perf_event = 0;
    g_bps[idx].hw_reg_idx = -1;
    g_bps[idx].notify = 1;   /* HW 断点默认通知（受 BP_NOTIFY 全局开关控制） */

    switch (type) {
    case KPM_BP_TYPE_SOFTWARE:
        ret = sw_bp_set(pid, addr, idx);
        break;

    case KPM_BP_TYPE_HW_EXEC:
    case KPM_BP_TYPE_HW_WRITE:
    case KPM_BP_TYPE_HW_RW:
        ret = hw_bp_set(pid, type, addr, size, idx);
        break;

    case KPM_BP_TYPE_MEMORY:
        ret = mem_bp_set(pid, addr, size, idx);
        break;

    default:
        kpm_log("debug: unknown bp type %d\n", type);
        debug_leave();
        return -KPM_E_INVAL;
    }

    if (ret < 0) {
        lib_memset(&g_bps[idx], 0, sizeof(kpm_breakpoint_t));
        debug_leave();
        return ret;
    }

    g_bps[idx].enabled = 1;
    g_bp_kind[idx] = 0;
    debug_leave();
    return idx;
}

/* 内核/宽硬件断点（force）。仅 W/RW 数据观察；X 无安全推进。 */
long kpm_debug_bp_set_kernel(uint64_t addr, int type, uint64_t size,
                             uint64_t flags)
{
    int idx;
    struct kpm_perf_event_attr attr;
    void *pevs;
    int bp_type, len;

    if (!addr || (addr & 0x3))
        return -KPM_E_INVAL;
    if (type == KPM_BP_TYPE_HW_EXEC)
        return -KPM_E_DISABLED;   /* 内核 exec 无安全 PC 推进 */
    if (type != KPM_BP_TYPE_HW_WRITE && type != KPM_BP_TYPE_HW_RW)
        return -KPM_E_INVAL;
    if (!kf_register_wide_hw_bp || !kf_unregister_wide_hw_bp)
        return -KPM_E_DISABLED;
    if (g_hwbp_pmu_status != 1)
        return -KPM_E_DISABLED;
    if (size != 1 && size != 2 && size != 4 && size != 8)
        return -KPM_E_INVAL;
    if (addr & (size - 1))
        return -KPM_E_INVAL;
    bp_type = (type == KPM_BP_TYPE_HW_WRITE) ? KPM_HW_BREAKPOINT_W
                                             : KPM_HW_BREAKPOINT_RW;
    len = (int)size;

    if (debug_enter() < 0)
        return -KPM_E_BUSY;
    idx = find_free_slot();
    if (idx < 0) {
        debug_leave();
        return -KPM_E_NOMEM;
    }
    lib_memset(&g_bps[idx], 0, sizeof(g_bps[idx]));
    g_bps[idx].pid = 0;
    g_bps[idx].addr = addr;
    g_bps[idx].size = size;
    g_bps[idx].type = type;
    g_bps[idx].notify = 0;
    attr = g_hwbp_attr;
    attr.bp_type = (uint32_t)bp_type;
    attr.bp_addr = addr;
    attr.bp_len = (uint64_t)len;
    attr.sample_period = KPM_BP_SAMPLE_PERIOD;
    attr.sample_type = KPM_PERF_SAMPLE_IP;
    /* 内核数据观察：exclude_user + exclude_hv，允许 kernel */
    attr.flags &= ~(1ULL << 0);   /* disabled=0 */
    attr.flags |= (1ULL << 4) | (1ULL << 6);
    attr.flags &= ~(1ULL << 5);

    pevs = kf_register_wide_hw_bp(&attr, (void *)kpm_debug_bp_on_hit,
                                  &g_bps[idx]);
    if (!pevs || ((long)pevs < 0 && (long)pevs >= -4095)) {
        kpm_log("debug: wide hw bp register failed (%ld) addr=0x%llx\n",
                (long)pevs, (unsigned long long)addr);
        lib_memset(&g_bps[idx], 0, sizeof(g_bps[idx]));
        debug_leave();
        return -KPM_E_DISABLED;
    }
    g_bps[idx].perf_event = (uint64_t)pevs;
    g_bps[idx].enabled = 1;
    g_bp_kind[idx] = 1;
    g_bp_flags[idx] = (uint32_t)flags & 0xFFu;
    debug_leave();
    kpm_log("debug: wide kernel bp set idx=%d addr=0x%llx type=%d len=%d\n",
            idx, (unsigned long long)addr, type, len);
    return idx;
}

int kpm_debug_bp_limits(int *brp, int *wrp)
{
    if (brp) *brp = g_hw_brp_limit;
    if (wrp) *wrp = g_hw_wrp_limit;
    return 0;
}

/* 带 flags 的用户断点（增强调试） */
long kpm_debug_bp_set_flags(pid_t pid, int type, uint64_t addr,
                            uint64_t size_flags)
{
    uint64_t size = size_flags & 0xFFFFFFFFULL;
    uint32_t packed = (uint32_t)(size_flags >> 32) & 0xFFFFu;
    uint32_t flags = packed & 0xFFu;
    uint32_t maxhits = (packed >> 8) & 0xFFu;
    unsigned long lf;
    long idx;

    /* EXEC_INST：真执行需要软件单步舞步（摘武装 → SS → 步进回装）。
     * 该路径存在 perf 单步竞态风险，必须显式 force STEP；单步不可用
     * （如 4.19 register_user_step_hook 门控）返回 DISABLED。 */
    if (flags & KPM_BP_FLAG_EXEC_INST) {
        if (type != KPM_BP_TYPE_HW_EXEC)
            return -KPM_E_INVAL;
        if (kpm_force_require(KPM_FORCE_STEP) < 0)
            return -KPM_E_PERM;
        if (!g_step_ok)
            return -KPM_E_DISABLED;
    }
    if (flags & KPM_BP_FLAG_KERNEL_ACCESS) {
        if (kpm_force_require(KPM_FORCE_KERNEL_BP) < 0)
            return -KPM_E_PERM;
    }

    idx = kpm_debug_bp_set(pid, type, addr, size);
    if (idx < 0)
        return idx;

    lf = kpm_spin_lock_irqsave(&g_debug_lock);
    g_bp_flags[idx] = flags;
    g_bp_maxhits[idx] = maxhits;
    if (flags & KPM_BP_FLAG_NO_NOTIFY)
        g_bps[idx].notify = 0;
    kpm_spin_unlock_irqrestore(&g_debug_lock, lf);
    kpm_log("debug: bp flags idx=%ld flags=0x%x max_hits=%u\n",
            idx, flags, maxhits);
    return idx;
}

/* 断点能力/容量查询 */
long kpm_debug_bp_info(kpm_bp_caps_t *out)
{
    int i;

    if (!out)
        return -KPM_E_INVAL;
    if (debug_enter() < 0)
        return -KPM_E_BUSY;
    lib_memset(out, 0, sizeof(*out));
    out->max_slots = KPM_DEBUG_MAX_BREAKPOINTS;
    out->brp = g_hw_brp_limit;
    out->wrp = g_hw_wrp_limit;
    out->step_ok = g_step_ok ? 1u : 0u;
    out->sync_ok = g_sync_ok ? 1u : 0u;
    for (i = 0; i < KPM_DEBUG_MAX_BREAKPOINTS; i++) {
        if (!g_bps[i].enabled)
            continue;
        out->used_slots++;
        if (g_bp_kind[i] == 1)
            out->kernel_bps++;
        else
            out->user_bps++;
    }
    debug_leave();
    return 0;
}

long kpm_debug_bp_clear(int index)
{
    long ret = 0;

    /* IMPORTANT: If this breakpoint was set via register_user_hw_breakpoint(),
     * it holds a reference to the target task_struct. Failing to clear it
     * before the target process exits will leak the perf_event and prevent
     * the kernel from fully reclaiming the task's resources. */
    if (index < 0 || index >= KPM_DEBUG_MAX_BREAKPOINTS)
        return -KPM_E_INVAL;

    if (debug_enter() < 0)
        return -KPM_E_BUSY;

    if (!g_bps[index].enabled) {
        debug_leave();
        return 0;   /* 幂等清除（无断点 = 成功） */
    }

    /* 放行该断点上仍停靠的同步命中（否则目标等超时才恢复） */
    {
        unsigned long f2;
        int k, nw = 0;
        struct task_struct *wake[KPM_SYNC_TRAP_MAX];
        f2 = kpm_spin_lock_irqsave(&g_debug_lock);
        for (k = 0; k < KPM_SYNC_TRAP_MAX; k++) {
            if (g_traps[k].state == KPM_TRAP_ST_TRAPPED &&
                g_traps[k].bp_index == index) {
                g_traps[k].state = KPM_TRAP_ST_RELEASE;
                wake[nw++] = (struct task_struct *)g_traps[k].task;
            }
        }
        kpm_spin_unlock_irqrestore(&g_debug_lock, f2);
        for (k = 0; k < nw; k++)
            if (wake[k] && kf_wake_up_process)
                kf_wake_up_process(wake[k]);
    }

    switch (g_bps[index].type) {
    case KPM_BP_TYPE_SOFTWARE:
        ret = sw_bp_clear(g_bps[index].pid, g_bps[index].addr,
                          g_bps[index].saved_orig);
        break;

    case KPM_BP_TYPE_HW_EXEC:
    case KPM_BP_TYPE_HW_WRITE:
    case KPM_BP_TYPE_HW_RW:
        ret = hw_bp_clear(index);
        break;

    case KPM_BP_TYPE_MEMORY:
        ret = mem_bp_clear(index);
        break;
    }

    lib_memset(&g_bps[index], 0, sizeof(kpm_breakpoint_t));
    g_bp_kind[index] = 0;
    g_bp_flags[index] = 0;
    g_bp_maxhits[index] = 0;
    g_bp_clear_pending[index] = 0;
    lib_memset(&g_bp_regmod[index], 0, sizeof(kpm_bp_regmod_t));
    g_bp_sync[index] = 0;      /* 同步属性随断点清除 */
    g_bp_timeout[index] = 0;
    lib_memset(&g_bp_hook[index], 0, sizeof(g_bp_hook[index]));
    debug_leave();
    return ret;
}

long kpm_debug_bp_copy_list(kpm_breakpoint_t *user_buf, int max_count)
{
    kpm_breakpoint_t snap[KPM_DEBUG_MAX_BREAKPOINTS];
    int i, last = -1, n;

    if (!user_buf || max_count <= 0)
        return -KPM_E_INVAL;
    if (max_count > KPM_DEBUG_MAX_BREAKPOINTS)
        max_count = KPM_DEBUG_MAX_BREAKPOINTS;

    if (debug_enter() < 0)
        return -KPM_E_BUSY;

    /* 输出 [0..last_active] 的稠密前缀（空槽照常输出，enabled=0），
     * 保留"位置 i == 槽位索引"的语义——客户端仍可用
     * BP_CLEAR(i)/HIT_COUNT(i)/MODIFY(i) 直接操作对应槽位。
     * 无断点时 last=-1 → 返回 0。不能压缩掉空槽，否则位置与槽位索引
     * 错位，会清错断点。 */
    for (i = 0; i < KPM_DEBUG_MAX_BREAKPOINTS; i++) {
        if (g_bps[i].enabled)
            last = i;
    }
    n = last + 1;
    if (n > max_count)
        n = max_count;
    if (n > 0)
        lib_memcpy(snap, g_bps, (unsigned long)n * sizeof(snap[0]));
    debug_leave();

    if (n == 0)
        return 0;
    if (!kf_copy_to_user)
        return -KPM_E_FAULT;
    if (kf_copy_to_user(user_buf, snap, (unsigned long)n * sizeof(snap[0])))
        return -KPM_E_FAULT;
    return n;
}

/* UDP 通道版（resp_data 是内核缓冲，不能用 copy_to_user）。
 * 与 kpm_debug_bp_copy_list 同锁同语义，内核态直接 memcpy。 */
long kpm_debug_bp_copy_list_kernel(void *kbuf, int max_count)
{
    int i, last = -1, n;

    if (!kbuf || max_count <= 0)
        return -KPM_E_INVAL;
    if (max_count > KPM_DEBUG_MAX_BREAKPOINTS)
        max_count = KPM_DEBUG_MAX_BREAKPOINTS;

    if (debug_enter() < 0)
        return -KPM_E_BUSY;

    /* 同 kpm_debug_bp_copy_list：稠密前缀，保留位置=槽位索引 */
    for (i = 0; i < KPM_DEBUG_MAX_BREAKPOINTS; i++) {
        if (g_bps[i].enabled)
            last = i;
    }
    n = last + 1;
    if (n > max_count)
        n = max_count;
    if (n > 0)
        lib_memcpy(kbuf, g_bps, (unsigned long)n * sizeof(g_bps[0]));
    debug_leave();
    return n;
}

long kpm_debug_bp_copy_hit(kpm_bp_hit_t *user_buf)
{
    long ret;

    if (!user_buf)
        return -KPM_E_INVAL;

    if (debug_enter() < 0)
        return -KPM_E_BUSY;

    ret = 0;
    if (kf_copy_to_user) {
        if (kf_copy_to_user(user_buf, &g_bp_hit, sizeof(kpm_bp_hit_t)))
            ret = -KPM_E_FAULT;
        else
            ret = 0;
    } else {
        ret = -KPM_E_FAULT;
    }

    /* Clear hit after reading */
    lib_memset(&g_bp_hit, 0, sizeof(g_bp_hit));
    debug_leave();
    return ret;
}

/* UDP 通道版（resp_data 是内核缓冲，不能用 copy_to_user）。
 * 同锁同语义（读后清命中）。 */
long kpm_debug_bp_copy_hit_kernel(void *kbuf)
{
    long ret;

    if (!kbuf)
        return -KPM_E_INVAL;

    if (debug_enter() < 0)
        return -KPM_E_BUSY;

    lib_memcpy(kbuf, &g_bp_hit, sizeof(kpm_bp_hit_t));
    ret = 0;

    /* Clear hit after reading */
    lib_memset(&g_bp_hit, 0, sizeof(g_bp_hit));
    debug_leave();
    return ret;
}

/* 断点命中通知开关（KPM_CMD_DEBUG_BP_NOTIFY）。
 * enable: 1=启用 0=停用；client_addr 非空时记录通知目标（UDP 通道
 * 传 recvfrom 源地址）；prctl 通道传 NULL 复用上次记录地址。
 * 启用后 notify=1 的断点命中经 workqueue 异步推送 kpm_bp_notify_t。 */
long kpm_debug_bp_notify_set(int enable, void *client_addr, int port)
{
    unsigned long flags;

    (void)port;
    flags = kpm_spin_lock_irqsave(&g_debug_lock);
    if (client_addr)
        g_bp_notify_client = *(struct kpm_sockaddr_in *)client_addr;
    g_bp_notify_enabled = enable ? 1 : 0;
    if (!enable)
        g_bp_notify_pending = 0;
    kpm_spin_unlock_irqrestore(&g_debug_lock, flags);

    kpm_log("debug: bp notify %s (client %s)\n",
            enable ? "enabled" : "disabled",
            enable ? "recorded" : "cleared");
    return 0;
}

/* ===== Single Step & Continue =====
 *
 * Single step on ARM64 is controlled by MDSCR_EL1.SS (bit 0), a global
 * register that affects the current CPU rather than a specific process.
 * Stepping a target thread is done via task_work (PSTATE.SS at the return
 * to userspace) and register_user_step_hook, which suppresses SIGTRAP
 * and records the register snapshot; see kpm_debug_step_trace.
 */

long kpm_debug_single_step(pid_t pid, pid_t tid)
{
    /* 真单步（1 条指令）——task_work 在目标返回用户态时置
     * PSTATE.SS，user_step_hook 抑制 SIGTRAP 并记录快照。
     * 4.19 无 register_user_step_hook → DISABLED（不能抑制 SIGTRAP）。 */
    return kpm_debug_step_trace(pid, tid, 1);
}

long kpm_debug_continue(pid_t pid, pid_t tid)
{
    /* 提前结束该 tid 的单步/step trace */
    long r = kpm_debug_step_stop(tid);
    (void)pid;
    if (r == 0)
        return 0;
    return -KPM_E_NOTFOUND;
}