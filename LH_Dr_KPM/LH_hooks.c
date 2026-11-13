/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_hooks.c - prctl command dispatch for TVF V2 TouchHandle API
 *
 * Maps prctl commands to the TouchHandle API:
 *   KPM_CMD_TOUCH_CREATE  → touch_create
 *   KPM_CMD_TOUCH_MOVE    → touch_move
 *   KPM_CMD_TOUCH_UP      → touch_up
 *   KPM_CMD_TOUCH_DESTROY → touch_destroy
 *   KPM_CMD_TOUCH_MOVE_TO → touch_move_to
 *   KPM_CMD_TOUCH_MOVE_DIR→ touch_move_dir
 *   KPM_CMD_TOUCH_GET     → touch_get_info
 *   KPM_CMD_TOUCH_GET_ALL → touch_get_all_info
 *   KPM_CMD_TOUCH_COUNT   → touch_get_active_count
 *   KPM_CMD_TOUCH_SUSPEND → touch_suspend
 *   KPM_CMD_TOUCH_RESUME  → touch_resume
 *   KPM_CMD_TOUCH_TAKEOVER→ touch_takeover
 *   KPM_CMD_TOUCH_POLICY  → touch_set_policy
 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>
#include <ksyms.h>
#include <baselib.h>

#include "LH_comm.h"
#include "LH_cmd.h"      /* 统一协议处理层 */
#include "LH_hooks.h"
#include "LH_touch.h"
#include "LH_utils.h"
#include "LH_log.h"
#include "LH_intercept.h"
#include "LH_syms.h"
#include "touch_manager.h"
#include "LH_mem_scan.h"
#include "LH_mem_freeze.h"
#include "LH_ptr_scan.h"
#include "LH_debug.h"
#include "LH_hook_enhanced.h"
#include "LH_mem_rw.h"
#include "LH_proc.h"

/* prctl syscall number: __NR_prctl = 167 (ARM64) */
#define KPM_PRCTL_NR  __NR_prctl

static int g_prctl_hooked = 0;

/* prctl 通道诊断预算：仅对 DEBUG_BP_SET..FEAT_STATE 区段记录
 * 前 64 条（debug 构建生效，release 为空操作），避免 root 常驻进程
 * prctl 刷屏。 */
#ifdef KPM_DEBUG
static volatile uint32_t g_prctl_dbg_budget = 64;
#endif

/* prctl 回调在途计数。
 * 回调内含 kf_copy_to_user（可 sleep），不能用 RCU 读锁（RCU 临界区
 * sleep 触发内核告警），改用无锁原子加减（LH_utils.h
 * kpm_atomic_inc/dec_acq_rel + kpm_inflight_is_zero）+ 卸载侧有界等待归零：
 *   1. wrapper 在回调入口 inc / 出口 dec（多 return 路径统一由 wrapper 收口）
 *   2. kpm_hooks_exit 在 fp_unhook_syscalln 之后等待 g_prctl_inflight 归零，
 *      保证在途回调全部退出后才释放模块 .text（防取指 UAF）
 * 计数在 UID 过滤之前（必须覆盖 hook 入口的全部在途流量）；
 * 忙等仅发生在卸载路径（低频、有界）。 */
static volatile int g_prctl_inflight = 0;

#define KPM_PRCTL_DRAIN_TIMEOUT_LOOPS  100000000UL   /* ~10s @ 10M loops/s，覆盖长命令（prctl 扫描） */

static void kpm_prctl_drain(void)
{
    unsigned long spins = 0;
    int confirm_tries = 0;

    for (;;) {
        /* 第一段：普通 acquire 读自旋等归零（无额外延迟，避免放大等待） */
        while (kpm_atomic_read_acquire(&g_prctl_inflight) != 0) {
            if (++spins > KPM_PRCTL_DRAIN_TIMEOUT_LOOPS) {
                kpm_log("kpm: prctl hook drain timeout (%d inflight)\n",
                        (int)kpm_atomic_read_acquire(&g_prctl_inflight));
                return;   /* 有界兜底：超时不再等 */
            }
            asm volatile("yield" ::: "memory");
        }

        /* 第二段：读到 0 后做**一次**最终确认（barrier + 有界等待 + 复读），
         * 关掉"对方 inc 已执行但 store 还压在 store buffer"的窗口 ——
         * 推导见 LH_utils.h: kpm_inflight_final_zero。确认失败（计数又冒出来）
         * 就回到第一段继续等，最多 3 轮。 */
        if (kpm_inflight_final_zero(&g_prctl_inflight))
            return;
        if (++confirm_tries >= 3) {
            kpm_log("kpm: prctl inflight unstable after %d confirmations\n",
                    confirm_tries);
            return;
        }
    }
}

static void kpm_prctl_inflight_inc(void)
{
    kpm_atomic_inc_acq_rel(&g_prctl_inflight);
}

static void kpm_prctl_inflight_dec(void)
{
    kpm_atomic_dec_acq_rel(&g_prctl_inflight);
}

/* 函数体（wrapper 调用，需前向声明） */
void kpm_prctl_before_impl(hook_fargs5_t *args, void *udata);

/* ===== prctl hook callback =====
 * wrapper 负责在途计数保护，函数体在 _impl 实现。 */
void kpm_prctl_before(hook_fargs5_t *args, void *udata)
{
    kpm_prctl_inflight_inc();
    kpm_prctl_before_impl(args, udata);
    kpm_prctl_inflight_dec();
}

void kpm_prctl_before_impl(hook_fargs5_t *args, void *udata)
{
    uint64_t *sargs = syscall_args(args);
    unsigned int option = (unsigned int)sargs[0];
    unsigned long arg2 = sargs[1];
    unsigned long arg3 = sargs[2];
    unsigned long arg4 = sargs[3];
    unsigned long arg5 = sargs[4];

    long ret = 0;

    (void)udata;  /* 预留回调数据，当前未使用 */

    /* Anti-detection: only respond to root (UID 0) callers.
     * Non-root callers get identical behavior to unknown prctl options
     * (returns -EINVAL via original handler), preventing brute-force
     * command code probing by unprivileged apps. */
    if (current_uid() != 0) {
        args->skip_origin = 0;
        return;
    }

    /* ===== 统一协议处理层 =====
     * prctl 接口层仅做参数布局翻译 + 调 kpm_cmd_dispatch；
     * 命令实现统一收敛在协议层（与 UDP 通道共用）。
     *
     * prctl 布局 → 协议层统一布局翻译：
     *   列表/结果类命令 prctl 用 arg2=user_buf, arg3=max_count, arg4=offset；
     *   协议层统一 arg2=max_count, arg3=offset，user_out=用户缓冲。
     *   内存读写 prctl 用 arg4=user_buf；协议层统一 user_out=arg4。 */
    {
        uint32_t cmd = (uint32_t)option ^ KPM_CMD_XOR_KEY;  /* 还原命令码 */
        kpm_cmd_ctx_t ctx;
        long dispatch_ret;

        /* 诊断日志覆盖 DEBUG_BP_SET(0x1130)..FEAT_STATE(0x1203) 区段，
         * 仅 debug 构建保留（release 零开销）。 */
#ifdef KPM_DEBUG
        if (cmd >= KPM_CMD_DEBUG_BP_SET && cmd <= KPM_CMD_FEAT_STATE &&
            g_prctl_dbg_budget > 0) {
            g_prctl_dbg_budget--;
            kpm_log_info("prctl: cmd=0x%x a2=0x%llx a3=0x%llx\n",
                         (unsigned int)cmd,
                         (unsigned long long)arg2,
                         (unsigned long long)arg3);
        }
#endif

        lib_memset(&ctx, 0, sizeof(ctx));
        ctx.channel  = KPM_CHAN_PRCTL;
        ctx.cmd      = cmd;
        ctx.arg2     = arg2;
        ctx.arg3     = arg3;
        ctx.arg4     = arg4;
        ctx.arg5     = arg5;
        ctx.chan_ctx = NULL;   /* prctl 无源地址，断点通知复用上次记录地址 */

        /* 参数布局翻译：把 prctl 的用户缓冲参数装入 user_out，
         * 列表/结果类命令的 max_count/offset 重排到协议层统一位置。 */
        switch (cmd) {
        /* 内存读写：arg4 = user_buf */
        case KPM_CMD_READ_MEM:
        case KPM_CMD_WRITE_MEM:
            ctx.user_out = (void *)arg4;
            ctx.user_out_cap = (uint32_t)arg5;
            break;
        /* 进程列表：arg2=buf, arg3=max_count, arg4=offset */
        case KPM_CMD_PROC_LIST:
            ctx.user_out = (void *)arg2;
            ctx.arg2 = arg3;          /* max_count */
            ctx.arg3 = arg4;          /* offset */
            break;
        /* 进程 maps：arg2=pid, arg3=buf, arg4=max_count */
        case KPM_CMD_PROC_MAPS:
            ctx.user_out = (void *)arg3;
            ctx.arg3 = arg4;          /* max_count */
            ctx.arg4 = 0;             /* offset=0（prctl 无分页） */
            break;
        /* 查询区域：arg2=pid, arg3=addr, arg4=buf */
        case KPM_CMD_PROC_QUERY_REGION:
            ctx.user_out = (void *)arg4;
            break;
        /* 扫描结果：arg2=buf, arg3=max_count, arg4=offset */
        case KPM_CMD_MEM_SCAN_RESULT:
            ctx.user_out = (void *)arg2;
            ctx.arg2 = arg3;          /* max_count */
            ctx.arg3 = arg4;          /* offset */
            break;
        /* 冻结列表：arg2=buf, arg3=max_count */
        case KPM_CMD_FREEZE_LIST:
            ctx.user_out = (void *)arg2;
            ctx.arg2 = arg3;          /* max_count */
            break;
        /* 指针结果：arg2=buf, arg3=max_count, arg4=offset */
        case KPM_CMD_PTR_RESULT:
            ctx.user_out = (void *)arg2;
            ctx.arg2 = arg3;          /* max_count */
            ctx.arg3 = arg4;          /* offset */
            break;
        /* 断点列表：arg2=buf, arg3=max_count, arg4=buf_size（可选，0=不限） */
        case KPM_CMD_DEBUG_BP_LIST:
            ctx.user_out = (void *)arg2;
            ctx.arg2 = arg3;          /* max_count */
            ctx.user_out_cap = (uint32_t)arg4;  /* 可选 buf_size */
            break;
        /* 断点命中：arg2=buf */
        case KPM_CMD_DEBUG_BP_HIT:
            ctx.user_out = (void *)arg2;
            break;
        /* Hook 列表：arg2=buf, arg3=max_count */
        case KPM_CMD_HOOK_LIST:
            ctx.user_out = (void *)arg2;
            ctx.arg2 = arg3;          /* max_count */
            break;
        /* 隐藏记录列表：arg2=buf, arg3=max_count */
        case KPM_CMD_HIDE_LIST:
            ctx.user_out = (void *)arg2;
            ctx.arg2 = arg3;          /* max_count */
            break;
        /* Hook 安装：arg3 = target_name 用户指针（协议层 user_out 承载） */
        case KPM_CMD_HOOK_INSTALL:
            ctx.user_out = (void *)arg3;
            break;
        /* PLT Hook：arg3=module 用户指针, arg4=func 用户指针 */
        case KPM_CMD_HOOK_PLT_SET:
            ctx.user_out = (void *)arg3;   /* module_name */
            ctx.arg4 = arg4;               /* func_name（协议层按用户指针处理） */
            break;
        /* 日志：arg2=buf, arg3=size */
        case KPM_CMD_GET_LOG:
            ctx.user_out = (void *)arg2;
            ctx.user_out_cap = (uint32_t)arg3;
            break;
        /* 模块信息：arg2=buf, arg3=size（可选——传 buf 才返回完整 256B
         * kpm_state_info_t，含陀螺仪传感器状态；不传则仅返回 state 位图） */
        case KPM_CMD_HOOK_INFO:
            ctx.user_out = (void *)arg2;
            ctx.user_out_cap = (uint32_t)arg3;
            break;
        /* 触摸查询：arg3 = user_buf（单对象 8B） */
        case KPM_CMD_TOUCH_GET:
            ctx.user_out = (void *)arg3;
            break;
        /* 触摸全查：arg2=buf, arg3=max_count */
        case KPM_CMD_TOUCH_GET_ALL:
            ctx.user_out = (void *)arg2;
            break;
        /* 拦截 slot 状态：arg2=buf */
        case KPM_CMD_INTERCEPT_SLOT_STATE:
            ctx.user_out = (void *)arg2;
            break;
        /* 功能单元列表：标准 prctl 布局 arg2=buf,
         * arg3=max_count；兼容 lhctl 的 UDP 布局 arg2=max_count,
         * arg3=buf。判定依据：arg2 <= 4096 不可能是合法用户指针，
         * 且 arg3 >= 0x10000（高于 mmap_min_addr 的用户地址下界）。 */
        case KPM_CMD_FEAT_LIST:
            if (arg2 <= 4096 && arg3 >= 0x10000) {
                /* lhctl 布局：arg4 未定义，不解析容量（保持不限） */
                ctx.user_out = (void *)arg3;
                ctx.arg2 = arg2;          /* max_count */
            } else {
                ctx.user_out = (void *)arg2;
                ctx.arg2 = arg3;          /* max_count */
                ctx.user_out_cap = (uint32_t)arg4;  /* 可选 buf_size */
            }
            break;
        /* FEAT_ENABLE/DISABLE/STATE：单元 id 在 arg2，绝不做指针翻译。
         * 显式列出，防止未来把 FEAT_* 纳入列表命令的范围翻译。 */
        case KPM_CMD_FEAT_ENABLE:
        case KPM_CMD_FEAT_DISABLE:
        case KPM_CMD_FEAT_STATE:
            break;
        /* trace / memwatch 列表与 fetch（prctl arg2=buf, arg3=max） */
        case KPM_CMD_TRACE_FETCH:
            ctx.user_out = (void *)arg2;
            ctx.arg2 = arg3;          /* max_count */
            break;
        case KPM_CMD_TRACE_INFO:
            ctx.user_out = (void *)arg2;
            break;
        case KPM_CMD_MEMWATCH_LIST:
        case KPM_CMD_MEMWATCH_FETCH:
            ctx.user_out = (void *)arg2;
            ctx.arg2 = arg3;          /* max_count */
            break;
        /* FORCE_QUERY 用 arg5 作为可选输出缓冲（其余 op 忽略） */
        case KPM_CMD_FORCE:
            if ((int)arg2 == KPM_FORCE_OP_QUERY)
                ctx.user_out = (void *)arg5;
            break;
        /* BP_INFO arg2=buf, arg3=buf_size（可选，0=不限） */
        case KPM_CMD_DEBUG_BP_INFO:
            ctx.user_out = (void *)arg2;
            ctx.user_out_cap = (uint32_t)arg3;
            break;
        /* STEP_FETCH arg2=buf, arg3=max_count */
        case KPM_CMD_STEP_FETCH:
            ctx.user_out = (void *)arg2;
            ctx.arg2 = arg3;          /* max_count */
            break;
        /* W^X shadow：PATCH arg4=buf,arg5=len；LIST arg2=buf,arg3=max；
         * INFO arg2=buf,arg3=cap */
        case KPM_CMD_WX_PATCH:
            ctx.user_out = (void *)arg4;
            break;
        case KPM_CMD_WX_LIST:
            ctx.user_out = (void *)arg2;
            ctx.arg2 = arg3;
            break;
        case KPM_CMD_WX_INFO:
            ctx.user_out = (void *)arg2;
            ctx.user_out_cap = (uint32_t)arg3;
            break;
        /* 同步停靠上下文读：arg2=trap_id, arg3=buf */
        case KPM_CMD_TRAP_GET:
            ctx.user_out = (void *)arg3;
            break;
        /* 同步停靠列表：arg2=buf, arg3=max_count */
        case KPM_CMD_TRAP_LIST:
            ctx.user_out = (void *)arg2;
            ctx.arg2 = arg3;          /* max_count */
            break;
        /* 挂起记录列表：arg2=buf, arg3=max_count */
        case KPM_CMD_SUSPEND_LIST:
            ctx.user_out = (void *)arg2;
            ctx.arg2 = arg3;          /* max_count */
            break;
        /* 禁网状态：arg2=buf */
        case KPM_CMD_NETCTL_LIST:
            ctx.user_out = (void *)arg2;
            break;
        default:
            break;
        }

        dispatch_ret = kpm_cmd_dispatch(&ctx);
        if (dispatch_ret == KPM_CMD_UNHANDLED) {
            /* 非本模块命令，放行原始 prctl */
            args->skip_origin = 0;
            return;
        }
        ret = dispatch_ret;
    }

    args->ret = ret;
    args->skip_origin = 1;
}

void kpm_prctl_after(hook_fargs5_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

long kpm_hooks_init(void)
{
    hook_err_t err;

    err = fp_hook_syscalln(KPM_PRCTL_NR, 5, kpm_prctl_before, kpm_prctl_after, 0);
    if (err != HOOK_NO_ERR) {
        kpm_log("kpm: fp_hook prctl failed: %d\n", err);
        return -1;
    }

    g_prctl_hooked = 1;
    kpm_set_state(KPM_STATE_PRCTL_HOOK);
    kpm_log("kpm: prctl fp_hook installed (nr=%d)\n", KPM_PRCTL_NR);
    return 0;
}

void kpm_hooks_exit(void)
{
    if (g_prctl_hooked) {
        fp_unhook_syscalln(KPM_PRCTL_NR, kpm_prctl_before, kpm_prctl_after);
        g_prctl_hooked = 0;
        kpm_clear_state(KPM_STATE_PRCTL_HOOK);
        /* unhook 后等待在途回调退出，再允许模块 .text 释放
         * （防取指 UAF）。有界等待防卸载卡死。 */
        kpm_prctl_drain();
        kpm_log("kpm: prctl fp_hook removed (inflight drained)\n");
    }
}

/* prctl FP hook 安装状态（UN_HOOK 用），1=已安装 */
int kpm_hooks_active(void)
{
    return g_prctl_hooked;
}
