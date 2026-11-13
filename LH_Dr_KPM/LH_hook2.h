/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_hook2.h - hook 引擎双模式
 *
 * 无痕模式（KPM_FEAT_STEALTH_HOOK，BRP 硬件断点重定向）：
 *   不修改目标任何代码。命中时内核态处理器应用原语（观察/改参/跳过
 *   函数/跳转 trampoline），详见 LH_debug.h kpm_bp_hook_rule_t。
 *   auto 模式 = µs 级命中即应用不停靠；manual 模式 = 同步停靠闭环。
 *   风险注释：命中时序可侧信道感知；调试寄存器 EL0 不可读（隐蔽）。
 *
 * 普通模式（KPM_FEAT_HOOK，内核函数 hook_wrap 封装）：
 *   对内核函数挂框架 inline hook（跳板+重定位），支持观察/改参/拒绝。
 *   风险注释：内核文本被修改，内核完整性校验可发现（罕见但存在）。
 *   用户态普通 hook（GOT/PLT/inline 补丁）由客户端经内存写引擎实施
 *   （READ_MEM/WRITE_MEM 已覆盖）。
 *
 * 命令（LH_comm.h）：
 *   HOOK2_SET_STEALTH 0x1173: arg2=pid, arg3=func_addr,
 *       arg4=arg_mask(低8)|action<<16|auto<<24, arg5=aux
 *       （ARG_MOD 的 X0-X7 值经 HOOK2_ARGS 窗口预置）→ ret=hook id
 *   HOOK2_SET_KFUNC 0x1174: arg2=func_addr,
 *       arg3=action<<48|arg_idx<<40|errno<<32, arg4=value → ret=hook id
 *   HOOK2_ARGS 0x1175: arg2=user_buf(8×u64) → 置 ARG_MOD 窗口
 *   HOOK2_DEL 0x1176: arg2=id → ret=0
 *   HOOK2_LIST 0x1177: arg2=max_count → kpm_hook2_entry_t[](32B×N)
 */
#ifndef _LH_HOOK2_H_
#define _LH_HOOK2_H_

#include <ktypes.h>
#include "LH_comm.h"
#include "LH_debug.h"

#define KPM_HOOK2_MAX_STEALTH 8   /* 受 BRP 槽位约束（ID_AA64DFR0 动态更小） */
#define KPM_HOOK2_MAX_KFUNC   8   /* 框架 HOOK_CHAIN_NUM=16，留余量 */

long kpm_hook2_init_stealth(void);
void kpm_hook2_exit_stealth(void);
long kpm_hook2_init_kfunc(void);
void kpm_hook2_exit_kfunc(void);

long kpm_hook2_set_stealth(pid_t pid, uint64_t func_addr, uint64_t packed,
                           uint64_t aux);
long kpm_hook2_set_kfunc(uint64_t func_addr, uint64_t packed, uint64_t value);
long kpm_hook2_args_window(const void *user_buf);       /* 8×u64 prctl 版 */
long kpm_hook2_args_window_kernel(const void *kbuf);    /* 8×u64 UDP 版 */
long kpm_hook2_del(int id);
long kpm_hook2_list(void *user_buf, int max_count);
long kpm_hook2_list_kernel(void *kbuf, int max_count);

#endif /* _LH_HOOK2_H_ */
