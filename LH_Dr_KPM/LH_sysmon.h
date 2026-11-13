/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_sysmon.h - syscall/ioctl 监控与劫持
 *
 * 覆盖：ioctl(29)、socket/connect/bind 族、
 * sendmsg/recvmsg 族、execve/openat 文件族。
 *
 * 延迟设计：before 回调热路径 = 一次总开关读 +
 * kpm_filter 位图测试（未匹配 ≈ 十几 ns，低于时序噪声，系统级无感）；
 * 仅过滤命中的目标才进入规则匹配/监控路径。监控事件写 128 槽环形
 * 缓冲（有锁，但只对命中目标执行）——绝不阻塞目标线程，满则丢弃并
 * 计数（拉取侧可见）。
 *
 * 动作：
 *   MONITOR —— 事件入环（异步 FETCH 拉取）
 *   DENY    —— skip_origin=1 伪造返回（errno 可配）
 *   TAMPER  —— 改写第 arg_idx 个参数（syscall_args 解包后写回，
 *              wrapped syscall 即写 pt_regs，原调用看到新值）
 *
 * 风险注释（必然暴露面）：被拦截目标自身可感知参数被改/调用被拒
 * （功能语义）；监控事件仅在命中目标时产生，未命中目标零痕迹。
 */
#ifndef _LH_SYSMON_H_
#define _LH_SYSMON_H_

#include <ktypes.h>
#include "LH_comm.h"

#define KPM_SYSMON_ACTION_MONITOR 0
#define KPM_SYSMON_ACTION_DENY    1
#define KPM_SYSMON_ACTION_TAMPER  2

#define KPM_SYSMON_NR_IOCTL    29
#define KPM_SYSMON_NR_OPENAT   56
#define KPM_SYSMON_NR_SOCKET   198
#define KPM_SYSMON_NR_BIND     200
#define KPM_SYSMON_NR_CONNECT  203
#define KPM_SYSMON_NR_SENDTO   206
#define KPM_SYSMON_NR_RECVFROM 207
#define KPM_SYSMON_NR_SENDMSG  211
#define KPM_SYSMON_NR_RECVMSG  212
#define KPM_SYSMON_NR_EXECVE   221

long kpm_sysmon_init(void);
void kpm_sysmon_exit(void);
/* 最近一次 init 失败的 syscall nr（0=成功/未失败），用于 FEAT reason 上报 */
int  kpm_sysmon_last_err_nr(void);
/* 总开关。flags bit0=监控事件入环 */
long kpm_sysmon_set(int enable, uint64_t flags);
/* 规则：op(0=add 1=del 2=clear)
 * arg3 = nr(低16) | action<<16 | arg_idx<<24 | errno_mode<<28
 * arg4 = cmd_match（0=任意；ioctl 场景 = ioctl cmd 精确值）
 * arg5 = arg_value（TAMPER 时写入第 arg_idx 个参数的完整 64 位值） */
long kpm_sysmon_rule(int op, uint64_t packed, uint64_t cmd_match,
                     uint64_t arg_value);
long kpm_sysmon_fetch(void *user_buf, int max_count, uint64_t *dropped);
long kpm_sysmon_fetch_kernel(void *kbuf, int max_count, uint64_t *dropped);
long kpm_sysmon_rules_list(void *user_buf, int max_count);
long kpm_sysmon_rules_list_kernel(void *kbuf, int max_count);

#endif /* _LH_SYSMON_H_ */
