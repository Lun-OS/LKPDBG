/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_netctl.h - 进程禁止联网
 *
 * 机制：网络 syscall fp 链拦截——hook socket/connect/
 * bind/sendto/sendmsg 族，命中过滤器（kpm_filter：uid 位图 + tgid 表）
 * 即返回可配置 errno，目标进程的联网请求在内核入口处被拒。
 *
 * 拦截集合（arm64 nr）：socket(198) bind(200) connect(203) sendto(206)
 * recvfrom(207) sendmsg(211) recvmsg(212) sendmmsg(269) recvmmsg(270)。
 * 已建立连接通过拦 send* 使其实效中断；recv* 同拦保证完整拒绝。
 *
 * 拒绝码（伪装语义，NETCTL_SET arg3）：
 *   0 = ENETUNREACH（默认，伪装"无网络"，不像防火墙）
 *   1 = EACCES（防火墙语义，暴露"被策略拦截"）
 *   2 = EPERM
 *
 * 风险注释（必然暴露面）：目标 APP 必然感知"无网络"（功能本身即效果）；
 * 拦截目标自身的连接失败模式（超时 vs 立即拒绝）可被 App 区分；过滤器
 * 未命中的进程开销为纳秒级（时序不可察觉）。
 */
#ifndef _LH_NETCTL_H_
#define _LH_NETCTL_H_

#include <ktypes.h>
#include "LH_comm.h"

#define KPM_NETCTL_ERRNO_UNREACH 0
#define KPM_NETCTL_ERRNO_EACCES  1
#define KPM_NETCTL_ERRNO_EPERM   2

long kpm_netctl_init(void);
void kpm_netctl_exit(void);

/* 规则操作（op: 0=add 1=del 2=clear；type: 0=uid 1=pid 2=all_apps） */
long kpm_netctl_rule(int op, int type, uint64_t value);
/* 总开关 + 拒绝码。返回 0 成功。 */
long kpm_netctl_set(int enable, int errno_mode);
long kpm_netctl_list(void *user_buf, int max_count);   /* max_count 备用 */
long kpm_netctl_list_kernel(void *kbuf, int max_count);

#endif /* _LH_NETCTL_H_ */
