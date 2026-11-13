/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_resctl.h - 内核级 CPU 亲和性/频率控制
 *
 * 机制（兼容性退回）：
 *   亲和性：set_cpus_allowed_ptr，整线程组应用。
 *   单进程频率限制：
 *     - 6.1（uclamp 可用）：sched_setattr_nocheck + SCHED_FLAG_KEEP_POLICY|
 *       UTIL_CLAMP_MAX 设 per-task uclamp_max（0-1024），EAS 下等效限频。
 *       能力探测：sysctl_sched_uclamp_util_max 变量可解析 → FULL。
 *       残余检测面：sched_getattr/部分厂商 /proc/pid/sched 可读出 clamp。
 *     - 4.19（无 uclamp）：DEGRADED——仅亲和性压制到小核（等效降频），
 *       uclamp 命令返回 -KPM_E_DISABLED。
 *   全局限频：全局规则即时应用到全部 app 进程（uid>=10000）；
 *     集群级真·限频（freq_qos）需要 cpufreq_policy.constraints 偏移，
 *     该偏移无法离线验证，故禁用（返回 -KPM_E_DISABLED）。
 *     全局规则不自动追加到新进程（依赖 execve hook）。
 *
 * 风险注释（必然暴露面）：uclamp 可被 sched_getattr 读出（检测面小）；
 * 亲和性可被 sched_getaffinity 读出；restore 亲和性为"全核"近似
 * （原掩码无法无偏移读取）。
 */
#ifndef _LH_RESCTL_H_
#define _LH_RESCTL_H_

#include <ktypes.h>
#include "LH_comm.h"

#define KPM_RESCTL_UTIL_MAX_DEFAULT 1024

long kpm_resctl_init(void);
void kpm_resctl_exit(void);
/* 亲和性：arg=tgid, cpu_mask64（bit n = CPU n 允许），0xF..F=恢复全核 */
long kpm_resctl_affinity(pid_t tgid, uint64_t cpu_mask);
/* 单进程限频：util_max 0-1024；0xFFFFFFFF=清除（恢复 1024）。
 * 设备无 uclamp → -KPM_E_DISABLED。 */
long kpm_resctl_freq(pid_t tgid, uint64_t util_max);
/* 全局：应用到全部 app 进程（uid>=10000）。affinity_mask=0 跳过；
 * util_max=0xFFFFFFFF 跳过。 */
long kpm_resctl_global(uint64_t affinity_mask, uint64_t util_max);
/* 能力查询：bit0=亲和性 bit1=uclamp */
long kpm_resctl_caps(void);

#endif /* _LH_RESCTL_H_ */
