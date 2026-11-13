/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_filter.h - uid/pid 快速过滤器核心
 *
 * 设计目标：syscall hook before 回调的热路径开销必须压到
 * 纳秒级——未匹配进程仅付出一次全局使能读 + 一次位图测试，无锁无原子。
 * 写侧（规则增删）持自旋锁；读侧无锁（字节级原子可见，管理操作允许
 * 最终一致）。
 *
 * 过滤对象：
 *   - app uid 段 [10000, 19999]，位图 10000 位（1250B）；root/系统 uid
 *     （<10000）**刻意不可匹配**——误拦 init/zygote 会直接软化系统，
 *     属稳定性红线。
 *   - pid/tgid 小表（按 tgid 匹配整进程）。
 */
#ifndef _LH_FILTER_H_
#define _LH_FILTER_H_

#include <ktypes.h>

#define KPM_FILTER_UID_BASE   10000
#define KPM_FILTER_UID_RANGE  10000            /* app uid 段宽（10000-19999） */
#define KPM_FILTER_PID_MAX    32

long kpm_filter_init(void);
/* 热路径：命中（当前调用者 uid/pid 匹配规则）返回 1。ns 级。 */
int  kpm_filter_hit(void);
/* 规则管理（命令层调用，可睡眠上下文） */
long kpm_filter_uid_add(uint64_t uid);        /* 0=全部 app uid(all_apps) */
long kpm_filter_uid_del(uint64_t uid);
long kpm_filter_pid_add(uint64_t pid);
long kpm_filter_pid_del(uint64_t pid);
long kpm_filter_clear(void);
void kpm_filter_set_all_apps(int on);
/* 统一规则入口（FILTER_RULE 命令用，独立于 netctl/sysmon 生命周期；
 * op/type 语义见 LH_comm.h FILTER_RULE） */
long kpm_filter_rule(int op, int type, uint64_t value);
void kpm_filter_counts(uint32_t *uid_count, uint32_t *pid_count,
                       int *all_apps);
/* ===== 使用者生命周期（netctl/sysmon 共用）=====
 * register/unregister 只维护自身位，不碰规则（避免互清）；
 * request_on 按使用者请求总开关，任一使用者 on → 热路径 on；
 * 最后一个使用者 unregister 时才清规则并关总开关。 */
#define KPM_FILTER_USER_NETCTL 0x1u
#define KPM_FILTER_USER_SYSMON 0x2u
void kpm_filter_user_register(uint32_t user);
void kpm_filter_user_unregister(uint32_t user);
void kpm_filter_request_on(uint32_t user, int on);
int  kpm_filter_get_on(void);
/* pid 表快照（LIST 输出用），返回实际条数 */
long kpm_filter_pids_copy(pid_t *out, int max);

#endif /* _LH_FILTER_H_ */
