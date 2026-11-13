/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_suspend.h - 进程挂起/恢复
 *
 * 三模式兼容性退回：
 *   mode 0 trap-park（默认，最隐蔽）：
 *     对线程组每线程 task_work_add —— 线程在返回用户态边界（进程上下文，
 *     可睡眠）停靠循环等待恢复。/proc 显示 S（sleeping）而非 T，父进程
 *     零通知（无 SIGCHLD）、无信号进入目标队列。
 *     固有限制：阻塞在长系统调用（epoll_wait 等）中的
 *     线程要等下次到达内核/用户边界才停靠（定时器中断必然到达，典型
 *     ≤4ms/100ms 粒度）；挂起期间新建线程不受控。
 *   mode 1 sigstop（兜底）：
 *     do_send_sig_info(SIGSTOP, SEND_SIG_PRIV, leader, group=1) 全组停。
 *     风险注释：父进程（zygote）收到停止通知、目标可捕获 SIGCONT、
 *     /proc 显示 T——暴露面最大，仅在显式指定时使用。
 *   mode 2 freezer-trap（6.1 专用硬停档，当前禁用）：
 *     需 task_struct.jobctl 偏移（框架未导出），未验证偏移即拒绝服务，
 *     恒返回 -KPM_E_DISABLED。
 *
 * 符号依赖：trap-park 需 task_work_add 等 5 符号（缺失时 mode 0 不可用）；
 * sigstop 需 do_send_sig_info（缺失时 mode 1 不可用）。
 * mode 0xFF=auto：按可用性自动选最优（trap-park > sigstop）。
 */
#ifndef _LH_SUSPEND_H_
#define _LH_SUSPEND_H_

#include <ktypes.h>
#include "LH_comm.h"

#define KPM_SUSPEND_MAX          8    /* 同时挂起记录数 */
#define KPM_SUSPEND_MAX_THREADS  16   /* 单记录停靠线程数上限（超出拒绝） */

#define KPM_SUSPEND_MODE_PARK    0    /* trap-park（默认） */
#define KPM_SUSPEND_MODE_SIGSTOP 1    /* SIGSTOP/SIGCONT（兜底） */
#define KPM_SUSPEND_MODE_FREEZER 2    /* freezer-trap（预留，未验证偏移，禁用） */
#define KPM_SUSPEND_MODE_AUTO    0xFF

#define KPM_SUSPEND_ST_FREE      0
#define KPM_SUSPEND_ST_SUSPENDED 1
#define KPM_SUSPEND_ST_ZOMBIE    2    /* 已恢复，等待迟到回调归还工作项 */

/* 挂起记录摘要（48B，SUSPEND_LIST 输出） */
#pragma pack(push, 1)
typedef struct {
    int32_t  rec_id;
    pid_t    tgid;
    uint32_t mode;            /* KPM_SUSPEND_MODE_*（AUTO 已解析为实际值） */
    uint32_t state;           /* KPM_SUSPEND_ST_*（FREE 不输出） */
    uint32_t nthreads;        /* 已停靠/已覆盖线程数 */
    uint32_t reserved;
    char     name[24];        /* 挂起时刻主线程 comm */
} kpm_suspend_entry_t;        /* sizeof = 48 */
#pragma pack(pop)
typedef char kpm_suspend_entry_size_check[sizeof(kpm_suspend_entry_t) == 48 ? 1 : -1];

long kpm_suspend_init(void);
void kpm_suspend_exit(void);
/* arg: tgid（线程组 id）；mode=KPM_SUSPEND_MODE_*；timeout_ms=0 无限。
 * 返回：记录 id（>=0），负错误码。 */
long kpm_suspend_proc(pid_t tgid, int mode, uint32_t timeout_ms);
long kpm_suspend_resume(pid_t tgid);          /* 0=恢复全部 */
long kpm_suspend_list(void *user_buf, int max_count);
long kpm_suspend_list_kernel(void *kbuf, int max_count);
int  kpm_suspend_release_all(void);           /* 卸载路径：全部恢复（幂等） */

#endif /* _LH_SUSPEND_H_ */
