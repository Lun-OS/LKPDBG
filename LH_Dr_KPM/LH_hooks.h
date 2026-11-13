/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_HOOKS_H_
#define _KPM_HOOKS_H_

#include <kpmodule.h>
#include <hook.h>

/* 初始化 prctl FP Hook，返回 0 成功 */
long kpm_hooks_init(void);

/* 卸载 prctl FP Hook */
void kpm_hooks_exit(void);

/* prctl FP hook 安装状态（UN_HOOK 用），1=已安装 */
int kpm_hooks_active(void);

/* prctl hook 的 before 回调 */
void kpm_prctl_before(hook_fargs5_t *args, void *udata);

/* prctl hook 的 after 回调 */
void kpm_prctl_after(hook_fargs5_t *args, void *udata);

#endif /* _KPM_HOOKS_H_ */
