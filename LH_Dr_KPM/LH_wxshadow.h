/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_wxshadow.h - W^X shadow 无痕 hook
 */
#ifndef _LH_WXSHADOW_H_
#define _LH_WXSHADOW_H_

#include <ktypes.h>
#include "LH_comm.h"

/* FEAT 生命周期（LH_main.c 注册） */
long kpm_wx_init(void);
void kpm_wx_exit(void);
void kpm_wx_pre_exit(void);      /* FEAT_DISABLE / 卸载前：恢复全部 PTE */

/* 用户接口（prctl / UDP 分发） */
long kpm_wx_patch(pid_t pid, uint64_t addr, const void *data, uint32_t len);
long kpm_wx_set_bp(pid_t pid, uint64_t addr);
long kpm_wx_set_reg(pid_t pid, uint64_t addr, uint32_t reg_idx, uint64_t value);
long kpm_wx_del_bp(pid_t pid, uint64_t addr);   /* addr=0 → 该进程全部 */
long kpm_wx_release(pid_t pid, uint64_t addr);  /* addr=0 → 该进程全部 */
long kpm_wx_list(kpm_wx_page_info_t *out, int max_count);
long kpm_wx_info(kpm_wx_info_t *out);

/* 能力：1=patch 可用, 2=+BP(BRK+step) 可用 */
int kpm_wx_caps(void);

#endif /* _LH_WXSHADOW_H_ */
