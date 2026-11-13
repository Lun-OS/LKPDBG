/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_force.h - 强制提权会话（Force Mode）
 *
 * 语义：带 force 会话时不受驱动安全限制，允许可能崩溃的操作；
 * 不带时危险命令统一返回 -KPM_E_PERM（权限不足）。
 * force 只跳过驱动安全限制，不跳过符号/硬件存在性检查。
 */
#ifndef _LH_FORCE_H_
#define _LH_FORCE_H_

#include <ktypes.h>
#include "LH_comm.h"

void kpm_force_init(void);
void kpm_force_exit(void);

/* op: KPM_FORCE_OP_*；out 可为空。
 * 返回：UNLOCK/LOCK 0；QUERY 0；PROBE=能力 bitmap；BYPASS=已应用 bit；
 * 失败负错误码。 */
long kpm_force_control(int op, uint32_t timeout_ms, uint32_t magic,
                       uint32_t mask, kpm_force_info_t *out);

int  kpm_force_active(void);
uint32_t kpm_force_mask(void);
/* 0=允许；-KPM_E_PERM=无 force 或 mask 不足 */
int  kpm_force_require(uint32_t mask);
uint32_t kpm_force_probe(void);

#endif /* _LH_FORCE_H_ */
