/* SPDX-License-Identifier: GPL-2.0-or-later */
/* LH_trace.h - 全量 trace（syscall / kfunc / 通用事件环） */
#ifndef _LH_TRACE_H_
#define _LH_TRACE_H_

#include <ktypes.h>
#include "LH_comm.h"

void kpm_trace_init(void);
void kpm_trace_exit(void);

/* op: KPM_TRACE_OP_*；mode: KPM_TRACE_MODE_*。
 * UDP: cfg/payload 由调用方给出；prctl: func_addr/argno 标量。 */
long kpm_trace_control(int op, int mode, int32_t pid_filter,
                       uint32_t uid_filter, uint64_t func_addr,
                       int argno, const void *cfg, uint32_t cfg_len,
                       int force_hot);

long kpm_trace_fetch_kernel(void *dst, int max_count);
long kpm_trace_fetch_user(void *dst, int max_count);
long kpm_trace_info(kpm_trace_info_t *out);

/* 供 BP/memwatch 复用的通用事件入口（type=KPM_TRACE_TYPE_*） */
void kpm_trace_push(const kpm_trace_event_t *ev);

#endif /* _LH_TRACE_H_ */
