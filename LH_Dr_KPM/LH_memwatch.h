/* SPDX-License-Identifier: GPL-2.0-or-later */
/* LH_memwatch.h - PTE 内存断点 */
#ifndef _LH_MEMWATCH_H_
#define _LH_MEMWATCH_H_

#include <ktypes.h>
#include "LH_comm.h"

void kpm_memwatch_init(void);
void kpm_memwatch_exit(void);

long kpm_memwatch_set(pid_t pid, uint64_t addr, uint32_t mode,
                      uint32_t flags, uint32_t pages);
long kpm_memwatch_clear(uint32_t id);      /* 0xFFFFFFFF=全部 */
long kpm_memwatch_rearm(uint32_t id);      /* 0xFFFFFFFF=全部 */
long kpm_memwatch_list(kpm_memwatch_entry_t *out, int max_count);
long kpm_memwatch_fetch_kernel(void *dst, int max_count);
long kpm_memwatch_fetch_user(void *dst, int max_count);
void kpm_memwatch_stop_all(void);

#endif /* _LH_MEMWATCH_H_ */
