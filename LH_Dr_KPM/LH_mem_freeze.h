/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_MEM_FREEZE_H_
#define _KPM_MEM_FREEZE_H_

#include <ktypes.h>
#include <stdint.h>

/* ===== Memory Freeze =====
 * Periodically writes a fixed value to a target process address,
 * effectively "freezing" the value to prevent it from changing.
 */

#define KPM_FREEZE_MAX_ENTRIES 32
#define KPM_FREEZE_DEFAULT_INTERVAL_MS 50

/* A single freeze entry */
typedef struct {
    int      enabled;       /* 1 = actively freezing */
    pid_t    pid;           /* target process PID */
    uint64_t addr;          /* target address */
    uint64_t value;         /* value to write (up to 8 bytes) */
    int      size;          /* value size in bytes (1/2/4/8) */
    int      hit_count;     /* number of times value was restored */
} kpm_freeze_entry_t;

/* Initialize freeze module */
long kpm_mem_freeze_init(void);

/* Exit freeze module (stop timer, clear all entries) */
void kpm_mem_freeze_exit(void);

/* Add a freeze entry.
 * pid: target process PID
 * addr: target address
 * value: value to write
 * size: size in bytes (1, 2, 4, or 8)
 * Returns entry index >= 0, or negative on error */
long kpm_mem_freeze_add(pid_t pid, uint64_t addr, uint64_t value, int size);

/* Remove a freeze entry by index.
 * Returns 0 on success, negative on error */
long kpm_mem_freeze_remove(int index);

/* Copy freeze list to user buffer.
 * Returns number of entries copied, or negative on error */
long kpm_mem_freeze_copy_list(kpm_freeze_entry_t *user_buf, int max_count);

/* Copy freeze list to kernel buffer (for UDP channel).
 * Uses lib_memcpy instead of copy_to_user, suitable when caller
 * passes a kernel-space buffer (e.g. g_resp_buf in UDP handler).
 * Returns number of entries copied, or negative on error */
long kpm_mem_freeze_copy_list_kernel(kpm_freeze_entry_t *kbuf, int max_count);

/* Toggle a freeze entry on/off.
 * index: entry index
 * enable: 1=enable, 0=disable
 * Returns 0 on success, negative on error */
long kpm_mem_freeze_toggle(int index, int enable);

/* Clear all freeze entries and stop the timer */
long kpm_mem_freeze_clear(void);

/* Periodic tick: refresh all enabled freeze entries.
 * Called from UDP recv work loop (kpm_udp_recv_work) to ensure
 * freeze values are periodically rewritten to target process.
 * Without this call, freeze entries are written only once at add time. */
void kpm_mem_freeze_tick(void);

#endif /* _KPM_MEM_FREEZE_H_ */