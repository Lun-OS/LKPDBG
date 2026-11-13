/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_PTR_SCAN_H_
#define _KPM_PTR_SCAN_H_

#include <ktypes.h>
#include <stdint.h>

/* ===== Pointer Scanner =====
 * Given a target address, scans process memory for pointers pointing to it.
 * Supports multi-level pointer chain discovery.
 */

#define KPM_PTR_SCAN_MAX_RESULTS 16384
#define KPM_PTR_CHAIN_MAX_DEPTH 8

/* Single pointer scan result */
typedef struct {
    uint64_t addr;      /* address where pointer was found */
    uint64_t value;     /* pointer value (the address it points to) */
} kpm_ptr_result_t;

/* Pointer chain entry (one level) */
typedef struct {
    uint64_t offsets[KPM_PTR_CHAIN_MAX_DEPTH];  /* offsets at each level */
    int      depth;                              /* chain depth (1 = single pointer) */
    uint64_t base_addr;                          /* final resolved address */
} kpm_ptr_chain_t;

/* Initialize pointer scan module */
long kpm_ptr_scan_init(void);

/* Exit pointer scan module */
void kpm_ptr_scan_exit(void);

/* Scan for pointers pointing to target_addr ± range.
 * pid: target process PID
 * target_addr: address to search for
 * range: allowed deviation from target_addr (e.g. 0 for exact match, 4096 for page)
 * Returns 0 on success, negative on error */
long kpm_ptr_scan_start(pid_t pid, uint64_t target_addr, uint64_t range);

/* Multi-level pointer chain scan.
 * Finds chains: [ptr] -> [ptr+off1] -> [ptr+off1+off2] -> ... -> target_addr
 * pid: target process PID
 * target_addr: final address we want to reach
 * depth: max chain depth
 * Returns 0 on success, negative on error */
long kpm_ptr_scan_chain(pid_t pid, uint64_t target_addr, int depth);

/* Copy pointer scan results to user buffer.
 * Returns number of results copied, or negative on error */
long kpm_ptr_scan_copy_results(kpm_ptr_result_t *user_buf,
                               int max_count, int offset);

/* Copy pointer scan results to kernel buffer (for UDP channel).
 * Uses lib_memcpy instead of copy_to_user, suitable when caller
 * passes a kernel-space buffer (e.g. g_resp_buf in UDP handler).
 * Returns number of results copied, or negative on error */
long kpm_ptr_scan_copy_results_kernel(kpm_ptr_result_t *kbuf,
                                      int max_count, int offset);

/* Clear current pointer scan session */
long kpm_ptr_scan_clear(void);

#endif /* _KPM_PTR_SCAN_H_ */