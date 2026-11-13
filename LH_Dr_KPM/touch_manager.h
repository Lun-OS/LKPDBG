/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * touch_manager.h - TVF V2 Core: Internal APIs
 *
 * Implements: TouchObject pool, Slot Virtualizer, Scheduler, Transaction.
 * Public TouchHandle API is declared in kpm_touch.h, implemented here.
 */
#ifndef _TOUCH_MANAGER_H_
#define _TOUCH_MANAGER_H_

#include "LH_touch.h"

/* ===== Pool initialization ===== */
void tvf_pool_init(void);

/* ===== Slot Virtualizer ===== */

/* Acquire an output slot for an object (may preempt lower priority) */
int tvf_virtualizer_acquire(TouchObject *obj);

/* Release an output slot */
void tvf_virtualizer_release(TouchObject *obj);

/* Try to resume suspended objects if slots are available */
void tvf_virtualizer_try_resume(void);

/* ===== Scheduler ===== */

/* Run one scheduling frame:
 * 1. Scan all active TouchObjects
 * 2. Assign/release output slots
 * 3. Update FrameBuffer
 * 4. Call tvf_output_commit_frame() */
void tvf_scheduler_run(void);

/* ===== Transaction Buffer ===== */

/* Clear frame (mark all slots non-dirty) */
void tvf_transaction_begin(void);

/* Write object state to pending frame slot */
void tvf_transaction_update(TouchObject *obj);

/* Mark a slot for release (tracking_id = -1) */
void tvf_transaction_release_slot(int slot);

/* ===== Lock =====
 * tvf_lock / tvf_unlock: for process context (prctl path).
 *   Disables IRQs before acquiring spinlock, restores on release.
 *   Prevents touch IRQ from interrupting prctl and deadlocking.
 *
 * tvf_lock_nointr / tvf_unlock_nointr: for IRQ context (hook path).
 *   IRQs already disabled by input_event's spin_lock_irqsave.
 *   Does NOT touch DAIF (would wrongly enable IRQs if it did).
 */
void tvf_lock(void);
void tvf_unlock(void);
void tvf_lock_nointr(void);
void tvf_unlock_nointr(void);

/* ===== Next tracking ID generator ===== */
int tvf_next_tracking_id(void);

#endif /* _TOUCH_MANAGER_H_ */
