/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_intercept.h - TVF V2 Input Capture Layer + Intercept Offset
 *
 * Two responsibilities:
 *   1. Input Capture: hook input_handle_event, route hardware events
 *      through TVF (tvf_register_user/update_user/release_user), run
 *      scheduler on EV_SYN. All original events are blocked; the output
 *      layer re-emits the complete frame.
 *   2. Intercept Offset: apply coordinate transformation (REDIRECT/OFFSET/
 *      MIRROR) to user touch coordinates before writing to TouchObjects.
 *
 * Per-slot state design:
 *   All displacement/offset tracking is per hardware slot to support
 *   multi-touch intercept without cross-finger state corruption.
 *
 * Integer-only arithmetic:
 *   All arithmetic is integer-only (no double/float) to avoid
 *   FP-in-IRQ-context issues on ARM64 kernel.
 */

#ifndef _KPM_INTERCEPT_H_
#define _KPM_INTERCEPT_H_

#include <ktypes.h>
#include <stdint.h>
#include "LH_touch.h"   /* MAX_OUTPUT_SLOTS */

/* Intercept modes (coordinate transformation for user touches) */
typedef enum {
    KPM_INTERCEPT_OFF      = 0,  /* disabled */
    KPM_INTERCEPT_REDIRECT = 1,  /* reverse offset proportional to displacement */
    KPM_INTERCEPT_OFFSET   = 2,  /* fixed offset applied directly (no EMA smoothing) */
    KPM_INTERCEPT_MIRROR   = 3,  /* full mirror (100% reverse) */
    KPM_INTERCEPT_PIN      = 4,  /* fix touch to specified position (for aim assist) */
    KPM_INTERCEPT_PIN_ZERO = 5   /* PIN 零方向: 直接丢弃 X/Y 事件，不透传硬件坐标，消除抖动 */
} kpm_intercept_mode_t;

/* Target slot sentinel: apply operation to all slots */
#define KPM_INTERCEPT_SLOT_ALL  0xFF

/* Intercept state — per-slot tracking for multi-touch support.
 *
 * Global config (shared across all fingers):
 *   enabled, mode, target_x/y, scale, max_offset, mirror_x/y, smoothing_q8
 *
 * Per-slot state (each hardware slot has its own):
 *   finger_down[], prev_x/y[], user_dx/dy[], offset_x/y[]
 *
 * smoothing_q8 is set in init/start_offset/set_scale but is not
 * consumed by any offset calculation.
 */
typedef struct {
    /* Global config */
    int                  enabled;        /* offset calculation active */
    kpm_intercept_mode_t mode;           /* current mode */

    /* OFFSET mode target (pixels, screen coords) */
    int                  target_x;       /* target offset X */
    int                  target_y;       /* target offset Y */

    /* Tunable parameters */
    int                  scale;          /* offset ratio [1-100], default 50 */
    int                  max_offset;     /* max offset magnitude (px), default 200 */
    int                  mirror_x;       /* X axis mirror flag */
    int                  mirror_y;       /* Y axis mirror flag */
    int                  smoothing_q8;   /* Q8 factor [1-256], default 90; not used by offset calculation */

    /* Slot selection: which slots are intercepted (bit i = slot i).
     * 0xFFFF = all slots (default).
     * Multiple start_* calls OR-accumulate bits to allow incremental slot add. */
    uint16_t             slot_mask;

    /* PIN mode: per-slot fixed position (screen coords).
     * output = pin_x[slot], so offset = pin_x[slot] - screen_x.
     * Allows each slot to be pinned to a different position. */
    int                  pin_x[MAX_OUTPUT_SLOTS];
    int                  pin_y[MAX_OUTPUT_SLOTS];

    /* Per-slot state (indexed by hardware MT slot) */
    int                  finger_down[MAX_OUTPUT_SLOTS];   /* slot has finger down */
    int                  prev_x[MAX_OUTPUT_SLOTS];        /* previous screen X per slot */
    int                  prev_y[MAX_OUTPUT_SLOTS];        /* previous screen Y per slot */
    int                  user_dx[MAX_OUTPUT_SLOTS];       /* cumulative displacement X per slot */
    int                  user_dy[MAX_OUTPUT_SLOTS];      /* cumulative displacement Y per slot */
    int                  offset_x[MAX_OUTPUT_SLOTS];      /* current applied offset X per slot */
    int                  offset_y[MAX_OUTPUT_SLOTS];     /* current applied offset Y per slot */
} kpm_intercept_state_t;

/* Global intercept state */
extern kpm_intercept_state_t g_intercept;

/* 真实手指按下计数（IN-PLACE 模式下 hook 仅置 finger_down 位、
 * 不注册 USER 对象，touch_count 需叠加此数才能反映真实手指）。
 * 返回 g_intercept.finger_down[] 中置位的 slot 数（0-10）。 */
int kpm_intercept_count_real_fingers(void);

/* Initialize intercept state */
void kpm_intercept_init(void);

/* Start intercept (redirect mode)
 * scale: reverse ratio [1-100]; offset = -2 * displacement * scale / 100
 *        (50 = offset is -displacement, output frozen at start)
 * max_offset: max offset in pixels
 * target_slot: which slot to apply (KPM_INTERCEPT_SLOT_ALL = all) */
long kpm_intercept_start_redirect(int scale, int max_offset, int target_slot);

/* Start intercept (offset mode)
 * offset_x, offset_y: fixed offset in pixels
 * scale: [1-100], sets smoothing_q8; not consumed by OFFSET calculation
 * target_slot: which slot to apply (KPM_INTERCEPT_SLOT_ALL = all) */
long kpm_intercept_start_offset(int offset_x, int offset_y, int scale, int target_slot);

/* Start intercept (mirror mode)
 * target_slot: which slot to apply (KPM_INTERCEPT_SLOT_ALL = all) */
long kpm_intercept_start_mirror(int mirror_x, int mirror_y, int target_slot);

/* Start intercept (PIN mode): fix touch to specified position.
 * pin_x, pin_y: screen coordinate to pin to
 * target_slot: which slot to apply (KPM_INTERCEPT_SLOT_ALL = all).
 * For per-slot PIN, call multiple times with different target_slot values. */
long kpm_intercept_start_pin(int pin_x, int pin_y, int target_slot);

/* Start PIN_ZERO mode: fix touch position by dropping X/Y events entirely.
 * Unlike PIN (mode=4) which rewrites coordinates and may show 1-frame jitter
 * when hardware reports a new position before the offset is applied,
 * PIN_ZERO drops ABS_MT_POSITION_X/Y events at the hook level, so Android
 * only sees the initial DOWN position and never receives any movement.
 * The touch appears "frozen" at the initial position with zero jitter.
 *
 * pin_x/pin_y: the fixed position (screen coordinates)
 * target_slot: which slot to apply (KPM_INTERCEPT_SLOT_ALL = all)
 *
 * Returns 0 on success, <0 on error. */
long kpm_intercept_start_pin_zero(int pin_x, int pin_y, int target_slot);

/* Disable intercept for a single slot (keeps other slots active).
 * If no slots remain, fully stops intercept. */
long kpm_intercept_slot_off(int slot_id);

/* Stop intercept (offset calculation only, hook stays installed) */
long kpm_intercept_stop(void);

/* Query intercept state (packed into long) */
long kpm_intercept_get_state(void);

/* Query per-slot intercept state (copied to user buffer)
 * Returns 0 on success, negative on error */
long kpm_intercept_get_slot_state(kpm_intercept_slot_state_t *state);

/* Set offset ratio */
long kpm_intercept_set_scale(int scale);

/* Set max offset */
long kpm_intercept_set_max_offset(int max_offset);

/* Install input capture hook on input_handle_event.
 * Must be called after kpm_touch_init() (needs touch device).
 * Returns 0 on success, non-zero on failure. */
long kpm_intercept_hook_install(void);

/* Uninstall input capture hook */
void kpm_intercept_hook_uninstall(void);

/* 捕获 hook 安装状态查询（UN_HOOK 用），1=已安装 */
long kpm_intercept_hook_active(void);

#endif /* _KPM_INTERCEPT_H_ */
