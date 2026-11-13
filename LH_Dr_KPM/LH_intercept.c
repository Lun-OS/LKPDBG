/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_intercept.c - TVF V2 Input Capture Layer + Intercept Offset
 *
 * Core role: hook input_handle_event and handle hardware touch events in
 * two modes. In TVF CAPTURE (virtual touches active) original events are
 * blocked (skip_origin=1), routed through TVF, and the Output Layer
 * (tvf_output_commit_frame) re-emits complete frames. In IN-PLACE mode
 * hardware events pass through, with only intercept coordinate transforms
 * applied in place.
 *
 * Event flow:
 *   HW IRQ → input_handle_event → [this hook]
 *     → EV_SYN: tvf_run_frame() (scheduler + output)
 *     → ABS_MT_SLOT: track current slot
 *     → ABS_MT_TRACKING_ID: tvf_register_user / tvf_release_user
 *     → ABS_MT_POSITION_X/Y: apply intercept offset → tvf_update_user
 *     → ABS_MT_TOUCH_MAJOR/PRESSURE: tvf_update_user
 *     → EV_KEY (BTN_*): blocked (output layer sends its own)
 *
 * Intercept offset (optional, enabled by start_redirect/offset/mirror):
 *   Applies a coordinate transformation to user touch coordinates before
 *   writing to TouchObjects. Modes:
 *     REDIRECT: offset = -2 * displacement * scale / 100 (reverse proportional)
 *     OFFSET:   offset = target (applied directly, no smoothing)
 *     MIRROR:   offset = -2 * displacement (full reverse)
 *
 * Per-slot state: each hardware MT slot has independent tracking to
 * support multi-touch intercept without cross-finger corruption.
 *
 * Integer-only arithmetic: all arithmetic is integer-only (no floating
 * point) to avoid FP-in-IRQ-context issues on ARM64 kernel (kernel doesn't
 * save FPCR/FPSR on IRQ entry, so double arithmetic produces garbage or
 * traps).
 */

#include <compiler.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <hook.h>
#include "LH_intercept.h"
#include "LH_touch.h"
#include "LH_syms.h"
#include "LH_utils.h"
#include "LH_log.h"
#include "LH_comm.h"
#include "touch_manager.h"

/* Touch coordinate scale: dynamically set from kpm_touch_get_scale() in hook_install.
 * hardware_coord = screen_coord * g_intercept_scale */
static int g_intercept_scale = 1;

/* EV types */
#define EV_SYN_CODE     0x00
#define EV_KEY_CODE     0x01
#define EV_ABS_CODE     0x03

/* EV_SYN codes */
#define SYN_REPORT_CODE 0x00

/* EV_ABS codes */
#define ABS_MT_SLOT         0x2f
#define ABS_MT_TOUCH_MAJOR  0x30
#define ABS_MT_POSITION_X   0x35
#define ABS_MT_POSITION_Y   0x36
#define ABS_MT_TRACKING_ID  0x39
#define ABS_MT_PRESSURE     0x3a

/* EV_KEY codes (blocked, output layer sends its own) */
#define BTN_TOUCH_CODE      0x14a
#define BTN_TOOL_FINGER     0x145

/* hook install state */
static int g_hook_installed = 0;

/* current hardware MT slot (Type-B protocol) */
static int current_mt_slot = 0;

/* cached screen dimensions (for boundary clamping) */
static int g_screen_w = 0;
static int g_screen_h = 0;

/* global intercept state */
kpm_intercept_state_t g_intercept;

/* Diagnostic counter: limit per-event logs to avoid buffer overflow */
static int g_diag_log_count = 0;
#define DIAG_LOG_MAX  64

void kpm_intercept_init(void)
{
    int i;
    g_intercept.enabled       = 0;
    g_intercept.mode          = KPM_INTERCEPT_OFF;
    g_intercept.target_x      = 0;
    g_intercept.target_y      = 0;
    g_intercept.scale         = 50;
    g_intercept.max_offset    = 200;
    g_intercept.mirror_x      = 0;
    g_intercept.mirror_y      = 0;
    g_intercept.smoothing_q8  = 90;  /* ~0.35 */
    g_intercept.slot_mask     = 0xFFFF;  /* default: all slots */

    for (i = 0; i < MAX_OUTPUT_SLOTS; i++) {
        g_intercept.pin_x[i]        = 0;
        g_intercept.pin_y[i]        = 0;
        g_intercept.finger_down[i] = 0;
        g_intercept.prev_x[i]       = -1;
        g_intercept.prev_y[i]      = -1;
        g_intercept.user_dx[i]     = 0;
        g_intercept.user_dy[i]     = 0;
        g_intercept.offset_x[i]    = 0;
        g_intercept.offset_y[i]    = 0;
    }

    g_hook_installed = 0;
    current_mt_slot  = 0;
    g_diag_log_count = 0;
    g_screen_w       = 0;
    g_screen_h       = 0;
}

/* Reset per-slot tracking state for a specific slot.
 * Does NOT clear pin_x/pin_y — those are configuration values set by the
 * user via start_pin() and must persist across finger up/down cycles.
 * If PIN mode is active and pin coords are cleared here, the next finger
 * down would compute offset = 0 - screen_x, pinning to (0,0).
 *
 * Does NOT clear finger_down — that flag reflects the physical touch state
 * (set on TRACKING_ID DOWN, cleared on TRACKING_ID UP). Clearing it here
 * would cause start_*() functions to lose the finger-down state when
 * activating intercept mid-touch, breaking PIN/REDIRECT/OFFSET/MIRROR
 * for the already-down finger (high-frequency re-tap scenario). */
static void reset_slot_state(int slot)
{
    if (slot < 0 || slot >= MAX_OUTPUT_SLOTS) return;
    g_intercept.prev_x[slot]      = -1;
    g_intercept.prev_y[slot]      = -1;
    g_intercept.user_dx[slot]     = 0;
    g_intercept.user_dy[slot]     = 0;
    g_intercept.offset_x[slot]    = 0;
    g_intercept.offset_y[slot]    = 0;
}

/* Reset all slots */
static void reset_all_slots(void)
{
    int i;
    for (i = 0; i < MAX_OUTPUT_SLOTS; i++)
        reset_slot_state(i);
}

/* ===== Intercept offset start/stop ===== */

/* Update slot_mask based on target_slot.
 * Called by start_* functions after mode has been set.
 *
 * Logic:
 *   - If mode changed (different from previous), reset slot_mask=0 first
 *     to avoid stale slot bits from a different mode.
 *   - target_slot == KPM_INTERCEPT_SLOT_ALL: set slot_mask = 0xFFFF (all slots)
 *   - Otherwise: OR-in the target_slot bit (incremental add, allows
 *     multiple `intercept slot <id> ...` calls to accumulate slots).
 *
 * This is the "hybrid scheme": global mode + slot_mask filter, with
 * PIN supporting per-slot coordinates. */
static void update_slot_mask(int target_slot, int prev_mode, int new_mode)
{
    if (prev_mode != new_mode) {
        /* Mode switch: clear stale mask bits from previous mode */
        g_intercept.slot_mask = 0;
    }

    if (target_slot == KPM_INTERCEPT_SLOT_ALL || target_slot < 0 ||
        target_slot >= MAX_OUTPUT_SLOTS) {
        g_intercept.slot_mask = 0xFFFF;
    } else {
        g_intercept.slot_mask |= (uint16_t)(1u << target_slot);
    }
}

long kpm_intercept_start_redirect(int scale, int max_offset, int target_slot)
{
    int prev_mode = g_intercept.mode;
    int mode_changed = (prev_mode != KPM_INTERCEPT_REDIRECT);

    if (scale < 1) scale = 1;
    if (scale > 100) scale = 100;
    if (max_offset < 10) max_offset = 10;
    if (max_offset > 2000) max_offset = 2000;

    g_intercept.enabled      = 1;
    g_intercept.mode         = KPM_INTERCEPT_REDIRECT;
    g_intercept.scale        = scale;
    g_intercept.max_offset   = max_offset;
    update_slot_mask(target_slot, prev_mode, KPM_INTERCEPT_REDIRECT);

    /* Only reset slots that are newly added. If mode changed, reset all
     * for a fresh start. If adding a specific slot to the same mode,
     * only reset that slot — do NOT reset already-intercepted slots
     * (their finger_down/prev_x/user_dx state must be preserved). */
    if (mode_changed || target_slot == KPM_INTERCEPT_SLOT_ALL ||
        target_slot < 0 || target_slot >= MAX_OUTPUT_SLOTS) {
        reset_all_slots();
    } else {
        reset_slot_state(target_slot);
    }

    kpm_log("kpm: intercept REDIRECT started scale=%d max=%d slot=0x%x\n",
            scale, max_offset, g_intercept.slot_mask);
    return 0;
}

long kpm_intercept_start_offset(int offset_x, int offset_y, int scale, int target_slot)
{
    int prev_mode = g_intercept.mode;
    int mode_changed = (prev_mode != KPM_INTERCEPT_OFFSET);

    if (scale < 1) scale = 1;
    if (scale > 100) scale = 100;

    g_intercept.enabled      = 1;
    g_intercept.mode         = KPM_INTERCEPT_OFFSET;
    g_intercept.target_x     = offset_x;
    g_intercept.target_y     = offset_y;
    g_intercept.scale        = scale;
    g_intercept.max_offset   = 2000;
    /* Q8 conversion: 0.15 + scale*0.008 → (38 + scale*2) */
    g_intercept.smoothing_q8 = 38 + scale * 2;
    update_slot_mask(target_slot, prev_mode, KPM_INTERCEPT_OFFSET);

    if (mode_changed || target_slot == KPM_INTERCEPT_SLOT_ALL ||
        target_slot < 0 || target_slot >= MAX_OUTPUT_SLOTS) {
        reset_all_slots();
    } else {
        reset_slot_state(target_slot);
    }

    kpm_log("kpm: intercept OFFSET started (%d,%d) scale=%d smooth_q8=%d slot=0x%x\n",
            offset_x, offset_y, scale, g_intercept.smoothing_q8, g_intercept.slot_mask);
    return 0;
}

long kpm_intercept_start_mirror(int mirror_x, int mirror_y, int target_slot)
{
    int prev_mode = g_intercept.mode;
    int mode_changed = (prev_mode != KPM_INTERCEPT_MIRROR);

    g_intercept.enabled      = 1;
    g_intercept.mode         = KPM_INTERCEPT_MIRROR;
    g_intercept.mirror_x     = mirror_x ? 1 : 0;
    g_intercept.mirror_y     = mirror_y ? 1 : 0;
    update_slot_mask(target_slot, prev_mode, KPM_INTERCEPT_MIRROR);

    if (mode_changed || target_slot == KPM_INTERCEPT_SLOT_ALL ||
        target_slot < 0 || target_slot >= MAX_OUTPUT_SLOTS) {
        reset_all_slots();
    } else {
        reset_slot_state(target_slot);
    }

    kpm_log("kpm: intercept MIRROR started mx=%d my=%d slot=0x%x\n",
            g_intercept.mirror_x, g_intercept.mirror_y, g_intercept.slot_mask);
    return 0;
}

long kpm_intercept_start_pin(int pin_x, int pin_y, int target_slot)
{
    int prev_mode = g_intercept.mode;
    int mode_changed = (prev_mode != KPM_INTERCEPT_PIN);
    int i;

    g_intercept.enabled = 1;
    g_intercept.mode    = KPM_INTERCEPT_PIN;
    /* Allow large offsets for PIN: pinning to a far position may require
     * offsetting by hundreds of pixels. Same as OFFSET mode. */
    g_intercept.max_offset = 2000;
    update_slot_mask(target_slot, prev_mode, KPM_INTERCEPT_PIN);

    /* Reset tracking state before setting pin coordinates.
     * reset_all_slots() / reset_slot_state() does NOT clear pin_x/pin_y
     * (those are configuration values), so we only need to reset tracking
     * state (finger_down, prev_x/y, user_dx/y, offset_x/y). */
    if (mode_changed || target_slot == KPM_INTERCEPT_SLOT_ALL ||
        target_slot < 0 || target_slot >= MAX_OUTPUT_SLOTS) {
        reset_all_slots();
    } else {
        reset_slot_state(target_slot);
    }

    /* PIN supports per-slot coordinates: when targeting all slots, set
     * every slot to the same pin position. When targeting one slot,
     * set only that slot's pin position (other slots keep their
     * existing pin coordinates for incremental per-slot PIN). */
    if (target_slot == KPM_INTERCEPT_SLOT_ALL || target_slot < 0 ||
        target_slot >= MAX_OUTPUT_SLOTS) {
        for (i = 0; i < MAX_OUTPUT_SLOTS; i++) {
            g_intercept.pin_x[i] = pin_x;
            g_intercept.pin_y[i] = pin_y;
        }
    } else {
        g_intercept.pin_x[target_slot] = pin_x;
        g_intercept.pin_y[target_slot] = pin_y;
    }

    kpm_log("kpm: intercept PIN started (%d,%d) slot=%d mask=0x%x\n",
            pin_x, pin_y, target_slot, g_intercept.slot_mask);
    return 0;
}

long kpm_intercept_start_pin_zero(int pin_x, int pin_y, int target_slot)
{
    int prev_mode = g_intercept.mode;
    int mode_changed = (prev_mode != KPM_INTERCEPT_PIN_ZERO);
    int i;

    g_intercept.enabled = 1;
    g_intercept.mode    = KPM_INTERCEPT_PIN_ZERO;
    g_intercept.max_offset = 2000;
    update_slot_mask(target_slot, prev_mode, KPM_INTERCEPT_PIN_ZERO);

    if (mode_changed || target_slot == KPM_INTERCEPT_SLOT_ALL ||
        target_slot < 0 || target_slot >= MAX_OUTPUT_SLOTS) {
        reset_all_slots();
    } else {
        reset_slot_state(target_slot);
    }

    /* PIN_ZERO 与 PIN 一样支持 per-slot 坐标 */
    if (target_slot == KPM_INTERCEPT_SLOT_ALL || target_slot < 0 ||
        target_slot >= MAX_OUTPUT_SLOTS) {
        for (i = 0; i < MAX_OUTPUT_SLOTS; i++) {
            g_intercept.pin_x[i] = pin_x;
            g_intercept.pin_y[i] = pin_y;
        }
    } else {
        g_intercept.pin_x[target_slot] = pin_x;
        g_intercept.pin_y[target_slot] = pin_y;
    }

    kpm_log("kpm: intercept PIN_ZERO started (%d,%d) slot=%d mask=0x%x\n",
            pin_x, pin_y, target_slot, g_intercept.slot_mask);
    return 0;
}

long kpm_intercept_slot_off(int slot_id)
{
    if (slot_id < 0 || slot_id >= MAX_OUTPUT_SLOTS)
        return -KPM_E_INVAL;

    if (!g_intercept.enabled)
        return 0;

    /* Clear this slot's bit in the mask */
    g_intercept.slot_mask &= (uint16_t)~(1u << slot_id);

    /* Reset this slot's state so a later re-enable starts fresh */
    reset_slot_state(slot_id);

    if (g_intercept.slot_mask == 0) {
        /* No slots remain: fully stop intercept */
        kpm_log("kpm: intercept slot %d off (mask empty, stopping)\n", slot_id);
        return kpm_intercept_stop();
    }

    kpm_log("kpm: intercept slot %d off, mask=0x%x\n",
            slot_id, g_intercept.slot_mask);
    return 0;
}

long kpm_intercept_stop(void)
{
    int was_enabled = g_intercept.enabled;

    g_intercept.enabled = 0;
    g_intercept.mode    = KPM_INTERCEPT_OFF;
    g_intercept.target_x = 0;
    g_intercept.target_y = 0;
    g_intercept.slot_mask = 0xFFFF;  /* reset to default for next start */
    reset_all_slots();

    if (was_enabled)
        kpm_log("kpm: intercept STOPPED\n");
    return 0;
}

/* ===== Intercept offset calculation (integer-only, per-slot) =====
 *
 * All arithmetic is integer-only to avoid FP-in-IRQ-context issues on ARM64
 * kernel (kernel doesn't save FPCR/FPSR on IRQ entry).
 *
 * OFFSET mode directly applies the target offset for immediate visible effect.
 * The smoothing_q8 field is not consumed by any offset calculation.
 */
static void clamp_offset_slot(int slot)
{
    int mo = g_intercept.max_offset;
    if (g_intercept.offset_x[slot] > mo)  g_intercept.offset_x[slot] = mo;
    if (g_intercept.offset_x[slot] < -mo) g_intercept.offset_x[slot] = -mo;
    if (g_intercept.offset_y[slot] > mo)  g_intercept.offset_y[slot] = mo;
    if (g_intercept.offset_y[slot] < -mo) g_intercept.offset_y[slot] = -mo;
}

/* Calculate X offset for current frame given the new screen X.
 * Slot is the hardware MT slot. Always computes offset (even on first event
 * for OFFSET mode — the target is applied immediately). */
static int calc_offset_x(int slot, int screen_x)
{
    int prev;
    int dx;
    int is_first;

    if (slot < 0 || slot >= MAX_OUTPUT_SLOTS) return 0;

    prev = g_intercept.prev_x[slot];
    is_first = (prev < 0);

    if (!is_first) {
        dx = screen_x - prev;
        g_intercept.user_dx[slot] += dx;
    }
    g_intercept.prev_x[slot] = screen_x;

    switch (g_intercept.mode) {
    case KPM_INTERCEPT_REDIRECT:
        /* 反向滑动: offset = -2 * displacement * scale / 100
         * 推导: output = current + offset
         *      = (start + displacement) + (-2 * displacement * scale / 100)
         *      = start + displacement * (1 - 2*scale/100)
         * scale=100: output = start - displacement (完全反向)
         * scale=50:  output = start (冻结)
         * scale=25:  output = start + 0.5*displacement (阻尼同向) */
        g_intercept.offset_x[slot] =
            -2 * (g_intercept.user_dx[slot]) * g_intercept.scale / 100;
        break;

    case KPM_INTERCEPT_OFFSET:
        /* 直接设置 offset = target_x，立即到达目标（不做平滑过渡）。 */
        g_intercept.offset_x[slot] = g_intercept.target_x;
        break;

    case KPM_INTERCEPT_MIRROR:
        /* 真正的镜像: offset = -2 * displacement (等价 scale=100 反向)
         * output = (start + displacement) - 2*displacement = start - displacement
         * 手指向右移 D，触摸点向左移 D（关于起点镜像）。 */
        if (g_intercept.mirror_x)
            g_intercept.offset_x[slot] = -2 * (g_intercept.user_dx[slot]);
        else
            g_intercept.offset_x[slot] = 0;
        break;

    case KPM_INTERCEPT_PIN:
        /* 固定到指定位置: output = pin_x[slot]
         * offset = pin_x[slot] - screen_x，使用户滑动不影响触摸位置。
         * 用于瞄准辅助场景：外部程序设定目标坐标，触摸点锁定到该坐标。 */
        g_intercept.offset_x[slot] = g_intercept.pin_x[slot] - screen_x;
        break;

    default:
        g_intercept.offset_x[slot] = 0;
        break;
    }

    clamp_offset_slot(slot);
    return g_intercept.offset_x[slot];
}

/* Calculate Y offset for current frame given the new screen Y. */
static int calc_offset_y(int slot, int screen_y)
{
    int prev;
    int dy;
    int is_first;

    if (slot < 0 || slot >= MAX_OUTPUT_SLOTS) return 0;

    prev = g_intercept.prev_y[slot];
    is_first = (prev < 0);

    if (!is_first) {
        dy = screen_y - prev;
        g_intercept.user_dy[slot] += dy;
    }
    g_intercept.prev_y[slot] = screen_y;

    switch (g_intercept.mode) {
    case KPM_INTERCEPT_REDIRECT:
        /* 真正的反向滑动: offset = -2 * displacement * scale / 100
         * scale=100: 完全反向, scale=50: 冻结, scale=25: 阻尼同向
         * (详见 calc_offset_x 中相同公式的推导) */
        g_intercept.offset_y[slot] =
            -2 * (g_intercept.user_dy[slot]) * g_intercept.scale / 100;
        break;

    case KPM_INTERCEPT_OFFSET:
        /* 直接设置 offset = target_y，立即到达目标 */
        g_intercept.offset_y[slot] = g_intercept.target_y;
        break;

    case KPM_INTERCEPT_MIRROR:
        /* 真正的镜像: offset = -2 * displacement
         * output = start - displacement (关于起点镜像) */
        if (g_intercept.mirror_y)
            g_intercept.offset_y[slot] = -2 * (g_intercept.user_dy[slot]);
        else
            g_intercept.offset_y[slot] = 0;
        break;

    case KPM_INTERCEPT_PIN:
        /* 固定到指定位置: output = pin_y[slot]
         * offset = pin_y[slot] - screen_y，使用户滑动不影响触摸位置。 */
        g_intercept.offset_y[slot] = g_intercept.pin_y[slot] - screen_y;
        break;

    default:
        g_intercept.offset_y[slot] = 0;
        break;
    }

    clamp_offset_slot(slot);
    return g_intercept.offset_y[slot];
}

long kpm_intercept_get_state(void)
{
    /* Pack state into long:
     *   enabled[0-7] | mode[8-15] | offset_x[16-30] | offset_y[32-46]
     * Use 15-bit signed encoding to keep bit 31 = 0 (avoid sign extension).
     * Returns first active slot's offset, or slot 0 if none active.
     */
    int i;
    int ox = 0, oy = 0;

    for (i = 0; i < MAX_OUTPUT_SLOTS; i++) {
        if (g_intercept.finger_down[i]) {
            ox = g_intercept.offset_x[i];
            oy = g_intercept.offset_y[i];
            break;
        }
    }

    if (ox > 16383) ox = 16383;
    if (ox < -16383) ox = -16383;
    if (oy > 16383) oy = 16383;
    if (oy < -16383) oy = -16383;
    return ((long)g_intercept.enabled)
         | ((long)g_intercept.mode << 8)
         | ((long)(ox & 0x7FFF) << 16)
         | ((long)(oy & 0x7FFF) << 32);
}

/* 真实手指按下计数。
 * IN-PLACE 模式（无虚拟触摸）下 hook 仅更新 g_intercept.finger_down[]，
 * 不注册 TVF USER 对象，故返回 finger_down[] 中置位的 slot 数，
 * 供 touch_count 叠加。 */
int kpm_intercept_count_real_fingers(void)
{
    int i, count = 0;

    /* hook 可能在 IRQ 上下文写 finger_down，读侧用内存屏障防撕裂 */
    asm volatile("dmb ish" ::: "memory");
    for (i = 0; i < MAX_OUTPUT_SLOTS; i++) {
        if (g_intercept.finger_down[i])
            count++;
    }
    asm volatile("dmb ish" ::: "memory");
    return count;
}

long kpm_intercept_get_slot_state(kpm_intercept_slot_state_t *state)
{
    int i;

    if (!state)
        return -KPM_E_INVAL;

    state->slot_mask = g_intercept.slot_mask;
    state->enabled   = (uint8_t)g_intercept.enabled;
    state->mode      = (uint8_t)g_intercept.mode;

    for (i = 0; i < MAX_OUTPUT_SLOTS && i < KPM_MAX_SLOTS; i++) {
        int ox = g_intercept.offset_x[i];
        int oy = g_intercept.offset_y[i];
        if (ox > 32767) ox = 32767;
        if (ox < -32768) ox = -32768;
        if (oy > 32767) oy = 32767;
        if (oy < -32768) oy = -32768;
        state->offset_x[i] = (int16_t)ox;
        state->offset_y[i] = (int16_t)oy;

        int px = g_intercept.pin_x[i];
        int py = g_intercept.pin_y[i];
        if (px > 32767) px = 32767;
        if (px < -32768) px = -32768;
        if (py > 32767) py = 32767;
        if (py < -32768) py = -32768;
        state->pin_x[i] = (int16_t)px;
        state->pin_y[i] = (int16_t)py;

        state->finger_down[i] = (uint8_t)g_intercept.finger_down[i];
    }

    /* Zero-fill remaining slots if KPM_MAX_SLOTS > MAX_OUTPUT_SLOTS */
    for (i = MAX_OUTPUT_SLOTS; i < KPM_MAX_SLOTS; i++) {
        state->offset_x[i] = 0;
        state->offset_y[i] = 0;
        state->pin_x[i] = 0;
        state->pin_y[i] = 0;
        state->finger_down[i] = 0;
    }

    return 0;
}

long kpm_intercept_set_scale(int scale)
{
    if (scale < 1) scale = 1;
    if (scale > 100) scale = 100;
    g_intercept.scale = scale;
    g_intercept.smoothing_q8 = 38 + scale * 2;
    kpm_log("kpm: intercept scale set to %d (smooth_q8=%d)\n",
            scale, g_intercept.smoothing_q8);
    return 0;
}

long kpm_intercept_set_max_offset(int max_offset)
{
    if (max_offset < 10) max_offset = 10;
    if (max_offset > 2000) max_offset = 2000;
    g_intercept.max_offset = max_offset;
    kpm_log("kpm: intercept max_offset set to %d\n", max_offset);
    return 0;
}

/* ===== Input Capture Hook =====
 *
 * Hooks input_handle_event(dev, type, code, value) — 4 args.
 */
static void kpm_intercept_input_before_impl(hook_fargs4_t *args, void *udata);

/* 输入 hook 回调在途计数 + 卸载排空：hook_unwrap 移除回调后立即
 * hook_mem_free(chain)，在途回调不排空；本回调在 IRQ/软中断上下文执行
 * （不能睡眠），故用无锁原子加减（LH_utils.h kpm_atomic_inc/dec_acq_rel
 * + kpm_inflight_is_zero）计数，卸载前以 barrier + 有界复检等待归零
 * （不用 RCU 读锁，synchronize_rcu 需睡眠）。 */
static volatile int g_intercept_inflight = 0;

static void kpm_intercept_inflight_inc(void)
{
    kpm_atomic_inc_acq_rel(&g_intercept_inflight);
}

static void kpm_intercept_inflight_dec(void)
{
    kpm_atomic_dec_acq_rel(&g_intercept_inflight);
}

/* 等待在途回调归零必须是有界等待：若计数因异常泄漏（如 wrapper 早退
 * 跳过 dec），kpm_intercept_hook_uninstall 会永久挂死。超时后记录日志并
 * 放行（回调在 IRQ 上下文且极短促，正常运行微秒级归零，10s 超时仅是
 * 防挂死兜底）。 */
#define KPM_INTERCEPT_DRAIN_TIMEOUT_LOOPS  100000000UL  /* ~10s @ 10M loops/s */

void kpm_intercept_drain(void)
{
    unsigned long spins = 0;
    int confirm_tries = 0;

    for (;;) {
        /* 第一段：acquire 读自旋等归零（无额外延迟） */
        while (kpm_atomic_read_acquire(&g_intercept_inflight) != 0) {
            if (++spins > KPM_INTERCEPT_DRAIN_TIMEOUT_LOOPS) {
                kpm_log("kpm: intercept hook drain timeout (%d inflight)\n",
                        (int)kpm_atomic_read_acquire(&g_intercept_inflight));
                return;
            }
            asm volatile("yield" ::: "memory");
        }
        /* 第二段：一次性最终确认（barrier + 有界等待 + 复读），
         * 关掉"inc 的 store 还在 store buffer"的窗口（LH_utils.h）。 */
        if (kpm_inflight_final_zero(&g_intercept_inflight))
            return;
        if (++confirm_tries >= 3) {
            kpm_log("kpm: intercept inflight unstable after %d confirmations\n",
                    confirm_tries);
            return;
        }
    }
}

/* ===== 输入捕获 hook 回调 ===== */
static void kpm_intercept_input_before(hook_fargs4_t *args, void *udata)
{
    kpm_intercept_inflight_inc();
    kpm_intercept_input_before_impl(args, udata);
    kpm_intercept_inflight_dec();
}

static void kpm_intercept_input_before_impl(hook_fargs4_t *args, void *udata)
{
    void *dev;
    unsigned int type, code;
    int value;
    void *touch_dev;
    int need_tvf;

    (void)udata;

    /* Skip our own injected events (prevents feedback loop) */
    asm volatile("dmb ish" ::: "memory");
    if (g_injecting) return;

    dev = (void *)args->arg0;
    type = (unsigned int)args->arg1;
    code = (unsigned int)args->arg2;
    value = (int)args->arg3;

    /* Only handle the touch device */
    touch_dev = kpm_touch_get_dev();
    if (!touch_dev || dev != touch_dev) return;

    /* 触摸事件记录器（真实硬件输入样本）。
     * 此处 g_injecting 已返回（不记录驱动输出），且是触摸设备事件，
     * 记录所有类型（含 EV_SYN 帧结构）→ 完整真实触摸事件流。 */
    kpm_tvrecord(KPM_TVREC_SRC_HW, current_mt_slot, (int)code, value);

    /* Determine mode:
     * - TVF CAPTURE: virtual touches active -> route through TVF, block originals
     * - IN-PLACE: no virtual touches -> modify coordinates in-place, events
     *   pass through with zero detectable trace
     *
     * 当有虚拟触摸活跃时必须走 CAPTURE 模式，否则:
     *   - 虚拟触摸的 DOWN 事件和用户 DOWN 事件都透传 → Android 收到两个 DOWN
     *   - 用户触摸会"带走"虚拟触摸，产生长按现象
     * CAPTURE 模式下所有硬件事件被拦截，由 TVF 框架统一合并输出。
     */
    need_tvf = (g_virtual_touch_count > 0);

    /* ============================================================
     * TVF CAPTURE MODE: virtual touches active
     * Route all events through TVF framework, block originals.
     * ============================================================ */
    if (need_tvf) {
        if (type == EV_SYN_CODE && code == SYN_REPORT_CODE) {
            tvf_run_frame();
            args->skip_origin = 1;
            return;
        }
        if (type == EV_KEY_CODE) {
            args->skip_origin = 1;  /* output layer sends its own */
            return;
        }
        if (type != EV_ABS_CODE) return;

        switch (code) {
        case ABS_MT_SLOT:
            /* Track current hardware MT slot */
            if (value >= 0 && value < MAX_OUTPUT_SLOTS)
                current_mt_slot = value;
            args->skip_origin = 1;
            return;

        case ABS_MT_TRACKING_ID: {
            int slot = current_mt_slot;
            if (value == -1) {
                /* User finger up */
                tvf_release_user(slot);
                g_intercept.finger_down[slot] = 0;
                reset_slot_state(slot);
                if (g_diag_log_count < DIAG_LOG_MAX) {
                    kpm_log("kpm: intercept UP slot=%d en=%d\n",
                            slot, g_intercept.enabled);
                    g_diag_log_count++;
                }
            } else {
                /* User finger down */
                tvf_register_user(slot, value);
                g_intercept.finger_down[slot] = 1;
                g_intercept.prev_x[slot]     = -1;
                g_intercept.prev_y[slot]     = -1;
                g_intercept.user_dx[slot]    = 0;
                g_intercept.user_dy[slot]    = 0;
                g_intercept.offset_x[slot]  = 0;
                g_intercept.offset_y[slot]  = 0;
                if (g_diag_log_count < DIAG_LOG_MAX) {
                    kpm_log("kpm: intercept DOWN slot=%d tid=%d en=%d mode=%d\n",
                            slot, value, g_intercept.enabled, g_intercept.mode);
                    g_diag_log_count++;
                }
            }
            args->skip_origin = 1;
            return;
        }

        case ABS_MT_POSITION_X: {
            int slot = current_mt_slot;
            int screen_x = value / g_intercept_scale;
            int final_x = screen_x;
            int off = 0;

            /* PIN_ZERO 模式: 丢弃硬件 X 事件，改用 pin_x 固定坐标更新 TVF。
             * 必须用 tvf_update_user 传入 pin_x，否则 TVF 注册了用户触摸却
             * 永不接收坐标 → 触摸停留在默认值(-1/0,0)，用户触摸消失或
             * 定位到左上角。 */
            if (g_intercept.enabled && g_intercept.mode == KPM_INTERCEPT_PIN_ZERO &&
                slot >= 0 && slot < MAX_OUTPUT_SLOTS &&
                g_intercept.finger_down[slot] &&
                (g_intercept.slot_mask & (uint16_t)(1u << slot))) {
                args->skip_origin = (tvf_update_user(
                    slot, g_intercept.pin_x[slot], -1, -1, -1) == 1);
                return;
            }

            /* Apply intercept offset if enabled, this slot has a finger down,
             * AND this slot is in the slot_mask (per-slot intercept support).
             * Slots not in mask pass through unmodified. */
            if (g_intercept.enabled && slot >= 0 && slot < MAX_OUTPUT_SLOTS &&
                g_intercept.finger_down[slot] &&
                (g_intercept.slot_mask & (uint16_t)(1u << slot))) {
                off = calc_offset_x(slot, screen_x);
                /* Apply offset in raw touch coordinates to preserve sub-pixel
                 * precision. offset*SCALE is exact; only screen conversion
                 * truncates the remainder (same as hardware ADC noise floor). */
                {
                    int raw_val = value + off * g_intercept_scale;
                    if (raw_val < 0) raw_val = 0;
                    if (g_screen_w > 0 && raw_val > g_screen_w)
                        raw_val = g_screen_w;
                    final_x = raw_val / g_intercept_scale;
                }
                if (g_diag_log_count < DIAG_LOG_MAX) {
                    kpm_log("kpm: intercept X slot=%d raw=%d sx=%d off=%d fx=%d\n",
                            slot, value, screen_x, off, final_x);
                    g_diag_log_count++;
                }
            }

            /* tvf_update_user 返回 0（手指 DOWN 早于 CAPTURE、未注册
             * USER 对象）时必须放行原事件，否则坐标被吞 → 真实手指
             * 固定不动；对象存在才拦截。 */
            args->skip_origin = (tvf_update_user(
                slot, final_x, -1, -1, -1) == 1);
            return;
        }

        case ABS_MT_POSITION_Y: {
            int slot = current_mt_slot;
            int screen_y = value / g_intercept_scale;
            int final_y = screen_y;
            int off = 0;

            /* PIN_ZERO 模式: 丢弃硬件 Y 事件，改用 pin_y 固定坐标更新 TVF。
             * 必须用 tvf_update_user 传入 pin_y，否则触摸 Y 坐标丢失。 */
            if (g_intercept.enabled && g_intercept.mode == KPM_INTERCEPT_PIN_ZERO &&
                slot >= 0 && slot < MAX_OUTPUT_SLOTS &&
                g_intercept.finger_down[slot] &&
                (g_intercept.slot_mask & (uint16_t)(1u << slot))) {
                args->skip_origin = (tvf_update_user(
                    slot, -1, g_intercept.pin_y[slot], -1, -1) == 1);
                return;
            }

            if (g_intercept.enabled && slot >= 0 && slot < MAX_OUTPUT_SLOTS &&
                g_intercept.finger_down[slot] &&
                (g_intercept.slot_mask & (uint16_t)(1u << slot))) {
                off = calc_offset_y(slot, screen_y);
                {
                    int raw_val = value + off * g_intercept_scale;
                    if (raw_val < 0) raw_val = 0;
                    if (g_screen_h > 0 && raw_val > g_screen_h)
                        raw_val = g_screen_h;
                    final_y = raw_val / g_intercept_scale;
                }
            }

            args->skip_origin = (tvf_update_user(
                slot, -1, final_y, -1, -1) == 1);
            return;
        }

        case ABS_MT_TOUCH_MAJOR:
            args->skip_origin = (tvf_update_user(
                current_mt_slot, -1, -1, -1, value) == 1);
            return;

        case ABS_MT_PRESSURE:
            args->skip_origin = (tvf_update_user(
                current_mt_slot, -1, -1, value, -1) == 1);
            return;

        default:
            /* Forward unknown ABS_MT events (WIDTH_MAJOR, ORIENTATION, DISTANCE,
             * etc.) instead of blocking them. This prevents event type gaps
             * that anti-cheat can detect by reading /dev/input/eventX directly.
             * These events are not routed through TVF but are passed through
             * to the original handler so the event stream remains complete. */
            args->skip_origin = 0;
            return;
        }
    } /* end of TVF CAPTURE mode */

    /* ============================================================
     * IN-PLACE MUTATION MODE: no virtual touches
     *
     * ALL events pass through to the original handler unchanged.
     * If intercept is enabled, only ABS_MT_POSITION_X/Y values are
     * modified in-place by rewriting args->arg3.
     *
     * This leaves ZERO detectable trace:
     *   - Event timing: unchanged (original hardware timing)
     *   - Event sequence: unchanged (original hardware sequence)
     *   - BTN_TOUCH/EV_SYN: unchanged (passed through)
     *   - ABS_MT_SLOT/TRACKING_ID: unchanged
     *   - Only coordinate values are modified, indistinguishable from
     *     a user actually touching at the modified position
     * ============================================================ */
    if (type != EV_ABS_CODE) return;

    switch (code) {
    case ABS_MT_SLOT:
        if (value >= 0 && value < MAX_OUTPUT_SLOTS)
            current_mt_slot = value;
        break;

    case ABS_MT_TRACKING_ID: {
        int slot = current_mt_slot;
        if (value == -1) {
            g_intercept.finger_down[slot] = 0;
            reset_slot_state(slot);
            /* 清理 CAPTURE 关闭时静默移交（DETACH）的用户触摸对象
             * （用户真正抬起，对象不再需要保护 real_slot） */
            tvf_user_detach_cleanup(slot);
        } else {
            g_intercept.finger_down[slot] = 1;
            g_intercept.prev_x[slot]     = -1;
            g_intercept.prev_y[slot]     = -1;
            g_intercept.user_dx[slot]    = 0;
            g_intercept.user_dy[slot]    = 0;
            g_intercept.offset_x[slot]  = 0;
            g_intercept.offset_y[slot]  = 0;
        }
        break;
    }

    case ABS_MT_POSITION_X: {
        int slot = current_mt_slot;
        int screen_x = value / g_intercept_scale;

        /* PIN_ZERO 模式: 直接丢弃 X 事件，不透传给 Android。
         * IN-PLACE 模式下通过 skip_origin=1 阻止事件传递。 */
        if (g_intercept.enabled && g_intercept.mode == KPM_INTERCEPT_PIN_ZERO &&
            slot >= 0 && slot < MAX_OUTPUT_SLOTS &&
            g_intercept.finger_down[slot] &&
            (g_intercept.slot_mask & (uint16_t)(1u << slot))) {
            args->skip_origin = 1;
            return;
        }

        if (g_intercept.enabled && slot >= 0 && slot < MAX_OUTPUT_SLOTS &&
            g_intercept.finger_down[slot] &&
            (g_intercept.slot_mask & (uint16_t)(1u << slot))) {
            int off = calc_offset_x(slot, screen_x);
            int raw_val = value + off * g_intercept_scale;
            if (raw_val < 0) raw_val = 0;
            if (g_screen_w > 0 && raw_val > g_screen_w)
                raw_val = g_screen_w;
            /* In-place modification: rewrite the value argument.
             * The original input_handle_event receives the modified value
             * and processes it as if the hardware sent it. */
            args->arg3 = raw_val;
            if (g_diag_log_count < DIAG_LOG_MAX) {
                kpm_log("kpm: intercept X(in-place) slot=%d raw=%d sx=%d off=%d fx=%d\n",
                        slot, value, screen_x, off, raw_val / g_intercept_scale);
                g_diag_log_count++;
            }
        }
        break;
    }

    case ABS_MT_POSITION_Y: {
        int slot = current_mt_slot;
        int screen_y = value / g_intercept_scale;

        /* PIN_ZERO 模式: 直接丢弃 Y 事件 */
        if (g_intercept.enabled && g_intercept.mode == KPM_INTERCEPT_PIN_ZERO &&
            slot >= 0 && slot < MAX_OUTPUT_SLOTS &&
            g_intercept.finger_down[slot] &&
            (g_intercept.slot_mask & (uint16_t)(1u << slot))) {
            args->skip_origin = 1;
            return;
        }

        if (g_intercept.enabled && slot >= 0 && slot < MAX_OUTPUT_SLOTS &&
            g_intercept.finger_down[slot] &&
            (g_intercept.slot_mask & (uint16_t)(1u << slot))) {
            int off = calc_offset_y(slot, screen_y);
            int raw_val = value + off * g_intercept_scale;
            if (raw_val < 0) raw_val = 0;
            if (g_screen_h > 0 && raw_val > g_screen_h)
                raw_val = g_screen_h;
            args->arg3 = raw_val;
            if (g_diag_log_count < DIAG_LOG_MAX) {
                kpm_log("kpm: intercept Y(in-place) slot=%d raw=%d sy=%d off=%d fy=%d\n",
                        slot, value, screen_y, off, raw_val / g_intercept_scale);
                g_diag_log_count++;
            }
        }
        break;
    }

    default:
        /* All other ABS_MT events pass through unchanged */
        break;
    }

    /* Do NOT set skip_origin -- event passes through with modified value */
}

static void kpm_intercept_input_after(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

/* ===== Hook install / uninstall ===== */

long kpm_intercept_hook_install(void)
{
    hook_err_t err;

    if (g_hook_installed) return 0;

    if (!kf_input_handle_event) {
        kpm_log("kpm: capture hook skipped - input_handle_event not resolved\n");
        return -1;
    }

    if (!kpm_touch_get_dev()) {
        kpm_log("kpm: capture hook skipped - touch device not found\n");
        return -1;
    }

    /* Cache screen dimensions for boundary clamping in the hook */
    kpm_touch_get_screen_info(&g_screen_w, &g_screen_h);

    /* Sync intercept coordinate scale with touch subsystem.
     * g_screen_w/h store absinfo.maximum (hardware coordinates), so
     * boundary clamps must NOT multiply by scale again.
     *
     * scale 探测可能失败返回 0；后续 hook 回调中 `value / g_intercept_scale`
     * 会除零并在 IRQ 上下文 panic，故强制最小值 1。 */
    g_intercept_scale = kpm_touch_get_scale();
    if (g_intercept_scale <= 0) {
        kpm_log("kpm: intercept scale=%d invalid, forcing to 1\n",
                g_intercept_scale);
        g_intercept_scale = 1;
    }
    kpm_log("kpm: intercept scale=%d screen=%dx%d\n",
            g_intercept_scale, g_screen_w, g_screen_h);

    err = hook_wrap(kf_input_handle_event, 4,
                    kpm_intercept_input_before,
                    kpm_intercept_input_after,
                    0);
    if (err != HOOK_NO_ERR) {
        kpm_log("kpm: capture hook_wrap failed: %d\n", (int)err);
        return (long)err;
    }

    g_hook_installed = 1;
    kpm_log("kpm: input capture hook installed on input_handle_event\n");
    return 0;
}

void kpm_intercept_hook_uninstall(void)
{
    if (!g_hook_installed) return;

    hook_unwrap(kf_input_handle_event,
                kpm_intercept_input_before,
                kpm_intercept_input_after);

    g_hook_installed = 0;
    /* unhook 后等待在途回调退出，再允许模块 .text 释放（防取指 UAF）。
     * 回调短促（IRQ 上下文），drain 以有界等待防挂死。 */
    kpm_intercept_drain();
    kpm_log("kpm: input capture hook removed (inflight drained)\n");
}

/* 输入捕获 hook 安装状态查询（UN_HOOK 用）。
 * 返回 1 = input_handle_event 捕获 hook 已安装，0 = 未安装。 */
long kpm_intercept_hook_active(void)
{
    return (long)g_hook_installed;
}
