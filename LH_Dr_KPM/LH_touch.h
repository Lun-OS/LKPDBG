/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_touch.h - Touch Virtualization Framework V2 (TVF V2)
 *
 * Core design: Unified TouchObject pool + Slot Virtualizer + Scheduler.
 * All touch sources (user + virtual) are abstracted as TouchObjects.
 * The Scheduler arbitrates output slot assignment per-frame with
 * priority-based preemption. The Transaction Buffer ensures frame
 * consistency (one SYN_REPORT = one complete touch state snapshot).
 */
#ifndef _KPM_TOUCH_H_
#define _KPM_TOUCH_H_

#include <ktypes.h>
#include <stdint.h>
#include "LH_comm.h"

/* ===== Limits ===== */
#define MAX_TOUCH_OBJECTS  32   /* pool size (allows suspension) */
#define MAX_OUTPUT_SLOTS   10   /* device max touch points (= KPM_MAX_TOUCH_POINTS) */

/* ===== Owner enum ===== */
enum {
    TVF_OWNER_FREE = 0,     /* idle object */
    TVF_OWNER_USER,         /* real user touch */
    TVF_OWNER_VIRTUAL,      /* driver-created virtual touch */
    TVF_OWNER_TAKEOVER,     /* virtual touch hijacking a real slot's output */
};

/* ===== TouchObject state ===== */
enum {
    TVF_STATE_INACTIVE = 0, /* not active (free or released) */
    TVF_STATE_ACTIVE,       /* has output slot, producing events */
    TVF_STATE_SUSPENDED,    /* preempted (no output slot, awaiting resume) */
    TVF_STATE_DETACH,       /* CAPTURE 关闭时仍在屏的用户触摸已
                             * 静默移交回硬件直通（不发 UP 帧）。对象保留
                             * real_slot 保护，待用户真正抬起时由
                             * tvf_user_detach_cleanup 清理，防泄漏。 */
};

/* ===== Scheduler policy ===== */
enum {
    TVF_POLICY_AUTO = 0,        /* USER first, suspend lowest-priority VIRTUAL on contention */
    TVF_POLICY_REAL_FIRST,      /* user absolute priority, discard virtual if needed */
    TVF_POLICY_PRIORITY,        /* strictly by TouchObject.priority */
    TVF_POLICY_CUSTOM,          /* application controls via suspend/resume */
};

/* ===== Priority defaults (lower = higher priority) ===== */
#define TVF_PRIO_USER     0
#define TVF_PRIO_VIRTUAL  10
#define TVF_PRIO_NORMAL   10

/* ===== Animation types (internal, for move_to etc.) ===== */
#define TVF_ANIM_NONE     0
#define TVF_ANIM_MOVE_TO  1
#define TVF_ANIM_MOVE_DIR 2

/* ===== TouchObject — the unified touch entity ===== */
typedef struct {
    uint32_t id;                /* unique identifier (for validation) */
    uint8_t  owner;             /* TVF_OWNER_* */
    uint8_t  state;             /* TVF_STATE_* */
    uint8_t  priority;          /* lower = higher priority */
    uint8_t  reserved;

    int      real_slot;         /* hardware slot (-1 = virtual/no hw slot) */
    int      output_slot;       /* assigned output slot (-1 = none) */

    int      tracking_id;       /* MT tracking ID for input subsystem */
    int      x, y;              /* screen coordinates (pixel); raw 模式下为显示近似值 */
    int      raw_x, raw_y;      /* hardware raw coords (min unit), -1 = pixel mode.
                                 * 输出帧 raw_x>=0 时直接透传不 ×scale，
                                 * 支持亚像素精度（scale=16 时 1 raw = 1/16 像素） */
    int      pressure;
    int      touch_major;

    /* animation control (for virtual touches) */
    volatile int cancel;
    volatile int anim_type;
    int      allow_interrupt;

    /* frame tracking: set when object changed since last frame */
    uint8_t  dirty;
} TouchObject;

/* ===== TouchHandle — opaque handle for external API =====
 * Internally a pool index [0, MAX_TOUCH_OBJECTS).
 * -1 = invalid. Returned to userspace as a long. */
typedef int TouchHandle;

#define TVF_INVALID_HANDLE  (-1)

/* ===== FrameBuffer slot state (transaction buffer) ===== */
typedef struct {
    int      tracking_id;   /* -1 = slot is being released (UP) */
    int      x, y;
    int      raw_x, raw_y;  /* raw 单位坐标（-1=像素模式） */
    int      pressure;
    int      touch_major;
    uint8_t  active;        /* 1 = touch down/move, 0 = up/release */
    uint8_t  dirty;         /* 1 = needs output this frame */
} SlotState;

/* ===== Initialization / Device ===== */

/* Initialize touch subsystem: find touch device, init pool/scheduler */
long kpm_touch_init(void);

/* Exit cleanup */
void kpm_touch_exit(void);

/* Query touch device readiness */
int kpm_touch_ready(void);

/* Get screen resolution */
void kpm_touch_get_screen_info(int *width, int *height);

/* Get touch coordinate scale (hardware_coord = screen_coord * scale) */
int kpm_touch_get_scale(void);

/* Get touch device pointer (for hook filtering) */
void *kpm_touch_get_dev(void);

/* Get detected input_dev node offset (-1 = not detected) */
int kpm_touch_get_node_offset(void);

/* Injection flag: distinguishes real vs injected events (hook uses this) */
extern volatile int g_injecting;

/* Virtual touch count: lock-free counter for hook's pass-through decision.
 * Incremented in touch_create(), decremented in touch_destroy()/touch_up().
 * Read without lock in IRQ context by the input_handle_event hook.
 * When g_virtual_touch_count > 0, the hook stays in capture mode even if
 * intercept is off, because virtual touches must be merged with real touches. */
extern volatile int g_virtual_touch_count;

/* ===== TouchHandle API (external, for virtual touches) ===== */

/* Create a virtual touch (DOWN emitted on first touch_move)
 * priority: TVF_PRIO_* or custom
 * touch_major: contact area (0 = use default 10)
 * pressure: touch pressure (0 = use default 30)
 * Returns: TouchHandle >= 0, or -1 on failure */
TouchHandle touch_create(int priority, int touch_major, int pressure);

/* Update touch coordinates (MOVE on next frame) */
void touch_move(TouchHandle h, int x, int y);

/* raw 硬件坐标（1 raw = 1/scale 像素）。
 * 与像素版互斥：调用后对象进入 raw 模式，输出帧直接透传不 ×scale。
 * 可表达亚像素位置（scale=16 时粒度 1/16 像素）。 */
void touch_move_raw(TouchHandle h, int raw_x, int raw_y);
long touch_move_to_raw(TouchHandle h, int target_raw_x, int target_raw_y,
                       int touch_major, int pressure,
                       int duration_ms, int allow_interrupt);
long touch_move_dir_raw(TouchHandle h, int dx_raw, int dy_raw,
                        int touch_major, int pressure,
                        int duration_ms, int allow_interrupt);

/* Lift touch (UP on next frame). Object is released after output. */
void touch_up(TouchHandle h);

/* Destroy touch (force release; sends UP if it holds a slot) */
void touch_destroy(TouchHandle h);

/* Takeover a real touch (virtual output replaces real touch coordinates)
 * real_tracking_id: the hardware tracking ID to hijack */
long touch_takeover(TouchHandle h, int real_tracking_id);

/* Suspend output (object retained, no output slot) */
void touch_suspend(TouchHandle h);

/* Resume output (re-acquire output slot if available) */
void touch_resume(TouchHandle h);

/* Query if touch is active (has output slot) */
int touch_is_active(TouchHandle h);

/* ===== Animation helpers (blocking, for move_to) ===== */

/* Move to target with linear interpolation animation (blocking)
 * Returns: 0=done, 1=interrupted, negative=error */
long touch_move_to(TouchHandle h, int target_x, int target_y,
                   int touch_major, int pressure,
                   int duration_ms, int allow_interrupt);

/* Move by delta (instant, for high-frequency calling) */
long touch_move_dir(TouchHandle h, int dx, int dy,
                    int touch_major, int pressure,
                    int duration_ms, int allow_interrupt);

/* Cancel ongoing animation */
void touch_cancel_anim(TouchHandle h);

/* Cancel ALL ongoing animations, non-blocking（模块卸载前置，见实现注释）。
 * 必须在 kpm_touch_destroy_all()/drain 之前调用。 */
void touch_cancel_all(void);

/* 动画时长与步长上限
 * 动画在命令回调内忙等：duration 无界会让单条命令占用数分钟，卸载排空
 * 窗口内仍在取指 → UAF。命令层按 MAX_MS 夹 duration，动画层按
 * MAX_STEP_US 夹单步间隔，取消响应与排空因此都有上界。 */
#define KPM_TOUCH_ANIM_MAX_MS        5000    /* 单次动画总时长上限 5s */
#define KPM_TOUCH_ANIM_MAX_STEP_US   50000   /* 单步间隔上限 50ms */

/* ===== Query API ===== */

/* Get single touch info by handle */
long touch_get_info(TouchHandle h, kpm_touch_info_t *info);

/* Get all active touch info (fills array, returns count) */
long touch_get_all_info(kpm_touch_info_t *infos, int max_count);

/* Get active touch count (user + virtual with output slots) */
int touch_get_active_count(void);

/* ===== 触摸心跳保活 =====
 * 客户端必须周期调用 touch_keepalive（KEEPALIVE 命令，≤5s 一次）。
 * 超过 5s 无心跳 → 视为客户端离线 → 自动销毁全部虚拟触摸 + 释放
 * USER 对象（关闭 CAPTURE 代理），保证设备稳定。
 * touch_purge_all_if_idle(): process 上下文检查并清理（返回 1=已清理）
 * kpm_touch_destroy_all(): 无条件销毁全部（模块卸载用，发 UP 帧） */
void touch_keepalive(void);
int touch_purge_all_if_idle(void);
void kpm_touch_destroy_all(void);

/* ===== 触摸事件记录器 =====
 * 记录触摸事件流到内核环形缓冲，经 UDP TOUCH_RECORD_GET 拉取分析。 */
#define KPM_TVREC_MAX       2048
#define KPM_TVREC_SRC_HW    1    /* 硬件输入（hook 观察，真实触摸） */
#define KPM_TVREC_SRC_OUT   2    /* 驱动输出（tvf_output_commit_frame） */

void kpm_tvrecord(int src, int slot, int code, int value);
int  kpm_tvrecord_start(int src_mask);
int  kpm_tvrecord_stop(void);
int  kpm_tvrecord_copy(int start_idx, int count, void *dst, int *total_out);
/* 序号读取（供 UDP 推送 work 使用） */
int  kpm_tvrecord_fetch(uint64_t from_seq, int max, void *buf, uint64_t *next_seq);
uint64_t kpm_tvrecord_total(void);
/* 事件到达唤醒 UDP 推送（kpm_udp.c 实现，跨文件声明） */
void kpm_udp_tvpush_wakeup(void);

/* ===== Scheduler / Policy ===== */

/* Set scheduler policy */
void touch_set_policy(int policy);

/* Get current scheduler policy */
int touch_get_policy(void);

/* Set touch parameters (touch_major, pressure) at runtime
 * mask bits: 0x1 = update touch_major, 0x2 = update pressure
 * Returns: 0 on success, -1 on invalid handle */
long touch_set_params(TouchHandle h, int touch_major, int pressure, int mask);

/* ===== Input Capture (called by hook layer) ===== */

/* Register a user touch DOWN (from hardware event) */
TouchObject *tvf_register_user(int real_slot, int tracking_id);

/* 更新用户触摸对象坐标（hook 用）。返回 1=对象存在（调用方应拦截原事件），
 * 0=对象不存在（必须放行原事件，否则真实手指坐标被吞）。 */
int tvf_update_user(int real_slot, int x, int y, int pressure, int touch_major);

/* Release a user touch UP (from hardware event) */
void tvf_release_user(int real_slot);

/* 清理 CAPTURE 关闭时静默移交（TVF_STATE_DETACH）的用户触摸对象。
 * hook 在 IN-PLACE 模式下检测到用户抬起（tracking_id==-1）时调用，
 * 释放对应 real_slot 的 DETACH 对象（防 pool 泄漏，不影响触摸直通）。 */
void tvf_user_detach_cleanup(int real_slot);

/* Run scheduler + commit frame (called on EV_SYN) */
void tvf_run_frame(void);

/* ===== Output Layer ===== */

/* Commit the pending frame to input subsystem (sends complete MT frame + SYN) */
void tvf_output_commit_frame(void);

/* ===== Object lookup (internal) ===== */

/* Find TouchObject by real_slot (for hook layer) */
TouchObject *tvf_find_by_real_slot(int real_slot);

/* Validate and get TouchObject from handle */
TouchObject *tvf_get_object(TouchHandle h);

/* ===== Pool access (for kpm_intercept.c) ===== */
extern TouchObject g_touch_pool[MAX_TOUCH_OBJECTS];
extern int g_output_slot_owner[MAX_OUTPUT_SLOTS];
extern SlotState g_pending_frame[MAX_OUTPUT_SLOTS];

#endif /* _KPM_TOUCH_H_ */
