/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * touch_manager.c - TVF V2 Core Implementation
 *
 * Implements the Touch Virtualization Framework:
 *   - TouchObject pool (unified user + virtual touch entities)
 *   - Slot Virtualizer (logical → output slot mapping with preemption)
 *   - Scheduler (per-frame arbitration with policy engine)
 *   - Transaction Buffer (frame-consistent output)
 *   - TouchHandle API (touch_create/move/up/destroy/suspend/resume/takeover)
 *
 * Flow:
 *   Hardware event → tvf_register_user/update_user/release_user
 *   Virtual touch  → touch_create/move/up
 *   EV_SYN         → tvf_run_frame → scheduler → output_commit_frame
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <kputils.h>
#include <ktypes.h>

#include "touch_manager.h"
#include "LH_touch.h"
#include "LH_syms.h"
#include "LH_intercept.h"
#include "LH_utils.h"
#include "LH_log.h"
#include "LH_comm.h"

/* ===== Global state ===== */
TouchObject g_touch_pool[MAX_TOUCH_OBJECTS];
int g_output_slot_owner[MAX_OUTPUT_SLOTS];   /* stores pool index, -1 = free */
SlotState g_pending_frame[MAX_OUTPUT_SLOTS];

/* Scheduler state */
static int g_policy = TVF_POLICY_AUTO;
static volatile int g_tvf_lock = 0;

/* Tracking ID counter (for virtual touches; user touches use hardware ID).
 * Virtual tracking_id range: 0x0A-0xFF (10-255), indistinguishable from
 * a multi-touch controller with 10+ touch points. Hardware typically uses
 * 0-9 for 10-point controllers, so virtual touches start at 10 to avoid
 * collision while staying within plausible hardware range.
 * No raw event reader can distinguish virtual tracking_ids from hardware. */
static int g_next_tracking_id = 0x0A;

/* ===== Lock =====
 * Two variants:
 *
 * tvf_lock / tvf_unlock — process context (prctl path):
 *   Disables IRQs, then acquires the spinlock atomically (LDAXR/STXR).
 *   On unlock: releases atomically (STLR), then restores IRQs.
 *   This prevents a touch IRQ from interrupting a prctl
 *   call and deadlocking on the spinlock.
 *
 * tvf_lock_nointr / tvf_unlock_nointr — IRQ context (hook path):
 *   IRQs already disabled by input_event's spin_lock_irqsave.
 *   Pure atomic spinlock (LDAXR/STXR + STLR), does NOT touch DAIF.
 *   If tvf_unlock enabled IRQs here, it would break the
 *   spin_lock_irqsave invariant in input_event.
 *
 * Atomicity: ARM64 LDAXR (Load-Acquire Exclusive) + STXR (Store Exclusive)
 * with retry loop provides true atomic test-and-set across CPUs.
 * STLR (Store-Release) guarantees prior stores are visible before unlock.
 */

/* --- Process context: IRQ-safe atomic lock --- */
void tvf_lock(void)
{
    int one = 1;
    int tmp;
    asm volatile("msr daifset, #3" ::: "memory");  /* disable IRQ+FIQ */
    asm volatile(
        "1: ldaxr %w0, [%2]\n"
        "   cbnz %w0, 1b\n"
        "   stxr %w0, %w1, [%2]\n"
        "   cbnz %w0, 1b\n"
        : "=&r"(tmp)
        : "r"(one), "r"(&g_tvf_lock)
        : "memory"
    );
}

void tvf_unlock(void)
{
    asm volatile("stlr wzr, [%0]" : : "r"(&g_tvf_lock) : "memory");
    asm volatile("msr daifclr, #3" ::: "memory");  /* enable IRQ+FIQ */
}

/* --- IRQ context: no DAIF manipulation, atomic lock only --- */
void tvf_lock_nointr(void)
{
    int one = 1;
    int tmp;
    asm volatile(
        "1: ldaxr %w0, [%2]\n"
        "   cbnz %w0, 1b\n"
        "   stxr %w0, %w1, [%2]\n"
        "   cbnz %w0, 1b\n"
        : "=&r"(tmp)
        : "r"(one), "r"(&g_tvf_lock)
        : "memory"
    );
}

void tvf_unlock_nointr(void)
{
    asm volatile("stlr wzr, [%0]" : : "r"(&g_tvf_lock) : "memory");
}

/* ===== Tracking ID generator ===== */
int tvf_next_tracking_id(void)
{
    int id = g_next_tracking_id;
    g_next_tracking_id++;
    if (g_next_tracking_id > 0xFF)
        g_next_tracking_id = 0x0A;
    return id;
}

/* ===== Pool initialization ===== */
void tvf_pool_init(void)
{
    int i;
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        g_touch_pool[i].id = 0;
        g_touch_pool[i].owner = TVF_OWNER_FREE;
        g_touch_pool[i].state = TVF_STATE_INACTIVE;
        g_touch_pool[i].priority = TVF_PRIO_NORMAL;
        g_touch_pool[i].real_slot = -1;
        g_touch_pool[i].output_slot = -1;
        g_touch_pool[i].tracking_id = -1;
        g_touch_pool[i].x = 0;
        g_touch_pool[i].y = 0;
        g_touch_pool[i].pressure = 0;
        g_touch_pool[i].touch_major = 0;
        g_touch_pool[i].cancel = 0;
        g_touch_pool[i].anim_type = TVF_ANIM_NONE;
        g_touch_pool[i].allow_interrupt = 0;
        g_touch_pool[i].dirty = 0;
    }
    for (i = 0; i < MAX_OUTPUT_SLOTS; i++) {
        g_output_slot_owner[i] = -1;
        g_pending_frame[i].dirty = 0;
        g_pending_frame[i].active = 0;
        g_pending_frame[i].tracking_id = -1;
    }
}

/* ===== Object lookup ===== */
TouchObject *tvf_get_object(TouchHandle h)
{
    if (h < 0 || h >= MAX_TOUCH_OBJECTS)
        return NULL;
    if (g_touch_pool[h].owner == TVF_OWNER_FREE)
        return NULL;
    return &g_touch_pool[h];
}

TouchObject *tvf_find_by_real_slot(int real_slot)
{
    int i;
    if (real_slot < 0 || real_slot >= MAX_OUTPUT_SLOTS)
        return NULL;
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        if (g_touch_pool[i].owner != TVF_OWNER_FREE &&
            g_touch_pool[i].real_slot == real_slot)
            return &g_touch_pool[i];
    }
    return NULL;
}

/* ===== Pool allocation ===== */
static TouchObject *pool_alloc(void)
{
    int i;
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        if (g_touch_pool[i].owner == TVF_OWNER_FREE)
            return &g_touch_pool[i];
    }
    return NULL;
}

static void pool_free(TouchObject *obj)
{
    obj->owner = TVF_OWNER_FREE;
    obj->state = TVF_STATE_INACTIVE;
    obj->real_slot = -1;
    obj->output_slot = -1;
    obj->tracking_id = -1;
    obj->x = -1;
    obj->y = -1;
    obj->raw_x = -1;  /* 释放时清 raw，防 pool_alloc 复用残留 */
    obj->raw_y = -1;
    obj->dirty = 0;
    obj->cancel = 0;
    obj->anim_type = TVF_ANIM_NONE;
}

/* 释放所有用户触摸对象（静默移交或清理残留）
 *
 * 在 g_virtual_touch_count 递减到 0 时调用。
 *
 * 原因：CAPTURE 模式下用户触摸被注册为 TVF_OWNER_USER 对象。
 * 当最后一个虚拟触摸被销毁/抬起时，g_virtual_touch_count 变为 0，
 * hook 切换回 IN-PLACE 模式。此时用户后续的 UP 事件不再被拦截，
 * tvf_release_user 不会被调用，用户触摸对象会泄漏在 pool 中。
 *
 * 按状态分流，避免打断用户仍在进行中的真实触摸（不发 UP 帧）：
 * - ACTIVE（手指还在）：静默移交 —— 解除 output_slot 关联但不发
 *   UP 帧，系统继续跟踪该 slot；对象转 TVF_STATE_DETACH 保留
 *   real_slot 保护（虚拟触摸不会抢占），待用户真正抬起时由
 *   tvf_user_detach_cleanup 清理。之后硬件事件 IN-PLACE 直通，
 *   触摸无缝连续。
 * - INACTIVE/SUSPENDED（已抬起残留）：直接 pool_free 清理。
 */
static void tvf_purge_user_touches(void)
{
    int i;

    /* 快速检查是否有用户触摸对象 */
    {
        int has_user = 0;
        for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
            if (g_touch_pool[i].owner == TVF_OWNER_USER) {
                has_user = 1;
                break;
            }
        }
        if (!has_user) return;
    }

    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        TouchObject *o = &g_touch_pool[i];
        if (o->owner != TVF_OWNER_USER)
            continue;
        if (o->state == TVF_STATE_ACTIVE) {
            /* 手指还在：静默移交回硬件直通（不发 UP 帧） */
            int slot = o->output_slot;
            if (slot >= 0 && slot < MAX_OUTPUT_SLOTS &&
                g_output_slot_owner[slot] == i) {
                g_output_slot_owner[slot] = -1;   /* 解除 slot 关联 */
            }
            o->output_slot = -1;
            o->state = TVF_STATE_DETACH;
            kpm_log("kpm: tvf_purge: detach user slot=%d real=%d (finger still down)\n",
                    slot, o->real_slot);
        } else {
            /* 已抬起残留：直接清理 */
            pool_free(o);
        }
    }
}

/* 用户抬起时清理静默移交的 DETACH 用户触摸对象（防 pool 泄漏）。
 * hook 在 IN-PLACE 模式下检测 tracking_id==-1 时调用。 */
void tvf_user_detach_cleanup(int real_slot)
{
    TouchObject *obj;

    tvf_lock_nointr();
    obj = tvf_find_by_real_slot(real_slot);
    if (obj && obj->owner == TVF_OWNER_USER &&
        obj->state == TVF_STATE_DETACH) {
        pool_free(obj);
        kpm_log("kpm: tvf_detach_cleanup real_slot=%d obj freed\n", real_slot);
    }
    tvf_unlock_nointr();
}

/* ===== 触摸心跳保活 =====
 * 语义：
 *   - 客户端有触摸操作（CREATE/MOVE/UP/DESTROY 等任何触摸命令）即刷新
 *     保活时间戳 → 5 秒内还在操作就不需要发送专门 ping
 *   - 客户端空闲时（无操作）必须周期发 KEEPALIVE（≤5s 一次）；
 *     超过 5s 既无操作也无 ping → 视为客户端离线（崩溃/被杀/断网），
 *     自动销毁全部虚拟触摸并释放 USER 对象，关闭 CAPTURE 代理
 *   - UDP 与 prctl 双通道一致（统一走协议层 dispatch，触摸命令范围
 *     0x1020-0x102f 在 dispatch 入口统一刷新）
 * 性能：比较用 CNTPCT tick 差值（只读一次 MRS，无 64 位除法），
 * 无虚拟触摸时无锁快路径直接返回（不拿锁、不读时间戳）。 */
#define KPM_TOUCH_KEEPALIVE_TIMEOUT_MS 5000   /* 5s */

static uint64_t g_touch_last_ping_ticks = 0;
static uint64_t g_touch_cntfreq = 0;          /* 缓存频率（只读一次） */
static uint64_t g_touch_timeout_ticks = 0;    /* 缓存超时 tick 数 */

static inline uint64_t kpm_touch_ticks(void)
{
    uint64_t t;
    asm volatile("mrs %0, cntpct_el0" : "=r"(t));
    return t;
}

static uint64_t kpm_touch_timeout_ticks_get(void)
{
    if (g_touch_timeout_ticks == 0) {
        if (g_touch_cntfreq == 0)
            asm volatile("mrs %0, cntfrq_el0" : "=r"(g_touch_cntfreq));
        if (g_touch_cntfreq == 0)
            return 0;   /* 频率不可读：永不超时（保守） */
        g_touch_timeout_ticks = (g_touch_cntfreq *
                                 KPM_TOUCH_KEEPALIVE_TIMEOUT_MS) / 1000ULL;
    }
    return g_touch_timeout_ticks;
}

/* 持锁时调用：销毁全部虚拟触摸（发 UP 帧）+ 释放 USER 对象。
 * 调用方必须已持有 tvf_lock 或 tvf_lock_nointr。 */
static void tvf_destroy_all_locked(void)
{
    int i, any = 0;

    /* 先清 dirty（transaction_begin），随后 release 设 UP 标记——
     * 顺序与 touch_up 一致（begin 在 release 前，否则 UP 标记被抹掉，
     * commit 不发任何帧 = 设备残留活动触摸 slot）。 */
    tvf_transaction_begin();

    /* 1) 虚拟触摸：release slot（发 UP）+ 释放对象 */
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        TouchObject *o = &g_touch_pool[i];
        if (o->owner == TVF_OWNER_VIRTUAL && o->output_slot >= 0) {
            tvf_virtualizer_release(o);
            any = 1;
        }
    }
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        TouchObject *o = &g_touch_pool[i];
        if (o->owner == TVF_OWNER_VIRTUAL)
            pool_free(o);
    }

    /* 2) 用户触摸：静默移交回硬件直通（detach）或清理 */
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        TouchObject *o = &g_touch_pool[i];
        if (o->owner != TVF_OWNER_USER)
            continue;
        if (o->state == TVF_STATE_ACTIVE) {
            int slot = o->output_slot;
            if (slot >= 0 && slot < MAX_OUTPUT_SLOTS &&
                g_output_slot_owner[slot] == i)
                g_output_slot_owner[slot] = -1;
            o->output_slot = -1;
            o->state = TVF_STATE_DETACH;
        } else {
            pool_free(o);
        }
    }

    g_virtual_touch_count = 0;

    /* 客户端离线（心跳超时/卸载）时一并关闭 intercept——
     * "固定/偏移/镜像"用户触摸的拦截若残留，用户触摸会被永久改变。
     * kpm_intercept_stop 无锁纯状态清理，IRQ 上下文（nointr 锁内）安全。 */
    kpm_intercept_stop();

    /* 3) 提交 UP 帧（若有释放的 slot） */
    if (any) {
        /* 其他仍活动的对象（detach 前的 USER）保持输出 */
        for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
            TouchObject *o = &g_touch_pool[i];
            if (o->state == TVF_STATE_ACTIVE && o->output_slot >= 0) {
                tvf_transaction_update(o);
                o->dirty = 0;
            }
        }
        tvf_output_commit_frame();
    }
}

/* 客户端心跳：刷新保活时间戳（KEEPALIVE 命令入口 + 触摸命令范围统一刷新） */
void touch_keepalive(void)
{
    g_touch_last_ping_ticks = kpm_touch_ticks();
}

/* 检查并清理超时残留（process 上下文：UDP/命令路径调用）。
 * 返回 1 = 已清理。
 * 覆盖两类会话：①虚拟触摸（g_virtual_touch_count>0）②intercept 拦截
 * （g_intercept.enabled>0，固定/偏移/镜像用户触摸）——客户端离线（崩溃/
 * 断网）时都要自动恢复：销毁虚拟触摸 + 关闭拦截（用户触摸恢复原样）。
 * 性能：两者皆无时无锁快路径（volatile 读）；有才拿锁 + 读 tick。 */
int touch_purge_all_if_idle(void)
{
    uint64_t now, timeout_ticks;
    int cleaned = 0;

    if (g_virtual_touch_count <= 0 && !g_intercept.enabled)
        return 0;   /* 无虚拟触摸且无拦截：零开销快路径 */

    timeout_ticks = kpm_touch_timeout_ticks_get();
    if (timeout_ticks == 0)
        return 0;   /* 频率不可读：保守不超时 */

    tvf_lock();
    if (g_virtual_touch_count > 0 || g_intercept.enabled) {
        now = kpm_touch_ticks();
        if (g_touch_last_ping_ticks == 0 ||
            (now > g_touch_last_ping_ticks &&
             (now - g_touch_last_ping_ticks) > timeout_ticks)) {
            kpm_log("kpm: touch keepalive timeout, cleanup (virt=%d intercept=%d)\n",
                    g_virtual_touch_count, g_intercept.enabled);
            /* 销毁虚拟触摸（发 UP）+ 关闭 intercept（用户触摸恢复原样） */
            tvf_destroy_all_locked();
            cleaned = 1;
        }
    }
    tvf_unlock();
    return cleaned;
}

/* 无条件销毁全部（模块卸载用，发 UP 帧恢复设备干净） */
void kpm_touch_destroy_all(void)
{
    tvf_lock();
    if (g_virtual_touch_count > 0) {
        kpm_log("kpm: touch_destroy_all: destroying %d virtual touches\n",
                g_virtual_touch_count);
        tvf_destroy_all_locked();
    }
    tvf_unlock();
}

/* ===== Slot Virtualizer ===== */

/* Find the lowest priority object holding an output slot (for preemption) */
static int find_preempt_victim(int new_prio)
{
    int i;
    int victim_slot = -1;
    int lowest_prio = new_prio;  /* must be strictly lower priority (higher number) */

    for (i = 0; i < MAX_OUTPUT_SLOTS; i++) {
        int owner_idx = g_output_slot_owner[i];
        if (owner_idx < 0) continue;
        {
            TouchObject *o = &g_touch_pool[owner_idx];
            /* Can only preempt VIRTUAL or TAKEOVER objects, never USER */
            if (o->owner == TVF_OWNER_VIRTUAL || o->owner == TVF_OWNER_TAKEOVER) {
                if (o->priority > lowest_prio) {
                    lowest_prio = o->priority;
                    victim_slot = i;
                }
            }
        }
    }
    return victim_slot;
}

/* Suspend an object: release its output slot, mark for UP in frame */
static void suspend_object(TouchObject *obj)
{
    int slot = obj->output_slot;
    if (slot >= 0) {
        g_output_slot_owner[slot] = -1;
        tvf_transaction_release_slot(slot);
    }
    obj->output_slot = -1;
    obj->state = TVF_STATE_SUSPENDED;
    obj->dirty = 1;
    kpm_log("kpm: tvf suspend obj[%d] slot=%d prio=%d\n",
            (int)(obj - g_touch_pool), slot, obj->priority);
}

/* Check if a slot is claimed by a user touch (real_slot match).
 * Includes INACTIVE objects — real_slot stays reserved until pool_free()
 * clears it, preventing virtual touches from grabbing slots the hardware
 * is likely to reuse for new user touches. */
static int is_user_real_slot(int slot)
{
    int i;
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        TouchObject *o = &g_touch_pool[i];
        if (o->owner == TVF_OWNER_USER &&
            o->real_slot == slot)
            return 1;
    }
    return 0;
}

/* Find a free slot for a virtual touch, skipping user real_slots.
 * exclude_slot: slot being taken over (-1 = no exclusion) */
static int find_free_virtual_slot(int exclude_slot)
{
    int i;
    for (i = MAX_OUTPUT_SLOTS - 1; i >= 0; i--) {
        if (i == exclude_slot) continue;
        if (g_output_slot_owner[i] >= 0) continue;
        if (is_user_real_slot(i)) continue;
        return i;
    }
    return -1;
}

int tvf_virtualizer_acquire(TouchObject *obj)
{
    int victim_slot;

    /* User touches: output_slot = real_slot (direct mapping) */
    if (obj->owner == TVF_OWNER_USER) {
        int desired = obj->real_slot;
        if (desired < 0 || desired >= MAX_OUTPUT_SLOTS)
            return -1;

        /* Check if slot is free or held by a preemptable virtual */
        if (g_output_slot_owner[desired] >= 0) {
            int holder_idx = g_output_slot_owner[desired];
            TouchObject *holder = &g_touch_pool[holder_idx];
            if (holder->owner == TVF_OWNER_VIRTUAL ||
                holder->owner == TVF_OWNER_TAKEOVER) {
                /* Try to migrate the virtual touch to another free non-user slot */
                int new_slot = find_free_virtual_slot(desired);
                if (new_slot >= 0) {
                    /* Migrate: old slot UP + new slot DOWN in same frame */
                    g_output_slot_owner[new_slot] = holder_idx;
                    holder->output_slot = new_slot;
                    if (holder->owner == TVF_OWNER_VIRTUAL)
                        holder->tracking_id = tvf_next_tracking_id();
                    holder->dirty = 1;
                    /* Mark old slot as UP in transaction buffer */
                    tvf_transaction_release_slot(desired);
                    g_output_slot_owner[desired] = -1;
                    kpm_log("kpm: tvf migrate obj[%d] slot=%d->%d\n",
                            holder_idx, desired, new_slot);
                } else {
                    /* No free slot: suspend the virtual touch */
                    suspend_object(holder);
                }
            } else {
                /* Another user touch holds this slot — shouldn't happen */
                kpm_log("kpm: tvf slot conflict: real_slot=%d held by USER obj[%d]\n",
                        desired, holder_idx);
                return -1;
            }
        }
        g_output_slot_owner[desired] = (int)(obj - g_touch_pool);
        obj->output_slot = desired;
        obj->state = TVF_STATE_ACTIVE;
        obj->dirty = 1;
        return desired;
    }

    /* Virtual touches: find free slot that is NOT a user real_slot */
    {
        int slot = find_free_virtual_slot(-1);
        if (slot >= 0) {
            g_output_slot_owner[slot] = (int)(obj - g_touch_pool);
            obj->output_slot = slot;
            obj->state = TVF_STATE_ACTIVE;
            obj->dirty = 1;
            return slot;
        }
    }

    /* No free slot: try preemption based on policy */
    if (g_policy == TVF_POLICY_REAL_FIRST) {
        /* Discard virtual touch if no slot */
        obj->state = TVF_STATE_SUSPENDED;
        obj->output_slot = -1;
        kpm_log("kpm: tvf REAL_FIRST: virtual obj[%d] suspended (no slot)\n",
                (int)(obj - g_touch_pool));
        return -1;
    }

    if (g_policy == TVF_POLICY_AUTO || g_policy == TVF_POLICY_PRIORITY) {
        victim_slot = find_preempt_victim(obj->priority);
        if (victim_slot >= 0) {
            int victim_idx = g_output_slot_owner[victim_slot];
            TouchObject *victim = &g_touch_pool[victim_idx];
            suspend_object(victim);
            g_output_slot_owner[victim_slot] = (int)(obj - g_touch_pool);
            obj->output_slot = victim_slot;
            obj->state = TVF_STATE_ACTIVE;
            obj->dirty = 1;
            kpm_log("kpm: tvf preempt: obj[%d] took slot=%d from obj[%d]\n",
                    (int)(obj - g_touch_pool), victim_slot, victim_idx);
            return victim_slot;
        }
    }

    /* POLICY_CUSTOM or no preemption possible: suspend */
    obj->state = TVF_STATE_SUSPENDED;
    obj->output_slot = -1;
    kpm_log("kpm: tvf no slot for obj[%d] prio=%d, suspended\n",
            (int)(obj - g_touch_pool), obj->priority);
    return -1;
}

void tvf_virtualizer_release(TouchObject *obj)
{
    int slot = obj->output_slot;
    if (slot >= 0 && slot < MAX_OUTPUT_SLOTS) {
        if (g_output_slot_owner[slot] == (int)(obj - g_touch_pool)) {
            g_output_slot_owner[slot] = -1;
            tvf_transaction_release_slot(slot);
        }
    }
    obj->output_slot = -1;
    obj->dirty = 1;
}

void tvf_virtualizer_try_resume(void)
{
    int i;
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        TouchObject *obj = &g_touch_pool[i];
        if (obj->state == TVF_STATE_SUSPENDED && obj->owner != TVF_OWNER_FREE) {
            /* Find a free slot that is NOT a user real_slot */
            int slot = find_free_virtual_slot(-1);
            if (slot >= 0) {
                g_output_slot_owner[slot] = i;
                obj->output_slot = slot;
                obj->state = TVF_STATE_ACTIVE;
                /* Assign new tracking_id for resume (simulates new DOWN) */
                if (obj->owner == TVF_OWNER_VIRTUAL)
                    obj->tracking_id = tvf_next_tracking_id();
                obj->dirty = 1;
                kpm_log("kpm: tvf resume obj[%d] slot=%d tid=%d\n",
                        i, slot, obj->tracking_id);
            }
        }
    }
}

/* ===== Transaction Buffer ===== */

void tvf_transaction_begin(void)
{
    int i;
    for (i = 0; i < MAX_OUTPUT_SLOTS; i++) {
        g_pending_frame[i].dirty = 0;
    }
}

void tvf_transaction_update(TouchObject *obj)
{
    int slot = obj->output_slot;
    int has_pixel, has_raw;
    if (slot < 0 || slot >= MAX_OUTPUT_SLOTS)
        return;
    /* Skip objects with invalid coordinates (not yet positioned by touch_move)
     * raw 模式：x/y 可能为 -1，但 raw_x/raw_y 有效即可输出 */
    has_pixel = (obj->x >= 0 && obj->y >= 0);
    has_raw   = (obj->raw_x >= 0 && obj->raw_y >= 0);
    if (!has_pixel && !has_raw)
        return;
    g_pending_frame[slot].tracking_id = obj->tracking_id;
    g_pending_frame[slot].x = obj->x;
    g_pending_frame[slot].y = obj->y;
    g_pending_frame[slot].raw_x = obj->raw_x;
    g_pending_frame[slot].raw_y = obj->raw_y;
    g_pending_frame[slot].pressure = obj->pressure;
    g_pending_frame[slot].touch_major = obj->touch_major;
    g_pending_frame[slot].active = 1;
    g_pending_frame[slot].dirty = 1;
}

void tvf_transaction_release_slot(int slot)
{
    if (slot < 0 || slot >= MAX_OUTPUT_SLOTS)
        return;
    g_pending_frame[slot].active = 0;
    g_pending_frame[slot].tracking_id = -1;
    g_pending_frame[slot].dirty = 1;
}

/* ===== Scheduler ===== */

void tvf_scheduler_run(void)
{
    int i;
    int need_output = 0;

    tvf_transaction_begin();

    /* Phase 1: Process objects that need release (INACTIVE with slot) */
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        TouchObject *obj = &g_touch_pool[i];
        if (obj->owner == TVF_OWNER_FREE)
            continue;
        if (obj->state == TVF_STATE_INACTIVE && obj->output_slot >= 0) {
            tvf_virtualizer_release(obj);
            need_output = 1;
        }
    }

    /* Phase 2: Process objects that need acquire (ACTIVE without slot) */
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        TouchObject *obj = &g_touch_pool[i];
        if (obj->owner == TVF_OWNER_FREE)
            continue;
        if (obj->state == TVF_STATE_ACTIVE && obj->output_slot < 0) {
            if (tvf_virtualizer_acquire(obj) >= 0)
                need_output = 1;
        }
    }

    /* Phase 3: Try resume suspended objects */
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        TouchObject *obj = &g_touch_pool[i];
        if (obj->state == TVF_STATE_SUSPENDED && obj->owner != TVF_OWNER_FREE) {
            /* try_resume handles all suspended objects at once */
            break;
        }
    }
    tvf_virtualizer_try_resume();

    /* Phase 4: Update frame with all active objects */
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        TouchObject *obj = &g_touch_pool[i];
        if (obj->state == TVF_STATE_ACTIVE && obj->output_slot >= 0) {
            tvf_transaction_update(obj);
            if (obj->dirty) {
                need_output = 1;
                obj->dirty = 0;
            }
        }
    }

    /* Phase 5: Check if any slot is dirty */
    for (i = 0; i < MAX_OUTPUT_SLOTS; i++) {
        if (g_pending_frame[i].dirty) {
            need_output = 1;
            break;
        }
    }

    /* Phase 6: Commit frame */
    if (need_output)
        tvf_output_commit_frame();

    /* Phase 7: Free released objects (INACTIVE without slot) */
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        TouchObject *obj = &g_touch_pool[i];
        if (obj->owner != TVF_OWNER_FREE &&
            obj->state == TVF_STATE_INACTIVE &&
            obj->output_slot < 0) {
            /* Only free if not in animation */
            if (obj->anim_type == TVF_ANIM_NONE)
                pool_free(obj);
        }
    }
}

/* ===== Run frame (called on EV_SYN) ===== */
void tvf_run_frame(void)
{
    uint64_t timeout_ticks, now;

    tvf_lock_nointr();
    /* 心跳超时检查——客户端离线（崩溃/中断）残留的虚拟触摸
     * 在用户下一次触摸（EV_SYN）时立即销毁，恢复 IN-PLACE 直通。
     * 性能：仅当有虚拟触摸且频率可读时才读 tick（一次 MRS，无除法）。 */
    if (g_virtual_touch_count > 0 &&
        (timeout_ticks = kpm_touch_timeout_ticks_get()) != 0) {
        now = kpm_touch_ticks();
        if (g_touch_last_ping_ticks == 0 ||
            (now > g_touch_last_ping_ticks &&
             (now - g_touch_last_ping_ticks) > timeout_ticks)) {
            kpm_log("kpm: touch keepalive timeout (irq), destroying all\n");
            tvf_destroy_all_locked();
        }
    }
    tvf_scheduler_run();
    tvf_unlock_nointr();
}

/* ===== Input Capture (called by hook layer) ===== */

TouchObject *tvf_register_user(int real_slot, int tracking_id)
{
    TouchObject *obj;

    tvf_lock_nointr();

    /* Check if already registered (hardware may re-report) */
    obj = tvf_find_by_real_slot(real_slot);
    if (obj) {
        obj->tracking_id = tracking_id;
        obj->state = TVF_STATE_ACTIVE;
        obj->dirty = 1;
        /* Defensive: if output_slot was reassigned by scheduler, force re-acquire */
        if (obj->output_slot >= 0 &&
            g_output_slot_owner[obj->output_slot] != (int)(obj - g_touch_pool)) {
            obj->output_slot = -1;
        }
        tvf_unlock_nointr();
        return obj;
    }

    obj = pool_alloc();
    if (!obj) {
        tvf_unlock_nointr();
        kpm_log("kpm: tvf pool exhausted (register_user slot=%d)\n", real_slot);
        return NULL;
    }

    obj->id = (uint32_t)(obj - g_touch_pool) + 1;
    obj->owner = TVF_OWNER_USER;
    obj->state = TVF_STATE_ACTIVE;
    obj->priority = TVF_PRIO_USER;
    obj->real_slot = real_slot;
    obj->output_slot = -1;  /* scheduler will assign */
    obj->tracking_id = tracking_id;
    obj->x = -1;  /* invalid until first POSITION_X/Y */
    obj->y = -1;
    obj->raw_x = -1;  /* pool_alloc 复用对象不清字段，必须显式禁用 raw 模式，
                      * 否则残留旧 raw_x>=0 → 输出帧优先用残留 raw →
                      * 用户触摸点被固定/错位 */
    obj->raw_y = -1;
    obj->pressure = 30;   /* warm default, updated by hardware ABS_MT_PRESSURE */
    obj->touch_major = 10; /* typical finger contact area */
    obj->dirty = 1;
    obj->anim_type = TVF_ANIM_NONE;
    obj->cancel = 0;

    tvf_unlock_nointr();
    kpm_log("kpm: tvf register_user slot=%d tid=%d obj[%d]\n",
            real_slot, tracking_id, (int)(obj - g_touch_pool));
    return obj;
}

/* 返回是否找到 real_slot 对应的 USER 对象（1=是）。
 * hook 依赖此返回值决定 skip_origin：对象存在才拦截原事件（由池合并输出），
 * 对象不存在（手指 DOWN 早于 CAPTURE 开始，未注册）必须放行原事件，
 * 否则真实手指坐标被吞 → 屏幕触摸固定不动。 */
int tvf_update_user(int real_slot, int x, int y, int pressure, int touch_major)
{
    TouchObject *obj;
    int found = 0;

    tvf_lock_nointr();
    obj = tvf_find_by_real_slot(real_slot);
    if (!obj) {
        tvf_unlock_nointr();
        return 0;
    }
    found = 1;
    /* TAKEOVER: driver controls position, ignore hardware updates to prevent
     * the touch point from jumping between driver position and user finger. */
    if (obj->owner == TVF_OWNER_TAKEOVER) {
        tvf_unlock_nointr();
        return found;
    }
    if (x >= 0) obj->x = x;
    if (y >= 0) obj->y = y;
    if (pressure >= 0) obj->pressure = pressure;
    if (touch_major >= 0) obj->touch_major = touch_major;
    obj->dirty = 1;
    tvf_unlock_nointr();
    return found;
}

void tvf_release_user(int real_slot)
{
    TouchObject *obj;

    tvf_lock_nointr();
    obj = tvf_find_by_real_slot(real_slot);
    if (!obj) {
        tvf_unlock_nointr();
        return;
    }
    /* TAKEOVER: user lifted finger — convert to VIRTUAL so driver can keep
     * controlling the touch. Keep output_slot and tracking_id, only detach
     * from hardware real_slot. Driver ends via touch_up/touch_destroy. */
    if (obj->owner == TVF_OWNER_TAKEOVER) {
        obj->owner = TVF_OWNER_VIRTUAL;
        obj->real_slot = -1;
        tvf_unlock_nointr();
        kpm_log("kpm: tvf takeover->virtual obj[%d] slot=%d (user lifted)\n",
                (int)(obj - g_touch_pool), obj->output_slot);
        return;
    }
    obj->state = TVF_STATE_INACTIVE;
    obj->dirty = 1;
    kpm_log("kpm: tvf release_user slot=%d obj[%d]\n",
            real_slot, (int)(obj - g_touch_pool));
    tvf_unlock_nointr();
}

/* ===== TouchHandle API ===== */

TouchHandle touch_create(int priority, int touch_major, int pressure)
{
    TouchObject *obj;

    tvf_lock();
    obj = pool_alloc();
    if (!obj) {
        tvf_unlock();
        kpm_log("kpm: tvf pool exhausted (touch_create)\n");
        return TVF_INVALID_HANDLE;
    }

    obj->id = (uint32_t)(obj - g_touch_pool) + 1;
    obj->owner = TVF_OWNER_VIRTUAL;
    obj->state = TVF_STATE_ACTIVE;
    obj->priority = (uint8_t)priority;
    obj->real_slot = -1;
    obj->output_slot = -1;
    obj->tracking_id = tvf_next_tracking_id();
    obj->x = -1;  /* invalid until touch_move sets real coords */
    obj->y = -1;
    obj->raw_x = -1;  /* raw mode disabled by default */
    obj->raw_y = -1;
    obj->pressure = (pressure > 0) ? pressure : 30;
    obj->touch_major = (touch_major > 0) ? touch_major : 10;
    obj->dirty = 1;
    obj->anim_type = TVF_ANIM_NONE;
    obj->cancel = 0;

    /* Increment counter BEFORE unlock so the hook sees the update.
     * This counter is read lock-free in IRQ context by the input_handle_event
     * hook to decide between pass-through and capture mode. */
    g_virtual_touch_count++;

    /* 触摸会话建立，刷新保活时间戳（后续由操作/KEEPALIVE 维持） */
    g_touch_last_ping_ticks = kpm_touch_ticks();

    /* Try to acquire slot immediately, but do NOT output initial DOWN frame.
     * Coordinates are (-1,-1) = invalid. The first DOWN frame is sent when
     * touch_move() sets valid coordinates. This prevents a phantom touch
     * at (0,0) from appearing on screen. */
    if (tvf_virtualizer_acquire(obj) < 0) {
        /* Acquire failed — object unusable, undo counter and free */
        g_virtual_touch_count--;
        obj->owner = TVF_OWNER_FREE;
        tvf_unlock();
        kpm_log("kpm: touch_create acquire failed, pool exhausted\n");
        return TVF_INVALID_HANDLE;
    }

    tvf_unlock();

    kpm_log("kpm: touch_create obj[%d] prio=%d slot=%d tid=%d\n",
            (int)(obj - g_touch_pool), priority, obj->output_slot, obj->tracking_id);
    return (TouchHandle)(obj - g_touch_pool);
}

void touch_move(TouchHandle h, int x, int y)
{
    TouchObject *obj;

    tvf_lock();
    obj = tvf_get_object(h);
    if (!obj) {
        tvf_unlock();
        return;
    }
    if (obj->owner == TVF_OWNER_USER) {
        tvf_unlock();
        return;
    }
    obj->x = x;
    obj->y = y;
    obj->raw_x = -1;  /* 像素模式：禁用 raw（互斥） */
    obj->raw_y = -1;
    obj->dirty = 1;

    /* Output frame */
    tvf_transaction_begin();
    if (obj->state == TVF_STATE_ACTIVE && obj->output_slot >= 0)
        tvf_transaction_update(obj);
    /* Also update any other dirty objects */
    {
        int i;
        for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
            TouchObject *o = &g_touch_pool[i];
            if (o != obj && o->state == TVF_STATE_ACTIVE && o->output_slot >= 0 && o->dirty) {
                tvf_transaction_update(o);
                o->dirty = 0;
            }
        }
    }
    tvf_output_commit_frame();
    tvf_unlock();
}

/* raw 硬件坐标移动（1 raw = 1/scale 像素）。
 * 对象进入 raw 模式：输出帧直接透传 raw_x/raw_y，不 ×scale。
 * x/y 仅保留 raw/scale 取整近似供 get/getall 显示。 */
void touch_move_raw(TouchHandle h, int raw_x, int raw_y)
{
    TouchObject *obj;
    int scale;

    tvf_lock();
    obj = tvf_get_object(h);
    if (!obj) {
        tvf_unlock();
        return;
    }
    if (obj->owner == TVF_OWNER_USER) {
        tvf_unlock();
        return;
    }
    obj->raw_x = raw_x;
    obj->raw_y = raw_y;
    scale = kpm_touch_get_scale();
    if (scale <= 0) scale = 1;
    obj->x = (raw_x >= 0) ? (raw_x / scale) : -1;
    obj->y = (raw_y >= 0) ? (raw_y / scale) : -1;
    obj->dirty = 1;

    /* Output frame */
    tvf_transaction_begin();
    if (obj->state == TVF_STATE_ACTIVE && obj->output_slot >= 0)
        tvf_transaction_update(obj);
    /* Also update any other dirty objects */
    {
        int i;
        for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
            TouchObject *o = &g_touch_pool[i];
            if (o != obj && o->state == TVF_STATE_ACTIVE && o->output_slot >= 0 && o->dirty) {
                tvf_transaction_update(o);
                o->dirty = 0;
            }
        }
    }
    tvf_output_commit_frame();
    tvf_unlock();
}

void touch_up(TouchHandle h)
{
    TouchObject *obj;

    tvf_lock();
    obj = tvf_get_object(h);
    if (!obj) {
        tvf_unlock();
        return;
    }
    if (obj->owner == TVF_OWNER_USER) {
        tvf_unlock();
        return;
    }

    /* Mark for release: scheduler will output UP and free the slot */
    obj->state = TVF_STATE_INACTIVE;
    obj->dirty = 1;

    /* Output frame with UP event.
     * Order: begin (clear dirty) → release (set dirty=1 for UP) → update others */
    tvf_transaction_begin();
    tvf_virtualizer_release(obj);
    /* Update other active objects */
    {
        int i;
        for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
            TouchObject *o = &g_touch_pool[i];
            if (o->state == TVF_STATE_ACTIVE && o->output_slot >= 0) {
                tvf_transaction_update(o);
                o->dirty = 0;
            }
        }
    }
    tvf_output_commit_frame();

    /* Free the object */
    pool_free(obj);

    /* Decrement counter AFTER pool_free, BEFORE unlock */
    g_virtual_touch_count--;
    if (g_virtual_touch_count <= 0) {
        /* 最后一个虚拟触摸已抬起，CAPTURE 模式将关闭。
         * 强制释放所有用户触摸对象，防止泄漏 */
        g_virtual_touch_count = 0;
        tvf_purge_user_touches();
    }

    tvf_unlock();
    kpm_log("kpm: touch_up handle=%d\n", h);
}

void touch_destroy(TouchHandle h)
{
    TouchObject *obj;

    tvf_lock();
    obj = tvf_get_object(h);
    if (!obj) {
        tvf_unlock();
        return;
    }
    if (obj->owner == TVF_OWNER_USER) {
        tvf_unlock();
        return;
    }

    /* Cancel animation if running */
    if (obj->anim_type != TVF_ANIM_NONE) {
        obj->cancel = 1;
        /* Can't wait for animation to stop here (we hold the lock).
         * The animation loop checks cancel and will exit. */
    }

    /* Release slot with UP event if active.
     * Order matters: transaction_begin (clears dirty) MUST come before
     * virtualizer_release (sets dirty=1 for UP). Otherwise begin clears
     * the UP marker and the event is never sent. */
    if (obj->output_slot >= 0) {
        tvf_transaction_begin();
        tvf_virtualizer_release(obj);
        {
            int i;
            for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
                TouchObject *o = &g_touch_pool[i];
                if (o != obj && o->state == TVF_STATE_ACTIVE && o->output_slot >= 0) {
                    tvf_transaction_update(o);
                    o->dirty = 0;
                }
            }
        }
        tvf_output_commit_frame();
    }

    pool_free(obj);

    /* Decrement counter AFTER pool_free, BEFORE unlock.
     * This ensures the hook sees the correct count when it checks
     * g_virtual_touch_count in the next EV_SYN. */
    g_virtual_touch_count--;
    if (g_virtual_touch_count <= 0) {
        /* 最后一个虚拟触摸已销毁，CAPTURE 模式将关闭。
         * 强制释放所有用户触摸对象，防止泄漏 */
        g_virtual_touch_count = 0;
        tvf_purge_user_touches();
    }

    tvf_unlock();
    kpm_log("kpm: touch_destroy handle=%d\n", h);
}

long touch_takeover(TouchHandle h, int real_tracking_id)
{
    TouchObject *obj;
    TouchObject *victim;
    int i;
    int victim_slot;

    tvf_lock();
    obj = tvf_get_object(h);
    if (!obj) {
        tvf_unlock();
        return -KPM_E_INVAL;
    }

    /* Find the user touch with matching tracking_id */
    victim = NULL;
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        if (g_touch_pool[i].owner == TVF_OWNER_USER &&
            g_touch_pool[i].tracking_id == real_tracking_id) {
            victim = &g_touch_pool[i];
            break;
        }
    }
    if (!victim) {
        tvf_unlock();
        return -KPM_E_NOTFOUND;
    }

    /* Release obj's old output_slot (if any) to avoid slot leak */
    if (obj->output_slot >= 0 && obj->output_slot != victim->output_slot) {
        tvf_virtualizer_release(obj);  /* old slot marked UP */
    }

    /* Copy coordinates from victim */
    obj->x = victim->x;
    obj->y = victim->y;
    obj->raw_x = -1;  /* TAKEOVER 用像素坐标，清 raw 防残留 */
    obj->raw_y = -1;
    obj->pressure = victim->pressure;
    obj->touch_major = victim->touch_major;
    obj->real_slot = victim->real_slot;  /* share the real slot for hook routing */
    obj->owner = TVF_OWNER_TAKEOVER;
    obj->dirty = 1;

    /* Take over the victim's output_slot */
    victim_slot = victim->output_slot;
    if (victim_slot >= 0) {
        g_output_slot_owner[victim_slot] = (int)(obj - g_touch_pool);
        obj->output_slot = victim_slot;
        obj->state = TVF_STATE_ACTIVE;
    }

    /* Inherit victim's tracking_id for seamless takeover (avoids
     * UP+DOWN flicker caused by tracking_id change on the output slot),
     * then free the victim. pool_free prevents tvf_virtualizer_try_resume
     * from resuming the victim to another slot (which would create a
     * second visible touch point). */
    obj->tracking_id = victim->tracking_id;
    pool_free(victim);

    /* Output frame: old slot UP + takeover slot MOVE */
    tvf_transaction_begin();
    if (obj->state == TVF_STATE_ACTIVE && obj->output_slot >= 0)
        tvf_transaction_update(obj);
    {
        for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
            TouchObject *o = &g_touch_pool[i];
            if (o != obj && o->state == TVF_STATE_ACTIVE && o->output_slot >= 0 && o->dirty) {
                tvf_transaction_update(o);
                o->dirty = 0;
            }
        }
    }
    tvf_output_commit_frame();

    tvf_unlock();
    kpm_log("kpm: touch_takeover handle=%d tid=%d slot=%d\n",
            h, real_tracking_id, obj->output_slot);
    return 0;
}

void touch_suspend(TouchHandle h)
{
    TouchObject *obj;

    tvf_lock();
    obj = tvf_get_object(h);
    if (!obj) {
        tvf_unlock();
        return;
    }
    if (obj->owner == TVF_OWNER_USER) {
        tvf_unlock();
        return;
    }
    if (obj->state == TVF_STATE_ACTIVE && obj->output_slot >= 0) {
        tvf_transaction_begin();
        suspend_object(obj);
        {
            int i;
            for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
                TouchObject *o = &g_touch_pool[i];
                if (o->state == TVF_STATE_ACTIVE && o->output_slot >= 0) {
                    tvf_transaction_update(o);
                    o->dirty = 0;
                }
            }
        }
        tvf_output_commit_frame();
    }
    tvf_unlock();
    kpm_log("kpm: touch_suspend handle=%d\n", h);
}

void touch_resume(TouchHandle h)
{
    TouchObject *obj;

    tvf_lock();
    obj = tvf_get_object(h);
    if (!obj) {
        tvf_unlock();
        return;
    }
    if (obj->owner == TVF_OWNER_USER) {
        tvf_unlock();
        return;
    }
    if (obj->state == TVF_STATE_SUSPENDED) {
        /* Assign new tracking_id for resume (new DOWN sequence) */
        if (obj->owner == TVF_OWNER_VIRTUAL || obj->owner == TVF_OWNER_TAKEOVER)
            obj->tracking_id = tvf_next_tracking_id();
        obj->state = TVF_STATE_ACTIVE;
        obj->dirty = 1;
        /* Output frame.
         * Order: begin (clear dirty) → acquire (may preempt, set victim dirty)
         * → update active objects → commit */
        tvf_transaction_begin();
        tvf_virtualizer_acquire(obj);
        {
            int i;
            for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
                TouchObject *o = &g_touch_pool[i];
                if (o->state == TVF_STATE_ACTIVE && o->output_slot >= 0) {
                    tvf_transaction_update(o);
                    o->dirty = 0;
                }
            }
        }
        tvf_output_commit_frame();
    }
    tvf_unlock();
    kpm_log("kpm: touch_resume handle=%d slot=%d\n", h, obj->output_slot);
}

int touch_is_active(TouchHandle h)
{
    TouchObject *obj;
    int active;
    tvf_lock();
    obj = tvf_get_object(h);
    active = obj ? (obj->state == TVF_STATE_ACTIVE) : 0;
    tvf_unlock();
    return active;
}

/* ===== Animation helpers ===== */

/* 等待当前动画结束。调用方必须已持有 tvf_lock。
 * 不能在持锁下忙等——动画循环（touch_move_to 内部）每步需要
 * tvf_lock（unlock→delay→lock），持锁等待会导致两个并发 touch_move_to
 * 同一 handle 死锁。设置 cancel 后释放锁轮询，期间用 saved_id 校验
 * 对象未被销毁/复用（池对象可被并发释放）。
 * 返回时重新持有 tvf_lock；返回 0 后调用方必须重新 tvf_get_object(h)
 * 校验（obj 可能在等待期间被销毁/复用）。 */
static long wait_anim(TouchHandle h, TouchObject *obj, int allow_interrupt)
{
    uint32_t saved_id;
    int wait_us = 0;

    if (obj->anim_type == TVF_ANIM_NONE)
        return 0;
    if (!allow_interrupt)
        return -KPM_E_PERM;

    saved_id = obj->id;
    obj->cancel = 1;
    for (;;) {
        TouchObject *o;
        tvf_unlock();
        kpm_udelay_range(50, 100);
        wait_us += 100;
        tvf_lock();
        o = tvf_get_object(h);
        if (!o || o->owner == TVF_OWNER_FREE || o->id != saved_id)
            return 0;   /* 动画对象已销毁/复用：无需等待 */
        if (o->anim_type == TVF_ANIM_NONE)
            return 0;
        if (wait_us > 200000) {
            o->anim_type = TVF_ANIM_NONE;   /* 超时强制终止 */
            return 0;
        }
    }
}

long touch_move_to(TouchHandle h, int target_x, int target_y,
                   int touch_major, int pressure,
                   int duration_ms, int allow_interrupt)
{
    TouchObject *obj;
    int start_x, start_y;
    int steps, i;
    int interval_us;
    long ret;

    tvf_lock();
    obj = tvf_get_object(h);
    if (!obj) {
        tvf_unlock();
        return -KPM_E_INVAL;
    }
    if (obj->owner == TVF_OWNER_USER) {
        tvf_unlock();
        return -KPM_E_PERM;
    }
    if (obj->state == TVF_STATE_SUSPENDED) {
        tvf_unlock();
        return -KPM_E_NOTFOUND;
    }

    ret = wait_anim(h, obj, allow_interrupt);
    if (ret) {
        tvf_unlock();
        return ret;
    }
    /* wait_anim 释放过锁，对象可能被销毁/复用——重新获取校验 */
    obj = tvf_get_object(h);
    if (!obj || obj->owner == TVF_OWNER_FREE) {
        tvf_unlock();
        return -KPM_E_NOTFOUND;
    }

    start_x = obj->x;
    start_y = obj->y;
    /* If no valid start coords (touch_create without touch_move), use target */
    if (start_x < 0) start_x = target_x;
    if (start_y < 0) start_y = target_y;

    /* Instant move */
    if (duration_ms <= 0) {
        obj->x = target_x;
        obj->y = target_y;
        obj->raw_x = -1;  /* 像素模式：禁用 raw */
        obj->raw_y = -1;
        if (touch_major > 0) obj->touch_major = touch_major;
        if (pressure > 0) obj->pressure = pressure;  /* 0 = not specified, keep default */
        obj->dirty = 1;
        /* Output frame */
        tvf_transaction_begin();
        if (obj->state == TVF_STATE_ACTIVE && obj->output_slot >= 0)
            tvf_transaction_update(obj);
        tvf_output_commit_frame();
        tvf_unlock();
        return 0;
    }

    obj->anim_type = TVF_ANIM_MOVE_TO;
    obj->cancel = 0;
    obj->allow_interrupt = allow_interrupt;
    tvf_unlock();

    /* Linear interpolation animation */
    steps = duration_ms / 10;
    if (steps < 2) steps = 2;
    if (steps > 200) steps = 200;
    interval_us = (duration_ms * 1000) / steps;
    /* 单步间隔夹紧：steps 有上限但 interval 会随 duration 线性放大
     * （duration=10min → 单步约 3s），使 obj->cancel 的响应时间失去
     * 上界。卸载时排空窗口内动画仍在取指 → .text 释放后 UAF。
     * 夹到 50ms 后，无论 duration 多大，取消/排空都在 50ms 内收敛。 */
    if (interval_us > KPM_TOUCH_ANIM_MAX_STEP_US)
        interval_us = KPM_TOUCH_ANIM_MAX_STEP_US;
    if (interval_us < 2000) interval_us = 2000;

    for (i = 1; i <= steps; i++) {
        int cx, cy;
        uint32_t saved_id;

        /* Save object ID before releasing lock — after kpm_udelay_range
         * another thread may have freed and re-allocated the slot. */
        saved_id = obj->id;
        tvf_unlock();

        kpm_udelay_range(interval_us - 1000, interval_us + 1000);

        tvf_lock();
        obj = tvf_get_object(h);
        /* Verify: (1) object exists, (2) not freed, (3) same object (not re-allocated) */
        if (!obj || obj->owner == TVF_OWNER_FREE || obj->id != saved_id) {
            tvf_unlock();
            if (obj && obj->id != saved_id)
                kpm_log("kpm: moveto anim slot reused, aborting\n");
            return -KPM_E_NOTFOUND;
        }
        if (obj->cancel) {
            obj->cancel = 0;
            obj->anim_type = TVF_ANIM_NONE;
            tvf_unlock();
            return 1;
        }

        cx = start_x + (target_x - start_x) * i / steps;
        cy = start_y + (target_y - start_y) * i / steps;
        obj->x = cx;
        obj->y = cy;
        obj->raw_x = -1;
        obj->raw_y = -1;
        if (touch_major > 0) obj->touch_major = touch_major;
        if (pressure > 0) obj->pressure = pressure;  /* 0 = not specified */
        obj->dirty = 1;

        tvf_transaction_begin();
        if (obj->state == TVF_STATE_ACTIVE && obj->output_slot >= 0)
            tvf_transaction_update(obj);
        tvf_output_commit_frame();
        tvf_unlock();
    }

    /* Ensure target reached */
    tvf_lock();
    obj = tvf_get_object(h);
    if (obj) {
        obj->x = target_x;
        obj->y = target_y;
        obj->raw_x = -1;
        obj->raw_y = -1;
        if (touch_major > 0) obj->touch_major = touch_major;
        if (pressure > 0) obj->pressure = pressure;  /* 0 = not specified, keep default */
        obj->anim_type = TVF_ANIM_NONE;
    }
    tvf_unlock();
    return 0;
}

/* raw 域动画移动（插值在 raw 坐标进行，
 * 终点/每帧坐标均为硬件最小单位，不受 scale 量化网格限制）。 */
long touch_move_to_raw(TouchHandle h, int target_raw_x, int target_raw_y,
                       int touch_major, int pressure,
                       int duration_ms, int allow_interrupt)
{
    TouchObject *obj;
    int start_raw_x, start_raw_y;
    int steps, i;
    int interval_us;
    int scale;
    long ret;

    tvf_lock();
    obj = tvf_get_object(h);
    if (!obj) {
        tvf_unlock();
        return -KPM_E_INVAL;
    }
    if (obj->owner == TVF_OWNER_USER) {
        tvf_unlock();
        return -KPM_E_PERM;
    }
    if (obj->state == TVF_STATE_SUSPENDED) {
        tvf_unlock();
        return -KPM_E_NOTFOUND;
    }

    ret = wait_anim(h, obj, allow_interrupt);
    if (ret) {
        tvf_unlock();
        return ret;
    }
    /* wait_anim 释放过锁，对象可能被销毁/复用——重新获取校验 */
    obj = tvf_get_object(h);
    if (!obj || obj->owner == TVF_OWNER_FREE) {
        tvf_unlock();
        return -KPM_E_NOTFOUND;
    }

    start_raw_x = (obj->raw_x >= 0) ? obj->raw_x : obj->x * kpm_touch_get_scale();
    start_raw_y = (obj->raw_y >= 0) ? obj->raw_y : obj->y * kpm_touch_get_scale();
    if (start_raw_x < 0) start_raw_x = target_raw_x;
    if (start_raw_y < 0) start_raw_y = target_raw_y;
    scale = kpm_touch_get_scale();
    if (scale <= 0) scale = 1;

    /* Instant move */
    if (duration_ms <= 0) {
        obj->raw_x = target_raw_x;
        obj->raw_y = target_raw_y;
        obj->x = target_raw_x / scale;   /* 显示近似 */
        obj->y = target_raw_y / scale;
        if (touch_major > 0) obj->touch_major = touch_major;
        if (pressure > 0) obj->pressure = pressure;
        obj->dirty = 1;
        /* Output frame */
        tvf_transaction_begin();
        if (obj->state == TVF_STATE_ACTIVE && obj->output_slot >= 0)
            tvf_transaction_update(obj);
        tvf_output_commit_frame();
        tvf_unlock();
        return 0;
    }

    obj->anim_type = TVF_ANIM_MOVE_TO;
    obj->cancel = 0;
    obj->allow_interrupt = allow_interrupt;
    tvf_unlock();

    /* Linear interpolation in raw domain */
    steps = duration_ms / 10;
    if (steps < 2) steps = 2;
    if (steps > 200) steps = 200;
    interval_us = (duration_ms * 1000) / steps;
    /* 单步间隔夹紧：同 touch_move_to 的处理，
     * 保证取消响应与卸载排空窗口都有上界。 */
    if (interval_us > KPM_TOUCH_ANIM_MAX_STEP_US)
        interval_us = KPM_TOUCH_ANIM_MAX_STEP_US;
    if (interval_us < 2000) interval_us = 2000;

    for (i = 1; i <= steps; i++) {
        int crx, cry;
        uint32_t saved_id;

        saved_id = obj->id;
        tvf_unlock();

        kpm_udelay_range(interval_us - 1000, interval_us + 1000);

        tvf_lock();
        obj = tvf_get_object(h);
        if (!obj || obj->owner == TVF_OWNER_FREE || obj->id != saved_id) {
            tvf_unlock();
            if (obj && obj->id != saved_id)
                kpm_log("kpm: moveto_raw anim slot reused, aborting\n");
            return -KPM_E_NOTFOUND;
        }
        if (obj->cancel) {
            obj->cancel = 0;
            obj->anim_type = TVF_ANIM_NONE;
            tvf_unlock();
            return 1;
        }

        crx = start_raw_x + (target_raw_x - start_raw_x) * i / steps;
        cry = start_raw_y + (target_raw_y - start_raw_y) * i / steps;
        obj->raw_x = crx;
        obj->raw_y = cry;
        obj->x = crx / scale;
        obj->y = cry / scale;
        if (touch_major > 0) obj->touch_major = touch_major;
        if (pressure > 0) obj->pressure = pressure;
        obj->dirty = 1;

        tvf_transaction_begin();
        if (obj->state == TVF_STATE_ACTIVE && obj->output_slot >= 0)
            tvf_transaction_update(obj);
        tvf_output_commit_frame();
        tvf_unlock();
    }

    /* Ensure target reached */
    tvf_lock();
    obj = tvf_get_object(h);
    if (obj) {
        obj->raw_x = target_raw_x;
        obj->raw_y = target_raw_y;
        obj->x = target_raw_x / scale;
        obj->y = target_raw_y / scale;
        if (touch_major > 0) obj->touch_major = touch_major;
        if (pressure > 0) obj->pressure = pressure;
        obj->anim_type = TVF_ANIM_NONE;
    }
    tvf_unlock();
    return 0;
}

long touch_move_dir(TouchHandle h, int dx, int dy,
                    int touch_major, int pressure,
                    int duration_ms, int allow_interrupt)
{
    TouchObject *obj;
    int target_x, target_y;
    long ret;

    tvf_lock();
    obj = tvf_get_object(h);
    if (!obj) {
        tvf_unlock();
        return -KPM_E_INVAL;
    }
    if (obj->owner == TVF_OWNER_USER) {
        tvf_unlock();
        return -KPM_E_PERM;
    }

    ret = wait_anim(h, obj, allow_interrupt);
    if (ret) {
        tvf_unlock();
        return ret;
    }
    /* wait_anim 释放过锁，对象可能被销毁/复用——重新获取校验 */
    obj = tvf_get_object(h);
    if (!obj || obj->owner == TVF_OWNER_FREE) {
        tvf_unlock();
        return -KPM_E_NOTFOUND;
    }

    target_x = obj->x + dx;
    target_y = obj->y + dy;

    /* If duration specified, use animated move via touch_move_to which
     * already has ID-verified loop and unlock/lock safety. */
    if (duration_ms > 0) {
        tvf_unlock();
        return touch_move_to(h, target_x, target_y,
                             touch_major, pressure,
                             duration_ms, allow_interrupt);
    }

    /* Instant move (duration_ms == 0) */
    obj->x = target_x;
    obj->y = target_y;
    obj->raw_x = -1;  /* 像素模式：禁用 raw */
    obj->raw_y = -1;
    if (touch_major > 0) obj->touch_major = touch_major;
    if (pressure > 0) obj->pressure = pressure;
    obj->dirty = 1;

    tvf_transaction_begin();
    if (obj->state == TVF_STATE_ACTIVE && obj->output_slot >= 0)
        tvf_transaction_update(obj);
    tvf_output_commit_frame();
    tvf_unlock();
    return 0;
}

/* raw 域增量移动（delta 为硬件最小单位）。 */
long touch_move_dir_raw(TouchHandle h, int dx_raw, int dy_raw,
                        int touch_major, int pressure,
                        int duration_ms, int allow_interrupt)
{
    TouchObject *obj;
    int target_raw_x, target_raw_y;
    int scale;
    long ret;

    tvf_lock();
    obj = tvf_get_object(h);
    if (!obj) {
        tvf_unlock();
        return -KPM_E_INVAL;
    }
    if (obj->owner == TVF_OWNER_USER) {
        tvf_unlock();
        return -KPM_E_PERM;
    }

    ret = wait_anim(h, obj, allow_interrupt);
    if (ret) {
        tvf_unlock();
        return ret;
    }
    /* wait_anim 释放过锁，对象可能被销毁/复用——重新获取校验 */
    obj = tvf_get_object(h);
    if (!obj || obj->owner == TVF_OWNER_FREE) {
        tvf_unlock();
        return -KPM_E_NOTFOUND;
    }

    scale = kpm_touch_get_scale();
    if (scale <= 0) scale = 1;
    target_raw_x = (obj->raw_x >= 0) ? obj->raw_x + dx_raw
                                     : obj->x * scale + dx_raw;
    target_raw_y = (obj->raw_y >= 0) ? obj->raw_y + dy_raw
                                     : obj->y * scale + dy_raw;

    /* If duration specified, use animated move via touch_move_to_raw which
     * already has ID-verified loop and unlock/lock safety. */
    if (duration_ms > 0) {
        tvf_unlock();
        return touch_move_to_raw(h, target_raw_x, target_raw_y,
                                 touch_major, pressure,
                                 duration_ms, allow_interrupt);
    }

    /* Instant move (duration_ms == 0) */
    obj->raw_x = target_raw_x;
    obj->raw_y = target_raw_y;
    obj->x = target_raw_x / scale;   /* 显示近似 */
    obj->y = target_raw_y / scale;
    if (touch_major > 0) obj->touch_major = touch_major;
    if (pressure > 0) obj->pressure = pressure;
    obj->dirty = 1;

    tvf_transaction_begin();
    if (obj->state == TVF_STATE_ACTIVE && obj->output_slot >= 0)
        tvf_transaction_update(obj);
    tvf_output_commit_frame();
    tvf_unlock();
    return 0;
}

void touch_cancel_anim(TouchHandle h)
{
    TouchObject *obj;
    tvf_lock();
    obj = tvf_get_object(h);
    if (obj && obj->anim_type != TVF_ANIM_NONE) {
        obj->cancel = 1;
        while (obj->anim_type != TVF_ANIM_NONE) {
            tvf_unlock();
            kpm_udelay_range(50, 100);
            tvf_lock();
            obj = tvf_get_object(h);
            if (!obj) break;
        }
    }
    tvf_unlock();
}

/* 给全部在进行中的动画打上 cancel 标志（不等待）。
 * 卸载路径必须在 drain/hook 拆除之前调用本函数，否则动画（在
 * prctl/UDP 命令回调内忙等）会一路跑到 drain 超时被放行 → 模块
 * .text 释放而动画仍在取指 → UAF panic。
 * 不等待是刻意的：本函数在卸载上下文被调用，等待会与"谁先拿到 tvf_lock"
 * 纠缠；打标志后由动画循环自己在回锁后检查（每步都查，且单步 ≤50ms），
 * 后续的 inflight drain 自然能在预算内归零。 */
void touch_cancel_all(void)
{
    int i;
    int n = 0;

    tvf_lock();
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        TouchObject *obj = &g_touch_pool[i];

        if (obj->owner == TVF_OWNER_FREE)
            continue;
        if (obj->anim_type != TVF_ANIM_NONE) {
            obj->cancel = 1;
            n++;
        }
    }
    tvf_unlock();

    if (n)
        kpm_log("kpm: touch_cancel_all: cancelled %d animating object(s)\n", n);
}

/* ===== Query API ===== */

long touch_get_info(TouchHandle h, kpm_touch_info_t *info)
{
    TouchObject *obj;
    long ret = 0;

    if (!info) return -KPM_E_INVAL;

    tvf_lock();
    obj = tvf_get_object(h);
    if (!obj || obj->state == TVF_STATE_INACTIVE) {
        tvf_unlock();
        return -KPM_E_NOTFOUND;
    }

    /* Skip if coordinates not yet valid */
    if (obj->x < 0 || obj->y < 0) {
        tvf_unlock();
        return -KPM_E_NOTFOUND;
    }

    info->x = (int16_t)obj->x;
    info->y = (int16_t)obj->y;
    info->touch_major = (uint8_t)obj->touch_major;
    info->pressure = (uint8_t)obj->pressure;
    info->is_user = (obj->owner == TVF_OWNER_USER) ? 1 : 0;
    info->handle = (uint8_t)h;
    tvf_unlock();
    return ret;
}

long touch_get_all_info(kpm_touch_info_t *infos, int max_count)
{
    int i, count = 0;

    if (!infos || max_count <= 0) return -KPM_E_INVAL;

    tvf_lock();
    for (i = 0; i < MAX_TOUCH_OBJECTS && count < max_count; i++) {
        TouchObject *obj = &g_touch_pool[i];
        if (obj->owner == TVF_OWNER_FREE)
            continue;
        if (obj->state != TVF_STATE_ACTIVE)
            continue;
        if (obj->x < 0 || obj->y < 0)
            continue;
        infos[count].x = (int16_t)obj->x;
        infos[count].y = (int16_t)obj->y;
        infos[count].touch_major = (uint8_t)obj->touch_major;
        infos[count].pressure = (uint8_t)obj->pressure;
        infos[count].is_user = (obj->owner == TVF_OWNER_USER) ? 1 : 0;
        infos[count].handle = (uint8_t)i;
        count++;
    }
    tvf_unlock();
    return (long)count;
}

int touch_get_active_count(void)
{
    int i, count = 0;
    tvf_lock();
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        /* 池内只统计 VIRTUAL 对象；真实手指数由
         * kpm_intercept_count_real_fingers() 叠加（覆盖 IN-PLACE 与
         * CAPTURE 两种模式，避免 CAPTURE 下已注册 USER 对象重复计数）。 */
        if (g_touch_pool[i].owner == TVF_OWNER_VIRTUAL &&
            g_touch_pool[i].state == TVF_STATE_ACTIVE)
            count++;
    }
    tvf_unlock();
    count += kpm_intercept_count_real_fingers();
    return count;
}

/* ===== Policy ===== */

void touch_set_policy(int policy)
{
    tvf_lock();
    g_policy = policy;
    tvf_unlock();
    kpm_log("kpm: tvf policy set to %d\n", policy);
}

int touch_get_policy(void)
{
    return g_policy;
}

long touch_set_params(TouchHandle h, int touch_major, int pressure, int mask)
{
    TouchObject *obj;

    if (h < 0 || h >= MAX_TOUCH_OBJECTS) {
        return -1;
    }

    tvf_lock();
    obj = tvf_get_object(h);
    if (!obj || obj->owner != TVF_OWNER_VIRTUAL) {
        tvf_unlock();
        return -1;
    }

    if (mask & 0x01) {
        obj->touch_major = (touch_major > 0) ? touch_major : 10;
    }
    if (mask & 0x02) {
        obj->pressure = (pressure > 0) ? pressure : 30;
    }
    obj->dirty = 1;

    /* Commit updated params inside the lock — obj must not be accessed
     * after tvf_unlock() because another thread may free it. */
    tvf_transaction_begin();
    if (obj->state == TVF_STATE_ACTIVE && obj->output_slot >= 0) {
        tvf_transaction_update(obj);
    }
    tvf_unlock();
    tvf_output_commit_frame();

    return 0;
}
