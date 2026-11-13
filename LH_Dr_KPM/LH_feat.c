/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_feat.c - 功能单元注册表实现
 *
 * 并发模型：管理操作（enable/disable/list）极低频，用一把 irqsave 自旋锁
 * 保护注册表元数据；init/exit 可睡眠（vmalloc/摘 hook/RCU 排空），一律在
 * 锁外执行，锁内仅做状态迁移（UNINIT/OK/DEGRADED ↔ TRANSITION）。
 * TRANSITION 状态对 kpm_feat_enabled() 门是不可见的（视为未启用）——
 * 命令门控不等待管理操作完成，避免 recv_work 被长 init 阻塞。
 */
#include <compiler.h>
#include <linux/string.h>
#include <baselib.h>
#include "LH_feat.h"
#include "LH_utils.h"
#include "LH_log.h"

typedef struct {
    const char      *name;
    kpm_feat_ops_t   ops;        /* init/exit/pre_exit（可空=未实现/未编译） */
    uint32_t         dep_mask;   /* 位 i = 依赖 KPM_FEAT_i */
    uint32_t         state_bit;  /* KPM_STATE_* 联动位（0=不联动） */
    uint32_t         reason;     /* 最近一次 enable 的失败/降级原因（FEAT_LIST） */
    uint8_t          state;      /* KPM_FEATST_* */
    uint8_t          cap;        /* KPM_FEATCAP_* */
    uint8_t          core;       /* 1=核心通道，FEAT_DISABLE 拒绝 */
    uint8_t          registered;
} kpm_feat_unit_t;

static kpm_feat_unit_t g_units[KPM_FEAT_MAX];
static kpm_spinlock_t g_feat_lock = KPM_SPINLOCK_INIT;
static int g_feat_ready;

/* ===== 卸载序列（显式声明，与单元 id 数值无关） =====
 * 注册表按 id 索引存储，卸载顺序若按 id 逆序会违反拆卸约束
 * （如 touch 释放跑到 prctl 排空之前 → 卸载 UAF），故顺序在此
 * 显式列出，disable_all 两阶段均按本序列遍历：
 *   exit 顺序 = 事件产生端（新功能单元/陀螺仪）→ 命令通道
 *   （prctl 排空 → UDP 拆除）→ 数据面（mem_rw/proc/hide/dump/scan）；
 *   pre_exit 阶段顺序 = 本序列正序（pass1 整体先于 pass2，位置只影响
 *   产生端之间的相对顺序：触摸取消最先、扫描中止随后）。
 * prctl 排空须先于 touch 释放、断点 disarm 须先于 UDP 拆除、
 * 扫描中止（pre_exit）须先于 UDP 拆除，否则分别会引发卸载 UAF、
 * TOCTOU 竞态或 flush 卡死。 */
static const uint8_t k_teardown_order[KPM_FEAT_MAX] = {
    KPM_FEAT_WXSHADOW,     /* 先恢复 PTE / 摘 BRK+fault hook */
    KPM_FEAT_TRACE,        /* 先摘 tracepoint / kfunc hook */
    KPM_FEAT_MEMWATCH,     /* 先恢复 PTE / 摘 do_mem_abort hook */
    KPM_FEAT_RESCTL,       /* 频率/亲和性规则先清（无依赖） */
    KPM_FEAT_SYSMON,       /* 摘 syscall/ioctl 监控 hook */
    KPM_FEAT_NETCTL,       /* 摘网络拦截 hook */
    KPM_FEAT_SUSPEND,      /* 强制恢复全部挂起（pre_exit） */
    KPM_FEAT_STEALTH_HOOK, /* 摘 BRP 重定向并释放停靠（pre_exit） */
    KPM_FEAT_HOOK,         /* 普通 hook 摘除 */
    KPM_FEAT_GYRO,         /* 卸载传感器 uprobe */
    KPM_FEAT_PRCTL,        /* prctl hook 移除 + 在途命令排空 */
    KPM_FEAT_TOUCH,        /* touch 状态释放（pre_exit 已停输入捕获） */
    KPM_FEAT_DEBUG,        /* 断点 disarm + bp workqueue 销毁 */
    KPM_FEAT_UDP,          /* UDP socket/workqueue 拆除 */
    KPM_FEAT_MEM_RW,       /* 内存读写引擎 */
    KPM_FEAT_PROC,         /* 进程信息 */
    KPM_FEAT_HIDE,         /* 恢复全部隐藏进程 + idr 释放 */
    KPM_FEAT_DUMP,         /* dump 会话取消 */
    KPM_FEAT_PTR_SCAN,     /* 指针扫描 */
    KPM_FEAT_MEM_FREEZE,   /* 冻结表 */
    KPM_FEAT_MEM_SCAN,     /* 扫描表（abort 在 pre_exit 已执行） */
};

/* 核心通道：拆除即失联（prctl 是 UDP 全灭后唯一救援通道，反之亦然），
 * FEAT_DISABLE 拒绝，只能随模块卸载退出。 */
static const uint8_t k_feat_core[KPM_FEAT_MAX] = {
    [KPM_FEAT_UDP]   = 1,
    [KPM_FEAT_PRCTL] = 1,
};

void kpm_feat_init(void)
{
    lib_memset(g_units, 0, sizeof(g_units));
    g_feat_ready = 1;
}

long kpm_feat_register(uint32_t id, const char *name, uint32_t dep_mask,
                       uint32_t state_bit, const kpm_feat_ops_t *ops)
{
    unsigned long flags;
    kpm_feat_unit_t *u;

    if (!g_feat_ready || id >= KPM_FEAT_MAX || !name)
        return -KPM_E_INVAL;

    flags = kpm_spin_lock_irqsave(&g_feat_lock);
    u = &g_units[id];
    if (u->registered) {
        kpm_spin_unlock_irqrestore(&g_feat_lock, flags);
        return -KPM_E_INVAL;
    }
    u->name      = name;
    if (ops)
        u->ops   = *ops;               /* ops=NULL = 未编译/未实现（cap=NONE） */
    u->dep_mask  = dep_mask;
    u->state_bit = state_bit;
    u->core      = k_feat_core[id];
    u->reason    = 0;
    /* 能力档位：init 为空 = 编译未包含（或尚未实现），FEAT_ENABLE 直接拒绝 */
    u->cap       = ops ? (ops->init ? KPM_FEATCAP_FULL : KPM_FEATCAP_NONE)
                       : KPM_FEATCAP_NONE;
    u->state     = KPM_FEATST_DISABLED;
    u->registered = 1;
    kpm_spin_unlock_irqrestore(&g_feat_lock, flags);
    return 0;
}

/* 依赖检查：所有 dep_mask 置位的单元须处于 OK/DEGRADED */
static int kpm_feat_deps_ok(kpm_feat_unit_t *u)
{
    uint32_t i;
    for (i = 0; i < KPM_FEAT_MAX; i++) {
        if (!(u->dep_mask & (1u << i)))
            continue;
        if (g_units[i].state != KPM_FEATST_OK &&
            g_units[i].state != KPM_FEATST_DEGRADED)
            return 0;
    }
    return 1;
}

/* 反向依赖：是否有已启用单元依赖 id（disable 前置检查） */
static int kpm_feat_has_dependents(uint32_t id)
{
    uint32_t i;
    for (i = 0; i < KPM_FEAT_MAX; i++) {
        if (i == id || !g_units[i].registered)
            continue;
        if ((g_units[i].dep_mask & (1u << id)) &&
            (g_units[i].state == KPM_FEATST_OK ||
             g_units[i].state == KPM_FEATST_DEGRADED))
            return 1;
    }
    return 0;
}

long kpm_feat_enable(uint32_t id)
{
    kpm_feat_unit_t *u;
    unsigned long flags;
    long ret;

    if (!g_feat_ready)
        return -KPM_E_DISABLED;
    if (id >= KPM_FEAT_MAX)
        return -KPM_E_INVAL;               /* 越界 id 与未启用的语义区分开 */

    flags = kpm_spin_lock_irqsave(&g_feat_lock);
    u = &g_units[id];
    if (!u->registered) {
        kpm_spin_unlock_irqrestore(&g_feat_lock, flags);
        return -KPM_E_INVAL;
    }
    if (u->state == KPM_FEATST_OK || u->state == KPM_FEATST_DEGRADED) {
        kpm_spin_unlock_irqrestore(&g_feat_lock, flags);
        return u->state;                       /* 幂等 */
    }
    if (u->state == KPM_FEATST_TRANSITION) {
        kpm_spin_unlock_irqrestore(&g_feat_lock, flags);
        return -KPM_E_BUSY;                    /* 进行中 ≠ 未实现 */
    }
    if (u->cap == KPM_FEATCAP_NONE || !u->ops.init) {
        kpm_spin_unlock_irqrestore(&g_feat_lock, flags);
        return -KPM_E_DISABLED;                /* 未实现/未编译 */
    }
    if (!kpm_feat_deps_ok(u)) {
        kpm_spin_unlock_irqrestore(&g_feat_lock, flags);
        return -KPM_E_DISABLED;                /* 依赖未启用 */
    }
    u->state = KPM_FEATST_TRANSITION;
    u->reason = 0;
    kpm_spin_unlock_irqrestore(&g_feat_lock, flags);

    /* 锁外执行 init：符号解析/自检/挂钩，可睡眠可耗时。
     * 返回 0=OK；KPM_FEATST_DEGRADED(2)=降级成功（原因由单元经
     * kpm_feat_set_reason 预先写入）；负值=失败。 */
    ret = u->ops.init();

    flags = kpm_spin_lock_irqsave(&g_feat_lock);
    if (ret == 0 || ret == KPM_FEATST_DEGRADED) {
        u->state = (ret == KPM_FEATST_DEGRADED) ? KPM_FEATST_DEGRADED
                                                : KPM_FEATST_OK;
        if (u->state_bit)
            kpm_set_state(u->state_bit);
    } else {
        /* 失败零残留：状态记 FAILED，init 自身负责回滚（约定见 LH_feat.h）。
         * reason 优先保留 init 写入的具体原因（如 sysmon 失败的 nr）。 */
        u->state = KPM_FEATST_FAILED;
        if (u->reason == 0)
            u->reason = (ret < 0) ? (uint32_t)(-ret) : (uint32_t)ret;
    }
    kpm_spin_unlock_irqrestore(&g_feat_lock, flags);

    kpm_log("feat: enable %s -> %s (%ld)\n", u->name,
            ret == 0 ? "ok" :
            (ret == KPM_FEATST_DEGRADED ? "degraded" : "failed"), ret);
    if (ret == 0 || ret == KPM_FEATST_DEGRADED)
        return u->state;
    return ret > 0 ? -ret : ret;               /* 统一负错误码 */
}

long kpm_feat_disable(uint32_t id)
{
    kpm_feat_unit_t *u;
    unsigned long flags;

    if (!g_feat_ready)
        return -KPM_E_DISABLED;
    if (id >= KPM_FEAT_MAX)
        return -KPM_E_INVAL;

    flags = kpm_spin_lock_irqsave(&g_feat_lock);
    u = &g_units[id];
    if (!u->registered) {
        kpm_spin_unlock_irqrestore(&g_feat_lock, flags);
        return -KPM_E_INVAL;
    }
    if (u->core) {
        kpm_spin_unlock_irqrestore(&g_feat_lock, flags);
        /* 核心通道拆除 = 客户端失联（prctl/UDP 互为救援通道），
         * 只随模块卸载退出。风险注释：强行关闭需 UN_HOOK(0x4) 等价语义。 */
        return -KPM_E_PERM;
    }
    if (u->state == KPM_FEATST_DISABLED ||
        u->state == KPM_FEATST_FAILED) {
        kpm_spin_unlock_irqrestore(&g_feat_lock, flags);
        return 0;                              /* 幂等 */
    }
    if (u->state == KPM_FEATST_TRANSITION) {
        kpm_spin_unlock_irqrestore(&g_feat_lock, flags);
        return -KPM_E_BUSY;
    }
    if (kpm_feat_has_dependents(id)) {
        kpm_spin_unlock_irqrestore(&g_feat_lock, flags);
        return -KPM_E_BUSY;                    /* 先关闭依赖方 */
    }
    u->state = KPM_FEATST_TRANSITION;
    kpm_spin_unlock_irqrestore(&g_feat_lock, flags);

    if (u->ops.pre_exit)
        u->ops.pre_exit();
    if (u->ops.exit)
        u->ops.exit();

    flags = kpm_spin_lock_irqsave(&g_feat_lock);
    u->state = KPM_FEATST_DISABLED;
    u->reason = 0;
    if (u->state_bit)
        kpm_clear_state(u->state_bit);
    kpm_spin_unlock_irqrestore(&g_feat_lock, flags);

    kpm_log("feat: disable %s\n", u->name);
    return 0;
}

void kpm_feat_disable_all(void)
{
    int i;
    kpm_feat_unit_t *u;

    if (!g_feat_ready)
        return;

    /* 两阶段（按 k_teardown_order 显式序列）：
     * pass1 pre_exit：停事件产生端/强制恢复停靠——在一切资源释放前
     *   统一执行（输入捕获取消最先、扫描中止随后、挂起/停靠强制恢复）；
     * pass2 exit：事件产生端 → 通道（prctl 排空 → UDP）→ 数据面。 */
    for (i = 0; i < KPM_FEAT_MAX; i++) {
        u = &g_units[k_teardown_order[i]];
        if (u->registered && u->ops.pre_exit &&
            (u->state == KPM_FEATST_OK || u->state == KPM_FEATST_DEGRADED))
            u->ops.pre_exit();
    }
    for (i = 0; i < KPM_FEAT_MAX; i++) {
        u = &g_units[k_teardown_order[i]];
        if (!u->registered)
            continue;
        if (u->ops.exit &&
            (u->state == KPM_FEATST_OK || u->state == KPM_FEATST_DEGRADED)) {
            u->ops.exit();
            u->state = KPM_FEATST_DISABLED;
            u->reason = 0;
            if (u->state_bit)
                kpm_clear_state(u->state_bit);
        }
        if (u->state == KPM_FEATST_TRANSITION) {
            /* 不可能到达（TRANSITION 期间 disable_all 不会被并发调起，
             * 模块卸载与命令互斥由 prctl/UDP 已排空保证）；防御性兜底。 */
            u->state = KPM_FEATST_DISABLED;
        }
    }
}

int kpm_feat_enabled(uint32_t id)
{
    if (!g_feat_ready || id >= KPM_FEAT_MAX)
        return 0;
    return g_units[id].state == KPM_FEATST_OK ||
           g_units[id].state == KPM_FEATST_DEGRADED;
}

/* 单元 init 在返回 KPM_FEATST_DEGRADED 前写入具体降级原因，
 * FEAT_LIST.reason 原样上报（0=无原因）。由 init 单写者调用，
 * kpm_feat_enable 在 init 返回后读取，无需额外加锁。 */
void kpm_feat_set_reason(uint32_t id, uint32_t reason)
{
    unsigned long flags;

    if (!g_feat_ready || id >= KPM_FEAT_MAX)
        return;
    flags = kpm_spin_lock_irqsave(&g_feat_lock);
    g_units[id].reason = reason;
    kpm_spin_unlock_irqrestore(&g_feat_lock, flags);
}

int kpm_feat_state(uint32_t id)
{
    if (!g_feat_ready)
        return KPM_FEATST_DISABLED;
    if (id >= KPM_FEAT_MAX)
        return -KPM_E_INVAL;   /* 越界 id：与“未启用(0)”区分开 */
    return g_units[id].state;
}

int kpm_feat_cap(uint32_t id)
{
    if (!g_feat_ready || id >= KPM_FEAT_MAX)
        return KPM_FEATCAP_NONE;
    return g_units[id].cap;
}

long kpm_feat_list_fill(kpm_feat_entry_t *arr, int max)
{
    uint32_t i;
    int n = 0;
    unsigned long flags;

    if (!arr || max <= 0 || max > KPM_FEAT_MAX)
        return -KPM_E_INVAL;

    flags = kpm_spin_lock_irqsave(&g_feat_lock);
    for (i = 0; i < KPM_FEAT_MAX && n < max; i++) {
        kpm_feat_unit_t *u = &g_units[i];
        kpm_feat_entry_t *e = &arr[n];
        lib_memset(e, 0, sizeof(*e));
        e->id = i;
        e->state = u->registered ? u->state : KPM_FEATST_DISABLED;
        e->cap = u->registered ? u->cap : KPM_FEATCAP_NONE;
        e->reason = u->registered ? u->reason : 0;
        if (u->name)
            lib_strncpy(e->name, u->name, sizeof(e->name) - 1);
        n++;
    }
    kpm_spin_unlock_irqrestore(&g_feat_lock, flags);
    return n;
}
