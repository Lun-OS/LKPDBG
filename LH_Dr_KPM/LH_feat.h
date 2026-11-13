/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_feat.h - 功能单元注册表
 *
 * 设计：
 *   - 隐蔽性优先：默认仅启用内存读写 + 两协议接口。未启用的功能单元
 *     零初始化——不解析符号、不挂钩、不占硬件断点/工作队列。
 *   - 功能完全关闭：FEAT_DISABLE 摘 hook、释放资源、清状态位，关闭后
 *     命令统一返回 -KPM_E_DISABLED（指定错误，见 LH_comm.h）。
 *   - 兼容性退回：每个单元 init 内做能力自检，
 *     自检不过按退回链降档（DEGRADED）或整体拒绝（FAILED→零残留），
 *     绝不带病运行（不做未验证偏移写入）。
 *
 * 卸载顺序由注册表内显式拆卸序列（k_teardown_order）声明：事件产生端
 * （hook/断点/停靠）先于通道（prctl/UDP）拆除，通道先于数据面
 * （mem_rw/scan）释放。
 */
#ifndef _LH_FEAT_H_
#define _LH_FEAT_H_

#include <ktypes.h>
#include "LH_comm.h"

/* 注册单元描述（kpm_feat_register 参数） */
typedef struct {
    long (*init)(void);      /* 启用：符号解析+能力自检+挂钩；可睡眠。
                              * 返回 0=OK，KPM_FEATST_DEGRADED(2)=降级成功
                              * （原因经 kpm_feat_set_reason 写入），负值=失败 */
    void (*exit)(void);      /* 关闭：摘 hook+释放资源；可睡眠；幂等 */
    void (*pre_exit)(void);  /* 卸载前摇（可选）：停事件产生端/强制恢复，
                              * 在所有单元 exit 之前统一执行 */
} kpm_feat_ops_t;

/* ===== 生命周期 =====
 * kpm_feat_init 清空注册表（模块 init 早期调用）。
 * 返回 0 成功；注册表满/重复 id 返回 -KPM_E_INVAL。 */
void kpm_feat_init(void);
long kpm_feat_register(uint32_t id, const char *name, uint32_t dep_mask,
                       uint32_t state_bit, const kpm_feat_ops_t *ops);

/* ===== 开关 =====
 * kpm_feat_enable:  越界/未注册 → -KPM_E_INVAL；能力 NONE/依赖未启用 →
 *                   -KPM_E_DISABLED；进行中 → -KPM_E_BUSY；
 *                   init 返回 0=OK，KPM_FEATST_DEGRADED(2)=降级成功，
 *                   负值=FAILED 且零残留。
 *                   已启用 → 直接返回当前状态 1/2（幂等）。
 *                   返回值语义：>0 时返回最终状态（OK=1/DEGRADED=2）。
 * kpm_feat_disable: 核心通道（UDP/PRCTL）→ -KPM_E_PERM；
 *                   被已启用单元依赖 → -KPM_E_BUSY；
 *                   已禁用 → 0（幂等）。 */
long kpm_feat_enable(uint32_t id);
long kpm_feat_disable(uint32_t id);
/* 卸载路径：按 k_teardown_order 序列 pre_exit 全部 → exit 全部（无依赖检查、幂等） */
void kpm_feat_disable_all(void);

/* ===== 查询 =====
 * kpm_feat_enabled: 状态门（dispatch/UDP 入口热路径用）——
 *                   OK/DEGRADED 返回 1，其余 0。id 越界返回 0。 */
int  kpm_feat_enabled(uint32_t id);
/* kpm_feat_state: 越界 id 返回 -KPM_E_INVAL；否则 KPM_FEATST_*。 */
int  kpm_feat_state(uint32_t id);
int  kpm_feat_cap(uint32_t id);
/* 单元 init 降级时写入原因（FEAT_LIST.reason），见 LH_debug.h 原因位 */
void kpm_feat_set_reason(uint32_t id, uint32_t reason);
/* FEAT_LIST 数据源：填充最多 max 条，返回实际条数 */
long kpm_feat_list_fill(kpm_feat_entry_t *arr, int max);

#endif /* _LH_FEAT_H_ */
