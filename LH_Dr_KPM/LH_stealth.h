/* SPDX-License-Identifier: GPL-2.0-or-later */
/* kpm_stealth.h - 隐蔽性子模块（精简版）
 *
 * 设计准则：只采用架构层面自然可实现的方法，不刻意修改系统来隐藏。
 *
 * 隐蔽性机制（均为架构层自然方法，无需本模块额外初始化）：
 *   - DMA Device-nGnRnE 内存读写
 *   - IN-PLACE MUTATION 触摸模式
 *   - prctl 命令码 XOR 混淆 + UID 过滤
 *   - 内部日志缓冲区（不经过 dmesg）
 *   - 编译模式控制（release 零 dmesg 痕迹）
 *
 * hook 统一使用 KPM 框架标准 hook_wrap/hook_unwrap。
 */
#ifndef _KPM_STEALTH_H_
#define _KPM_STEALTH_H_

/* 隐蔽性初始化，返回 0 */
long kpm_stealth_init(const char *args);

/* 隐蔽性退出 */
void kpm_stealth_exit(void);

#endif /* _KPM_STEALTH_H_ */
