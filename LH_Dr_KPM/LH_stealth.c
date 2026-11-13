/* SPDX-License-Identifier: GPL-2.0-or-later */
/* kpm_stealth.c - 隐蔽性子模块（精简版）
 *
 * 设计准则：只采用架构层面自然可实现的方法，不刻意修改系统来隐藏。
 *
 * 隐蔽性机制（均为架构层自然方法）：
 *   - DMA Device-nGnRnE 内存读写（ARM64 架构原生内存属性）
 *   - IN-PLACE MUTATION 触摸模式（利用 input 子系统自然事件流）
 *   - prctl 命令码 XOR 混淆 + UID 过滤（系统原生权限机制）
 *   - 内部日志缓冲区（不经过 dmesg/printk）
 *   - 编译模式控制（release 模式零 dmesg 痕迹）
 *
 * hook 实现：所有 hook 统一使用 KPM 框架标准的 hook_wrap/hook_unwrap，
 * 框架标准 hook 是 KPM 机制的自然组成部分。
 */

#include <compiler.h>
#include <kpmodule.h>

#include "LH_stealth.h"
#include "LH_log.h"
#include "LH_comm.h"

long kpm_stealth_init(const char *args)
{
    (void)args;

    /* 隐蔽性完全依赖架构层自然方法，无需额外初始化；保留此函数
     * 仅为兼容 LH_main.c 的调用序列。 */
    kpm_log("kpm: stealth init (architecture-level only, no system modification)\n");

    return 0;
}

void kpm_stealth_exit(void)
{
    kpm_log("kpm: stealth exit\n");
}
