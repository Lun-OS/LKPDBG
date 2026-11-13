/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include "LH_utils.h"

/* 模块状态标志 */
static uint32_t g_state = 0;

uint32_t kpm_get_state(void) { return g_state; }
void kpm_set_state(uint32_t flags) { g_state |= flags; }
void kpm_clear_state(uint32_t flags) { g_state &= ~flags; }

/* ===== 随机数 =====
 * 使用 KPM 框架提供的 get_random_u64() 作为熵源。
 * 内核态不得使用浮点指令：内核不保存/恢复用户态 FPSIMD 上下文，
 * FPSIMD 指令会污染用户态 FPSIMD 寄存器（轻则浮点结果错乱，
 * 重则触发 SIGILL；CONFIG_KERNEL_MODE_NEON 下仅 kernel_neon_begin/end
 * 保护区间可用）。本实现为纯整数（aarch64 UDIV 单指令，无 libgcc 依赖）：
 * kpm_rand_range 用 get_random_u64 取模，us 级延时范围下模偏差可忽略
 * （区间宽度 ≤ 数千，2^64 取模偏差 < 2^-50）。 */
int kpm_rand_range(int min, int max)
{
    uint64_t v;
    if (max <= min) return min;
    v = get_random_u64();
    return min + (int)(v % (uint64_t)(max - min + 1));
}

/* ===== 微秒延迟 =====
 * KPM 运行在内核态，使用忙等待（原子上下文安全）
 */
void kpm_udelay_range(int min_us, int max_us)
{
    int delay = kpm_rand_range(min_us, max_us);
    volatile uint64_t i;
    uint64_t loops = (uint64_t)delay * 700ULL;
    for (i = 0; i < loops; i++) {
        __asm__ volatile("nop" ::: "memory");
    }
}
