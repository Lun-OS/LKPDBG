/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_armor_keys.h — 构建期生成的混淆密钥碎片 (由 kpm_armor.py 覆盖写入)。
 *
 * 设计: 真实密钥不以字面量出现, 而以 rotl/rotr、加/减、XOR(KPM_KDM) 的变形
 *       碎片存于此。KPM_KDM = KPENC_MUL ^ KPENC_ADD 由节内既有的合法
 *       SplitMix64 常量派生, 单独看碎片皆像普通代码常量, objdump/IDA 搜不到
 *       密钥字面量。运行侧逐层逆还原(内联汇编, 常量不被编译器折叠)。
 * 约束: 每次正式构建随机重生成(整节区加密与运行侧解码保持一致); 本文件为
 *       NOARMOR 回退提供默认值。切勿手改。
 */
#ifndef _LH_ARMOR_KEYS_H_
#define _LH_ARMOR_KEYS_H_

/* 整节区字符串密钥碎片(3 层混淆; 仅 .kpm.once 内 kpm_armor_init 使用, init 后随区抹零) */
#define KPM_STR_K1 0xED4C5648E8F39944ull

/* 关键函数指针密钥碎片(2 层混淆; 热路径访问器内联还原) */
#define KPM_PTR_K1 0x2DF4A101ADE6F839ull

#endif /* _LH_ARMOR_KEYS_H_ */
