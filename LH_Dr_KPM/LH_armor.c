/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_armor.c — KPM 深度加固运行侧实现
 *
 * 1) kpm_armor_init : init 首句调用; 在依赖任何字符串(printk/log)之前, 将
 *    .kpm.str(全部字符串字面量) 就地解密。因此 init 里第一条对 .kpm.str 的
 *    读取(本函数自身的 printk/strcmp)必须是解密之后, 调用方放在首句即可。
 *
 *    注意: 本文件不得在解密前使用任何 .kpm.str 里的字符串常量(会读到密文),
 *          故本函数执行期间不打印 用户字符串, 只用寄存器+整数运算。
 *
 * 2) kpm_armor_seal : init 末尾调用; 将 .kpm.once(一次性符号解析/设值代码)
 *    整段指令清零, 并做 I/D cache 同步, 使该代码从可执行内存彻底消失。
 *    解析出的地址存于 .data 数据槽(独立于代码区), 抹零不影响功能。
 *
 * 3) 只用 AArch64 基础指令 + 缓存/屏障, 无 libgcc (__aarch64 系/__atomic 系) 依赖。
 */
#include <linux/string.h>

#include "LH_armor.h"

/* ===== SplitMix64 常量(与 kpenc.h / tools/kpm_armor.py 一致) ===== */
#define KPENC_MUL 0x5851F42D4C957F2Dull
#define KPENC_ADD 0x14057B7EF767814Full

/* lds 注入的"节内定义符号", loader 会重定位为运行期真实地址 */
extern unsigned char __kenc_region_begin[];
extern unsigned char __kenc_region_end[];
extern unsigned char __konce_region_begin[];
extern unsigned char __konce_region_end[];

/* 就地解密: plain[i] = rotr3(enc[i] ^ keyb(i)), 与 kpm_armor.py 互逆。
 * 置于 .kpm.once: 仅被 kpm_armor_init 在 init 期调用, 末尾随区整段抹零,
 * 使 SplitMix64 密钥流常量在运行内存 dump 中彻底消失。 */
__attribute__((section(".kpm.once")))
void kp_armor_decrypt_region(void *base, unsigned long size, unsigned long long key)
{
    volatile unsigned char *p = (volatile unsigned char *)base;
    unsigned long i;
    for (i = 0; i < size; i++) {
        unsigned long long k;
        unsigned char keyb, c;
        k = key ^ (((unsigned long long)(i + 1)) * KPENC_MUL +
                   ((unsigned long long)(i + 2)) * KPENC_ADD);
        keyb = (unsigned char)((k >> (8u * (i & 7u))) & 0xffull);
        c = (unsigned char)(p[i] ^ keyb);
        p[i] = (unsigned char)((c >> 3) | (c << 5));
    }
}

/*
 * init 首句: 解密 .kpm.str。
 * 注意: 解密前不能读取任何 .kpm.str 字符串, 故本函数内避免使用用户格式串。
 * 置于 .kpm.once: 本函数(含内联的 kp_str_key 密钥碎片还原)init 末尾随区抹零,
 * 因此字符串密钥碎片即使在静态产物里可见, 运行内存 dump 中也不会残留。
 */
__attribute__((section(".kpm.once")))
void kpm_armor_init(void)
{
#if KP_ARMOR_STR
    unsigned long begin = (unsigned long)&__kenc_region_begin;
    unsigned long end = (unsigned long)&__kenc_region_end;
    if (end > begin) {
        kp_armor_decrypt_region((void *)begin, end - begin, kp_str_key());
    }
#endif
}

/* D-cache 回写并废弃 + I-cache 失效, 保证代码修改对取指可见 */
static void kpm_flush_code_range(void *start, unsigned long size)
{
    unsigned long addr = (unsigned long)start;
    unsigned long end = addr + size;
    /* 逐 cache line (64B): 先 dc civac 回写/废弃数据缓存, 再 dsb 屏障 */
    asm volatile(
        "1:  dc   civac, %0\n"
        "    add  %0, %0, #64\n"
        "    cmp  %0, %1\n"
        "    b.lo 1b\n"
        "    dsb  ish\n"
        : "+r"(addr) : "r"(end) : "memory", "cc");
    addr = (unsigned long)start;
    /* 逐 cache line 做 ic ivau 失效指令缓存, 再 dsb + isb 完成全局可见 */
    asm volatile(
        "2:  ic   ivau, %0\n"
        "    add  %0, %0, #64\n"
        "    cmp  %0, %1\n"
        "    b.lo 2b\n"
        "    dsb  ish\n"
        "    isb\n"
        : "+r"(addr) : "r"(end) : "memory", "cc");
}

/* init 末尾: 抹零 .kpm.once 一次性代码区 */
void kpm_armor_seal(void)
{
#if KP_ARMOR_ONCE
    unsigned long begin = (unsigned long)&__konce_region_begin;
    unsigned long end = (unsigned long)&__konce_region_end;
    if (end > begin) {
        unsigned long size = end - begin;
        /* 先确保代码(含其依赖的指令)已一致可读 */
        kpm_flush_code_range((void *)begin, size);
        /* 清零指令字节 */
        memset((void *)begin, 0, size);
        /* 再做 D->I 同步, 使 exec 路径取出的是全零/旧快照 */
        kpm_flush_code_range((void *)begin, size);
    }
#endif
}