/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpenc.h -- KPM 字符串运行时解密 (Step 2 加固)
 *
 * 用途: 敏感字符串(内核符号名、路径、检测协议签名等)在构建期被加密为 blob,
 *       明文不出现在产物 .rodata/.data 中(静态 strings/IDA 无法直接提取),
 *       运行时由 KENC(id) 解密到各 id 独立的 static 缓冲再返回。
 *
 * 关键设计约束(self-contained, 满足 KPM 加载/隐蔽性要求):
 *   - 解密只用 XOR + 移位 + 常系数乘加, 全部是 AArch64 基本指令,
 *     绝不生成对 libgcc (aeabi 系/__div 系/__mul 系) 或 __atomic/__sync 的调用
 *     (这些符号不在 KernelPatch 导出表, 会 KPM 加载失败 unknown symbol)。
 *   - blob 声明为 `volatile`, 解密函数 noinline: 防止编译期常量折叠
 *     (否则编译器会把解密结果重新折叠回明文放进 .rodata, 使加密失效)。
 *   - 每个 KENC id 拥有独立 static 缓冲, 互不覆盖。
 *
 * 密钥调度 (SplitMix-64 派生, 与 tools/encstr.py 严格互逆):
 *   k0 = 条目派生密钥(由构建种子 seed 与条目顺序派生, 每条独立)
 *   第 i 字节密钥字  k_i = k0 ^ ((i+1)*MUL + (i+2)*ADD)   (mod 2^64)
 *   取密钥字节       key_byte = (k_i >> (8*(i&7))) & 0xff
 *   密文             enc[i] = rotl3(plain[i]) ^ key_byte
 * 64-bit 常系数乘加的低位字节随 i 展开呈长周期雪崩, 且每条 id 种子独立,
 * 抵抗"单字节流重复"与已知明文攻击, 明显强于旧版 0x1f*k+0x71 单字节流。
 *
 * 用法 (由 tools/encstr.py 生成的 encstr_autogen.h 提供逐条定义):
 *     #include "encstr_autogen.h"
 *     ... strcmp(path, KENC(k_proc_net_udp)) ...
 *     ... kallsyms_lookup_name(KENC(k_sym_find_task)) ...
 *
 * 已知限制: 单 id 静态缓冲非线程安全; 若同一 id 在并发路径中被反复使用,
 *           上层应在极短生命周期内使用(典型的 kallsyms/strcmp/strstr 瞬时
 *           查询场景满足要求)。需要更强的并发隔离时可改为调用方自备缓冲。
 */
#ifndef _KP_KPENC_H_
#define _KP_KPENC_H_

/* SplitMix64 常量(与 tools/encstr.py 保持一致) */
#define KPENC_MUL	0x5851F42D4C957F2Dull
#define KPENC_ADD	0x14057B7EF767814Full

/*
 * 解密核心: SplitMix-64 派生字节流 XOR + 旋转, 与 encstr.py 的加密互逆。
 * src : 构建期加密的 blob (volatile, 防常量折叠)
 * dst : 调用方/static 缓冲, 末尾补 0 -> 返回 C 字符串
 * n   : 明文长度 (不含结尾 0)
 * k0  : 条目派生密钥(64-bit; 由 encstr.py 逐条写入)
 */
static inline char *kpenc_decrypt(const volatile unsigned char *src,
                                  char *dst, unsigned int n,
                                  unsigned long long k0)
{
    unsigned int i;
    for (i = 0; i < n; i++) {
        unsigned long long k;
        unsigned char keyb;
        unsigned char c;
        k = k0 ^ (((unsigned long long)(i + 1)) * KPENC_MUL +
                  ((unsigned long long)(i + 2)) * KPENC_ADD);
        keyb = (unsigned char)((k >> (8u * (i & 7u))) & 0xffull);
        c = (unsigned char)(src[i] ^ keyb);
        dst[i] = (char)((unsigned char)((c >> 3) | (c << 5)));
    }
    dst[n] = '\0';
    return dst;
}

#endif /* _KP_KPENC_H_ */