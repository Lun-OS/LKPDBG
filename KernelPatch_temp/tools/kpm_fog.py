#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kpm_fog.py -- KPM 反静态分析迷雾区生成器 (Step4 加固)

生成 <out>.S：一个独立的可执行节区 `.kpm.fog`（SHF_EXECINSTR|SHF_ALLOC），
填充大量 PC 相对的"回跳"分支（b / cbz / tbz / b.cond / ldr[pc]+br / 真指令+假序言），
构成一个庞大、密集、自指的向后分支蜘蛛网。

效果：
  - IDA 一加载 .kpm，会对该可执行节区做线性扫描 + 递归下降，立即陷入千级
    "疯狂循环回跳"基本块网，CFG 图爆炸 / 分析渲染显著变慢 / 难以阅读。
  - 配合 `.rodata` 锚点表（R_AARCH64_ABS64 数据引用散布进迷雾），进一步压入
    32 个散布目标反查，叠加 xref 压力。

为什么安全（运行时惰性 + 加载兼容）：
  - 迷雾只"看起来像代码"，没有任何真实代码引用/调用它，真实路径永不进入。
  - 所有分支采用手工编码的 PC 相对立即数（与节区加载基址无关），生成的是
    **原始 4 字节字，零重定位** —— 链接器/加载器对这些字节不做任何处理，
    天然规避 R_AARCH64_BRANCH* 重定位负担，保证 KPM 加载兼容。
  - 仅锚点表产生少量 R_AARCH64_ABS64（数据指针，惰性无副作用）。
  - 无任何 UNDEF / libgcc 依赖，通过 check-syms 门禁。

用法：
  python kpm_fog.py --size 65536 --seed 0x6A09E667 --out LH_fog.S
  （--size 为字数，65536 字 = 262144B = 256KB）
"""

import argparse
import random
import sys

# ---- AArch64 编码（均为有效真实指令）----

def w_b(delta):
    """b label; target vs pc 的字偏移 delta."""
    return 0x14000000 | (delta & 0x3FFFFFF)

def w_cbz_x0(delta):
    """cbz x0, label"""
    return 0xB4000000 | ((delta & 0x7FFFF) << 5)

def w_cbz_x1(delta):
    """cbz x1, label"""
    return 0xB4000001 | ((delta & 0x7FFFF) << 5)

def w_tbz_x8(delta):
    """tbz x8, #7, label"""
    return 0x36000000 | ((delta & 0x3FFF) << 5) | ((7 & 0x3F) << 19) | 8

def w_tbz_x9(delta):
    """tbz x9, #3, label"""
    return 0x36000000 | ((delta & 0x3FFF) << 5) | ((3 & 0x3F) << 19) | 9

def w_bcond(delta, cond):
    """b.<cond> label; cond: EQ..NV"""
    return 0x54000000 | ((delta & 0x7FFFF) << 5) | (cond & 0xF)

def w_ldr_pc(xreg, delta):
    """ldr x<xreg>, [pc, #delta*4]"""
    return 0x58000000 | ((delta & 0x7FFFF) << 5) | (xreg & 0x1F)

def w_br(xreg):
    """br x<xreg>"""
    return 0xD61F0000 | ((xreg & 0x1F) << 5)

# 真指令常量（移入/序言/返回，制造真实指令外观）
NOP        = 0xD503201F
MOV_X1_X0  = 0xAA0003E1
SUB_SP_16  = 0xD10043FF   # sub sp, sp, #16
MOV_X29_SP = 0x910003FD   # mov x29, sp
MOV_X0_X29 = 0xAA1D03E0   # mov x0, x29
RET        = 0xD65F03C0


def build_words(count, seed):
    """生成 count 个 4 字节字（迷雾主体）。返回 list[int]."""
    rng = random.Random(seed)
    CLUSTER = 1024
    # 在环簇内分配的权重：回跳 b / cbz / tbz / bcond / 间接 / 真指令+假序言
    words = [0] * count
    i = 0
    while i < count:
        base = (i // CLUSTER) * CLUSTER
        nxt = min(base + CLUSTER, count)

        # 簇首：假序言（sub sp + mov x29,sp）+ 回跳簇首，诱 IDA 函数识别
        if i + 2 < nxt:
            words[i] = SUB_SP_16
            words[i + 1] = MOV_X29_SP
            # b 回簇首
            words[i + 2] = w_b(base - i - 2)
            i += 3

        # 簇主体：密集回跳混合
        while i < nxt:
            r = rng.random()
            if r < 0.40:
                # b 回跳前 1..64 字
                d = rng.randint(1, 64)
                tgt = i - d
                if tgt < base:
                    tgt = base
                words[i] = w_b(tgt - i)
                i += 1
            elif r < 0.55:
                # cbz 回跳
                d = rng.randint(1, 256)
                tgt = i - d
                if tgt < base:
                    tgt = base
                words[i] = w_cbz_x0(tgt - i)
                i += 1
            elif r < 0.67:
                # tbz 回跳
                d = rng.randint(1, 128)
                tgt = i - d
                if tgt < base:
                    tgt = base
                words[i] = w_tbz_x8(tgt - i)
                i += 1
            elif r < 0.74:
                # b.cond 回跳
                d = rng.randint(1, 192)
                tgt = i - d
                if tgt < base:
                    tgt = base
                words[i] = w_bcond(tgt - i, rng.randint(0, 14))
                i += 1
            elif r < 0.90:
                # 间接自指：ldr x7,[pc,#-2]; br x7  （PC 相对，固定字）
                if i + 1 < nxt:
                    words[i] = w_ldr_pc(7, -2)
                    words[i + 1] = w_br(7)
                    i += 2
                else:
                    words[i] = w_b(base - i)
                    i += 1
            else:
                # 真指令 + 回跳
                pick = rng.choice([NOP, MOV_X1_X0, MOV_X0_X29, NOP, NOP])
                words[i] = pick
                i += 1
                if i < nxt and rng.random() < 0.5:
                    words[i] = w_b(base - i)
                    i += 1
        i = nxt
    return words


def main():
    ap = argparse.ArgumentParser(description="KPM 反静态分析迷雾区生成器")
    ap.add_argument("--out", dest="fout", required=True, help="输出 .S 文件")
    ap.add_argument("--size", type=int, default=65536,
                    help="字数(4 字节/字)；默认 65536 字 = 256KB")
    ap.add_argument("--anchors", type=int, default=32, help="锚点数(散布进迷雾)")
    ap.add_argument("--seed", type=lambda x: int(x, 0), default=0x6A09E667)
    args = ap.parse_args()

    if args.size <= 0:
        sys.exit("[-] --size 必须 > 0")
    if args.anchors <= 0:
        sys.exit("[-] --anchors 必须 > 0")

    seed = args.seed & 0xFFFFFFFFFFFFFFFF
    words = build_words(args.size, seed)

    # 锚点散布位置（确定性）
    n = args.size
    anchor_idx = sorted({(i * n) // args.anchors for i in range(args.anchors)})

    lines = []
    lines.append("/* AUTO-GENERATED by tools/kpm_fog.py -- do not edit. */")
    lines.append("/* Seed: 0x%016x, words: %d, anchors: %d */"
                 % (seed, n, args.anchors))
    lines.append(".section\t.kpm.fog,\"ax\",%progbits")
    lines.append(".align\t4")
    lines.append("")
    apos = 0
    for i, wc in enumerate(words):
        if apos < len(anchor_idx) and i == anchor_idx[apos]:
            lines.append("fog_a%d:" % apos)
            apos += 1
        lines.append("\t.long\t0x%08x" % (wc & 0xFFFFFFFF))
    lines.append("")
    lines.append(".section\t.rodata,\"a\",%progbits")
    lines.append(".align\t8")
    lines.append("__fog_anchor:")
    for k in range(args.anchors):
        lines.append("\t.quad\tfog_a%d" % k)
    lines.append("")
    lines.append(".ident\t\"kpm_fog\"")

    with open(args.fout, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("[+] %s: %d words (%.2f KiB), %d anchors, seed 0x%016x"
          % (args.fout, n, n * 4.0 / 1024, args.anchors, seed))


if __name__ == "__main__":
    main()