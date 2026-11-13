#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kpm_armor.py — KPM 深度加固 R2: 字符串整节区密文化 (Step6)

在最终可重定位 `.kpm` 上, 将 `.kpm.str` (全部字符串字面量) 逐字节原地加密,
使产物静态可读性与(dump 到内存后)运行时内存中均无明文串。

加密与 KernelPatch_temp/kernel/include/kpenc.h 的 kpenc_decrypt 严格互逆:
    key_i  = k0 ^ ((i+1)*KPENC_MUL + (i+2)*KPENC_ADD)   (mod 2^64)
    keyb   = (key_i >> (8*(i&7))) & 0xff
    enc[i] = rotl3(plain[i]) ^ keyb                     # 本工具写入文件
运行时解密(LH_armor.c kp_armor_decrypt_region):
    plain[i] = rotr3(enc[i] ^ keyb)

k0(种子)必须与 LH_armor.c 中 KP_ARMOR_STR_KEY 严格一致, 否则解密错乱。
仅依赖 XOR/移位, 无 libgcc 依赖; 全节区一次就地解密, 无静态缓冲, 线程安全。
"""
import argparse
import random
import struct

KPENC_MUL = 0x5851F42D4C957F2D
KPENC_ADD = 0x14057B7EF767814F

# ===== 密钥混淆常量(与运行侧 LH_armor.h / 生成头严格一致) =====
# KDM = MUL ^ ADD —— 由节内已存在的合法 SplitMix64 常量派生的"盲化掩码",
# 密钥不再以自身字面量出现, 而是 rotl(K ^ KDM) 之类的变形存储。
M64 = (1 << 64) - 1
KPM_KDM = KPENC_MUL ^ KPENC_ADD
KSTR_S1 = 0x51528  # 字符串密钥第 2 层"代码味"加数(非密, 仅混淆)
KSTR_S2 = 0x3A17   # 字符串密钥第 3 层加数
KSTR_B  = 23       # 字符串密钥额外一层旋转量

# 生成的密钥碎片头 / 原始密钥旁证文件(供整节区加密读取, 与编译期一致)
KEYS_HEADER = "LH_armor_keys.h"
KEYS_SIDECAR = ".armor_keys"


def rotl(x, n):
    n &= 63
    return ((x << n) | (x >> (64 - n))) & M64


def rotr(x, n):
    n &= 63
    return ((x >> n) | (x << (64 - n))) & M64


def ptr_encode(ptr):
    """热路径指针密钥的存储碎片: K1 = rotl17(PTR ^ KDM)。
    运行侧 kp_ptr_key(): rotr17(K1) ^ KDM == PTR (asm 内联, 常量不被折叠)。"""
    return rotl(ptr ^ KPM_KDM, 17)


def str_encode(s):
    """整节区字符串密钥的存储碎片(3 层混淆): 运行侧逐层逆还原。
    编码: d = ((rotr17(s)^KDM)-S1 ^S2)-B; K1 = rotl23(d)。
    每步显式 &M64, 防减法产生负数中间值。"""
    u = rotr(s, 17) & M64
    a = ((u ^ KPM_KDM) - KSTR_S1) & M64
    b = ((a ^ KSTR_S2) - KSTR_B) & M64
    return rotl(b, KSTR_B) & M64


def parse_keys_header(path):
    """从生成的 LH_armor_keys.h 读取 KPM_STR_K1、KPM_PTR_K1(十六进制)。"""
    import re
    with open(path, "r", encoding="latin1") as f:
        txt = f.read()
    def grab(name):
        m = re.search(r"#define\s+%s\s+0x([0-9A-Fa-f]+)ull" % name, txt)
        if not m:
            raise ValueError("key piece %s not found in %s" % (name, path))
        return int(m.group(1), 16)
    return grab("KPM_STR_K1"), grab("KPM_PTR_K1")


def str_key_from_pieces(k1):
    """逆还原整节区字符串密钥(与运行侧 KP_ARMOR_STR_KEY 逐层一致)。
    解码是 str_encode 的严格逆: d=rotr23(K1); c=d+B; b=c^S2; a=b+S1;
    u=a^KDM; s=rotl17(u)。注意 ^ 与 + 分别加括号, 规避 Python 运算符优先级。"""
    d = rotr(k1, KSTR_B)
    c = (d + KSTR_B) & M64
    b = (c ^ KSTR_S2) & M64
    a = (b + KSTR_S1) & M64
    u = (a ^ KPM_KDM) & M64
    return rotl(u, 17) & M64


HEADER_TMPL = """/* SPDX-License-Identifier: GPL-2.0-or-later */
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
#define KPM_STR_K1 0x{STR_K1:016X}ull

/* 关键函数指针密钥碎片(2 层混淆; 热路径访问器内联还原) */
#define KPM_PTR_K1 0x{PTR_K1:016X}ull

#endif /* _LH_ARMOR_KEYS_H_ */
"""


def emit_keys_header(out_dir, rng=None):
    """生成随机 STR/PTR 密钥, 计算混淆碎片, 写 LH_armor_keys.h 与 .armor_keys。
    返回 (str_key, ptr_key)。rng=None -> 系统熵(secrets.urandom)。"""
    import os
    import secrets
    if rng is None:
        str_key = int.from_bytes(secrets.token_bytes(8), "little")
        ptr_key = int.from_bytes(secrets.token_bytes(8), "little")
    else:
        str_key = rng.getrandbits(64)
        ptr_key = rng.getrandbits(64)
    str_key &= M64
    ptr_key &= M64
    kstr = str_encode(str_key)
    kptr = ptr_encode(ptr_key)
    header = HEADER_TMPL.format(STR_K1=kstr, PTR_K1=kptr)
    hp = os.path.join(out_dir, KEYS_HEADER)
    with open(hp, "w", encoding="utf-8", newline="\n") as f:
        f.write(header)
    with open(os.path.join(out_dir, KEYS_SIDECAR), "w", encoding="latin1", newline="\n") as f:
        f.write("str_key=0x%016X\nptr_key=0x%016X\n" % (str_key, ptr_key))
    print("[kpm_armor] generated fresh keys -> %s (STR/PTR randomized, obfuscated pieces only)"
          % KEYS_HEADER)
    return str_key, ptr_key

# ===== ②符号名隐藏: 定义符号名等长随机化(不可逆) =====
# 加载器(simplify_symbols/layout_symtab)只按"名字"解析 SHN_UNDEF 内核导入符号,
# 以及需要保留的 lds 边界符号。其余"定义于真实节"的符号(FUNC/OBJECT/NOTYPE,
# 含 LOCAL 与 GLOBAL)的名字: 重定位按 symtab 索引寻址、加载器不按名解析, 故对其
# strtab 字节做等长随机化绝对安全, 且静态(nm/IDA)与内存 dump 中均只见乱码。
ELF_STT_NOTYPE, ELF_STT_OBJECT, ELF_STT_FUNC = 0, 1, 2
ELF_STT_SECTION, ELF_STT_FILE = 3, 4
ELF_SHN_UNDEF = 0
NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

# 即便定义于真实节, 也绝不改名的符号(运行时/链接期按名有隐含依赖或语义标记)。
ALWAYS_PROTECT_NAMES = {
    "__kenc_region_begin", "__kenc_region_end",
    "__konce_region_begin", "__konce_region_end",
}

# 整节区密钥种子(64-bit)。必须与 LH_armor.c 中 KP_ARMOR_STR_KEY 一致。
DEFAULT_KEY = 0x4B504D41524D4F52  # "KPMARMOR" little-endian

# 需要把 st_value 覆写为"节内偏移"的 lds 边界符号。
# _begin/_end 分别对应目标节的起点/终点(0 / 节大小)。
# loader(simplify_symbols) 对节内符号执行 st_value += 节运行基址, 因此
# st_value 必须是纯节内偏移(0 或节大小), 运行时才得到正确的模块内地址。
# 不依赖 ld 对自定义 SECTIONS 的 VMA 分配语义, 完全由本工具决定。
FIX_SYMS = {
    "__kenc_region_begin": (".kpm.str", 0),
    "__kenc_region_end":   (".kpm.str", 1),
    "__konce_region_begin": (".kpm.once", 0),
    "__konce_region_end":   (".kpm.once", 1),
}


def rotl3(c):
    return ((c << 3) & 0xFF) | (c >> 5)


def key_byte(k0, i):
    k = (k0 ^ (((i + 1) * KPENC_MUL) + (i + 2) * KPENC_ADD)) & ((1 << 64) - 1)
    return (k >> (8 * (i & 7))) & 0xFF


def find_section(data, name):
    """返回 ELF64 中名为 name 的节的 (sh_offset, sh_size), 未找到返回 None."""
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF")
    if data[4] != 2 or data[5] != 1:
        raise ValueError("require ELF64 little-endian")
    enc = "<"
    (e_shoff,) = struct.unpack("<Q", data[0x28:0x30])
    (e_shentsize, e_shnum) = struct.unpack("<HH", data[0x3A:0x3E])
    (e_shstrndx,) = struct.unpack("<H", data[0x3E:0x40])

    strsec_off = strsec_size = 0
    # 先找出 shstrtab
    for i in range(1, e_shnum):
        off = e_shoff + i * e_shentsize
        (name_off, _t, _f, _a, so, ss) = struct.unpack("<IIQQQQ", data[off:off + 40])
        if i == e_shstrndx:
            strsec_off, strsec_size = so, ss
    if not strsec_off:
        return None

    def secname(no):
        if no == 0 or no >= strsec_size:
            return ""
        end = data.find(b"\x00", strsec_off + no, strsec_off + strsec_size)
        if end < 0:
            return ""
        return data[strsec_off + no:end].decode("latin1")

    for i in range(1, e_shnum):
        off = e_shoff + i * e_shentsize
        (name_off, _t, _f, _a, so, ss) = struct.unpack("<IIQQQQ", data[off:off + 40])
        if secname(name_off) == name:
            return (so, ss)
    return None


def process(data, key, fix_syms=True, scramble=True):
    ret = find_section(data, ".kpm.str")
    if ret is None:
        print("[kpm_armor] WARNING: .kpm.str not found, skip")
        return data, 0
    shoff, shsize = ret
    raw = bytearray(data[shoff:shoff + shsize])
    n = len(raw)
    for i in range(n):
        raw[i] = rotl3(raw[i]) ^ key_byte(key, i)
    out = data[:shoff] + bytes(raw) + data[shoff + shsize:]
    print("[kpm_armor] encrypted .kpm.str: off=0x%x size=%d" % (shoff, n))
    if fix_syms:
        out, _ = fix_boundary_syms(out)
    if scramble:
        out, _ = scramble_defined_syms(out)
    return out, n


def parse_elf(data):
    """返回 (e_shoff, e_shentsize, e_shnum, e_shstrndx, [节表], [节名])."""
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF")
    if data[4] != 2 or data[5] != 1:
        raise ValueError("require ELF64 little-endian")
    enc = "<"
    (e_shoff,) = struct.unpack("<Q", data[0x28:0x30])
    (e_shentsize, e_shnum) = struct.unpack("<HH", data[0x3A:0x3E])
    (e_shstrndx,) = struct.unpack("<H", data[0x3E:0x40])

    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name_off, shtype, shflags, shaddr, shoff, shsize) = struct.unpack(
            "<IIQQQQ", data[off:off + 40])
        secs.append((name_off, shtype, shflags, shaddr, shoff, shsize))
    strsec = secs[e_shstrndx]
    so, ss = strsec[4], strsec[5]

    def secname(no):
        if no == 0 or no >= ss:
            return ""
        end = data.find(b"\x00", so + no, so + ss)
        if end < 0:
            return ""
        return data[so + no:end].decode("latin1")

    names = [secname(s[0]) for s in secs]
    return (e_shoff, e_shentsize, e_shnum, e_shstrndx, secs, names)


def find_section(data, name):
    ret = parse_elf(data)
    e_shoff, e_shentsize, e_shnum, e_shstrndx, secs, names = ret
    for i in range(1, e_shnum):
        if names[i] == name:
            return (secs[i][4], secs[i][5])  # sh_offset, sh_size
    return None


def fix_boundary_syms(data):
    """把 FIX_SYMS 中每个符号的 st_value 减去所属节 sh_addr, 还原为节内偏移。
    这样 loader 的 st_value += 节运行基址 得到正确的运行地址。
    返回 (新data, 变更数)."""
    e_shoff, e_shentsize, e_shnum, e_shstrndx, secs, names = parse_elf(data)

    # 找到 .symtab 和 .strtab
    sym_off = sym_size = str_off = str_size = None
    for i in range(1, e_shnum):
        if names[i] == ".symtab":
            sym_off, sym_size = secs[i][4], secs[i][5]
        if names[i] == ".strtab":
            str_off, str_size = secs[i][4], secs[i][5]
    if not sym_off:
        print("[kpm_armor] WARNING: no .symtab, skip st_value fix")
        return data, 0

    strtab = data[str_off:str_off + str_size]
    entsize = 24  # Elf64_Sym
    count = sym_size // entsize
    out = bytearray(data)
    changed = 0
    for i in range(count):
        off = sym_off + i * entsize
        (st_name, st_info, st_other, st_shndx, st_value, st_size) = struct.unpack(
            "<IBBHQQ", bytes(out[off:off + 24]))
        if st_name == 0:
            continue
        end = strtab.find(b"\x00", st_name)
        if end < 0:
            continue
        name = strtab[st_name:end].decode("latin1")
        if name in FIX_SYMS:
            secname, kind = FIX_SYMS[name]
            # 找到目标节索引
            tgt = None
            for si in range(1, e_shnum):
                if names[si] == secname:
                    tgt = si
                    break
            if tgt is None:
                print("[kpm_armor] warn: section %s not found for %s" % (secname, name))
                continue
            secsize = secs[tgt][5]
            newval = 0 if kind == 0 else secsize
            # 绑定符号所属节索引(loader 按 st_shndx 取节基址) + 覆写节内偏移
            if tgt != st_shndx:
                struct.pack_into("<H", out, off + 6, tgt)
                print("[kpm_armor] bind %s: st_shndx %d -> %d (sec '%s')" %
                      (name, st_shndx, tgt, secname))
            if newval != st_value:
                struct.pack_into("<Q", out, off + 8, newval)
                print("[kpm_armor] fix %s: st_value 0x%x -> 0x%x (sec '%s', size 0x%x)" %
                      (name, st_value, newval, secname, secsize))
                changed += 1
    if changed:
        print("[kpm_armor] fixed %d boundary symbol(s)" % changed)
    return bytes(out), changed


def scramble_defined_syms(data, seed=0x4B504D):
    """对 .strtab 中"定义于真实节"的内部符号名做等长随机化(不可逆隐藏)。
    保护: 任何被 SHN_UNDEF 符号引用的名字偏移(内核导入, 加载期按名解析),
    以及 ALWAYS_PROTECT_NAMES 边界符号。仅改写 strtab 字节, 长度不变 =>
    节大小/符号表偏移/其它所有偏移零变化。返回 (新data, 改名数)。"""
    e_shoff, e_shentsize, e_shnum, e_shstrndx, secs, names = parse_elf(data)
    sym_off = sym_size = str_off = str_size = None
    for i in range(1, e_shnum):
        if names[i] == ".symtab":
            sym_off, sym_size = secs[i][4], secs[i][5]
        if names[i] == ".strtab":
            str_off, str_size = secs[i][4], secs[i][5]
    if not sym_off or not str_off:
        print("[kpm_armor] warn: no .symtab/.strtab, skip symbol-name scramble")
        return data, 0

    entsize = 24
    count = sym_size // entsize
    out = bytearray(data)
    strtab = bytes(data[str_off:str_off + str_size])

    def str_at(nameoff):
        if nameoff == 0 or nameoff >= str_size:
            return ""
        end = strtab.find(b"\x00", nameoff)
        return "" if end < 0 else strtab[nameoff:end].decode("latin1")

    syms = []
    for i in range(count):
        off = sym_off + i * entsize
        st_name, st_info, _o, st_shndx, _v, _s = struct.unpack(
            "<IBBHQQ", bytes(out[off:off + 24]))
        syms.append((st_name, st_info, st_shndx))

    # 受保护字节区间: 任何被 SHN_UNDEF 符号引用的名字(内核/框架导入, 加载期按名
    # 解析), 以及 ALWAYS_PROTECT_NAMES 边界符号。必须用【字节级区间】保护, 而非仅
    # 按 st_name 偏移: ELF .strtab 存在后缀共享(suffix sharing), 一个"定义于真实节"
    # 的符号名可能在字节上【包含】某个 UNDEF 名字(如 task_struct_offset 作为更长名
    # 的后缀, 二者共用同一段字节)。若整段覆盖式随机化该定义名, 会连带改写 UNDEF 名
    # 的字节 -> 加载期 symbol_lookup_name 失败。故凡名字字节与受保护字节重叠者一律跳过。
    protected_offsets = set()
    for st_name, st_info, st_shndx in syms:
        if st_name == 0:
            continue
        if st_shndx == ELF_SHN_UNDEF:
            protected_offsets.add(st_name)
        elif str_at(st_name) in ALWAYS_PROTECT_NAMES:
            protected_offsets.add(st_name)

    protected_bytes = set()
    for p in protected_offsets:
        end = strtab.find(b"\x00", p)
        if end < 0:
            end = str_size - 1
        protected_bytes.update(range(p, end + 1))   # 含结尾 NUL

    # 候选偏移 -> 名字长度(去重: 同偏移只改一次)
    targets = {}
    for st_name, st_info, st_shndx in syms:
        if st_name == 0:
            continue
        if not (1 <= st_shndx < e_shnum):      # 只要"定义于真实节"的
            continue
        stt = st_info & 0xF
        if stt not in (ELF_STT_NOTYPE, ELF_STT_OBJECT, ELF_STT_FUNC):
            continue
        nm = str_at(st_name)
        if not nm or nm.startswith("$"):        # 跳过 $x/$d 映射标记符
            continue
        # 逐字节随机化: 只擦除【未被保护】的名字节字节。后缀共享时(如
        # g_gyro_hook 的 "hook"、kf_task_struct_offset 的 "task_struct_offset"
        # 恰为受保护导入), 保留被保护后缀, 仅擦除可辨识前缀 —— 既隐藏业务意图,
        # 又绝不破坏加载期 symbol_lookup_name(受保护字节一字节不动)。
        free = [i for i in range(len(nm)) if (st_name + i) not in protected_bytes]
        if not free:
            continue                            # 整名皆受保护 -> 保留明文
        targets[st_name] = free

    rnd = random.Random((seed ^ (len(data) * 0x9E3779B1)) & 0xFFFFFFFF)
    for nameoff, free in targets.items():
        base = str_off + nameoff
        for i in free:
            out[base + i] = ord(rnd.choice(NAME_CHARS))
    print("[kpm_armor] scrambled %d defined symbol name(s) (protect %d offset(s))"
          % (len(targets), len(protected_offsets)))
    return bytes(out), len(targets)


def resolve_encrypt_key(args_key, keys_dir):
    """决定整节区加密所用密钥, 严格与编译期生成的 LH_armor_keys.h 一致:
       1) 显式 --key  -> 直接用(高级/手工覆盖);
       2) 否则读 .armor_keys 旁证的 str_key(与本次构建碎片同源);
       3) 否则从 LH_armor_keys.h 碎片逆还原 str_key(旁证丢失时的兜底);
       4) 都没有 -> DEFAULT_KEY(仅用于 NOARMOR/未加密的历史产物)。"""
    if args_key is not None:
        return args_key
    import os
    side = os.path.join(keys_dir, KEYS_SIDECAR)
    if os.path.exists(side):
        kv = {}
        with open(side, "r", encoding="latin1") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    kv[k] = int(v, 16)
        if "str_key" in kv:
            return kv["str_key"]
    hdr = os.path.join(keys_dir, KEYS_HEADER)
    if os.path.exists(hdr):
        k1, _p1 = parse_keys_header(hdr)
        return str_key_from_pieces(k1)
    return DEFAULT_KEY


def main():
    import os
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--file")
    ap.add_argument("-o", "--out")
    ap.add_argument("--key", type=lambda x: int(x, 0), default=None,
                    help="显式整节区加密种子; 省略则自动与编译期生成的密钥碎片一致")
    ap.add_argument("--no-fix-syms", action="store_true")
    ap.add_argument("--no-scramble-syms", action="store_true",
                    help="关闭定义符号名等长随机化(默认开启: 隐藏内部符号名)")
    ap.add_argument("--gen-keys", metavar="DIR",
                    help="生成随机密钥并写出 DIR/%s 与 DIR/%s, 完成后退出"
                         % (KEYS_HEADER, KEYS_SIDECAR))
    ap.add_argument("--seed", type=lambda x: int(x, 0), default=None,
                    help="密钥生成确定性种子(仅用于生成默认头/自测; 正式构建省略=系统熵随机)")
    ap.add_argument("--keys-dir", default=None,
                    help="存放 LH_armor_keys.h/.armor_keys 的目录(默认取 -f 所在目录)")
    args = ap.parse_args()

    if args.gen_keys:
        rng = random.Random(args.seed) if args.seed is not None else None
        emit_keys_header(args.gen_keys, rng=rng)
        return

    if not args.file or not args.out:
        ap.error("-f/--file 与 -o/--out 为加密阶段必填(或使用 --gen-keys)")
    keys_dir = args.keys_dir or os.path.dirname(os.path.abspath(args.file)) or "."
    key = resolve_encrypt_key(args.key, keys_dir)
    with open(args.file, "rb") as f:
        data = f.read()
    data, n = process(data, key, fix_syms=not args.no_fix_syms,
                      scramble=not args.no_scramble_syms)
    with open(args.out, "wb") as f:
        f.write(data)
    print("[kpm_armor] done: %d bytes encrypted (key=0x%016X)" % (n, key))


if __name__ == "__main__":
    main()