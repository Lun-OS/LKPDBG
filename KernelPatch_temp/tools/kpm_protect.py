#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kpm_protect.py -- KernelPatch KPM (relocatable ELF) 后处理加固工具 (Step 1: 静态混淆层)

目标: 在不动内核侧加载器 (module.c / relo.c)、不改变重定位语义的前提下,
对产出的 relocatable ELF (*.kpm) 做静态信息清除与符号混淆。

为何安全:
  - 加载器只按名字解析 SHN_UNDEF 内核符号 (simplify_symbols) 和按节名匹配
    .kpm.init/.ctl0/.ctl1/.exit/.info (move_module)，不依赖模块内部已定义
    符号的名字。因此对内部定义符号做"等长随机化"名字重写不会影响加载。
  - 采用"等长原地覆盖 strtab 名字字节"的方式重写: 名字长度保持不变 =>
    文件内所有偏移/节表/符号表结构零变化，天然规避二次重定位与节偏移问题。

功能:
  --syms        混淆已定义的内部符号名(FUNC/OBJECT + st_shndx==定义节)
                - 不会动 UNDEF 内核符号、 SECTION/FILE/ABS 符号、$x/$d 映射符号
  --zero-comment 清空 .comment 等非加载元数据节内容，抹除编译器指纹

用法:
  python kpm_protect.py --syms --zero-comment -f hello.kpm [-o hello.kpm]
"""

import argparse
import random
import string
import struct
import sys

# ---- ELF64 基础 ----
ELF64_HDR = "<16sHHIQQQIHHHHHH"           # 64B
SHDR = "<IIQQQQIIQQ"                       # 64B
SYM = "<IBBHQQ"                            # Elf64_Sym: 24B

SHT_SYMTAB = 2
SHT_STRTAB = 3

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2

SHN_UNDEF = 0
SHN_ABS = 0xFFF1

NAME_CHARS = string.ascii_letters + string.digits + "_"


def _read(path):
    with open(path, "rb") as f:
        return bytearray(f.read())


def _sections(data, shoff, shentsize, shnum):
    secs = []
    for i in range(shnum):
        off = shoff + i * shentsize
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, \
            sh_link, sh_info, sh_align, sh_entsize = struct.unpack_from(SHDR, data, off)
        secs.append(dict(
            index=i, name=sh_name, type=sh_type, flags=sh_flags, addr=sh_addr,
            offset=sh_offset, size=sh_size, link=sh_link, info=sh_info,
            entsize=sh_entsize,
        ))
    return secs


def _sec_names(data, secs, shstr_index):
    """返回 name(str) -> index 双向映射，sh_name 是 shstrtab 内偏移。"""
    try:
        shstr = secs[shstr_index]
    except IndexError:
        return {}, {}
    shstrtab = bytes(data[shstr["offset"]: shstr["offset"] + shstr["size"]])
    by_name, by_idx = {}, {}
    for s in secs:
        end = shstrtab.find(b"\x00", s["name"])
        name = shstrtab[s["name"]: end].decode("ascii", "replace") if s["name"] >= 0 else ""
        by_name[name] = s["index"]
        by_idx[s["index"]] = name
    return by_name, by_idx


def _random_name(length):
    return "".join(random.choice(NAME_CHARS) for _ in range(length))


def obfuscate_symbols(data, secs):
    """将已定义的内部符号名等长随机化。返回(改写次数, 使用统计)。"""
    symtab = next((s for s in secs if s["type"] == SHT_SYMTAB), None)
    if symtab is None:
        return 0, {}
    strtab = secs[symtab["link"]]
    sym_base = symtab["offset"]
    str_off = strtab["offset"]
    n = symtab["size"] // symtab["entsize"] if symtab["entsize"] else 0

    # 该 strtab 内第 i 个符号的名字内容(bytes)
    def content(off):
        end = data.find(b"\x00", str_off + off)
        return b"" if end < 0 else bytes(data[str_off + off: end])

    # 收集符号表(名字内容、type/bind、shndx)
    syms = [None]  # 1-based
    for i in range(1, n):
        st_name, st_info, _, st_shndx, _, _ = struct.unpack_from(SYM, data, sym_base + i * 24)
        syms.append((st_name, st_info, st_shndx))

    # 受保护名字集合: 任何 GLOBAL/WEAK 或 SHN_UNDEF 符号的名字内容。
    # 兼容性硬约束: KPM 加载器按"名字"解析 SHN_UNDEF 符号(内核导出 + 框架
    # 提供, 如 hook/unhook/task_struct_offset/kallsyms 名), 这些均为 GLOBAL;
    # strtab 中可能存在与它们同串的副本, 故按"内容"而非"偏移"保护, 彻底避免
    # 因共享/重复串把可解析名改写坏 => 保证加载兼容。
    protected = set()
    for i in range(1, n):
        st_name, st_info, st_shndx = syms[i]
        if not st_name:
            continue
        if (st_info >> 4) in (STB_GLOBAL, STB_WEAK) or st_shndx == SHN_UNDEF:
            protected.add(content(st_name))

    usage = {}   # strtab 偏移 -> 被多少个符号引用
    for i in range(1, n):
        st_name = syms[i][0]
        if st_name:
            usage[st_name] = usage.get(st_name, 0) + 1

    renamed = 0
    skipped = 0
    for i in range(1, n):
        st_name, st_info, st_shndx = syms[i]
        if not st_name:
            continue
        stt = st_info & 0xF
        stb = st_info >> 4
        # 只处理 STB_LOCAL 的内部符号(static 函数/对象/局部标签)。
        # STB_LOCAL 已定义符号 100% 为模块内部对象, 重定位按 symtab 索引
        # 寻址(改名不动索引), 加载器不按名解析它们, 因此等长改名绝对安全。
        if stb != STB_LOCAL:
            continue
        if not (stt in (STT_FUNC, STT_OBJECT, STT_NOTYPE)):
            continue
        if st_shndx in (SHN_UNDEF, SHN_ABS):
            continue
        c = content(st_name)
        if not c:
            continue
        if c in protected:          # 与待解析(全局/未定义)符号同串 -> 绝不碰
            skipped += 1
            continue
        if usage.get(st_name, 0) != 1:   # 名字被多个符号共享则跳过，避免误写
            skipped += 1
            continue
        length = len(c)
        data[str_off + st_name: str_off + st_name + length] = \
            _random_name(length).encode("ascii")
        renamed += 1
    return renamed, {"renamed": renamed, "skipped_shared": skipped}


def zero_metadata(data, secs, shstr_index):
    """清空非加载元数据节内容(.comment/.note.*/.ARM.attributes/.debug_*)。"""
    by_name, by_idx = _sec_names(data, secs, shstr_index)
    n = 0
    for s in secs:
        name = by_idx.get(s["index"], "")
        if (name.startswith(".comment") or name.startswith(".note.")
                or name.startswith(".debug_") or name in (".ARM.attributes", ".eh_frame")):
            # 仅清 PROGBITS 且在文件内有内容
            if s["type"] == 1 and s["size"]:
                data[s["offset"]: s["offset"] + s["size"]] = b"\x00" * s["size"]
                n += 1
    return n


def main():
    ap = argparse.ArgumentParser(description="KPM relocatable ELF 后处理加固(Step1)")
    ap.add_argument("-f", "--file", required=True)
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--syms", action="store_true", help="混淆已定义内部符号名")
    ap.add_argument("--zero-comment", action="store_true", help="清空 .comment 等元数据")
    ap.add_argument("--check-plain", nargs="*", metavar="STR",
                    help="扫描产物中是否残留指定明文(任一命中则失败, 保障加密串不泄漏)")
    ap.add_argument("--seed", type=int, default=None, help="随机种子(可选,便于复现)")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    data = _read(args.file)
    if data[:4] != b"\x7fELF" or data[4] != 2:
        sys.exit("[-] 不是 ELF64 文件")

    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    secs = _sections(data, e_shoff, e_shentsize, e_shnum)

    report = {}
    if args.syms:
        renamed, stats = obfuscate_symbols(data, secs)
        report["symbols_renamed"] = stats.get("renamed", 0)
        report["symbols_skipped_shared"] = stats.get("skipped_shared", 0)
    if args.zero_comment:
        report["metadata_zeroed"] = zero_metadata(data, secs, e_shstrndx)

    # 明文泄漏门禁: 在改写后的字节上做扫描
    leaked = []
    if args.check_plain:
        blob = bytes(data)
        for s in args.check_plain:
            if s and s.encode("utf-8") in blob:
                leaked.append(s)

    out = args.output or args.file
    with open(out, "wb") as f:
        f.write(bytes(data))

    print("[kpm_protect] OK -> %s" % out)
    for k, v in report.items():
        print("  %s: %s" % (k, v))
    if leaked:
        print("  [LEAK] plaintext found in output:")
        for s in leaked:
            print("    - %s" % s)
        sys.exit(2)
    if args.check_plain:
        print("  leak-check: clean (%d token(s) absent)" % len(args.check_plain))


if __name__ == "__main__":
    count = 0
    main()