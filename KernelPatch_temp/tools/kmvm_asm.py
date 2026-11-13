#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kmvm_asm.py -- KPM VM 字节码汇编器 (Step 3 : VMP 加固)

把一个自定义汇编清单(*.vm)汇编成加密字节码, 输出 C 头文件 vm_prog.h,
其中每条指令的字与解释器(kernel/include/kpmvm.h 的 kpmvm_run) 用同一
SplitMix64 流式密钥逐字互逆加密 -- 明文操作码/立即数不直接出现在产物。

语法(每行, '#' 注释):
  label:                      ; 标签定义
  mov r0, r1                 ; r0 = r1
  mov r0, #123                ; r0 = imm (64-bit, 之后跟一个字)
  add r0, r1, r2              ; r0 = r1 + r2
  add r0, r1, #100            ; r0 = r1 + imm
  sub/and/orr/eor 同 add
  lsl r0, r1, r2
  lsr r0, r1, r2
  ldd r0, [r1]                ; r0 = mem[r1]
  sto [r1], r2                ; mem[r1] = r2
  cmp r0, r1                  ; Z/C = (r0 - r1) 无符号比较
  br label                    ; 相对跳转到 label
  bc eq, label                ; 条件跳转; 条件: eq ne gt ge lt le
  ret                         ; return r0

寄存器只能 r0..r7。汇编器两遍: 第一遍收录标签偏移(以"字"计),
第二遍生成指令字(含紧跟的 64-bit 立即数字)并流式加密。

用法:
  python kmvm_asm.py --in hello.vm --out vm_prog.h [--seed 0x1234]

输出提供:
  static const volatile unsigned long long vm_code[] ...  加密字节码
  #define vm_code_n  <字数>
  #define KPMVM_SEED <种子>
"""

import argparse
import re
import sys

MUL = 0x5851F42D4C957F2D
ADD = 0x14057B7EF767814F

VM_MOV2 = 0x01
VM_MOVI = 0x02
VM_ADD = 0x03
VM_ADDI = 0x04
VM_SUB = 0x05
VM_SUBI = 0x06
VM_AND = 0x07
VM_ORR = 0x08
VM_EOR = 0x09
VM_LSL = 0x0A
VM_LSR = 0x0B
VM_LDD = 0x0C
VM_STO = 0x0D
VM_CMP = 0x0E
VM_BR = 0x0F
VM_BC = 0x10
VM_RET = 0x11
VM_CALL = 0x12
VM_RSUB = 0x13
VM_ANDI = 0x14
VM_ORRI = 0x15
VM_EORI = 0x16
VM_NOT = 0x17
VM_NEG = 0x18
VM_LSLI = 0x19
VM_LSRI = 0x1A

COND = {"eq": 0, "ne": 1, "gt": 2, "ge": 3, "lt": 4, "le": 5}

BINARY = {"add": VM_ADD, "sub": VM_SUB, "and": VM_AND,
          "orr": VM_ORR, "eor": VM_EOR, "lsl": VM_LSL, "lsr": VM_LSR}
# 立即数形式: 用 'X  rY, rZ, #imm' (2 字) 编码
IMM_OP = {"addi": VM_ADDI, "subi": VM_SUBI, "andi": VM_ANDI, "orri": VM_ORRI,
          "eori": VM_EORI, "lsli": VM_LSLI, "lsri": VM_LSRI}
# 单寄存器形式: 'not rX, rY' / 'neg rX, rY' (1 字)
UNARY = {"not": VM_NOT, "neg": VM_NEG}

RE_OP = re.compile(r"^\s*([a-z0-9]+)\s*(.*?)\s*$")
RE_REG = re.compile(r"^r([0-7])$")
RE_IMM = re.compile(r"^#(0x[0-9a-fA-F]+|\d+)$")


def _label_name(line):
    """识别标签定义。仅 'name:' 或 ':name' 算标签; 裸 'ret' 等不算。"""
    s = line.strip()
    if s.endswith(":") and re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", s[:-1].strip()):
        return s[:-1].strip()
    if s.startswith(":") and re.fullmatch(r":\s*[a-zA-Z_][a-zA-Z0-9_]*", s):
        return s[1:].strip()
    return None


def _imm(v):
    return int(v, 0) if v.lower().startswith("0x") else int(v, 10)


def _enc_imm(text):
    m = RE_IMM.match(text)
    if not m:
        return None
    return _imm(m.group(1))


class AsmError(Exception):
    pass


def parse(path):
    """第一遍: 解析行, 记录指令并为标签收集字偏移。返回 (oplist, labels)。"""
    oplist = []
    labels = {}
    words = 0
    with open(path, "r", encoding="utf-8") as f:
        for ln, raw in enumerate(f, 1):
            # '#' 在行首=整行注释; 内联注释仅用 ';'; 保留 '#' 供立即数 #imm
            if raw.lstrip().startswith("#"):
                continue
            line = re.split(r"[;]", raw, 1)[0].strip()
            if not line:
                continue
            name = _label_name(line)
            if name is not None:
                labels.setdefault(name, words)
                continue
            m = RE_OP.match(line)
            if not m:
                raise AsmError("%s:%d 无法解析: %s" % (path, ln, raw.strip()))
            op, rest = m.group(1), m.group(2).strip()
            fields = [t.strip() for t in re.split(r"[,\s]+", rest) if t.strip()]
            oplist.append((op, fields, ln))

            # 指令占据的字数(与 encode() 完全一致)
            n = 1
            if op in ("br", "bc", "call"):
                n = 2
            elif op in ("mov",):
                n = 2 if fields and len(fields) > 1 and \
                    _enc_imm(fields[1]) is not None else 1
            elif op in IMM_OP:
                n = 2   # 恒需 64-bit 立即数字
            else:
                n = 1   # rsub/not/neg/ret 等
            words += n
    return oplist, labels, words


def encode(oplist, labels):
    """第二遍: 生成明文指令字序列。编号/字大小与解释器 kpmvm.h 一一对应。"""
    out = []

    def need(label):
        return labels.get(label.lstrip(":"), 0)

    def reg(tok, what):
        m = RE_REG.match(tok)
        if not m:
            raise AsmError("line %d: 非法寄存器 %s (%s)" % (ln, tok, what))
        return int(m.group(1))

    def imm(tok):
        if _enc_imm(tok) is None:
            raise AsmError("line %d: 需要立即数, 得到 %s" % (ln, tok))
        return _enc_imm(tok)

    for op, fields, ln in oplist:
        if op == "ret":
            out.append(VM_RET)

        elif op == "br":
            if len(fields) < 1:
                raise AsmError("line %d: br 需要标签" % ln)
            out.append(VM_BR | (1 << 23))        # wi: 下一字为跳转目标
            out.append(need(fields[0]))

        elif op == "bc":
            if len(fields) < 2 or fields[0] not in COND:
                raise AsmError("line %d: bc <cond>, <label>" % ln)
            out.append(VM_BC | (COND[fields[0]] << 24) | (1 << 23))
            out.append(need(fields[1]))

        elif op == "cmp":
            if len(fields) < 2:
                raise AsmError("line %d: cmp 需要 2 个寄存器" % ln)
            out.append(VM_CMP | (reg(fields[0], "a") << 13) |
                       (reg(fields[1], "b") << 18))

        elif op == "mov":
            if len(fields) < 2:
                raise AsmError("line %d: mov rX, #imm | rY" % ln)
            d = reg(fields[0], "dst")
            if _enc_imm(fields[1]) is not None:
                out.append(VM_MOVI | (d << 8) | (1 << 23))
                out.append(_enc_imm(fields[1]))
            else:
                out.append(VM_MOV2 | (d << 8) | (reg(fields[1], "src") << 13))

        elif op == "ldd":
            if len(fields) < 2:
                raise AsmError("line %d: ldd rX, [rY]" % ln)
            out.append(VM_LDD | (reg(fields[0], "dst") << 8) |
                       (reg(fields[1].lstrip("[").rstrip("]"), "addr") << 13))

        elif op == "sto":
            if len(fields) < 2:
                raise AsmError("line %d: sto [rX], rY" % ln)
            out.append(VM_STO | (reg(fields[0].lstrip("[").rstrip("]"), "addr") << 13) |
                       (reg(fields[1], "val") << 18))

        elif op in BINARY:            # add sub and orr eor lsl lsr: 3 regs
            if len(fields) < 3:
                raise AsmError("line %d: %s 需要 3 个寄存器" % (ln, op))
            out.append(BINARY[op] | (reg(fields[0], "dst") << 8) |
                       (reg(fields[1], "a") << 13) |
                       (reg(fields[2], "b") << 18))

        elif op == "addi" or op == "subi":   # dst, src, #imm
            if len(fields) < 3:
                raise AsmError("line %d: %s rX, rY, #imm" % (ln, op))
            base = VM_ADDI if op == "addi" else VM_SUBI
            out.append(base | (reg(fields[0], "dst") << 8) |
                       (reg(fields[1], "a") << 13) | (1 << 23))
            out.append(imm(fields[2]))

        else:
            raise AsmError("line %d: 未知指令 %s" % (ln, op))

    return out


def stream_encrypt(words, seed):
    """逐字索引密钥与 kpmvm.h 的 kpmvm_key 严格互逆:
       enc[i] = plain[i] ^ key(i, seed); key 仅由下标决定(跳转无关)。"""
    seed &= ((1 << 64) - 1)
    enc = []
    for i, w in enumerate(words):
        key = (seed ^ ((((i + 1) * MUL) + ((i + 2) * ADD)) & ((1 << 64) - 1)))
        enc.append((w & ((1 << 64) - 1)) ^ key)
    return enc


def emit_header(path, words, seed):
    n = len(words)
    enc = stream_encrypt(words, seed)
    lines = [
        "/* AUTO-GENERATED by tools/kmvm_asm.py -- do not edit */",
        "#ifndef KPMVM_PROG_H",
        "#define KPMVM_PROG_H",
        "#include <kpmvm.h>",
        "",
        "#define KPMVM_SEED 0x%016xULL" % (seed & ((1 << 64) - 1)),
        "#define vm_code_n %dUL" % n,
        "",
        "static const volatile unsigned long long vm_code[] = {",
    ]
    for i in range(0, n, 2):
        if i + 1 < n:
            lines.append("    0x%016xULL, 0x%016xULL," % (enc[i], enc[i + 1]))
        else:
            lines.append("    0x%016xULL," % enc[i])
    lines.append("};")
    lines.append("")
    lines.append("#endif /* KPMVM_PROG_H */")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    return n


def main():
    ap = argparse.ArgumentParser(description="KPM VM 字节码汇编器 (Step3)")
    ap.add_argument("--in", dest="fin", required=True, help="*.vm 汇编清单")
    ap.add_argument("--out", dest="fout", required=True, help="生成 vm_prog.h")
    ap.add_argument("--seed", type=lambda x: int(x, 0), default=0x6A09E667BB67AE8,
                    help="字节码流密钥种子(十六进制如 0x6A09...)")
    args = ap.parse_args()

    oplist, labels, nwords = parse(args.fin)
    words = encode(oplist, labels)
    n = emit_header(args.fout, words, args.seed)
    if n != nwords:
        print("[-] internal accounting mismatch %d != %d" % (n, nwords),
              file=sys.stderr)
        sys.exit(1)
    print("[kmvm_asm] OK -> %s (%d instructions / %d encoded words, labels=%d)"
          % (args.fout, len(oplist), n, len(labels)))


if __name__ == "__main__":
    main()