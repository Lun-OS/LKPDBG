/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpmvm.h -- KPM 函数虚拟化(VM)解释器 (Step 3 : VMP 级加固)
 *
 * 目的: 把敏感函数从 .text 中的可读机器码, 替换为"通用解释器 + 加密字节码"。
 *       静态分析(IDA/反汇编)在产物中只能看到:
 *          1) 一段通用的 kpmvm_run 解释器(对所有函数都一样, 无业务语义);
 *          2) .rodata 中按指令逐一流式加密的字节码(明文操作码/立即数不出现)。
 *       原始 C 逻辑(比较/分支/计算)被"编码"进字节码, 不再直接可见。
 *
 * 约束(与 KPM 加载/隐蔽性要求一致, self-contained):
 *   - 状态机只用寄存器与栈, 运算仅 位移/XOR/加乘/比较/分支, 全部是
 *     AArch64 基本指令, 绝不生成 libgcc (aeabi/__div/__mul) 或 __atomic/__sync
 *     调用(这些符号不在 KernelPatch 导出表 -> KPM 加载 unknown symbol)。
 *   - 字节码与指令读取都经 volatile, 解释器 noinline: 防止编译器常量折叠
 *     还原出明文逻辑。
 *   - 每一条指令字 = plain ^ keystream(pc), keystream 用 SplitMix64 常数
 *     逐字递推, 与 tools/kmvm_asm.py 的加密严格互逆。种子 KPMVM_SEED 由
 *     汇编器生成进 vm_prog.h, 每条虚拟函数独立。
 *
 * 寄存器机抽象(每函数): x0..x7 (u64), pc(字节码字下标), Z/C(N,S 未用)。
 *   指令字布局 (1 x u64):
 *     [7:0]   op
 *     [12:8]  dst
 *     [17:13] src1
 *     [22:18] src2
 *     [23]    wi   (1=下一条字是 64-bit 立即数操作元)
 *     [31:24] cond (BC 分支条件: 0 eq 1 ne 2 gt 3 ge 4 lt 5 le)
 *   有大立即数(MOVI/ADDI/SUBI/BR/BC)时, 紧接着的一个 u64 字作为操作元。
 *   分支立即数 = 字节码绝对字下标。
 *
 * 用法:
 *   #include <kpmvm.h>
 *   #include "vm_prog.h"          // tools/kmvm_asm.py 生成
 *   u64 r = kpmvm_run(vm_code, vm_code_n, KPMVM_SEED, 0);
 *   // 入参: 先把参数塞进 x0..x7 再调用(见 kpmvm_init_args)
 */
#ifndef _KP_KPMVM_H_
#define _KP_KPMVM_H_

#define KPMVM_REG	8u

/* 字节码内子程序调用栈深度 */
#define KPMVM_DEPTH	16u

/* 操作码 */
enum {
	VM_MOV2 = 0x01,	/* r[dst] = r[src1] */
	VM_MOVI = 0x02,	/* r[dst] = imm(wi)         */
	VM_ADD  = 0x03,	/* r[dst] = r[src1] + r[src2] */
	VM_ADDI = 0x04,	/* r[dst] = r[src1] + imm(wi) */
	VM_SUB  = 0x05,	/* r[dst] = r[src1] - r[src2] */
	VM_SUBI = 0x06,	/* r[dst] = r[src1] - imm(wi) */
	VM_AND  = 0x07,	/* r[dst] = r[src1] & r[src2] */
	VM_ORR  = 0x08,	/* r[dst] = r[src1] | r[src2] */
	VM_EOR  = 0x09,	/* r[dst] = r[src1] ^ r[src2] */
	VM_LSL  = 0x0A,	/* r[dst] = r[src1] << (r[src2]&63) */
	VM_LSR  = 0x0B,	/* r[dst] = r[src1] >> (r[src2]&63) */
	VM_LDD  = 0x0C,	/* r[dst] = *(volatile unsigned long long *)r[src1] */
	VM_STO  = 0x0D,	/* *(volatile unsigned long long *)r[src1] = r[src2] */
	VM_CMP  = 0x0E,	/* Z/C = cmp(r[src1], r[src2])  (无符号) */
	VM_BR   = 0x0F,	/* pc = imm(wi)(绝对字下标) */
	VM_BC   = 0x10,	/* if cond: pc = imm(wi) */
	VM_RET  = 0x11,	/* 结束解释, 返回 r[0] */
	VM_CALL = 0x12,	/* 子程序调用: 压入返回址, pc = imm(wi) */
	VM_RSUB = 0x13,	/* 子程序返回: pc = 出栈; 栈空则返回 r[0] */
	VM_ANDI = 0x14,	/* r[dst] = r[src1] & imm(wi) */
	VM_ORRI = 0x15,	/* r[dst] = r[src1] | imm(wi) */
	VM_EORI = 0x16,	/* r[dst] = r[src1] ^ imm(wi) */
	VM_NOT  = 0x17,	/* r[dst] = ~r[src1] */
	VM_NEG  = 0x18,	/* r[dst] = -r[src1] */
	VM_LSLI = 0x19,	/* r[dst] = r[src1] << (imm&63)(wi) */
	VM_LSRI = 0x1A,	/* r[dst] = r[src1] >> (imm&63)(wi) */
	VM_MAX_OP = 0x1A,
};

/* BC 条件(取低 8 位 CD 编码) */
enum {
	VM_C_EQ = 0, VM_C_NE = 1, VM_C_GT = 2, VM_C_GE = 3,
	VM_C_LT = 4, VM_C_LE = 5,
};

/* SplitMix64 常量: 与 kmvm_asm.py 保持完全一致 */
#define KPMVM_MUL		0x5851F42D4C957F2Dull
#define KPMVM_ADD		0x14057B7EF767814Full

/*
 * 单步解码后的指令(结构体避免重复移位, 代码可读性优先)。
 */
struct kpmvm_insn {
	unsigned int op;
	unsigned int dst, s1, s2, cond, wi;
	unsigned long long imm;
};

/*
 * 逐字索引密钥: 密钥只由 (字下标 idx, 种子 seed) 决定, 与执行路径/跳转无关,
 * 从而解释器与汇编器(tools/kmvm_asm.py 的 stream_encrypt) 严格互逆。
 * 纯 64-bit 移位/乘/加/XOR, 无 libgcc。
 */
static inline unsigned long long kpmvm_key(unsigned long idx,
					   unsigned long long seed)
{
	return seed ^ (((unsigned long long)idx + 1u) * KPMVM_MUL +
		       ((unsigned long long)idx + 2u) * KPMVM_ADD);
}

/*
 * 解码第 idx 个字, 返回明文指令字。
 */
static inline unsigned long long kpmvm_decode(
	const volatile unsigned long long *code, unsigned long idx,
	unsigned long long seed)
{
	return code[idx] ^ kpmvm_key(idx, seed);
}

/*
 * 解释一个从 (decoded word w) 得到的指令。
 * 返回 0 正常, 0xFFFFFFFF 表示非法操作码。
 */
static inline unsigned int kpmvm_insn_decode(const unsigned long long w,
					     struct kpmvm_insn *ins)
{
	ins->op   = (unsigned int)(w & 0xffu);
	ins->dst  = (unsigned int)((w >> 8)  & 0x1fu);
	ins->s1   = (unsigned int)((w >> 13) & 0x1fu);
	ins->s2   = (unsigned int)((w >> 18) & 0x1fu);
	ins->wi   = (unsigned int)((w >> 23) & 0x1u);
	ins->cond = (unsigned int)((w >> 24) & 0xffu);
	ins->imm  = 0ULL;
	return ins->op <= VM_MAX_OP ? 0 : 0xFFFFFFFFu;
}

/*
 * 解释执行入口。
 *   code : 加密字节码(来自 vm_prog.h)
 *   nwords: 字节码字总数(含立即数字)
 *   seed : KPMVM_SEED (字节码解密流种子)
 *   entry: 起始字下标(通常 0)
 *   inr  : 可选入参寄存器集合(长度>=8; 传 NULL 则全 0)。
 *          宿主把函数实参/指针按 x0..x7 约定放入即可。
 * 返回 r[0]。
 */
static __attribute__((noinline)) unsigned long long
kpmvm_run(const volatile unsigned long long *code, unsigned long nwords,
	  unsigned long long seed, unsigned long entry,
	  const unsigned long long *inr)
{
	unsigned long long r[KPMVM_REG] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned long long vst[KPMVM_DEPTH];
	unsigned long vsp = 0;
	unsigned long pc = entry;
	unsigned z = 0, c = 0;
	unsigned i;

	if (inr)
		for (i = 0; i < KPMVM_REG; i++)
			r[i] = inr[i];

	while (pc < nwords) {
		unsigned long long w = kpmvm_decode(code, pc, seed);
		struct kpmvm_insn ins;
		unsigned long long a, b, t;

		pc += 1;	/* 至少消耗本指令字 */
		if (kpmvm_insn_decode(w, &ins) != 0)
			break;	/* 非法操作码: 防御性退出 */

		if (ins.wi) {			/* 附加 64-bit 操作元 */
			ins.imm = kpmvm_decode(code, pc, seed);
			pc += 1;
		}

		a = r[ins.s1 & (KPMVM_REG - 1)];
		b = r[ins.s2 & (KPMVM_REG - 1)];

		switch (ins.op) {
		case VM_MOV2:
			r[ins.dst & (KPMVM_REG - 1)] = a;
			break;
		case VM_MOVI:
			r[ins.dst & (KPMVM_REG - 1)] = ins.imm;
			break;
		case VM_ADD:
			r[ins.dst & (KPMVM_REG - 1)] = a + b;
			break;
		case VM_ADDI:
			r[ins.dst & (KPMVM_REG - 1)] = a + ins.imm;
			break;
		case VM_SUB:
			r[ins.dst & (KPMVM_REG - 1)] = a - b;
			break;
		case VM_SUBI:
			r[ins.dst & (KPMVM_REG - 1)] = a - ins.imm;
			break;
		case VM_AND:
			r[ins.dst & (KPMVM_REG - 1)] = a & b;
			break;
		case VM_ORR:
			r[ins.dst & (KPMVM_REG - 1)] = a | b;
			break;
		case VM_EOR:
			r[ins.dst & (KPMVM_REG - 1)] = a ^ b;
			break;
		case VM_LSL:
			r[ins.dst & (KPMVM_REG - 1)] = a << (b & 63u);
			break;
		case VM_LSR:
			r[ins.dst & (KPMVM_REG - 1)] = a >> (b & 63u);
			break;
		case VM_LDD:
			r[ins.dst & (KPMVM_REG - 1)] =
				*((volatile unsigned long long *)(unsigned long)a);
			break;
		case VM_STO:
			*((volatile unsigned long long *)(unsigned long)a) = b;
			break;
		case VM_CMP:
			t = a - b;
			z = (t == 0) ? 1u : 0u;
			c = (a >= b) ? 1u : 0u;	/* 无符号 >= -> 无借位 */
			break;
		case VM_BR:
			pc = (unsigned long)ins.imm;
			break;
		case VM_BC: {
			int take = 0;
			switch (ins.cond & 0x7u) {
			case VM_C_EQ: take = z; break;
			case VM_C_NE: take = !z; break;
			case VM_C_GT: take = c && !z; break;
			case VM_C_GE: take = c; break;
			case VM_C_LT: take = !c; break;
			case VM_C_LE: take = !c || z; break;
			default:      take = 0; break;
			}
			if (take)
				pc = (unsigned long)ins.imm;
			}
			break;
		case VM_CALL:			/* 子程序调用(可嵌套, 深度受限) */
			if (vsp < KPMVM_DEPTH) {
				vst[vsp++] = pc;
				pc = (unsigned long)ins.imm;
			}
			break;
		case VM_RSUB:			/* 子程序返回 */
			if (vsp)
				pc = (unsigned long)vst[--vsp];
			else
				return r[0];
			break;
		case VM_ANDI:
			r[ins.dst & (KPMVM_REG - 1)] = a & ins.imm;
			break;
		case VM_ORRI:
			r[ins.dst & (KPMVM_REG - 1)] = a | ins.imm;
			break;
		case VM_EORI:
			r[ins.dst & (KPMVM_REG - 1)] = a ^ ins.imm;
			break;
		case VM_NOT:
			r[ins.dst & (KPMVM_REG - 1)] = ~a;
			break;
		case VM_NEG:
			r[ins.dst & (KPMVM_REG - 1)] = 0ULL - a;
			break;
		case VM_LSLI:
			r[ins.dst & (KPMVM_REG - 1)] = a << (ins.imm & 63u);
			break;
		case VM_LSRI:
			r[ins.dst & (KPMVM_REG - 1)] = a >> (ins.imm & 63u);
			break;
		case VM_RET:
			return r[0];
		default:
			break;	/* 防御: 忽略 */
		}
	}
	return r[0];
}

/*
 * 便捷: 初始化入参寄存器 x[v] = value, v < KPMVM_REG。
 */
static inline void kpmvm_set_arg(unsigned long long *r, unsigned int v,
				 unsigned long long value)
{
	if (v < KPMVM_REG)
		r[v] = value;
}

#endif /* _KP_KPMVM_H_ */