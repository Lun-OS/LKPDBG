/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_armor.h — KPM 深度加固运行侧接口
 *
 * 提供三类内存态对抗原语, 与 tools/kpm_armor.py / LH_main.lds 配套:
 *   1) kpm_armor_init : init 首句原地解密 .kpm.str (字符串整节区密文化)。
 *   2) kpm_armor_seal : init 末尾整段抹零 .kpm.once (一次性符号解析代码)。
 *   3) (可选, 宏门控) 运行时擦除 .strtab/.symtab。
 *
 * 约束: 全部只用 XOR/移位/缓存与屏障指令, 不生成 libgcc (__aarch64 系/__atomic 系)
 *       调用; 就地操作、单次 pass、无静态缓冲, 线程安全。
 *
 * 用法: 只改两处主入口——
 *       kpm_drv_init 首句加  kpm_armor_init();
 *       kpm_drv_init 末尾加 kpm_armor_seal();
 */
#ifndef _LH_ARMOR_H_
#define _LH_ARMOR_H_

/* 构建期随机生成的混淆密钥碎片。真实密钥从不以字面量出现, 此处仅存变形碎片
 * KPM_STR_K1 / KPM_PTR_K1。每次正式构建由 kpm_armor.py --gen-keys 覆盖重生成;
 * NOARMOR 回退时使用仓库内提交的默认值。切勿手改。 */
#include "LH_armor_keys.h"

/* ===== 密钥"伪装成代码"的多层还原(编译期防折叠) =====
 * 运行侧从碎片出发, 经内联汇编 ror/eor/add 逐层逆还原真实密钥。用 asm 是为
 * 阻断编译器在 -O2 下把 rotr17(K1)^KDM 折叠回原始密钥字面量(否则 mov/movk 复现)。
 * 盲化掩码 KPM_KDM 由节内既有的合法 SplitMix64 常量派生(= KPENC_MUL ^ KPENC_ADD),
 * 单独看像普通加密代码, objdump/IDA 搜不到任何密钥字面量。 */
#define KPM_KDM 0x4C548F53BBF2FE62ull /* = KPENC_MUL ^ KPENC_ADD, 非密钥本身 */
#define KSTR_S1 0x0000000000051528ull /* 字符串密钥第 3 层加数(仅混淆) */
#define KSTR_S2 0x0000000000003A17ull /* 字符串密钥第 2 层异或数(仅混淆) */
#define KSTR_B  23                    /* 字符串密钥旋转量兼第 4 层加数 */

/* 整节区字符串密钥还原(3 层)。str_encode 的严格逆:
 * d=rotr23(K1); c=d+KSTR_B; b=c^KSTR_S2; a=b+KSTR_S1; u=a^KDM; s=rotl17(u)。
 * 必须内联进 kpm_armor_init(.kpm.once), 使密钥碎片随区抹零; asm 非 volatile
 * => 编译器可上提/CSE 但不能跨 asm 折叠回原始密钥字面量。 */
static __attribute__((always_inline)) inline unsigned long long kp_str_key(void)
{
    unsigned long k = (unsigned long)KPM_STR_K1;
    asm("ror %0, %0, #23\n\t"
        "add %0, %0, %1\n\t"
        "eor %0, %0, %2\n\t"
        "add %0, %0, %3\n\t"
        "eor %0, %0, %4\n\t"
        "ror %0, %0, #47"
        : "+r"(k)
        : "r"((unsigned long)KSTR_B), "r"((unsigned long)KSTR_S2),
          "r"((unsigned long)KSTR_S1), "r"((unsigned long)KPM_KDM));
    return (unsigned long long)k;
}

/* 关键函数指针密钥还原(2 层): p = rotr17(KPM_PTR_K1) ^ KPM_KDM。
 * 内联 + 非 volatile asm: 编译器把这段寄存器还原上提到函数序言(每个用点一次),
 * 循环访存中不重复, 且无法折叠回原始密钥 => 热路径仅多 ror+eor, 访存性能不受影响。 */
static __attribute__((always_inline)) inline unsigned long kp_ptr_key(void)
{
    unsigned long k = (unsigned long)KPM_PTR_K1;
    unsigned long m = (unsigned long)KPM_KDM;
    asm("ror %0, %0, #17\n\t"
        "eor %0, %0, %1"
        : "+r"(k)
        : "r"(m));
    return k;
}


/* ===== 可选开关(逐层关闭重编即可回退) ===== */
/* 抹零 .kpm.once 一次性代码区 */
#define KP_ARMOR_ONCE 1
/* 加密 .kpm.str(与构建期 kpm_armor.py 配套, 关闭它则产物密文无法解密, 勿关) */
#define KP_ARMOR_STR  1

void kpm_armor_init(void);
void kpm_armor_seal(void);

/* 内部: 就地解密 region; key 与工具侧种子一致 */
void kp_armor_decrypt_region(void *base, unsigned long size, unsigned long long key);

/* ===== 关键函数指针静止态密文化 =====
 * 高价值函数指针(内核内存读写/映射原语)不再直接存地址, 而存 addr^KEY。
 * 存储槽是普通 unsigned long(位于 .data, 与 once 代码区独立), dump 只见密文。
 * 语义约定: 槽 0 == 未解析; 读取时 slot?slot^KEY:0 还原真地址(未解析仍得 0)。
 * 因此既有调用点 kf_X(...) 与可用性守卫 !kf_X / kf_X!=0 全部零改动、语义不变。
 * 密钥由 kp_ptr_key() 从碎片 KPM_PTR_K1 运行期还原(见上)。
 * 仅 eor/三目 + 两条寄存器还原指令, 无 libgcc。设值(kp_ptr_set)只出现在
 * kpm_syms_init(.kpm.once), init 末尾随 once 区一起抹零。 */

/* 槽 -> 真地址(未解析槽 0 还原为 0) */
#define kp_ptr_dec(s) ((s) ? ((unsigned long)(s) ^ kp_ptr_key()) : 0UL)
/* 地址(或 0) -> 密文槽(0 保持 0) */
#define kp_ptr_enc(a) ((a) ? ((unsigned long)(a) ^ kp_ptr_key()) : 0UL)
/* 写入密文槽 */
#define kp_ptr_set(slot, addr) (*(slot) = kp_ptr_enc(addr))

#endif /* _LH_ARMOR_H_ */