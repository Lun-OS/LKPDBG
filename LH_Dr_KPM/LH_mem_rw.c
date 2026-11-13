/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/err.h>   /* IS_ERR_OR_NULL */
#include <ksyms.h>
#include <kputils.h>
#include <ktypes.h>
#include <pgtable.h>   /* is_kimg_range / PTE 位 */
#include <baselib.h>   /* lib_memcpy 等 */

#include "LH_mem_rw.h"
#include "LH_utils.h"
#include "LH_comm.h"
#include "LH_syms.h"
#include "LH_log.h"

/* GFP_KERNEL 在 KPM 框架的 gfp.h 中被注释掉，此处手动定义 */
#ifndef GFP_KERNEL
#define GFP_KERNEL  0xcc0u
#endif

/* ===== 常量定义 ===== */
#define PHYS_ADDR_MASK  0x0000FFFFFFFFF000ULL  /* 48-bit PA 页地址掩码（PTE 4KB 页） */
#define PMD_BLOCK_MASK  0x0000FFFFFFFFFFE000ULL  /* 2MB 块 phys: bits[47:21] */
#define PUD_BLOCK_MASK  0x0000FFFFFC00000000ULL  /* 1GB 块 phys: bits[47:30] */
#define PAGE_SHIFT_4K   12
#define PAGE_SIZE_4K    (1ULL << PAGE_SHIFT_4K)
#define PAGE_MASK_4K    (~(PAGE_SIZE_4K - 1))

/* 分配策略分界：len 不超过阈值时用 kmalloc（slab，适合高频小读写），
 * 大块走 vmalloc（避免大块连续物理页分配失败）。 */
#define KPM_MEM_RW_KMALLOC_MAX  4096

/* kbuf 释放：与分配路径严格配对（kmalloc / vmalloc 二选一） */
static void kpm_mem_rw_kbuf_free(void *p, int is_vm)
{
    if (!p)
        return;
    if (is_vm)
        kf_vfree(p);
    else
        kf_kfree(p);
}

/* 39-bit VA 页表索引 */
#define PGD_SHIFT_39    30   /* bits [38:30] */
#define PMD_SHIFT_39    21   /* bits [29:21] */
#define PTE_SHIFT_39    12   /* bits [20:12] */
#define PGD_ENTRIES     512
#define PMD_ENTRIES     512
#define PTE_ENTRIES     512
#define PGD_MASK_39     (PGD_ENTRIES - 1)
#define PMD_MASK        (PMD_ENTRIES - 1)
#define PTE_MASK        (PTE_ENTRIES - 1)

/* 48-bit VA 页表索引（4 级页表） */
#define PGD_SHIFT_48    39   /* bits [47:39] */
#define PUD_SHIFT_48    30   /* bits [38:30] */
#define PMD_SHIFT_48    21   /* bits [29:21] */
#define PTE_SHIFT_48    12   /* bits [20:12] */

/* ===== 动态页表参数辅助 =====
 *
 * 按用户空间页大小动态计算各级索引：
 *   PTE_SHIFT = page_shift
 *   PMD_SHIFT = page_shift + 9
 *   PUD_SHIFT = page_shift + 18
 *   PGD_SHIFT = page_shift + 27
 * ARM64 每级页表固定 9 位索引（512 项），块映射大小 = 2^shift。
 * 物理地址掩码上限 = bits[47:12]（48-bit PA），排除 DBM 及
 * UXN/PXN/Contiguous 属性位，避免非物理地址位污染 phys。 */
#define KPM_PHYS_MASK_MAX  0x0000FFFFFFFFF000ULL  /* bits[47:12]（48-bit PA 上限，排除 DBM） */

static inline uint32_t kpm_pte_shift(void)
{
    kpm_detect_user_va_params();
    return (uint32_t)g_kpm_user_page_shift;
}

static inline uint32_t kpm_pmd_shift(void)
{
    kpm_detect_user_va_params();
    return (uint32_t)g_kpm_user_page_shift + 9;
}

static inline uint32_t kpm_pud_shift(void)
{
    kpm_detect_user_va_params();
    return (uint32_t)g_kpm_user_page_shift + 18;
}

static inline uint32_t kpm_pgd_shift(void)
{
    kpm_detect_user_va_params();
    return (uint32_t)g_kpm_user_page_shift + 27;
}

/* 物理地址掩码：页表项 bit[47:12]（4KB 页）或 bit[47:page_shift]（大页）。
 * 通过 KPM_PHYS_MASK_MAX 限定 48-bit PA 上限，清除 UXN/PXN/Contig/DBM 属性位。 */
static inline uint64_t kpm_phys_mask_shift(uint32_t shift)
{
    return (~((1ULL << shift) - 1)) & KPM_PHYS_MASK_MAX;
}

/* PTE 表项物理地址掩码 = 页对齐掩码（4KB: 0x...F000） */
static inline uint64_t kpm_pte_phys_mask(void)
{
    kpm_detect_user_va_params();
    return kpm_phys_mask_shift((uint32_t)g_kpm_user_page_shift);
}

/* PMD 块映射（大页）掩码：2^(page_shift+9) 对齐（4KB: 2MB） */
static inline uint64_t kpm_pmd_block_mask(void)
{
    kpm_detect_user_va_params();
    return kpm_phys_mask_shift((uint32_t)g_kpm_user_page_shift + 9);
}

/* PUD/PGD 块映射掩码：2^(page_shift+18) 对齐（4KB: 1GB） */
static inline uint64_t kpm_pud_block_mask(void)
{
    kpm_detect_user_va_params();
    return kpm_phys_mask_shift((uint32_t)g_kpm_user_page_shift + 18);
}

/* 用户空间页大小（字节） */
static inline uint64_t kpm_user_page_size(void)
{
    kpm_detect_user_va_params();
    return 1ULL << g_kpm_user_page_shift;
}

/* 用户空间 VA 位宽（39/48） */
static inline int kpm_user_va_bits(void)
{
    kpm_detect_user_va_params();
    return g_kpm_user_va_bits;
}

/* ===== VA 位宽 / 页表参数自动探测（不依赖框架 extern 变量） =====
 *
 * 问题：KPM 独立编译时，extern int64_t va_bits 解析到模块自身 .bss 段（值为 0），
 * 导致 page table walk 走错误的 39 位路径，48 位 VA 设备读取失败返回 -EFAULT。
 *
 * 解决方案：直接读 TCR_EL1 寄存器获取 VA 位宽（与框架 start.c 相同方式），
 * 不依赖 extern 框架变量。TCR_EL1 是 ARM64 系统寄存器，全版本稳定。
 *
 * 隐蔽性: A 级（MRS 指令是 EL1 特权读取，不产生任何可观测痕迹）
 */
int g_kpm_va_bits = 0;     /* 39 或 48 */
int g_kpm_page_shift = 0;  /* 12 / 14 / 16 */
int g_kpm_page_level = 0;  /* 3 或 4 */

/* 用户空间（TTBR0）参数：遍历用户进程页表必须用 T0SZ/TG0，
 * 不能用 T1SZ/TG1（内核空间）。 */
int g_kpm_user_va_bits = 0;      /* 用户空间 VA 位宽：39 或 48 */
int g_kpm_user_page_shift = 0;   /* 用户空间页大小：12 / 14 / 16 */

/* ===== TG1=2 真 64KB 页自洽验证 =====
 * 依赖前向声明（定义在本文件后方） */
static uint64_t get_page_offset(void);
static uint64_t kpm_ram_guard_start(void);
static uint64_t kpm_ram_guard_end(void);

/* 以 ps=16 假设 walk 内核 image 首地址，自洽性判定 TG1=2 是否真 64KB：
 *   - 真 64KB 内核：按 16KB/64KB 粒度索引能正确解析到 kernel image 的
 *     leaf PTE，物理地址 == kernel_pa 且属性 Normal → 验证通过
 *   - MTK EL2 干扰误读（实际 4KB）：错误粒度索引 → 条目无效 / 物理地址
 *     与 kernel_pa 不符 / 属性异常 → 验证失败，调用方回退 4KB
 * 39 位 VA + 64KB 页 = 2 级页表（level=2），48 位 = 3 级，均支持。
 * 仅依赖 pgd_va/kernel_pa/nofault/MRS（全版本稳定），无新内核 API。 */
static int kpm_verify_tg1_64k(void)
{
    extern uint64_t kernel_va, kernel_pa, pgd_va;   /* LH_syms.c */
    uint64_t base, entry, mair, po, next_phys;
    int level, shift, i;

    if (!kf_copy_from_kernel_nofault || !kernel_va || !kernel_pa || !pgd_va)
        return 0;

    level = (g_kpm_va_bits - 4) / (16 - 3);   /* 39→2, 48→3 */
    if (level < 2 || level > 3)
        return 0;

    asm volatile("mrs %0, mair_el1" : "=r"(mair));
    po = get_page_offset();
    if (!po || !g_memstart_addr)
        return 0;

    shift = (level - 1) * 9 + 16;
    base = pgd_va;
    for (i = 0; i < level; i++) {
        uint64_t idx = (kernel_va >> shift) & 0x1FF;

        if (kf_copy_from_kernel_nofault(&entry,
                (void *)(base + idx * 8), 8) != 0)
            return 0;
        if (!(entry & 0x1))
            return 0;   /* 未映射 → 64KB 假设错误 */

        if ((entry & 0x3) == 0x1 || shift <= 16) {
            /* leaf：物理地址必须等于 kernel_pa（64KB 对齐）且属性 Normal */
            uint64_t leaf_pa = entry & kpm_phys_mask_shift(16);
            uint64_t attr = (mair >> (((entry >> 2) & 7) * 8)) & 0xFF;
            return (leaf_pa == (kernel_pa & ~0xFFFFULL) &&
                    (attr & 0xF0) != 0) ? 1 : 0;
        }

        /* table 描述符 → 下钻（页表页物理 → 内核线性映射 VA） */
        next_phys = entry & kpm_phys_mask_shift(16);
        if (next_phys < kpm_ram_guard_start() ||
            next_phys >= kpm_ram_guard_end())
            return 0;
        base = next_phys - g_memstart_addr + po;
        shift -= 9;
    }
    return 0;
}

/* 非 static：供 kpm_state_info.c 等跨文件调用（统一探测逻辑） */
void kpm_detect_va_params(void)
{
    uint64_t tcr_el1;
    uint64_t t1sz, tg1;

    if (g_kpm_va_bits != 0) return;  /* 已探测 */

    /* 读取 TCR_EL1 寄存器（ARM64 系统寄存器，全版本稳定） */
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));

    /* T1SZ = TCR_EL1[21:16]，Top of high memory（内核空间 TTBR1）位宽 */
    t1sz = (tcr_el1 >> 16) & 0x3F;
    g_kpm_va_bits = 64 - t1sz;

    /* TG1 = TCR_EL1[31:30]，内核空间页大小：00=4KB, 01=16KB, 10=64KB。
     * MTK EL2 干扰下 TG1 可能误读为 2(64KB)，但实际内核是 4KB 页，
     * 故用 memstart_addr 物理内存量级保护：页表页物理地址应 < 16GB
     * （Android 设备 RAM 上限），TG1 判定 64KB 时物理地址会超界，回退 4KB。 */
    tg1 = (tcr_el1 >> 30) & 0x3;
    g_kpm_page_shift = 12;
    if (tg1 == 1) {
        g_kpm_page_shift = 14;   /* 16KB */
    } else if (tg1 == 2) {
        g_kpm_page_shift = 16;
        g_kpm_page_level = (g_kpm_va_bits - 4) / (16 - 3);
        if (kpm_verify_tg1_64k()) {
            kpm_printk("kpm: TG1=2 verified TRUE 64KB pages "
                       "(self-consistent walk to kernel_pa)\n");
        } else {
            kpm_printk("kpm: kern TG1=2 (64KB) detected via TCR, but self-"
                       "consistent walk FAILED; forcing 4KB (MTK EL2 case)\n");
            g_kpm_page_shift = 12;
            g_kpm_page_level = (g_kpm_va_bits - 4) / (12 - 3);
        }
    }

    if (g_mm_pgd_offset != 0) {
        /* 无 mm 时无法直接读 pgd，保留 TCR_EL1 探测值。 */
    }

    kpm_printk("kpm: kern detect tcr=%llx t1sz=%d tg1=%d va_bits=%d "
               "page_shift=%d level=%d\n",
               (unsigned long long)tcr_el1, (int)t1sz, (int)tg1,
               g_kpm_va_bits, g_kpm_page_shift, g_kpm_page_level);

    /* 页表级数 = (va_bits - 4) / (page_shift - 3) */
    g_kpm_page_level = (g_kpm_va_bits - 4) / (g_kpm_page_shift - 3);

    kpm_log("LH_mem: detect va_bits=%d page_shift=%d page_level=%d\n",
            g_kpm_va_bits, g_kpm_page_shift, g_kpm_page_level);
}

/* 探测用户空间（TTBR0）VA 位宽/页大小（T0SZ/TG0，幂等）。
 * 遍历用户进程页表时使用；get_page_offset（线性映射）仍用内核参数（T1SZ）。 */
void kpm_detect_user_va_params(void)
{
    uint64_t tcr_el1;
    uint64_t t0sz, tg0;

    if (g_kpm_user_va_bits != 0) return;  /* 已探测 */

    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));

    /* T0SZ = TCR_EL1[7:0]（低 6 位有效），用户空间（TTBR0）位宽 */
    t0sz = tcr_el1 & 0x3F;
    g_kpm_user_va_bits = 64 - t0sz;

    /* TG0 = TCR_EL1[15:14]，用户空间页大小。
     * ARM ARM TG0 编码：00=4KB, 01=64KB, 10=16KB（与 TG1 的 16K/64K 相反！） */
    tg0 = (tcr_el1 >> 14) & 0x3;
    g_kpm_user_page_shift = 12;
    if (tg0 == 1) {
        g_kpm_user_page_shift = 16;   /* TG0=01 → 64KB */
    } else if (tg0 == 2) {
        g_kpm_user_page_shift = 14;   /* TG0=10 → 16KB */
    }

    kpm_printk("kpm: user detect tcr=%llx t0sz=%d tg0=%d va_bits=%d "
               "page_shift=%d\n",
               (unsigned long long)tcr_el1, (int)t0sz, (int)tg0,
               g_kpm_user_va_bits, g_kpm_user_page_shift);

    kpm_log("LH_mem: user va_bits=%d page_shift=%d\n",
            g_kpm_user_va_bits, g_kpm_user_page_shift);
}


/* vmap Device-nGnRnE 的 pgprot 值
 * bits[7:6]=00 → Device 内存
 * bits[5:2]=0000 → AttrIndx=0 → MAIR[0] → Device-nGnRnE
 * bits[1:0]=11 → 有效页表项
 * bit[53] → PXN (Privileged Execute Never)
 * bit[54] → UXN (User Execute Never)
 */
#define PTPROT_DEVICE_nGnRnE  0x00E8000000000703ULL

/* vmemmap 是 struct page 数组，给定 PFN 对应地址 = vmemmap_base + pfn * page_size；
 * 按字节偏移（vmemmap_base + pfn）会指向错误的 struct page，导致 vmap 触发
 * __vmap_pages_range_noflush WARNING 并可能访问越界。
 * struct page 大小在 5.1~6.x 并非恒定 64 字节（5.9 前常见 56 字节，
 * 受 CONFIG_MEMCG 等配置影响），故运行时探测 g_struct_page_size，不硬编码。 */
static int g_struct_page_size = 64;  /* 默认值 */

/* vmemmap 可靠性标志：vmemmap 是运行时变量（KASLR/内存布局相关），
 * 无法从 kallsyms 读取；硬编码典型值（48位 0xFFFF7E0000000000 /
 * 39位 0xFFFFFFBF80000000）在部分设备上读不到有效 struct page。
 * 降级策略：probe 失败 → g_kpm_vmemmap_reliable=0 → kpm_phys_is_safe_ram
 * 仅用 memstart 物理域范围守卫（DEVAPC 核心防线：保护域物理地址在
 * [memstart, memstart+16GB) 之外），跳过 flags 校验，既保功能又防崩。 */
static int g_kpm_vmemmap_reliable = 0;

/* 运行时探测 struct page 大小 + 内核页大小。
 *
 * 原理：vmemmap 数组中，物理内存起始地址（memstart_addr 页对齐）对应的
 * struct page 必定有效，其 flags 字段（offset 0，unsigned long）为合理值
 * （非 0 非全 1）。对候选 (page_shift, S) 组合计算
 * base = vmemmap + (memstart >> page_shift) * S，读取并交叉验证相邻
 * 两个 page 的 flags。
 * 本函数用真实内存验证同时确定 g_kpm_page_shift 与 g_struct_page_size。
 *
 * 安全性：所有读取用 copy_from_kernel_nofault，不会 panic；
 * 探测失败回退默认（page_shift=12, size=64）。init 时执行一次。 */
static void kpm_detect_struct_page_size(void)
{
    /* PG_reserved 锚定探测：kernel image（kernel_pa..kernel_pa+kernel_size）
     * 全部页恒为 PG_reserved（reserve_bootmem_region() 设置，flags bit0=1）。
     * 对候选 (vmemmap, S, ps) 联合组合，读 kernel_pa 起连续 4 个 image 页的
     * struct page flags，全部 bit0=1 才选定。锚定成功 → reliable=1，DMA 路径可用；
     * 全候选失败 → reliable=0，read/write_via_dma 入口拒绝执行，回退 WB 线性映射路径，
     * 绝不 vmap 未经锚定的 struct page。
     * 兼容性：PG_reserved bit0 与 kernel_pa 均 4.14~6.x 可用，不引入新内核 API。
     * 隐蔽性：仅 init 时 nofault 读 kernel image 自身 struct page，不触碰目标进程，
     * 无缓存窥探，无持久状态。 */
    static const int size_cands[] = {56, 64, 72, 80};
    static const int shift_cands[] = {12, 14, 16};  /* 4KB/16KB/64KB */
    static const uint64_t vm_cands_static[] = {
        0xFFFFFFBE00000000ULL,  /* 39-bit 标准布局 vmemmap 起点 */
        0xFFFFFFBF00000000ULL,  /* 4.19 布局 */
        0xFFFFFFBF80000000ULL,  /* 39-bit 典型值 */
        0xFFFF7E0000000000ULL,  /* 48-bit 传统布局 */
        0xFFFFFC0000000000ULL,  /* 6.1 48-bit 公式 -(1<<(48-6)) */
    };
    uint64_t vm_cands[8];
    int nvm = 0, i, j, k;
    extern uint64_t kernel_pa;   /* LH_syms.c：框架符号链解析 */

    if (!g_vmemmap_base || !g_memstart_addr || !kf_copy_from_kernel_nofault)
        return;

    /* 确保 va_bits/page_level 先行探测（level 计算依赖 g_kpm_va_bits） */
    kpm_detect_va_params();

    if (kernel_pa) {
        /* 候选：现值（符号/公式推算）优先 + 静态布局表（去重） */
        vm_cands[nvm++] = g_vmemmap_base;
        for (i = 0; i < (int)(sizeof(vm_cands_static) / sizeof(vm_cands_static[0])); i++) {
            int dup = 0;
            for (j = 0; j < nvm; j++)
                if (vm_cands[j] == vm_cands_static[i]) dup = 1;
            if (!dup && nvm < (int)(sizeof(vm_cands) / sizeof(vm_cands[0])))
                vm_cands[nvm++] = vm_cands_static[i];
        }

        for (i = 0; i < nvm; i++) {
            for (j = 0; j < (int)(sizeof(shift_cands) / sizeof(shift_cands[0])); j++) {
                int ps = shift_cands[j];
                uint64_t pfn0 = kernel_pa >> ps;
                if ((pfn0 << ps) != kernel_pa)
                    continue;   /* kernel_pa 与 ps 不对齐（真实 ps 必对齐） */
                for (k = 0; k < (int)(sizeof(size_cands) / sizeof(size_cands[0])); k++) {
                    int S = size_cands[k];
                    uint64_t base = vm_cands[i] + pfn0 * (uint64_t)S;
                    uint64_t f;
                    int m, ok = 1;

                    /* 连续 4 个 image 页（页距 1<<ps）flags 均 PG_reserved */
                    for (m = 0; m < 4 && ok; m++) {
                        if (kf_copy_from_kernel_nofault(&f, (void *)(base +
                                (uint64_t)m * (1ULL << ps) * (uint64_t)S), 8) != 0)
                            ok = 0;
                        else if (f == ~0ULL || !(f & 1))
                            ok = 0;   /* PG_reserved bit0 必须 = 1 */
                    }
                    if (!ok)
                        continue;

                    g_vmemmap_base = vm_cands[i];
                    g_struct_page_size = S;
                    g_kpm_page_shift = ps;   /* 覆盖 TG1 误判 */
                    g_kpm_page_level = (g_kpm_va_bits - 4) / (ps - 3);
                    g_kpm_vmemmap_reliable = 1;
                    kpm_log("LH_mem: anchored vmemmap=0x%llx page_shift=%d "
                            "struct_page_size=%d (PG_reserved x4, kernel_pa=0x%llx)\n",
                            (unsigned long long)g_vmemmap_base, ps, S,
                            (unsigned long long)kernel_pa);
                    return;
                }
            }
        }

        /* 锚定全失败：绝不启用 DMA vmap。
         * reliable 保持 0 → read/write_via_dma 入口拒绝，回退 WB 路径。
         * 参数回退 GKI 默认。 */
        kpm_log("LH_mem: vmemmap anchor FAILED on all candidates, "
                "DMA path disabled (fallback WB), vmemmap=0x%llx\n",
                (unsigned long long)g_vmemmap_base);
        g_kpm_page_shift = 12;
        g_struct_page_size = 64;
        g_kpm_vmemmap_reliable = 0;
        if (g_kpm_va_bits)
            g_kpm_page_level = (g_kpm_va_bits - 4) / (12 - 3);
        return;
    }

    /* kernel_pa 不可用时用相邻两个 page 的 flags 交叉验证；
     * 不用三连读（会误拒空闲页）。 */
    for (j = 0; j < (int)(sizeof(shift_cands) / sizeof(shift_cands[0])); j++) {
        int ps = shift_cands[j];
        for (i = 0; i < (int)(sizeof(size_cands) / sizeof(size_cands[0])); i++) {
            int S = size_cands[i];
            uint64_t base = g_vmemmap_base +
                            (g_memstart_addr >> ps) * (uint64_t)S;
            uint64_t f0 = 0, f1 = 0;

            if (kf_copy_from_kernel_nofault(&f0, (void *)base, 8) != 0)
                continue;
            if (f0 == 0 || f0 == ~0ULL)
                continue;
            if (kf_copy_from_kernel_nofault(&f1, (void *)(base + S), 8) != 0)
                continue;
            if (f1 == 0 || f1 == ~0ULL)
                continue;

            g_struct_page_size = S;
            g_kpm_page_shift = ps;   /* 覆盖 TG1 误判 */
            g_kpm_page_level = (g_kpm_va_bits - 4) / (ps - 3);
            g_kpm_vmemmap_reliable = 1;  /* vmemmap 可读，启用 flags 校验 */
            kpm_log("LH_mem: detected page_shift=%d struct_page_size=%d "
                    "(flags=0x%llx/0x%llx)\n",
                    ps, S, (unsigned long long)f0, (unsigned long long)f1);
            return;
        }
    }

    kpm_log("LH_mem: struct_page_size probe failed, fallback page_shift=12 "
            "(4KB, Android GKI standard) size=64\n");
    /* 探测失败（vmemmap 不可读）时强制回退 4KB：ARM64 内核页大小
     * 与用户页大小一致，由 TG0 探测结果确定。 */
    g_kpm_page_shift = 12;
    g_struct_page_size = 64;
    g_kpm_vmemmap_reliable = 0;  /* vmemmap 不可读，降级跳过 flags 校验 */
    if (g_kpm_va_bits)
        g_kpm_page_level = (g_kpm_va_bits - 4) / (12 - 3);
}

/* VM_MAP 标志（来自 linux/vmalloc.h） */
#ifndef VM_MAP
#define VM_MAP_FLAG     0x00000004
#else
#define VM_MAP_FLAG     VM_MAP
#endif

/* MEMREMAP 标志 */
#define MEMREMAP_WB     0
#define MEMREMAP_WC     1

/* ioremap_prot 的 Normal Cacheable WB 页保护值（ARM64 PAGE_KERNEL）
 * bits[5:2]=AttrIndx=1(MT_NORMAL), bit[7]=Write, bit[10]=AF, bit[12]=SH
 * bits[53]=PXN, bits[54]=UXN
 */
#define IOREMAP_PROT_NORMAL_CACHEABLE  0x0060000000001484ULL

/* ===== DC CIVAC 缓存清洗（带物理地址合法性校验） =====
 *
 * dc civac 作用于未映射/非法虚拟地址会触发 translation fault → kernel panic，
 * 故统一封装并做双重校验：
 *   1. phys 合法性：非 0 且 < 256GB（ARM64 设备 RAM 保守上界，
 *      页表遍历来源的 phys 通常为合法 RAM/设备内存）
 *   2. linear_va 下界：>= PAGE_OFFSET，防止 phys - memstart 下溢
 * 非法时跳过清洗（仅损失隐蔽性，绝不崩溃）。
 */
#define KPM_PHYS_MAX  0x4000000000ULL  /* 256GB */

/* ===== 真实 System RAM 边界探测 =====
 * 兼容性准则：全版本 4.x+ 稳定 API、平台无关。
 * /proc/iomem 自 2.6 起内核标准 procfs，格式 "start-end : System RAM"。
 * 读取方式与 LH_proc.c 读 /proc/<pid>/cmdline 同构（同符号
 * kf_filp_open/kf_kernel_read/kf_filp_close）。
 * 探测成功 → 守卫用真实 RAM 边界（适配任意内存大小，含 >16GB 设备）；
 * 探测失败（SELinux 拒读/符号缺失）→ 回退 memstart+16GB。
 * walk 页表遍历与 DC-CIVAC 统一走 kpm_ram_guard_end()。 */
static uint64_t g_ram_start = 0;   /* 真实 System RAM 下界（iomem 探测） */
static uint64_t g_ram_end   = 0;   /* 真实 System RAM 上界 */

/* 4.19 CONFIG_RANDOMIZE_BASE 会把 memstart_addr 变成带符号 PHYS_OFFSET
 * （可为负/超大值），不能直接当物理 RAM 下界；优先用 iomem 探测结果，
 * 其次用 LH_syms 推导的 g_phys_ram_base，最后才是 memstart_addr。 */
static inline uint64_t kpm_ram_guard_start(void)
{
    if (g_ram_start)
        return g_ram_start;
    if (g_phys_ram_base)
        return g_phys_ram_base;
    return g_memstart_addr;
}

static inline uint64_t kpm_ram_guard_end(void)
{
    return g_ram_end ? g_ram_end
                     : (kpm_ram_guard_start() + 0x400000000ULL);  /* 回退 16GB */
}

/* 十六进制解析（iomem 地址无 0x 前缀），失败返回 0 */
static uint64_t kpm_hexval(const char *s, int n)
{
    uint64_t v = 0;
    int i;
    if (n <= 0 || n > 16)
        return 0;
    for (i = 0; i < n; i++) {
        char c = s[i];
        v <<= 4;
        if (c >= '0' && c <= '9')      v |= (uint64_t)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (uint64_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (uint64_t)(c - 'A' + 10);
        else return 0;
    }
    return v;
}

/* 读 /proc/iomem 解析 System RAM 区间，得 [g_ram_start, g_ram_end]。
 * init 时调用一次；失败保持 0（守卫回退 16GB）。 */
static void kpm_probe_ram_bounds(void)
{
    struct file *fp;
    loff_t pos = 0;
    ssize_t nread;
    char buf[4096];
    int i = 0;

    if (g_ram_end != 0)
        return;
    if (!kf_filp_open || !kf_filp_close || !kf_kernel_read)
        return;

    fp = kf_filp_open("/proc/iomem", 0, 0);
    if (IS_ERR_OR_NULL(fp)) {
        kpm_log("kpm: /proc/iomem open failed, RAM guard fallback 16GB\n");
        return;
    }
    nread = kf_kernel_read(fp, buf, sizeof(buf) - 1, &pos);
    kf_filp_close(fp, 0);
    if (nread <= 0)
        return;
    buf[nread] = '\0';

    while (i < nread) {
        char *line = &buf[i];
        int j, k, llen, dash = -1, colon = -1, has_ram = 0;
        uint64_t s = 0, e = 0;

        for (j = i; j < nread && buf[j] != '\n'; j++)
            ;
        llen = j - i;
        if (j < nread)
            buf[j] = '\0';

        for (k = 0; k < llen; k++) {
            if (line[k] == '-' && dash < 0)
                dash = k;
            if (line[k] == ':') {
                colon = k;
                break;
            }
        }
        /* 冒号后找 "System RAM" 子串 */
        if (colon >= 0) {
            for (k = colon; k <= llen - 10; k++) {
                if (line[k]=='S' && line[k+1]=='y' && line[k+2]=='s' &&
                    line[k+3]=='t' && line[k+4]=='e' && line[k+5]=='m' &&
                    line[k+6]==' ' && line[k+7]=='R' && line[k+8]=='A' &&
                    line[k+9]=='M') {
                    has_ram = 1;
                    break;
                }
            }
        }
        if (dash > 0 && colon > dash && has_ram) {
            int e0 = dash + 1, e1 = colon;
            while (e1 > e0 && line[e1 - 1] == ' ')
                e1--;
            s = kpm_hexval(line, dash);
            e = kpm_hexval(line + e0, e1 - e0);
            if (s && e > s) {
                if (!g_ram_start || s < g_ram_start)
                    g_ram_start = s;
                if (e > g_ram_end)
                    g_ram_end = e;
            }
        }
        i = j + 1;
    }

    if (g_ram_end > g_ram_start) {
        kpm_log("LH_mem: RAM bounds via /proc/iomem [0x%llx, 0x%llx) size=%lldMB\n",
                (unsigned long long)g_ram_start,
                (unsigned long long)g_ram_end,
                (long long)((g_ram_end - g_ram_start) >> 20));
    } else {
        kpm_log("LH_mem: /proc/iomem no System RAM parsed, guard fallback 16GB\n");
    }
}

/* ===== DEVAPC 物理域守卫 =====
 *
 * MTK DEVAPC（Device Access Permission Controller）为每个总线 slave/domain
 * 定义访问权限矩阵。DMA 路径（read_via_dma/write_via_dma）用 vmap +
 * PTPROT_DEVICE_nGnRnE 把目标物理页映射为 Device 域访问，若目标页属于
 * 受保护域（secure 保留区 / TEE / 硬件加速器私有域 / MTK 保留内存），
 * 会触发 DEVAPC 中断并导致硬件看门狗复位。
 *
 * struct page 的 flags==0/~0 校验只能防 vmap 崩溃（无效 struct page），
 * 不能防 DEVAPC 域访问，故需本守卫。
 *
 * 本守卫在 DMA/DC-CIVAC 访问前判断物理地址是否属于可安全访问的普通 RAM
 * 域：命中受保护域则拒绝访问（返回 0），合法 RAM 照常放行（返回 1）。
 * 保留 DMA Device-nGnRnE 隐蔽机制（Flush+Reload/Prime+Probe 不可检测），
 * 仅过滤 DEVAPC 保护域：纯内存判断、无持久状态、重启即恢复；复用
 * memstart/vmemmap/TCR 探测，无新内核 API。
 */
static int kpm_phys_is_safe_ram(uint64_t phys)
{
    uint64_t ram_start;

    /* 1. 物理上界绝对兜底：拒绝 0 与高位保留区 */
    if (phys == 0 || phys >= KPM_PHYS_MAX)
        return 0;

    /* 2. DEVAPC 核心守卫：phys 必须落在实际 RAM 区 [ram_start, guard_end]。
     *    KPM_PHYS_MAX（256GB）上界过宽，会放行大量非 RAM 的设备/保留区物理地址，
     *    故用实际 RAM 边界。ARM64 Android 设备 RAM 起始即物理 RAM 基址，RAM 上限
     *    保守取 ram_start+16GB（Android 设备 RAM 上限；超 16GB 设备极罕见，
     *    若有再按 /proc/iomem System RAM 动态扩展）。落在其外的物理地址
     *    （secure/TEE/设备/保留区）一律视为保护域，禁止 DMA/DC-CIVAC 访问。
     *    下界不直接用 memstart_addr：4.19 KASLR 会使其成为带符号 PHYS_OFFSET。 */
    ram_start = kpm_ram_guard_start();
    if (ram_start == 0)
        return 0;
    if (phys < ram_start || phys >= kpm_ram_guard_end())
        return 0;

    /* 3. struct page 有效校验（防无效 vmemmap 导致的 vmap 崩溃）：
     * 仅当 vmemmap 探测可靠时才做 flags 校验；不可靠时跳过本校验，
     * 仅靠上方 memstart 物理域范围守卫（DEVAPC 核心防线）拦截保护域。 */
    if (g_kpm_vmemmap_reliable &&
        g_vmemmap_base != 0 && g_struct_page_size != 0 &&
        kf_copy_from_kernel_nofault) {
        uint64_t pfn = phys >> g_kpm_page_shift;
        uint64_t flags;
        if (kf_copy_from_kernel_nofault(
                &flags,
                (void *)(g_vmemmap_base + pfn * (uint64_t)g_struct_page_size),
                sizeof(flags)) != 0)
            return 0;
        if (flags == 0 || flags == ~0UL)
            return 0;
    }
    return 1;
}

/* get_page_offset 定义于本文件后方，此处前向声明 */
static inline uint64_t get_page_offset(void);

static void kpm_dc_civac_phys(uint64_t phys_addr, uint64_t size)
{
    uint64_t po;
    uint64_t linear_va;

    if (phys_addr == 0 || phys_addr >= KPM_PHYS_MAX || size == 0)
        return;
    if (g_memstart_addr == 0)
        return;

    /* DEVAPC 物理域守卫：命中受保护域（secure/TEE/保留/设备区）跳过清洗。
     * DC CIVAC 同样可能触发 DEVAPC 硬件中断，必须在访问前用统一守卫拦截，
     * 仅对可安全访问的普通 RAM 域执行。 */
    if (!kpm_phys_is_safe_ram(phys_addr))
        return;

    /* 物理页必须是有效 RAM 页才清洗：GPU/ion/kgsl/DMA mmap 页的 phys 落在
     * 保留/设备区（< KPM_PHYS_MAX 但 vmemmap 处无有效 struct page），对其
     * dc civac 会触发 translation fault → panic。校验：vmemmap 可读且 flags
     * 非全 0/~0（与 read_via_dma 同一防御模式）。失败则跳过清洗（仅损失
     * 缓存一致性，绝不崩溃）。 */
    if (g_vmemmap_base != 0 && g_struct_page_size != 0) {
        uint64_t pfn = phys_addr >> g_kpm_page_shift;
        uint64_t flags;
        if (kf_copy_from_kernel_nofault(
                &flags,
                (void *)(g_vmemmap_base + pfn * (uint64_t)g_struct_page_size),
                sizeof(flags)) != 0)
            return;
        if (flags == 0 || flags == ~0UL)
            return;
    }

    po = get_page_offset();
    linear_va = phys_addr - g_memstart_addr + po;

    /* 下界校验（防下溢）+ phys 上界已校验（防落到未映射的 vmalloc/空洞区） */
    if (linear_va < po)
        return;

    /* dc civac 是唯一无 fault 兜底的指令：对无效线性 VA（RAM 空洞/保留区/
     * 并发页表撕裂产生的伪 phys）执行会触发同步数据 abort → panic。
     * flags 校验依赖探测正确的页参数，不能 100% 拦截，故加一道
     * copy_from_kernel_nofault 探针：线性 VA 本身不可读则跳过清洗，
     * 仅损失隐蔽性，绝不崩溃。探针读对缓存语义无副作用。 */
    if (kf_copy_from_kernel_nofault) {
        uint64_t probe = 0;
        if (kf_copy_from_kernel_nofault(&probe, (void *)linear_va, 8) != 0)
            return;
    }

    {
        uint64_t start = linear_va & ~63ULL;
        uint64_t end = linear_va + size;
        uint64_t a;
        for (a = start; a < end; a += 64)
            asm volatile("dc civac, %0" : : "r"(a) : "memory");
    }
    asm volatile("dsb ish" : : : "memory");
}

/* ===== 辅助函数 ===== */

/* mm 读锁适配层
 *
 * 设计原理：
 *   - VMA 遍历与页表遍历都是只读操作，RCU 读临界区足够保护
 *   - find_vma 在 Linux 6.1+ 内部自动走 RCU 路径（maple tree 无锁设计）
 *   - find_vma 在 Linux < 6.1 也是只读操作，RCU 下安全
 *   - 页表遍历用 copy_from_kernel_nofault 安全读取，不依赖任何锁
 *   - get_task_mm/mmput 引用计数保证 mm_struct 不释放
 *
 * 优先级：
 *   1. __rcu_read_lock（全版本导出，主路径）
 *   2. mmap_read_lock（5.8+ 标准 API，可选优化，暂不启用避免语义混用）
 *   3. 跳过（仅当 RCU 不可用时，copy_from_kernel_nofault 兜底）
 *
 * 隐蔽性：A 级
 *   - RCU 是 Linux 架构原生同步原语，非 root 程序无法检测
 *   - 不引入任何系统修改痕迹
 *
 * 并发安全：
 *   - RCU 读锁不阻塞写者，并发 mmap 可能读到中间态
 *   - copy_from_kernel_nofault + 有效位校验兜底，不会 panic
 *   - 最坏情况：读到 stale 页表项，返回 -KPM_E_FAULT，调用方重试
 *
 * 关键约束：RCU 读锁禁止睡眠
 *   - 持锁期间不得调用 copy_to_user/copy_from_user/vmalloc/mmput 等可睡眠函数
 *   - 适配层仅保护 read_mm_pgd（一次 copy_from_kernel_nofault，不睡眠）
 *   - 其余操作（页表遍历、DMA、用户态拷贝）必须在锁外执行
 */
static inline void kpm_mmap_read_lock(struct mm_struct *mm)
{
    /* 统一走 RCU 读锁（使用 KPM_RCU_READ_LOCK 宏自动处理 NULL）：
     *   - PREEMPT 内核：__rcu_read_lock 可解析，提供 RCU 保护
     *   - 非 PREEMPT 内核：__rcu_read_lock 不可解析（static inline），宏自动跳过
     *   - 与 copy_from_kernel_nofault 页表遍历天然匹配
     *   - mmap_read_lock 符号仅解析不使用（避免 lock/unlock 不配对）
     *   - mm 参数保留用于未来扩展（per-VMA lock 等） */
    (void)mm;
    KPM_RCU_READ_LOCK();
}

static inline void kpm_mmap_read_unlock(struct mm_struct *mm)
{
    (void)mm;
    KPM_RCU_READ_UNLOCK();
}

/* 安全读取 mm_struct 中的 pgd 指针 */
static int read_mm_pgd(struct mm_struct *mm, uint64_t *out_pgd)
{
    if (!kf_copy_from_kernel_nofault || !mm || g_mm_pgd_offset == 0)
        return -1;

    long ret = kf_copy_from_kernel_nofault(out_pgd,
                (void *)((uint64_t)mm + g_mm_pgd_offset), 8);
    if (ret < 0) {
        kpm_log("kpm: read_mm_pgd failed at offset %llx, ret=%ld\n",
                (unsigned long long)g_mm_pgd_offset, ret);
        return -1;
    }
    return 0;
}

/* 反推 mm_struct.pgd 字段偏移（用已知有效用户 VA 校验）。
 * 用于框架 mm_struct_offset.pgd_offset 解析失败（-1）导致 walk 失败的场景。
 * 扫描 mm 前 MM_PGD_PROBE_SZ 字节的每个 8 字节字段，若该字段是 4K 对齐
 * 内核地址，则用 walk_page_table 尝试解析 known_va；成功则该字段即 pgd。
 * 找到后写入全局 g_mm_pgd_offset。返回 0 成功，-1 失败。 */
static int walk_page_table(uint64_t pgd_va, uint64_t vaddr, uint64_t *out_phys);
#define MM_PGD_PROBE_SZ 1024
int kpm_probe_pgd_offset(struct mm_struct *mm, uint64_t known_va)
{
    uint8_t buf[MM_PGD_PROBE_SZ];
    uint64_t *fields = (uint64_t *)buf;
    int i, n;
    uint64_t phys;

    if (!mm || !kf_copy_from_kernel_nofault)
        return -1;
    n = (int)(sizeof(buf) / 8);
    if (kf_copy_from_kernel_nofault(buf, mm, sizeof(buf)) != 0)
        return -1;

    for (i = 0; i < n; i++) {
        uint64_t cand = fields[i];
        if (cand < 0xFFFF000000000000ULL || (cand & 0xFFF))
            continue;
        /* 用已知有效用户 VA 走页表，成功则该字段即 pgd */
        if (walk_page_table(cand, known_va, &phys) == 0) {
            g_mm_pgd_offset = (uint64_t)(i * 8);
            kpm_log("kpm: probe pgd offset=%d (known_va=%llx -> phys=%llx)\n",
                    i * 8, (unsigned long long)known_va,
                    (unsigned long long)phys);
            kpm_printk("LH_mem_dbg: probe pgd offset=%d (known_va=%llx "
                       "-> phys=%llx)\n", i * 8,
                       (unsigned long long)known_va,
                       (unsigned long long)phys);
            return 0;
        }
    }
    kpm_log("kpm: probe pgd offset FAILED via known_va=%llx\n",
            (unsigned long long)known_va);
    kpm_printk("LH_mem_dbg: probe pgd offset FAILED via known_va=%llx\n",
               (unsigned long long)known_va);
    return -1;
}

/* PAGE_OFFSET（ARM64 linear mapping base）
 *
 * PAGE_OFFSET 公式随内核版本变化，不能硬编码单一值：
 *   - <5.4: PAGE_OFFSET = -(1 << (VA_BITS - 1))        [4.19/5.0 布局]
 *   - >=5.4: PAGE_OFFSET = -(1 << VA_BITS)             [5.4+ 布局]
 * 运行时用框架导出的 kver 分支（kver = major<<16|minor<<8|patch）。 */
#define PAGE_OFFSET_OLD_48  0xFFFF800000000000ULL  /* -(1<<47), 4.x 48-bit */
#define PAGE_OFFSET_NEW_48  0xFFFF000000000000ULL  /* -(1<<48), 5.4+ 48-bit */
#define PAGE_OFFSET_OLD_39  0xFFFFFFC000000000ULL  /* -(1<<38), 4.x 39-bit */
#define PAGE_OFFSET_NEW_39  0xFFFFFF8000000000ULL  /* -(1<<39), 5.4+ 39-bit */

/* 导出线性映射基址（内核空间扫描 kpm_mem_scan_kernel_start 用）。
 * get_page_offset 为 static inline（本文件多处内部调用），此处提供公开包装。 */
uint64_t kpm_get_page_offset(void)
{
    return get_page_offset();
}

/* 根据内核空间位宽 + 内核版本动态返回线性映射 PAGE_OFFSET
 *
 * PAGE_OFFSET 由内核空间位宽（T1SZ/TTBR1）决定，不能用用户空间 va_bits
 * （T0SZ/TTBR0）：页表页物理→虚拟转换走内核线性映射，与用户进程地址位宽无关。 */
static inline uint64_t get_page_offset(void)
{
    uint32_t major, minor;

    kpm_detect_va_params();  /* 确保参数已探测（内部有幂等检查） */
    extern uint32_t kver;    /* KernelPatch 框架导出：major<<16|minor<<8|patch */
    major = (kver >> 16) & 0xFF;
    minor = (kver >> 8) & 0xFF;

    /* 版本分界取 5.4（minor>=4），与 LH_syms.c vmemmap 推算的判据对齐。 */
    if (g_kpm_va_bits == 48)
        return (major > 5 || (major == 5 && minor >= 4)) ?
               PAGE_OFFSET_NEW_48 : PAGE_OFFSET_OLD_48;
    return (major > 5 || (major == 5 && minor >= 4)) ?
           PAGE_OFFSET_NEW_39 : PAGE_OFFSET_OLD_39;
}

/* ===== 内核地址设备属性精确判定 =====
 *
 * 从 swapper_pg_dir（pgd_va）walk 内核页表取 leaf 描述符，解码 AttrIndx
 * 对应的 MAIR_EL1 属性：Device（高半字节 0）即拒绝。
 * 兼容性：仅依赖 pgd_va/nofault/TCR/MAIR（MRS，全版本稳定），
 * walk 不可用时返回 -1，调用方回退 vmalloc_to_page。
 * 返回 1=Normal 内存（安全）；0=Device/未映射（拒绝）；-1=基础设施不可用。 */
static int kpm_kern_pte_attr_normal(uint64_t kaddr)
{
    extern uint64_t pgd_va;   /* LH_syms.c：swapper_pg_dir / init_mm.pgd */
    uint64_t page_offset, mair, base, entry;
    int shift;

    if (!kf_copy_from_kernel_nofault)
        return -1;
    if (!pgd_va)
        return -1;

    kpm_detect_va_params();
    if ((g_kpm_va_bits != 39 && g_kpm_va_bits != 48) ||
        g_kpm_page_shift < 12 || g_kpm_page_shift > 16 ||
        g_kpm_page_level < 3 || g_kpm_page_level > 4)
        return -1;

    page_offset = get_page_offset();
    if (!page_offset || !g_memstart_addr)
        return -1;

    asm volatile("mrs %0, mair_el1" : "=r"(mair));

    /* 顶层 shift：3 级(39bit)=2*9+shift，4 级(48bit)=3*9+shift
     * （与 g_kpm_page_level = (va_bits-4)/(page_shift-3) 一致） */
    shift = (g_kpm_page_level - 1) * 9 + g_kpm_page_shift;
    base = pgd_va;

    for (;;) {
        uint64_t idx = (kaddr >> shift) & 0x1FF;

        if (kf_copy_from_kernel_nofault(&entry,
                (void *)(base + idx * 8), 8) != 0)
            return -1;

        if (!(entry & 0x1))
            return 0;   /* 未映射/PROT_NONE(bit[1:0]=10) → 拒绝 */

        if ((entry & 0x3) == 0x1 || shift <= g_kpm_page_shift) {
            /* leaf（block 描述符 01 或 PTE 级）：MAIR 属性判定。
             * Device（nGnRnE=0x00/nGnRE=0x04/GRE=0x0C）高半字节为 0；
             * Normal（NC=0x44/WT=0xBB/WB=0xEE/Tagged=0xF0）≥ 0x40 */
            uint64_t attr_indx = (entry >> 2) & 7;
            uint64_t attr = (mair >> (attr_indx * 8)) & 0xFF;
            return ((attr & 0xF0) != 0) ? 1 : 0;
        }

        /* table 描述符（bit[1:0]=11）→ 下钻：页表页物理地址转线性映射
         * VA（页表页均为普通 RAM），与 walk_page_table 同款 RAM 边界守卫 */
        {
            uint64_t next_phys = entry & kpm_phys_mask_shift(
                (uint32_t)g_kpm_page_shift);
            if (next_phys < kpm_ram_guard_start() ||
                next_phys >= kpm_ram_guard_end())
                return -1;
            base = next_phys - g_memstart_addr + page_offset;
        }
        shift -= 9;
    }
}

/* ===== 内核虚拟地址安全校验 =====
 *
 * copy_from_kernel_nofault 只能捕获翻译错误（page fault），无法拦截
 * MTK DEVAPC 硬件总线监控：读取保护域物理页映射（secure/TEE/保留 RAM 的
 * 线性映射地址）或 ioremap 设备映射都会触发硬件重启（nofault 的
 * exception table 不经过总线监控）。故读内核地址前做白名单校验：
 *   1) 线性映射区 [PAGE_OFFSET, PAGE_OFFSET+KPM_PHYS_MAX)：
 *      转物理 → kpm_phys_is_safe_ram（memstart+16GB RAM 域 + struct page
 *      flags 有效校验）→ 保护域物理页拒绝；
 *   2) 非线性映射区：必须通过 vmalloc_to_page 验证是 vmalloc 分配页
 *      （模块/驱动数据；对 VM_IOREMAP 设备映射/无效地址返回 NULL → 拒绝）；
 *   3) 其余（固定映射/PCI 窗口等）一律拒绝。
 * 兼容性：input_dev.name/phys 等字符串位于模块 .rodata（vmalloc 页）或
 * 内核 .data/.rodata（线性映射 RAM）→ 通过校验，触摸功能不受影响。
 * 注：仅用于"探测类"安全读取（读字符串/链表）；性能路径不受影响。 */
int kpm_is_safe_kern_addr(uint64_t addr)
{
    uint64_t po;
    struct page *pg;

    if (addr < 0xffff000000000000ULL)
        return 0;
    /* 0) 内核镜像区（text/rodata/data/bss）：普通 RAM 映射，读取安全。
     * 4.19 39bit 下 kernel image 位于 PAGE_OFFSET 之下，既非线性也非
     * vmalloc，若无此分支，触摸设备 name/phys（.rodata 字面量）会被误拒。 */
    if (kernel_va && kernel_size > 0 &&
        addr >= kernel_va && addr < kernel_va + (uint64_t)kernel_size)
        return 1;
    po = get_page_offset();
    if (po == 0)
        return 0;
    /* 1) 线性映射区：物理域守卫（保护域物理页 → 拒绝）。
     * 上界用 (addr - po) < KPM_PHYS_MAX，避免 po+KPM_PHYS_MAX 在
     * 39bit 4.19（PAGE_OFFSET=0xffffffc000000000）下溢出为 0，否则全部
     * 线性映射地址被漏判进 vmalloc 分支而被误拒。 */
    if (addr >= po && (addr - po) < KPM_PHYS_MAX) {
        uint64_t phys;
        if (g_memstart_addr == 0)
            return 0;
        /* __lm_to_phys：memstart_addr 即 arm64 PHYS_OFFSET（4.19 KASLR 下
         * 为带符号值，u64 回绕是正确语义），不可再做“下溢”拦截。 */
        phys = addr - po + g_memstart_addr;
        return kpm_phys_is_safe_ram(phys);
    }
    /* 2) 非线性映射：优先页表 MAIR 属性判定。
     * vmalloc_to_page 对 ioremap 设备映射同样返回非 NULL 伪 struct page
     * （pte_page = vmemmap + 设备 PA pfn * 64，不校验内存属性），堆内
     * 残留的外设寄存器基址指针会被误放行。
     * kpm_kern_pte_attr_normal：walk swapper_pg_dir 解码 leaf AttrIndx
     * 对应 MAIR_EL1 属性，Device（高半字节 0）拒绝、Normal 放行；
     * 返回 -1（基础设施不可用/越界守卫触发）时回退 vmalloc_to_page。 */
    {
        int pte_attr = kpm_kern_pte_attr_normal(addr);
        if (pte_attr == 1)
            return 1;
        if (pte_attr == 0)
            return 0;
    }
    /* 回退：vmalloc_to_page 验证（ioremap/无效地址 → NULL） */
    if (kf_vmalloc_to_page) {
        pg = kf_vmalloc_to_page((void *)addr);
        return (pg != NULL && (uint64_t)pg >= 0xffff000000000000ULL);
    }
    return 0;
}

/* ===== 手动 ARM64 页表遍历 =====
 * 从进程的 PGD 开始，遍历 3 级(39-bit VA) 或 4 级(48-bit VA) 页表，
 * 返回物理地址 + 页内偏移。
 *
 * 各级页表索引移位由 user_page_shift 决定：ARM64 每级 9 bits 索引，
 *   level_shift(最低级=PTE) = page_shift，往上每级 +9。
 *     4KB:  PTE=12, PMD=21, PUD=30, PGD=39(48bit)/30(39bit)
 *     16KB: PTE=14, PMD=23, PUD=32, PGD=41(48bit)/32(39bit)
 *     64KB: PTE=16, PMD=25, PUD=34, PGD=43(48bit)/34(39bit)
 * 块映射掩码随级变化：PMD 块 = 2^(page_shift+9) 对齐，
 * PUD 块 = 2^(page_shift+18) 对齐；PTE 物理掩码 = ~(page_size - 1)。
 * 用户空间参数用 T0SZ/TG0 探测（遍历用户页表不用内核空间的 T1SZ/TG1）。
 *
 * 所有页表页通过 kf_copy_from_kernel_nofault 安全读取线性映射地址，
 * 避免 memremap/ioremap 对高位物理地址映射失败的问题。
 * 每级页表条目都执行有效位校验（bit[0]=1）和块/表映射判定（bit[1:0]）。
 */
static int walk_page_table(uint64_t pgd_va, uint64_t vaddr, uint64_t *out_phys)
{
    uint64_t entry;
    int idx;
    long ret;
    uint64_t page_offset = get_page_offset();  /* 内部调用 kpm_detect_va_params */
    int va_bits;
    uint32_t page_shift;
    uint64_t page_size;

    if (!pgd_va || !out_phys) return -1;
    if (!kf_copy_from_kernel_nofault) return -1;

    /* pgd_va 是 mm->pgd 的线性映射虚拟地址（形态 0xffffff81xxxxxxxx，
     * PAGE_OFFSET 区），非物理地址 —— 不能用 [memstart, memstart+16GB]
     * 物理区间检查（会误拒全部遍历）。
     * 脏状态防护由后续各层（PUD/PMD/PTE）的物理地址域检查承担，
     * 该检查针对页表项中的物理地址，是 DEVAPC 防护的正确层级。 */

    /* 用户空间参数（T0SZ/TG0 探测） */
    va_bits = kpm_user_va_bits();
    page_shift = kpm_pte_shift();
    if (va_bits != 39 && va_bits != 48) {
        /* 探测失败（理论不可达，TCR_EL1 全版本稳定） */
        kpm_log("kpm: walk_page_table: invalid va_bits=%d\n", va_bits);
        return -1;
    }
    page_size = 1ULL << page_shift;

    /* Level 0: PGD
     * pgd_va（mm->pgd）在 Android 内核是线性映射虚拟地址，直接可访问，
     * 不做 phys→lin 换算；若为物理地址则需换算。 */
    if (va_bits == 48) {
        idx = (vaddr >> kpm_pgd_shift()) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(
            &entry, (void *)(pgd_va + idx * 8), 8);
        if (ret < 0) return -1;
        /* 有效位校验：bit[0]=0 无效，bit[1:0]=01 块映射，bit[1:0]=11 表映射 */
        if (!(entry & 0x1)) return -1;
        if ((entry & 0x3) == 0x1) {
            /* PGD 级块映射（4KB: 512GB，实际不出现），兜底处理 */
            *out_phys = (entry & kpm_phys_mask_shift(page_shift + 27)) |
                        (vaddr & ((1ULL << (page_shift + 27)) - 1));
            return 0;
        }
    } else {
        /* 39 位 VA：顶层 PGD 对应 48 位结构的 PUD 层 */
        idx = (vaddr >> kpm_pud_shift()) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(
            &entry, (void *)(pgd_va + idx * 8), 8);
        if (ret < 0) return -1;
        if (!(entry & 0x1)) return -1;
        if ((entry & 0x3) == 0x1) {
            /* 顶层块映射（4KB: 1GB） */
            *out_phys = (entry & kpm_pud_block_mask()) |
                        (vaddr & ((1ULL << (page_shift + 18)) - 1));
            return 0;
        }
    }

    /* Level 1: PUD（仅 48 位 VA） */
    if (va_bits == 48) {
        uint64_t pud_phys = entry & kpm_pte_phys_mask();
        uint64_t pud_va;
        if (pud_phys < kpm_ram_guard_start() ||
            pud_phys >= kpm_ram_guard_end())   /* 真实 RAM 边界 */
            return -1;   /* 防下溢成巨大 VA */
        pud_va = pud_phys - g_memstart_addr + page_offset;
        idx = (vaddr >> kpm_pud_shift()) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(&entry, (void *)(pud_va + idx * 8), 8);
        if (ret < 0) return -1;
        if (!(entry & 0x1)) return -1;
        if ((entry & 0x3) == 0x1) {
            /* PUD 级块映射（4KB: 1GB） */
            *out_phys = (entry & kpm_pud_block_mask()) |
                        (vaddr & ((1ULL << (page_shift + 18)) - 1));
            return 0;
        }
    }

    /* Level 2: PMD */
    {
        uint64_t pmd_phys = entry & kpm_pte_phys_mask();
        uint64_t pmd_va;
        if (pmd_phys < kpm_ram_guard_start() ||
            pmd_phys >= kpm_ram_guard_end())   /* 真实 RAM 边界 */
            return -1;   /* 防下溢成巨大 VA */
        pmd_va = pmd_phys - g_memstart_addr + page_offset;
        idx = (vaddr >> kpm_pmd_shift()) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(&entry, (void *)(pmd_va + idx * 8), 8);
        if (ret < 0 || !(entry & 0x1)) {
            return -1;
        }
        if ((entry & 0x3) == 0x1) {
            /* PMD 级块映射（4KB: 2MB 大页） */
            *out_phys = (entry & kpm_pmd_block_mask()) |
                        (vaddr & ((1ULL << (page_shift + 9)) - 1));
            return 0;
        }
    }

    /* Level 3: PTE */
    {
        uint64_t pte_phys = entry & kpm_pte_phys_mask();
        uint64_t pte_va;
        if (pte_phys < kpm_ram_guard_start() ||
            pte_phys >= kpm_ram_guard_end())   /* 真实 RAM 边界 */
            return -1;   /* 防下溢成巨大 VA */
        pte_va = pte_phys - g_memstart_addr + page_offset;
        idx = (vaddr >> page_shift) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(&entry, (void *)(pte_va + idx * 8), 8);
        if (ret < 0 || !(entry & 0x1)) {
            return -1;
        }
        /* PTE 必须是表映射（bit[1:0]==0x3），不能是块映射 */
    }

    *out_phys = (entry & kpm_pte_phys_mask()) | (vaddr & (page_size - 1));
    return 0;
}



/* ===== vmap Device-nGnRnE 读取（首选，完全不可检测） =====
 * 使用 vmap 对目标物理页创建 Device-nGnRnE 映射，然后逐字节读取
 * 绕过所有缓存层级（L1/L2/SLC），Flush+Reload / Prime+Probe 不可检测。
 *
 * Device-nGnRnE 读取每次产生总线事务，不加载缓存行，
 * 目标进程的缓存状态完全不受影响。
 */
/* DMA 批量 vmap 每批最大页数（4KB 页时 32 页 = 128KB）。
 * vmap/vunmap 是系统级昂贵操作（vmalloc 区查找 + TLB 维护），批量合并把
 * "每页一次"降为"每批一次"，显著降低长 READ_MEM 的 CPU 占用与时序特征；
 * 逐页安全校验（phys 范围 / DEVAPC 守卫 / struct page flags）粒度不变，
 * nGnRnE 属性与访存方式不变。 */
#define KPM_DMA_BATCH_PAGES  32

static int read_via_dma(uint64_t phys_addr, void *kbuf, int size)
{
    uint64_t cur_phys = phys_addr;
    int total = 0;
    int kern_page_sz;

    if (!kf_vmap || !kf_vunmap || !g_vmemmap_base)
        return -1;
    if (phys_addr == 0)
        return -1;
    /* vmemmap 未经 PG_reserved 锚定验证时禁用 DMA vmap，
     * 回退 WB 线性映射路径（调用方已有回退链）。 */
    if (!g_kpm_vmemmap_reliable)
        return -1;
    /* DEVAPC 物理域守卫：目标物理页必须属于可安全 DMA 访问的普通 RAM 域，
     * 命中保护域（secure/TEE/保留/设备区）直接拒绝，不产生 Device 域总线访问。 */
    if (!kpm_phys_is_safe_ram(phys_addr))
        return -1;

    kpm_detect_va_params();
    kern_page_sz = 1 << g_kpm_page_shift;
    if (kern_page_sz <= 0)
        return -1;

    while (total < size) {
        struct page *pages[KPM_DMA_BATCH_PAGES];
        void *dev_map;
        uint64_t page_off;
        uint64_t p = cur_phys;
        int want = size - total;
        int batch_len = 0, npages = 0;
        int i, off, rem, pre;

        /* 批量 vmap：单次调用内 cur_phys 连续推进，按页收集后一次性 vmap。
         * 逐页安全校验粒度不变，命中即整批拒绝。 */
        while (npages < KPM_DMA_BATCH_PAGES && batch_len < want) {
            uint64_t pfn;
            struct page *page;
            unsigned long flags;
            int avail = kern_page_sz - (int)(p & (kern_page_sz - 1));
            int take = want - batch_len;

            if (take > avail) take = avail;

            /* 物理地址合法性校验（防 pfn 越界 → 非法 struct page → vmap 崩溃）：
             * cur_phys 必须为合法 RAM 物理地址（非 0 且 < KPM_PHYS_MAX，
             * 即 256GB，ARM64 设备 RAM 保守上界），vmap 前必须拦截。
             * copy_from_kernel_nofault 读 flags 只防无效内存，不防
             * "合法地址处的非 struct page 数据"。 */
            if (p >= KPM_PHYS_MAX) {
                kpm_log("kpm: dma read phys out-of-range 0x%llx\n",
                        (unsigned long long)p);
                return -1;
            }
            /* 逐页 DEVAPC 守卫：多页读取时每页都要验证属于可安全 DMA 的
             * 普通 RAM 域，命中保护域页直接拒绝。 */
            if (!kpm_phys_is_safe_ram(p))
                return -1;
            pfn = p >> g_kpm_page_shift;
            page = (struct page *)(g_vmemmap_base + pfn * (uint64_t)g_struct_page_size);

            /* 防御：无效 struct page 直接返回失败（调用方回退 WB），杜绝 vmap 崩溃 */
            if (kf_copy_from_kernel_nofault(&flags, page, sizeof(flags)) != 0)
                return -1;
            if (flags == 0 || flags == ~0UL)
                return -1;

            pages[npages++] = page;
            batch_len += take;
            p += take;
        }
        if (batch_len <= 0) break;

        page_off = cur_phys & (kern_page_sz - 1);

        dev_map = kf_vmap(pages, npages, VM_MAP_FLAG, PTPROT_DEVICE_nGnRnE);
        if (!dev_map && npages > 1) {
            /* 批量 vmap 失败 → 回退单页映射（VMALLOC 紧张时 32 页可能
             * 失败而单页成功）。 */
            npages = 1;
            batch_len = kern_page_sz - (int)page_off;
            if (batch_len > want) batch_len = want;
            dev_map = kf_vmap(pages, 1, VM_MAP_FLAG, PTPROT_DEVICE_nGnRnE);
        }
        if (!dev_map)
            return -1;

        /* Device-nGnRnE 读取：8 字节对齐部分按 8B 步进（Device 内存未对齐
         * 访问是错误，必须对齐），头尾未对齐部分逐字节。
         * 无论哪种方式都不加载缓存行，保持完全不可检测。
         * 批量映射区域跨页连续，dev_map 页对齐，8B 对齐基准仍取物理地址。 */
        pre = (int)((page_off & 7) ? (8 - (int)(page_off & 7)) : 0);
        if (pre > batch_len) pre = batch_len;
        for (i = 0; i < pre; i++) {
            ((volatile uint8_t *)kbuf)[total + i] =
                ((volatile uint8_t *)dev_map)[page_off + i];
        }
        off = pre;
        rem = batch_len - pre;
        while (rem >= 8) {
            uint64_t v;
            v = *(volatile uint64_t *)((uint8_t *)dev_map + page_off + off);
            *(uint64_t *)((uint8_t *)kbuf + total + off) = v;
            off += 8;
            rem -= 8;
        }
        while (rem > 0) {
            ((volatile uint8_t *)kbuf)[total + off] =
                ((volatile uint8_t *)dev_map)[page_off + off];
            off++;
            rem--;
        }

        kf_vunmap(dev_map);
        total += batch_len;
        cur_phys += batch_len;
    }
    return total;
}


/* ===== 线性映射 WB 读取（回退方案，DMA 不可用时） =====
 * 通过 ARM64 线性映射地址直接读取目标物理页
 * 读取后由调用方执行 DC CIVAC 清除缓存行
 */
static int read_via_wb(uint64_t phys_addr, void *kbuf, int size)
{
    uint64_t page_base = phys_addr & PAGE_MASK_4K;
    uint64_t page_offset = phys_addr & ~PAGE_MASK_4K;
    uint64_t linear_va;
    long ret;

    if (!kf_copy_from_kernel_nofault)
        return -1;

    if (g_memstart_addr == 0)
        return -1;

    /* 计算线性映射地址：va = pa - memstart_addr + PAGE_OFFSET */
    if (page_base < kpm_ram_guard_start()) {
        /* phys < RAM 基址时减法下溢成巨大地址，copy_from_kernel_nofault
         * 会读到错误位置；页表遍历来源的 phys 正常 ≥ RAM 基址，此处仅防御。 */
        return -1;
    }
    linear_va = page_base - g_memstart_addr + get_page_offset();

    /* 使用 copy_from_kernel_nofault 安全读取 */
    ret = kf_copy_from_kernel_nofault(kbuf, (void *)(linear_va + page_offset), size);
    if (ret < 0)
        return -1;

    mb();  /* 内存屏障，确保读取完成 */
    return size;
}


/* ===== vmap Device-nGnRnE 写入（首选，完全不可检测） =====
 * 使用 vmap 对目标物理页创建 Device-nGnRnE 映射，然后逐字节写入
 * Device-nGnRnE 写入直接到达 DRAM，不经过任何缓存层级（L1/L2/SLC）
 *
 * 写入后执行 DC CIVAC 清除目标地址的线性映射缓存行，
 * 确保目标进程 CPU 核的缓存失效，下次读取时从 DRAM 获取新值。
 * DC CIVAC 是特权指令，用户态无法执行也不会观测到副作用。
 */
static int write_via_dma(uint64_t phys_addr, const void *kbuf, int size)
{
    uint64_t cur_phys = phys_addr;
    int total = 0;
    int kern_page_sz;

    if (!kf_vmap || !kf_vunmap || !g_vmemmap_base)
        return -1;
    if (size <= 0)
        return -1;
    if (phys_addr == 0)
        return -1;
    /* vmemmap 未经 PG_reserved 锚定验证时禁用 DMA vmap。 */
    if (!g_kpm_vmemmap_reliable)
        return -1;
    /* DEVAPC 物理域守卫：写入前验证目标物理页属于可安全 DMA 的普通 RAM 域，
     * 命中保护域直接拒绝，避免 Device 域写访问触发 DEVAPC 中断
     * （写比读更危险，会破坏保护域）。 */
    if (!kpm_phys_is_safe_ram(phys_addr))
        return -1;

    kpm_detect_va_params();
    kern_page_sz = 1 << g_kpm_page_shift;
    if (kern_page_sz <= 0)
        return -1;

    while (total < size) {
        struct page *pages[KPM_DMA_BATCH_PAGES];
        void *dev_map;
        uint64_t page_off;
        uint64_t p = cur_phys;
        int want = size - total;
        int batch_len = 0, npages = 0;
        int i, off, rem, pre;

        /* 批量 vmap，逐页安全校验 */
        while (npages < KPM_DMA_BATCH_PAGES && batch_len < want) {
            uint64_t pfn;
            struct page *page;
            unsigned long flags;
            int avail = kern_page_sz - (int)(p & (kern_page_sz - 1));
            int take = want - batch_len;

            if (take > avail) take = avail;

            /* phys 越界直接拒绝（防非法 struct page → vmap 崩溃） */
            if (p >= KPM_PHYS_MAX) {
                kpm_log("kpm: dma write phys out-of-range 0x%llx\n",
                        (unsigned long long)p);
                return -1;
            }
            /* 逐页 DEVAPC 守卫：多页写入每页都要验证 */
            if (!kpm_phys_is_safe_ram(p))
                return -1;
            pfn = p >> g_kpm_page_shift;
            page = (struct page *)(g_vmemmap_base + pfn * (uint64_t)g_struct_page_size);

            /* 与 read_via_dma 相同的防御：无效 struct page 直接回退 WB，杜绝 vmap 崩溃 */
            if (kf_copy_from_kernel_nofault(&flags, page, sizeof(flags)) != 0)
                return -1;
            if (flags == 0 || flags == ~0UL)
                return -1;

            pages[npages++] = page;
            batch_len += take;
            p += take;
        }
        if (batch_len <= 0) break;

        page_off = cur_phys & (kern_page_sz - 1);

        /* 必须先于 Device 写做 dc civac：Device-nGnRnE 写直达 DRAM、绕过
         * CPU 缓存，但目标缓存行中可能残留旧脏数据；若在 Device 写之后才
         * civac，clean 阶段会把旧脏行写回 DRAM，覆盖刚写入的新值。
         * 顺序：写前 civac（写回旧脏数据 + 失效缓存行）→ Device 写直达 DRAM
         * → 此后任何 CPU 读都从 DRAM 取新值。批量路径对整批区间一次性
         * civac（与逐页累计等价）。 */
        kpm_dc_civac_phys(cur_phys, (uint64_t)batch_len);

        dev_map = kf_vmap(pages, npages, VM_MAP_FLAG, PTPROT_DEVICE_nGnRnE);
        if (!dev_map && npages > 1) {
            /* 批量 vmap 失败 → 回退单页映射（VMALLOC 紧张时保持可用性）。
             * 已做的整批 civac 覆盖未写入页仅多失效少量缓存行，无副作用。 */
            npages = 1;
            batch_len = kern_page_sz - (int)page_off;
            if (batch_len > want) batch_len = want;
            dev_map = kf_vmap(pages, 1, VM_MAP_FLAG, PTPROT_DEVICE_nGnRnE);
        }
        if (!dev_map)
            return -1;

        /* Device-nGnRnE 写入：8 字节对齐部分按 8B 步进，头尾逐字节。
         * 直接到达 DRAM，不经过任何缓存层级。
         * 批量映射区域跨页连续，dev_map 页对齐，8B 对齐基准仍取物理地址。 */
        pre = (int)((page_off & 7) ? (8 - (int)(page_off & 7)) : 0);
        if (pre > batch_len) pre = batch_len;
        for (i = 0; i < pre; i++) {
            ((volatile uint8_t *)dev_map)[page_off + i] = ((const uint8_t *)kbuf)[total + i];
        }
        off = pre;
        rem = batch_len - pre;
        while (rem >= 8) {
            uint64_t v;
            lib_memcpy(&v, (const uint8_t *)kbuf + total + off, 8);
            *(volatile uint64_t *)((uint8_t *)dev_map + page_off + off) = v;
            off += 8;
            rem -= 8;
        }
        while (rem > 0) {
            ((volatile uint8_t *)dev_map)[page_off + off] =
                ((const uint8_t *)kbuf)[total + off];
            off++;
            rem--;
        }

        kf_vunmap(dev_map);
        total += batch_len;
        cur_phys += batch_len;
    }

    /* 写入后清洗目标地址的缓存行 -- 确保缓存一致性
     * Device 写入直接到 DRAM，但目标 CPU 核可能缓存了旧值。
     * DC CIVAC 使所有核的缓存行失效，下次读取时从 DRAM 获取新值，
     * 统一走带物理地址校验的 kpm_dc_civac_phys。 */
    kpm_dc_civac_phys(phys_addr, (uint64_t)size);

    return total;
}


/* ===== 线性映射 WB 写入（回退方案，DMA 不可用时） =====
 * 通过 ARM64 线性映射地址直接写入目标物理页
 * 整块写入后按缓存行对齐执行 DC CIVAC，减少缓存残留痕迹
 */
static int write_via_wb(uint64_t phys_addr, const void *kbuf, int size)
{
    uint64_t page_base = phys_addr & PAGE_MASK_4K;
    uint64_t page_offset = phys_addr & ~PAGE_MASK_4K;
    uint64_t linear_va;
    uint64_t page_off_val = get_page_offset();

    if (g_memstart_addr == 0)
        return -1;

    linear_va = page_base - g_memstart_addr + page_off_val;

    /* 地址范围校验在两个写分支之前统一执行：walk 返回伪 phys（并发页表
     * 撕裂）时 nofault 不触发但会写入已映射的错误内核页 → 静默内存损坏。
     * 校验：phys ≥ memstart（防 page_base-memstart 下溢成巨大 VA）
     * + target_va ∈ [po, po+KPM_PHYS_MAX) 线性映射区间。 */
    {
        uint64_t po = get_page_offset();
        uint64_t target_va = linear_va + page_offset;
        if (page_base < kpm_ram_guard_start() ||
            target_va < po || (target_va - po) >= KPM_PHYS_MAX) {
            kpm_log("write_via_wb: invalid target_va=0x%llx (po=0x%llx, "
                    "memstart=0x%llx, phys=0x%llx), abort\n",
                    (unsigned long long)target_va,
                    (unsigned long long)po,
                    (unsigned long long)g_memstart_addr,
                    (unsigned long long)page_base);
            return -1;
        }
    }

    /* 整块写入：优先使用 copy_to_kernel_nofault（语义为写，安全不触发
     * fault，即 probe_kernel_write 别名）。
     *
     * 回退：若 copy_to_kernel_nofault 不可用（极旧内核），直接 memcpy——
     * linear_va 是内核线性映射地址，本身可写，memcpy 安全（已通过上述
     * 范围校验，不会写入非法地址）。 */
    if (kf_copy_to_kernel_nofault) {
        if (kf_copy_to_kernel_nofault((void *)(linear_va + page_offset), kbuf, size) != 0)
            return -1;
    } else {
        {
            uint8_t *d = (uint8_t *)(linear_va + page_offset);
            const uint8_t *s = (const uint8_t *)kbuf;
            int i;
            for (i = 0; i < size; i++) d[i] = s[i];
        }
    }

    /* 按 64 字节缓存行清除，处理地址不对齐，
     * 统一走带物理地址校验的 kpm_dc_civac_phys。 */
    kpm_dc_civac_phys(phys_addr, (uint64_t)size);

    asm volatile("dsb ish\n\tisb\n\t" : : : "memory");
    return size;
}

/* ===== 主入口：跨进程内存读写 =====
 * 使用手动 ARM64 页表遍历获取物理地址。
 * 读取：DMA Device-nGnRnE 优先（完全绕过缓存，不可检测），
 *       WB 回退（读取后 DC CIVAC 清洗缓存残留）。
 * 写入：DMA Device-nGnRnE 优先（直接到 DRAM + DC CIVAC 确保一致性），
 *       WB 回退（写入后 DC CIVAC 清洗缓存残留）。
 *
 * 隐蔽性约束：
 * - 不触发 get_user_pages（无缺页，无 ProcEvent 痕迹）
 * - 绕过 Pagemap/PerfEvent 检测
 * - DMA Device-nGnRnE 绕过所有缓存层级，Flush+Reload 不可检测
 * - WB 回退后立即 DC CIVAC，将缓存残留窗口压缩到微秒级
 */
long kpm_mem_rw_process(pid_t pid, uint64_t remote_addr, void *user_buf, int len, int is_write)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    uint64_t pgd_va = 0;
    uint64_t phys_addr;
    void *kbuf = NULL;
    int kbuf_is_vm = 0;    /* kbuf 来自 vmalloc(1) 还是 kmalloc(0) */
    long total = 0;
    int remaining = len;
    uint64_t offset = 0;

    /* 参数检查
     *
     * RCU 读锁非必需：
     *   - PREEMPT/PREEMPT_RT 内核（大多数 Android）：__rcu_read_lock 可解析
     *   - PREEMPT_NONE/PREEMPT_VOLUNTARY 内核（服务器/stock）：static inline，不可解析
     *   - RCU 锁不可用时跳过是安全的：
     *     * read_mm_pgd 内仅一次 copy_from_kernel_nofault（不睡眠）
     *     * get_task_mm 引用计数保护 mm_struct 不释放
     *     * copy_from_kernel_nofault 兜底处理并发页表 fault
     *     * 最坏情况：读到 stale 页表项 → 返回 -KPM_E_FAULT，调用方重试
     */
    if (!kf_find_get_pid || !kf_get_pid_task || !kf_get_task_mm || !kf_mmput) {
        return -KPM_E_INVAL;
    }
    if (((!kf_copy_to_user || !kf_copy_from_kernel_nofault) && !is_write) ||
        ((!kf_copy_from_user || !kf_copy_from_kernel_nofault) && is_write)) {
        return -KPM_E_INVAL;
    }
    if (len <= 0 || len > 32768) {
        return -KPM_E_INVAL;
    }

    /* 查找目标进程 */
    pid_struct = kf_find_get_pid(pid);
    if (!pid_struct) {
        kpm_log("kpm: find_get_pid failed pid=%d\n", pid);
        return -KPM_E_NOTFOUND;
    }
    task = kf_get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        kpm_log("kpm: get_pid_task failed pid=%d\n", pid);
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }

    /* 分配内核缓冲区：按 len 选分配器——小长度 kmalloc（slab，微秒级），
     * 大长度 vmalloc（避免大块连续物理页分配失败）。两者都必须在任何锁
     * 之前完成（可睡眠，RCU 读锁禁止睡眠）。kmalloc 符号缺失时退回 vmalloc。 */
    if (len <= KPM_MEM_RW_KMALLOC_MAX && kf_kmalloc && kf_kfree) {
        kbuf = kf_kmalloc((size_t)len, GFP_KERNEL);
        kbuf_is_vm = 0;
    } else {
        kbuf = kf_vmalloc((unsigned long)len);
        kbuf_is_vm = 1;
    }
    if (!kbuf) {
        kpm_log("kpm: kbuf alloc failed (len=%d vm=%d)\n", len, kbuf_is_vm);
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_FAULT;
    }

    /* 获取 mm_struct */
    mm = kf_get_task_mm(task);
    if (!mm) {
        kpm_log("kpm: get_task_mm failed pid=%d\n", pid);
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        kpm_mem_rw_kbuf_free(kbuf, kbuf_is_vm);
        return -KPM_E_NOTFOUND;
    }

    /* ===== 写入路径：copy_from_user 必须在 RCU 锁外（可睡眠） ===== */
    if (is_write) {
        if (kf_copy_from_user(kbuf, user_buf, len) != 0) {
            kpm_log("kpm: copy_from_user failed\n");
            kf_mmput(mm);
            kpm_put_task_struct(task);
            kf_put_pid(pid_struct);
            kpm_mem_rw_kbuf_free(kbuf, kbuf_is_vm);
            return -KPM_E_FAULT;
        }
    }

    /* ===== RCU 读锁仅保护 read_mm_pgd（短临界区，禁止睡眠） =====
     *   - read_mm_pgd 内部用 copy_from_kernel_nofault，不睡眠
     *   - 临界区极短：仅一次 8 字节读取
     *   - 页表遍历和 DMA 操作在锁外执行（copy_from_kernel_nofault 兜底） */
    kpm_mmap_read_lock(mm);
    if (read_mm_pgd(mm, &pgd_va) < 0 || !pgd_va) {
        kpm_log("kpm: read_mm_pgd failed pid=%d pgd=0x%llx\n", pid, (unsigned long long)pgd_va);
        kpm_mmap_read_unlock(mm);
        kf_mmput(mm);
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        kpm_mem_rw_kbuf_free(kbuf, kbuf_is_vm);
        return -KPM_E_FAULT;
    }
    kpm_mmap_read_unlock(mm);

    /* 日志按每 256 次记一条 + 累计计数抽样：kpm_log 内部是 IRQ 自旋锁 +
     * kf_vsnprintf（持全局锁），高频读写时逐次记录开销大且会冲掉日志环。
     * 抽样可见流量，成本降到 1/256（计数器是普通自增，无锁）。 */
    {
        static unsigned long s_mem_rw_log_cnt = 0;
        s_mem_rw_log_cnt++;
        if ((s_mem_rw_log_cnt & 0xFF) == 1)
            kpm_log("kpm: mem_rw %s pid=%d addr=0x%llx len=%d pgd=0x%llx "
                    "(第 %lu 次调用，每 256 次记一条)\n",
                    is_write ? "write" : "read", pid,
                    (unsigned long long)remote_addr, len,
                    (unsigned long long)pgd_va, s_mem_rw_log_cnt);
    }

    /* ===== 页表遍历 + DMA/WB 操作（锁外执行） =====
     * 不依赖任何锁：
     *   - mm_struct 引用计数保护（get_task_mm/mmput 配对）
     *   - 页表项用 copy_from_kernel_nofault 安全读取
     *   - 并发 mmap 写时可能读到中间态，有效位校验兜底
     *   - DMA/WB 操作基于物理地址，与 mm 锁无关 */
    if (is_write) {
        /* ===== 写入路径 ===== */
        while (remaining > 0) {
            uint64_t cur_vaddr = remote_addr + offset;
            int page_remaining = (int)(PAGE_SIZE_4K - (cur_vaddr & ~PAGE_MASK_4K));
            int chunk = (remaining > page_remaining) ? page_remaining : remaining;

            if (walk_page_table(pgd_va, cur_vaddr, &phys_addr) < 0) {
                kpm_log("kpm: walk_page_table failed addr=0x%llx\n",
                        (unsigned long long)cur_vaddr);
                if (total == 0) total = -KPM_E_FAULT;
                break;
            }

            {
                /* DMA Device-nGnRnE 优先（完全不可检测），WB 回退 */
                int written = write_via_dma(phys_addr, kbuf + offset, chunk);
                if (written < 0) {
                    written = write_via_wb(phys_addr, kbuf + offset, chunk);
                }
                if (written < 0) {
                    kpm_log("kpm: write failed phys=0x%llx\n", (unsigned long long)phys_addr);
                    if (total == 0) total = -KPM_E_FAULT;
                    break;
                }
                total += written;
                offset += written;
                remaining -= written;
                if (written < chunk) break;
            }
        }

        kf_mmput(mm);
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        kpm_mem_rw_kbuf_free(kbuf, kbuf_is_vm);
        return total;
    }

    /* ===== 读取路径 ===== */
    while (remaining > 0) {
        uint64_t cur_vaddr = remote_addr + offset;
        int page_remaining = (int)(PAGE_SIZE_4K - (cur_vaddr & ~PAGE_MASK_4K));
        int chunk = (remaining > page_remaining) ? page_remaining : remaining;

        /* 1. 手动页表遍历：获取物理地址 */
        if (walk_page_table(pgd_va, cur_vaddr, &phys_addr) < 0) {
            kpm_log("kpm: walk_page_table failed addr=0x%llx\n",
                    (unsigned long long)cur_vaddr);
            if (total == 0) total = -KPM_E_FAULT;
            break;
        }

        /* 2. 物理读取：DMA Device-nGnRnE 优先（完全绕过缓存，不可检测），
         *    WB 回退（DMA 不可用时，读取后 DC CIVAC 清洗缓存残留）
         *
         * DMA 优先的原因：
         *   - Device-nGnRnE 绕过所有缓存层级（L1/L2/SLC）
         *   - Flush+Reload / Prime+Probe 缓存时序侧信道完全不可检测
         *
         * WB 回退后执行 DC CIVAC 清除读取的缓存行，将残留窗口压缩到微秒级
         */
        {
            int read_bytes;

            /* DMA Device-nGnRnE 优先（隐蔽性最高，完全不可检测） */
            read_bytes = read_via_dma(phys_addr, kbuf + offset, chunk);

            /* 回退到 WB 模式（DMA 不可用时，如高位物理地址 vmap 失败） */
            if (read_bytes < 0) {
                read_bytes = read_via_wb(phys_addr, kbuf + offset, chunk);
                /* WB 回退后清洗缓存行，减少 Flush+Reload 残留痕迹，
                 * 统一走带物理地址校验的 kpm_dc_civac_phys。 */
                if (read_bytes > 0)
                    kpm_dc_civac_phys(phys_addr, (uint64_t)read_bytes);
            }

            if (read_bytes < 0) {
                kpm_log("kpm: read failed phys=0x%llx\n", (unsigned long long)phys_addr);
                if (total == 0) total = -KPM_E_FAULT;
                break;
            }

            total += read_bytes;
            offset += read_bytes;
            remaining -= read_bytes;
            if (read_bytes < chunk) break;
        }
    }

    /* 3. 将内核缓冲区数据拷贝到用户空间（RCU 锁外，允许睡眠） */
    if (total > 0) {
        kf_copy_to_user(user_buf, kbuf, total);
    }

    kf_mmput(mm);
    kpm_put_task_struct(task);
    kf_put_pid(pid_struct);
    kpm_mem_rw_kbuf_free(kbuf, kbuf_is_vm);
    return total;
}

long kpm_mem_rw_init(void)
{
    /* 检查关键符号 */
    if (!kf_find_get_pid || !kf_get_pid_task || !kf_get_task_mm || !kf_mmput) {
        kpm_log("kpm: process access symbols not found, mem_rw disabled\n");
        return -1;
    }

    /* rcu_read_lock 可选（PREEMPT 内核可用，非 PREEMPT 内核跳过），
     * 不作为必需条件。 */
    if (!kf_rcu_read_lock || !kf_rcu_read_unlock) {
        kpm_log("kpm: rcu_read_lock/unlock not found (non-PREEMPT kernel), "
                "mem_rw will run without RCU protection (safe with "
                "copy_from_kernel_nofault + mm refcount)\n");
    }
    /* mmap_read_lock 符号存在时仅解析不使用，避免与 RCU 路径锁语义混用 */
    if (kf_mmap_read_lock && kf_mmap_read_unlock)
        kpm_log("kpm: mmap_read_lock available (optional, not used in RCU path)\n");

    if (!kf_copy_from_kernel_nofault) {
        kpm_log("kpm: copy_from_kernel_nofault not found, mem_rw disabled\n");
        return -1;
    }

    if (g_memstart_addr == 0) {
        kpm_log("kpm: memstart_addr not found, mem_rw disabled\n");
        return -1;
    }

    if (!kf_vmap || !kf_vunmap) {
        kpm_log("kpm: vmap not found, DMA path disabled\n");
    }

    if (g_vmemmap_base == 0) {
        kpm_log("kpm: vmemmap not found, DMA fallback unavailable\n");
    } else {
        /* 运行时探测 struct page 大小（5.1~6.x 不恒定） */
        kpm_detect_struct_page_size();
    }

    /* /proc/iomem 探测真实 System RAM 边界，守卫/walk 统一使用；
     * 失败回退 16GB。 */
    kpm_probe_ram_bounds();

    kpm_log("kpm: mem_rw using page table walk (memstart=0x%llx) + %s\n",
            (unsigned long long)g_memstart_addr,
            (kf_vmap && g_vmemmap_base) ? "DMA primary (WB fallback)" : "WB only");

    kpm_set_state(KPM_STATE_MEM_RW_OK);
    kpm_log("kpm: mem_rw init ok\n");
    return 0;
}

void kpm_mem_rw_exit(void)
{
    kpm_clear_state(KPM_STATE_MEM_RW_OK);
    kpm_log("kpm: mem_rw exit\n");
}

/* ===== 内核内部跨进程内存读取 =====
 * 不涉及用户态拷贝，直接读入内核缓冲区
 * 用于 PLT hook 等内核模块内部调用
 */
long kpm_mem_read_kernel(pid_t pid, uint64_t remote_addr, void *kbuf, int len)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    uint64_t pgd_va = 0;
    uint64_t phys_addr = 0;
    uint64_t offset = 0;
    int remaining = len;
    int total = 0;
    int ret;

    if (!kf_find_get_pid || !kf_get_pid_task || !kf_get_task_mm || !kf_mmput) {
        return -KPM_E_INVAL;
    }
    if (!kf_copy_from_kernel_nofault) {
        return -KPM_E_INVAL;
    }
    if (len <= 0 || len > 32768) {
        return -KPM_E_INVAL;
    }

    /* 查找目标进程 */
    pid_struct = kf_find_get_pid(pid);
    if (!pid_struct) return -KPM_E_NOTFOUND;

    task = kf_get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }

    mm = kf_get_task_mm(task);
    if (!mm) {
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }

    ret = read_mm_pgd(mm, &pgd_va);
    /* kf_mmput 在 walk 完成后执行，此处保持 mm 引用持有，
     * 保证 walk 期间 pgd 存活 */
    if (ret < 0 || !pgd_va) {
        kf_mmput(mm);
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_FAULT;
    }

    /* 逐块读取 */
    while (remaining > 0) {
        uint64_t cur_vaddr = remote_addr + offset;
        int page_remaining = (int)(PAGE_SIZE_4K - (cur_vaddr & ~PAGE_MASK_4K));
        int chunk = (remaining > page_remaining) ? page_remaining : remaining;

        if (walk_page_table(pgd_va, cur_vaddr, &phys_addr) < 0) {
            /* 区分 walk 失败与 read 失败 */
            kpm_log("kpm: READ walk-fail pid=%d vaddr=%llx pgd=%llx "
                    "(pgd_off=%llu va_bits=%d page_shift=%u)\n",
                    pid, (unsigned long long)cur_vaddr,
                    (unsigned long long)pgd_va,
                    (unsigned long long)g_mm_pgd_offset,
                    kpm_user_va_bits(), kpm_pte_shift());
            if (total == 0) total = -KPM_E_FAULT;
            break;
        }

        {
            /* DMA Device-nGnRnE 优先，WB 回退 + DC CIVAC */
            int read_bytes = read_via_dma(phys_addr, kbuf + offset, chunk);
            if (read_bytes < 0) {
                read_bytes = read_via_wb(phys_addr, kbuf + offset, chunk);
                if (read_bytes > 0) {
                    /* 统一走 kpm_dc_civac_phys（内部动态获取 PAGE_OFFSET，
                     * 并做物理地址合法性校验），清除 WB 读取的残留缓存，
                     * 保证隐蔽性。 */
                    kpm_dc_civac_phys(phys_addr, (uint64_t)read_bytes);
                }
            }
            if (read_bytes < 0) {
                /* DMA+WB 均失败 */
                kpm_log("kpm: READ phys-fail pid=%d vaddr=%llx phys=%llx\n",
                        pid, (unsigned long long)cur_vaddr,
                        (unsigned long long)phys_addr);
                if (total == 0) total = -KPM_E_FAULT;
                break;
            }
            total += read_bytes;
            offset += read_bytes;
            remaining -= read_bytes;
            if (read_bytes < chunk) break;
        }
    }

    kpm_put_task_struct(task);
    kf_put_pid(pid_struct);
    /* mm 引用持有到 walk 全部完成：pgd 页随 mm 生命周期（mm_users>0 时
     * __mmput 不触发、pgd 不释放），提前 kf_mmput 会让 walk 期间 pgd 可能
     * 被归还 buddy → 读到重分配对象伪装成页表 → 伪 phys → 写路径经
     * phys_to_virt 写任意物理页（内存损坏）。 */
    kf_mmput(mm);
    return total;
}

/* ===== uprobe handler 安全读取：强制 WB 路径 =====
 * 与 kpm_mem_read_kernel 的区别：只走 read_via_wb（线性映射直读 +
 * copy_from_kernel_nofault + DC CIVAC），【不走】read_via_dma——
 * DMA 路径内部 kf_vmap 可能睡眠（vmalloc 分配），而 uprobe 回调运行于
 * handler_chain 的 RCU 读临界区（rcu_read_lock），vmap 睡眠会无限延长
 * 临界区 → 卸载线程 synchronize_rcu 等待超时 → 系统卡死。
 * 用途：gyro/传感器 uprobe handler 读取用户态 sensors_event_t。
 * 其余语义（pid 查找、mm 引用、页级容错）与 kpm_mem_read_kernel 一致。 */
long kpm_mem_read_kernel_wb(pid_t pid, uint64_t remote_addr, void *kbuf, int len)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    uint64_t pgd_va = 0;
    uint64_t phys_addr = 0;
    uint64_t offset = 0;
    int remaining = len;
    int total = 0;
    int ret;

    if (!kf_find_get_pid || !kf_get_pid_task || !kf_get_task_mm || !kf_mmput) {
        return -KPM_E_INVAL;
    }
    if (!kf_copy_from_kernel_nofault) {
        return -KPM_E_INVAL;
    }
    if (len <= 0 || len > 32768) {
        return -KPM_E_INVAL;
    }

    pid_struct = kf_find_get_pid(pid);
    if (!pid_struct) return -KPM_E_NOTFOUND;

    task = kf_get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }

    mm = kf_get_task_mm(task);
    if (!mm) {
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }

    ret = read_mm_pgd(mm, &pgd_va);
    if (ret < 0 || !pgd_va) {
        kf_mmput(mm);
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_FAULT;
    }

    /* 逐块读取：仅 WB 路径（无 vmap 无睡眠，RCU 临界区安全） */
    while (remaining > 0) {
        uint64_t cur_vaddr = remote_addr + offset;
        int page_remaining = (int)(PAGE_SIZE_4K - (cur_vaddr & ~PAGE_MASK_4K));
        int chunk = (remaining > page_remaining) ? page_remaining : remaining;

        if (walk_page_table(pgd_va, cur_vaddr, &phys_addr) < 0) {
            if (total == 0) total = -KPM_E_FAULT;
            break;
        }

        {
            int read_bytes = read_via_wb(phys_addr, kbuf + offset, chunk);
            if (read_bytes > 0)
                kpm_dc_civac_phys(phys_addr, (uint64_t)read_bytes);
            if (read_bytes < 0) {
                if (total == 0) total = -KPM_E_FAULT;
                break;
            }
            total += read_bytes;
            offset += read_bytes;
            remaining -= read_bytes;
            if (read_bytes < chunk) break;
        }
    }

    kpm_put_task_struct(task);
    kf_put_pid(pid_struct);
    kf_mmput(mm);
    return total;
}

/* ===== 原始 PTE 读取（zram swap 换出页解析） =====
 * 与 walk_page_table 的区别：不判断 entry 有效位，返回最底层原始页表项。
 * 换出页 entry bit0=0 但含 swp_entry 编码（type/offset），客户端据此
 * 定位 /dev/zram0 中的原页（高隐蔽：不触发目标进程缺页，无 fault 痕迹）。
 * level: 1=PMD块, 2=PTE表项。
 */
long kpm_mem_get_pte(pid_t pid, uint64_t vaddr, uint64_t *out_entry,
                     uint32_t *out_level)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    uint64_t pgd_va = 0;
    uint64_t entry = 0;
    int idx;
    long ret;
    uint32_t level = 0;
    uint64_t page_offset = get_page_offset();
    int va_bits = kpm_user_va_bits();
    uint32_t page_shift = kpm_pte_shift();

    if (!out_entry || !out_level) return -KPM_E_INVAL;
    if (!kf_find_get_pid || !kf_get_pid_task || !kf_get_task_mm || !kf_mmput)
        return -KPM_E_INVAL;
    if (!kf_copy_from_kernel_nofault)
        return -KPM_E_INVAL;

    pid_struct = kf_find_get_pid(pid);
    if (!pid_struct) return -KPM_E_NOTFOUND;
    task = kf_get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }
    mm = kf_get_task_mm(task);
    if (!mm) {
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }
    ret = read_mm_pgd(mm, &pgd_va);
    /* kf_mmput 在 done 处（pgd 使用完成后）执行，
     * walk 期间保持 mm 引用 → pgd 存活 */
    if (ret < 0 || !pgd_va) {
        kf_mmput(mm);
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_FAULT;
    }

    /* 顶层（39 位 = PGD 当 PUD） */
    if (va_bits == 48) {
        idx = (vaddr >> kpm_pgd_shift()) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(&entry, (void *)(pgd_va + idx * 8), 8);
        if (ret < 0 || !(entry & 0x1)) goto done;
        if ((entry & 0x3) == 0x1) { level = 1; goto done; }  /* PGD 块（罕见） */
    } else {
        idx = (vaddr >> kpm_pud_shift()) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(&entry, (void *)(pgd_va + idx * 8), 8);
        if (ret < 0 || !(entry & 0x1)) goto done;
        if ((entry & 0x3) == 0x1) { level = 1; goto done; }  /* 顶层 1GB 块 */
    }

    /* 48 位 PUD */
    if (va_bits == 48) {
        uint64_t pud_phys2 = (entry & kpm_pte_phys_mask());
        uint64_t pud_va;
        if (pud_phys2 < kpm_ram_guard_start() || pud_phys2 >= KPM_PHYS_MAX)
            return -1;
        pud_va = pud_phys2 - g_memstart_addr + page_offset;
        idx = (vaddr >> kpm_pud_shift()) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(&entry, (void *)(pud_va + idx * 8), 8);
        if (ret < 0 || !(entry & 0x1)) goto done;
        if ((entry & 0x3) == 0x1) { level = 1; goto done; }  /* PUD 1GB 块 */
    }

    /* PMD */
    {
        uint64_t pmd_phys2 = (entry & kpm_pte_phys_mask());
        uint64_t pmd_va;
        if (pmd_phys2 < kpm_ram_guard_start() || pmd_phys2 >= KPM_PHYS_MAX)
            return -1;
        pmd_va = pmd_phys2 - g_memstart_addr + page_offset;
        idx = (vaddr >> kpm_pmd_shift()) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(&entry, (void *)(pmd_va + idx * 8), 8);
        if (ret < 0 || !(entry & 0x1)) goto done;
        if ((entry & 0x3) == 0x1) { level = 1; goto done; }  /* PMD 2MB 块 */
    }

    /* PTE 表项（不管有效位，返回原始值） */
    {
        uint64_t pte_phys2 = (entry & kpm_pte_phys_mask());
        uint64_t pte_va;
        if (pte_phys2 < kpm_ram_guard_start() || pte_phys2 >= KPM_PHYS_MAX)
            return -1;
        pte_va = pte_phys2 - g_memstart_addr + page_offset;
        idx = (vaddr >> page_shift) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(&entry, (void *)(pte_va + idx * 8), 8);
        if (ret < 0) goto done;
        level = 2;  /* PTE 表项（有效或 swap） */
    }

done:
    /* pgd 使用完成后再释放 mm 引用 */
    kf_mmput(mm);
    kpm_put_task_struct(task);
    kf_put_pid(pid_struct);
    *out_entry = entry;
    *out_level = level;
    return 0;
}

/* 由已持有的 pgd 直接定位 PTE 槽地址（不依赖 pgtable_entry）。
 * 与 kpm_mem_get_pte 相同的四级走页，但输出最后一跳的槽地址。 */
long kpm_mem_get_pte_va(uint64_t pgd_va, uint64_t vaddr, uint64_t *out_pte_va)
{
    uint64_t entry = 0;
    uint64_t va;
    int idx;
    uint64_t page_offset;
    int va_bits;
    uint32_t page_shift;

    if (!pgd_va || !out_pte_va || !kf_copy_from_kernel_nofault)
        return -KPM_E_INVAL;
    page_offset = kpm_get_page_offset();
    va_bits = kpm_user_va_bits();
    page_shift = kpm_pte_shift();

    if (va_bits == 48) {
        idx = (vaddr >> kpm_pgd_shift()) & 0x1FF;
        if (kf_copy_from_kernel_nofault(&entry, (void *)(pgd_va + idx * 8), 8) < 0)
            return -KPM_E_FAULT;
        if (!(entry & 0x1))
            return -KPM_E_NOTFOUND;
        if ((entry & 0x3) == 0x1)
            return -KPM_E_DISABLED;
    } else {
        idx = (vaddr >> kpm_pud_shift()) & 0x1FF;
        if (kf_copy_from_kernel_nofault(&entry, (void *)(pgd_va + idx * 8), 8) < 0)
            return -KPM_E_FAULT;
        if (!(entry & 0x1))
            return -KPM_E_NOTFOUND;
        if ((entry & 0x3) == 0x1)
            return -KPM_E_DISABLED;
    }

    if (va_bits == 48) {
        uint64_t p2 = entry & kpm_pte_phys_mask();
        if (p2 < kpm_ram_guard_start() || p2 >= KPM_PHYS_MAX)
            return -KPM_E_FAULT;
        va = p2 - g_memstart_addr + page_offset;
        idx = (vaddr >> kpm_pud_shift()) & 0x1FF;
        if (kf_copy_from_kernel_nofault(&entry, (void *)(va + idx * 8), 8) < 0)
            return -KPM_E_FAULT;
        if (!(entry & 0x1))
            return -KPM_E_NOTFOUND;
        if ((entry & 0x3) == 0x1)
            return -KPM_E_DISABLED;
    }

    {
        uint64_t p2 = entry & kpm_pte_phys_mask();
        if (p2 < kpm_ram_guard_start() || p2 >= KPM_PHYS_MAX)
            return -KPM_E_FAULT;
        va = p2 - g_memstart_addr + page_offset;
        idx = (vaddr >> kpm_pmd_shift()) & 0x1FF;
        if (kf_copy_from_kernel_nofault(&entry, (void *)(va + idx * 8), 8) < 0)
            return -KPM_E_FAULT;
        if (!(entry & 0x1))
            return -KPM_E_NOTFOUND;
        if ((entry & 0x3) == 0x1)
            return -KPM_E_DISABLED;
    }

    {
        uint64_t p2 = entry & kpm_pte_phys_mask();
        if (p2 < kpm_ram_guard_start() || p2 >= KPM_PHYS_MAX)
            return -KPM_E_FAULT;
        va = p2 - g_memstart_addr + page_offset;
        idx = (vaddr >> page_shift) & 0x1FF;
        *out_pte_va = va + (uint64_t)idx * 8;
    }
    return 0;
}

/* 页级容错批量读取：逐 4KB 页处理，失败页填充 0 并在 fail_map 置位，
 * 继续下一页，返回 len。
 * fail_map bit i = 第 i 个 4KB 页区间失败（调用方保证块起点 4KB 对齐）。 */
long kpm_mem_read_kernel_pages(pid_t pid, uint64_t remote_addr, void *kbuf,
                               int len, uint32_t *fail_map)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    uint64_t pgd_va = 0;
    uint64_t phys_addr = 0;
    int offset = 0;
    int ret;

    if (fail_map)
        *fail_map = 0;

    if (!kf_find_get_pid || !kf_get_pid_task || !kf_get_task_mm || !kf_mmput ||
        !kf_copy_from_kernel_nofault)
        return -KPM_E_INVAL;
    if (len <= 0 || len > 32768)
        return -KPM_E_INVAL;

    pid_struct = kf_find_get_pid(pid);
    if (!pid_struct)
        return -KPM_E_NOTFOUND;

    task = kf_get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }

    mm = kf_get_task_mm(task);
    if (!mm) {
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }

    ret = read_mm_pgd(mm, &pgd_va);
    /* kf_mmput 在循环后执行（pgd 使用完成后） */
    if (ret < 0 || !pgd_va) {
        kf_mmput(mm);
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_FAULT;
    }

    /* 逐页容错读取：失败页补零 + 标记，继续下一页 */
    while (offset < len) {
        uint64_t cur_vaddr = remote_addr + (uint64_t)offset;
        int page_remaining = (int)(PAGE_SIZE_4K - (cur_vaddr & ~PAGE_MASK_4K));
        int chunk = (len - offset > page_remaining) ? page_remaining : (len - offset);
        int read_bytes;

        if (walk_page_table(pgd_va, cur_vaddr, &phys_addr) < 0) {
            if (fail_map)
                *fail_map |= (uint32_t)(1u << (offset / PAGE_SIZE_4K));
            memset(kbuf + offset, 0, chunk);
            offset += chunk;
            continue;
        }

        read_bytes = read_via_dma(phys_addr, kbuf + offset, chunk);
        if (read_bytes < 0) {
            read_bytes = read_via_wb(phys_addr, kbuf + offset, chunk);
            if (read_bytes > 0)
                kpm_dc_civac_phys(phys_addr, (uint64_t)read_bytes);
        }
        if (read_bytes < chunk) {
            /* 整页失败或部分读取：剩余补零并标记该页 */
            if (fail_map)
                *fail_map |= (uint32_t)(1u << (offset / PAGE_SIZE_4K));
            if (read_bytes > 0)
                memset(kbuf + offset + read_bytes, 0, chunk - read_bytes);
            else
                memset(kbuf + offset, 0, chunk);
        }
        offset += chunk;
    }

    /* walk 全部完成后再释放 mm 引用 */
    kf_mmput(mm);
    kpm_put_task_struct(task);
    kf_put_pid(pid_struct);
    return len;
}

/* ===== 线性映射 WB 读取（单页内物理连续，安全包装） =====
 * linear_va = phys - memstart + PAGE_OFFSET，chunk 必须在同一物理页内
 * （调用方保证 chunk ≤ 用户页剩余），页内物理连续 → 一次拷贝安全。 */
static int read_via_linear(uint64_t phys_addr, void *kbuf, int size)
{
    uint64_t page_base;
    uint64_t page_off;
    uint64_t linear_va;

    if (!kf_copy_from_kernel_nofault)
        return -1;
    if (g_memstart_addr == 0)
        return -1;

    page_base = phys_addr & kpm_pte_phys_mask();
    page_off = phys_addr & (kpm_user_page_size() - 1);

    /* 同 read_via_wb，防 phys < RAM 基址下溢 */
    if (page_base < kpm_ram_guard_start())
        return -1;

    /* 计算线性映射地址：va = pa - memstart_addr + PAGE_OFFSET */
    linear_va = page_base - g_memstart_addr + get_page_offset();

    /* copy_from_kernel_nofault 安全读取：失败（地址无效）返回负值，不 panic */
    if (kf_copy_from_kernel_nofault(kbuf, (void *)(linear_va + page_off), size) < 0)
        return -1;
    return size;
}

/* ===== 批量读取 =====
 *
 * 隐蔽性：copy_from_kernel_nofault 是内核标准安全拷贝 API（probe 语义），
 *          DC CIVAC 是特权 cache 维护指令，用户态不可执行不可观测。
 * 稳定性：所有读取经 copy_from_kernel_nofault 安全包装，绝不 panic。
 * 兼容性：页大小自动适配 4K/16K/64K；fail_map 位索引按用户页大小计算，
 *          256KB 块 = 64 个 4K 页 / 16 个 16K 页 / 4 个 64K 页，均 ≤ 64。
 */
/* ===== 原始 PTE 探测（swap 换出页识别） =====
 * 走 pgd_va 页表，返回最后一级 PTE 的原始条目（不判断有效位）。
 * 返回 0 成功（out_entry 为原始值，可能无效/swap）；-1 中间级无效或非 swap。
 * 与 kpm_mem_get_pte 的区别：直接使用会话级 pgd_va，无进程查找开销。 */
static int kpm_walk_raw_pte(uint64_t pgd_va, uint64_t vaddr, uint64_t *out_entry)
{
    uint64_t entry = 0;
    int idx;
    long ret;
    uint64_t page_offset = get_page_offset();
    int va_bits = kpm_user_va_bits();
    uint32_t page_shift = kpm_pte_shift();

    if (!pgd_va || !out_entry || !kf_copy_from_kernel_nofault)
        return -1;
    if (va_bits != 39 && va_bits != 48)
        return -1;

    if (va_bits == 48) {
        idx = (vaddr >> kpm_pgd_shift()) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(&entry, (void *)(pgd_va + idx * 8), 8);
        if (ret < 0 || !(entry & 0x1)) return -1;
        if ((entry & 0x3) == 0x1) return -1;   /* PGD 块：有效映射非 swap */
    } else {
        idx = (vaddr >> kpm_pud_shift()) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(&entry, (void *)(pgd_va + idx * 8), 8);
        if (ret < 0 || !(entry & 0x1)) return -1;
        if ((entry & 0x3) == 0x1) return -1;   /* 顶层 1GB 块：有效映射非 swap */
    }

    if (va_bits == 48) {
        uint64_t pud_phys2 = (entry & kpm_pte_phys_mask());
        uint64_t pud_va;
        if (pud_phys2 < kpm_ram_guard_start() || pud_phys2 >= KPM_PHYS_MAX)
            return -1;
        pud_va = pud_phys2 - g_memstart_addr + page_offset;
        idx = (vaddr >> kpm_pud_shift()) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(&entry, (void *)(pud_va + idx * 8), 8);
        if (ret < 0 || !(entry & 0x1)) return -1;
        if ((entry & 0x3) == 0x1) return -1;
    }

    {
        uint64_t pmd_phys2 = (entry & kpm_pte_phys_mask());
        uint64_t pmd_va;
        if (pmd_phys2 < kpm_ram_guard_start() || pmd_phys2 >= KPM_PHYS_MAX)
            return -1;
        pmd_va = pmd_phys2 - g_memstart_addr + page_offset;
        idx = (vaddr >> kpm_pmd_shift()) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(&entry, (void *)(pmd_va + idx * 8), 8);
        if (ret < 0 || !(entry & 0x1)) return -1;
        if ((entry & 0x3) == 0x1) return -1;   /* PMD 2MB 块：有效映射非 swap */
    }

    {
        uint64_t pte_phys2 = (entry & kpm_pte_phys_mask());
        uint64_t pte_va;
        if (pte_phys2 < kpm_ram_guard_start() || pte_phys2 >= KPM_PHYS_MAX)
            return -1;
        pte_va = pte_phys2 - g_memstart_addr + page_offset;
        idx = (vaddr >> page_shift) & 0x1FF;
        ret = kf_copy_from_kernel_nofault(&entry, (void *)(pte_va + idx * 8), 8);
        if (ret < 0) return -1;
        *out_entry = entry;   /* 原始 PTE（可能无效/swap） */
        return 0;
    }
}

/* 批量读取扩展版（swap 换出页位图）。
 * 与 kpm_mem_read_batch 语义一致，额外输出 swap_map：
 *   bit i = 第 i 个用户页是 swap/zram 换出页（原始 PTE 非零且 bit0=0）。
 * swap_map 传 NULL 时兼容 ptr_scan 等调用方。 */
long kpm_mem_read_batch2(kpm_walk_ctx_t *ctx, uint64_t remote_addr,
                         void *kbuf, int len, uint64_t *fail_map,
                         uint64_t *swap_map)
{
    uint64_t phys_addr = 0;
    int offset = 0;
    int page_shift;
    uint64_t page_size;

    if (fail_map)
        *fail_map = 0;
    if (swap_map)
        *swap_map = 0;

    if (!ctx || !ctx->pgd_va || !kbuf)
        return -KPM_E_INVAL;
    if (!kf_copy_from_kernel_nofault)
        return -KPM_E_INVAL;
    if (len <= 0 || len > KPM_SCAN_BATCH_MAX)
        return -KPM_E_INVAL;

    page_shift = kpm_pte_shift();
    page_size = 1ULL << page_shift;

    /* 逐页容错读取：失败页补零 + 标记，继续下一页 */
    while (offset < len) {
        uint64_t cur_vaddr = remote_addr + (uint64_t)offset;
        int page_remaining = (int)(page_size - (cur_vaddr & (page_size - 1)));
        int chunk = (len - offset > page_remaining) ? page_remaining : (len - offset);
        int pbit = offset >> page_shift;

        /* 防御：fail_map 位索引越界（len > 64 页时截断，调用方保证 ≤64） */
        if (pbit >= 64)
            break;

        /* 大页 chunk 优化依赖 cached walk 的 last_map_granule，
         * 已随 cached walk 停用。 */
        if (0 && ctx->last_map_granule > page_size) {
            uint64_t gran = ctx->last_map_granule;
            int gran_remaining = (int)(gran - (cur_vaddr & (gran - 1)));
            if (chunk < gran_remaining)
                chunk = gran_remaining;
            if (chunk > len - offset)
                chunk = len - offset;
        }

        if (walk_page_table(ctx->pgd_va, cur_vaddr, &phys_addr) < 0) {
            if (fail_map)
                *fail_map |= (uint64_t)(1ULL << pbit);
            /* 区分 swap 换出页：ARM64 __swp_entry_to_pte 直接写入
             * (offset<<10)|(type<<5)，bit1-4 无编码（恒 0）；
             * 非零 + 非 present（bit0=0）= 换出/迁移条目。
             * 未映射/惰性页 entry=0 或中间级无效则不是 swap。 */
            if (swap_map) {
                uint64_t raw = 0;
                if (kpm_walk_raw_pte(ctx->pgd_va, cur_vaddr, &raw) == 0 &&
                    raw != 0 && !(raw & 0x1)) {
                    if (pbit < 64)
                        *swap_map |= (uint64_t)(1ULL << pbit);
                }
            }
            memset(kbuf + offset, 0, chunk);
            offset += chunk;
            continue;
        }

        /* 读取路径与直读保持一致：read_via_dma → read_via_wb → 失败标记。 */
        {
            int rb = read_via_dma(phys_addr, kbuf + offset, chunk);
            if (rb <= 0)
                rb = read_via_wb(phys_addr, kbuf + offset, chunk);
            if (rb <= 0) {
                /* 标记本次 chunk 覆盖的所有页。大页（chunk 扩大）整块失败时
                 * 必须全部标记，否则补零数据参与匹配造成假命中。 */
                if (fail_map) {
                    uint64_t pages = (uint64_t)((chunk + (int)page_size - 1) >> page_shift);
                    uint64_t bits;
                    int k;
                    if (pages >= 64) {
                        bits = ~0ULL;
                    } else {
                        bits = 0;
                        for (k = 0; k < (int)pages && (pbit + k) < 64; k++)
                            bits |= (1ULL << (pbit + k));
                    }
                    *fail_map |= bits;
                }
                memset(kbuf + offset, 0, chunk);
                offset += chunk;
                continue;
            }
        }

        /* WB 读取后清洗缓存行：压缩 Flush+Reload 残留窗口。
         * 大页（chunk 扩大）时一次清洗整块（比逐页清洗快 64 倍）。
         * kpm_dc_civac_phys 内含物理地址合法性校验，绝不 panic。 */
        kpm_dc_civac_phys(phys_addr, (uint64_t)chunk);
        offset += chunk;
    }

    return len;
}

/* 兼容薄包装：无 swap_map 的签名，行为与 kpm_mem_read_batch2(..., NULL) 一致 */
long kpm_mem_read_batch(kpm_walk_ctx_t *ctx, uint64_t remote_addr,
                        void *kbuf, int len, uint64_t *fail_map)
{
    return kpm_mem_read_batch2(ctx, remote_addr, kbuf, len, fail_map, NULL);
}

/* ===== 会话级缓存版批量读取 =====
 *
 * 与 kpm_mem_read_kernel_pages 的区别：
 *   1. 接受 pgd_va 参数（会话级缓存），跳过 find_get_pid/get_pid_task/
 *      get_task_mm/read_mm_pgd/mmput/put_task_struct/put_pid 全套进程查找。
 *   2. 单次 len 上限 256KB（KPM_SCAN_BATCH_MAX）。
 *
 * 隐蔽性：
 *   - 跳过的进程查找都是 atomic 操作（PID 引用计数、mm 引用计数），
 *     跳过它们反而减少可观测的同步原语调用。
 *
 * 稳定性：
 *   - pgd_va 由调用方在 scan_start 时获取并持有 mm 引用保护。
 *   - 整个会话期间 mm_struct 不释放，pgd 指向的页表有效。
 *   - PTE 表项每次重新读取，反映最新映射状态。
 */
long kpm_mem_read_kernel_pages_cached(uint64_t pgd_va, uint64_t remote_addr,
                                       void *kbuf, int len,
                                       uint64_t *fail_map)
{
    kpm_walk_ctx_t walk_ctx;
    long ret;

    if (fail_map)
        *fail_map = 0;

    if (!pgd_va || !kbuf)
        return -KPM_E_INVAL;
    if (!kf_copy_from_kernel_nofault)
        return -KPM_E_INVAL;
    if (len <= 0 || len > KPM_SCAN_BATCH_MAX)
        return -KPM_E_INVAL;

    /* 初始化 walk 上下文：本调用内复用 PMD/PTE 表项缓存 */
    memset(&walk_ctx, 0, sizeof(walk_ctx));
    walk_ctx.pgd_va = pgd_va;

    ret = kpm_mem_read_batch(&walk_ctx, remote_addr, kbuf, len, fail_map);
    return ret;
}

/* ===== 会话级进程引用管理 =====
 * scan_start 一次性获取并缓存，scan_clear 释放。
 * 详见 kpm_mem_rw.h 头部注释。 */
int kpm_mem_open_scan_session(pid_t pid, void **out_pid_struct,
                                void **out_task, void **out_mm,
                                uint64_t *out_pgd_va)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    uint64_t pgd_va = 0;
    int ret;

    if (out_pid_struct) *out_pid_struct = NULL;
    if (out_task) *out_task = NULL;
    if (out_mm) *out_mm = NULL;
    if (out_pgd_va) *out_pgd_va = 0;

    if (!kf_find_get_pid || !kf_get_pid_task || !kf_get_task_mm || !kf_mmput ||
        !kf_copy_from_kernel_nofault)
        return -KPM_E_INVAL;

    pid_struct = kf_find_get_pid(pid);
    if (!pid_struct) {
        kpm_log("kpm: session: find_get_pid failed pid=%d\n", pid);
        return -KPM_E_NOTFOUND;
    }

    task = kf_get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        kpm_log("kpm: session: get_pid_task failed pid=%d\n", pid);
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }

    mm = kf_get_task_mm(task);
    if (!mm) {
        kpm_log("kpm: session: get_task_mm failed pid=%d\n", pid);
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }

    /* RCU 读锁仅保护 read_mm_pgd（短临界区，禁止睡眠） */
    kpm_mmap_read_lock(mm);
    ret = read_mm_pgd(mm, &pgd_va);
    kpm_mmap_read_unlock(mm);

    if (ret < 0 || !pgd_va) {
        kpm_log("kpm: session: read_mm_pgd failed pid=%d pgd=%llx\n",
                pid, (unsigned long long)pgd_va);
        kf_mmput(mm);
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_FAULT;
    }

    if (out_pid_struct) *out_pid_struct = pid_struct;
    if (out_task) *out_task = task;
    if (out_mm) *out_mm = mm;
    if (out_pgd_va) *out_pgd_va = pgd_va;

    kpm_log("kpm: session opened pid=%d pgd=%llx\n",
            pid, (unsigned long long)pgd_va);
    return 0;
}

void kpm_mem_close_scan_session(void *pid_struct, void *task, void *mm)
{
    if (mm) {
        kf_mmput((struct mm_struct *)mm);
    }
    if (task) {
        kpm_put_task_struct((struct task_struct *)task);
    }
    if (pid_struct) {
        kf_put_pid((struct pid *)pid_struct);
    }
}

/* 内核内部跨进程内存写入（不涉及用户态拷贝）
 * 用于断点写入等内核模块内部调用
 * 绕过所有缓存层级，写入后执行 DC CIVAC 清除缓存行
 */
long kpm_mem_write_kernel(pid_t pid, uint64_t remote_addr, const void *kbuf, int len)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    uint64_t pgd_va = 0;
    uint64_t phys_addr = 0;
    uint64_t offset = 0;
    int remaining = len;
    int total = 0;
    int ret;

    if (!kf_find_get_pid || !kf_get_pid_task || !kf_get_task_mm || !kf_mmput) {
        return -KPM_E_INVAL;
    }
    if (len <= 0 || len > 32768) {
        return -KPM_E_INVAL;
    }

    pid_struct = kf_find_get_pid(pid);
    if (!pid_struct) return -KPM_E_NOTFOUND;

    task = kf_get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }

    mm = kf_get_task_mm(task);
    if (!mm) {
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }

    ret = read_mm_pgd(mm, &pgd_va);
    /* kf_mmput 在 walk 完成后执行。写路径对 pgd 的依赖比读路径更关键：
     * pgd 被提前释放后 walk 可能解析出伪 phys → write_via_wb 经
     * phys_to_virt 写任意物理页 → 内核内存损坏 */
    if (ret < 0 || !pgd_va) {
        kf_mmput(mm);
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_FAULT;
    }

    while (remaining > 0) {
        uint64_t cur_vaddr = remote_addr + offset;
        int page_remaining = (int)(PAGE_SIZE_4K - (cur_vaddr & ~PAGE_MASK_4K));
        int chunk = (remaining > page_remaining) ? page_remaining : remaining;

        if (walk_page_table(pgd_va, cur_vaddr, &phys_addr) < 0) {
            if (total == 0) total = -KPM_E_FAULT;
            break;
        }

        {
            int written = write_via_dma(phys_addr, kbuf + offset, chunk);
            /* DMA 写入失败时回退 write_via_wb（kf_vmap 或 g_vmemmap_base
             * 不可用时 DMA 路径失效），保持两条路径一致。 */
            if (written < 0) {
                written = write_via_wb(phys_addr, kbuf + offset, chunk);
            }
            if (written < 0) {
                if (total == 0) total = -KPM_E_FAULT;
                break;
            }
            total += written;
            offset += written;
            remaining -= written;
            if (written < chunk) break;
        }
    }

    /* walk 全部完成后再释放 mm 引用 */
    kf_mmput(mm);
    kpm_put_task_struct(task);
    kf_put_pid(pid_struct);
    return total;
}

/* ===== 内核虚拟地址读写（pid=0 通道） =====
 * 安全要点：
 *   - 读不分页遍历：内核 VA 直接 copy_from_kernel_nofault（失败不 panic）；
 *   - 非 force 逐页过 kpm_is_safe_kern_addr（DEVAPC 守卫）；
 *   - 写非 force 一律返回 -KPM_E_PERM；force 下 text 走官方 patch 接口。
 */
long kpm_mem_read_kernel_va(uint64_t addr, void *kbuf, int len, int force)
{
    int offset = 0;

    if (!kbuf || len <= 0)
        return -KPM_E_INVAL;
    if (!addr || addr < 0xFFFF000000000000ULL)
        return -KPM_E_INVAL;
    if (!kf_copy_from_kernel_nofault)
        return -KPM_E_DISABLED;
    if (len > 32768)
        len = 32768;

    while (offset < len) {
        uint64_t cur = addr + (uint64_t)offset;
        int page_rem = (int)(PAGE_SIZE_4K - (cur & (PAGE_SIZE_4K - 1)));
        int chunk = (len - offset > page_rem) ? page_rem : (len - offset);

        if (!force && !kpm_is_safe_kern_addr(cur)) {
            if (offset > 0)
                break;
            return -KPM_E_PERM;
        }
        if (kf_copy_from_kernel_nofault((char *)kbuf + offset,
                                        (const void *)cur, chunk) != 0)
            break;
        offset += chunk;
    }
    return (offset > 0) ? offset : -KPM_E_FAULT;
}

long kpm_mem_write_kernel_va(uint64_t addr, const void *kbuf, int len,
                             int force)
{
    if (!force)
        return -KPM_E_PERM;   /* 非 force：内核写一律拒绝（fail-closed） */
    if (!kbuf || len <= 0 || !addr || addr < 0xFFFF000000000000ULL)
        return -KPM_E_INVAL;
    if (len > 32768)
        len = 32768;

    if (is_kimg_range(addr)) {
        int done = 0;

        if (!kf_aarch64_insn_patch_text)
            return -KPM_E_DISABLED;
        if ((addr & 0x3) || (len & 0x3))
            return -KPM_E_INVAL;   /* text 只能 4 字节对齐写入 */
        while (done < len) {
            void *addrs[64];
            uint32_t insns[64];
            int cnt = (len - done) / 4;
            int i;

            if (cnt > 64)
                cnt = 64;
            for (i = 0; i < cnt; i++) {
                addrs[i] = (void *)(uintptr_t)(addr + (uint64_t)done +
                                               (uint64_t)i * 4);
                lib_memcpy(&insns[i],
                           (const char *)kbuf + done + i * 4, 4);
            }
            if (kf_aarch64_insn_patch_text(addrs, insns, cnt) != 0)
                return (done > 0) ? done : -KPM_E_FAULT;
            done += cnt * 4;
        }
        return done;
    }

    if (!kf_copy_to_kernel_nofault)
        return -KPM_E_DISABLED;
    {
        int offset = 0;

        while (offset < len) {
            uint64_t cur = addr + (uint64_t)offset;
            int page_rem = (int)(PAGE_SIZE_4K - (cur & (PAGE_SIZE_4K - 1)));
            int chunk = (len - offset > page_rem) ? page_rem : (len - offset);

            if (kf_copy_to_kernel_nofault((void *)cur,
                                          (const char *)kbuf + offset,
                                          chunk) != 0)
                break;
            offset += chunk;
        }
        return (offset > 0) ? offset : -KPM_E_FAULT;
    }
}

/* ===== uprobe handler 安全写入：强制 WB 路径 =====
 * 与 kpm_mem_write_kernel 的区别：只走 write_via_wb（线性映射直写 +
 * copy_to_kernel_nofault + DC CIVAC），【不走】write_via_dma——
 * DMA 路径内部 kf_vmap 可能睡眠（vmalloc 分配），而 uprobe 回调运行于
 * handler_chain 的 RCU 读临界区（rcu_read_lock），vmap 睡眠会无限延长
 * 临界区 → 卸载线程 synchronize_rcu 等待超时 → 系统卡死。
 * 用途：gyro/传感器 uprobe handler 改写用户态 sensors_event_t。 */
long kpm_mem_write_kernel_wb(pid_t pid, uint64_t remote_addr,
                             const void *kbuf, int len)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    uint64_t pgd_va = 0;
    uint64_t phys_addr = 0;
    uint64_t offset = 0;
    int remaining = len;
    int total = 0;
    int ret;

    if (!kf_find_get_pid || !kf_get_pid_task || !kf_get_task_mm || !kf_mmput) {
        return -KPM_E_INVAL;
    }
    if (len <= 0 || len > 32768) {
        return -KPM_E_INVAL;
    }

    pid_struct = kf_find_get_pid(pid);
    if (!pid_struct) return -KPM_E_NOTFOUND;

    task = kf_get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }

    mm = kf_get_task_mm(task);
    if (!mm) {
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_NOTFOUND;
    }

    ret = read_mm_pgd(mm, &pgd_va);
    if (ret < 0 || !pgd_va) {
        kf_mmput(mm);
        kpm_put_task_struct(task);
        kf_put_pid(pid_struct);
        return -KPM_E_FAULT;
    }

    /* 逐块写入：仅 WB 路径（无 vmap 无睡眠，RCU 临界区安全） */
    while (remaining > 0) {
        uint64_t cur_vaddr = remote_addr + offset;
        int page_remaining = (int)(PAGE_SIZE_4K - (cur_vaddr & ~PAGE_MASK_4K));
        int chunk = (remaining > page_remaining) ? page_remaining : remaining;

        if (walk_page_table(pgd_va, cur_vaddr, &phys_addr) < 0) {
            if (total == 0) total = -KPM_E_FAULT;
            break;
        }

        {
            int written = write_via_wb(phys_addr, kbuf + offset, chunk);
            if (written < 0) {
                if (total == 0) total = -KPM_E_FAULT;
                break;
            }
            total += written;
            offset += written;
            remaining -= written;
            if (written < chunk) break;
        }
    }

    kf_mmput(mm);
    kpm_put_task_struct(task);
    kf_put_pid(pid_struct);
    return total;
}