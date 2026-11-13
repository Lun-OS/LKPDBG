/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_gyro.c - Gyro/Accel Sensor control via uprobe on libsensorservice
 *
 * 通过 uprobe 挂载 libsensorservice.so
 * 的 convertToSensorEvent() 函数，在"转换完成、尚未上报给应用"的返回点
 * 改写 sensors_event_t 输出缓冲（x/y/z float），实现传感器数据控制。
 *
 * 数据流：
 *   system_server 内 sensorservice 线程调用 convertToSensorEvent()
 *     ├─ uprobe pre handler : 记录本次调用的 sensors_event_t* 输出缓冲
 *     │                       （从 regs->regs[1] 取 x1，按 task 哈希入表）
 *     ├─ convertToSensorEvent() 执行，填充输出缓冲
 *     └─ uprobe ret handler : 按 task 查缓冲，读 type 字段
 *                            映射到本项目 (type,axis)，改写 x/y/z float
 *   之后事件上抛给应用 → 进程读到修改后的数据
 *
 * 控制方法：锁定（lock）+ 虚拟力（control: RAMP/DIRECT）+ 客户端保活（keepalive）。
 * 数据以 float 位模式存储（int 字段承载 float bits，避免浮点指令）。
 *
 * 关键实现（自包含，不依赖框架缺失的 uprobes.h/mpt_regs）：
 *   - struct uprobe_consumer 按内核 ABI 自包含定义（handler/ret_handler）
 *   - handler 签名用 struct pt_regs *（框架 asm/ptrace.h 已定义）
 *   - ELF 动态解析 convertToSensorEvent 符号偏移（AIDL 优先 + HIDL 回退）
 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/sched.h>   /* task_struct：current->pid（uprobe 上下文直读） */
#include <linux/err.h>   /* IS_ERR_OR_NULL */
#include <asm/current.h>
#include <asm/ptrace.h>
#include <baselib.h>    /* lib_memset */

#include "LH_gyro.h"
#include "LH_syms.h"
#include "LH_log.h"
#include "LH_utils.h"
#include "LH_proc.h"     /* kpm_read_file */
#include "LH_mem_rw.h"   /* kpm_mem_read_kernel */
#include "LH_comm.h"     /* KPM_E_* 错误码 */

/* ===== 传感器库路径 ===== */
#define KPM_GYRO_LIB_PATH       "/system/lib64/libsensorservice.so"
#define KPM_GYRO_LIB_BASENAME   "libsensorservice"

/* GFP_KERNEL 在 KPM 框架的 gfp.h 中被注释掉，此处手动定义（同 LH_syms.c） */
#ifndef GFP_KERNEL
#define GFP_KERNEL  0xcc0u
#endif
/* GFP_ATOMIC = __GFP_HIGH(0x20) | __GFP_ATOMIC(0x200) | __GFP_KSWAPD_RECLAIM(0x800)。
 * uprobe pre handler 运行于 mmap_lock 读锁持有上下文，禁止可睡眠
 * 分配（GFP_KERNEL 可能触发 reclaim 睡眠）；原子分配不睡眠，失败则本帧透传。 */
#ifndef GFP_ATOMIC
#define GFP_ATOMIC  0xa20u
#endif

/* ===== ELF64 结构（自包含，避免依赖缺失头） ===== */

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} kpm_elf64_ehdr;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} kpm_elf64_shdr;

typedef struct {
    uint32_t st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} kpm_elf64_sym;

#define KPM_SHT_DYNSYM  11
#define KPM_SHT_STRTAB  3
#define KPM_SHT_SYMTAB  2

/* =====  kern_path 用（自包含，避免依赖缺失的 namei.h/path.h） =====
 * LOOKUP_FOLLOW = 0x0001（include/linux/namei.h）
 * struct path（include/linux/path.h）：
 *   struct path { struct vfsmount *mnt; struct dentry *dentry; };
 *   mnt 在 +0，dentry 在 +8。框架未提供该头，此处仅声明所需字段。 */
#define KPM_LOOKUP_FOLLOW  0x0001
struct kpm_path {
    void *mnt;      /* struct vfsmount *，offset 0 */
    void *dentry;   /* struct dentry *，offset 8 */
};
/* struct dentry :: d_inode 偏移 = d_name.name 偏移(g_dentry_name_offset) + 8
 * （标准 64 位布局：d_flags+d_seq+d_hash+d_parent+d_name(16B) 后紧跟 d_inode） */

/* ===== uprobe consumer（按内核 ABI 自包含定义） =====
 * 与内核 include/linux/uprobes.h 一致（6.1 无 ref_ctr 字段）：
 *   struct uprobe_consumer {
 *       int (*handler)(struct uprobe_consumer *self, struct pt_regs *regs);
 *       int (*ret_handler)(struct uprobe_consumer *self,
 *                           unsigned long func, struct pt_regs *regs);
 *       bool (*filter)(struct uprobe_consumer *self, struct task_struct *task);
 *       struct uprobe_consumer *next;
 *   }; */
struct kpm_uprobe_consumer {
    int (*handler)(struct kpm_uprobe_consumer *self, struct pt_regs *regs);
    int (*ret_handler)(struct kpm_uprobe_consumer *self,
                       unsigned long func, struct pt_regs *regs);
    int (*filter)(struct kpm_uprobe_consumer *self, struct task_struct *task);
    struct kpm_uprobe_consumer *next;
};

/* ===== 全局状态 ===== */
kpm_gyro_state_t g_gyro;

static int g_gyro_hook = 0;          /* uprobe 已注册 */
static int g_gyro_ready = 0;         /* 已安装（inode+offset 就绪） */
static int g_gyro_tp_ok = 0;         /* sys_enter tracepoint 已注册 */
static uint64_t g_gyro_up_hits = 0;  /* uprobe 路径改写计数（自动侦测：路径是否真在工作） */
static uint64_t g_gyro_tp_hits = 0;  /* tracepoint 路径改写计数 */
static struct kpm_uprobe_consumer g_gyro_uc;   /* AIDL 符号 consumer */
static struct kpm_uprobe_consumer g_gyro_uc2;  /* HIDL 符号 consumer */
static long long g_gyro_offset2 = -1;          /* HIDL convertToSensorEvent 偏移 */
static void *g_gyro_inode = NULL;    /* libsensorservice*.so 的 inode（igrab 持有引用） */
static long long g_gyro_offset = -1; /* convertToSensorEvent 文件偏移 */
static pid_t g_gyro_mem_pid = 0;     /* 已映射 libsensorservice.so 的目标进程 */
static uint64_t g_gyro_mem_base = 0; /* 目标进程内 libsensorservice.so 加载基址 */
static const char *g_gyro_lib_path = KPM_GYRO_LIB_PATH;  /* 选定库路径 */

/* 原子递增（ldxr/stxr）。自实现原因：__sync_fetch_and_add 的 64 位版本
 * 会生成对 __aarch64_ldadd8_sync 的调用（libgcc），该符号不在 KPM 框架
 * .kp.symbol 段 → kpm 加载器 UND 解析失败 → 加载报 -2（ENOENT）。 */
static inline void kpm_gyro_count_inc(uint64_t *p)
{
    uint64_t v;

    asm volatile(
        "1: ldxr %0, [%1]\n"
        "   add  %0, %0, #1\n"
        "   stxr w2, %0, [%1]\n"
        "   cbnz w2, 1b\n"
        : "=&r"(v)
        : "r"(p)
        : "memory", "w2");
}

/* ===== 传感器 type 映射表 =====
 * Android sensor type → 本项目 (type, axis)。X/Y/Z 轴直接对应 data[0..2]。 */
const kpm_gyro_stype_map_t kpm_gyro_stype_map[] = {
    { KPM_STYPE_GYROSCOPE,              KPM_GYRO_ROTATION },
    { KPM_STYPE_GYROSCOPE_UNCALIBRATED, KPM_GYRO_ROTATION },
    { KPM_STYPE_ROTATION_VECTOR,        KPM_GYRO_ROTATION },
    { KPM_STYPE_ORIENTATION,            KPM_GYRO_ROTATION },
    { KPM_STYPE_ACCELEROMETER,          KPM_GYRO_TRANSLATION },
    { KPM_STYPE_ACCELEROMETER_UNCALIBRATED, KPM_GYRO_TRANSLATION },
    { KPM_STYPE_LINEAR_ACCELERATION,    KPM_GYRO_TRANSLATION },
    { KPM_STYPE_GRAVITY,                KPM_GYRO_TRANSLATION },
    { KPM_STYPE_MAGNETIC_FIELD,         KPM_GYRO_TRANSLATION },
};
const int kpm_gyro_stype_map_cnt =
    (int)(sizeof(kpm_gyro_stype_map) / sizeof(kpm_gyro_stype_map[0]));

/* 将 sensors_event_t.type 映射到本项目 type，未匹配返回 -1 */
static int kpm_gyro_stype_to_ktype(int32_t s_type)
{
    int i;
    for (i = 0; i < kpm_gyro_stype_map_cnt; i++) {
        if (kpm_gyro_stype_map[i].s_type == s_type)
            return kpm_gyro_stype_map[i].k_type;
    }
    return -1;
}

/* ===== 轴变换核心 =====
 * 传感器数据是 float（IEEE 754 位模式）。uprobe handler 运行在被跟踪进程
 * 上下文（非硬 IRQ，但 FP 状态未保存——arm64 懒加载 FP，handler 里用浮点
 * 会污染用户态 FP 状态），因此禁止浮点指令（-mgeneral-regs-only 也强制），
 * 所有控制量以 int32 承载 float 位模式，仅做整数位运算。
 *
 * 语义：
 *   - 基值（base）：
 *       locked   → lock_anchor（硬锁定锚点：用户输入完全被替换，轴脱离用户）
 *       !locked  → value_bits（用户实时读数，透传——用户控制始终有效）
 *   - 虚拟力（control）：输出 = base + force_offset【叠加，绝不替换】
 *     DIRECT: force_offset 一步置为 force_target（叠加偏移量）
 *     RAMP:   force_offset 以 speed 步长逼近 target（平滑叠加）
 *     叠加而非替换 → 用户转动设备时 value_bits 变化，输出跟随变化，
 *     虚拟力只是在用户读数上叠加一个偏移，用户控制永不被覆盖。
 *   - 锁定当前（lock_current）：捕获下一帧后置 lock_anchor=0（零角速度，
 *     角度冻结在当前朝向），而非捕获瞬时角速度——否则冻结非零角速度会
 *     导致视角持续旋转。
 *   - 停止/超时：force_offset 直接归 0（叠加量归零，恢复纯透传/纯锚点）。 */

/* ===== IEEE754 单精度软浮点（整数位运算，兼容 -mgeneral-regs-only） =====
 * 用于 base + force_offset 的叠加（float 加法无法用硬件 FP 指令）。
 * 仅需加/减/比较，不涉及乘除。 */

/* 单精度加法：返回 (a + b) 的位模式。简化实现：支持 0/次正规/有限数/Inf；
 * NaN 按 a 处理（本场景不会出现 NaN 输入）。 */
static int32_t kpm_f32_add(int32_t a_bits, int32_t b_bits)
{
    uint32_t a = (uint32_t)a_bits;
    uint32_t b = (uint32_t)b_bits;
    uint32_t sa = a & 0x80000000u;
    uint32_t sb = b & 0x80000000u;
    uint32_t ea = (a >> 23) & 0xFFu;
    uint32_t eb = (b >> 23) & 0xFFu;
    uint32_t ma = a & 0x7FFFFFu;
    uint32_t mb = b & 0x7FFFFFu;
    uint32_t sign, exp, mant;
    int32_t diff;

    /* 零 + x = x（含 -0 + x） */
    if ((ea == 0 && ma == 0) || (eb == 0 && mb == 0)) {
        if (ea == 0 && ma == 0) return (int32_t)b;
        return (int32_t)a;
    }
    /* Inf 处理 */
    if (ea == 0xFFu || eb == 0xFFu) {
        if (ea == 0xFFu) return (int32_t)a;
        return (int32_t)b;
    }
    /* 次正规：指数按 1 处理，无隐式位 */
    if (ea == 0) { ea = 1; } else { ma |= 0x800000u; }
    if (eb == 0) { eb = 1; } else { mb |= 0x800000u; }

    /* 对齐：取较大指数，较小者尾数右移 */
    if (ea > eb) {
        diff = (int32_t)(ea - eb);
        if (diff > 25) diff = 25;   /* 完全移出 */
        mb >>= diff;
    } else if (eb > ea) {
        diff = (int32_t)(eb - ea);
        if (diff > 25) diff = 25;
        ma >>= diff;
    }
    exp = (ea > eb) ? ea : eb;

    if (sa == sb) {
        /* 同号：尾数相加 */
        mant = ma + mb;
        sign = sa;
        if (mant & 0x1000000u) { mant >>= 1; exp++; }  /* 进位 */
    } else {
        /* 异号：尾数相减，符号取大者 */
        if (ma >= mb) { mant = ma - mb; sign = sa; }
        else         { mant = mb - ma; sign = sb; }
        if (mant == 0) return 0;   /* a + (-a) = 0 */
        /* 归一化：左移直到最高位为 1（隐式位位置） */
        while (!(mant & 0x800000u)) {
            mant <<= 1;
            exp--;
        }
        if ((int32_t)exp <= 0) {
            /* 下溢到次正规/零：取指数 0 粗略近似 */
            return 0;
        }
    }

    /* 舍入：简单截断（低 1 位丢弃）。溢出到 Inf。 */
    if (exp >= 0xFFu) {
        return (int32_t)(sign | 0x7F800000u);   /* ±Inf */
    }
    mant &= 0x7FFFFFu;
    return (int32_t)(sign | (exp << 23) | mant);
}

/* 单精度减法：a - b */
static int32_t kpm_f32_sub(int32_t a_bits, int32_t b_bits)
{
    return kpm_f32_add(a_bits, (int32_t)((uint32_t)b_bits ^ 0x80000000u));
}

/* 单精度比较：返回 <0 / 0 / >0（位模式安全比较，含负数） */
static int kpm_f32_cmp(int32_t a_bits, int32_t b_bits)
{
    int32_t d = kpm_f32_sub(a_bits, b_bits);
    if (d == 0) return 0;
    return ((uint32_t)d & 0x80000000u) ? -1 : 1;
}
static int32_t kpm_gyro_transform(int type, int axis, int32_t value_bits,
                                  int is_rate_sensor)
{
    kpm_gyro_axis_t *a;
    int32_t base, out;

    if (type < 0 || type >= KPM_GYRO_TYPE_MAX)
        return value_bits;
    if (axis < 0 || axis >= KPM_GYRO_AXIS_MAX)
        return value_bits;

    a = (type == KPM_GYRO_TRANSLATION) ? &g_gyro.tran[axis]
                                       : &g_gyro.rot[axis];

    /* 内存屏障：与 process 上下文的 control/lock 写入保持顺序 */
    asm volatile("dmb ish" ::: "memory");

    /* 虚拟力偏移演化（float 域软浮点步进）：
     * force_offset 是【叠加量】，与基值相加输出，绝不替换基值。
     * DIRECT: 一步置为 target；RAMP: 以 speed 逼近 target。 */
    if (a->force_active) {
        if (a->force_mode == KPM_GYRO_FORCE_DIRECT) {
            /* 直接偏移模式：offset 一步置为 target，保持不回正 */
            a->force_offset = a->force_target;
        } else if (kpm_f32_cmp(a->force_offset, a->force_target) < 0) {
            a->force_offset = kpm_f32_add(a->force_offset, a->force_speed);
            if (kpm_f32_cmp(a->force_offset, a->force_target) > 0)
                a->force_offset = a->force_target;
        } else if (kpm_f32_cmp(a->force_offset, a->force_target) > 0) {
            a->force_offset = kpm_f32_sub(a->force_offset, a->force_speed);
            if (kpm_f32_cmp(a->force_offset, a->force_target) < 0)
                a->force_offset = a->force_target;
        }
    } else if (a->force_offset != 0) {
        /* 停止控制：叠加量直接归 0（恢复纯透传/纯锚点输出）。
         * 不做平滑回正：force_speed 可能是次正规极小值（float 位模式
         * 1.4e-45），步进回正几乎永远走不完；且叠加量归零只影响
         * 偏移部分，输出 = base + 0 = base，与停止前 base 连续。 */
        a->force_offset = 0;
    }

    /* 基值：锁定锚点 或 用户实时读数 */
    if (a->locked) {
        if (a->lock_current) {
            /* 锁定当前读数：捕获本帧真实值作为锚点，此后冻结在该位置。
             * 本帧透传真实值，下一事件起输出锚点。
             * - 角度型传感器（旋转矢量/方向/加速度，data=位置）：
             *   锚点 = 捕获的当前读数（位置本身，直接冻结）✓
             * - 角速度型传感器（陀螺仪，data=角速度）：
             *   锚点 = 0（零角速度 = 角度冻结在当前朝向）。若锚点取
             *   捕获的瞬时角速度，冻结的是非零转速 → 视角持续旋转。 */
            a->lock_anchor = is_rate_sensor ? 0 : value_bits;
            a->lock_current = 0;
            base = value_bits;
        } else {
            base = a->lock_anchor;        /* 硬锁定：用户输入完全替换为锚点 */
        }
    } else {
        base = value_bits;                /* 未锁定：透传用户实时读数 */
    }

    /* 输出 = 基值 + 虚拟偏移（叠加；偏移为 0 时即纯基值）。
     * 用户转动设备时 value_bits 变化，输出跟随变化 → 用户控制永不被覆盖；
     * 偏移固定时（角度型传感器）输出收敛到"真实位置 + 目标偏移"，
     * 不会持续旋转。 */
    if (a->force_offset != 0)
        out = kpm_f32_add(base, a->force_offset);
    else
        out = base;

    asm volatile("dmb ish" ::: "memory");
    return out;
}

/* ===== 每任务上下文记录 =====
 * 由于 sensorservice 可能在多线程并发调用 convertToSensorEvent，按 task
 * 哈希分桶隔离，避免跨线程串扰。桶数 16，黄金比例哈希。 */

#define KPM_GYRO_CTX_HT_SIZE  16

struct kpm_gyro_ctx {
    struct kpm_gyro_ctx *next;
    struct task_struct *task;   /* 当前线程 */
    void *dst;                  /* sensors_event_t* 输出缓冲（用户态） */
};

static struct kpm_gyro_ctx *g_gyro_ctx_ht[KPM_GYRO_CTX_HT_SIZE];
static kpm_spinlock_t g_gyro_ctx_lock = KPM_SPINLOCK_INIT;

static unsigned int kpm_gyro_ctx_hash(struct task_struct *task)
{
    uint64_t v = (uint64_t)task;
    v ^= v >> 32;
    v = v * 0x61C8864680B583EBULL;
    return (unsigned int)((v >> 57) & (KPM_GYRO_CTX_HT_SIZE - 1));
}

/* 是否有任一控制处于启用状态（锁定 / 虚拟力）——定义见文件后半段
 * （kpm_gyro_purge_if_idle 上方）。pre handler 复用同一判定：无控制时
 * 不分配 ctx、不插链，ret 侧找不到 ctx 自然跳过。此处前置声明以便
 * pre handler 调用。 */
static int kpm_gyro_any_active(void);

/* pre handler：记录本次调用的 sensors_event_t* 输出缓冲 */
static int kpm_gyro_uprobe_pre(struct kpm_uprobe_consumer *self,
                               struct pt_regs *regs)
{
    struct task_struct *task = current;
    struct kpm_gyro_ctx *ctx;
    struct kpm_gyro_ctx **head;
    unsigned int h;
    unsigned long flags;

    (void)self;
    if (!g_gyro_ready) return 0;
    /* 无任一控制启用 → 本帧不需要改写，直接透传：不分配、不插链。
     * 与 ret 侧同一判定（kpm_gyro_any_active），避免每帧空转的
     * GFP_ATOMIC 分配 + 哈希 + 链表操作。 */
    if (!kpm_gyro_any_active()) return 0;

    /* 从 regs 取 x1 = convertToSensorEvent 第二个参数 = sensors_event_t*。
     * 原子分配：pre handler 在 mmap_lock 读锁上下文，GFP_KERNEL 睡眠分配
     * 有 reclaim 风险；失败则返回 0（本帧透传，ret handler 无 ctx 直接跳过）。 */
    ctx = (struct kpm_gyro_ctx *)kf_kmalloc(sizeof(*ctx), GFP_ATOMIC);
    if (!ctx) return 0;
    ctx->task = task;
    ctx->dst  = (void *)regs->regs[1];
    ctx->next = NULL;

    h = kpm_gyro_ctx_hash(task);
    flags = kpm_spin_lock_irqsave(&g_gyro_ctx_lock);
    head = &g_gyro_ctx_ht[h];
    ctx->next = *head;
    *head = ctx;
    kpm_spin_unlock_irqrestore(&g_gyro_ctx_lock, flags);
    return 0;
}

/* ===== 陀螺仪用户态读写：walk 页表 + 线性映射 WB 直读直写 =====
 * read/write_user_float 经 kpm_mem_*_kernel_wb 走当前进程 mm->pgd 页表 →
 * 物理地址 → 线性映射 WB 直读直写：不触发 fault、不碰 mmap_lock、无 vmap
 * 无睡眠（RCU 临界区安全）。 */
#define KPM_GYRO_BARE_ACCESS 0   /* 裸解引用在设备 PAN 开启时 handler 上下文读不到用户内存；walk 页表 + 线性映射 WB 直读直写不受 PAN 影响。 */

/* 获取当前进程 pid：框架 task_struct 为不透明类型（仅前向声明），
 * 用 LH_syms 运行时探测的 g_pid_offset 偏移读取，兼容全版本内核。
 * 探测失败（偏移非法）返回 0 → kpm_mem_read/write_kernel_wb 查不到进程
 * 返回错误 → handler 本帧透传，安全降级。
 * 注：仅 KPM_GYRO_BARE_ACCESS=0（walk 回退）时使用。 */
#if !KPM_GYRO_BARE_ACCESS
static int kpm_gyro_current_pid(void)
{
    if (g_pid_offset <= 0 || g_pid_offset > 0x4000)
        return 0;
    return *(const int *)((const char *)current + g_pid_offset);
}
#endif

/* 读取用户态 float 值（位模式）。walk 页表直读。 */
static int kpm_gyro_read_user_float(void *addr, int32_t *out)
{
    /* 直接 walk 页表，不做过早的 TASK_SIZE 检查——kpm_detect_va_params
     * 探测的用户 VA 位宽在 uprobe 上下文可能与 dst（sensors_event_t）
     * 实际地址不符，导致检查误拦截、全部改写失效。walk 内部已有
     * mm/页表校验兜底。 */
    if (!addr)
        return -1;
    {
        int32_t v = 0;
        if (kpm_mem_read_kernel_wb(kpm_gyro_current_pid(),
                                   (uint64_t)addr, &v, 4) < 0)
            return -1;
        *out = v;
        return 0;
    }
}

/* 写入用户态 float 值（位模式）。walk 页表直写。 */
static int kpm_gyro_write_user_float(void *addr, int32_t v)
{
    /* 同 read：直接 walk，不做 TASK_SIZE 过早检查（可能误拦截）。 */
    if (!addr)
        return -1;
    if (kpm_mem_write_kernel_wb(kpm_gyro_current_pid(),
                                (uint64_t)addr, &v, 4) < 0)
        return -1;
    return 0;
}

/* ret handler：改写输出缓冲 x/y/z */
static int kpm_gyro_uprobe_ret(struct kpm_uprobe_consumer *self,
                               unsigned long func, struct pt_regs *regs)
{
    struct task_struct *task = current;
    struct kpm_gyro_ctx *ctx, **pp;
    struct kpm_gyro_ctx **head;
    void *dst;
    int32_t s_type;
    unsigned int h;
    unsigned long flags;
    int k_type;
    int is_rate;
    int32_t x, y, z;
    int active = 0;

    (void)self; (void)func; (void)regs;

    if (!g_gyro_ready) return 0;

    /* 无任一控制启用时快速返回（避免无谓开销）。
     * 判定由 kpm_gyro_any_active() 统一，pre 侧同款复用
     * （pre 已在无控制时不分配 ctx，这里自然走 cleanup 空转一次）。 */
    active = kpm_gyro_any_active();
    if (!active) {
        /* 仍需摘除并释放本线程的 ctx（避免泄漏） */
        goto cleanup_ctx;
    }

    /* 客户端心跳超时检查（客户端离线残留的锁/偏移在下一事件释放回正） */
    if (kpm_gyro_purge_if_idle())
        goto cleanup_ctx;

    /* 按 task 查找本线程上下文，摘除 */
cleanup_ctx:
    h = kpm_gyro_ctx_hash(task);
    flags = kpm_spin_lock_irqsave(&g_gyro_ctx_lock);
    head = &g_gyro_ctx_ht[h];
    pp = head;
    ctx = NULL;
    while (*pp) {
        if ((*pp)->task == task) {
            ctx = *pp;
            *pp = ctx->next;
            break;
        }
        pp = &(*pp)->next;
    }
    kpm_spin_unlock_irqrestore(&g_gyro_ctx_lock, flags);
    if (!ctx) return 0;
    dst = ctx->dst;
    kf_kfree(ctx);

    if (!active) return 0;
    if (!dst) return 0;

    /* 读 type 字段（偏移 8）——walk 页表 WB 直读（见 read_user_float 注释：
     * uprobe 上下文禁止 copy_from_user/裸解引用，避免 ABBA 死锁与 PAN）。 */
    if (kpm_gyro_read_user_float((uint8_t *)dst + KPM_SEV_TYPE_OFF,
                                 &s_type) < 0)
        return 0;

    k_type = kpm_gyro_stype_to_ktype(s_type);
    if (k_type < 0)
        return 0;   /* 非目标传感器（非陀螺仪/加速度计等），不动 */

    /* 角速度型（陀螺仪）：data 是 rad/s 角速度；锁"当前"须输出 0 角速度
     * 冻结角度。角度型（旋转矢量/方向/加速度）：data 是位置/角度；
     * 锁"当前"直接冻结捕获值。 */
    is_rate = (s_type == KPM_STYPE_GYROSCOPE ||
               s_type == KPM_STYPE_GYROSCOPE_UNCALIBRATED) ? 1 : 0;

    /* 读 x/y/z（偏移 24/28/32），应用变换，写回 */
    if (kpm_gyro_read_user_float((uint8_t *)dst + KPM_SEV_DATA_OFF +
                                 KPM_SEV_DATA_STRIDE * 0, &x) != 0)
        return 0;
    if (kpm_gyro_read_user_float((uint8_t *)dst + KPM_SEV_DATA_OFF +
                                 KPM_SEV_DATA_STRIDE * 1, &y) != 0)
        return 0;
    if (kpm_gyro_read_user_float((uint8_t *)dst + KPM_SEV_DATA_OFF +
                                 KPM_SEV_DATA_STRIDE * 2, &z) != 0)
        return 0;

    x = kpm_gyro_transform(k_type, KPM_GYRO_AXIS_X, x, is_rate);
    y = kpm_gyro_transform(k_type, KPM_GYRO_AXIS_Y, y, is_rate);
    z = kpm_gyro_transform(k_type, KPM_GYRO_AXIS_Z, z, is_rate);

    kpm_gyro_write_user_float((uint8_t *)dst + KPM_SEV_DATA_OFF +
                              KPM_SEV_DATA_STRIDE * 0, x);
    kpm_gyro_write_user_float((uint8_t *)dst + KPM_SEV_DATA_OFF +
                              KPM_SEV_DATA_STRIDE * 1, y);
    kpm_gyro_write_user_float((uint8_t *)dst + KPM_SEV_DATA_OFF +
                              KPM_SEV_DATA_STRIDE * 2, z);

    /* 自动侦测：uprobe 路径改写计数（供客户端判断该路径是否真在工作） */
    kpm_gyro_count_inc(&g_gyro_up_hits);

#ifdef KPM_DEBUG
    {
        static unsigned long ret_cnt = 0;
        if ((++ret_cnt & 0xFFF) == 1)
            kpm_log("kpm: gyro UP[ret] type=%d ktype=%d dst=%p\n",
                    (int)s_type, k_type, dst);
    }
#endif
    return 0;
}

/* ===== sys_enter tracepoint 陀螺仪路径 =====
 *   签名 (void *data, struct pt_regs *regs, long id) —— 标准 sys_enter
 *   tracepoint 回调。仅处理 id==206(read)/211(pread64)，且
 *   size % 0x68(104)==0（sizeof(sensors_event_t)）——即"读取传感器事件
 *   数组"的系统调用。copy_from_user 读回用户缓冲 → 遍历每个事件（104B）
 *   → type(+8)==4(GYRO) 的条目改写 data[0]/data[1]（+24/+28）→
 *   copy_to_user 写回。与 sensorservice 内部实现完全解耦：无论 Android
 *   版本/传感器 HAL 架构如何，应用最终都通过 read/pread64 从传感器 fd
 *   读事件数组 → 数据在 syscall 层被拦截改写。这是在 Android 16
 *   （uprobe 失效）上仍可用的根本。
 * handler 运行于普通 syscall 入口上下文（非 uprobe RCU 临界区），
 * copy_from/to_user 合法可用（正常 fault-in，无 ABBA 死锁风险）。
 * 隐蔽性：tracepoint 注册是标准内核机制（不修改 syscall table、无
 * inline hook、零 dmesg 痕迹）；TIF_SYSCALL_TRACEPOINT 激活由内核
 * syscall_regfunc 在首个 probe 注册时自动完成（无需regfunc
 * hook——LH 不修改内核代码，更隐蔽）。
 * 崩溃防护：符号缺失→不注册（非致命）；参数全校验（size 范围/104 对齐、
 * buf 非空）；kmalloc/copy 返回值检查；卸载先 unregister 再 synchronize
 * 等全部在途 handler 退出后才返回（防 UAF）。 */
#define KPM_GYRO_SEV_SIZE      0x68u    /* sizeof(sensors_event_t) = 104 */
#define KPM_GYRO_SEV_MAX       (1u << 21) /* 单次 read 上限 2MB */
/* pid 空间扫描上界：运行时取内核 pid_max（见 LH_syms.h: kpm_pid_max()）。
 * pid 分配 1..pid_max 循环复用，进程崩溃重启后会拿到高位 pid，写死上界
 * 会漏掉；由 kpm_gyro_is_sensor_host() 的 comm 快路径把扫描开销压回来。 */

/* 分块处理上限：必须为 KPM_GYRO_SEV_SIZE(104) 的整数倍
 * （104*315=32760，≤32KB），保持事件边界对齐；每次仅分配 32760B
 * （物理连续 order-3，GFP_ATOMIC 可行）。 */
#define KPM_GYRO_CHUNK_MAX     (KPM_GYRO_SEV_SIZE * 315u)

/* sys_enter 回调：拦截 read/pread64 读传感器事件数组并改写 x/y */
static void kpm_gyro_sys_enter_cb(void *data, struct pt_regs *regs, long id)
{
    unsigned long buf, size, cnt, i;
    int32_t *tmp;
    int active = 0;

    (void)data;
    if (!g_gyro_ready && !g_gyro_tp_ok)
        return;
    if (id != 206 && id != 211)   /* read / pread64 */
        return;
    if (!regs)
        return;
    buf  = (unsigned long)regs->regs[1];   /* x1 = 用户 buf */
    size = (unsigned long)regs->regs[2];   /* x2 = count */
    if (!buf || size < KPM_GYRO_SEV_SIZE || size > KPM_GYRO_SEV_MAX)
        return;
    if (size % KPM_GYRO_SEV_SIZE != 0)
        return;   /* 非传感器事件数组读取，跳过（性能过滤） */

    /* 用户地址范围 + 溢出校验。
     * buf 必须落在用户空间（< TASK_SIZE），且 buf+size 不溢出、不越界——
     * 防内核地址误传 / 攻击者构造 (buf+size) 溢出绕过上界检查。 */
    {
        unsigned long task_size, end;

        kpm_detect_va_params();
        if (g_kpm_user_va_bits <= 0 || g_kpm_user_va_bits > 48)
            return;
        task_size = 1UL << g_kpm_user_va_bits;
        if (buf >= task_size)
            return;
        end = buf + size;
        if (end < buf || end > task_size)
            return;
    }

    /* 无任一控制启用时快速返回（同 uprobe ret handler） */
    for (i = 0; i < KPM_GYRO_AXIS_MAX; i++) {
        if (g_gyro.tran[i].locked || g_gyro.tran[i].force_active ||
            g_gyro.tran[i].force_offset ||
            g_gyro.rot[i].locked || g_gyro.rot[i].force_active ||
            g_gyro.rot[i].force_offset) {
            active = 1;
            break;
        }
    }
    if (!active)
        return;

    /* 分块处理。每次分配一块 32760B（≤32KB，order-3，
     * GFP_ATOMIC 可行），逐块 copy_from_user → 变换 → copy_to_user。
     * 任一块拷贝失败：清零后跳过该块继续（防泄漏）；
     * 分配失败：整帧透传（本帧不改写，下一帧重试）。 */
    tmp = (int32_t *)kf_kmalloc(KPM_GYRO_CHUNK_MAX, GFP_ATOMIC);
    if (!tmp)
        return;
    {
        unsigned long off;

        for (off = 0; off < size; off += KPM_GYRO_CHUNK_MAX) {
            unsigned long chunk = size - off;

            if (chunk > KPM_GYRO_CHUNK_MAX)
                chunk = KPM_GYRO_CHUNK_MAX;
            if (kf_copy_from_user(tmp, (const void *)(buf + off),
                                  chunk) != 0) {
                /* 拷贝失败先清零再继续——
                 * 防传感器事件数据残留泄漏到 slab 复用。 */
                lib_memset(tmp, 0, KPM_GYRO_CHUNK_MAX);
                continue;
            }
            cnt = chunk / KPM_GYRO_SEV_SIZE;
            for (i = 0; i < cnt; i++) {
                int32_t *ev = tmp + i * (KPM_GYRO_SEV_SIZE / sizeof(int32_t));
                int32_t s_type = ev[KPM_SEV_TYPE_OFF / sizeof(int32_t)];
                int k_type = kpm_gyro_stype_to_ktype(s_type);
                int is_rate;
                if (k_type < 0)
                    continue;   /* 非目标传感器（仅陀螺仪/加速度计等映射表内 type） */
                is_rate = (s_type == KPM_STYPE_GYROSCOPE ||
                           s_type == KPM_STYPE_GYROSCOPE_UNCALIBRATED) ? 1 : 0;
                ev[KPM_SEV_DATA_OFF / sizeof(int32_t) + 0] =
                    kpm_gyro_transform(k_type, KPM_GYRO_AXIS_X,
                        ev[KPM_SEV_DATA_OFF / sizeof(int32_t) + 0], is_rate);
                ev[KPM_SEV_DATA_OFF / sizeof(int32_t) + 1] =
                    kpm_gyro_transform(k_type, KPM_GYRO_AXIS_Y,
                        ev[KPM_SEV_DATA_OFF / sizeof(int32_t) + 1], is_rate);
                /* 仅改 x/y（data[0]/data[1]），z 保留原值 */
            }
            kf_copy_to_user((void *)(buf + off), tmp, chunk);
            /* 自动侦测：tracepoint 路径改写计数（供客户端判断该路径
             * 是否真在工作） */
            kpm_gyro_count_inc(&g_gyro_tp_hits);
        }
    }
#ifdef KPM_DEBUG
    {
        static unsigned int s_tp_dbg;
        if (((++s_tp_dbg) & 0x3FF) == 1)
            kpm_printk("LH_gyro_dbg: tp HIT cnt=%u size=%lu type=%d\n",
                       s_tp_dbg, (unsigned long)size,
                       (int)tmp[KPM_SEV_TYPE_OFF / sizeof(int32_t)]);
    }
#endif
    kf_kfree(tmp);
}

#define KPM_TIF_SYSCALL_TRACEPOINT  10   /* 设备内核 thread_info.h：
                                        * （thread_info.flags @ task_struct+0，ARM64） */

/* 原子置位（ARM64 ldxr/stxr，通用寄存器，无浮点——兼容 -mgeneral-regs-only） */
static inline void kpm_tif_set_bit(unsigned long *addr, int bit)
{
    unsigned long old;
    unsigned long mask = 1UL << bit;

    asm volatile(
        "1: ldxr %0, [%1]\n"
        "   orr  %0, %0, %2\n"
        "   stxr w2, %0, [%1]\n"
        "   cbnz w2, 1b\n"
        : "=&r"(old)
        : "r"(addr), "r"(mask)
        : "memory", "w2");
}

/* 遍历所有 pid（每个线程独立 pid → 覆盖全部线程）置位 TIF_SYSCALL_TRACEPOINT。
 * 内核 syscall_regfunc 自动置位不可靠，故注册成功后手动遍历置位。
 * 用 kpm_task_acquire()：优先走 RCU 免引用路径（find_vpid + pid_task），
 * 零引用计数、不触碰 usage；仅在 RCU 不可用时才回退到取引用路径。
 * 置位动作是单条原子 orr（ldxr/stxr），不睡眠，故可安全处于 RCU 读临界区。 */
static void kpm_gyro_tp_set_tif(void)
{
    int pid;
    int pid_lim;

    /* 免引用路径可用就直接走（不需要 find_get_pid/get_pid_task/put_pid 三件套）；
     * 否则要求取引用路径的符号齐全（kpm_task_acquire 内部同款判定）。 */
    if (!kpm_task_fetch_available())
        return;
    pid_lim = kpm_pid_max();   /* 运行时上界：低 pid 写死会漏掉晚启动/重启的任务 */
    for (pid = 1; pid < pid_lim; pid++) {
        struct task_struct *t;
        int needs_put = 0;

        if (kpm_task_acquire(pid, &t, &needs_put) != 0)
            continue;

        kpm_tif_set_bit((unsigned long *)t, KPM_TIF_SYSCALL_TRACEPOINT);
#ifdef KPM_DEBUG
        if ((pid & 0x3FF) == 1)
            kpm_printk("LH_gyro_dbg: tif pid=%d flags=%08lx (bit10=%d)\n",
                       pid, *(volatile unsigned long *)t,
                       (int)((*(volatile unsigned long *)t >> 10) & 1));
#endif
        if (needs_put)
            kpm_put_task_struct(t);
        else
            kpm_task_end();
    }
}

/* ===== sched_process_fork probe——晚启动进程覆盖 =====
 * kpm_gyro_tp_set_tif 只覆盖【模块加载时已存在】的任务；加载后启动的
 * 进程依赖 fork 时 TIF 从父进程继承。虽然 arch_dup_task_struct
 * 整体拷贝 task_struct（thread_info.flags 一并继承），但部分内核
 * 继承不可靠。本 probe 与内核 syscall_regfunc 行为对齐（对每个新 task
 * 置位，含内核线程），保证全版本晚启动任务覆盖，且不依赖任何内核修改。
 * probe 签名: (void *data, struct task_struct *parent, struct task_struct *child)
 * 上下文：copy_process 内（可能持 tasklist 写锁/关中断）——仅做一次原子
 * 位置位（ldxr/stxr），不睡眠不分配，安全。 */
static void kpm_gyro_fork_cb(void *data, void *parent, void *child)
{
    (void)data;
    (void)parent;
    /* 仅在 sys_enter probe 已注册时置位——避免 TIF 残留：
     * sys_enter 注销后本 probe 也会立即注销，不会给新进程置无效位 */
    if (!g_gyro_tp_ok || !child)
        return;
    kpm_tif_set_bit((unsigned long *)child, KPM_TIF_SYSCALL_TRACEPOINT);
}

/* 注册 sys_enter tracepoint（兼容路径）。符号缺失/注册失败 → 非致命。 */
static long kpm_gyro_tp_init(void)
{
    if (g_gyro_tp_ok)
        return 0;
    /* tracepoint_synchronize_unregister 不是全内核导出，不强制——只
     * 要求 tp + probe_register + probe_unregister（卸载同步可选降级）。 */
    if (!kf_tp_sys_enter || !kf_tracepoint_probe_register ||
        !kf_tracepoint_probe_unregister) {
        kpm_log("kpm: gyro tp skipped - tracepoint syms not resolved\n");
        kpm_printk("LH_gyro_dbg: tp SKIP syms missing (tp=%p reg=%p "
                   "unreg=%p sync=%p)\n",
                   kf_tp_sys_enter, kf_tracepoint_probe_register,
                   kf_tracepoint_probe_unregister,
                   kf_tracepoint_synchronize_unregister);
        return -KPM_E_NOTFOUND;
    }
    if (!kf_tracepoint_synchronize_unregister)
        kpm_printk("LH_gyro_dbg: tp sync_unreg missing (non-fatal, "
                   "exit uses probe_unregister only)\n");
    if (kf_tracepoint_probe_register(kf_tp_sys_enter,
                                     (void *)kpm_gyro_sys_enter_cb,
                                     NULL) != 0) {
        kpm_log("kpm: gyro tp - tracepoint_probe_register failed\n");
        kpm_printk("LH_gyro_dbg: tp register FAIL\n");
        return -KPM_E_NOTFOUND;
    }
    kpm_printk("LH_gyro_dbg: tp registered tp=%p\n", kf_tp_sys_enter);
    /* 注册 sched_process_fork probe，fork 时给新 task
     * 置位 TIF——覆盖加载后启动的进程。时序（sys_enter 注册 → fork probe
     * 注册 → g_gyro_tp_ok=1 → set_tif）保证无遗漏窗口：
     *   ① 此前 fork 的所有任务由末尾 set_tif 覆盖；
     *   ② g_gyro_tp_ok=1 之后 fork 的 child 由 fork cb 置位；
     *   ③ cb 置位与 set_tif 幂等重叠，无害。
     * fork probe 失败非致命——此时仅靠 TIF 继承 + set_tif。 */
    if (kf_tp_sched_fork &&
        kf_tracepoint_probe_register(kf_tp_sched_fork,
                                     (void *)kpm_gyro_fork_cb,
                                     NULL) != 0) {
        kf_tp_sched_fork = 0;   /* 注册失败视为不可用 */
        kpm_log("kpm: gyro fork tp register failed - late-start task "
                "coverage relies on TIF inheritance only\n");
        kpm_printk("LH_gyro_dbg: fork tp register FAIL\n");
    } else if (kf_tp_sched_fork) {
        kpm_printk("LH_gyro_dbg: fork tp registered tp=%p\n",
                   kf_tp_sched_fork);
    }
    /* 先置 g_gyro_tp_ok=1 再 set_tif：确保 set_tif 遍历期间新 fork 的
     * child（不在遍历快照内）已能被 fork cb 覆盖 */
    g_gyro_tp_ok = 1;
    /* 置位全进程 TIF_SYSCALL_TRACEPOINT（regfunc hook 等效，零内核
     * 修改）。不依赖内核 syscall_regfunc 自动置位（不可靠）。 */
    kpm_gyro_tp_set_tif();
    kpm_log("kpm: gyro sys_enter tracepoint registered (read/pread64 "
            "sensors_event_t interception active)\n");
    return 0;
}

/* 注销 sys_enter tracepoint（先 unregister 再 synchronize 等 handler 退出） */
static void kpm_gyro_tp_exit(void)
{
    if (!g_gyro_tp_ok)
        return;
    /* 先置 g_gyro_tp_ok=0 停止 fork cb 置位，再注销 fork probe
     * （顺序与注册相反；先停门控再拆 probe，无新置位窗口） */
    g_gyro_tp_ok = 0;
    if (kf_tp_sched_fork && kf_tracepoint_probe_unregister)
        kf_tracepoint_probe_unregister(kf_tp_sched_fork,
                                       (void *)kpm_gyro_fork_cb, NULL);
    if (kf_tracepoint_probe_unregister)
        kf_tracepoint_probe_unregister(kf_tp_sys_enter,
                                       (void *)kpm_gyro_sys_enter_cb, NULL);
    if (kf_tracepoint_synchronize_unregister)
        kf_tracepoint_synchronize_unregister();  /* 等所有在途 handler 完成 */
    kpm_log("kpm: gyro sys_enter tracepoint unregistered\n");
}

/* ===== ELF 符号偏移解析（动态，不反编译） =====
 * 读取 libsensorservice.so，解析 .dynsym 找 convertToSensorEvent 符号
 * 偏移。AIDL 优先，HIDL 回退。
 * 返回文件内偏移（st_value），失败返回 -1。 */

static const char KPM_GYRO_SYM_AIDL[] =
    "_ZN7android8hardware7sensors14implementation20convertToSensorEvent"
    "ERKN4aidl7android8hardware7sensors5EventEP15sensors_event_t";
static const char KPM_GYRO_SYM_HIDL[] =
    "_ZN7android8hardware7sensors4V1_014implementation20convertToSensorEvent"
    "ERKNS2_5EventEP15sensors_event_t";

/* 精确字符串比较（不依赖未声明的 lib_strcmp） */
static int kpm_gyro_name_eq(const char *a, const char *b)
{
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return (*a == 0 && *b == 0) ? 1 : 0;
}

/* 从目标进程用户内存读取文件偏移 foff 处的 len 字节。返回实际读取字节数。 */
static long kpm_gyro_mem_read(pid_t pid, uint64_t base, uint64_t foff,
                              void *buf, int len)
{
    return kpm_mem_read_kernel(pid, base + foff, buf, len);
}

/* ===== inode 获取 =====
 * 用 kern_path 直接解析 libsensorservice.so 路径获取 inode。
 * 流程：kern_path(path, LOOKUP_FOLLOW, &path) → igrab(path.dentry->d_inode)
 *       → path_put(&path)。
 * 规避：task_struct.tasks 偏移探测失败依赖。
 * 注：kern_path 只做 pathname 查找（不触发文件 open 权限检查），可解析
 *     /system 下可读文件，规避 SELinux 对 filp_open 的限制。 */

/* 提取 inode：kern_path 后从 struct path.dentry 取 d_inode。
 * struct path = { mnt@0, dentry@8 }；dentry->d_inode 偏移 = g_dentry_name_offset + 8。
 * 成功后 g_gyro_inode 持有 igrab 引用。返回 0 成功，-1 失败。 */
static long kpm_gyro_get_inode_by_path(void)
{
    struct kpm_path path;
    uint64_t dentry_ptr = 0, inode = 0;
    int d_inode_off;
    void *ig;

    if (!kf_kern_path || !kf_igrab || !kf_path_put) {
        kpm_log("kpm: gyro inode - kern_path syms missing\n");
        kpm_log_info("kpm: gyro inode - syms missing (kern_path=%p igrab=%p "
                     "path_put=%p)\n", kf_kern_path, kf_igrab, kf_path_put);
        return -1;
    }
    if (g_dentry_name_offset < 0) {
        kpm_log("kpm: gyro inode - dentry name offset not probed (%d)\n",
                g_dentry_name_offset);
        return -1;
    }
    kpm_log_info("kpm: gyro inode - start path=%s dentry_name_off=%d "
                 "(d_inode_off=%d)\n", KPM_GYRO_LIB_PATH,
                 g_dentry_name_offset, g_dentry_name_offset + 8);

    if (kf_kern_path(g_gyro_lib_path, KPM_LOOKUP_FOLLOW,
                     (struct path *)&path) != 0) {
        kpm_log("kpm: gyro inode - kern_path failed for %s\n",
                g_gyro_lib_path);
        kpm_printk("LH_gyro_dbg: kern_path FAILED for %s (SELinux? path?)\n",
                   g_gyro_lib_path);
        return -1;
    }
    kpm_log_info("kpm: gyro inode - kern_path ok (dentry=%llx)\n",
                 (unsigned long long)path.dentry);

    /* struct path: mnt@0, dentry@8（自包含布局，直接读本地结构体成员） */
    dentry_ptr = (uint64_t)path.dentry;
    if (dentry_ptr < 0xFFFF000000000000ULL) {
        kpm_log("kpm: gyro inode - bad dentry=%llx\n",
                (unsigned long long)dentry_ptr);
        kf_path_put((struct path *)&path);
        return -1;
    }

    /* d_inode 偏移 = d_name.name 偏移 + 8（标准 5.1-6.x dentry 布局） */
    d_inode_off = g_dentry_name_offset + 8;
    if (kf_copy_from_kernel_nofault(&inode,
            (void *)(dentry_ptr + d_inode_off), 8) != 0 ||
        inode < 0xFFFF000000000000ULL) {
        kpm_log("kpm: gyro inode - bad d_inode=%llx (d_inode_off=%d)\n",
                (unsigned long long)inode, d_inode_off);
        kf_path_put((struct path *)&path);
        return -1;
    }

    ig = kf_igrab((struct inode *)(unsigned long)inode);
    kf_path_put((struct path *)&path);
    if (!ig) {
        kpm_log("kpm: gyro inode - igrab failed inode=%llx\n",
                (unsigned long long)inode);
        return -1;
    }
    g_gyro_inode = ig;
    kpm_log("kpm: gyro inode - kern_path ok inode=%p\n", g_gyro_inode);
    return 0;
}

/* ===== 进程定位 + 加载基址 =====
 * 用 kpm_task_acquire 按 PID 空间扫描（非任务链表遍历），
 * 找到已映射 libsensorservice.so 的进程，返回其加载基址（ELF 头所在映射）。
 * 不参与 inode 获取（inode 走 kern_path）。返回 0 成功，-1 失败。
 *
 * 扫描上界运行时取 kpm_pid_max()：pid 分配 1..pid_max 循环复用，写死上界
 * 会漏掉崩溃重启后拿到高位 pid 的进程。全域 VMA 遍历开销大，故两遍扫描：
 *   第 1 遍（快）：只对疑似传感器服务宿主的进程做 VMA 遍历
 *                 （comm 含 system_server / sensor / android.hardware）；
 *   第 2 遍（兜底）：第 1 遍一无所获时退化为全域 VMA 扫描。 */
#define KPM_GYRO_COMM_MAX 32

/* 子串匹配（大小写不敏感） */
static int kpm_gyro_str_has(const char *hay, const char *needle)
{
    int i, j;

    for (i = 0; hay[i]; i++) {
        for (j = 0; needle[j]; j++) {
            char a = hay[i + j], b = needle[j];
            if (!a)
                return 0;
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b)
                break;
        }
        if (!needle[j])
            return 1;
    }
    return 0;
}

/* 快路径归属判定：是否为"可能映射 libsensorservice 的进程"。
 * 只做宽松匹配——宁可多留候选（多几次 VMA 遍历），也不能漏掉宿主进程。 */
static int kpm_gyro_is_sensor_host(struct task_struct *task)
{
    char comm[KPM_GYRO_COMM_MAX];

    if (!kf_get_task_comm)
        return 0;
    comm[0] = '\0';
    kf_get_task_comm(comm, KPM_GYRO_COMM_MAX - 1, task);
    comm[KPM_GYRO_COMM_MAX - 1] = '\0';
    if (kpm_gyro_str_has(comm, "sensor") ||
        kpm_gyro_str_has(comm, "system_server") ||
        kpm_gyro_str_has(comm, "android.hardware"))
        return 1;
    return 0;
}

static long kpm_gyro_find_lib_base(pid_t *out_pid, uint64_t *out_base)
{
    pid_t pid;
    int found = 0;
    int scanned = 0;
    int pass, npass, pid_lim;

    if (!kf_find_get_pid || !kf_get_pid_task || !kf_get_task_mm ||
        !kf_mmput || !kf_find_vma || !kf_copy_from_kernel_nofault) {
        kpm_log("kpm: gyro find_base - precheck fail\n");
        kpm_log_info("kpm: gyro find_base - precheck fail "
                     "(find_get_pid=%p get_pid_task=%p get_task_mm=%p "
                     "mmput=%p find_vma=%p nofault=%p)\n",
                     kf_find_get_pid, kf_get_pid_task, kf_get_task_mm,
                     kf_mmput, kf_find_vma, kf_copy_from_kernel_nofault);
        return -1;
    }
    pid_lim = kpm_pid_max();
    npass = kf_get_task_comm ? 2 : 1;   /* 有 comm 就先跑快路径 */
    kpm_log_info("kpm: gyro find_base - precheck OK, probing %s in pids 1..%d "
                 "(%d pass%s)\n", KPM_GYRO_LIB_BASENAME, pid_lim, npass,
                 npass > 1 ? "es" : "");
    kpm_printk("LH_gyro_dbg: find_base start (lib=%s, pid_max=%d)\n",
               KPM_GYRO_LIB_BASENAME, pid_lim);

    for (pass = 0; pass < npass && !found; pass++) {
    int use_filter = (pass == 0 && npass > 1);

    for (pid = 1; pid < pid_lim && !found; pid++) {
        struct task_struct *task;
        struct mm_struct *mm;
        void *vma;
        uint64_t last_end = 0;
        int iter_count = 0;
        int needs_put = 0;
        /* kpm_mm_read_lock 统一加锁（1=原生 mmap 读锁，
         * 0=RCU），与 LH_proc.c 六处遍历点同一适配层——5.12+ 上
         * kpm_find_vma_next 走 find_vma 主路径，必须持 mmap 读锁满足
         * 持锁契约；解锁同值配对。gyro init 为可睡眠上下文。 */
        int mm_locked = 0;

        /* 免引用优先：取 task 不增引用计数；取到 mm 后即可退出 RCU
         * （mm 自带引用），此后才允许做可睡眠的 mmap 读锁。 */
        if (kpm_task_acquire(pid, &task, &needs_put) != 0)
            continue;

        /* 快路径：comm 不像传感器宿主就直接跳过，省掉全 VMA 遍历 */
        if (use_filter && !kpm_gyro_is_sensor_host(task)) {
            if (needs_put) kpm_put_task_struct(task); else kpm_task_end();
            continue;
        }

        mm = kf_get_task_mm(task);
        if (!mm) {
            if (needs_put) kpm_put_task_struct(task); else kpm_task_end();
            continue;
        }
        if (!needs_put)
            kpm_task_end();          /* mm 已持引用：退出 RCU，别再碰 task */
        scanned++;

        /* 加锁移至惰性探测之前——kpm_probe_vma_offsets/
         * kpm_probe_vm_file_offsets 内部同样调用 kpm_find_vma_next，
         * 契约要求持锁（与 LH_proc.c 调用顺序一致）。 */
        mm_locked = kpm_mm_read_lock(mm);

        /* 惰性探测 VMA 偏移（首次调用，纯内存） */
        if (g_vm_start_offset == -1)
            kpm_probe_vma_offsets(mm);
        if (g_vm_file_offset == -1)
            kpm_probe_vm_file_offsets(mm);

        vma = kpm_find_vma_next(mm, 0);
        while (vma) {
            uint64_t vs = 0, ve = 0;
            char name[64];

            if (++iter_count > 65536) break;
            if (kf_copy_from_kernel_nofault(&vs,
                    (void *)((unsigned long)vma + g_vm_start_offset), 8) != 0) break;
            if (kf_copy_from_kernel_nofault(&ve,
                    (void *)((unsigned long)vma + g_vm_end_offset), 8) != 0) break;
            if (!vs || !ve || vs >= ve) break;

            if (kpm_vma_get_path(vma, name, sizeof(name)) == 0 &&
                kpm_gyro_name_eq(name, KPM_GYRO_LIB_BASENAME)) {
                *out_pid = pid;
                *out_base = vs;   /* 首映射即 ELF 头所在映射（vm_pgoff=0） */
                found = 1;
                kpm_log_info("kpm: gyro find_base - HIT pid=%d base=0x%llx "
                             "path=\"%s\" (scanned=%d, vma_off: start=%d end=%d "
                             "file=%d)\n", pid, (unsigned long long)vs, name,
                             scanned, g_vm_start_offset, g_vm_end_offset,
                             g_vm_file_offset);
                kpm_printk("LH_gyro_dbg: find_base HIT pid=%d base=0x%llx\n",
                           pid, (unsigned long long)vs);
                break;
            }
            last_end = ve;
            vma = kpm_find_vma_next(mm, last_end);
        }
        kpm_mm_read_unlock(mm, mm_locked);

        /* 找到 lib 基址后，用该已知有效 VA 反推 mm_struct.pgd 正确偏移，
         * 规避框架 mm_struct_offset.pgd_offset 解析失败导致的 walk-fail */
        if (found)
            kpm_probe_pgd_offset(mm, *out_base);

        kf_mmput(mm);
        if (needs_put)
            kpm_put_task_struct(task);   /* 免引用路径无引用可放（RCU 已退） */
    }
    if (use_filter && !found)
        kpm_log("kpm: gyro find_base - fast pass (comm filter) missed, "
                "falling back to full pid scan\n");
    }

    if (!found) {
        kpm_log("kpm: gyro find_base - NOT FOUND\n");
        kpm_log_info("kpm: gyro find_base - NOT FOUND after %d pids scanned "
                     "(lib=%s, vm_start_off=%d vm_file_off=%d)\n",
                     scanned, KPM_GYRO_LIB_BASENAME,
                     g_vm_start_offset, g_vm_file_offset);
        kpm_printk("LH_gyro_dbg: find_base NOT FOUND (scanned=%d)\n", scanned);
        return -1;
    }

    /* 验证 base 处为 ELF 头（纯内存读取） */
    {
        uint8_t magic[4];
        long r = kpm_gyro_mem_read(*out_pid, *out_base, 0, magic, 4);
        if (r != 4 ||
            magic[0] != 0x7F || magic[1] != 'E' ||
            magic[2] != 'L' || magic[3] != 'F') {
            kpm_log("kpm: gyro find_base - bad ELF magic pid=%d base=0x%llx "
                    "(read=%ld %02x %02x %02x %02x)\n",
                    *out_pid, (unsigned long long)*out_base,
                    r, magic[0], magic[1], magic[2], magic[3]);
            kpm_printk("LH_gyro_dbg: bad ELF magic pid=%d base=0x%llx "
                       "read=%ld [%02x %02x %02x %02x] (walk/mm-pgd?)\n",
                       *out_pid, (unsigned long long)*out_base,
                       r, magic[0], magic[1], magic[2], magic[3]);
            return -1;
        }
        kpm_log_info("kpm: gyro find_base - ELF magic verified at pid=%d base=0x%llx\n",
                     *out_pid, (unsigned long long)*out_base);
    }
    kpm_log("kpm: gyro find_base - pid=%d base=0x%llx\n",
            *out_pid, (unsigned long long)*out_base);
    return 0;
}

/* 从文件读取 libsensorservice.so 解析 convertToSensorEvent 符号偏移（filp_open+kernel_read）。
 * 直接读取磁盘文件，无需进程内存映射与偏移探测，规避 SELinux 对纯内存路径的依赖。
 * 返回文件内偏移（st_value），失败返回 -1。 */
static long long kpm_gyro_elf_find_sym_file(const char *want)
{
    struct file *fp;
    loff_t pos = 0;
    kpm_elf64_ehdr ehdr;
    kpm_elf64_shdr *shdr = NULL;
    int shnum, i;
    long long off = -1;

    if (!kf_filp_open || !kf_kernel_read || !kf_filp_close) {
        kpm_log("kpm: gyro sym_file - file syms missing\n");
        return -1;
    }

    fp = kf_filp_open(g_gyro_lib_path, 0 /* O_RDONLY */, 0);
    if (IS_ERR_OR_NULL(fp)) {
        kpm_log("kpm: gyro sym_file - filp_open failed for %s\n",
                g_gyro_lib_path);
        kpm_printk("LH_gyro_dbg: filp_open FAILED for %s (SELinux? file gone?)\n",
                   g_gyro_lib_path);
        return -1;
    }
    kpm_log_info("kpm: gyro sym_file - opened %s, searching %s\n",
                 KPM_GYRO_LIB_PATH, want);

    pos = 0;
    if (kf_kernel_read(fp, &ehdr, sizeof(ehdr), &pos) != (ssize_t)sizeof(ehdr)) {
        kpm_log("kpm: gyro sym_file - ehdr read fail\n");
        goto out_close;
    }
    if (ehdr.e_ident[0] != 0x7F || ehdr.e_ident[1] != 'E' ||
        ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F') {
        kpm_log("kpm: gyro sym_file - bad ELF magic (%02x %02x %02x %02x)\n",
                ehdr.e_ident[0], ehdr.e_ident[1],
                ehdr.e_ident[2], ehdr.e_ident[3]);
        goto out_close;
    }
    shnum = (int)ehdr.e_shnum;
    if (shnum <= 0 || shnum > 64) {
        kpm_log("kpm: gyro sym_file - bad shnum=%d (ehdr read ok, "
                "shoff=0x%llx)\n", shnum, (unsigned long long)ehdr.e_shoff);
        goto out_close;
    }
    kpm_log_info("kpm: gyro sym_file - ELF ok: shnum=%d shoff=0x%llx "
                 "machine=0x%x\n", shnum, (unsigned long long)ehdr.e_shoff,
                 ehdr.e_machine);

    shdr = (kpm_elf64_shdr *)kf_vmalloc((unsigned long)shnum *
                                        sizeof(kpm_elf64_shdr));
    if (!shdr)
        goto out_close;
    pos = (loff_t)ehdr.e_shoff;
    if (kf_kernel_read(fp, shdr, (size_t)(shnum * sizeof(kpm_elf64_shdr)),
                       &pos) != (ssize_t)(shnum * sizeof(kpm_elf64_shdr))) {
        kpm_log("kpm: gyro sym_file - shdr read fail (shnum=%d)\n", shnum);
        goto out_free;
    }

    for (i = 0; i < shnum; i++) {
        const kpm_elf64_shdr *ds;    /* dynsym */
        const kpm_elf64_shdr *dstr;  /* dynstr */
        unsigned char *symtab = NULL, *strtab = NULL;
        int cnt, j;

        if (shdr[i].sh_type != KPM_SHT_DYNSYM)
            continue;
        ds = &shdr[i];
        if ((int)ds->sh_link >= shnum)
            continue;
        dstr = &shdr[ds->sh_link];
        if (dstr->sh_type != KPM_SHT_STRTAB)
            continue;
        cnt = (int)(ds->sh_size / sizeof(kpm_elf64_sym));
        if (cnt <= 0 || cnt > 65536)
            continue;
        kpm_log_info("kpm: gyro sym_file - dynsym[%d]: %d syms, "
                     "strtab_size=%u\n", i, cnt, (unsigned int)dstr->sh_size);

        symtab = (unsigned char *)kf_vmalloc((unsigned long)ds->sh_size);
        strtab = (unsigned char *)kf_vmalloc((unsigned long)dstr->sh_size);
        if (!symtab || !strtab) {
            kf_vfree(symtab);
            kf_vfree(strtab);
            continue;
        }
        pos = (loff_t)ds->sh_offset;
        if (kf_kernel_read(fp, symtab, (size_t)ds->sh_size, &pos) !=
                (ssize_t)ds->sh_size) {
            kpm_log("kpm: gyro sym_file - symtab read fail (sec %d)\n", i);
            kf_vfree(symtab);
            kf_vfree(strtab);
            continue;
        }
        pos = (loff_t)dstr->sh_offset;
        if (kf_kernel_read(fp, strtab, (size_t)dstr->sh_size, &pos) !=
                (ssize_t)dstr->sh_size) {
            kpm_log("kpm: gyro sym_file - strtab read fail (sec %d)\n", i);
            kf_vfree(symtab);
            kf_vfree(strtab);
            continue;
        }

        {
            int want_len = 0;
            while (want[want_len]) want_len++;
            for (j = 0; j < cnt; j++) {
                kpm_elf64_sym *s = (kpm_elf64_sym *)symtab + j;
                uint32_t noff = s->st_name;
                if (noff + (uint32_t)want_len >= (uint32_t)dstr->sh_size)
                    continue;
                if (kpm_strstr((char *)strtab + noff, want)) {
                    off = (long long)s->st_value;
                    kpm_log_info("kpm: gyro sym_file - MATCH in dynsym[%d] "
                                 "sym#%d st_value=0x%llx\n",
                                 i, j, (unsigned long long)off);
                    kpm_printk("LH_gyro_dbg: sym MATCH \"%s\" off=0x%llx\n",
                               want, (unsigned long long)off);
                    break;
                }
            }
            if (off < 0)
                kpm_log_info("kpm: gyro sym_file - \"%s\" NOT in dynsym[%d] "
                             "(%d syms scanned)\n", want, i, cnt);
        }
        kf_vfree(symtab);
        kf_vfree(strtab);
        if (off >= 0)
            break;
    }

out_free:
    kf_vfree(shdr);
out_close:
    kf_filp_close(fp, NULL);
    return off;
}

/* ===== 生命周期 ===== */

long kpm_gyro_init(void)
{
    int i;
    long long off;

    for (i = 0; i < KPM_GYRO_AXIS_MAX; i++) {
        g_gyro.tran[i].locked = 0;
        g_gyro.tran[i].lock_anchor = 0;
        g_gyro.tran[i].lock_current = 0;
        g_gyro.tran[i].force_mode = KPM_GYRO_FORCE_RAMP;
        g_gyro.tran[i].force_active = 0;
        g_gyro.tran[i].force_target = 0;
        g_gyro.tran[i].force_speed = 1;
        g_gyro.tran[i].force_offset = 0;
        g_gyro.rot[i].locked = 0;
        g_gyro.rot[i].lock_anchor = 0;
        g_gyro.rot[i].lock_current = 0;
        g_gyro.rot[i].force_mode = KPM_GYRO_FORCE_RAMP;
        g_gyro.rot[i].force_active = 0;
        g_gyro.rot[i].force_target = 0;
        g_gyro.rot[i].force_speed = 1;
        g_gyro.rot[i].force_offset = 0;
    }
    g_gyro_hook = 0;
    g_gyro_ready = 0;
    g_gyro_inode = NULL;
    g_gyro_offset = -1;

    /* 0. sys_enter tracepoint：先注册。
     *    Android 16 上 uprobe（convertToSensorEvent）不触发时，tracepoint
     *    拦截 read/pread64 读传感器事件数组仍有效（与 sensorservice 内部
     *    实现解耦）。失败非致命（符号缺失/注册失败 → 仅 uprobe 路径）。 */
    kpm_gyro_tp_init();

    if (!kf_uprobe_register || !kf_uprobe_unregister ||
        !kf_kmalloc || !kf_kfree) {
        kpm_log("kpm: gyro uprobe skipped - uprobe syms not resolved\n");
        kpm_log_info("kpm: gyro init - syms missing (uprobe_register=%p "
                     "uprobe_unregister=%p kmalloc=%p kfree=%p)\n",
                     kf_uprobe_register, kf_uprobe_unregister,
                     kf_kmalloc, kf_kfree);
        if (g_gyro_tp_ok)
            return 0;   /* tracepoint 路径已生效 */
        return -KPM_E_NOTFOUND;
    }
    kpm_log_info("kpm: gyro init - uprobe syms OK, installing...\n");
    kpm_printk("LH_gyro_dbg: init start\n");

    /* 1. PID 扫描定位 libsensorservice.so 加载基址（尽力而为）。
     *    此步仅用于 mm->pgd 偏移探测（kpm_probe_pgd_offset）；符号解析
     *    走文件（step3 filp_open+kernel_read），g_gyro_mem_pid/base
     *    已无消费者。失败不阻断 uprobe 安装，仅记录并跳过 base。 */
    {
        pid_t tpid = 0;
        uint64_t tbase = 0;
        if (kpm_gyro_find_lib_base(&tpid, &tbase) != 0) {
            kpm_log("kpm: gyro find_lib_base failed (non-fatal, "
                    "uprobe install continues)\n");
            kpm_printk("LH_gyro_dbg: step1 skipped (find_lib_base fail, "
                       "non-fatal)\n");
            g_gyro_mem_pid = 0;
            g_gyro_mem_base = 0;
        } else {
            g_gyro_mem_pid = tpid;
            g_gyro_mem_base = tbase;
            kpm_printk("LH_gyro_dbg: step1 ok pid=%d base=0x%llx\n",
                       tpid, (unsigned long long)tbase);
        }
    }

    /* 2. kern_path 直接获取 inode（无任务遍历，无 filp_open）。
     *    依赖 g_dentry_name_offset（已在 find_lib_base 中探测）。 */
    g_gyro_lib_path = KPM_GYRO_LIB_PATH;
    if (kpm_gyro_get_inode_by_path() != 0) {
        kpm_log("kpm: gyro cannot get inode via kern_path\n");
        kpm_printk("LH_gyro_dbg: FAIL step2 get_inode\n");
        if (g_gyro_tp_ok)
            return 0;   /* tracepoint 路径已生效 */
        return -KPM_E_NOTFOUND;
    }
    kpm_printk("LH_gyro_dbg: step2 ok inode=%p lib=%s\n",
               g_gyro_inode, g_gyro_lib_path);

    /* 3. 双符号解析：AIDL + HIDL
     * 两个 convertToSensorEvent 都解析并注册——sensorservice 可能
     * 走 AIDL 或 HIDL 任一路径，双挂保证任一被调用都触发。 */
    off = kpm_gyro_elf_find_sym_file(KPM_GYRO_SYM_AIDL);
    if (off >= 0) {
        g_gyro_offset = off;
        kpm_printk("LH_gyro_dbg: step3 AIDL off=0x%llx\n",
                   (unsigned long long)off);
    } else {
        kpm_log("kpm: gyro AIDL symbol not found\n");
        kpm_printk("LH_gyro_dbg: step3 AIDL miss\n");
    }
    off = kpm_gyro_elf_find_sym_file(KPM_GYRO_SYM_HIDL);
    if (off >= 0) {
        g_gyro_offset2 = off;
        kpm_printk("LH_gyro_dbg: step3 HIDL off=0x%llx\n",
                   (unsigned long long)off);
    } else {
        kpm_log("kpm: gyro HIDL symbol not found\n");
        kpm_printk("LH_gyro_dbg: step3 HIDL miss\n");
    }
    if (g_gyro_offset < 0 && g_gyro_offset2 < 0) {
        kpm_log("kpm: gyro convertToSensorEvent both AIDL+HIDL not found\n");
        kpm_printk("LH_gyro_dbg: FAIL step3 both AIDL+HIDL miss\n");
        kf_iput((struct inode *)g_gyro_inode);
        g_gyro_inode = NULL;
        if (g_gyro_tp_ok)
            return 0;   /* tracepoint 路径已生效 */
        return -KPM_E_NOTFOUND;
    }

    /* 4. 双 uprobe 注册。
     * AIDL + HIDL 两个 consumer 都注册（handler 相同、幂等改写，双触发
     * 无冲突——sensorservice 走任一路径都命中）。任一成功即
     * READY；两个都失败才返回（tracepoint 路径兜底）。
     *
     * uprobe_register 在 6.11 及以前恒为 3 参；6.12 起变 4 参
     * （ref_ctr_offset 插在第 3 参位置）且 uprobe_unregister 符号被删除、
     * struct uprobe_consumer 布局也变。按 3 参调用 6.12+ 内核会把 uc
     * 读成 ref_ctr_offset、真正 uc 落在第 4 个寄存器 → 解引用垃圾指针
     * → oops。故 6.12+ 直接放弃 uprobe（LH_syms 也已在解析层置 0，
     * 这里再兜一层），gyro 由 sys_enter tracepoint 承担。 */
    {
        extern uint32_t kver;
        if (kver >= 0x00060C00u || !kf_uprobe_register || !kf_uprobe_unregister) {
            kpm_log("kpm: gyro uprobe skipped (kver=%u.%u.%u; 3-arg "
                    "uprobe_register only valid below 6.12)\n",
                    (kver >> 16) & 0xFFu, (kver >> 8) & 0xFFu, kver & 0xFFu);
            kpm_printk("LH_gyro_dbg: step4 skipped (kver>=6.12 or syms 0)\n");
            if (kf_iput)
                kf_iput((struct inode *)g_gyro_inode);
            g_gyro_inode = NULL;
            if (g_gyro_tp_ok)
                return 0;   /* tracepoint 路径已生效 */
            return -KPM_E_NOTFOUND;
        }
    }
    {
        int reg_cnt = 0;

        lib_memset(&g_gyro_uc, 0, sizeof(g_gyro_uc));
        g_gyro_uc.handler = kpm_gyro_uprobe_pre;
        g_gyro_uc.ret_handler = kpm_gyro_uprobe_ret;
        g_gyro_uc.filter = NULL;
        lib_memset(&g_gyro_uc2, 0, sizeof(g_gyro_uc2));
        g_gyro_uc2.handler = kpm_gyro_uprobe_pre;
        g_gyro_uc2.ret_handler = kpm_gyro_uprobe_ret;
        g_gyro_uc2.filter = NULL;

        /* AIDL */
        if (g_gyro_offset >= 0) {
            int rc = kf_uprobe_register(g_gyro_inode, g_gyro_offset,
                                        &g_gyro_uc);
            if (rc == 0) {
                reg_cnt++;
                kpm_printk("LH_gyro_dbg: step4 AIDL registered off=0x%llx\n",
                           (unsigned long long)g_gyro_offset);
            } else {
                kpm_log("kpm: gyro AIDL uprobe_register failed (%d)\n", rc);
                kpm_printk("LH_gyro_dbg: step4 AIDL reg fail rc=%d\n", rc);
            }
        }
        /* HIDL */
        if (g_gyro_offset2 >= 0) {
            int rc = kf_uprobe_register(g_gyro_inode, g_gyro_offset2,
                                        &g_gyro_uc2);
            if (rc == 0) {
                reg_cnt++;
                kpm_printk("LH_gyro_dbg: step4 HIDL registered off=0x%llx\n",
                           (unsigned long long)g_gyro_offset2);
            } else {
                kpm_log("kpm: gyro HIDL uprobe_register failed (%d)\n", rc);
                kpm_printk("LH_gyro_dbg: step4 HIDL reg fail rc=%d\n", rc);
            }
        }
        if (reg_cnt == 0) {
            kpm_log("kpm: gyro both uprobe_register failed\n");
            kf_iput((struct inode *)g_gyro_inode);
            g_gyro_inode = NULL;
            if (g_gyro_tp_ok)
                return 0;   /* tracepoint 路径已生效 */
            return -KPM_E_NOTFOUND;
        }
        g_gyro_hook = 1;
        g_gyro_ready = 1;
    }
    kpm_log("kpm: gyro uprobe installed (AIDL+HIDL dual)\n");
    kpm_printk("LH_gyro_dbg: step4 uprobe_register OK, READY\n");
    return 0;
}

void kpm_gyro_exit(void)
{
    if (!g_gyro_hook && !g_gyro_tp_ok) return;

    /* 卸载约束：
     * - 6.1 的 uprobe_unregister 摘除 consumer 后不同步等待在途 handler
     *   （synchronize_srcu 是 6.8+ 才引入），返回时仍可能有 pre/ret 回调在
     *   RCU 读锁内执行；须先 KPM_RCU_SYNC()（synchronize_rcu，expedited
     *   回退）等在途 handler 退出，再释放 inode/ctx，否则模块内存释放后
     *   handler 访问 → UAF。
     * - 框架可能在 RCU 读临界区内调用 exit，exit 内 synchronize_rcu 会
     *   等待自己 → 自死锁。用 kpm_rcu_exit_guard_acquire()（三态借出，见
     *   LH_syms.c）借出/还回 RCU 读锁（先探测 rcu_read_lock_nesting 偏移，
     *   不依赖 rcu_read_lock_held 符号），嵌套计数守恒。
     * - guard<0（RCU 状态无法确认）时跳过全部可睡眠注销，仅复位门控
     *   （残留可接受于死锁）。 */
    {
        int guard = kpm_rcu_exit_guard_acquire();
        if (guard < 0) {
            kpm_log("kpm: gyro exit in RCU ctx (unconfirmed), skip "
                    "sleeping unregister (uprobe/tp residual)\n");
            g_gyro_tp_ok = 0;
            g_gyro_hook = 0;
            g_gyro_ready = 0;
            /* inode 引用与 ctx 残留：iput 可能睡眠（iput_final 需进程
             * 上下文），一并跳过——unload 前 FEAT_DISABLE(gyro) 预清理
             * 路径（正常上下文）会完整释放。 */
        } else {
            if (kf_uprobe_unregister && g_gyro_inode) {
                if (g_gyro_offset >= 0)
                    kf_uprobe_unregister(g_gyro_inode, g_gyro_offset,
                                         &g_gyro_uc);
                if (g_gyro_offset2 >= 0)
                    kf_uprobe_unregister(g_gyro_inode, g_gyro_offset2,
                                         &g_gyro_uc2);
            }
            KPM_RCU_SYNC();            /* 等所有在途 handler 完成 */
            /* sys_enter tracepoint 卸载：先 unregister 再
             * synchronize_unregister 等待全部在途 handler 退出（防 UAF）。
             * 必须在借出窗口内执行（synchronize_unregister → synchronize_rcu）。 */
            kpm_gyro_tp_exit();
            if (guard > 0)
                kpm_rcu_exit_guard_release();   /* 还回框架 RCU 读锁 */
        }
    }

    g_gyro_hook = 0;
    g_gyro_ready = 0;

    /* 释放 igrab 持有的 inode 引用 */
    if (g_gyro_inode && kf_iput) {
        kf_iput((struct inode *)g_gyro_inode);
        g_gyro_inode = NULL;
    }
    g_gyro_offset = -1;
    g_gyro_mem_pid = 0;
    g_gyro_mem_base = 0;

    /* 释放残留 ctx */
    {
        int i;
        unsigned long flags;
        flags = kpm_spin_lock_irqsave(&g_gyro_ctx_lock);
        for (i = 0; i < KPM_GYRO_CTX_HT_SIZE; i++) {
            struct kpm_gyro_ctx *ctx = g_gyro_ctx_ht[i];
            g_gyro_ctx_ht[i] = NULL;
            while (ctx) {
                struct kpm_gyro_ctx *next = ctx->next;
                kf_kfree(ctx);
                ctx = next;
            }
        }
        kpm_spin_unlock_irqrestore(&g_gyro_ctx_lock, flags);
    }

    kpm_log("kpm: gyro uprobe removed\n");
}

int kpm_gyro_ready(void)
{
    return g_gyro_ready;
}

/* 传感器 hook 安装状态查询（UN_HOOK 用）。
 * 1 = uprobe 或 sys_enter tracepoint 任一已注册。 */
int kpm_gyro_hook_active(void)
{
    return (g_gyro_hook || g_gyro_tp_ok) ? 1 : 0;
}

/* ===== 锁定 / 解锁 ===== */

long kpm_gyro_lock(int type, int axis, int value)
{
    kpm_gyro_axis_t *a;

    if (!g_gyro_ready && !g_gyro_tp_ok) return -KPM_E_NOTFOUND;
    if (type < 0 || type >= KPM_GYRO_TYPE_MAX) return -KPM_E_INVAL;
    if (axis < 0 || axis >= KPM_GYRO_AXIS_MAX) return -KPM_E_INVAL;

    a = (type == KPM_GYRO_TRANSLATION) ? &g_gyro.tran[axis]
                                       : &g_gyro.rot[axis];
    asm volatile("dmb ish" ::: "memory");
    a->locked = 1;
    if (value == KPM_GYRO_LOCK_CURRENT) {
        /* 锁定当前读数：置 lock_current，下一事件捕获并置锚点=0（冻结） */
        a->lock_current = 1;
        a->lock_anchor = 0;
        kpm_log("kpm: gyro lock-current %s axis=%d\n",
                type == KPM_GYRO_TRANSLATION ? "tran" : "rot", axis);
    } else {
        a->lock_current = 0;
        a->lock_anchor = value;   /* float 位模式 */
        kpm_log("kpm: gyro lock %s axis=%d value=%d\n",
                type == KPM_GYRO_TRANSLATION ? "tran" : "rot", axis, value);
    }
    asm volatile("dmb ish" ::: "memory");
    return 0;
}

long kpm_gyro_unlock(int type, int axis)
{
    int i, lo, hi;

    if (!g_gyro_ready && !g_gyro_tp_ok) return -KPM_E_NOTFOUND;
    if (type < 0 || type >= KPM_GYRO_TYPE_MAX) return -KPM_E_INVAL;

    if (axis == KPM_GYRO_ALL_AXIS) { lo = 0; hi = KPM_GYRO_AXIS_MAX - 1; }
    else if (axis >= 0 && axis < KPM_GYRO_AXIS_MAX) { lo = hi = axis; }
    else return -KPM_E_INVAL;

    asm volatile("dmb ish" ::: "memory");
    for (i = lo; i <= hi; i++) {
        kpm_gyro_axis_t *a = (type == KPM_GYRO_TRANSLATION)
                             ? &g_gyro.tran[i] : &g_gyro.rot[i];
        a->locked = 0;
        a->lock_anchor = 0;
        a->lock_current = 0;
    }
    asm volatile("dmb ish" ::: "memory");
    kpm_log("kpm: gyro unlock %s axis=%d\n",
            type == KPM_GYRO_TRANSLATION ? "tran" : "rot", axis);
    return 0;
}

long kpm_gyro_get_locks(void *buf, int max, int *count_out)
{
    int n = 0, t, i;
    kpm_gyro_entry_t *dst = (kpm_gyro_entry_t *)buf;

    if (!g_gyro_ready && !g_gyro_tp_ok) return -KPM_E_NOTFOUND;
    if (!buf || max <= 0) return -KPM_E_INVAL;

    for (t = 0; t < KPM_GYRO_TYPE_MAX && n < max; t++) {
        for (i = 0; i < KPM_GYRO_AXIS_MAX && n < max; i++) {
            kpm_gyro_axis_t *a = (t == KPM_GYRO_TRANSLATION)
                                 ? &g_gyro.tran[i] : &g_gyro.rot[i];
            if (!a->locked && !a->force_offset && !a->force_active)
                continue;  /* 仅导出有控制/锁定的轴 */
            dst[n].type = (uint8_t)t;
            dst[n].axis = (uint8_t)i;
            dst[n].locked = (uint8_t)a->locked;
            dst[n].force_mode = (uint8_t)a->force_mode;
            dst[n].lock_value = a->lock_anchor;
            dst[n].lock_current = (uint8_t)a->lock_current;
            dst[n].force_active = a->force_active;
            dst[n].force_target = a->force_target;
            dst[n].force_speed = a->force_speed;
            dst[n].force_offset = a->force_offset;
            n++;
        }
    }
    if (count_out) *count_out = n;
    return (long)n;
}

/* ===== 虚拟力控制（不覆盖用户输入） ===== */

long kpm_gyro_control(int type, int axis, int speed, int offset, int mode)
{
    int i, lo, hi;
    kpm_gyro_axis_t *a;

    if (!g_gyro_ready && !g_gyro_tp_ok) return -KPM_E_NOTFOUND;
    if (type < 0 || type >= KPM_GYRO_TYPE_MAX) return -KPM_E_INVAL;
    if (mode < 0 || mode > KPM_GYRO_FORCE_DIRECT) return -KPM_E_INVAL;

    if (axis == KPM_GYRO_ALL_AXIS) { lo = 0; hi = KPM_GYRO_AXIS_MAX - 1; }
    else if (axis >= 0 && axis < KPM_GYRO_AXIS_MAX) { lo = hi = axis; }
    else return -KPM_E_INVAL;

    if (speed <= 0) {
        /* speed<=0 视为停止控制（衰减到 0） */
        return kpm_gyro_control_stop(type, axis);
    }

    asm volatile("dmb ish" ::: "memory");
    for (i = lo; i <= hi; i++) {
        a = (type == KPM_GYRO_TRANSLATION) ? &g_gyro.tran[i] : &g_gyro.rot[i];
        a->force_mode = mode;
        a->force_active = 1;
        a->force_target = offset;   /* float 位模式 */
        a->force_speed = speed;     /* float 位模式 */
        if (mode == KPM_GYRO_FORCE_DIRECT)
            a->force_offset = offset;  /* 直接偏移：一步置位 */
    }
    asm volatile("dmb ish" ::: "memory");
    kpm_log("kpm: gyro control %s axis=%d mode=%d speed=%d offset=%d\n",
            type == KPM_GYRO_TRANSLATION ? "tran" : "rot", axis, mode,
            speed, offset);
    return 0;
}

long kpm_gyro_control_stop(int type, int axis)
{
    int i, lo, hi;
    kpm_gyro_axis_t *a;

    if (!g_gyro_ready && !g_gyro_tp_ok) return -KPM_E_NOTFOUND;
    if (type < 0 || type >= KPM_GYRO_TYPE_MAX) return -KPM_E_INVAL;

    if (axis == KPM_GYRO_ALL_AXIS) { lo = 0; hi = KPM_GYRO_AXIS_MAX - 1; }
    else if (axis >= 0 && axis < KPM_GYRO_AXIS_MAX) { lo = hi = axis; }
    else return -KPM_E_INVAL;

    asm volatile("dmb ish" ::: "memory");
    for (i = lo; i <= hi; i++) {
        a = (type == KPM_GYRO_TRANSLATION) ? &g_gyro.tran[i] : &g_gyro.rot[i];
        a->force_active = 0;
        a->force_target = 0;
        a->force_offset = 0;   /* 停止即清除，避免残留偏移导致 get_locks 仍导出 */
    }
    asm volatile("dmb ish" ::: "memory");
    kpm_log("kpm: gyro control_stop %s axis=%d\n",
            type == KPM_GYRO_TRANSLATION ? "tran" : "rot", axis);
    return 0;
}

/* ===== 客户端心跳保活 ===== */

#define KPM_GYRO_KEEPALIVE_TIMEOUT_MS 5000   /* 5s */

static uint64_t g_gyro_last_ping_ticks = 0;
static uint64_t g_gyro_cntfreq = 0;          /* 缓存频率（只读一次） */
static uint64_t g_gyro_timeout_ticks = 0;    /* 缓存超时 tick 数 */

static inline uint64_t kpm_gyro_ticks(void)
{
    uint64_t t;
    asm volatile("mrs %0, cntpct_el0" : "=r"(t));
    return t;
}

static uint64_t kpm_gyro_timeout_ticks_get(void)
{
    if (g_gyro_timeout_ticks == 0) {
        if (g_gyro_cntfreq == 0)
            asm volatile("mrs %0, cntfrq_el0" : "=r"(g_gyro_cntfreq));
        if (g_gyro_cntfreq == 0)
            return 0;   /* 频率不可读：永不超时（保守） */
        g_gyro_timeout_ticks = (g_gyro_cntfreq *
                                 KPM_GYRO_KEEPALIVE_TIMEOUT_MS) / 1000ULL;
    }
    return g_gyro_timeout_ticks;
}

/* 是否有任一轴存在锁/控制（purge 快路径判断） */
static int kpm_gyro_any_active(void)
{
    int i;
    for (i = 0; i < KPM_GYRO_AXIS_MAX; i++) {
        if (g_gyro.tran[i].locked || g_gyro.tran[i].force_active ||
            g_gyro.tran[i].force_offset ||
            g_gyro.rot[i].locked || g_gyro.rot[i].force_active ||
            g_gyro.rot[i].force_offset)
            return 1;
    }
    return 0;
}

long kpm_gyro_keepalive(void)
{
    g_gyro_last_ping_ticks = kpm_gyro_ticks();
    return 0;
}

int kpm_gyro_purge_if_idle(void)
{
    uint64_t now, timeout_ticks;
    int i;

    if (!kpm_gyro_any_active())
        return 0;   /* 无任何锁/控制：零开销快路径 */

    timeout_ticks = kpm_gyro_timeout_ticks_get();
    if (timeout_ticks == 0)
        return 0;   /* 频率不可读：保守不超时 */

    now = kpm_gyro_ticks();
    if (g_gyro_last_ping_ticks == 0 ||
        (now > g_gyro_last_ping_ticks &&
         (now - g_gyro_last_ping_ticks) > timeout_ticks)) {
        kpm_log("kpm: gyro keepalive timeout, release all locks + recenter\n");
        asm volatile("dmb ish" ::: "memory");
        for (i = 0; i < KPM_GYRO_AXIS_MAX; i++) {
            g_gyro.tran[i].locked = 0;
            g_gyro.tran[i].lock_anchor = 0;
            g_gyro.tran[i].lock_current = 0;
            g_gyro.tran[i].force_active = 0;
            g_gyro.tran[i].force_target = 0;
            g_gyro.tran[i].force_offset = 0;
            g_gyro.rot[i].locked = 0;
            g_gyro.rot[i].lock_anchor = 0;
            g_gyro.rot[i].lock_current = 0;
            g_gyro.rot[i].force_active = 0;
            g_gyro.rot[i].force_target = 0;
            g_gyro.rot[i].force_offset = 0;
        }
        asm volatile("dmb ish" ::: "memory");
        return 1;
    }
    return 0;
}

/* 状态查询（供 HOOK_INFO 输出，UDP/prctl 双通道） */
void kpm_gyro_get_state(int *ready, int *dev_count,
                        int *locked_axes, int *controlled_axes,
                        int *client_alive)
{
    int i, locked = 0, controlled = 0;
    uint64_t now, timeout_ticks;
    int alive = 1;

    if (ready)         *ready = (g_gyro_ready || g_gyro_tp_ok);
    /* dev_count 语义（uprobe 方案）：返回 convertToSensorEvent 偏移（0x61070
     * 等），便于诊断；未就绪时返回 0 */
    if (dev_count)     *dev_count = g_gyro_ready ? (int)g_gyro_offset : 0;

    for (i = 0; i < KPM_GYRO_AXIS_MAX; i++) {
        if (g_gyro.tran[i].locked || g_gyro.rot[i].locked) locked++;
        if (g_gyro.tran[i].force_active || g_gyro.tran[i].force_offset ||
            g_gyro.rot[i].force_active || g_gyro.rot[i].force_offset)
            controlled++;
    }
    if (locked_axes)      *locked_axes = locked;
    if (controlled_axes)  *controlled_axes = controlled;

    /* 客户端在线：有保活时间戳且未超时 */
    timeout_ticks = kpm_gyro_timeout_ticks_get();
    if (g_gyro_last_ping_ticks != 0 && timeout_ticks != 0) {
        now = kpm_gyro_ticks();
        alive = (now >= g_gyro_last_ping_ticks &&
                 (now - g_gyro_last_ping_ticks) <= timeout_ticks) ? 1 : 0;
    } else if (g_gyro_last_ping_ticks == 0) {
        alive = 0;
    }
    if (client_alive) *client_alive = alive;
}

/* 自动侦测：各拦截路径的启用状态与改写命中计数。
 * 用途：多路径并存时，客户端通过 LH_info 读取
 * 各路径命中数，判断"哪条路径真在工作"——命中为 0 的路径（注册成功但
 * 事件流不经过）不阻塞其他路径；全部为 0 则提示无有效路径。
 * 不改变共享结构体长度（仅 info dump 输出，无协议兼容风险）。 */
void kpm_gyro_get_stats(uint64_t *up_hits, uint64_t *tp_hits,
                        int *up_ready, int *tp_ready)
{
    if (up_hits)  *up_hits  = g_gyro_up_hits;
    if (tp_hits)  *tp_hits  = g_gyro_tp_hits;
    if (up_ready) *up_ready = g_gyro_ready;
    if (tp_ready) *tp_ready = g_gyro_tp_ok;
}