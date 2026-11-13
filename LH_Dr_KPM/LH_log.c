/* SPDX-License-Identifier: GPL-2.0-or-later */
/* kpm_log.c - 模块内部日志缓冲区实现
 *
 * 使用从 kallsyms 解析的 vsnprintf 格式化字符串，写入静态缓冲区。
 * 通过 prctl(KPM_CMD_GET_LOG) 拷贝到用户态。
 *
 * 线程安全策略：
 *   - 使用 AArch64 LDXR/STLXR 内联汇编自旋锁保护 g_log_head 读写
 *   - 禁止使用 __atomic_* / __sync_*（会生成 libgcc 辅助函数调用，
 *     这些符号不在 KernelPatch 导出表内，导致 KPM 加载失败）
 *   - 锁粒度：整个 kpm_log 调用（格式化 + 写入），确保日志内容完整
 *   - 读取端（copy_to_user/copy_to_kernel）也加锁，确保读取一致快照
 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <baselib.h>  /* lib_memcpy（kpm_log_copy_to_kernel 内核态拷贝使用） */

#include "LH_log.h"
#include "LH_syms.h"
#include "LH_comm.h"

/* 内部日志缓冲区（静态分配，避免依赖 kmalloc） */
static char g_log_buf[KPM_LOG_BUF_SIZE];

/* 当前写入位置（即已用字节数） */
static volatile int g_log_head = 0;

/* 溢出标志：1 表示有日志因缓冲区满被丢弃 */
static volatile int g_log_overflow = 0;

/* 模块是否已初始化 */
static int g_log_inited = 0;

/* 日志自旋锁（AArch64 LDXR/STLXR 实现，0=未锁，1=已锁） */
static volatile int g_log_lock = 0;

/* AArch64 自旋锁：获取（同时禁用 IRQ）
 * kpm_log 可能在 IRQ 上下文被调用（如 kpm_intercept_input_before 中）；
 * 若 process 上下文持锁时被 IRQ 打断、IRQ 中再调 kpm_log 会永久自旋
 * 等待锁导致死锁，故须禁用 IRQ。
 *
 * 使用 DAIF 寄存器禁用 IRQ（DAIFSET #2），保存原始 DAIF 状态用于恢复。
 * LDXR/STXR 实现原子锁获取，WFE 降低功耗。 */
static inline unsigned long kpm_log_spin_lock_irqsave(void)
{
    unsigned long flags;
    int tmp;
    /* 保存 DAIF 状态并禁用 IRQ（bit 2 = IRQ mask） */
    asm volatile("mrs %0, daif\n"
                 "msr daifset, #2\n"
                 : "=r"(flags)
                 :
                 : "memory");

    asm volatile(
        "1: ldxr %w0, [%1]\n"       /* 排他读取锁值 */
        "   cbnz %w0, 2f\n"         /* 非0=已锁，跳转等待 */
        "   stxr %w0, %w2, [%1]\n"  /* 尝试排他写入1 */
        "   cbnz %w0, 1b\n"         /* STXR 失败(返回非0)，重试 */
        "   b 3f\n"                  /* 成功获取锁 */
        "2: wfe\n"                   /* 等待事件（降低功耗） */
        "   b 1b\n"                  /* 重新尝试 */
        "3:\n"
        : "=&r"(tmp)
        : "r"(&g_log_lock), "r"(1)
        : "memory");
    /* 获取锁后加内存屏障，确保后续操作不重排到锁之前 */
    asm volatile("dmb ish" ::: "memory");
    return flags;
}

/* AArch64 自旋锁：释放（同时恢复 IRQ） */
static inline void kpm_log_spin_unlock_irqrestore(unsigned long flags)
{
    /* 释放前加内存屏障，确保之前的写入对其他 CPU 可见 */
    asm volatile("dmb ish" ::: "memory");
    /* 普通写释放锁 + SEV 唤醒等待者 */
    g_log_lock = 0;
    asm volatile("sev");
    /* 恢复原始 DAIF 状态（可能重新启用 IRQ） */
    asm volatile("msr daif, %0" : : "r"(flags) : "memory");
}

/* 兼容性别名：无 IRQ 保存的版本（仅供已确认不在 IRQ 上下文的调用方使用） */
static inline void kpm_log_spin_lock(void)
{
    int tmp;
    asm volatile(
        "1: ldxr %w0, [%1]\n"
        "   cbnz %w0, 2f\n"
        "   stxr %w0, %w2, [%1]\n"
        "   cbnz %w0, 1b\n"
        "   b 3f\n"
        "2: wfe\n"
        "   b 1b\n"
        "3:\n"
        : "=&r"(tmp)
        : "r"(&g_log_lock), "r"(1)
        : "memory");
    asm volatile("dmb ish" ::: "memory");
}

static inline void kpm_log_spin_unlock(void)
{
    asm volatile("dmb ish" ::: "memory");
    g_log_lock = 0;
    asm volatile("sev");
}

long kpm_log_init(void)
{
    /* 清空缓冲区 */
    g_log_head = 0;
    g_log_overflow = 0;
    g_log_lock = 0;
    g_log_inited = 1;

    if (!kf_vsnprintf) {
        /* vsnprintf 不可用时内部日志无法工作，静默返回
         * 不使用 pr_warn 写入 dmesg，避免暴露模块加载痕迹 */
        return -1;
    }

    kpm_log("LH_log: init ok (buf_size=%d)\n", KPM_LOG_BUF_SIZE);
    return 0;
}

void kpm_log_exit(void)
{
    kpm_log("LH_log: exit\n");
    g_log_inited = 0;
}

void kpm_log(const char *fmt, ...)
{
    __builtin_va_list args;
    int space, len;
    unsigned long flags;

    if (!g_log_inited || !kf_vsnprintf || !fmt) return;

    /* 使用 IRQ 保存版本自旋锁：kpm_log 可能在 IRQ 上下文被调用。 */
    flags = kpm_log_spin_lock_irqsave();

    space = KPM_LOG_BUF_SIZE - g_log_head;
    if (space <= 1) {
        g_log_overflow = 1;
        kpm_log_spin_unlock_irqrestore(flags);
        return;
    }

    __builtin_va_start(args, fmt);
    len = kf_vsnprintf(g_log_buf + g_log_head,
                       (unsigned long)space, fmt, args);
    __builtin_va_end(args);

    if (len < 0) {
        kpm_log_spin_unlock_irqrestore(flags);
        return;  /* 格式化失败 */
    }

    if (len >= space) {
        /* 输出被截断，缓冲区已满 */
        g_log_head = KPM_LOG_BUF_SIZE;
        g_log_overflow = 1;
    } else {
        g_log_head += len;
    }

    kpm_log_spin_unlock_irqrestore(flags);
}

long kpm_log_copy_to_user(void *user_buf, unsigned long size)
{
    /* copy_to_user 可能触发 page fault 而睡眠，不可在自旋锁内调用
     * （会死锁或 panic）。锁内只取 head 一致快照并 lib_memcpy 到
     * 1024B 栈临时缓冲区（内核到内核、不睡眠、线程安全），锁外再
     * copy_to_user；超出 1024B 的部分截断。 */
    char tmp_buf[1024];
    int head_snapshot;
    unsigned long to_copy;
    unsigned long not_copied;
    unsigned long flags;

    if (!user_buf || !size) return -KPM_E_INVAL;
    if (!kf_copy_to_user) return -KPM_E_FAULT;

    flags = kpm_log_spin_lock_irqsave();
    head_snapshot = g_log_head;
    to_copy = (unsigned long)head_snapshot;
    if (to_copy > size) to_copy = size;
    if (to_copy > sizeof(tmp_buf)) to_copy = sizeof(tmp_buf);
    if (to_copy == 0) {
        kpm_log_spin_unlock_irqrestore(flags);
        return 0;
    }
    /* 锁内：仅内核到内核拷贝（lib_memcpy 不睡眠） */
    lib_memcpy(tmp_buf, g_log_buf, to_copy);
    kpm_log_spin_unlock_irqrestore(flags);

    /* 锁外：copy_to_user 允许睡眠 */
    not_copied = kf_copy_to_user(user_buf, tmp_buf, to_copy);
    return (long)(to_copy - not_copied);
}

/* UDP 通道需要直接拷贝日志到内核缓冲区（resp_data），
 * 不依赖 copy_to_user（UDP resp_data 是内核空间 g_resp_buf 的一部分）。 */
long kpm_log_copy_to_kernel(void *kbuf, unsigned long size)
{
    unsigned long to_copy;
    int head_snapshot;
    unsigned long flags;

    if (!kbuf || !size) return -KPM_E_INVAL;

    /* 加锁读取一致快照（IRQ 保存版本，因调用方可能在
     * 任何上下文调用，包括 UDP work 和 IRQ） */
    flags = kpm_log_spin_lock_irqsave();
    head_snapshot = g_log_head;
    to_copy = (unsigned long)head_snapshot;
    if (to_copy > size) to_copy = size;
    if (to_copy == 0) {
        kpm_log_spin_unlock_irqrestore(flags);
        return 0;
    }
    lib_memcpy(kbuf, g_log_buf, to_copy);
    kpm_log_spin_unlock_irqrestore(flags);
    return (long)to_copy;
}

void kpm_log_clear(void)
{
    unsigned long flags = kpm_log_spin_lock_irqsave();
    g_log_head = 0;
    g_log_overflow = 0;
    kpm_log_spin_unlock_irqrestore(flags);
}

unsigned long kpm_log_length(void)
{
    unsigned long len;
    unsigned long flags = kpm_log_spin_lock_irqsave();
    len = (unsigned long)g_log_head;
    kpm_log_spin_unlock_irqrestore(flags);
    return len;
}

int kpm_log_overflow(void)
{
    return g_log_overflow;
}
