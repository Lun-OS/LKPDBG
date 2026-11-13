/* SPDX-License-Identifier: GPL-2.0-or-later */
/* kpm_log.h - 模块内部日志缓冲区 + 编译模式控制
 *
 * 不依赖 dmesg/printk 的日志系统。所有日志写入内部静态环形缓冲区，
 * 通过 prctl(KPM_CMD_GET_LOG, buf, size) 拷贝到用户态。
 *
 * 编译模式：
 *   debug   (KPM_DEBUG 定义): kpm_printk 映射到 printk，输出到 dmesg 供调试
 *   release (KPM_DEBUG 未定义): kpm_printk 为空操作，零 dmesg 痕迹
 *
 * 设计目标：
 *   - release 模式下不向 dmesg 输出任何内容，非 root 无法通过 dmesg 检测
 *   - debug 模式下输出详尽日志，便于开发调试
 *   - 内部日志缓冲区两种模式均可用（通过 prctl 获取）
 */
#ifndef _KPM_LOG_H_
#define _KPM_LOG_H_

#include <stdint.h>
#include <linux/printk.h>

/* 日志缓冲区大小（字节） */
#define KPM_LOG_BUF_SIZE  8192

/* ===== 编译模式控制 =====
 * KPM_DEBUG 由 Makefile 的 DEBUG=1 选项定义。
 *   debug:   kpm_printk -> printk (输出到 dmesg)
 *   release: kpm_printk -> 空操作 (零 dmesg 痕迹)
 *
 * 用法：
 *   make DEBUG=1 TARGET_COMPILE=...    (debug，默认)
 *   make TARGET_COMPILE=...            (release)
 */
#ifdef KPM_DEBUG
/* 6.1+ 内核将 printk 重命名为 _printk，printk 不存在。
 * 运行时通过 kpm_syms_init 解析正确符号，存入 kf_printk 函数指针。
 * 注意：RELEASE 模式下 kpm_printk 为空操作，不依赖任何符号。 */
extern int (*kf_printk)(const char *fmt, ...);
/* 不回退到 printk 编译时符号：
 * 6.1+ 内核中 printk 符号不存在，.o 文件中的未解析 printk 引用
 * 会导致 KPM Loader 加载失败。仅使用运行时解析的 kf_printk。 */
#define kpm_printk(fmt, ...)  do { \
    if (kf_printk) kf_printk(fmt, ##__VA_ARGS__); \
} while (0)
#else
#define kpm_printk(fmt, ...)  do {} while (0)
#endif

/* 初始化日志模块
 * 返回 0 成功，非 0 失败（vsnprintf 未解析）
 */
long kpm_log_init(void);

/* 退出日志模块 */
void kpm_log_exit(void);

/* 追加一条日志到缓冲区
 * 用法同 printk：kpm_log("kpm: xxx=%d\n", xxx);
 * 若 vsnprintf 未解析或缓冲区已满，静默丢弃。
 */
void kpm_log(const char *fmt, ...);

/* ===== 日志分级（release 仅错误日志） =====
 * kpm_log_err: 错误级，两种模式均记录（错误对调试/运维必需）
 * kpm_log_info: 信息级，仅 debug 记录；release 空操作（零痕迹）
 *
 * 用法：
 *   debug:   kpm_log_err / kpm_log_info 均写入 RAM 缓冲 + printk
 *   release: kpm_log_err 写入 RAM 缓冲（错误可查），kpm_log_info 完全关闭
 */
#ifdef KPM_DEBUG
#define kpm_log_err(fmt, ...)   kpm_log(fmt, ##__VA_ARGS__)
#define kpm_log_info(fmt, ...)  kpm_log(fmt, ##__VA_ARGS__)
#else
#define kpm_log_err(fmt, ...)   kpm_log(fmt, ##__VA_ARGS__)
#define kpm_log_info(fmt, ...)  do {} while (0)
#endif

/* 拷贝日志到用户态缓冲区
 * user_buf: 用户态缓冲区地址
 * size: 用户态缓冲区大小
 * 返回: >=0 实际拷贝字节数, <0 错误码
 */
long kpm_log_copy_to_user(void *user_buf, unsigned long size);

/* 拷贝日志到内核态缓冲区（用于 UDP 通道，不依赖 copy_to_user）
 * kbuf: 内核态缓冲区地址
 * size: 缓冲区大小
 * 返回: >=0 实际拷贝字节数, <0 错误码
 */
long kpm_log_copy_to_kernel(void *kbuf, unsigned long size);

/* 清空日志缓冲区 */
void kpm_log_clear(void);

/* 获取当前日志长度（字节） */
unsigned long kpm_log_length(void);

/* 获取缓冲区溢出标志（1=有日志被丢弃） */
int kpm_log_overflow(void);

#endif /* _KPM_LOG_H_ */
