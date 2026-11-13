/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_PROC_H_
#define _KPM_PROC_H_

#include <ktypes.h>
#include "LH_comm.h"

/* 通用文件读取: 优先用 kernel_read_iter (支持 procfs seq_file), 回退到 kernel_read.
 * 解决 Linux 5.10+ 移除 set_fs() 后 kernel_read 不支持 procfs 的问题.
 * fp: 已打开的文件指针, buf: 内核缓冲区, count: 读取字节数, pos: 文件偏移
 * 返回读取的字节数, 失败返回负数 */
ssize_t kpm_read_file(struct file *fp, void *buf, size_t count, loff_t *pos);

/* Initialize process enumeration module */
long kpm_proc_init(void);

/* Exit process enumeration module */
void kpm_proc_exit(void);

/* Enumerate all processes.
 * buf: user buffer to receive kpm_proc_entry_t array
 * max_count: max entries to return
 * offset: starting offset (for pagination)
 * Returns number of entries written, or negative on error */
long kpm_proc_list(kpm_proc_entry_t *buf, int max_count, int offset);

/* Get memory maps for a process.
 * pid: target process PID
 * buf: user buffer to receive kpm_map_entry_t array
 * max_count: max entries to return
 * Returns number of entries written, or negative on error */
long kpm_proc_maps(pid_t pid, kpm_map_entry_t *buf, int max_count);

/* Query the single memory region containing addr.
 * pid: target process PID
 * addr: query address
 * out: user buffer to receive one kpm_map_entry_t
 * Returns 0 on success, negative on error (-KPM_E_NOTFOUND if no region contains addr)
 * Reads /proc/pid/maps in kernel context and returns the first region whose
 * [start, end) contains addr. Avoids CE-side procmaps caching. */
long kpm_proc_query_region(pid_t pid, uint64_t addr, kpm_map_entry_t *out);

/* ===== 内核空间版本（不涉及 copy_to_user，供 UDP 服务使用） ===== */

/* 内核空间进程枚举：直接填充内核缓冲区 */
long kpm_proc_list_kernel(kpm_proc_entry_t *kbuf, int max_count, int offset);

/* 内核空间内存映射枚举：直接填充内核缓冲区
 * offset: 跳过前 offset 个区域（UDP 分页支持，0 = 从头开始） */
long kpm_proc_maps_kernel(pid_t pid, kpm_map_entry_t *kbuf, int max_count, int offset, uint64_t start_addr);

/* 内核空间区域查询：直接填充单个内核缓冲区 */
long kpm_proc_query_region_kernel(pid_t pid, uint64_t addr, kpm_map_entry_t *out);

/* 按 PID + 地址查找包含该地址的 VMA（供 UDP FULLPATH 命令）。
 * 返回 VMA 指针（调用方需在使用期内保持有效），失败返回 NULL */
void *kpm_find_vma_for_pid(pid_t pid, uint64_t addr);

/* 按 PID + 地址查找 VMA 并解析完整路径（RCU 锁内完成，无锁外指针泄漏）。
 * 返回 0 = 成功（out 为完整路径），负值 = 失败 */
int kpm_find_vma_path_for_pid(pid_t pid, uint64_t addr, char *out, int out_size);

#endif /* _KPM_PROC_H_ */