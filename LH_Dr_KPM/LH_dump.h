/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_DUMP_H_
#define _KPM_DUMP_H_

#include <ktypes.h>
#include "LH_comm.h"

/* ===== 内存 dump 子模块（协议化传输版，ELF 重建供 IDA/脱壳分析） =====
 *
 * 3 阶段会话（纯内存读取，数据经 UDP 分块回传）：
 *   - kpm_dump_begin: 解析 ELF 头/phdr，建立会话，返回 kpm_dump_hdr_t
 *     （含 Module/Base/Size 三信息 + 分块参数）。
 *   - kpm_dump_fetch: 按文件偏移读一块内存（未驻留页补零），
 *     返回 kpm_dump_chunk_t + data，块级 CRC32。
 *   - kpm_dump_end:   结束会话，返回 kpm_dump_done_t（整体 SHA256）。
 *
 * 设计约束：
 *   - 队列语义：同一时间仅一个会话（busy 互斥）。
 *   - 纯内存读取（页表遍历），无 VFS 痕迹，无内核态文件操作。
 *   - 无动态分配（会话状态静态全局），防内存泄漏/溢出。
 */

/* 初始化（模块加载时调用） */
int kpm_dump_init(void);

/* 退出（模块卸载时调用，清理会话） */
void kpm_dump_exit(void);

/* BEGIN：建立 dump 会话。
 * pid: 目标进程 PID；modname: 模块名（basename 包含匹配）；
 * name_len: 模块名长度；out: 输出协议头（128B）。
 * 返回 0 成功，-KPM_E_BUSY 会话忙，-KPM_E_NOTFOUND 模块未找到，
 * -KPM_E_INVAL 参数/ELF 非法，-KPM_E_NOMEM 内存不足 */
long kpm_dump_begin(pid_t pid, const char *modname, int name_len,
                    kpm_dump_hdr_t *out);

/* FETCH：按文件偏移读取一块。
 * file_off: 文件偏移；chunk: 输出块头（16B）；data_out: 数据缓冲；
 * max_len: data_out 容量。返回实际读取字节数（>0），负值错误 */
long kpm_dump_fetch(uint64_t file_off, kpm_dump_chunk_t *chunk,
                    uint8_t *data_out, int max_len);

/* END：结束会话，返回整体校验。
 * out: 输出 kpm_dump_done_t（48B）。返回 0 成功 */
long kpm_dump_end(kpm_dump_done_t *out);

#endif /* _KPM_DUMP_H_ */
