/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_MEM_SCAN_H_
#define _KPM_MEM_SCAN_H_

#include <ktypes.h>
#include <stdint.h>

/* ===== Memory Scanner =====
 * Scans target process memory for values matching a pattern.
 * Supports multi-round refinement (first round full scan, subsequent rounds filter).
 */

#define KPM_MEM_SCAN_MAX_RESULTS 1048576   /* 1M × 24B ≈ 24MB vmalloc，超限置 truncated */
#define KPM_MEM_SCAN_MAX_REGIONS 32768     /* 全量 VMA 上限 */
#define KPM_SCAN_MAPS_PAGE       56        /* 小步长连续分页（1024 大步长跳过不稳定） */
/* 扫描批量：256KB = 64 页，与 kpm_mem_read_kernel_pages_cached 的 uint64 fail_map
 * 位宽完全对应（bit i = 第 i 个 4KB 页）。 */
#define KPM_SCAN_PAGE_BUF        KPM_SCAN_BATCH_MAX  /* 262144，见 kpm_mem_rw.h */

/* 单次拷贝结果的最大条数（防止 max_count 过大导致拷贝越界。
 * 1024 × 24B = 24KB，超出 UDP payload 上限时由 UDP 层先行裁剪） */
#define KPM_SCAN_COPY_MAX 1024

/* 长 AOB 特征上限（CE 式 AOB 扫描，特征经 UDP payload 传递）。
 * 64B 覆盖 UTF-16 字符串、函数头部字节序列等常见用途。
 * 仅影响 BYTEARRAY 语义（精确逐字节匹配），不改变现有 8B 打包兼容路径。 */
#define KPM_SCAN_AOB_MAX  64

/* Scan value types */
#define KPM_SCAN_TYPE_INT8      0
#define KPM_SCAN_TYPE_INT16     1
#define KPM_SCAN_TYPE_INT32     2
#define KPM_SCAN_TYPE_INT64     3
#define KPM_SCAN_TYPE_FLOAT     4
#define KPM_SCAN_TYPE_DOUBLE    5
#define KPM_SCAN_TYPE_BYTEARRAY 6
#define KPM_SCAN_TYPE_STRING    7

/* Scan modes */
#define KPM_SCAN_MODE_EXACT     0   /* exact value match */
#define KPM_SCAN_MODE_RANGE     1   /* value in [val, val+range] */
#define KPM_SCAN_MODE_CHANGED   2   /* value changed since last scan */
#define KPM_SCAN_MODE_UNCHANGED 3   /* value unchanged */
#define KPM_SCAN_MODE_INCREASED 4   /* value increased */
#define KPM_SCAN_MODE_DECREASED 5   /* value decreased */

/* Single scan result */
typedef struct {
    uint64_t addr;      /* matching address */
    uint64_t value;     /* current value (up to 8 bytes) */
    uint64_t prev_value; /* previous value (for changed/unchanged modes) */
} kpm_scan_result_t;

/* Memory region info */
typedef struct {
    uint64_t start;
    uint64_t end;
    uint32_t flags;     /* bit 0=R, 1=W, 2=X */
} kpm_mem_region_t;

/* 扫描会话状态（KPM_CMD_MEM_SCAN_STATUS 返回）。
 * 供客户端感知"扫描是否完整/结果是否被截断"，避免误判为扫描范围小。
 */
typedef struct {
    int      active;         /* 会话是否激活 */
    int      pid;            /* 目标 PID（内核扫描时为 0） */
    int      region_count;   /* 本次扫描覆盖的区域数 */
    int      result_count;   /* 当前命中结果数 */
    int      result_capacity;/* 结果缓冲容量 */
    int      truncated;      /* 1=结果缓冲已满，有区域未记录（客户端应视为"部分结果"） */
    uint64_t scanned_bytes;  /* 已扫描字节数（含失败页，失败页计为跳过） */
    uint64_t total_bytes;    /* 全部区域字节总数（扫描进度 = scanned_bytes/total_bytes） */
    uint32_t failed_pages;   /* 读取失败页数（walk 失败，正常跳过不计假命中） */
    uint32_t swap_pages;     /* swap/zram 换出页数（失败页中识别出的 swap 页）。
                              * 客户端可据此判断数据完整性，并用 recover_swap 补读。 */
} kpm_scan_status_t;

/* Initialize */
long kpm_mem_scan_init(void);

/* Exit */
void kpm_mem_scan_exit(void);

/* Start a new scan session.
 * pid: target process PID
 * value_type: KPM_SCAN_TYPE_*
 * scan_mode: KPM_SCAN_MODE_*
 * value: pointer to the value to match (up to 8 bytes, or byte array pointer)
 * value_len: length of value (for byte array/string)
 * range: for KPM_SCAN_MODE_RANGE, value must be in [value, value+range]
 * Returns 0 on success, negative on error */
long kpm_mem_scan_start(pid_t pid, int value_type, int scan_mode,
                        uint64_t value, int value_len, uint64_t range);

/* 长 AOB 特征扫描（支持通配符 mask）。
 * 支持 >8 字节的字节模式匹配（如 UTF-16 字符串 30B、函数头特征）。
 * pattern: 特征字节指针（内核空间，来自 UDP payload 拷贝），长度 ≤ KPM_SCAN_AOB_MAX(64)
 * mask: 通配掩码（可为 NULL = 全精确）。mask[i]==0 表示 pattern[i] 为通配符（任意字节）；
 *       非 0 表示该字节精确匹配（CE 风格 AOB 特征码：'?' = 任意）。
 * plen: 特征长度（mask 长度与 plen 一致）
 * scan_mode: 仅支持 KPM_SCAN_MODE_EXACT（与 BYTEARRAY 一致）
 * 内部复制 pattern/mask 到会话缓冲，扫描为同步操作。 */
long kpm_mem_scan_start_aob(pid_t pid, const uint8_t *pattern, int plen,
                            const uint8_t *mask,
                            int scan_mode, uint64_t range);

/* 内核线性映射范围扫描（KPM_CMD_MEM_SCAN_KERNEL_START）。
 * pid 必须传 0（保留）；扫描范围 = [PAGE_OFFSET, PAGE_OFFSET+range)。
 * 直接 copy_from_kernel_nofault 逐页读取（无进程页表遍历，无 VMA 依赖）。
 * 其余语义（匹配/过滤/结果）与 kpm_mem_scan_start 一致。
 * range 上限 KPM_SCAN_KERNEL_MAX（64GB），防御误传超大。 */
long kpm_mem_scan_kernel_start(int value_type, int scan_mode,
                               uint64_t value, int value_len, uint64_t range);

/* Next round: filter existing results.
 * value_type: KPM_SCAN_TYPE_*
 * scan_mode: KPM_SCAN_MODE_*
 * value: pointer to the value to match
 * value_len: length of value
 * range: for KPM_SCAN_MODE_RANGE */
long kpm_mem_scan_next(int value_type, int scan_mode,
                       uint64_t value, int value_len, uint64_t range);

/* Copy scan results to user buffer.
 * user_buf: user-space buffer
 * max_count: max number of results to copy
 * offset: starting offset in results array
 * Returns number of results copied, or negative on error */
long kpm_mem_scan_copy_results(kpm_scan_result_t *user_buf,
                               int max_count, int offset);

/* Copy scan results to kernel buffer (for UDP channel).
 * Uses lib_memcpy instead of copy_to_user, suitable when caller
 * passes a kernel-space buffer (e.g. g_resp_buf in UDP handler).
 * Returns number of results copied, or negative on error */
long kpm_mem_scan_copy_results_kernel(kpm_scan_result_t *kbuf,
                                      int max_count, int offset);

/* 查询扫描会话状态。
 * 返回 region_count / result_count / truncated / 进度等，供客户端判断
 * 扫描完整性（结果是否被截断、扫描是否完成）。 */
long kpm_mem_scan_status(kpm_scan_status_t *out);

/* Clear current scan session and free memory */
long kpm_mem_scan_clear(void);

/* 中止当前扫描（模块卸载时调用）。
 * 置 cancel 标志，扫描主循环/过滤循环检查后提前退出（返回部分结果），
 * 防大范围扫描阻塞 UDP workqueue 的卸载 flush。 */
void kpm_mem_scan_abort(void);

#endif /* _KPM_MEM_SCAN_H_ */