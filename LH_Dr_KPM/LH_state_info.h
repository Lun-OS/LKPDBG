/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef KPM_STATE_INFO_H
#define KPM_STATE_INFO_H

#include <ktypes.h>
#include "LH_comm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 模块版本与构建时间（均为弱符号，kpm_build_time 默认 0） */
extern uint32_t kpm_build_version;
extern uint32_t kpm_build_time;

/* 填充 kpm_state_info_t 结构体（256 字节定长）
 *
 * info: 输出缓冲区（调用方负责分配，至少 256 字节）
 * syms_init_ret: kpm_syms_init 返回值
 * touch_ready, node_offset: 触摸设备就绪状态与 node 偏移
 * screen_w/h, raw_w/h, scale: 屏幕实际像素 + 硬件原始坐标 + 缩放因子
 * intercept_on, active_count: 拦截开启状态 + 活跃触摸数
 * mem_rw_path: KPM_PATH_MEM_RW_*
 * touch_path: KPM_PATH_TOUCH_*
 * cmdline_path: KPM_PATH_CMDLINE_*
 * put_task_path: 0=原生,1=手动+__put,2=free_task,3=泄漏
 * vmemmap_source: 0=符号,1=vmemmap_base,2=推算
 */
void kpm_fill_state_info(kpm_state_info_t *info,
                         int syms_init_ret,
                         int touch_ready, int node_offset,
                         int screen_w, int screen_h,
                         int raw_w, int raw_h, int screen_scale,
                         int intercept_on, int active_count,
                         uint8_t mem_rw_path, uint8_t touch_path,
                         uint8_t cmdline_path, uint8_t put_task_path,
                         uint8_t vmemmap_source);

#ifdef __cplusplus
}
#endif

#endif /* KPM_STATE_INFO_H */
