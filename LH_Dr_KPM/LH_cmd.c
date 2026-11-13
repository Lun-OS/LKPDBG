/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_cmd.c - 统一协议处理层
 *
 * 架构：
 *   执行层 → 协议处理层（本文件）→ UDP 接口 / prctl 接口
 *
 * 职责：
 *   1. 命令解码（已由接口层完成 XOR 还原）
 *   2. 参数解析（统一使用 UDP 布局，prctl 适配层负责翻译）
 *   3. 执行功能函数（_kernel 版写内核缓冲 / 用户指针版内部 copy_to_user）
 *   4. 数据出口统一（kpm_cmd_out_write / 通道内选函数）
 *
 * 新增功能：在 kpm_cmd_dispatch 添加一个 case 即可，UDP/prctl 双接口自动获得。
 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <kputils.h>
#include <ksyms.h>
#include <baselib.h>

#include "LH_comm.h"
#include "LH_cmd.h"
#include "LH_syms.h"
#include "LH_log.h"
#include "LH_touch.h"
#include "touch_manager.h"
#include "LH_intercept.h"
#include "LH_gyro.h"
#include "LH_mem_rw.h"
#include "LH_proc.h"
#include "LH_mem_scan.h"
#include "LH_mem_freeze.h"
#include "LH_ptr_scan.h"
#include "LH_debug.h"
#include "LH_hook_enhanced.h"
#include "LH_hide.h"
#include "LH_state_info.h"
#include "LH_utils.h"
#include "LH_feat.h"
#include "LH_suspend.h"
#include "LH_netctl.h"
#include "LH_filter.h"
#include "LH_sysmon.h"
#include "LH_resctl.h"
#include "LH_hook2.h"
#include "LH_force.h"
#include "LH_trace.h"
#include "LH_memwatch.h"
#include "LH_wxshadow.h"

/* GFP_KERNEL 在 KPM 框架的 gfp.h 中被注释掉，此处手动定义（与 kpm_mem_rw.c 一致） */
#ifndef GFP_KERNEL
#define GFP_KERNEL  0xcc0u
#endif

/* ===== 统一数据出口 ===== */
long kpm_cmd_out_write(kpm_cmd_ctx_t *ctx, const void *data, uint32_t len)
{
    if (!ctx || !data)
        return -KPM_E_INVAL;

    if (ctx->channel == KPM_CHAN_UDP) {
        if (!ctx->out_buf || len > ctx->out_cap)
            return -KPM_E_FAULT;
        lib_memcpy(ctx->out_buf, data, len);
        if (ctx->out_len)
            *ctx->out_len = len;
        return 0;
    } else {
        /* prctl：copy_to_user 到用户目标。
         * user_out_cap 非 0 时做容量校验：避免调用方传入
         * 小于结果长度的缓冲区时，内核 copy_to_user 写越界（用户栈
         * 腐蚀）。0 = 旧客户端未提供容量，保持兼容（不限）。 */
        if (!ctx->user_out || !kf_copy_to_user)
            return -KPM_E_FAULT;
        if (ctx->user_out_cap && len > ctx->user_out_cap)
            return -KPM_E_INVAL;
        if (kf_copy_to_user(ctx->user_out, data, len))
            return -KPM_E_FAULT;
        return 0;
    }
}

/* ===== 统一命令分发 =====
 * 参数统一布局（以 UDP 通道为准）：
 *   READ_MEM:      arg2=pid, arg3=addr, arg5=len
 *   WRITE_MEM:     arg2=pid, arg3=addr, 数据在 req_data
 *   PROC_LIST:     arg2=max_count, arg3=offset
 *   PROC_MAPS:     arg2=pid, arg3=max_count, arg4=offset
 *   PROC_QUERY:    arg2=pid, arg3=addr
 *   SCAN_RESULT:   arg2=max_count, arg3=offset
 *   FREEZE_LIST:   arg2=max_count
 *   PTR_RESULT:    arg2=max_count, arg3=offset
 *   BP_LIST:       arg2=max_count
 *   HOOK_LIST:     arg2=max_count
 *   TOUCH_GET:     arg2=handle
 *   TOUCH_GET_ALL: arg3=max_count
 * 其余命令参数语义与 prctl 通道一致。
 */
long kpm_cmd_dispatch(kpm_cmd_ctx_t *ctx)
{
    long ret = 0;

    if (!ctx)
        return -KPM_E_INVAL;

    /* 触摸心跳超时清理——每个命令入口先清残留
     * （客户端离线遗留的虚拟触摸），随后命令正常处理。 */
    touch_purge_all_if_idle();

    /* 陀螺仪心跳超时清理——客户端离线（崩溃/断网）残留的
     * 锁/偏移在任意命令入口自动释放回正（与触摸同机制）。 */
    kpm_gyro_purge_if_idle();

    /* 触摸/拦截命令范围一律视为"客户端正在操作"，刷新保活
     * 时间戳——"5 秒内还在操作就不需要发送专门 ping"。覆盖两类：
     *   - 触摸命令 0x1020-0x102f（CREATE/MOVE/UP/DESTROY/…）
     *   - 拦截命令 0x1014-0x1019（INTERCEPT_ON/OFF/… 修改用户触摸）
     * 拦截开启后若客户端离线（崩溃/断网）且无心跳 → 超时自动关闭拦截，
     * 恢复用户触摸原样（见 touch_purge_all_if_idle）。UDP 与 prctl 双通道
     * 都走本 dispatch，行为天然一致。 */
    if ((ctx->cmd >= KPM_CMD_INTERCEPT_ON && ctx->cmd <= KPM_CMD_INTERCEPT_SLOT_STATE) ||
        (ctx->cmd >= KPM_CMD_TOUCH_CREATE && ctx->cmd <= KPM_CMD_TOUCH_KEEPALIVE))
        touch_keepalive();

    /* GYRO 命令范围（0x1040-0x1046）一律视为"客户端正在操作"，
     * 刷新陀螺仪保活时间戳——"5 秒内还在操作就不需要发送专门 ping"。 */
    if (ctx->cmd >= KPM_CMD_GYRO_LOCK && ctx->cmd <= KPM_CMD_GYRO_KEEPALIVE)
        kpm_gyro_keepalive();

    /* ===== 功能单元命令门控 =====
     * 命令段 → 功能单元映射，未启用的功能统一返回指定错误
     * -KPM_E_DISABLED（客户端据此先 FEAT_ENABLE）。集中门控放在
     * dispatch 顶部：两通道一致、开销为几次比较。
     * 不门控：诊断命令（HOOK_INFO/GET_LOG/SCREEN_INFO/TOUCH_DEV 查询）、
     * 功能开关命令本身（FEAT_*）、旧 HOOK 禁用壳（恒 -KPM_E_INVAL）。
     * UDP 特有命令（批量读/流/DUMP/READ_FILE 等）在 LH_udp.c 同规则门控。 */
    {
        uint32_t unit = KPM_FEAT_MAX;
        uint32_t c = ctx->cmd;

        if (c == KPM_CMD_READ_MEM || c == KPM_CMD_WRITE_MEM)
            unit = KPM_FEAT_MEM_RW;
        else if (c >= KPM_CMD_PROC_LIST && c <= KPM_CMD_PROC_QUERY_REGION)
            unit = KPM_FEAT_PROC;
        else if (c == KPM_CMD_PROC_PID_BY_NAME ||
                 c == KPM_CMD_PROC_MODULE_BASE ||
                 c == KPM_CMD_PROC_MODULE_BSS)
            unit = KPM_FEAT_PROC;
        else if ((c >= KPM_CMD_TOUCH_CREATE && c <= KPM_CMD_TOUCH_KEEPALIVE) ||
                 (c >= KPM_CMD_INTERCEPT_ON && c <= KPM_CMD_INTERCEPT_SLOT_STATE))
            unit = KPM_FEAT_TOUCH;
        else if (c >= KPM_CMD_GYRO_LOCK && c <= KPM_CMD_GYRO_KEEPALIVE)
            unit = KPM_FEAT_GYRO;
        else if (c >= KPM_CMD_MEM_SCAN_START && c <= KPM_CMD_MEM_SCAN_CLEAR)
            unit = KPM_FEAT_MEM_SCAN;
        else if (c >= KPM_CMD_FREEZE_ADD && c <= KPM_CMD_FREEZE_CLEAR)
            unit = KPM_FEAT_MEM_FREEZE;
        else if (c >= KPM_CMD_PTR_SCAN && c <= KPM_CMD_PTR_RESULT)
            unit = KPM_FEAT_PTR_SCAN;
        else if ((c >= KPM_CMD_DEBUG_BP_SET && c <= KPM_CMD_DEBUG_BP_REGMOD) ||
                 (c >= KPM_CMD_DEBUG_BP_SET_KERNEL &&
                  c <= KPM_CMD_DEBUG_BP_SET_FLAGS) ||
                 (c >= KPM_CMD_STEP_TRACE && c <= KPM_CMD_STEP_FETCH) ||
                 (c >= KPM_CMD_TRAP_GET && c <= KPM_CMD_DEBUG_BP_SET_SYNC))
            unit = KPM_FEAT_DEBUG;
        else if (c >= KPM_CMD_TRACE_CTRL && c <= KPM_CMD_TRACE_INFO)
            unit = KPM_FEAT_TRACE;
        else if (c >= KPM_CMD_MEMWATCH_SET && c <= KPM_CMD_MEMWATCH_REARM)
            unit = KPM_FEAT_MEMWATCH;
        else if (c >= KPM_CMD_WX_SET_BP && c <= KPM_CMD_WX_INFO)
            unit = KPM_FEAT_WXSHADOW;
        else if (c >= KPM_CMD_SUSPEND_PROC && c <= KPM_CMD_SUSPEND_LIST)
            unit = KPM_FEAT_SUSPEND;
        else if (c >= KPM_CMD_NETCTL_RULE && c <= KPM_CMD_NETCTL_LIST)
            unit = KPM_FEAT_NETCTL;
        else if (c == KPM_CMD_FILTER_RULE) {
            /* 共享过滤器：netctl 或 sysmon 任一启用即可管理规则 */
            if (!kpm_feat_enabled(KPM_FEAT_NETCTL) &&
                !kpm_feat_enabled(KPM_FEAT_SYSMON))
                return -KPM_E_DISABLED;
        }
        else if (c >= KPM_CMD_SYSMON_SET && c <= KPM_CMD_SYSMON_RULES)
            unit = KPM_FEAT_SYSMON;
        else if (c >= KPM_CMD_RESCTL_AFFINITY && c <= KPM_CMD_RESCTL_CAPS)
            unit = KPM_FEAT_RESCTL;
        else if (c == KPM_CMD_HOOK2_SET_KFUNC)
            unit = KPM_FEAT_HOOK;           /* 普通（内核函数）模式 */
        else if (c >= KPM_CMD_HOOK2_SET_STEALTH && c <= KPM_CMD_HOOK2_LIST)
            unit = KPM_FEAT_STEALTH_HOOK;   /* 无痕（BRP）模式 */
        else if (c == KPM_CMD_HIDE_PROCESS || c == KPM_CMD_RECOVER_PROCESS ||
                 c == KPM_CMD_HIDE_LIST || c == KPM_CMD_UN_HOOK ||
                 c == KPM_CMD_HIDE_P1)
            unit = KPM_FEAT_HIDE;

        if (unit != KPM_FEAT_MAX && !kpm_feat_enabled(unit))
            return -KPM_E_DISABLED;
    }

    switch (ctx->cmd) {

    /* ===== 通用命令 ===== */

    case KPM_CMD_HOOK_INFO: {
        /* UDP 返回 256B kpm_state_info_t（含陀螺仪传感器状态）；
         * prctl 客户端传 arg2=buf, arg3=size 时同样返回完整结构，
         * 否则仅返回 state 位图（兼容旧客户端）。
         * 两者 ret 均为 state（兼容旧客户端）。 */
        int want_struct = (ctx->channel == KPM_CHAN_UDP) ||
                          (ctx->user_out &&
                           ctx->user_out_cap >= sizeof(kpm_state_info_t));
        if (want_struct) {
            kpm_state_info_t si;
            int raw_w = 0, raw_h = 0;
            int scale = kpm_touch_get_scale();
            int sw, sh;
            uint8_t mem_rw_path, touch_path, cmdline_path, put_task_path,
                    vmemmap_source;

            kpm_touch_get_screen_info(&raw_w, &raw_h);
            sw = (scale > 0) ? (raw_w / scale) : raw_w;
            sh = (scale > 0) ? (raw_h / scale) : raw_h;
            mem_rw_path = (kf_vmap && kf_vunmap) ? KPM_PATH_MEM_RW_DMA
                                                 : KPM_PATH_MEM_RW_WB_ONLY;
            touch_path = (kpm_intercept_get_state() > 0) ? KPM_PATH_TOUCH_CAPTURE
                                                         : KPM_PATH_TOUCH_INPLACE;
            if (!kpm_touch_ready()) touch_path = KPM_PATH_TOUCH_NONE;
            if (kf_get_cmdline) cmdline_path = KPM_PATH_CMDLINE_NATIVE;
            else if (g_arg_start_offset > 0) cmdline_path = KPM_PATH_CMDLINE_MEM;
            else if (kf_filp_open) cmdline_path = KPM_PATH_CMDLINE_FILP;
            else cmdline_path = KPM_PATH_CMDLINE_COMM;
            put_task_path = kpm_put_task_path();
            vmemmap_source = (g_vmemmap_base > 0) ? 1 : 2;

            kpm_fill_state_info(&si, 0, kpm_touch_ready() ? 1 : 0,
                                kpm_touch_get_node_offset(),
                                sw, sh, raw_w, raw_h, scale,
                                (kpm_intercept_get_state() > 0) ? 1 : 0,
                                (int)touch_get_active_count(),
                                mem_rw_path, touch_path, cmdline_path,
                                put_task_path, vmemmap_source);
            ret = kpm_cmd_out_write(ctx, &si, sizeof(si));
            if (ret != 0)
                break;   /* 输出失败：保留错误码 */
        }
        ret = (long)kpm_get_state();
        break;
    }

    case KPM_CMD_TOUCH_DEV:
        ret = kpm_touch_ready() ? 1 : 0;
        break;

    case KPM_CMD_SCREEN_INFO: {
        /* UDP: 返回 5 个 int（sw/sh/raw_w/raw_h/scale，20B）。
         * prctl: 返回 2 个 int（w/h）到 arg2/arg3 两个用户指针。 */
        int raw_w = 0, raw_h = 0;
        int scale = kpm_touch_get_scale();
        int sw, sh;
        kpm_touch_get_screen_info(&raw_w, &raw_h);
        sw = (scale > 0) ? (raw_w / scale) : raw_w;
        sh = (scale > 0) ? (raw_h / scale) : raw_h;
        if (ctx->channel == KPM_CHAN_UDP) {
            int fields[5];
            fields[0] = sw;
            fields[1] = sh;
            fields[2] = raw_w;
            fields[3] = raw_h;
            fields[4] = scale;
            ret = kpm_cmd_out_write(ctx, fields, sizeof(fields));
        } else {
            /* prctl: arg2=&w, arg3=&h（两个独立用户指针） */
            if (kf_copy_to_user)
                kf_copy_to_user((void *)(uintptr_t)ctx->arg2, &sw, sizeof(int));
            if (kf_copy_to_user)
                kf_copy_to_user((void *)(uintptr_t)ctx->arg3, &sh, sizeof(int));
            ret = 0;
        }
        break;
    }

    case KPM_CMD_GET_LOG: {
        /* UDP: 写内核缓冲（固定 16KB）；prctl: copy_to_user 到用户缓冲 */
        if (ctx->channel == KPM_CHAN_UDP) {
            ret = kpm_log_copy_to_kernel(ctx->out_buf, ctx->out_cap);
            if (ret > 0)
                *ctx->out_len = (unsigned long)ret;
        } else {
            ret = kpm_log_copy_to_user((void *)ctx->user_out,
                                       (unsigned long)ctx->user_out_cap);
        }
        break;
    }

    /* ===== 内存读写 ===== */

    case KPM_CMD_READ_MEM: {
        pid_t target_pid = (pid_t)ctx->arg2;
        uint64_t remote_addr = ctx->arg3;
        int len = (int)ctx->arg5;

        if (len <= 0) { ret = -KPM_E_INVAL; break; }
        if (target_pid == 0) {
            /* 内核 VA 读。非 force 仅安全白名单（DEVAPC 守卫）；
             * force 允许任意 kernel VA。 */
            int force = (kpm_force_mask() & KPM_FORCE_KERNEL_RW) ? 1 : 0;
            if (ctx->channel == KPM_CHAN_UDP) {
                if (len > (int)ctx->out_cap) len = (int)ctx->out_cap;
                ret = kpm_mem_read_kernel_va(remote_addr, ctx->out_buf,
                                             len, force);
                if (ret > 0) *ctx->out_len = (unsigned long)ret;
            } else {
                char tmp[256];
                int done = 0;
                long last = 0;
                if (!ctx->user_out || !kf_copy_to_user) {
                    ret = -KPM_E_INVAL;
                    break;
                }
                while (done < len) {
                    int chunk = len - done;
                    if (chunk > (int)sizeof(tmp))
                        chunk = (int)sizeof(tmp);
                    last = kpm_mem_read_kernel_va(
                                remote_addr + (uint64_t)done,
                                tmp, chunk, force);
                    if (last <= 0)
                        break;
                    if (kf_copy_to_user((char *)ctx->user_out + done,
                                        tmp, (unsigned long)last)) {
                        last = -KPM_E_FAULT;
                        break;
                    }
                    done += (int)last;
                    if (last < chunk)
                        break;
                }
                ret = (done > 0) ? done : last;
            }
            break;
        }
        if (ctx->channel == KPM_CHAN_UDP) {
            if (len > (int)ctx->out_cap) len = (int)ctx->out_cap;
            ret = kpm_mem_read_kernel(target_pid, remote_addr, ctx->out_buf, len);
            if (ret > 0) *ctx->out_len = (unsigned long)ret;
        } else {
            ret = kpm_mem_rw_process(target_pid, remote_addr,
                                     ctx->user_out, len, 0);
        }
        break;
    }

    case KPM_CMD_WRITE_MEM: {
        pid_t target_pid = (pid_t)ctx->arg2;
        uint64_t remote_addr = ctx->arg3;

        if (target_pid == 0) {
            /* 内核 VA 写——非 force 一律 -PERM（fail-closed）；
             * force 下 text 走 aarch64_insn_patch_text，其它直写。 */
            int force = (kpm_force_mask() & KPM_FORCE_KERNEL_RW) ? 1 : 0;
            if (!force) { ret = -KPM_E_PERM; break; }
            if (ctx->channel == KPM_CHAN_UDP) {
                int wlen = (int)ctx->req_len;
                if (wlen <= 0) { ret = -KPM_E_INVAL; break; }
                ret = kpm_mem_write_kernel_va(remote_addr, ctx->req_data,
                                              wlen, 1);
            } else {
                int wlen = (int)ctx->arg5;
                char tmp[256];
                int done = 0;
                long last = 0;
                if (wlen <= 0 || !ctx->user_out || !kf_copy_from_user) {
                    ret = -KPM_E_INVAL;
                    break;
                }
                while (done < wlen) {
                    int chunk = wlen - done;
                    if (chunk > (int)sizeof(tmp))
                        chunk = (int)sizeof(tmp);
                    if (kf_copy_from_user(tmp,
                                          (const char *)ctx->user_out + done,
                                          (unsigned long)chunk)) {
                        last = -KPM_E_FAULT;
                        break;
                    }
                    last = kpm_mem_write_kernel_va(
                                remote_addr + (uint64_t)done, tmp, chunk, 1);
                    if (last <= 0)
                        break;
                    done += (int)last;
                    if (last < chunk)
                        break;
                }
                ret = (done > 0) ? done : last;
            }
            break;
        }
        if (ctx->channel == KPM_CHAN_UDP) {
            int wlen = (int)ctx->req_len;
            if (wlen <= 0) { ret = -KPM_E_INVAL; break; }
            ret = kpm_mem_write_kernel(target_pid, remote_addr,
                                       ctx->req_data, wlen);
        } else {
            int wlen = (int)ctx->arg5;
            if (wlen <= 0) { ret = -KPM_E_INVAL; break; }
            ret = kpm_mem_rw_process(target_pid, remote_addr,
                                     ctx->user_out, wlen, 1);
        }
        break;
    }

    /* ===== 进程枚举 ===== */

    case KPM_CMD_PROC_LIST: {
        int max_count = (int)ctx->arg2;
        int offset = (int)ctx->arg3;
        int entry_size = sizeof(kpm_proc_entry_t);

        if (max_count <= 0) max_count = 32;
        if (ctx->channel == KPM_CHAN_UDP) {
            if ((uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
                max_count = ctx->out_cap / entry_size;
            ret = kpm_proc_list_kernel((kpm_proc_entry_t *)ctx->out_buf,
                                       max_count, offset);
            if (ret > 0) *ctx->out_len = (unsigned long)ret * entry_size;
        } else {
            ret = kpm_proc_list((kpm_proc_entry_t *)ctx->user_out,
                                max_count, offset);
        }
        break;
    }

    case KPM_CMD_PROC_MAPS: {
        pid_t target_pid = (pid_t)ctx->arg2;
        int max_count = (int)ctx->arg3;
        int offset = (int)ctx->arg4;
        uint64_t start_addr = ctx->arg5;   /* cursor 续扫起点 */
        int entry_size = sizeof(kpm_map_entry_t);

        if (max_count <= 0) max_count = 32;
        if (offset < 0) offset = 0;
        if (ctx->channel == KPM_CHAN_UDP) {
            if ((uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
                max_count = ctx->out_cap / entry_size;
            ret = kpm_proc_maps_kernel(target_pid,
                                       (kpm_map_entry_t *)ctx->out_buf,
                                       max_count, offset, start_addr);
            if (ret > 0) *ctx->out_len = (unsigned long)ret * entry_size;
        } else {
            ret = kpm_proc_maps(target_pid, (kpm_map_entry_t *)ctx->user_out,
                                max_count);
        }
        break;
    }

    case KPM_CMD_PROC_QUERY_REGION: {
        pid_t target_pid = (pid_t)ctx->arg2;
        uint64_t addr = ctx->arg3;

        if (ctx->channel == KPM_CHAN_UDP) {
            ret = kpm_proc_query_region_kernel(target_pid, addr,
                        (kpm_map_entry_t *)ctx->out_buf);
            if (ret == 0) *ctx->out_len = sizeof(kpm_map_entry_t);
        } else {
            ret = kpm_proc_query_region(target_pid, addr,
                        (kpm_map_entry_t *)ctx->user_out);
        }
        break;
    }

    /* ===== 按名查询 =====
     * 名字经用户指针传（arg2/arg3），协议层 copy_from_user 读入内核缓冲；
     * 大缓冲用 vmalloc + 分页拉取（kpm_proc_entry_t=536B / kpm_map_entry_t=288B）。 */

    case KPM_CMD_PROC_PID_BY_NAME: {
        char name[256];
        kpm_proc_entry_t *entries;
        int batch = 64;
        long i;

        if (ctx->channel != KPM_CHAN_PRCTL || !ctx->arg2 || !kf_copy_from_user) {
            ret = -KPM_E_INVAL;
            break;
        }
        lib_memset(name, 0, sizeof(name));
        if (kf_copy_from_user(name, (void *)(uintptr_t)ctx->arg2,
                              sizeof(name) - 1) != 0) {
            ret = -KPM_E_FAULT;
            break;
        }
        name[sizeof(name) - 1] = '\0';
        if (!name[0]) { ret = -KPM_E_INVAL; break; }

        entries = (kpm_proc_entry_t *)kf_vmalloc(
                    (unsigned long)batch * sizeof(kpm_proc_entry_t));
        if (!entries) { ret = -KPM_E_NOMEM; break; }
        ret = -KPM_E_NOTFOUND;
        {
            int pass;
            for (pass = 0; pass < 2 && ret < 0; pass++) {
                long off2 = 0;
                for (;;) {
                    long count = kpm_proc_list_kernel(entries, batch,
                                                      (int)off2);
                    if (count <= 0) break;
                    for (i = 0; i < count; i++) {
                        const char *p = entries[i].name;
                        const char *q;
                        const char *c;
                        int found = 0;
                        if (pass == 0) {
                            /* 精确全等（自实现，零外部符号依赖） */
                            c = p; q = name;
                            while (*q && *c && *q == *c) { q++; c++; }
                            found = (*q == 0 && *c == 0) ? 1 : 0;
                        } else {
                            /* 回退：子串匹配（边界开头/空格/冒号/斜杠） */
                            while (*p && !found) {
                                c = p; q = name;
                                while (*q && *c && *q == *c) { q++; c++; }
                                if (*q == '\0' &&
                                    (p == entries[i].name || p[-1] == ' ' ||
                                     p[-1] == ':' || p[-1] == '/'))
                                    found = 1;
                                p++;
                            }
                        }
                        if (found) {
                            ret = entries[i].pid;   /* ret = pid */
                            break;
                        }
                    }
                    if (ret >= 0 || count < batch) break;
                    off2 += count;
                    if (off2 > 4096) break;   /* 进程数防御上限 */
                }
            }
        }
        kf_vfree(entries);
        break;
    }

    case KPM_CMD_PROC_MODULE_BASE:
    case KPM_CMD_PROC_MODULE_BSS: {
        pid_t target_pid = (pid_t)ctx->arg2;
        char modname[256];
        kpm_map_entry_t *maps;
        int batch = 128;
        long offset = 0;
        uint64_t base = 0, bss = 0;
        long i;
        int want_bss = (ctx->cmd == KPM_CMD_PROC_MODULE_BSS);

        if (ctx->channel != KPM_CHAN_PRCTL || !ctx->arg3 || !kf_copy_from_user) {
            ret = -KPM_E_INVAL;
            break;
        }
        lib_memset(modname, 0, sizeof(modname));
        if (kf_copy_from_user(modname, (void *)(uintptr_t)ctx->arg3,
                              sizeof(modname) - 1) != 0) {
            ret = -KPM_E_FAULT;
            break;
        }
        modname[sizeof(modname) - 1] = '\0';
        if (!modname[0]) { ret = -KPM_E_INVAL; break; }

        maps = (kpm_map_entry_t *)kf_vmalloc(
                 (unsigned long)batch * sizeof(kpm_map_entry_t));
        if (!maps) { ret = -KPM_E_NOMEM; break; }
        ret = -KPM_E_NOTFOUND;
        for (;;) {
            long count = kpm_proc_maps_kernel(target_pid, maps, batch,
                                              (int)offset, 0);
            if (count <= 0) break;
            for (i = 0; i < count; i++) {
                /* 路径后缀匹配（前一个字符为 '/' 或开头） */
                const char *path = maps[i].path;
                int plen = 0, mlen = 0;
                int j, match = 0;
                while (path[plen]) plen++;
                while (modname[mlen]) mlen++;
                if (mlen <= plen) {
                    match = 1;
                    for (j = 0; j < mlen; j++) {
                        if (path[plen - mlen + j] != modname[j]) { match = 0; break; }
                    }
                    if (match && plen > mlen && path[plen - mlen - 1] != '/')
                        match = 0;
                }
                if (!match)
                    continue;
                if (base == 0 || maps[i].start < base)
                    base = maps[i].start;
            }
            if (count < batch) break;
            offset += count;
            if (offset > 65536) break;   /* maps 数量防御上限 */
        }
        kf_vfree(maps);

        if (base != 0) {
            if (want_bss) {
                /* 内存 ELF 解析：PT_LOAD 且 p_memsz>p_filesz 段 → bss = base+p_vaddr+p_filesz */
                uint8_t eh[64];
                uint64_t phoff;
                uint16_t phentsz, phnum;
                if (kpm_mem_read_kernel(target_pid, base, eh, sizeof(eh)) >= 0 &&
                    eh[0] == 0x7f && eh[1] == 'E' && eh[2] == 'L' &&
                    eh[3] == 'F' && eh[4] == 2) {
                    phoff = *(uint64_t *)(eh + 0x20);
                    phentsz = *(uint16_t *)(eh + 0x36);
                    phnum = *(uint16_t *)(eh + 0x38);
                    if (phentsz >= 56 && phnum > 0 && phnum <= 64 &&
                        phoff <= 0x1000000ULL) {
                        bss = 0;
                        for (i = 0; i < phnum; i++) {
                            uint8_t ph[56];
                            uint32_t p_type;
                            uint64_t p_vaddr, p_filesz, p_memsz;
                            if (kpm_mem_read_kernel(target_pid,
                                    base + phoff + (uint64_t)i * phentsz,
                                    ph, 56) < 0)
                                break;
                            p_type = *(uint32_t *)(ph + 0);
                            p_vaddr = *(uint64_t *)(ph + 16);
                            p_filesz = *(uint64_t *)(ph + 32);
                            p_memsz = *(uint64_t *)(ph + 40);
                            if (p_type == 1 && p_memsz > p_filesz) {
                                bss = base + p_vaddr + p_filesz;
                                break;
                            }
                        }
                        if (bss) { ret = (long)bss; break; }
                    }
                }
                ret = -KPM_E_NOTFOUND;   /* ELF 解析失败 */
            } else {
                ret = (long)base;
            }
        }
        break;
    }

    /* ===== 触摸命令 ===== */

    case KPM_CMD_TOUCH_CREATE: {
        int priority = (int)ctx->arg2;
        int touch_major = (int)(ctx->arg4 & 0xFFFF);
        int pressure = (int)((ctx->arg4 >> 16) & 0xFFFF);
        TouchHandle h;
        if (touch_major <= 0) touch_major = 10;
        if (pressure <= 0) pressure = 30;
        h = touch_create(priority, touch_major, pressure);
        ret = (long)h;
        break;
    }

    case KPM_CMD_TOUCH_MOVE: {
        TouchHandle h = (TouchHandle)(int)ctx->arg2;
        int x = (int)(ctx->arg3 & 0xFFFFFFFF);
        int y = (int)(ctx->arg3 >> 32);
        unsigned int unit = (unsigned int)((ctx->arg4 >> 32) & KPM_TOUCH_UNIT_MASK);
        if (unit == KPM_TOUCH_UNIT_RAW)
            touch_move_raw(h, x, y);
        else
            touch_move(h, x, y);
        ret = 0;
        break;
    }

    case KPM_CMD_TOUCH_UP: {
        TouchHandle h = (TouchHandle)(int)ctx->arg2;
        touch_up(h);
        ret = 0;
        break;
    }

    case KPM_CMD_TOUCH_DESTROY: {
        TouchHandle h = (TouchHandle)(int)ctx->arg2;
        touch_destroy(h);
        ret = 0;
        break;
    }

    case KPM_CMD_TOUCH_COUNT:
        ret = (long)touch_get_active_count();
        break;

    case KPM_CMD_TOUCH_SUSPEND: {
        TouchHandle h = (TouchHandle)(int)ctx->arg2;
        touch_suspend(h);
        ret = 0;
        break;
    }

    case KPM_CMD_TOUCH_RESUME: {
        TouchHandle h = (TouchHandle)(int)ctx->arg2;
        touch_resume(h);
        ret = 0;
        break;
    }

    case KPM_CMD_TOUCH_MOVE_TO: {
        TouchHandle h = (TouchHandle)(int)ctx->arg2;
        int target_x = (int)(ctx->arg3 & 0xFFFFFFFF);
        int target_y = (int)(ctx->arg3 >> 32);
        int touch_major = (int)(ctx->arg4 & 0xFFFF);
        int pressure = (int)((ctx->arg4 >> 16) & 0xFFFF);
        int duration_ms = (int)(ctx->arg5 & 0xFFFFFFFF);
        int allow_interrupt = (int)(ctx->arg5 >> 32);
        unsigned int unit = (unsigned int)((ctx->arg4 >> 32) & KPM_TOUCH_UNIT_MASK);
        if (touch_major <= 0) touch_major = 10;
        /* 时长夹紧：动画在本回调内忙等，duration
         * 无界会让单条命令占用数分钟；卸载排空窗口内仍在取指 → UAF。
         * 上限 5s + 单步 ≤50ms（touch_manager 侧夹紧）。 */
        if (duration_ms < 0) duration_ms = 0;
        if (duration_ms > KPM_TOUCH_ANIM_MAX_MS)
            duration_ms = KPM_TOUCH_ANIM_MAX_MS;
        if (unit == KPM_TOUCH_UNIT_RAW)
            ret = touch_move_to_raw(h, target_x, target_y,
                                    touch_major, pressure,
                                    duration_ms, allow_interrupt);
        else
            ret = touch_move_to(h, target_x, target_y,
                                touch_major, pressure,
                                duration_ms, allow_interrupt);
        break;
    }

    case KPM_CMD_TOUCH_MOVE_DIR: {
        TouchHandle h = (TouchHandle)(int)ctx->arg2;
        int dx = (int)(int32_t)(ctx->arg3 & 0xFFFFFFFF);
        int dy = (int)(int32_t)(ctx->arg3 >> 32);
        int touch_major = (int)(ctx->arg4 & 0xFFFF);
        int pressure = (int)((ctx->arg4 >> 16) & 0xFFFF);
        int duration_ms = (int)(ctx->arg5 & 0xFFFFFFFF);
        int allow_interrupt = (int)(ctx->arg5 >> 32);
        unsigned int unit = (unsigned int)((ctx->arg4 >> 32) & KPM_TOUCH_UNIT_MASK);
        if (touch_major <= 0) touch_major = 10;
        /* 时长夹紧（同 TOUCH_MOVE_TO，见该处注释） */
        if (duration_ms < 0) duration_ms = 0;
        if (duration_ms > KPM_TOUCH_ANIM_MAX_MS)
            duration_ms = KPM_TOUCH_ANIM_MAX_MS;
        if (unit == KPM_TOUCH_UNIT_RAW)
            ret = touch_move_dir_raw(h, dx, dy,
                                     touch_major, pressure,
                                     duration_ms, allow_interrupt);
        else
            ret = touch_move_dir(h, dx, dy,
                                 touch_major, pressure,
                                 duration_ms, allow_interrupt);
        break;
    }

    case KPM_CMD_TOUCH_GET: {
        TouchHandle h = (TouchHandle)(int)ctx->arg2;
        kpm_touch_info_t info;
        ret = touch_get_info(h, &info);
        if (ret == 0)
            ret = kpm_cmd_out_write(ctx, &info, sizeof(info));
        break;
    }

    case KPM_CMD_TOUCH_GET_ALL: {
        int max_count = (int)ctx->arg3;
        kpm_touch_info_t buf[KPM_MAX_TOUCH_POINTS];
        long count;
        if (max_count > KPM_MAX_TOUCH_POINTS) max_count = KPM_MAX_TOUCH_POINTS;
        if (max_count <= 0) { ret = -KPM_E_INVAL; break; }
        count = touch_get_all_info(buf, max_count);
        if (count > 0) {
            unsigned long nbytes = (unsigned long)count * sizeof(kpm_touch_info_t);
            if (ctx->channel == KPM_CHAN_UDP && nbytes > ctx->out_cap) {
                count = ctx->out_cap / sizeof(kpm_touch_info_t);
                nbytes = (unsigned long)count * sizeof(kpm_touch_info_t);
            }
            ret = kpm_cmd_out_write(ctx, buf, (uint32_t)nbytes);
            /* out_write 成功返回 0，TOUCH_GET_ALL 的 ret 语义是 count（与 PROC_LIST/FREEZE_LIST 等列表命令一致）。 */
            if (ret == 0)
                ret = count;
        } else {
            ret = count;
        }
        break;
    }

    case KPM_CMD_TOUCH_TAKEOVER: {
        TouchHandle h = (TouchHandle)(int)ctx->arg2;
        int real_tracking_id = (int)ctx->arg3;
        ret = touch_takeover(h, real_tracking_id);
        break;
    }

    case KPM_CMD_TOUCH_POLICY: {
        touch_set_policy((int)ctx->arg2);
        ret = 0;
        break;
    }

    case KPM_CMD_TOUCH_SET_PARAMS: {
        TouchHandle h = (TouchHandle)(int)ctx->arg2;
        int touch_major = (int)(ctx->arg3 & 0xFFFF);
        int pressure = (int)((ctx->arg3 >> 16) & 0xFFFF);
        int mask = (int)((ctx->arg3 >> 32) & 0xFF);
        ret = touch_set_params(h, touch_major, pressure, mask);
        break;
    }

    case KPM_CMD_TOUCH_KEEPALIVE: {
        /* 触摸心跳：刷新保活时间戳（dispatch 入口已先清超时残留） */
        touch_keepalive();
        ret = 0;
        break;
    }

    /* ===== 拦截命令 ===== */

    case KPM_CMD_INTERCEPT_ON: {
        int mode = (int)(ctx->arg2 & 0xFF);
        int scale = (int)((ctx->arg2 >> 8) & 0xFF);
        int max_off = (int)((ctx->arg2 >> 16) & 0xFFFF);
        int target_slot = (int)((ctx->arg4 >> 16) & 0xFF);
        if (max_off > 32767) max_off -= 65536;
        switch (mode) {
        case 1:
            ret = kpm_intercept_start_redirect(scale, max_off, target_slot);
            break;
        case 2: {
            int ox = (int)(ctx->arg3 & 0xFFFF);
            int oy = (int)((ctx->arg3 >> 16) & 0xFFFF);
            if (ox > 32767) ox -= 65536;
            if (oy > 32767) oy -= 65536;
            ret = kpm_intercept_start_offset(ox, oy, scale, target_slot);
            break;
        }
        case 3: {
            int mx = (int)(ctx->arg3 & 0xFF);
            int my = (int)((ctx->arg3 >> 8) & 0xFF);
            ret = kpm_intercept_start_mirror(mx, my, target_slot);
            break;
        }
        case 4: {
            int px = (int)(ctx->arg3 & 0xFFFF);
            int py = (int)((ctx->arg3 >> 16) & 0xFFFF);
            if (px > 32767) px -= 65536;
            if (py > 32767) py -= 65536;
            ret = kpm_intercept_start_pin(px, py, target_slot);
            break;
        }
        case 5: {
            int px = (int)(ctx->arg3 & 0xFFFF);
            int py = (int)((ctx->arg3 >> 16) & 0xFFFF);
            if (px > 32767) px -= 65536;
            if (py > 32767) py -= 65536;
            ret = kpm_intercept_start_pin_zero(px, py, target_slot);
            break;
        }
        default:
            ret = -KPM_E_INVAL;
            break;
        }
        break;
    }

    case KPM_CMD_INTERCEPT_OFF:
        ret = kpm_intercept_stop();
        break;

    case KPM_CMD_INTERCEPT_SLOT_OFF:
        ret = kpm_intercept_slot_off((int)ctx->arg2);
        break;

    case KPM_CMD_INTERCEPT_SCALE:
        ret = kpm_intercept_set_scale((int)ctx->arg2);
        break;

    case KPM_CMD_INTERCEPT_STATE: {
        /* UDP 返回 5 个 int；prctl 返回压缩 state 值（兼容旧客户端） */
        if (ctx->channel == KPM_CHAN_UDP) {
            long state = kpm_intercept_get_state();
            int enabled = (int)(state & 0xFF);
            int mode = (int)((state >> 8) & 0xFF);
            int ox = (int)((state >> 16) & 0xFFFF);
            int oy = (int)((state >> 32) & 0xFFFF);
            int smask = 0;
            kpm_intercept_slot_state_t sbuf;
            int fields[5];
            if (kpm_intercept_get_slot_state(&sbuf) == 0)
                smask = (int)sbuf.slot_mask;
            if (ox > 32767) ox -= 65536;
            if (oy > 32767) oy -= 65536;
            fields[0] = enabled;
            fields[1] = mode;
            fields[2] = smask;
            fields[3] = ox;
            fields[4] = oy;
            ret = kpm_cmd_out_write(ctx, fields, sizeof(fields));
        } else {
            ret = kpm_intercept_get_state();
        }
        break;
    }

    case KPM_CMD_INTERCEPT_SLOT_STATE: {
        kpm_intercept_slot_state_t sbuf;
        lib_memset(&sbuf, 0, sizeof(sbuf));
        ret = kpm_intercept_get_slot_state(&sbuf);
        if (ret == 0)
            ret = kpm_cmd_out_write(ctx, &sbuf, sizeof(sbuf));
        break;
    }

    /* ===== 陀螺仪/加速度传感器控制命令 ===== */

    case KPM_CMD_GYRO_LOCK: {
        int type = (int)(ctx->arg2 & 0xFF);
        int axis = (int)((ctx->arg2 >> 8) & 0xFF);
        int value = (int)(int32_t)ctx->arg3;
        ret = kpm_gyro_lock(type, axis, value);
        break;
    }

    case KPM_CMD_GYRO_UNLOCK: {
        int type = (int)(ctx->arg2 & 0xFF);
        int axis = (int)((ctx->arg2 >> 8) & 0xFF);
        ret = kpm_gyro_unlock(type, axis);
        break;
    }

    case KPM_CMD_GYRO_LOCK_LIST: {
        int max_count = (int)ctx->arg2;
        kpm_gyro_entry_t buf[KPM_GYRO_TYPE_MAX * KPM_GYRO_AXIS_MAX];
        long count;
        if (max_count <= 0) { ret = -KPM_E_INVAL; break; }
        if (max_count > KPM_GYRO_TYPE_MAX * KPM_GYRO_AXIS_MAX)
            max_count = KPM_GYRO_TYPE_MAX * KPM_GYRO_AXIS_MAX;
        count = kpm_gyro_get_locks(buf, max_count, NULL);
        if (count > 0) {
            unsigned long nbytes = (unsigned long)count * sizeof(kpm_gyro_entry_t);
            if (ctx->channel == KPM_CHAN_UDP && nbytes > ctx->out_cap)
                count = ctx->out_cap / sizeof(kpm_gyro_entry_t);
            ret = kpm_cmd_out_write(ctx, buf, (uint32_t)((unsigned long)count *
                                  sizeof(kpm_gyro_entry_t)));
            if (ret == 0)
                ret = count;
        } else {
            ret = count;   /* 0 或负错误码 */
        }
        break;
    }

    case KPM_CMD_GYRO_CONTROL: {
        int type = (int)(ctx->arg2 & 0xFF);
        int axis = (int)((ctx->arg2 >> 8) & 0xFF);
        int speed = (int)(int32_t)ctx->arg3;
        int offset = (int)(int32_t)ctx->arg4;
        int mode = (int)(int32_t)ctx->arg5;   /* 0=RAMP 力, 1=DIRECT 直接偏移 */
        ret = kpm_gyro_control(type, axis, speed, offset, mode);
        break;
    }

    case KPM_CMD_GYRO_CONTROL_STOP: {
        int type = (int)(ctx->arg2 & 0xFF);
        int axis = (int)((ctx->arg2 >> 8) & 0xFF);
        ret = kpm_gyro_control_stop(type, axis);
        break;
    }

    case KPM_CMD_GYRO_STATE: {
        /* UDP 输出 [ready]；prctl 返回 ready */
        if (ctx->channel == KPM_CHAN_UDP) {
            int fields[1];
            fields[0] = kpm_gyro_ready();
            ret = kpm_cmd_out_write(ctx, fields, sizeof(fields));
        } else {
            ret = (long)kpm_gyro_ready();
        }
        break;
    }

    case KPM_CMD_GYRO_KEEPALIVE: {
        /* 客户端心跳：刷新保活时间戳（dispatch 入口已统一刷新，此处兜底） */
        ret = kpm_gyro_keepalive();
        break;
    }

    /* ===== 内存扫描 ===== */

    case KPM_CMD_MEM_SCAN_START: {
        pid_t pid = (pid_t)ctx->arg2;
        int type = (int)(ctx->arg3 & 0xFF);
        int mode = (int)((ctx->arg3 >> 8) & 0xFF);
        uint64_t value = ctx->arg4;
        int value_len = (int)(ctx->arg5 & 0xFFFF);
        uint64_t range = (ctx->arg5 >> 32) & 0xFFFFFFFFULL;
        ret = kpm_mem_scan_start(pid, type, mode, value, value_len, range);
        break;
    }

    case KPM_CMD_MEM_SCAN_NEXT: {
        int type = (int)(ctx->arg2 & 0xFF);
        int mode = (int)((ctx->arg2 >> 8) & 0xFF);
        uint64_t value = ctx->arg3;
        int value_len = (int)(ctx->arg5 & 0xFFFF);
        uint64_t range = (ctx->arg5 >> 32) & 0xFFFFFFFFULL;
        ret = kpm_mem_scan_next(type, mode, value, value_len, range);
        break;
    }

    case KPM_CMD_MEM_SCAN_RESULT: {
        int max_count = (int)ctx->arg2;
        int offset = (int)ctx->arg3;
        int entry_size = sizeof(kpm_scan_result_t);
        if (max_count <= 0) max_count = 32;
        if (ctx->channel == KPM_CHAN_UDP) {
            if ((uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
                max_count = ctx->out_cap / entry_size;
            ret = kpm_mem_scan_copy_results_kernel(
                    (kpm_scan_result_t *)ctx->out_buf, max_count, offset);
            if (ret > 0) *ctx->out_len = (unsigned long)ret * entry_size;
        } else {
            ret = kpm_mem_scan_copy_results(
                    (kpm_scan_result_t *)ctx->user_out, max_count, offset);
        }
        break;
    }

    case KPM_CMD_MEM_SCAN_CLEAR:
        ret = kpm_mem_scan_clear();
        break;

    /* ===== 内存冻结 ===== */

    case KPM_CMD_FREEZE_ADD: {
        ret = kpm_mem_freeze_add((pid_t)ctx->arg2, ctx->arg3, ctx->arg4,
                                 (int)ctx->arg5);
        break;
    }

    case KPM_CMD_FREEZE_REMOVE:
        ret = kpm_mem_freeze_remove((int)ctx->arg2);
        break;

    case KPM_CMD_FREEZE_LIST: {
        int max_count = (int)ctx->arg2;
        int entry_size = sizeof(kpm_freeze_entry_t);
        if (max_count <= 0) max_count = 32;
        if (ctx->channel == KPM_CHAN_UDP) {
            if ((uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
                max_count = ctx->out_cap / entry_size;
            ret = kpm_mem_freeze_copy_list_kernel(
                    (kpm_freeze_entry_t *)ctx->out_buf, max_count);
            if (ret > 0) *ctx->out_len = (unsigned long)ret * entry_size;
        } else {
            ret = kpm_mem_freeze_copy_list(
                    (kpm_freeze_entry_t *)ctx->user_out, max_count);
        }
        break;
    }

    case KPM_CMD_FREEZE_TOGGLE:
        ret = kpm_mem_freeze_toggle((int)ctx->arg2, (int)ctx->arg3);
        break;

    case KPM_CMD_FREEZE_CLEAR:
        ret = kpm_mem_freeze_clear();
        break;

    /* ===== 指针扫描 ===== */

    case KPM_CMD_PTR_SCAN:
        ret = kpm_ptr_scan_start((pid_t)ctx->arg2, ctx->arg3, ctx->arg4);
        break;

    case KPM_CMD_PTR_SCAN_CHAIN:
        ret = kpm_ptr_scan_chain((pid_t)ctx->arg2, ctx->arg3, (int)ctx->arg4);
        break;

    case KPM_CMD_PTR_RESULT: {
        int max_count = (int)ctx->arg2;
        int offset = (int)ctx->arg3;
        int entry_size = sizeof(kpm_ptr_result_t);
        if (max_count <= 0) max_count = 32;
        if (ctx->channel == KPM_CHAN_UDP) {
            if ((uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
                max_count = ctx->out_cap / entry_size;
            ret = kpm_ptr_scan_copy_results_kernel(
                    (kpm_ptr_result_t *)ctx->out_buf, max_count, offset);
            if (ret > 0) *ctx->out_len = (unsigned long)ret * entry_size;
        } else {
            ret = kpm_ptr_scan_copy_results(
                    (kpm_ptr_result_t *)ctx->user_out, max_count, offset);
        }
        break;
    }

    /* ===== 调试断点 ===== */

    case KPM_CMD_DEBUG_BP_SET:
        ret = kpm_debug_bp_set((pid_t)ctx->arg2, (int)ctx->arg3,
                               ctx->arg4, ctx->arg5);
        break;

    case KPM_CMD_DEBUG_BP_SET_KERNEL:
        /* 内核/宽断点，危险操作，必须 force。 */
        if (kpm_force_require(KPM_FORCE_KERNEL_BP) < 0) {
            ret = -KPM_E_PERM;
            break;
        }
        ret = kpm_debug_bp_set_kernel(ctx->arg2, (int)ctx->arg3,
                                      ctx->arg4, ctx->arg5);
        break;

    case KPM_CMD_DEBUG_BP_SET_FLAGS:
        /* 增强断点（size 低 32 位 | flags16 高 32 位）。
         * force 需求在 kpm_debug_bp_set_flags 内按 flags 校验。 */
        ret = kpm_debug_bp_set_flags((pid_t)ctx->arg2, (int)ctx->arg3,
                                     ctx->arg4, ctx->arg5);
        break;

    case KPM_CMD_DEBUG_BP_INFO: {
        kpm_bp_caps_t caps;
        ret = kpm_debug_bp_info(&caps);
        if (ret == 0)
            ret = kpm_cmd_out_write(ctx, &caps, sizeof(caps));
        break;
    }

    case KPM_CMD_STEP_TRACE:
        /* 用户单步 / step trace（arg4=count；<5.10 返回 DISABLED） */
        ret = kpm_debug_step_trace((pid_t)ctx->arg2, (pid_t)ctx->arg3,
                                   (uint32_t)ctx->arg4);
        break;

    case KPM_CMD_STEP_FETCH: {
        int max_count = (int)ctx->arg2;
        int entry_size = sizeof(kpm_trap_regs_t);
        if (max_count <= 0)
            max_count = 8;
        if (ctx->channel == KPM_CHAN_UDP) {
            if ((uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
                max_count = (int)(ctx->out_cap / (uint32_t)entry_size);
            ret = kpm_debug_step_fetch_kernel(ctx->out_buf, max_count);
            if (ret > 0)
                *ctx->out_len = (unsigned long)ret * entry_size;
        } else {
            ret = kpm_debug_step_fetch_user(ctx->user_out, max_count);
        }
        break;
    }

    case KPM_CMD_DEBUG_BP_CLEAR:
        ret = kpm_debug_bp_clear((int)ctx->arg2);
        break;

    case KPM_CMD_DEBUG_BP_LIST: {
        int max_count = (int)ctx->arg2;
        int entry_size = sizeof(kpm_breakpoint_t);
        if (max_count <= 0) max_count = KPM_DEBUG_MAX_BREAKPOINTS;
        if (ctx->channel == KPM_CHAN_UDP) {
            if ((uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
                max_count = ctx->out_cap / entry_size;
            ret = kpm_debug_bp_copy_list_kernel(ctx->out_buf, max_count);
            if (ret > 0) *ctx->out_len = (unsigned long)ret * entry_size;
        } else {
            /* prctl：arg4=buf_size（可选，0=不限）。BP_LIST 直接调
             * copy_to_user（不经 kpm_cmd_out_write），容量必须在此
             * 折算成 max_count，否则小缓冲区会被写越界。 */
            if (ctx->user_out_cap) {
                int capn = (int)(ctx->user_out_cap / (uint32_t)entry_size);
                if (capn < max_count)
                    max_count = capn;
                if (max_count <= 0) {
                    ret = -KPM_E_INVAL;
                    break;
                }
            }
            ret = kpm_debug_bp_copy_list(
                    (kpm_breakpoint_t *)ctx->user_out, max_count);
        }
        break;
    }

    case KPM_CMD_DEBUG_BP_HIT: {
        if (ctx->channel == KPM_CHAN_UDP) {
            ret = kpm_debug_bp_copy_hit_kernel(ctx->out_buf);
            if (ret == 0) *ctx->out_len = sizeof(kpm_bp_hit_t);
        } else {
            ret = kpm_debug_bp_copy_hit((kpm_bp_hit_t *)ctx->user_out);
        }
        break;
    }

    case KPM_CMD_DEBUG_BP_NOTIFY:
        /* UDP 传 client_addr；prctl 传 NULL（复用上次记录地址） */
        ret = kpm_debug_bp_notify_set((int)ctx->arg2, ctx->chan_ctx,
                                      (int)ctx->arg3);
        break;

    case KPM_CMD_DEBUG_SINGLE_STEP:
        ret = kpm_debug_single_step((pid_t)ctx->arg2, (pid_t)ctx->arg3);
        break;

    case KPM_CMD_DEBUG_CONTINUE:
        ret = kpm_debug_continue((pid_t)ctx->arg2, (pid_t)ctx->arg3);
        break;

    /* ===== 断点寄存器篡改 =====
     * regmod 窗口模式：REGMOD 预置规则 → SET_EX/MODIFY 消费。 */

    case KPM_CMD_DEBUG_BP_REGMOD:
        if (ctx->channel != KPM_CHAN_PRCTL) {
            ret = -KPM_E_INVAL;
            break;
        }
        ret = kpm_debug_bp_regmod_set(ctx->arg2, ctx->arg3,
                                      (const void *)(uintptr_t)ctx->arg4);
        break;

    case KPM_CMD_DEBUG_BP_SET_EX:
        if (ctx->channel != KPM_CHAN_PRCTL) {
            ret = -KPM_E_INVAL;
            break;
        }
        ret = kpm_debug_bp_set_ex((pid_t)ctx->arg2, (int)ctx->arg3,
                                  ctx->arg4, ctx->arg5);
        break;

    case KPM_CMD_DEBUG_BP_MODIFY:
        if (ctx->channel != KPM_CHAN_PRCTL) {
            ret = -KPM_E_INVAL;
            break;
        }
        ret = kpm_debug_bp_modify((int)ctx->arg2);
        break;

    case KPM_CMD_DEBUG_BP_HIT_COUNT: {
        uint64_t total = 0;
        ret = kpm_debug_bp_get_hit_count((int)ctx->arg2, &total, NULL);
        if (ret == 0)
            ret = (long)total;   /* 标量返回累计命中 */
        break;
    }

    /* ===== Enhanced hook ===== */

    case KPM_CMD_HOOK_INSTALL: {
        int type = (int)ctx->arg2;
        void *replace_addr = (void *)(uintptr_t)ctx->arg4;
        if (ctx->channel == KPM_CHAN_UDP) {
            /* target_name 在 payload（内核指针版） */
            ret = kpm_hook_install(type, (const char *)ctx->req_data,
                                   replace_addr);
        } else {
            ret = kpm_hook_install(type, (const char *)ctx->user_out,
                                   replace_addr);
        }
        break;
    }

    case KPM_CMD_HOOK_REMOVE:
        ret = kpm_hook_remove((int)ctx->arg2);
        break;

    case KPM_CMD_HOOK_LIST: {
        int max_count = (int)ctx->arg2;
        int entry_size = sizeof(kpm_hook_entry_t);
        if (max_count <= 0) max_count = KPM_HOOK_MAX_ENTRIES;
        if (max_count > KPM_HOOK_MAX_ENTRIES) max_count = KPM_HOOK_MAX_ENTRIES;
        if (ctx->channel == KPM_CHAN_UDP) {
            if ((uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
                max_count = ctx->out_cap / entry_size;
            ret = kpm_hook_copy_list_kernel((kpm_hook_entry_t *)ctx->out_buf,
                                            max_count);
            if (ret > 0) *ctx->out_len = (unsigned long)ret * entry_size;
        } else {
            ret = kpm_hook_copy_list((kpm_hook_entry_t *)ctx->user_out,
                                     max_count);
        }
        break;
    }

    case KPM_CMD_HOOK_TOGGLE:
        ret = kpm_hook_toggle((int)ctx->arg2, (int)ctx->arg3);
        break;

    case KPM_CMD_HOOK_PLT_SET: {
        pid_t pid = (pid_t)ctx->arg2;
        void *replace_addr = (void *)(uintptr_t)ctx->arg5;
        if (ctx->channel == KPM_CHAN_UDP) {
            /* payload = [module\0][func\0] */
            const char *payload = (const char *)ctx->req_data;
            uint32_t dlen = ctx->req_len;
            const char *mod, *fn;
            uint32_t mod_len = 0, fn_len = 0;
            if (dlen < 2 || dlen > 256) { ret = -KPM_E_INVAL; break; }
            mod = payload;
            while (mod_len < dlen - 1 && payload[mod_len] != '\0')
                mod_len++;
            if (mod_len == 0 || mod_len >= dlen - 1) {
                ret = -KPM_E_INVAL; break;
            }
            fn = payload + mod_len + 1;
            while (fn_len < dlen - mod_len - 2 && fn[fn_len] != '\0')
                fn_len++;
            if (fn_len == 0) { ret = -KPM_E_INVAL; break; }
            ret = kpm_hook_plt_set_kernel(pid, mod, fn, replace_addr);
        } else {
            ret = kpm_hook_plt_set(pid, (const char *)ctx->arg3,
                                   (const char *)ctx->arg4, replace_addr);
        }
        break;
    }

    /* ===== 进程隐藏 / 反检测 =====
     * HIDE_PROCESS:    arg2=pid → ret=隐藏槽位(1..KPM_HIDE_MAX)
     * RECOVER_PROCESS: arg2=pid(0=全部) → ret=恢复条数
     * UN_HOOK:         arg2=掩码(0=全部) → ret=下线 hook 类数
     * HIDE_LIST:       arg2=max_count, 输出 kpm_hide_entry_t[]（80B×N） */
    case KPM_CMD_HIDE_PROCESS:
        ret = kpm_hide_process((pid_t)ctx->arg2);
        break;

    case KPM_CMD_RECOVER_PROCESS:
        ret = kpm_hide_recover((pid_t)ctx->arg2);
        break;

    case KPM_CMD_UN_HOOK:
        ret = kpm_hide_unhook(ctx->arg2,
                              (ctx->channel == KPM_CHAN_PRCTL) ? 1 : 0);
        break;

    case KPM_CMD_HIDE_P1:
        /* P1 兜底开关：arg2=1 启用 / 0 关闭（默认）/ <0 查询 → ret=当前开关 */
        ret = kpm_hide_p1_set((int)ctx->arg2);
        break;

    case KPM_CMD_HIDE_LIST: {
        int max_count = (int)ctx->arg2;
        int entry_size = sizeof(kpm_hide_entry_t);
        kpm_hide_entry_t arr[KPM_HIDE_MAX];
        long n;
        if (max_count <= 0) max_count = KPM_HIDE_MAX;
        if (max_count > KPM_HIDE_MAX) max_count = KPM_HIDE_MAX;
        if (ctx->channel == KPM_CHAN_UDP &&
            (uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
            max_count = (int)(ctx->out_cap / (uint32_t)entry_size);
        n = kpm_hide_list(arr, max_count);
        if (n > 0) {
            ret = kpm_cmd_out_write(ctx, arr,
                        (uint32_t)((unsigned long)n * (unsigned long)entry_size));
            if (ret == 0)
                ret = n;      /* ret = 条数（与其他列表命令一致） */
        } else {
            ret = n;
        }
        break;
    }

    /* ===== 功能单元开关 =====
     * FEAT_LIST:    arg2=max_count → kpm_feat_entry_t[]（32B×N，ret=条数）
     * FEAT_ENABLE:  arg2=单元id → ret=最终状态（OK/DEGRADED）或负错误码
     * FEAT_DISABLE: arg2=单元id → ret=0；核心通道 -KPM_E_PERM、
     *               被依赖 -KPM_E_BUSY、进行中 -KPM_E_BUSY
     * FEAT_STATE:   arg2=单元id → ret=KPM_FEATST_* */
    case KPM_CMD_FEAT_LIST: {
        int max_count = (int)ctx->arg2;
        kpm_feat_entry_t arr[KPM_FEAT_MAX];
        long n;
        if (max_count <= 0) max_count = KPM_FEAT_MAX;
        if (max_count > KPM_FEAT_MAX) max_count = KPM_FEAT_MAX;
        n = kpm_feat_list_fill(arr, max_count);
        if (n > 0) {
            ret = kpm_cmd_out_write(ctx, arr,
                        (uint32_t)((unsigned long)n * sizeof(kpm_feat_entry_t)));
            if (ret == 0)
                ret = n;      /* ret = 条数（与其他列表命令一致） */
        } else {
            ret = n;
        }
        break;
    }

    case KPM_CMD_FEAT_ENABLE:
        ret = kpm_feat_enable((uint32_t)ctx->arg2);
        break;

    case KPM_CMD_FEAT_DISABLE:
        ret = kpm_feat_disable((uint32_t)ctx->arg2);
        break;

    case KPM_CMD_FEAT_STATE:
        ret = kpm_feat_state((uint32_t)ctx->arg2);
        break;

    /* ===== 同步断点 =====
     * 命中停靠 → GET_CONTEXT → SET_CONTEXT → RESUME 读-改-写闭环。
     * 通知数据报 'KBPT'（48B）携带 trap_id；'KBPN'（32B）为 async 旧格式。 */

    case KPM_CMD_TRAP_GET: {
        if (ctx->channel == KPM_CHAN_UDP) {
            ret = kpm_sync_trap_get_kernel(ctx->out_buf, (int)ctx->arg2);
            if (ret == 0) *ctx->out_len = (unsigned long)sizeof(kpm_trap_regs_t);
        } else {
            ret = kpm_sync_trap_get((int)ctx->arg2, ctx->user_out);
        }
        break;
    }

    case KPM_CMD_TRAP_SET:
        if (ctx->channel == KPM_CHAN_UDP) {
            if (ctx->req_len < sizeof(kpm_trap_regs_t)) {
                ret = -KPM_E_INVAL;
                break;
            }
            ret = kpm_sync_trap_set_kernel((int)ctx->arg2, ctx->arg3,
                                           ctx->req_data);
        } else {
            /* prctl 布局：arg2=trap_id, arg3=reg_mask, arg4=user_buf(272B) */
            ret = kpm_sync_trap_set((int)ctx->arg2, ctx->arg3,
                                    (const void *)(uintptr_t)ctx->arg4);
        }
        break;

    case KPM_CMD_TRAP_RESUME:
        /* arg2=trap_id（0xFFFFFFFF=放行全部）；arg3=flags（bit0=EXEC_INST：
         * 放行时单步执行命中指令，Frida 语义；默认 0=PC+4 跳过） */
        ret = kpm_sync_trap_resume((uint32_t)ctx->arg2 == 0xFFFFFFFFu
                                       ? (int)0xFFFFFFFF
                                       : (int)ctx->arg2,
                                   ctx->arg3);
        break;

    case KPM_CMD_TRAP_LIST: {
        int max_count = (int)ctx->arg2;
        int entry_size = sizeof(kpm_trap_info_t);
        if (max_count <= 0) max_count = KPM_SYNC_TRAP_MAX;
        if (max_count > KPM_SYNC_TRAP_MAX) max_count = KPM_SYNC_TRAP_MAX;
        if (ctx->channel == KPM_CHAN_UDP) {
            if ((uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
                max_count = (int)(ctx->out_cap / (uint32_t)entry_size);
            ret = kpm_sync_trap_list_kernel(ctx->out_buf, max_count);
            if (ret > 0) *ctx->out_len = (unsigned long)ret * entry_size;
        } else {
            ret = kpm_sync_trap_list((kpm_trap_info_t *)ctx->user_out,
                                     max_count);
        }
        break;
    }

    case KPM_CMD_DEBUG_BP_SET_SYNC:
        /* arg2=pid, arg3=type, arg4=addr,
         * arg5=size(低32)|timeout_ms<<32（0=默认2s，0xFFFFFFFF=无限） */
        ret = kpm_debug_bp_set_sync((pid_t)ctx->arg2, (int)ctx->arg3,
                                    ctx->arg4,
                                    ctx->arg5 & 0xFFFFFFFFULL,
                                    (uint32_t)(ctx->arg5 >> 32));
        break;

    /* ===== 进程挂起/恢复 =====
     * 模式与风险注释见 LH_suspend.h / LH_comm.h。 */

    case KPM_CMD_SUSPEND_PROC:
        /* arg2=tgid, arg3=mode, arg4=timeout_ms(0=无限) → ret=记录id */
        ret = kpm_suspend_proc((pid_t)ctx->arg2, (int)ctx->arg3,
                               (uint32_t)ctx->arg4);
        break;

    case KPM_CMD_RESUME_PROC:
        ret = kpm_suspend_resume((pid_t)ctx->arg2);
        break;

    case KPM_CMD_SUSPEND_LIST: {
        int max_count = (int)ctx->arg2;
        int entry_size = sizeof(kpm_suspend_entry_t);
        if (max_count <= 0) max_count = KPM_SUSPEND_MAX;
        if (max_count > KPM_SUSPEND_MAX) max_count = KPM_SUSPEND_MAX;
        if (ctx->channel == KPM_CHAN_UDP) {
            if ((uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
                max_count = (int)(ctx->out_cap / (uint32_t)entry_size);
            ret = kpm_suspend_list_kernel(ctx->out_buf, max_count);
            if (ret > 0) *ctx->out_len = (unsigned long)ret * entry_size;
        } else {
            ret = kpm_suspend_list(ctx->user_out, max_count);
        }
        break;
    }

    /* ===== 进程禁止联网 ===== */

    case KPM_CMD_NETCTL_RULE:
        /* arg2=op, arg3=type, arg4=value → ret=0 */
        ret = kpm_netctl_rule((int)ctx->arg2, (int)ctx->arg3, ctx->arg4);
        break;

    case KPM_CMD_NETCTL_SET:
        ret = kpm_netctl_set((int)ctx->arg2, (int)ctx->arg3);
        break;

    case KPM_CMD_NETCTL_LIST: {
        kpm_netctl_info_t info;
        long n = kpm_netctl_list_kernel(&info, 0);
        if (n == 0) {
            ret = kpm_cmd_out_write(ctx, &info, sizeof(info));
            if (ret == 0)
                ret = 0;
        } else {
            ret = n;
        }
        break;
    }

    /* ===== 共享过滤器规则 ===== */

    case KPM_CMD_FILTER_RULE:
        ret = kpm_filter_rule((int)ctx->arg2, (int)ctx->arg3, ctx->arg4);
        break;

    /* ===== syscall/ioctl 监控与劫持 ===== */

    case KPM_CMD_SYSMON_SET:
        ret = kpm_sysmon_set((int)ctx->arg2, ctx->arg3);
        break;

    case KPM_CMD_SYSMON_RULE:
        ret = kpm_sysmon_rule((int)ctx->arg2, ctx->arg3, ctx->arg4, ctx->arg5);
        break;

    case KPM_CMD_SYSMON_FETCH: {
        uint64_t dropped = 0;
        int max_count = (int)ctx->arg2;
        if (max_count <= 0) max_count = 16;
        if (ctx->channel == KPM_CHAN_UDP) {
            ret = kpm_sysmon_fetch_kernel(ctx->out_buf, max_count, &dropped);
            if (ret > 0)
                *ctx->out_len = (unsigned long)ret * sizeof(kpm_sysmon_event_t);
        } else {
            ret = kpm_sysmon_fetch((void *)(uintptr_t)ctx->arg3,
                                   max_count, &dropped);
        }
        if (ret >= 0 && ctx->arg4) {
            /* dropped 回传：UDP 通道下次响应头部无位置，仅 prctl 支持 */
            if (ctx->channel == KPM_CHAN_PRCTL && kf_copy_to_user)
                kf_copy_to_user((void *)(uintptr_t)ctx->arg4, &dropped,
                                sizeof(dropped));
        }
        break;
    }

    case KPM_CMD_SYSMON_RULES: {
        int max_count = (int)ctx->arg2;
        if (max_count <= 0) max_count = KPM_SYSMON_RULE_MAX;
        if (max_count > KPM_SYSMON_RULE_MAX) max_count = KPM_SYSMON_RULE_MAX;
        if (ctx->channel == KPM_CHAN_UDP) {
            if ((uint64_t)max_count * sizeof(kpm_sysmon_rule_t) > ctx->out_cap)
                max_count = (int)(ctx->out_cap / sizeof(kpm_sysmon_rule_t));
            ret = kpm_sysmon_rules_list_kernel(ctx->out_buf, max_count);
            if (ret > 0)
                *ctx->out_len = (unsigned long)ret * sizeof(kpm_sysmon_rule_t);
        } else {
            ret = kpm_sysmon_rules_list((void *)(uintptr_t)ctx->arg3,
                                        max_count);
        }
        break;
    }

    /* ===== CPU 亲和性/频率控制 ===== */

    case KPM_CMD_RESCTL_AFFINITY:
        ret = kpm_resctl_affinity((pid_t)ctx->arg2, ctx->arg3);
        break;

    case KPM_CMD_RESCTL_FREQ:
        ret = kpm_resctl_freq((pid_t)ctx->arg2, ctx->arg3);
        break;

    case KPM_CMD_RESCTL_GLOBAL:
        ret = kpm_resctl_global(ctx->arg2, ctx->arg3);
        break;

    case KPM_CMD_RESCTL_CAPS:
        ret = kpm_resctl_caps();
        break;

    /* ===== hook 引擎双模式 ===== */

    case KPM_CMD_HOOK2_SET_STEALTH: {
        /* arg2=pid, arg3=func_addr, arg4=packed, arg5=aux → ret=id */
        ret = kpm_hook2_set_stealth((pid_t)ctx->arg2, ctx->arg3,
                                    ctx->arg4, ctx->arg5);
        break;
    }

    case KPM_CMD_HOOK2_SET_KFUNC:
        ret = kpm_hook2_set_kfunc(ctx->arg2, ctx->arg3, ctx->arg4);
        break;

    case KPM_CMD_HOOK2_ARGS:
        if (ctx->channel == KPM_CHAN_UDP) {
            if (ctx->req_len < 64) {
                ret = -KPM_E_INVAL;
                break;
            }
            ret = kpm_hook2_args_window_kernel(ctx->req_data);
        } else {
            ret = kpm_hook2_args_window((const void *)(uintptr_t)ctx->arg2);
        }
        break;

    case KPM_CMD_HOOK2_DEL:
        ret = kpm_hook2_del((int)ctx->arg2);
        break;

    case KPM_CMD_HOOK2_LIST: {
        int max_count = (int)ctx->arg2;
        int entry_size = sizeof(kpm_hook2_entry_t);
        if (max_count <= 0) max_count = 16;
        if (max_count > 16) max_count = 16;
        if (ctx->channel == KPM_CHAN_UDP) {
            if ((uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
                max_count = (int)(ctx->out_cap / (uint32_t)entry_size);
            ret = kpm_hook2_list_kernel(ctx->out_buf, max_count);
            if (ret > 0) *ctx->out_len = (unsigned long)ret * entry_size;
        } else {
            ret = kpm_hook2_list(ctx->user_out, max_count);
        }
        break;
    }

    /* ===== force / trace / memwatch ===== */

    case KPM_CMD_FORCE: {
        kpm_force_info_t fi;
        long fr = kpm_force_control((int)ctx->arg2, (uint32_t)ctx->arg3,
                                    (uint32_t)ctx->arg4, (uint32_t)ctx->arg5,
                                    &fi);
        if (fr < 0) {
            ret = fr;
            break;
        }
        if ((int)ctx->arg2 == KPM_FORCE_OP_QUERY) {
            ret = kpm_cmd_out_write(ctx, &fi, sizeof(fi));
            if (ret == 0)
                ret = 0;
        } else {
            ret = fr;
        }
        break;
    }

    case KPM_CMD_TRACE_CTRL: {
        int op = (int)ctx->arg2;
        int mode = (int)ctx->arg3;
        int32_t pf = (int32_t)ctx->arg4;
        uint32_t uf = (uint32_t)ctx->arg5;
        uint64_t func = 0;
        int argno = 0;
        const void *cfg = NULL;
        uint32_t cfg_len = 0;
        if (ctx->channel == KPM_CHAN_UDP) {
            cfg = ctx->req_data;
            cfg_len = ctx->req_len;
        } else {
            func = ctx->arg4;
            argno = (int)ctx->arg5;
            pf = 0;
            uf = 0xFFFFFFFFu;
        }
        /* prctl 通道布局：arg2=op, arg3=mode, arg4=func_addr, arg5=argno；
         * syscall filter 走 UDP payload，prctl 只支持标量 kfunc。 */
        ret = kpm_trace_control(op, mode, pf, uf, func, argno,
                                cfg, cfg_len, 0);
        break;
    }

    case KPM_CMD_TRACE_FETCH: {
        int max_count = (int)ctx->arg2;
        int entry_size = sizeof(kpm_trace_event_t);
        if (max_count <= 0)
            max_count = 64;
        if (ctx->channel == KPM_CHAN_UDP) {
            /* 容量折算：防止大 max_count 写越 16KB resp_data */
            if ((uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
                max_count = (int)(ctx->out_cap / (uint32_t)entry_size);
            ret = kpm_trace_fetch_kernel(ctx->out_buf, max_count);
            if (ret > 0)
                *ctx->out_len = (unsigned long)ret * entry_size;
        } else {
            ret = kpm_trace_fetch_user(ctx->user_out, max_count);
        }
        break;
    }

    case KPM_CMD_TRACE_INFO: {
        kpm_trace_info_t ti;
        ret = kpm_trace_info(&ti);
        if (ret == 0)
            ret = kpm_cmd_out_write(ctx, &ti, sizeof(ti));
        break;
    }

    case KPM_CMD_MEMWATCH_SET: {
        uint32_t mode = (uint32_t)ctx->arg4;
        uint32_t mflags = (uint32_t)(ctx->arg4 >> 32);
        if (kpm_force_active() &&
            (kpm_force_mask() & KPM_FORCE_MEMWATCH_UNSAFE))
            mflags |= KPM_MEMWATCH_FLAG_FORCE;
        ret = kpm_memwatch_set((pid_t)ctx->arg2, ctx->arg3, mode,
                               mflags, (uint32_t)ctx->arg5);
        break;
    }

    case KPM_CMD_MEMWATCH_CLEAR:
        ret = kpm_memwatch_clear((uint32_t)ctx->arg2);
        break;

    case KPM_CMD_MEMWATCH_REARM:
        ret = kpm_memwatch_rearm((uint32_t)ctx->arg2);
        break;

    case KPM_CMD_MEMWATCH_LIST: {
        int max_count = (int)ctx->arg2;
        if (max_count <= 0)
            max_count = 32;
        if (max_count > 64)
            max_count = 64;
        if (ctx->channel == KPM_CHAN_UDP) {
            ret = kpm_memwatch_list((kpm_memwatch_entry_t *)ctx->out_buf,
                                    max_count);
            if (ret > 0)
                *ctx->out_len = (unsigned long)ret * sizeof(kpm_memwatch_entry_t);
        } else {
            kpm_memwatch_entry_t arr[32];
            if (max_count > 32)
                max_count = 32;
            ret = kpm_memwatch_list(arr, max_count);
            if (ret > 0) {
                long wr = kpm_cmd_out_write(ctx, arr,
                            (uint32_t)((unsigned long)ret * sizeof(arr[0])));
                if (wr == 0)
                    ret = ret;
                else
                    ret = wr;
            }
        }
        break;
    }

    case KPM_CMD_MEMWATCH_FETCH: {
        int max_count = (int)ctx->arg2;
        int entry_size = sizeof(kpm_memwatch_event_t);
        if (max_count <= 0)
            max_count = 64;
        if (ctx->channel == KPM_CHAN_UDP) {
            if ((uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
                max_count = (int)(ctx->out_cap / (uint32_t)entry_size);
            ret = kpm_memwatch_fetch_kernel(ctx->out_buf, max_count);
            if (ret > 0)
                *ctx->out_len = (unsigned long)ret * entry_size;
        } else {
            ret = kpm_memwatch_fetch_user(ctx->user_out, max_count);
        }
        break;
    }

    /* ===== W^X shadow 无痕 hook ===== */

    case KPM_CMD_WX_SET_BP:
        ret = kpm_wx_set_bp((pid_t)ctx->arg2, ctx->arg3);
        break;

    case KPM_CMD_WX_SET_REG:
        ret = kpm_wx_set_reg((pid_t)ctx->arg2, ctx->arg3,
                             (uint32_t)ctx->arg4, ctx->arg5);
        break;

    case KPM_CMD_WX_DEL_BP:
        ret = kpm_wx_del_bp((pid_t)ctx->arg2, ctx->arg3);
        break;

    case KPM_CMD_WX_PATCH: {
        const void *pdata;
        uint32_t plen;
        if (ctx->channel == KPM_CHAN_UDP) {
            pdata = ctx->req_data;
            plen = ctx->req_len;
        } else {
            pdata = ctx->user_out;   /* prctl arg4=buf */
            plen = (uint32_t)ctx->arg5;
        }
        ret = kpm_wx_patch((pid_t)ctx->arg2, ctx->arg3, pdata, plen);
        break;
    }

    case KPM_CMD_WX_RELEASE:
        ret = kpm_wx_release((pid_t)ctx->arg2, ctx->arg3);
        break;

    case KPM_CMD_WX_LIST: {
        int max_count = (int)ctx->arg2;
        int entry_size = sizeof(kpm_wx_page_info_t);
        if (max_count <= 0)
            max_count = KPM_WX_MAX_PAGES;
        if (ctx->channel == KPM_CHAN_UDP) {
            if ((uint64_t)max_count * (uint64_t)entry_size > ctx->out_cap)
                max_count = (int)(ctx->out_cap / (uint32_t)entry_size);
            ret = kpm_wx_list((kpm_wx_page_info_t *)ctx->out_buf, max_count);
            if (ret > 0)
                *ctx->out_len = (unsigned long)ret * entry_size;
        } else {
            ret = kpm_wx_list((kpm_wx_page_info_t *)ctx->user_out, max_count);
        }
        break;
    }

    case KPM_CMD_WX_INFO: {
        kpm_wx_info_t wi;
        ret = kpm_wx_info(&wi);
        if (ret == 0)
            ret = kpm_cmd_out_write(ctx, &wi, sizeof(wi));
        break;
    }

    default:
        /* 非公共命令：由接口层处理（UDP 特有命令 / prctl 放行） */
        return KPM_CMD_UNHANDLED;
    }

    return ret;
}
