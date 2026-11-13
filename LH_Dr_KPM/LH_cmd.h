/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_cmd.h - 统一协议处理层
 *
 * 架构：
 *   执行层（kpm_mem_rw / kpm_proc / touch_manager / ...）
 *     ↓ 调用
 *   协议处理层（kpm_cmd_dispatch：命令解码 + 参数解析 + 执行调用 + 数据出口）
 *     ↓ 双接口
 *   UDP 接口（kpm_udp.c：socket 收包 → 内核缓冲回传）
 *   prctl 接口（kpm_hooks.c：syscall hook → copy_to_user 回传）
 *
 * 设计目标：
 *   - 新增功能只改协议层一处（dispatch 加一个 case），两个接口自动获得
 *   - 数据出口统一为 kpm_cmd_out_write（UDP=内核缓冲，prctl=copy_to_user）
 *   - 通道特有逻辑（UID 门控 / 来源 IP 过滤 / 流式直发）留在接口层
 */
#ifndef KPM_CMD_H
#define KPM_CMD_H

#include <ktypes.h>

/* 通道标识 */
#define KPM_CHAN_UDP   0
#define KPM_CHAN_PRCTL 1

/* 协议层未处理的命令（接口层自行处理特有命令） */
#define KPM_CMD_UNHANDLED  (-9999L)

/* ===== 统一命令上下文（通道无关） ===== */
typedef struct {
    int      channel;       /* KPM_CHAN_UDP / KPM_CHAN_PRCTL */

    /* 已解码命令码（已 XOR 还原） */
    uint32_t cmd;

    /* 统一参数（arg2-arg5，语义由各 case 定义） */
    uint64_t arg2, arg3, arg4, arg5;

    /* 请求附带数据（UDP payload；prctl 无） */
    const void *req_data;
    uint32_t    req_len;

    /* 输出目标：
     * UDP:   out_buf=内核缓冲(resp_data), out_cap=容量, out_len=实际长度
     * prctl: user_out=用户指针(copy_to_user 目标), user_out_cap=容量 */
    uint8_t  *out_buf;
    uint32_t  out_cap;
    uint32_t *out_len;
    void     *user_out;
    uint32_t  user_out_cap;

    /* 通道上下文：UDP=client_addr；prctl=NULL */
    void     *chan_ctx;
} kpm_cmd_ctx_t;

/* ===== 统一数据出口 =====
 * 将 len 字节写到目标：
 *   UDP:   memcpy 到 ctx->out_buf，*ctx->out_len = len
 *   prctl: kf_copy_to_user(ctx->user_out, data, len)
 * 返回 0 成功，负值失败 */
long kpm_cmd_out_write(kpm_cmd_ctx_t *ctx, const void *data, uint32_t len);

/* ===== 协议层统一分发入口 =====
 * 处理两通道公共命令；返回命令执行结果（ret）。
 * 未识别命令返回 KPM_CMD_UNHANDLED，由接口层处理（UDP=静默丢弃/本地特有，
 * prctl=放行原 syscall）。 */
long kpm_cmd_dispatch(kpm_cmd_ctx_t *ctx);

#endif /* KPM_CMD_H */
