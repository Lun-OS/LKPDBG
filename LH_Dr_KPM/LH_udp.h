/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_udp.h - Kernel-space UDP service for KPM hidden driver
 *
 * 替代用户态 kpmctl 守护进程，实现：
 *   - 内核态 UDP socket（端口可配置，默认 17891）
 *   - sk_data_ready 回调 + workqueue 事件驱动（零空转）
 *   - 二进制协议，XOR 命令码与 prctl 通道一致
 *   - 卸载时序：shutdown → flush_workqueue → 恢复回调 → release
 *
 * 隐蔽性：
 *   - 无用户态进程（无 /proc/pid 痕迹）
 *   - 无文件痕迹
 *   - 端口不响应未知探测（魔数静默）
 */
#ifndef KPM_UDP_H
#define KPM_UDP_H

#include <ktypes.h>
#include <linux/list.h>

/* ===== 常量定义（框架缺失 net.h/in.h/asm/socket.h，手动定义） =====
 *
 * 不直接 #include <linux/socket.h>：该头文件依赖 <asm/socket.h>、
 * <linux/sockios.h>、<linux/uio.h>、<uapi/linux/socket.h>，
 * 这些头文件在 KernelPatch KPM 构建环境中均缺失。
 * 改为自定义与 ARM64 Linux 6.1 内核 ABI 兼容的最小类型定义。
 */

#define KPM_AF_INET       2
#define KPM_SOCK_DGRAM    2
#define KPM_IPPROTO_UDP   17

#define KPM_MSG_DONTWAIT  0x40
#define KPM_MSG_WAITALL   0x100

/* workqueue flags */
#define KPM_WQ_UNBOUND    0x2
#define KPM_WQ_FREEZABLE   0x4

/* ===== 最小类型定义（与 ARM64 Linux 6.1 内核 ABI 兼容） ===== */

/* sa_family_t：与内核 __kernel_sa_family_t 一致（unsigned short，2 字节） */
typedef uint16_t kpm_sa_family_t;

/* struct sockaddr：与内核 ABI 完全一致（16 字节）
 * kernel_bind 只读取 sa_family 字段判断地址族 */
struct sockaddr {
    kpm_sa_family_t sa_family;
    char             sa_data[14];
};

/* struct msghdr：与 ARM64 Linux 6.1 内核 ABI 布局兼容
 *
 * 实际内核 struct msghdr 布局：
 *   offset 0:  void    *msg_name        (8 字节)
 *   offset 8:  int      msg_namelen     (4 字节)
 *   offset 12: int      msg_inq         (4 字节)
 *   offset 16: struct iov_iter msg_iter (~40 字节，kernel_recvmsg 会写入)
 *   offset 56: union { void *msg_control; ... }
 *   offset 64: unsigned int msg_flags
 *   offset 72: __kernel_size_t msg_controllen
 *   offset 80: struct kiocb *msg_iocb
 *   offset 88: struct ubuf_info *msg_ubuf
 *   offset 96: int (*sg_from_iter)(...)
 * 总大小约 104 字节
 *
 * 我们只使用 msg_name / msg_namelen，其余字段交给 kernel_recvmsg
 * 自己填充（iov_iter 由 kernel_recvmsg 通过 iov_iter_kvec() 构造）。
 * 保留 88 字节填充区域足够容纳 iov_iter + msg_control + msg_flags +
 * msg_controllen + msg_iocb + msg_ubuf + sg_from_iter。
 *
 * 全结构清零后只设置 msg_name/msg_namelen，kernel_recvmsg/sendmsg
 * 内部会按需读写其他字段，不会越界（96 字节足够）。 */
struct msghdr {
    void *msg_name;             /* offset 0  */
    int   msg_namelen;          /* offset 8  */
    int   msg_inq;              /* offset 12 */
    char  __reserved[88];       /* offset 16..103, 容纳 iov_iter + 后续字段 */
};  /* sizeof = 104 字节，与 ARM64 Linux 6.1 内核 msghdr 一致 */

/* sockaddr_in（框架无 in.h） */
struct kpm_sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;    /* 网络字节序 */
    uint32_t sin_addr;    /* 网络字节序 */
    uint8_t  sin_zero[8];
};

/* kvec（用于 kernel_recvmsg/kernel_sendmsg）
 * 注意：内核 struct kvec 字段名也是 iov_base/iov_len，ABI 一致 */
struct kpm_kvec {
    void *iov_base;
    size_t iov_len;
};

/* work_struct 最小定义（匹配 ARM64 内核 ABI，32 字节）
 * data: atomic_long_t，低 bit 为 pending 标志
 * entry: 链表节点
 * func: 工作函数指针 */
struct kpm_work_struct {
    uint64_t data;
    struct list_head entry;
    void (*func)(struct kpm_work_struct *work);
};

/* workqueue_struct 和 socket/sock 用不透明指针 */
struct kpm_workqueue_struct;
struct kpm_socket;
struct kpm_sock;
struct kpm_net;

/* ===== 网络函数指针（运行时通过 kallsyms 解析） ===== */

/* socket 操作 */
extern int  (*kf_sock_create_kern)(struct kpm_net *net, int family, int type,
                                   int proto, struct kpm_socket **res);
/* sock_create 4 参数回退（无 net 参数，内部用 current->nsproxy->net_ns）。
 * 当 sock_create_kern 缺失（厂商内核 static 化）时由 kpm_udp_init 分支调用。 */
extern int  (*kf_sock_create)(int family, int type, int proto,
                              struct kpm_socket **res);
extern void (*kf_sock_release)(struct kpm_socket *sock);
extern int  (*kf_kernel_bind)(struct kpm_socket *sock, struct sockaddr *addr,
                              int addrlen);
extern int  (*kf_kernel_recvmsg)(struct kpm_socket *sock, struct msghdr *msg,
                                  struct kpm_kvec *vec, unsigned int vlen,
                                  size_t min, int flags);
extern int  (*kf_kernel_sendmsg)(struct kpm_socket *sock, struct msghdr *msg,
                                 struct kpm_kvec *vec, unsigned int vlen,
                                 size_t min);
extern int  (*kf_kernel_sock_shutdown)(struct kpm_socket *sock, int how);

/* workqueue 操作 */
extern struct kpm_workqueue_struct *(*kf_alloc_workqueue)(const char *fmt,
    int flags, int max_active);
extern void (*kf_destroy_workqueue)(struct kpm_workqueue_struct *wq);
/* queue_work 是宏，展开为 queue_work_on(WORK_CPU_END, wq, work)
 * 直接解析 queue_work_on，调用时传 cpu=0 */
extern int  (*kf_queue_work)(int cpu, struct kpm_workqueue_struct *wq,
                             struct kpm_work_struct *work);
/* flush_workqueue 仅 exit 时用，可选（为 NULL 时跳过） */
extern void (*kf_flush_workqueue)(struct kpm_workqueue_struct *wq);

/* init_net（网络命名空间，sock_create_kern 第一个参数） */
extern struct kpm_net *kf_init_net;

/* ===== UDP 协议定义 ===== */

/* 单包最大有效载荷 16384 字节。IP 分片由内核协议栈自动处理
 * （UDP sendmsg 路径），接收端 ip_defrag 重组。 */
#define KPM_UDP_MAX_PAYLOAD   16384
#define KPM_UDP_DEFAULT_PORT  17891

/* 请求头（客户端 → 内核）
 *
 * arg2-arg5 为 uint64_t，与 prctl 的 unsigned long (ARM64 = 8 字节) 完全兼容。
 * 这样 64 位参数无需拆分打包：
 *   - KPM_CMD_READ_MEM: arg3 = 64 位远程地址
 *   - KPM_CMD_TOUCH_CREATE: arg3 = x | (y << 32)
 *   - KPM_CMD_PROC_QUERY_REGION: arg3 = 64 位查询地址
 */
struct kpm_udp_request {
    uint32_t cmd;         /* KPM_CMD(code) XOR 编码 */
    uint32_t seq;         /* 序列号（响应匹配用） */
    uint64_t arg2;        /* 参数 1（与 prctl arg2 对应） */
    uint64_t arg3;        /* 参数 2 */
    uint64_t arg4;        /* 参数 3 */
    uint64_t arg5;        /* 参数 4 */
    uint32_t data_len;    /* 附加数据长度（如 WRITE_MEM 的写入数据） */
    uint32_t reserved;    /* 对齐 */
    /* 后接 data_len 字节附加数据 */
};
/* 头部 48 字节 + payload ≤ 16384 字节 */

/* 响应头（内核 → 客户端） */
struct kpm_udp_response {
    uint32_t seq;         /* 匹配请求 seq */
    int32_t  ret;         /* 返回码 */
    uint32_t data_len;    /* 响应数据长度 */
    uint32_t reserved;    /* 对齐 */
    /* 后接 data_len 字节响应数据 */
};
/* 头部 16 字节 + payload ≤ 16384 字节 */

/* ===== API ===== */

/* 初始化 UDP 服务
 * port: 监听端口，0 = 使用默认端口 17891
 * 返回 0 成功，负数失败（失败时 prctl 通道仍可用） */
int kpm_udp_init(int port);

/* 退出 UDP 服务
 * 严格执行安全卸载时序：
 *   1. kernel_sock_shutdown 停止收包
 *   2. flush_workqueue 等待所有 work 完成
 *   3. 恢复原始 sk_data_ready 回调
 *   4. sock_release 释放 socket
 *   5. destroy_workqueue 释放工作队列 */
void kpm_udp_exit(void);

/* 查询 UDP 服务是否就绪 */
int kpm_udp_is_ready(void);

/* 查询当前 UDP 监听端口（未启动时返回配置的默认端口） */
int kpm_udp_get_port(void);

/* 通用通知发送（断点命中通知等独立事件用）。
 * 向指定客户端地址发送一段自定义数据（DONTWAIT + 退避，复用流式发送核心）。
 * 不附加协议头（调用方自包含格式）。返回 0 成功，负值失败。 */
int kpm_udp_notify_send(struct kpm_sockaddr_in *client,
                        const void *data, int len);

#endif /* KPM_UDP_H */
