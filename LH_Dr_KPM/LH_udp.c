/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_udp.c - Kernel-space UDP service for KPM hidden driver
 *
 * 替代用户态 kpmctl 守护进程，实现完全内核态通信：
 *   - sk_data_ready 回调 + workqueue 事件驱动（零空转）
 *   - 循环收包直到 -EAGAIN（防丢包）
 *   - 安全卸载时序：shutdown → flush → 恢复回调 → release
 *
 * 隐蔽性：
 *   - 无用户态进程（无 /proc/pid 痕迹）
 *   - 无文件痕迹
 *   - 未知探测静默丢弃（魔数静默）
 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <kputils.h>
#include <ksyms.h>
#include <linux/list.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <baselib.h>
/* 不包含 <linux/socket.h>：框架缺失 <asm/socket.h>，使用 kpm_udp.h 中的自定义类型 */

#include "LH_udp.h"
#include "LH_comm.h"
#include "LH_cmd.h"    /* 统一协议处理层 */
#include "LH_feat.h"   /* 功能单元门控 */
#include "LH_force.h"  /* force 能力掩码（STREAM_WRITE 内核写） */
#include "LH_syms.h"
#include "LH_log.h"
#include "LH_mem_rw.h"
#include "LH_proc.h"
#include "LH_touch.h"
#include "LH_intercept.h"
#include "touch_manager.h"
#include "LH_stealth.h"
#include "LH_mem_scan.h"
#include "LH_mem_freeze.h"
#include "LH_ptr_scan.h"
#include "LH_utils.h"  /* kpm_get_state */
#include "LH_state_info.h"
#include "LH_debug.h"  /* 调试断点命令 */
#include "LH_dump.h"   /* 内存 dump（ELF 重建） */
#include "LH_hook_enhanced.h"  /* PLT hook 命令 */

/* GFP_KERNEL 在 KPM 框架的 gfp.h 中被注释掉，此处手动定义（与 kpm_mem_rw.c 一致） */
#ifndef GFP_KERNEL
#define GFP_KERNEL  0xcc0u
#endif

/* ===== 全局状态 ===== */
static struct kpm_socket *g_udp_sock = 0;
static struct kpm_workqueue_struct *g_udp_wq = 0;
static struct kpm_work_struct g_recv_work;
static struct kpm_work_struct g_tvpush_work;
static volatile int g_work_active = 0;
static volatile int g_udp_ready = 0;
static int g_udp_port = KPM_UDP_DEFAULT_PORT;
/* recv_work 退出标志。KPM_EXIT 在 RCU 读临界区内调用，异常上下文不能睡眠，
 * 卸载时用本标志 + 非睡眠有界自旋等待 work 退出。 */
static volatile int g_recv_work_done = 0;

/* 触摸事件流式推送（定义在文件后部，此处前向声明供 init/命令使用） */
static void kpm_udp_tvpush_work(struct kpm_work_struct *work);
int kpm_udp_tvstream_start(struct kpm_sockaddr_in *client, int src_mask);
int kpm_udp_tvstream_ping(void);
int kpm_udp_tvstream_stop(void);
static uint64_t kpm_udp_tvtime_ns(void);

/* 收包缓冲区（work 函数中使用，process 上下文） */
static uint8_t g_recv_buf[sizeof(struct kpm_udp_request) + KPM_UDP_MAX_PAYLOAD];

/* 响应缓冲区（静态分配，避免 16KB 栈溢出）。
 * kpm_udp_handle_request 仅在单 workqueue 中串行调用，静态变量线程安全。 */
static uint8_t g_resp_buf[sizeof(struct kpm_udp_response) + KPM_UDP_MAX_PAYLOAD];

/* 流式传输数据块缓冲（静态 16KB，逐块复用）。
 * 流式命令（STREAM_BEGIN/DUMP_STREAM）在单 workqueue 串行上下文中执行，
 * 静态缓冲安全；数据报头（20B）在栈上构建，经双 kvec 发送，不拷贝数据。 */
static uint8_t g_stream_buf[KPM_STREAM_CHUNK];

/* ===== 流式传输 =====
 *
 * 设计：
 *   - 单次请求 → 内核连续发送 N 个 ≤16KB 数据报（零往返等待）
 *   - 每块带 CRC32 + offset + session（=请求 seq），客户端重组校验
 *   - 非阻塞发送（msg_flags=DONTWAIT）+ 2-4ms 退避重试 + 30s 总预算，
 *     客户端消失时不会永久挂死 UDP 服务；g_udp_ready=0 时立即中止（卸载安全）
 *   - 无动态分配（g_stream_buf 静态 + 栈头），无内存泄漏
 */

/* errno 常量（KPM 框架无 errno.h） */
#define KPM_EAGAIN    (-11)
#define KPM_ENOBUFS   (-105)

/* 前向声明（辅助函数定义在本文件后方） */
static void kpm_udp_memset(void *dst, int c, unsigned long n);
static void kpm_udp_memcpy(void *dst, const void *src, unsigned long n);

/* msghdr 中 msg_flags 偏移（见 kpm_udp.h 注释）：
 *   msg_name(0) + msg_namelen(8) + msg_inq(12,5.15+) + msg_iter(16,32B)
 *   + msg_control(48,8B) + msg_controllen(56,8B) → msg_flags 在 offset 64。
 * 4.19 iov_iter = {int type; size_t count; union{ptr}; union{nr_segs}} = 32B；
 * 5.15+ 增加的 msg_inq(4B) 恰好填充 namelen 后的 padding、iov_iter 仍 32B，
 * 两代布局 msg_flags 均在 offset 64，本偏移在 4.14~6.x 通用。
 * iov_iter 由 kernel_sendmsg 内部构造（调用方仅填 msg_name/namelen，
 * 无内部布局依赖）；kernel_sendmsg 为 net/socket.c 非 static
 * EXPORT_SYMBOL（4.14+ 签名稳定），kallsyms 可解析。
 * 自定义 struct msghdr 的 __reserved[88] 覆盖 offset 16..104，安全写入。 */
#define KPM_STREAM_SEND_BACKOFF_US_MIN  2000
#define KPM_STREAM_SEND_BACKOFF_US_MAX  4000
#define KPM_STREAM_SEND_MAX_RETRIES     10000

/* CRC32（表驱动，多项式 0xEDB88320，与 kpm_dump.c kd_crc32 一致） */
static const uint32_t kpm_udp_crc32_table[256] = {
    0x00000000U, 0x77073096U, 0xee0e612cU, 0x990951baU, 0x076dc419U, 0x706af48fU, 0xe963a535U, 0x9e6495a3U,
    0x0edb8832U, 0x79dcb8a4U, 0xe0d5e91eU, 0x97d2d988U, 0x09b64c2bU, 0x7eb17cbdU, 0xe7b82d07U, 0x90bf1d91U,
    0x1db71064U, 0x6ab020f2U, 0xf3b97148U, 0x84be41deU, 0x1adad47dU, 0x6ddde4ebU, 0xf4d4b551U, 0x83d385c7U,
    0x136c9856U, 0x646ba8c0U, 0xfd62f97aU, 0x8a65c9ecU, 0x14015c4fU, 0x63066cd9U, 0xfa0f3d63U, 0x8d080df5U,
    0x3b6e20c8U, 0x4c69105eU, 0xd56041e4U, 0xa2677172U, 0x3c03e4d1U, 0x4b04d447U, 0xd20d85fdU, 0xa50ab56bU,
    0x35b5a8faU, 0x42b2986cU, 0xdbbbc9d6U, 0xacbcf940U, 0x32d86ce3U, 0x45df5c75U, 0xdcd60dcfU, 0xabd13d59U,
    0x26d930acU, 0x51de003aU, 0xc8d75180U, 0xbfd06116U, 0x21b4f4b5U, 0x56b3c423U, 0xcfba9599U, 0xb8bda50fU,
    0x2802b89eU, 0x5f058808U, 0xc60cd9b2U, 0xb10be924U, 0x2f6f7c87U, 0x58684c11U, 0xc1611dabU, 0xb6662d3dU,
    0x76dc4190U, 0x01db7106U, 0x98d220bcU, 0xefd5102aU, 0x71b18589U, 0x06b6b51fU, 0x9fbfe4a5U, 0xe8b8d433U,
    0x7807c9a2U, 0x0f00f934U, 0x9609a88eU, 0xe10e9818U, 0x7f6a0dbbU, 0x086d3d2dU, 0x91646c97U, 0xe6635c01U,
    0x6b6b51f4U, 0x1c6c6162U, 0x856530d8U, 0xf262004eU, 0x6c0695edU, 0x1b01a57bU, 0x8208f4c1U, 0xf50fc457U,
    0x65b0d9c6U, 0x12b7e950U, 0x8bbeb8eaU, 0xfcb9887cU, 0x62dd1ddfU, 0x15da2d49U, 0x8cd37cf3U, 0xfbd44c65U,
    0x4db26158U, 0x3ab551ceU, 0xa3bc0074U, 0xd4bb30e2U, 0x4adfa541U, 0x3dd895d7U, 0xa4d1c46dU, 0xd3d6f4fbU,
    0x4369e96aU, 0x346ed9fcU, 0xad678846U, 0xda60b8d0U, 0x44042d73U, 0x33031de5U, 0xaa0a4c5fU, 0xdd0d7cc9U,
    0x5005713cU, 0x270241aaU, 0xbe0b1010U, 0xc90c2086U, 0x5768b525U, 0x206f85b3U, 0xb966d409U, 0xce61e49fU,
    0x5edef90eU, 0x29d9c998U, 0xb0d09822U, 0xc7d7a8b4U, 0x59b33d17U, 0x2eb40d81U, 0xb7bd5c3bU, 0xc0ba6cadU,
    0xedb88320U, 0x9abfb3b6U, 0x03b6e20cU, 0x74b1d29aU, 0xead54739U, 0x9dd277afU, 0x04db2615U, 0x73dc1683U,
    0xe3630b12U, 0x94643b84U, 0x0d6d6a3eU, 0x7a6a5aa8U, 0xe40ecf0bU, 0x9309ff9dU, 0x0a00ae27U, 0x7d079eb1U,
    0xf00f9344U, 0x8708a3d2U, 0x1e01f268U, 0x6906c2feU, 0xf762575dU, 0x806567cbU, 0x196c3671U, 0x6e6b06e7U,
    0xfed41b76U, 0x89d32be0U, 0x10da7a5aU, 0x67dd4accU, 0xf9b9df6fU, 0x8ebeeff9U, 0x17b7be43U, 0x60b08ed5U,
    0xd6d6a3e8U, 0xa1d1937eU, 0x38d8c2c4U, 0x4fdff252U, 0xd1bb67f1U, 0xa6bc5767U, 0x3fb506ddU, 0x48b2364bU,
    0xd80d2bdaU, 0xaf0a1b4cU, 0x36034af6U, 0x41047a60U, 0xdf60efc3U, 0xa867df55U, 0x316e8eefU, 0x4669be79U,
    0xcb61b38cU, 0xbc66831aU, 0x256fd2a0U, 0x5268e236U, 0xcc0c7795U, 0xbb0b4703U, 0x220216b9U, 0x5505262fU,
    0xc5ba3bbeU, 0xb2bd0b28U, 0x2bb45a92U, 0x5cb36a04U, 0xc2d7ffa7U, 0xb5d0cf31U, 0x2cd99e8bU, 0x5bdeae1dU,
    0x9b64c2b0U, 0xec63f226U, 0x756aa39cU, 0x026d930aU, 0x9c0906a9U, 0xeb0e363fU, 0x72076785U, 0x05005713U,
    0x95bf4a82U, 0xe2b87a14U, 0x7bb12baeU, 0x0cb61b38U, 0x92d28e9bU, 0xe5d5be0dU, 0x7cdcefb7U, 0x0bdbdf21U,
    0x86d3d2d4U, 0xf1d4e242U, 0x68ddb3f8U, 0x1fda836eU, 0x81be16cdU, 0xf6b9265bU, 0x6fb077e1U, 0x18b74777U,
    0x88085ae6U, 0xff0f6a70U, 0x66063bcaU, 0x11010b5cU, 0x8f659effU, 0xf862ae69U, 0x616bffd3U, 0x166ccf45U,
    0xa00ae278U, 0xd70dd2eeU, 0x4e048354U, 0x3903b3c2U, 0xa7672661U, 0xd06016f7U, 0x4969474dU, 0x3e6e77dbU,
    0xaed16a4aU, 0xd9d65adcU, 0x40df0b66U, 0x37d83bf0U, 0xa9bcae53U, 0xdebb9ec5U, 0x47b2cf7fU, 0x30b5ffe9U,
    0xbdbdf21cU, 0xcabac28aU, 0x53b39330U, 0x24b4a3a6U, 0xbad03605U, 0xcdd70693U, 0x54de5729U, 0x23d967bfU,
    0xb3667a2eU, 0xc4614ab8U, 0x5d681b02U, 0x2a6f2b94U, 0xb40bbe37U, 0xc30c8ea1U, 0x5a05df1bU, 0x2d02ef8dU,
};

static uint32_t kpm_udp_crc32(const uint8_t *data, int len)
{
    uint32_t crc = 0xFFFFFFFFU;
    int i;
    for (i = 0; i < len; i++)
        crc = (crc >> 8) ^ kpm_udp_crc32_table[(crc ^ data[i]) & 0xFF];
    return crc ^ 0xFFFFFFFFU;
}

/* msghdr 中 msg_flags 偏移：4.14~6.x 各版本均在 offset 64，
 * 自定义 struct msghdr 的 __reserved[88] 覆盖 offset 16..104，安全写入。 */
#define KPM_MSGHDR_FLAGS_OFF   64

/* 发送一个流式数据报（20B 头 + 数据，双 kvec，零拷贝）。
 * DONTWAIT + 退避重试 + 总预算 + 卸载感知。
 * 返回 0 成功；-KPM_E_FAULT 超时/错误；-KPM_E_BUSY 模块卸载中。 */
static int kpm_udp_stream_send_dgram(struct kpm_sockaddr_in *client,
                                     uint32_t session, uint32_t offset,
                                     const void *data, uint32_t len)
{
    kpm_stream_dgram_t dg;   /* 匿名结构体 typedef，勿加 struct 前缀 */
    struct kpm_kvec vecs[2];
    struct msghdr msg;
    int retries = 0;
    unsigned long total_len;

    if (!kf_kernel_sendmsg || !g_udp_sock)
        return -KPM_E_FAULT;

    dg.magic = KPM_STREAM_MAGIC_CHUNK;
    dg.session = session;
    dg.offset = offset;
    dg.len = len;
    dg.crc32 = kpm_udp_crc32((const uint8_t *)data, (int)len);
    total_len = sizeof(dg) + len;

    vecs[0].iov_base = &dg;
    vecs[0].iov_len = sizeof(dg);
    vecs[1].iov_base = (void *)data;
    vecs[1].iov_len = len;

    kpm_udp_memset(&msg, 0, sizeof(msg));
    msg.msg_name = client;
    msg.msg_namelen = sizeof(*client);
    *(unsigned int *)((uint8_t *)&msg + KPM_MSGHDR_FLAGS_OFF) = KPM_MSG_DONTWAIT;

    for (;;) {
        int r;
        if (!g_udp_ready)
            return -KPM_E_BUSY;
        r = kf_kernel_sendmsg(g_udp_sock, &msg, vecs, 2, total_len);
        if (r == (int)total_len)
            return 0;
        if (r == KPM_EAGAIN || r == KPM_ENOBUFS ||
            r == -1 /* EPERM */ || r == -12 /* ENOMEM */) {
            if (++retries >= KPM_STREAM_SEND_MAX_RETRIES) {
                kpm_log("LH_udp: stream dgram timeout r=%d (offset=%u)\n", r, offset);
                return -KPM_E_FAULT;
            }
            kpm_udelay_range(KPM_STREAM_SEND_BACKOFF_US_MIN,
                             KPM_STREAM_SEND_BACKOFF_US_MAX);
            continue;
        }
        kpm_log("LH_udp: stream dgram send failed r=%d (offset=%u)\n", r, offset);
        return -KPM_E_FAULT;
    }
}

/* 通用通知发送（断点命中通知等独立事件）。
 * 向指定客户端地址发送一段自定义数据（DONTWAIT + 退避 + 预算）。
 * 与 kpm_udp_stream_send_dgram 共用发送核心，但不附加协议头。
 * 调用方（kpm_debug）保证 data 长度 <= 256（通知小报文）。 */
/* 通用非阻塞响应发送（work 单线程串行上下文安全）。
 * 与 kpm_udp_stream_send_dgram / kpm_udp_notify_send 共用
 * DONTWAIT + 2-4ms 退避重试 + 总预算（20-40s）+ 卸载感知策略，
 * 保证退避耗尽后静默丢弃而不阻塞 work 线程。
 * 返回 0 成功；-KPM_E_BUSY 卸载中/超预算；-KPM_E_FAULT 其他错误。 */
static int kpm_udp_send_resp_pkt(struct kpm_sockaddr_in *client,
                                 struct kpm_kvec *vec, int nvec,
                                 unsigned long total)
{
    struct msghdr msg;
    int retries = 0;

    if (!client || !vec || nvec <= 0 || total <= 0)
        return -KPM_E_INVAL;
    if (!kf_kernel_sendmsg || !g_udp_sock)
        return -KPM_E_FAULT;

    kpm_udp_memset(&msg, 0, sizeof(msg));
    msg.msg_name = client;
    msg.msg_namelen = sizeof(*client);
    *(unsigned int *)((uint8_t *)&msg + KPM_MSGHDR_FLAGS_OFF) = KPM_MSG_DONTWAIT;

    for (;;) {
        int r;
        if (!g_udp_ready)
            return -KPM_E_BUSY;
        r = kf_kernel_sendmsg(g_udp_sock, &msg, vec, nvec, total);
        if (r == (int)total)
            return 0;
        /* 除 EAGAIN/ENOBUFS 外，-EPERM(-1) 可能由 netfilter/SELinux
         * 瞬态拒绝触发（16KB 分片路径），-ENOMEM(-12) 可能由网络缓冲区
         * 瞬态耗尽触发；两者均可能在短暂退避后恢复，重试可避免整页丢弃。 */
        if (r == KPM_EAGAIN || r == KPM_ENOBUFS ||
            r == -1 /* EPERM */ || r == -12 /* ENOMEM */) {
            if (++retries >= KPM_STREAM_SEND_MAX_RETRIES) {
                kpm_log("LH_udp: resp pkt send timeout r=%d (total=%lu)\n", r, total);
                return -KPM_E_BUSY;
            }
            kpm_udelay_range(KPM_STREAM_SEND_BACKOFF_US_MIN,
                             KPM_STREAM_SEND_BACKOFF_US_MAX);
            continue;
        }
        kpm_log("LH_udp: resp pkt send failed r=%d (total=%lu)\n", r, total);
        return -KPM_E_FAULT;
    }
}

int kpm_udp_notify_send(struct kpm_sockaddr_in *client,
                        const void *data, int len)
{
    struct kpm_kvec vec;
    struct msghdr msg;
    int retries = 0;

    if (!client || !data || len <= 0 || len > 256)
        return -KPM_E_INVAL;
    if (!kf_kernel_sendmsg || !g_udp_sock)
        return -KPM_E_FAULT;

    vec.iov_base = (void *)data;
    vec.iov_len = (unsigned long)len;

    kpm_udp_memset(&msg, 0, sizeof(msg));
    msg.msg_name = client;
    msg.msg_namelen = sizeof(*client);
    *(unsigned int *)((uint8_t *)&msg + KPM_MSGHDR_FLAGS_OFF) = KPM_MSG_DONTWAIT;

    for (;;) {
        int r;
        if (!g_udp_ready)
            return -KPM_E_BUSY;
        r = kf_kernel_sendmsg(g_udp_sock, &msg, &vec, 1, (unsigned long)len);
        if (r == len)
            return 0;
        if (r == KPM_EAGAIN || r == KPM_ENOBUFS) {
            if (++retries >= KPM_STREAM_SEND_MAX_RETRIES)
                return -KPM_E_FAULT;
            kpm_udelay_range(KPM_STREAM_SEND_BACKOFF_US_MIN,
                             KPM_STREAM_SEND_BACKOFF_US_MAX);
            continue;
        }
        return -KPM_E_FAULT;
    }
}

/* ===== 来源 IP 过滤 =====
 *
 * 要求：发包端 IP 必须是内网地址（RFC1918 / CGNAT）且不是本机 IP，
 * 防止：① 公网探测扫描 UDP 端口；② 本机应用（如扫描工具）探测。
 * 不符合条件的请求：静默丢弃，不发送任何响应（假装端口未开放，发送端 recvfrom 超时）。
 *
 * 本机 IP 列表从 /proc/net/fib_trie 的 "Local:" 段解析（纯文本，无内核结构体
 * 偏移依赖，安全性高）。加载失败时降级为仅排除回环地址（127.0.0.0/8）。
 */
#define KPM_UDP_MAX_LOCAL_IPS 16
static uint32_t g_local_ips[KPM_UDP_MAX_LOCAL_IPS];  /* 网络字节序 */
static int g_local_ip_count = 0;

/* 解析 /proc/net/fib_trie 中的本机 IPv4 地址（"Local:" 段后的 x.x.x.x/32 条目） */
static void kpm_udp_load_local_ips(void)
{
    struct file *fp;
    loff_t pos = 0;
    char *buf;
    ssize_t n;
    char *p, *end;
    int in_local = 0;

    g_local_ip_count = 0;

    if (!kf_filp_open || !kf_filp_close || !kf_kernel_read)
        return;
    if (!kf_kmalloc || !kf_kfree)
        return;   /* 防御：kf_kmalloc 为 NULL 时调用会 panic */

    /* 读 /proc/net/fib_trie（文本 32KB 足够容纳路由表） */
    buf = (char *)kf_kmalloc(32768, GFP_KERNEL);
    if (!buf)
        return;

    fp = kf_filp_open("/proc/net/fib_trie", 0 /* O_RDONLY */, 0);
    if (IS_ERR_OR_NULL(fp)) {
        kf_kfree(buf);
        return;
    }
    n = kf_kernel_read(fp, buf, 32767, &pos);
    kf_filp_close(fp, 0);
    if (n <= 0) {
        kf_kfree(buf);
        return;
    }
    buf[n] = '\0';
    end = buf + n;

    /* 逐行扫描：进入 "Local:" 段后解析所有 a.b.c.d/32 条目 */
    p = buf;
    while (p < end && g_local_ip_count < KPM_UDP_MAX_LOCAL_IPS) {
        char *nl = p;
        char *line;
        int line_len;
        char *s, *se;
        const char *q;

        while (nl < end && *nl != '\n') nl++;
        line = p;
        line_len = (int)(nl - p);

        /* 段标题判断：行首无缩进的 "xxx:" 行（如 "Main:" / "Local:"） */
        if (line_len > 0 && line[0] != ' ' && line[0] != '\t' &&
            line[0] != '|' && line[0] != '+') {
            if (line_len == 6 && line[0] == 'L' && line[1] == 'o' &&
                line[2] == 'c' && line[3] == 'a' && line[4] == 'l' &&
                line[5] == ':') {
                in_local = 1;
            } else {
                in_local = 0;   /* 离开 Local 段 */
            }
        }

        if (in_local) {
            /* 扫描行内所有 IPv4 形态 token，要求紧跟 "/32" 后缀 */
            s = line;
            se = line + line_len;
            while (s < se) {
                uint32_t ip = 0;
                uint32_t cur = 0;
                int dots = 0;
                int ok = 1;
                char *tok_end;

                if (!((*s >= '0' && *s <= '9') || *s == '.')) { s++; continue; }

                tok_end = s;
                while (tok_end < se && ((*tok_end >= '0' && *tok_end <= '9') || *tok_end == '.')) {
                    if (*tok_end == '.') {
                        dots++;
                        if (dots > 3) { ok = 0; break; }
                        if (cur > 255) { ok = 0; break; }
                        ip = (ip << 8) | cur;
                        cur = 0;
                    } else {
                        cur = cur * 10 + (uint32_t)(*tok_end - '0');
                        if (cur > 255) { ok = 0; break; }
                    }
                    tok_end++;
                }

                if (ok && dots == 3 && cur <= 255) {
                    ip = (ip << 8) | cur;
                    /* 要求紧跟 "/32" */
                    q = tok_end;
                    while (q < se && (*q == ' ' || *q == '\t')) q++;
                    if (q + 3 <= se && q[0] == '/' && q[1] == '3' && q[2] == '2') {
                        g_local_ips[g_local_ip_count++] = ip;
                    }
                }
                s = tok_end;
            }
        }

        p = nl + 1;
    }

    kf_kfree(buf);
    kpm_log("LH_udp: loaded %d local IPv4 from fib_trie\n", g_local_ip_count);
}

/* 判断来源地址是否被允许：
 *   1. 必须是 IPv4（UDP socket 本就只有 IPv4）
 *   2. 必须是内网地址（RFC1918: 10/8, 172.16/12, 192.168/16；CGNAT: 100.64/10）
 *   3. 不能是本机 IP（回环 127/8 恒排除；本机真实 IP 依据 g_local_ips 排除；
 *      列表未加载时降级为仅排除回环）
 * 返回 1 = 允许，0 = 拒绝（静默丢弃，不响应） */
static int kpm_udp_source_allowed(const struct kpm_sockaddr_in *sa)
{
    uint8_t *b;
    uint32_t ip;
    int i;

    if (!sa)
        return 0;
    if (sa->sin_family != KPM_AF_INET)
        return 0;

    ip = sa->sin_addr;   /* 网络字节序 */
    b = (uint8_t *)&ip;

    /* 1. 内网地址检查（RFC1918 + CGNAT） */
    if (!(b[0] == 10 ||
          (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
          (b[0] == 192 && b[1] == 168) ||
          (b[0] == 100 && b[1] >= 64 && b[1] <= 127))) {
        kpm_log("LH_udp: drop packet from non-private ip %d.%d.%d.%d\n",
                b[0], b[1], b[2], b[3]);
        return 0;
    }

    /* 2. 回环（本机）排除 */
    if (b[0] == 127)
        return 0;

    /* 3. 本机真实 IP 排除（列表加载成功时） */
    if (g_local_ip_count > 0) {
        for (i = 0; i < g_local_ip_count; i++) {
            if (g_local_ips[i] == ip)
                return 0;
        }
    }

    return 1;
}

/* ===== 辅助函数 ===== */

/* 简单 memset（框架可能未导出 memset） */
static void kpm_udp_memset(void *dst, int c, unsigned long n)
{
    uint8_t *d = (uint8_t *)dst;
    while (n--) *d++ = (uint8_t)c;
}

/* 简单 memcpy */
static void kpm_udp_memcpy(void *dst, const void *src, unsigned long n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
}

/* htons: 主机字节序 → 网络字节序 */
static uint16_t kpm_htons(uint16_t x)
{
    return (uint16_t)(((x & 0xFF) << 8) | ((x >> 8) & 0xFF));
}

/* INIT_WORK 等效实现（匹配内核 work_struct ABI） */
static void kpm_init_work(struct kpm_work_struct *work,
                          void (*func)(struct kpm_work_struct *))
{
    work->data = 0;
    INIT_LIST_HEAD(&work->entry);
    work->func = func;
}

/* ===== 命令分发（work 函数中调用） ===== */

static void kpm_udp_handle_request(struct kpm_udp_request *req,
                                    struct kpm_sockaddr_in *client_addr)
{
    /* 响应缓冲区：使用静态全局 g_resp_buf（避免 16KB 栈溢出）。
     * 仅单 workqueue 串行调用，无需加锁。 */
    struct kpm_udp_response *resp = (struct kpm_udp_response *)g_resp_buf;
    uint8_t *resp_data = g_resp_buf + sizeof(struct kpm_udp_response);
    unsigned long resp_data_len = 0;
    int cmd;
    long ret = 0;

    kpm_udp_memset(g_resp_buf, 0, sizeof(g_resp_buf));
    resp->seq = req->seq;

    /* 解码 XOR */
    cmd = (int)(req->cmd ^ KPM_CMD_XOR_KEY);

    if (cmd == KPM_CMD_PROC_MAPS) {
        kpm_log("LH_udp: PROC_MAPS enter seq=%u pid=%llu\n",
                req->seq, (unsigned long long)req->arg2);
    }

    /* ===== 统一协议处理层 =====
     * 公共命令（UDP/prctl 双通道共有）统一由 kpm_cmd_dispatch 处理，
     * 本函数仅保留 UDP 特有命令（流式/DUMP/批量读/文件回退等）。 */
    kpm_cmd_ctx_t ctx;
    long ret2;
    kpm_udp_memset(&ctx, 0, sizeof(ctx));
    ctx.channel  = KPM_CHAN_UDP;
    ctx.cmd      = (uint32_t)cmd;
    ctx.arg2     = req->arg2;
    ctx.arg3     = req->arg3;
    ctx.arg4     = req->arg4;
    ctx.arg5     = req->arg5;
    ctx.req_data = (const void *)((uint8_t *)req + sizeof(struct kpm_udp_request));
    ctx.req_len  = req->data_len;
    ctx.out_buf  = resp_data;
    ctx.out_cap  = KPM_UDP_MAX_PAYLOAD;
    ctx.out_len  = (uint32_t *)&resp_data_len;
    ctx.chan_ctx = (void *)client_addr;
    ret2 = kpm_cmd_dispatch(&ctx);
    if (ret2 != KPM_CMD_UNHANDLED) {
        /* 公共命令已处理：ret2 即 ret，resp_data_len 已由协议层填充 */
        ret = ret2;   /* 统一写回 ret，共用下方发送块 */
        resp->ret = (int32_t)ret;
        resp->data_len = (uint32_t)resp_data_len;
        goto udp_send_resp;
    }

    /* ===== UDP 特有命令功能门控 =====
     * 与协议层 dispatch 门控同规则：命令 → 功能单元，未启用统一
     * -KPM_E_DISABLED。覆盖批量读/流/DUMP/文件读取/触摸记录等
     * UDP-only 命令（公共命令已在 kpm_cmd_dispatch 内门控）。 */
    {
        uint32_t unit = KPM_FEAT_MAX;
        switch (cmd) {
        case KPM_CMD_READ_FILE:
        case KPM_CMD_PROC_FULLPATH:                  unit = KPM_FEAT_PROC;     break;
        case KPM_CMD_TOUCH_RECORD_START:
        case KPM_CMD_TOUCH_RECORD_STOP:
        case KPM_CMD_TOUCH_RECORD_GET:               unit = KPM_FEAT_TOUCH;    break;
        case KPM_CMD_MEM_SCAN_AOB_START:
        case KPM_CMD_MEM_SCAN_KERNEL_START:
        case KPM_CMD_MEM_SCAN_STATUS:                unit = KPM_FEAT_MEM_SCAN; break;
        case KPM_CMD_DUMP_BEGIN:
        case KPM_CMD_DUMP_FETCH:
        case KPM_CMD_DUMP_END:
        case KPM_CMD_DUMP_STREAM:                    unit = KPM_FEAT_DUMP;     break;
        case KPM_CMD_MEM_READ_BATCH:
        case KPM_CMD_MEM_READ_BATCH2:
        case KPM_CMD_MEM_GET_PTE:
        case KPM_CMD_STREAM_BEGIN:
        case KPM_CMD_STREAM_WRITE:                   unit = KPM_FEAT_MEM_RW;   break;
        default: break;
        }
        if (unit != KPM_FEAT_MAX && !kpm_feat_enabled(unit)) {
            ret = -KPM_E_DISABLED;
            resp->ret = (int32_t)ret;
            resp->data_len = 0;
            goto udp_send_resp;
        }
    }

    switch (cmd) {
    /* ===== UDP 特有命令（公共命令已在协议层处理） ===== */

    case KPM_CMD_READ_FILE: {
        /* 文件回退读取（dump 未驻留页用）：data=完整路径, arg5=文件偏移。
         * 返回文件内容（最多 KPM_UDP_MAX_PAYLOAD 字节）。
         * 隐蔽性：内核态 O_RDONLY 读取，无用户态痕迹。
         * 兼容性：filp_open/kernel_read 已通过 kallsyms 解析。 */
        uint32_t fname_len = req->data_len;
        uint64_t file_off = req->arg5;
        char fpath[256];
        int rlen;

        if (fname_len <= 0 || fname_len >= (int)sizeof(fpath)) {
            ret = -KPM_E_INVAL;
            break;
        }
        if (!kf_filp_open || !kf_kernel_read || !kf_filp_close) {
            ret = -KPM_E_NOTFOUND;
            break;
        }
        /* 拷贝路径（g_recv_buf 内，安全） */
        kpm_udp_memcpy(fpath, (uint8_t *)req + sizeof(struct kpm_udp_request),
                       fname_len);
        fpath[fname_len] = '\0';

        {
            struct file *rfp;
            loff_t pos = (loff_t)file_off;

            /* 不做凭证切换：仅可读 SELinux 允许的路径（/system 等），
             * 块设备/zram 返回 -KPM_E_NOTFOUND。 */
            rfp = kf_filp_open(fpath, 0 /* O_RDONLY */, 0);
            if (IS_ERR_OR_NULL(rfp)) {
                kpm_log("read_file: open %s failed\n", fpath);
                ret = -KPM_E_NOTFOUND;
                break;
            }
            rlen = (int)kf_kernel_read(rfp, resp_data,
                                       (size_t)KPM_UDP_MAX_PAYLOAD, &pos);
            kf_filp_close(rfp, NULL);
            if (rlen < 0) {
                ret = -KPM_E_FAULT;
                break;
            }
            if (rlen == 0) {
                ret = -KPM_E_NOTFOUND;   /* EOF 或越界 */
                break;
            }
            ret = rlen;
            resp_data_len = (unsigned long)rlen;
        }
        break;
    }

    case KPM_CMD_PROC_FULLPATH: {
        /* VMA 完整路径（dump 文件回退用）：arg2=pid, arg3=addr。
         * 返回以 '/' 开头的完整文件路径（如 /system/lib64/libx.so）。
         * 纯内存解析（d_parent 链），无 VFS 痕迹。
         * 用 kpm_find_vma_path_for_pid 在 RCU 读临界区内完成路径解析，
         * 不返回 vma 指针供锁外使用，避免 UAF。 */
        pid_t target_pid = (pid_t)req->arg2;
        uint64_t addr = req->arg3;
        char path_buf[256];

        if (kpm_find_vma_path_for_pid(target_pid, addr, path_buf,
                                      (int)sizeof(path_buf)) != 0) {
            ret = -KPM_E_NOTFOUND;
            break;
        }
        ret = 0;
        kpm_udp_memcpy(resp_data, path_buf,
                       (unsigned long)(lib_strlen(path_buf) + 1));
        resp_data_len = (unsigned long)(lib_strlen(path_buf) + 1);
        break;
    }


    /* ===== 触摸事件流式推送（客户端 PING 保活 + 内核主动推送） =====
     * 0x1030 START: 建立会话（记住源地址）+ 记录启动，arg2=src_mask
     * 0x1031 PING:  保活（刷新最后活跃时间），返回 0=会话活跃 / -1=未启动
     * 0x1032 STOP:  停止推送 + 记录
     * 事件到达时 kpm_tvrecord → kpm_udp_tvpush_wakeup → push work 增量推送 */
    case KPM_CMD_TOUCH_RECORD_START: {
        ret = (long)kpm_udp_tvstream_start(client_addr, (int)req->arg2);
        break;
    }
    case KPM_CMD_TOUCH_RECORD_STOP: {
        ret = (long)kpm_udp_tvstream_ping();
        break;
    }
    case KPM_CMD_TOUCH_RECORD_GET: {
        ret = (long)kpm_udp_tvstream_stop();
        break;
    }





    /* 长 AOB 特征扫描（>8B）。
     * 请求: arg2=pid, arg3=mode<<8, arg5=len(1-64), payload=特征字节
     * 与 SCAN_START 参数格式对齐（type 固定 BYTEARRAY 语义）。
     * payload 两种格式：
     *   带 mask: [u32 len][pattern(len)][mask(len)]，mask[i]==0=通配
     *   兼容格式: [pattern(len)]，全精确
     * 特征从 payload 拷贝（请求头 48B 之后），由 kpm_mem_scan_start_aob
     * 深拷贝到会话缓冲，避免 g_recv_buf 复用覆盖。 */
    case KPM_CMD_MEM_SCAN_AOB_START: {
        pid_t pid = (pid_t)req->arg2;
        int mode = (int)((req->arg3 >> 8) & 0xFF);
        int plen = (int)req->arg5;
        uint8_t *pattern;
        uint8_t *mask = NULL;
        uint32_t dlen = req->data_len;

        if (plen <= 0 || plen > KPM_SCAN_AOB_MAX) {
            ret = -KPM_E_INVAL;
            break;
        }
        /* payload 校验：请求头 + 特征字节 必须都在收包内（g_recv_buf） */
        if ((uint32_t)plen > dlen) {
            ret = -KPM_E_INVAL;
            break;
        }
        pattern = (uint8_t *)req + sizeof(struct kpm_udp_request);
        /* 带 mask 格式 [u32 len][pattern][mask]：dlen == 4 + 2*plen */
        if (dlen == (uint32_t)(4 + 2 * plen)) {
            uint32_t hlen;
            kpm_udp_memcpy(&hlen, pattern, 4);
            if (hlen == (uint32_t)plen) {
                mask = pattern + 4 + plen;
            }
        }
        ret = kpm_mem_scan_start_aob(pid, pattern + (mask ? 4 : 0), plen,
                                     mask, mode, 0);
        break;
    }

    /* 内核线性映射范围扫描。
     * arg2=0(pid 保留), arg3=type|mode<<8|range_hi<<32, arg4=value,
     * arg5=value_len|range_lo<<32
     * range(64位) = range_hi<<32 | range_lo → 上限 KPM_SCAN_KERNEL_MAX(64GB)。 */
    case KPM_CMD_MEM_SCAN_KERNEL_START: {
        int type = (int)(req->arg3 & 0xFF);
        int mode = (int)((req->arg3 >> 8) & 0xFF);
        uint64_t value = req->arg4;
        int value_len = (int)(req->arg5 & 0xFFFF);
        uint64_t range_lo = (req->arg5 >> 32) & 0xFFFFFFFFULL;
        uint64_t range_hi = (req->arg3 >> 32) & 0xFFFFFFFFULL;
        uint64_t range = (range_hi << 32) | range_lo;
        ret = kpm_mem_scan_kernel_start(type, mode, value, value_len, range);
        break;
    }


    /* 扫描会话状态查询。
     * 返回 kpm_scan_status_t（48 字节）：
     *   active/pid/region_count/result_count/result_capacity/truncated/
     *   scanned_bytes/total_bytes/failed_pages
     * 用途：客户端判断扫描完整性（truncated=1 表示结果被截断而非范围小）、
     * 显示扫描进度（scanned_bytes/total_bytes）。 */
    case KPM_CMD_MEM_SCAN_STATUS: {
        kpm_scan_status_t sbuf;
        kpm_udp_memset(&sbuf, 0, sizeof(sbuf));
        ret = kpm_mem_scan_status(&sbuf);
        if (ret == 0) {
            kpm_udp_memcpy(resp_data, &sbuf, sizeof(sbuf));
            resp_data_len = sizeof(sbuf);
        }
        break;
    }



    /* ===== 内存 dump 协议化传输（ELF 重建，供 IDA/脱壳分析） =====
     *   DUMP_BEGIN:  arg2=pid, data=模块名 → 返回 kpm_dump_hdr_t (128B)
     *   DUMP_FETCH:  arg2=offset → 返回 kpm_dump_chunk_t + data (≤15872B)
     *   DUMP_END:    结束会话 → 返回 kpm_dump_done_t (48B)
     */
    case KPM_CMD_DUMP_BEGIN: {
        pid_t target_pid = (pid_t)req->arg2;
        uint32_t dlen = req->data_len;
        char mname[KPM_DUMP_MODULE_MAX];
        kpm_dump_hdr_t hdr;
        int mlen;

        if (dlen <= 0) { ret = -KPM_E_INVAL; break; }
        if (dlen >= (uint32_t)sizeof(mname)) dlen = (uint32_t)sizeof(mname) - 1;
        kpm_udp_memcpy(mname, (uint8_t *)req + sizeof(struct kpm_udp_request), dlen);
        mname[dlen] = '\0';
        mlen = (int)dlen;
        /* 去掉末尾换行/空白 */
        while (mlen > 0 && (mname[mlen-1] == '\n' || mname[mlen-1] == '\r' ||
                            mname[mlen-1] == ' '))
            mname[--mlen] = '\0';

        ret = kpm_dump_begin(target_pid, mname, mlen, &hdr);
        if (ret == 0) {
            kpm_udp_memcpy(resp_data, &hdr, sizeof(hdr));
            resp_data_len = sizeof(hdr);
        }
        break;
    }

    case KPM_CMD_DUMP_FETCH: {
        uint64_t file_off = req->arg2;
        kpm_dump_chunk_t chunk;
        uint8_t *dbuf = resp_data + sizeof(chunk);
        long r;

        if ((unsigned long)(sizeof(chunk) + KPM_DUMP_CHUNK_MAX) >
            (unsigned long)KPM_UDP_MAX_PAYLOAD) {
            ret = -KPM_E_INVAL;
            break;
        }
        r = kpm_dump_fetch(file_off, &chunk, dbuf, KPM_DUMP_CHUNK_MAX);
        if (r > 0) {
            kpm_udp_memcpy(resp_data, &chunk, sizeof(chunk));
            resp_data_len = sizeof(chunk) + (unsigned long)r;
            ret = (int)r;
        } else {
            ret = (int)r;
        }
        break;
    }

    case KPM_CMD_DUMP_END: {
        kpm_dump_done_t done;
        ret = kpm_dump_end(&done);
        if (ret == 0) {
            kpm_udp_memcpy(resp_data, &done, sizeof(done));
            resp_data_len = sizeof(done);
        }
        break;
    }

    case KPM_CMD_MEM_READ_BATCH: {
        /* 通用批量读：payload = [u32 count][u32 per_len] + count × u64 地址
         * 响应 = count × per_len 字节（失败条目全 0xFF），ret = 成功条目数
         *
         * per_len 取 1..KPM_READ_BATCH_LEN_MAX 任意值；count×per_len ≤ 16384
         * 总载荷约束（响应缓冲安全）。 */
        pid_t pid = (pid_t)req->arg2;
        uint32_t count = 0, per_len = 0;
        const uint8_t *p = (const uint8_t *)req +
                           sizeof(struct kpm_udp_request);
        uint32_t i;
        int ok = 0;

        if (req->data_len >= 8) {
            kpm_udp_memcpy(&count, p, 4);
            kpm_udp_memcpy(&per_len, p + 4, 4);
        }
        if (count == 0 || count > KPM_READ_BATCH_MAX ||
            per_len < KPM_READ_BATCH_LEN_MIN ||
            per_len > KPM_READ_BATCH_LEN_MAX ||
            (uint64_t)count * per_len > KPM_UDP_MAX_PAYLOAD ||
            8 + (uint64_t)count * 8 > req->data_len) {
            ret = -KPM_E_INVAL;
            break;
        }
        /* 失败条目填充 0xFF（区分真实数据与不可读页） */
        kpm_udp_memset(resp_data, 0xFF, (unsigned long)count * per_len);
        for (i = 0; i < count; i++) {
            uint64_t addr;
            long got;
            kpm_udp_memcpy(&addr, p + 8 + (uint64_t)i * 8, 8);
            got = kpm_mem_read_kernel(pid, addr, resp_data + (uint64_t)i * per_len,
                                      (int)per_len);
            if (got == (long)per_len)
                ok++;
        }
        resp_data_len = (unsigned long)count * per_len;
        ret = ok;
        break;
    }

    case KPM_CMD_MEM_READ_BATCH2: {
        /* 变长批量读：每条目独立长度。
         * 请求 payload: [u32 count] + count × {u32 len, u64 addr}
         * 响应: 按请求顺序拼接每条目 len 字节（失败条目全 0xFF）
         * ret = 成功条目数。约束 Σ len ≤ 16384。 */
        pid_t pid = (pid_t)req->arg2;
        const uint8_t *p = (const uint8_t *)req +
                           sizeof(struct kpm_udp_request);
        uint32_t count = 0;
        uint32_t total_out = 0;
        uint32_t i;
        int ok = 0;

        if (req->data_len >= 4) {
            kpm_udp_memcpy(&count, p, 4);
            p += 4;
        }
        /* 校验 count 与载荷长度一致性 */
        if (count == 0 || count > KPM_READ_BATCH2_MAX ||
            4 + (uint64_t)count * 12 > req->data_len) {
            ret = -KPM_E_INVAL;
            break;
        }
        /* 预扫描：校验每条目 len 合法 + Σ len ≤ 16384 */
        {
            const uint8_t *q = p;
            uint64_t sum = 0;
            for (i = 0; i < count; i++) {
                uint32_t len;
                kpm_udp_memcpy(&len, q, 4);
                if (len == 0 || len > KPM_READ_BATCH2_LEN_MAX) {
                    ret = -KPM_E_INVAL;
                    goto batch2_done;
                }
                sum += len;
                q += 12;
            }
            if (sum > KPM_UDP_MAX_PAYLOAD) {
                ret = -KPM_E_INVAL;
                goto batch2_done;
            }
        }
        /* 逐条读取，顺序拼接 */
        for (i = 0; i < count; i++) {
            uint32_t len;
            uint64_t addr;
            long got;
            kpm_udp_memcpy(&len, p, 4);
            kpm_udp_memcpy(&addr, p + 4, 8);
            p += 12;
            got = kpm_mem_read_kernel(pid, addr, resp_data + total_out, (int)len);
            if (got == (long)len)
                ok++;
            else
                kpm_udp_memset(resp_data + total_out, 0xFF, len);
            total_out += len;
        }
        resp_data_len = (unsigned long)total_out;
        ret = ok;
    batch2_done:
        break;
    }

    case KPM_CMD_MEM_GET_PTE: {
        /* 读原始 PTE（zram swap 解析）
         * 响应 payload = {u64 entry, u32 level, u32 rsvd} */
        pid_t pid = (pid_t)req->arg2;
        uint64_t addr = req->arg3;
        uint64_t entry = 0;
        uint32_t level = 0;
        uint32_t rsvd = 0;
        ret = kpm_mem_get_pte(pid, addr, &entry, &level);
        if (ret == 0) {
            kpm_udp_memcpy(resp_data, &entry, 8);
            kpm_udp_memcpy(resp_data + 8, &level, 4);
            kpm_udp_memcpy(resp_data + 12, &rsvd, 4);
            resp_data_len = KPM_GET_PTE_RESP_LEN;
        }
        break;
    }

    /* ===== 流式传输命令 =====
     *
     * STREAM_BEGIN：任意地址范围流式读（≤64MB）。
     *   响应 = 标准响应头 + kpm_stream_hdr_t(40B) + chunks 个数据报。
     *   数据报格式 kpm_stream_dgram_t(20B) + data，session = 请求 seq。
     *   用户内存读用 kpm_mem_read_kernel_pages（页级容错，失败页补零）；
     *   内核地址直读（flags bit0）用 copy_from_kernel_nofault 逐页。
     * 稳定性：发送非阻塞 + 退避 + 总预算；g_udp_ready=0 中止（卸载安全）；
     *        无动态分配，无内存泄漏。 */
    case KPM_CMD_STREAM_BEGIN: {
        pid_t pid = (pid_t)req->arg2;
        uint64_t addr = req->arg3;
        uint64_t total = req->arg4;
        uint32_t flags = (uint32_t)req->arg5;
        uint32_t chunks, i;
        uint32_t session = (uint32_t)req->seq;
        int stream_ret = 0;

        /* 参数校验（防溢出/滥用） */
        if (total == 0 || total > KPM_STREAM_MAX) {
            ret = -KPM_E_INVAL;
            break;
        }
        if (addr + total < addr) {
            ret = -KPM_E_INVAL;   /* 地址加法溢出 */
            break;
        }
        chunks = (uint32_t)((total + KPM_STREAM_CHUNK - 1) / KPM_STREAM_CHUNK);
        if (chunks == 0 || chunks > (KPM_STREAM_MAX / KPM_STREAM_CHUNK + 1)) {
            ret = -KPM_E_INVAL;
            break;
        }
        if (flags & KPM_STREAM_FLAG_KERNEL) {
            if (!kf_copy_from_kernel_nofault) {
                ret = -KPM_E_INVAL;
                break;
            }
        } else {
            if (pid <= 0) {
                ret = -KPM_E_INVAL;
                break;
            }
            if (!kf_find_get_pid || !kf_get_pid_task || !kf_get_task_mm ||
                !kf_mmput || !kf_copy_from_kernel_nofault) {
                ret = -KPM_E_INVAL;
                break;
            }
        }

        /* 发送流式头（标准响应格式）。
         * 检查发送返回值：hdr 发送失败时中止，不再发送 chunks，
         * 避免客户端收到不匹配的流（客户端超时重发自愈）。 */
        {
            struct kpm_udp_response *rh = (struct kpm_udp_response *)g_resp_buf;
            kpm_stream_hdr_t *hdr =
                (kpm_stream_hdr_t *)(g_resp_buf + sizeof(struct kpm_udp_response));
            struct kpm_kvec vec;
            int hdr_ret;

            kpm_udp_memset(g_resp_buf, 0, sizeof(g_resp_buf));
            rh->seq = req->seq;
            rh->ret = 0;
            rh->data_len = sizeof(kpm_stream_hdr_t);
            hdr->magic = KPM_STREAM_MAGIC_HDR;
            hdr->version = KPM_STREAM_VERSION;
            hdr->total = total;
            hdr->chunk = KPM_STREAM_CHUNK;
            hdr->chunks = chunks;
            hdr->crc32 = 0;                 /* 块级 CRC32 为准 */
            hdr->flags = 0;
            hdr->session = session;
            hdr->reserved = 0;

            vec.iov_base = g_resp_buf;
            vec.iov_len = sizeof(struct kpm_udp_response) + sizeof(kpm_stream_hdr_t);
            /* hdr 发送用 DONTWAIT + 退避预算 helper，避免客户端消失时
             * 裸 sendmsg 阻塞 sleep 卡死 UDP work。 */
            hdr_ret = kpm_udp_send_resp_pkt(client_addr, &vec, 1, vec.iov_len);
            if (hdr_ret != 0) {
                kpm_log("LH_udp: stream_begin hdr send failed r=%d\n",
                        hdr_ret);
                return;   /* 中止：不发送 chunks */
            }
        }

        /* 逐块读取 + 发送数据报 */
        for (i = 0; i < chunks; i++) {
            uint64_t off = (uint64_t)i * KPM_STREAM_CHUNK;
            uint32_t cur = (off + KPM_STREAM_CHUNK <= total) ?
                           KPM_STREAM_CHUNK : (uint32_t)(total - off);
            int r;

            if (flags & KPM_STREAM_FLAG_KERNEL) {
                /* 内核地址直读：逐 4KB 页 copy_from_kernel_nofault，失败页补零 */
                uint32_t done = 0;
                while (done < cur) {
                    uint64_t va = addr + off + done;
                    uint32_t piece = (uint32_t)(0x1000 - (va & 0xFFF));
                    if (piece > cur - done) piece = cur - done;
                    if (kf_copy_from_kernel_nofault(g_stream_buf + done,
                                                    (const void *)va,
                                                    (size_t)piece) == 0) {
                        done += piece;
                    } else {
                        kpm_udp_memset(g_stream_buf + done, 0, piece);
                        done += piece;
                    }
                }
            } else {
                uint32_t fail_map = 0;
                long got = kpm_mem_read_kernel_pages(pid, addr + off,
                                                     g_stream_buf,
                                                     (int)cur, &fail_map);
                if (got != (long)cur) {
                    /* 进程查找/页表失败：补零继续流，保证数据报总数不变 */
                    kpm_udp_memset(g_stream_buf, 0, cur);
                }
            }

            r = kpm_udp_stream_send_dgram(client_addr, session, (uint32_t)off,
                                          g_stream_buf, cur);
            if (r < 0) {
                stream_ret = (int)r;
                break;
            }
        }
        if (stream_ret != 0) {
            kpm_log("LH_udp: stream_begin aborted at chunk %u/%u (ret=%d)\n",
                    i, chunks, stream_ret);
        }
        /* 流式数据已全部发出（或中止）；响应头已先行发送，跳过通用响应 */
        return;
    }

    /* STREAM_WRITE：分片写（切片自包含，可独立重试）。
     * payload = [u32 slice_off][data...]；写入 addr+slice_off。
     * arg5 bit0=KPM_STREAM_FLAG_KERNEL：内核 VA 写（需 pid=0 + force
     * KERNEL_RW）；免 force 一律 -PERM。 */
    case KPM_CMD_STREAM_WRITE: {
        pid_t pid = (pid_t)req->arg2;
        uint64_t base = req->arg3;
        uint64_t total_len = req->arg4;
        uint32_t wflags = (uint32_t)req->arg5;
        uint32_t dlen = req->data_len;
        const uint8_t *p = (const uint8_t *)req +
                           sizeof(struct kpm_udp_request);
        uint32_t slice_off = 0;
        uint32_t slen;

        if (pid < 0) {
            ret = -KPM_E_INVAL;
            break;
        }
        if (dlen < 4) {
            ret = -KPM_E_INVAL;
            break;
        }
        kpm_udp_memcpy(&slice_off, p, 4);
        slen = dlen - 4;
        if (slen == 0 || slen > KPM_STREAM_WRITE_SLICE_MAX) {
            ret = -KPM_E_INVAL;
            break;
        }
        if (total_len == 0 || total_len > KPM_STREAM_MAX) {
            ret = -KPM_E_INVAL;
            break;
        }
        if ((uint64_t)slice_off + slen > total_len) {
            ret = -KPM_E_INVAL;   /* 切片越界 */
            break;
        }
        if (base + (uint64_t)slice_off + slen < base + (uint64_t)slice_off) {
            ret = -KPM_E_INVAL;   /* 地址加法溢出 */
            break;
        }
        if (pid == 0 && (wflags & KPM_STREAM_FLAG_KERNEL)) {
            if (!(kpm_force_mask() & KPM_FORCE_KERNEL_RW)) {
                ret = -KPM_E_PERM;
                break;
            }
            ret = kpm_mem_write_kernel_va(base + (uint64_t)slice_off,
                                          (const void *)(p + 4), (int)slen, 1);
        } else if (pid > 0) {
            ret = kpm_mem_write_kernel(pid, base + (uint64_t)slice_off,
                                       (const void *)(p + 4), (int)slen);
        } else {
            ret = -KPM_E_PERM;   /* pid=0 必须显式带内核标志 */
        }
        break;
    }

    /* DUMP_STREAM：模块 dump 流式 fetch（复用 dump 会话语义）。
     * arg2=file_off, arg3=本批字节数(1..64MB)。
     * 响应 = 直接发送数据报（无头报；total/chunk 由 DUMP_BEGIN 提供）。
     * 每块经 kpm_dump_fetch 获得 ELF 语义数据（含 bss 补零），
     * 块级 CRC32 与块内偏移由数据报携带，客户端重组校验。 */
    case KPM_CMD_DUMP_STREAM: {
        uint64_t file_off = req->arg2;
        uint64_t want = req->arg3;
        uint32_t session = (uint32_t)req->seq;
        int stream_ret = 0;

        if (want == 0 || want > KPM_STREAM_MAX) {
            ret = -KPM_E_INVAL;
            break;
        }
        while (want > 0) {
            kpm_dump_chunk_t chunk;
            uint32_t cur = (want > KPM_STREAM_CHUNK) ?
                           KPM_STREAM_CHUNK : (uint32_t)want;
            long got = kpm_dump_fetch(file_off, &chunk, g_stream_buf, (int)cur);
            int r;

            if (got <= 0) {
                kpm_log("LH_udp: dump_stream fetch off=%llu failed %ld\n",
                        (unsigned long long)file_off, got);
                stream_ret = (int)((got < 0) ? got : -KPM_E_FAULT);
                break;
            }
            if ((uint64_t)got > cur)
                got = (long)cur;   /* 防溢出 */
            r = kpm_udp_stream_send_dgram(client_addr, session,
                                          (uint32_t)file_off,
                                          g_stream_buf, (uint32_t)got);
            if (r < 0) {
                stream_ret = r;
                break;
            }
            file_off += (uint64_t)got;
            want -= (uint64_t)got;
        }
        if (want > 0 && stream_ret == 0)
            stream_ret = -KPM_E_FAULT;   /* 未拉满本批 */
        if (stream_ret != 0) {
            kpm_log("LH_udp: dump_stream aborted (remaining=%llu ret=%d)\n",
                    (unsigned long long)want, stream_ret);
        }
        /* 数据报已全部发出；无头响应可回（客户端按字节数判定完成） */
        return;
    }

    default:
        /* 未知命令：静默丢弃（魔数静默，不响应） */
        return;
    }

udp_send_resp:
    if (cmd == KPM_CMD_PROC_MAPS) {
        kpm_log("LH_udp: PROC_MAPS done seq=%u ret=%ld\n",
                req->seq, ret);
    }

    /* 发送响应 */
    resp->ret = (int32_t)ret;
    resp->data_len = (uint32_t)resp_data_len;

    {
        struct kpm_kvec vec = {
            .iov_base = g_resp_buf,
            .iov_len = sizeof(struct kpm_udp_response) + resp_data_len
        };
        /* 用 DONTWAIT + 退避预算 helper 发送，避免 sndbuf 满 + 客户端消失时
         * 阻塞 sleep 卡死整个 UDP work。 */
        if (kpm_udp_send_resp_pkt(client_addr, &vec, 1, vec.iov_len) != 0)
            kpm_log("LH_udp: send_resp dropped (client gone/slow, cmd=%d)\n", cmd);
    }
}

/* ===== Work 函数（process 上下文，可睡眠） =====
 *
 * 阻塞收包模式，不替换 sk_data_ready 回调，零结构偏移依赖：
 *   - work 启动后进入循环，kernel_recvmsg(flags=0) 阻塞等待数据包
 *     （DGRAM socket 无包时睡眠在 sk_wait_data，不占 CPU）
 *   - 收到包 → 来源过滤 → 处理 → 继续循环
 *   - 卸载时 kernel_sock_shutdown(SHUT_RDWR) 唤醒阻塞的 recvmsg
 *     （返回错误）→ 循环退出
 *   不修改任何内核对象。
 *
 * kpm_mem_freeze_tick 在每次收到请求时刷新一次，冻结刷新频率 = 请求频率。
 */
static void kpm_udp_recv_work(struct kpm_work_struct *work)
{
    (void)work;

    while (g_udp_ready) {
        struct kpm_kvec vec = {
            .iov_base = g_recv_buf,
            .iov_len = sizeof(g_recv_buf)
        };
        struct msghdr msg;
        struct kpm_sockaddr_in client_addr;
        int n;

        /* 内存冻结 tick：收到请求时刷新冻结项 */
        kpm_mem_freeze_tick();

        kpm_udp_memset(&msg, 0, sizeof(msg));
        kpm_udp_memset(&client_addr, 0, sizeof(client_addr));
        msg.msg_name = &client_addr;
        msg.msg_namelen = sizeof(client_addr);

        if (!kf_kernel_recvmsg)
            break;

        /* 阻塞收包（flags=0）：无包时睡眠等待，不占 CPU。
         * 卸载时 shutdown 使此调用返回错误，循环退出。 */
        n = kf_kernel_recvmsg(g_udp_sock, &msg, &vec, 1,
                              sizeof(g_recv_buf), 0);

        if (n <= 0) {
            /* shutdown 或 socket 错误：退出循环（卸载路径） */
            break;
        }

        /* 来源 IP 过滤：发包端必须是内网 IP 且非本机 IP，
         * 否则静默丢弃（不响应，发送端 recvfrom 超时，假装端口未开放） */
        if (!kpm_udp_source_allowed(&client_addr)) {
            kpm_log("LH_udp: drop packet from filtered source\n");
            continue;
        }

        /* 验证包大小：至少包含请求头 */
        if (n >= (int)sizeof(struct kpm_udp_request)) {
            struct kpm_udp_request *req = (struct kpm_udp_request *)g_recv_buf;

            /* data_len 必须同时满足 ≤ 协议上限 且 ≤ 实际收包中携带的数据长度，
             * 防止攻击者声称大 data_len 导致越界读取 g_recv_buf 相邻内存
             * （g_resp_buf 等全局变量） */
            if (req->data_len <= KPM_UDP_MAX_PAYLOAD &&
                req->data_len <= (uint32_t)(n - (int)sizeof(struct kpm_udp_request))) {
                kpm_udp_handle_request(req, &client_addr);
            }
        }
    }
    /* 循环退出（卸载/g_udp_ready=0/socket 错误）后置位退出标志，
     * 供 kpm_udp_exit 非睡眠等待识别。 */
    g_recv_work_done = 1;
}

/* ===== ABI 探测 =====
 * 创建 socket 并 bind 成功后，向 127.0.0.1:9（discard）发 1 字节 UDP
 * 探测包，验证自定义 msghdr/kvec 结构与内核 ABI 兼容：
 *   - kernel_sendmsg 返回 1（发送成功）→ ABI 兼容，继续启动收发
 *   - 返回 <0 → ABI 不兼容（老内核 msghdr/iov_iter 布局差异），
 *     禁用 UDP 不崩溃（prctl 通道不受影响）
 * 安全性：iov_iter 全版本（5.4-6.x）均 40B，__reserved[88] 覆盖
 * offset 16..103 余量充足；探测包仅 1 字节发往本机回环，无副作用。
 * （kernel_sendmsg 内部经 iov_iter_kvec 构造 msg_iter，调用者只需
 *   设置 msg_name/msg_namelen，见 LH_udp.h 注释。） */
static int kpm_udp_probe_abi(void)
{
    struct kpm_sockaddr_in daddr;
    struct msghdr msg;
    struct kpm_kvec vec;
    char byte = 'K';
    int r;

    if (!kf_kernel_sendmsg || !g_udp_sock)
        return -1;

    kpm_udp_memset(&daddr, 0, sizeof(daddr));
    daddr.sin_family = KPM_AF_INET;
    daddr.sin_port = kpm_htons(9);            /* discard 端口 */
    daddr.sin_addr = 0x7f000001;              /* 127.0.0.1 网络序 */

    kpm_udp_memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&daddr;
    msg.msg_namelen = sizeof(daddr);

    kpm_udp_memset(&vec, 0, sizeof(vec));
    vec.iov_base = &byte;
    vec.iov_len = 1;

    r = kf_kernel_sendmsg(g_udp_sock, &msg, &vec, 1, 1);
    kpm_log("LH_udp: ABI probe sendmsg(127.0.0.1:9,1B) -> %d %s\n", r,
            r == 1 ? "ABI OK" : "ABI MISMATCH");
    kpm_printk("LH_debug: udp ABI probe sendmsg -> %d\n", r);
    return (r == 1) ? 0 : -1;
}

/* ===== 初始化 ===== */

int kpm_udp_init(int port)
{
    struct kpm_sockaddr_in addr;
    int ret;

    kpm_log("LH_udp: init, port=%d\n", port > 0 ? port : KPM_UDP_DEFAULT_PORT);
    kpm_printk("LH_debug: udp_init entered, port=%d\n", port > 0 ? port : KPM_UDP_DEFAULT_PORT);

    if (port > 0)
        g_udp_port = port;
    else
        g_udp_port = KPM_UDP_DEFAULT_PORT;

    /* 1. 检查必需的符号（flush_workqueue 可选，仅 exit 时用）
     * socket 创建：sock_create_kern（5 参数）或 sock_create（4 参数回退）任一可用即可；
     * init_net 仅 sock_create_kern 路径需要。 */
    if ((!kf_sock_create_kern && !kf_sock_create) || !kf_sock_release ||
        !kf_kernel_bind || !kf_kernel_recvmsg || !kf_kernel_sendmsg ||
        !kf_kernel_sock_shutdown || !kf_alloc_workqueue || !kf_destroy_workqueue ||
        !kf_queue_work || (kf_sock_create_kern && !kf_init_net)) {
        kpm_log("LH_udp: missing symbols, UDP disabled "
                "(sock_create=%p sock_create_kern=%p bind=%p recv=%p send=%p "
                "shutdown=%p wq_alloc=%p wq_destroy=%p queue=%p flush=%p init_net=%p)\n",
                kf_sock_create, kf_sock_create_kern, kf_kernel_bind, kf_kernel_recvmsg,
                kf_kernel_sendmsg, kf_kernel_sock_shutdown,
                kf_alloc_workqueue, kf_destroy_workqueue, kf_queue_work,
                kf_flush_workqueue, kf_init_net);
        kpm_printk("LH_debug: udp_init - missing symbols, returning\n");
        return -KPM_E_NOTFOUND;
    }
    if (!kf_flush_workqueue) {
        kpm_log("LH_udp: flush_workqueue not found, exit will skip flush (non-fatal)\n");
    }
    kpm_printk("LH_debug: udp_init step1 - symbols OK\n");

    /* 1b. 加载本机 IPv4 地址列表（来源 IP 过滤用）
     * 失败时降级为仅排除回环地址 */
    kpm_udp_load_local_ips();

    /* 2. 创建内核 UDP socket（优先 sock_create_kern，回退 sock_create） */
    if (kf_sock_create_kern) {
        kpm_printk("LH_debug: udp_init step2 - calling sock_create_kern\n");
        ret = kf_sock_create_kern(kf_init_net, KPM_AF_INET, KPM_SOCK_DGRAM,
                                   KPM_IPPROTO_UDP, &g_udp_sock);
    } else {
        kpm_printk("LH_debug: udp_init step2 - calling sock_create (4-arg fallback)\n");
        ret = kf_sock_create(KPM_AF_INET, KPM_SOCK_DGRAM,
                             KPM_IPPROTO_UDP, &g_udp_sock);
    }
    if (ret < 0 || !g_udp_sock) {
        kpm_log("LH_udp: sock_create failed: %d\n", ret);
        g_udp_sock = 0;
        kpm_printk("LH_debug: udp_init - sock_create failed: %d\n", ret);
        return -KPM_E_NOMEM;
    }
    kpm_printk("LH_debug: udp_init step2 - sock_create OK, sock=%p\n", g_udp_sock);

    /* 3. 绑定端口 */
    kpm_udp_memset(&addr, 0, sizeof(addr));
    addr.sin_family = KPM_AF_INET;
    addr.sin_port = kpm_htons((uint16_t)g_udp_port);
    addr.sin_addr = 0;  /* INADDR_ANY */

    kpm_printk("LH_debug: udp_init step3 - calling kernel_bind\n");
    ret = kf_kernel_bind(g_udp_sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        kpm_log("LH_udp: bind failed: %d\n", ret);
        kf_sock_release(g_udp_sock);
        g_udp_sock = 0;
        kpm_printk("LH_debug: udp_init - bind failed: %d\n", ret);
        return -KPM_E_FAULT;
    }
    kpm_printk("LH_debug: udp_init step3 - bind OK\n");

    /* 3b. ABI 探测：发 1B 回环探测包验证自定义 msghdr/kvec 布局
     * 与内核 ABI 兼容。失败 → 禁用 UDP（不崩溃），prctl 通道不受影响。 */
    kpm_printk("LH_debug: udp_init step3b - ABI probe\n");
    if (kpm_udp_probe_abi() != 0) {
        kpm_log("LH_udp: ABI probe failed, UDP disabled (prctl channel still works)\n");
        kpm_printk("LH_debug: udp_init - ABI probe failed, UDP disabled\n");
        kf_sock_release(g_udp_sock);
        g_udp_sock = 0;
        return -KPM_E_NOTFOUND;
    }
    kpm_printk("LH_debug: udp_init step3b - ABI probe OK\n");

    /* 4. 创建 workqueue 并初始化 work（阻塞收包模式，无 sk_data_ready
     *    回调替换） */
    kpm_printk("LH_debug: udp_init step4 - creating workqueue\n");
    /* max_active 取 2：recv work 阻塞在 recvmsg 时，单并发 wq 无法执行
     * 触摸事件推送 work（永远排队）。提高并发度让 push work 可运行；
     * push 仅读记录缓冲 + 非阻塞发送，与 recv work 无共享静态缓冲冲突。 */
    g_udp_wq = kf_alloc_workqueue("LH_udp", KPM_WQ_UNBOUND, 2);
    if (!g_udp_wq) {
        kpm_log("LH_udp: alloc_workqueue failed\n");
        kpm_printk("LH_debug: udp_init - alloc_workqueue failed\n");
        kf_sock_release(g_udp_sock);
        g_udp_sock = 0;
        return -KPM_E_NOMEM;
    }
    kpm_printk("LH_debug: udp_init step4 - workqueue created OK\n");

    /* 5. 启动阻塞收包 work：queue_work 一次，work 内部 while(g_udp_ready)
     *    循环阻塞收包，无需事件驱动回调 */
    kpm_init_work(&g_recv_work, kpm_udp_recv_work);
    g_work_active = 1;
    g_udp_ready = 1;
    g_recv_work_done = 0;   /* 重置退出标志，供卸载非睡眠等待 */
    kpm_set_state(KPM_STATE_UDP_OK);

    kf_queue_work(0, g_udp_wq, &g_recv_work);
    kpm_log("LH_udp: recv work queued (blocking loop)\n");
    kpm_printk("LH_debug: udp_init step5 - recv work queued\n");

    /* 触摸事件推送 work 初始化（事件驱动，仅在会话活跃时被唤醒） */
    kpm_init_work(&g_tvpush_work, kpm_udp_tvpush_work);

    kpm_log("LH_udp: ready, port=%d (blocking recv, no callback replacement)\n",
            g_udp_port);
    kpm_printk("LH_debug: udp_init complete, port=%d\n", g_udp_port);
    return 0;
}

/* ===== 触摸事件流式推送 =====
 * 架构：事件驱动推送 —— hook 记录触摸事件（kpm_tvrecord）后调用
 * kpm_udp_tvpush_wakeup 唤醒 push work（无定时器/忙等）；push work 增量
 * 读取缓冲并 UDP 主动推送给客户端。客户端每 5s PING 保活，>15s 无 ping
 * 自动停止推送（防孤儿会话）。事件数据走数据报流，不写 kpm_log
 * （日志仅保留 DOWN/UP 关键事件）。 */
#define KPM_TVPUSH_MAX_PING_GAP_NS  15000000000ULL   /* 15s */
#define KPM_TVPUSH_MAX_EVENTS       32               /* 每报事件数（32×24=768B+头<MTU） */

static volatile int g_tvpush_active = 0;
static volatile int g_tvpush_pending = 0;
static volatile uint64_t g_tvpush_last_ping = 0;     /* CNTPCT ns */
static uint64_t g_tvpush_sent = 0;                   /* 已推送序号 */
static uint32_t g_tvpush_session = 0;
static struct kpm_sockaddr_in g_tvpush_client;
/* g_tvpush_client 的访问锁。
 * workqueue 是 KPM_WQ_UNBOUND/max_active=2 —— recv_work 与 tvpush_work
 * **可以并发**，而会话地址在 recv_work（tvstream_start）里写、在
 * tvpush_work 里读：半更新状态下推送会发到错误地址（后果是数据报被丢弃，
 * 不崩，但仍属未定义行为）。读写两侧各自取本地副本，锁内只做结构体拷贝。 */
static kpm_spinlock_t g_tvpush_cli_lock = KPM_SPINLOCK_INIT;

static uint64_t kpm_udp_tvtime_ns(void)
{
    uint64_t cnt, freq;
    asm volatile("mrs %0, cntpct_el0" : "=r"(cnt));
    asm volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    if (!freq) return 0;
    return (cnt * 1000000000ULL) / freq;
}

/* 事件到达唤醒（kpm_tvrecord 末尾调用；hook IRQ 上下文 —— queue_work
 * 可从中断上下文安全调用，只做链表插入 + wake_up）。
 * 加 g_udp_ready 检查（wq 拆除期间拒收，防 queue_work 到已销毁 wq 的 UAF）。
 * 不需要 CAS：queue_work() 内部对同一 work 用 test_and_set_bit(PENDING) 判重，
 * 已在队列中/正在执行时重复调用直接返回 false，天然幂等。 */
void kpm_udp_tvpush_wakeup(void)
{
    if (!g_tvpush_active || !g_udp_ready)
        return;
    if (kf_queue_work == 0 || g_udp_wq == 0)
        return;
    /* 只是"有活要干"的标志（供诊断/观测），入队本身由 queue_work 幂等保证 */
    g_tvpush_pending = 1;
    kf_queue_work(0, g_udp_wq, &g_tvpush_work);
}

/* 推送 work：读增量 → 打包 dgram → 发送；有新事件则自排继续 */
static void kpm_udp_tvpush_work(struct kpm_work_struct *work)
{
    uint8_t buf[KPM_TVPUSH_MAX_EVENTS * 24];
    uint64_t now, gap;

    (void)work;
    g_tvpush_pending = 0;

    if (!g_tvpush_active || !g_udp_ready) {
        g_tvpush_pending = 0;
        return;
    }

    /* 保活检查：>15s 无 ping → 停推 */
    now = kpm_udp_tvtime_ns();
    gap = (now > g_tvpush_last_ping) ? (now - g_tvpush_last_ping)
                                     : 0ULL;
    if (gap > KPM_TVPUSH_MAX_PING_GAP_NS) {
        g_tvpush_active = 0;
        kpm_log("LH_udp: tvpush timeout (no ping), session stopped\n");
        return;
    }

    /* 增量读取 */
    {
        uint64_t next = g_tvpush_sent;
        struct kpm_sockaddr_in cli;
        int n = kpm_tvrecord_fetch(g_tvpush_sent, KPM_TVPUSH_MAX_EVENTS,
                                   buf, &next);
        /* 锁内只做一次结构体拷贝（会话地址可能正被 recv_work 的
         * tvstream_start 改写；见 g_tvpush_cli_lock 注释） */
        kpm_spin_lock(&g_tvpush_cli_lock);
        cli = g_tvpush_client;
        kpm_spin_unlock(&g_tvpush_cli_lock);

        if (n > 0) {
            uint32_t start_seq = (uint32_t)(g_tvpush_sent & 0xFFFFFFFFu);
            int sr = kpm_udp_stream_send_dgram(&cli,
                                               g_tvpush_session,
                                               start_seq, buf,
                                               (uint32_t)(n * 24));
            (void)sr;   /* 流式发送结果由客户端看门狗重发兜底，此处忽略 */
            g_tvpush_sent = next;
        }
        /* 还有未推送事件 → 自排继续（防止单次 work 处理量过小） */
        if (g_tvpush_sent < kpm_tvrecord_total() &&
            g_tvpush_active) {
            if (kf_queue_work && g_udp_wq) {
                g_tvpush_pending = 1;
                kf_queue_work(0, g_udp_wq, &g_tvpush_work);
            }
        }
    }
}

/* START：建立推送会话（记录源地址 + 启动记录），返回 0 */
int kpm_udp_tvstream_start(struct kpm_sockaddr_in *client, int src_mask)
{
    if (!client)
        return -KPM_E_INVAL;
    g_tvpush_active = 0;
    kpm_tvrecord_stop();
    /* 新会话：重置记录与推送序号 */
    kpm_tvrecord_start(src_mask ? src_mask : 3);
    g_tvpush_sent = 0;
    g_tvpush_session = (g_tvpush_session + 1) & 0xFFFFFFFFu;
    /* 会话地址锁内改写：tvpush_work 可能与本函数（recv_work）并发
     * （wq max_active=2），锁外半更新的地址会让推送发错目标 */
    kpm_spin_lock(&g_tvpush_cli_lock);
    g_tvpush_client = *client;
    kpm_spin_unlock(&g_tvpush_cli_lock);
    g_tvpush_last_ping = kpm_udp_tvtime_ns();
    g_tvpush_active = 1;
    g_tvpush_pending = 0;
    kpm_log("LH_udp: tvstream start (src_mask=%d session=%u)\n",
            src_mask ? src_mask : 3, g_tvpush_session);
    return 0;
}

/* PING：保活刷新，返回 0=会话活跃 / -KPM_E_BUSY=未启动 */
int kpm_udp_tvstream_ping(void)
{
    if (!g_tvpush_active)
        return -KPM_E_BUSY;
    g_tvpush_last_ping = kpm_udp_tvtime_ns();
    return 0;
}

/* STOP：停止推送与记录 */
int kpm_udp_tvstream_stop(void)
{
    g_tvpush_active = 0;
    g_tvpush_pending = 0;
    kpm_tvrecord_stop();
    kpm_log("LH_udp: tvstream stopped\n");
    return 0;
}

/* ===== 退出（安全卸载时序） =====
 *
 * 严格执行以下顺序，任何错乱都可能导致 use-after-free panic：
 *   1. kernel_sock_shutdown 停止收包（唤醒阻塞在 recvmsg 的 work）
 *   2. flush_workqueue 等待 work 退出循环（防止 work 访问已释放的 socket）
 *   3. sock_release 释放 socket
 *   4. destroy_workqueue 释放工作队列
 *   （无 sk_data_ready 回调替换，无需恢复步骤）
 */
void kpm_udp_exit(void)
{
    kpm_log("LH_udp: exit begin\n");

    if (!g_udp_ready) {
        kpm_log("LH_udp: not initialized, skipping exit\n");
        return;
    }

    g_udp_ready = 0;
    g_work_active = 0;
    /* 触摸推送会话停止（防 push work 访问已释放的 socket） */
    g_tvpush_active = 0;
    g_tvpush_pending = 0;
    kpm_clear_state(KPM_STATE_UDP_OK);

    /* 1. 停止收包：shutdown 使阻塞在 kernel_recvmsg 的 work 返回错误退出循环 */
    if (g_udp_sock && kf_kernel_sock_shutdown) {
        kf_kernel_sock_shutdown(g_udp_sock, 2 /* SHUT_RDWR */);
        kpm_log("LH_udp: sock shutdown done\n");
    }

    /* 2. 等待 work 完成 —— 非睡眠有界自旋。KPM_EXIT 在 RCU 读临界区内调用，
     *    异常上下文不能睡眠，故轮询 g_recv_work_done（recv_work 循环退出后置位），
     *    全程不睡眠；超时则记录并继续（socket 已 shutdown 无引用，残留 work
     *    在 wq 销毁后自然终止，仅损失一次日志）。 */
    if (g_udp_wq) {
        unsigned long spins = 0;
        while (!g_recv_work_done && spins++ < 200000000UL)  /* ~2s 上限 */
            asm volatile("yield" ::: "memory");
        if (g_recv_work_done)
            kpm_log("LH_udp: recv work drained (non-sleep)\n");
        else
            kpm_log("LH_udp: recv work not drained in time (leak)\n");
    }

    /* 3. 释放 socket */
    if (g_udp_sock && kf_sock_release) {
        kf_sock_release(g_udp_sock);
        g_udp_sock = 0;
        kpm_log("LH_udp: socket released\n");
    }

    /* 4. 销毁工作队列。destroy_workqueue 内部会等待 worker 线程退出（可睡眠）；
     * 此处 work 已确认退出（g_recv_work_done），destroy 几乎立即完成。
     * 本调用保留以释放 wq 内存。 */
    if (g_udp_wq && kf_destroy_workqueue) {
        kf_destroy_workqueue(g_udp_wq);
        g_udp_wq = 0;
        kpm_log("LH_udp: workqueue destroyed\n");
    }

    kpm_log("LH_udp: exit done\n");
}

int kpm_udp_is_ready(void)
{
    return g_udp_ready;
}

int kpm_udp_get_port(void)
{
    return g_udp_port;
}
