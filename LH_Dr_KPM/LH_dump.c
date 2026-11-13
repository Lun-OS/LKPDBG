/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_dump.c - 内存 dump 子模块（协议化传输版）
 *
 * 将指定进程的指定模块从内存重建为 ELF（脱壳/IDA 分析用），
 * 数据经 UDP 分块回传，块级 CRC32 + 整体 SHA256 双重校验。
 *
 * 架构（3 阶段会话）：
 *   - DUMP_BEGIN(0x1153): arg2=pid, data=模块名 → 解析 ELF 头/phdr，
 *     建立会话，返回 kpm_dump_hdr_t（含 Module/Base/Size 三信息 + 分块参数）。
 *   - DUMP_FETCH(0x1154):  arg2=offset → 从目标进程内存读取该偏移处数据，
 *     返回 kpm_dump_chunk_t + data（≤KPM_DUMP_CHUNK_MAX）。未驻留页补零并计数。
 *   - DUMP_END(0x1155):    结束会话，返回 kpm_dump_done_t（整体 SHA256）。
 *
 * 设计约束：
 *   - 队列语义：同一时间仅允许一个 dump 会话（busy 互斥）。
 *   - 纯内存读取：kpm_mem_read_kernel（页表遍历 + DMA/WB），无 VFS 痕迹。
 *   - 无内核态文件操作（规避 Android SELinux 对 kernel 域写文件的限制）。
 *   - 防泄漏/溢出：会话状态用静态全局（无动态分配）；所有缓冲固定大小；
 *     offset/length 逐级校验；SHA256/CRC32 无堆分配。
 *
 * 隐蔽性：读路径无用户态痕迹（页表遍历，不置 PTE AF、不触发缺页可观测
 *   路径）；未驻留页补零不产生任何用户态事件。
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <kputils.h>
#include <ksyms.h>
#include <baselib.h>
#include <linux/err.h>   /* IS_ERR_OR_NULL */

#include "LH_comm.h"
#include "LH_dump.h"
#include "LH_syms.h"
#include "LH_mem_rw.h"
#include "LH_proc.h"
#include "LH_log.h"
#include "LH_utils.h"
#include "LH_udp.h"

/* ===== ELF64 结构（本地定义，避免依赖缺失头文件） ===== */

struct kd_elf64_ehdr {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct kd_elf64_phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

/* 32 位 ELF program header（Elf32_Phdr，32 字节） */
struct kd_elf32_phdr {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
};

/* ===== SHA256（轻量实现，无动态分配） ===== */

typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t  buf[64];
    int      buflen;
} kd_sha256_ctx;

#define KD_ROTR32(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))

static const uint32_t kd_sha256_k[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

static void kd_sha256_transform(kd_sha256_ctx *ctx, const uint8_t *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = KD_ROTR32(w[i-15], 7) ^ KD_ROTR32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = KD_ROTR32(w[i-2], 17) ^ KD_ROTR32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = ctx->h[0]; b = ctx->h[1]; c = ctx->h[2]; d = ctx->h[3];
    e = ctx->h[4]; f = ctx->h[5]; g = ctx->h[6]; h = ctx->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = KD_ROTR32(e, 6) ^ KD_ROTR32(e, 11) ^ KD_ROTR32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + kd_sha256_k[i] + w[i];
        uint32_t S0 = KD_ROTR32(a, 2) ^ KD_ROTR32(a, 13) ^ KD_ROTR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

static void kd_sha256_init(kd_sha256_ctx *ctx)
{
    ctx->h[0] = 0x6a09e667U; ctx->h[1] = 0xbb67ae85U;
    ctx->h[2] = 0x3c6ef372U; ctx->h[3] = 0xa54ff53aU;
    ctx->h[4] = 0x510e527fU; ctx->h[5] = 0x9b05688cU;
    ctx->h[6] = 0x1f83d9abU; ctx->h[7] = 0x5be0cd19U;
    ctx->len = 0; ctx->buflen = 0;
}

static void kd_sha256_update(kd_sha256_ctx *ctx, const uint8_t *data, int len)
{
    ctx->len += (uint64_t)len;
    while (len > 0) {
        int need = 64 - ctx->buflen;
        int take = (len < need) ? len : need;
        lib_memcpy(ctx->buf + ctx->buflen, data, (size_t)take);
        ctx->buflen += take; data += take; len -= take;
        if (ctx->buflen == 64) {
            kd_sha256_transform(ctx, ctx->buf);
            ctx->buflen = 0;
        }
    }
}

static void kd_sha256_final(kd_sha256_ctx *ctx, uint8_t out[32])
{
    uint64_t bits = ctx->len << 3;
    uint8_t pad = 0x80;
    int i;

    kd_sha256_update(ctx, &pad, 1);
    pad = 0;
    while (ctx->buflen != 56) {
        kd_sha256_update(ctx, &pad, 1);
        if (ctx->buflen == 64)
            break;  /* 已满则 transform 后 buflen=0，继续填充到 56 */
    }
    /* 追加 64 位长度（大端） */
    for (i = 7; i >= 0; i--)
        kd_sha256_update(ctx, (const uint8_t *)&bits + i, 1);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(ctx->h[i] >> 24);
        out[i*4+1] = (uint8_t)(ctx->h[i] >> 16);
        out[i*4+2] = (uint8_t)(ctx->h[i] >> 8);
        out[i*4+3] = (uint8_t)ctx->h[i];
    }
}

/* ===== CRC32（查表法，无动态分配） ===== */

static uint32_t kd_crc32(const uint8_t *data, int len)
{
    /* 编译期生成的 CRC32 表（多项式 0xEDB88320），无运行时初始化竞态 */
    static const uint32_t table[256] = {
        0x00000000U,0x77073096U,0xee0e612cU,0x990951baU,0x076dc419U,0x706af48fU,0xe963a535U,0x9e6495a3U,
        0x0edb8832U,0x79dcb8a4U,0xe0d5e91eU,0x97d2d988U,0x09b64c2bU,0x7eb17cbdU,0xe7b82d07U,0x90bf1d91U,
        0x1db71064U,0x6ab020f2U,0xf3b97148U,0x84be41deU,0x1adad47dU,0x6ddde4ebU,0xf4d4b551U,0x83d385c7U,
        0x136c9856U,0x646ba8c0U,0xfd62f97aU,0x8a65c9ecU,0x14015c4fU,0x63066cd9U,0xfa0f3d63U,0x8d080df5U,
        0x3b6e20c8U,0x4c69105eU,0xd56041e4U,0xa2677172U,0x3c03e4d1U,0x4b04d447U,0xd20d85fdU,0xa50ab56bU,
        0x35b5a8faU,0x42b2986cU,0xdbbbc9d6U,0xacbcf940U,0x32d86ce3U,0x45df5c75U,0xdcd60dcfU,0xabd13d59U,
        0x26d930acU,0x51de003aU,0xc8d75180U,0xbfd06116U,0x21b4f4b5U,0x56b3c423U,0xcfba9599U,0xb8bda50fU,
        0x2802b89eU,0x5f058808U,0xc60cd9b2U,0xb10be924U,0x2f6f7c87U,0x58684c11U,0xc1611dabU,0xb6662d3dU,
        0x76dc4190U,0x01db7106U,0x98d220bcU,0xefd5102aU,0x71b18589U,0x06b6b51fU,0x9fbfe4a5U,0xe8b8d433U,
        0x7807c9a2U,0x0f00f934U,0x9609a88eU,0xe10e9818U,0x7f6a0dbbU,0x086d3d2dU,0x91646c97U,0xe6635c01U,
        0x6b6b51f4U,0x1c6c6162U,0x856530d8U,0xf262004eU,0x6c0695edU,0x1b01a57bU,0x8208f4c1U,0xf50fc457U,
        0x65b0d9c6U,0x12b7e950U,0x8bbeb8eaU,0xfcb9887cU,0x62dd1ddfU,0x15da2d49U,0x8cd37cf3U,0xfbd44c65U,
        0x4db26158U,0x3ab551ceU,0xa3bc0074U,0xd4bb30e2U,0x4adfa541U,0x3dd895d7U,0xa4d1c46dU,0xd3d6f4fbU,
        0x4369e96aU,0x346ed9fcU,0xad678846U,0xda60b8d0U,0x44042d73U,0x33031de5U,0xaa0a4c5fU,0xdd0d7cc9U,
        0x5005713cU,0x270241aaU,0xbe0b1010U,0xc90c2086U,0x5768b525U,0x206f85b3U,0xb966d409U,0xce61e49fU,
        0x5edef90eU,0x29d9c998U,0xb0d09822U,0xc7d7a8b4U,0x59b33d17U,0x2eb40d81U,0xb7bd5c3bU,0xc0ba6cadU,
        0xedb88320U,0x9abfb3b6U,0x03b6e20cU,0x74b1d29aU,0xead54739U,0x9dd277afU,0x04db2615U,0x73dc1683U,
        0xe3630b12U,0x94643b84U,0x0d6d6a3eU,0x7a6a5aa8U,0xe40ecf0bU,0x9309ff9dU,0x0a00ae27U,0x7d079eb1U,
        0xf00f9344U,0x8708a3d2U,0x1e01f268U,0x6906c2feU,0xf762575dU,0x806567cbU,0x196c3671U,0x6e6b06e7U,
        0xfed41b76U,0x89d32be0U,0x10da7a5aU,0x67dd4accU,0xf9b9df6fU,0x8ebeeff9U,0x17b7be43U,0x60b08ed5U,
        0xd6d6a3e8U,0xa1d1937eU,0x38d8c2c4U,0x4fdff252U,0xd1bb67f1U,0xa6bc5767U,0x3fb506ddU,0x48b2364bU,
        0xd80d2bdaU,0xaf0a1b4cU,0x36034af6U,0x41047a60U,0xdf60efc3U,0xa867df55U,0x316e8eefU,0x4669be79U,
        0xcb61b38cU,0xbc66831aU,0x256fd2a0U,0x5268e236U,0xcc0c7795U,0xbb0b4703U,0x220216b9U,0x5505262fU,
        0xc5ba3bbeU,0xb2bd0b28U,0x2bb45a92U,0x5cb36a04U,0xc2d7ffa7U,0xb5d0cf31U,0x2cd99e8bU,0x5bdeae1dU,
        0x9b64c2b0U,0xec63f226U,0x756aa39cU,0x026d930aU,0x9c0906a9U,0xeb0e363fU,0x72076785U,0x05005713U,
        0x95bf4a82U,0xe2b87a14U,0x7bb12baeU,0x0cb61b38U,0x92d28e9bU,0xe5d5be0dU,0x7cdcefb7U,0x0bdbdf21U,
        0x86d3d2d4U,0xf1d4e242U,0x68ddb3f8U,0x1fda836eU,0x81be16cdU,0xf6b9265bU,0x6fb077e1U,0x18b74777U,
        0x88085ae6U,0xff0f6a70U,0x66063bcaU,0x11010b5cU,0x8f659effU,0xf862ae69U,0x616bffd3U,0x166ccf45U,
        0xa00ae278U,0xd70dd2eeU,0x4e048354U,0x3903b3c2U,0xa7672661U,0xd06016f7U,0x4969474dU,0x3e6e77dbU,
        0xaed16a4aU,0xd9d65adcU,0x40df0b66U,0x37d83bf0U,0xa9bcae53U,0xdebb9ec5U,0x47b2cf7fU,0x30b5ffe9U,
        0xbdbdf21cU,0xcabac28aU,0x53b39330U,0x24b4a3a6U,0xbad03605U,0xcdd70693U,0x54de5729U,0x23d967bfU,
        0xb3667a2eU,0xc4614ab8U,0x5d681b02U,0x2a6f2b94U,0xb40bbe37U,0xc30c8ea1U,0x5a05df1bU,0x2d02ef8dU
    };
    uint32_t crc = 0xFFFFFFFFU;
    int i;

    for (i = 0; i < len; i++)
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFU;
}

/* ===== 会话状态（静态全局，无动态分配，防泄漏） ===== */

#define KD_MAX_PHDRS  16
#define KD_MAX_LOAD   8

/* 小端读取（memcpy 防未对齐；ARM64 小端字节序） */
static inline uint16_t kd_le16(const uint8_t *p)
{ uint16_t v; lib_memcpy(&v, p, 2); return v; }
static inline uint32_t kd_le32(const uint8_t *p)
{ uint32_t v; lib_memcpy(&v, p, 4); return v; }
static inline uint64_t kd_le64(const uint8_t *p)
{ uint64_t v; lib_memcpy(&v, p, 8); return v; }

typedef struct {
    int      busy;             /* 会话占用标志 */
    int      init;             /* BEGIN 填充会话字段中（FETCH 拒绝） */
    pid_t    pid;              /* 目标进程 */
    uint64_t base;             /* 模块加载基址 */
    uint64_t total_size;       /* dump 总大小（含 bss 补零） */
    uint64_t missing;          /* 缺失页补零字节数 */
    uint32_t segs;             /* PT_LOAD 段数 */
    uint32_t seg_done;         /* 已读段数 */
    int      is32;             /* 1=32 位 ELF, 0=64 位 */
    int      phnum;            /* program header 数量 */
    /* ELF 布局缓存（FETCH 按偏移定位段） */
    uint64_t load_off[KD_MAX_LOAD];   /* p_offset */
    uint64_t load_vaddr[KD_MAX_LOAD]; /* p_vaddr */
    uint64_t load_fsz[KD_MAX_LOAD];   /* p_filesz */
    uint64_t load_msz[KD_MAX_LOAD];   /* p_memsz */
    int      load_count;
    /* 完整性校验 */
    kd_sha256_ctx sha;
    kpm_spinlock_t lock;
    /* 会话活跃时间戳（ARM64 CNTPCT ticks）。客户端异常退出（未发 DUMP_END）
     * 时会话永久 BUSY，超时自动释放。CNTPCT_EL0/CNTFRQ_EL0 为架构寄存器，
     * 无内核符号依赖、无系统修改，符合项目隐蔽性原则。 */
    uint64_t last_activity;
} kd_session_t;

static kd_session_t g_dump_sess;

/* 架构时间：CNTPCT ticks 与频率（ARMv8 通用定时器，任意异常级别可读） */
static inline uint64_t kd_cntpct(void)
{
    uint64_t t;
    asm volatile("mrs %0, cntpct_el0" : "=r"(t));
    return t;
}
static inline uint64_t kd_cntfrq(void)
{
    uint64_t f;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(f));
    return f;
}
/* dump 会话超时（秒）：超过该时长无 FETCH 活动视为客户端已死，允许抢占 */
#define KD_SESSION_TIMEOUT_SEC  30

/* 读取一段进程内存（封装） */
static long kd_read(pid_t pid, uint64_t vaddr, void *buf, int len)
{
    return kpm_mem_read_kernel(pid, vaddr, buf, len);
}

/* 根据文件偏移定位 LOAD 段（按文件偏移范围匹配，含 bss 扩展区） */
static int kd_find_seg(uint64_t file_off)
{
    int i, best = -1;
    uint64_t best_end = 0;

    for (i = 0; i < g_dump_sess.load_count; i++) {
        uint64_t end = g_dump_sess.load_off[i] + g_dump_sess.load_fsz[i];
        if (file_off >= g_dump_sess.load_off[i] && file_off < end)
            return i;   /* 精确命中文件区（fsz 内） */
        /* bss 扩展区（msz > fsz）：记录为候选（取最小 end，避免重叠段误配） */
        if (g_dump_sess.load_msz[i] > g_dump_sess.load_fsz[i]) {
            uint64_t bss_end = g_dump_sess.load_off[i] + g_dump_sess.load_msz[i];
            if (file_off >= (g_dump_sess.load_off[i] + g_dump_sess.load_fsz[i]) &&
                file_off < bss_end && (best < 0 || bss_end < best_end)) {
                best = i;
                best_end = bss_end;
            }
        }
    }
    return best;   /* bss 区命中或 -1 */
}

/* ===== API：BEGIN（建立会话，解析 ELF） ===== */

long kpm_dump_begin(pid_t pid, const char *modname, int name_len,
                    kpm_dump_hdr_t *out)
{
    kpm_map_entry_t *maps = NULL;
    uint64_t base = 0;
    int i, n;
    int ret = -KPM_E_NOTFOUND;
    unsigned long flags;
    uint8_t ehdr_raw[64];              /* ELF 头裸字节（按 class 解析字段） */
    uint8_t phdr_raw[KD_MAX_PHDRS * 56];  /* 容纳 32/64 位 phdr */
    uint16_t e_phnum16 = 0, e_phentsize16 = 0;
    uint64_t e_phoff64 = 0;

    if (!modname || name_len <= 0 || pid <= 0 || !out)
        return -KPM_E_INVAL;
    if (name_len > KPM_DUMP_MODULE_MAX - 1)
        name_len = KPM_DUMP_MODULE_MAX - 1;

    /* 会话互斥：busy 超时抢占——客户端异常退出未发 DUMP_END 时会话永久
     * BUSY；超过 KD_SESSION_TIMEOUT_SEC 无 FETCH 活动则强制释放旧会话
     * （kd_session_t 无动态分配，直接清标志即可，字段被新 BEGIN 覆盖），
     * 避免 dump 功能卡死。 */
    flags = kpm_spin_lock_irqsave(&g_dump_sess.lock);
    if (g_dump_sess.busy) {
        if (g_dump_sess.last_activity != 0) {
            uint64_t freq = kd_cntfrq();
            uint64_t elapsed = (freq > 0) ?
                (kd_cntpct() - g_dump_sess.last_activity) / freq : 0;
            if (elapsed > KD_SESSION_TIMEOUT_SEC) {
                kpm_log("dump: stale session reclaimed "
                        "(idle=%llus pid=%d)\n",
                        (unsigned long long)elapsed,
                        (int)g_dump_sess.pid);
                g_dump_sess.busy = 0;
                g_dump_sess.init = 0;
                g_dump_sess.last_activity = 0;
            }
        }
        if (g_dump_sess.busy) {
            kpm_spin_unlock_irqrestore(&g_dump_sess.lock, flags);
            return -KPM_E_BUSY;
        }
    }
    g_dump_sess.busy = 1;
    g_dump_sess.init = 1;   /* 填充字段期间拒绝 FETCH */
    g_dump_sess.pid = pid;
    g_dump_sess.last_activity = kd_cntpct();
    kpm_spin_unlock_irqrestore(&g_dump_sess.lock, flags);

    /* 1. 获取模块区域：小步长连续分页（每页 56，offset 连续递增）。
     *    内核 maps 遍历在 offset 大步长(1024)时跳过不稳定，
     *    56 步长连续分页可靠。 */
    maps = (kpm_map_entry_t *)kf_vmalloc(56 * sizeof(kpm_map_entry_t));
    if (!maps) {
        flags = kpm_spin_lock_irqsave(&g_dump_sess.lock);
        g_dump_sess.busy = 0;
        kpm_spin_unlock_irqrestore(&g_dump_sess.lock, flags);
        return -KPM_E_NOMEM;
    }

    /* 2. basename 包含匹配模块名（跨页累计查找，取最小 start 为 base） */
    n = 0;
    base = 0;
    {
        int page;
        for (page = 0; page < 512; page++) {
            int offset = page * 56;
            int rc, k;

            rc = (int)kpm_proc_maps_kernel(pid, maps, 56, offset, 0);
            if (rc <= 0)
                break;   /* 无更多区域 */
            for (k = 0; k < rc && k < 56; k++) {
                if (!maps[k].path[0])
                    continue;
                if (kpm_strstr(maps[k].path, modname)) {
                    if (n == 0 || maps[k].start < base)
                        base = maps[k].start;
                    n++;
                }
            }
            if (rc < 56)
                break;   /* 最后一页 */
        }
    }
    kf_vfree(maps);
    if (n == 0 || base == 0) {
        kpm_log_err("dump begin: module '%s' not found\n", modname);
        goto out_fail;
    }
    kpm_log_info("dump begin: matched base=0x%llx n=%d\n",
            (unsigned long long)base, n);

    /* 3. 读 ELF 头（裸 64 字节，按 class 解析字段，防 32/64 布局错位） */
    if (kd_read(pid, base, ehdr_raw, 64) != 64) {
        kpm_log_err("dump begin: ehdr read fail\n");
        goto out_fail;
    }
    if (ehdr_raw[0] != 0x7F || ehdr_raw[1] != 'E' ||
        ehdr_raw[2] != 'L' || ehdr_raw[3] != 'F' ||
        ehdr_raw[5] != 1) {
        kpm_log_err("dump begin: bad magic class=%d\n", ehdr_raw[4]);
        ret = -KPM_E_INVAL;
        goto out_fail;
    }
    g_dump_sess.is32 = (ehdr_raw[4] == 1) ? 1 : 0;
    if (ehdr_raw[4] != 1 && ehdr_raw[4] != 2) {
        kpm_log_err("dump begin: unsupported class=%d\n", ehdr_raw[4]);
        ret = -KPM_E_INVAL;
        goto out_fail;
    }
    /* 按 class 解析关键字段 */
    if (g_dump_sess.is32) {
        e_phoff64   = kd_le32(ehdr_raw + 28);
        e_phentsize16 = kd_le16(ehdr_raw + 42);
        e_phnum16   = kd_le16(ehdr_raw + 44);
    } else {
        e_phoff64   = kd_le64(ehdr_raw + 32);
        e_phentsize16 = kd_le16(ehdr_raw + 54);
        e_phnum16   = kd_le16(ehdr_raw + 56);
    }
    kpm_log_info("dump begin: class=%d phoff=0x%llx phentsize=%d phnum=%d\n",
            ehdr_raw[4], (unsigned long long)e_phoff64,
            e_phentsize16, e_phnum16);

    /* 4. 读 program headers（按架构选择结构大小） */
    {
        int phentsize = g_dump_sess.is32 ? (int)sizeof(struct kd_elf32_phdr)
                                         : (int)sizeof(struct kd_elf64_phdr);
        uint64_t phoff_min = g_dump_sess.is32 ? 52ULL : 64ULL;
        if (e_phnum16 <= 0 || e_phnum16 > KD_MAX_PHDRS ||
            e_phentsize16 != phentsize ||
            e_phoff64 < phoff_min ||
            e_phoff64 + (uint64_t)e_phnum16 * (uint64_t)phentsize > 0x40000ULL) {
            kpm_log_err("dump begin: phdr check fail phnum=%d phentsize=%d(exp %d) phoff=0x%llx\n",
                    e_phnum16, e_phentsize16, phentsize,
                    (unsigned long long)e_phoff64);
            ret = -KPM_E_INVAL;
            goto out_fail;
        }
        if (kd_read(pid, base + e_phoff64, phdr_raw,
                    (int)((uint64_t)e_phnum16 * (uint64_t)phentsize)) !=
            (long)((uint64_t)e_phnum16 * (uint64_t)phentsize)) {
            kpm_log_err("dump begin: phdr read fail\n");
            goto out_fail;
        }
    }
    g_dump_sess.phnum = e_phnum16;

    /* 5. 计算总大小 + 记录 LOAD 段（统一转 64 位存会话） */
    g_dump_sess.load_count = 0;
    g_dump_sess.total_size = 0;
    g_dump_sess.segs = 0;
    for (i = 0; i < g_dump_sess.phnum; i++) {
        uint64_t p_off, p_vaddr, p_fsz, p_msz;
        uint64_t end;
        int p_type;

        if (g_dump_sess.is32) {
            struct kd_elf32_phdr *p32 = (struct kd_elf32_phdr *)phdr_raw + i;
            p_type = p32->p_type;
            p_off = p32->p_offset;
            p_vaddr = p32->p_vaddr;
            p_fsz = p32->p_filesz;
            p_msz = p32->p_memsz;
        } else {
            struct kd_elf64_phdr *p64 = (struct kd_elf64_phdr *)phdr_raw + i;
            p_type = p64->p_type;
            p_off = p64->p_offset;
            p_vaddr = p64->p_vaddr;
            p_fsz = p64->p_filesz;
            p_msz = p64->p_memsz;
        }
        if (p_type != 1)  /* PT_LOAD */
            continue;
        if (p_fsz > 512ULL * 1024 * 1024 ||
            p_off > 512ULL * 1024 * 1024 ||
            p_msz > 512ULL * 1024 * 1024 ||
            p_vaddr > 0xFFFFFFFFULL ||
            g_dump_sess.load_count >= KD_MAX_LOAD) {
            kpm_log_err("dump begin: load seg fail idx=%d off=0x%llx fsz=0x%llx count=%d\n",
                       i, (unsigned long long)p_off, (unsigned long long)p_fsz,
                       g_dump_sess.load_count);
            ret = -KPM_E_INVAL;
            goto out_fail;
        }
        g_dump_sess.load_off[g_dump_sess.load_count] = p_off;
        g_dump_sess.load_vaddr[g_dump_sess.load_count] = p_vaddr;
        g_dump_sess.load_fsz[g_dump_sess.load_count] = p_fsz;
        g_dump_sess.load_msz[g_dump_sess.load_count] = p_msz;
        g_dump_sess.load_count++;
        g_dump_sess.segs++;
        end = p_off + ((p_msz > p_fsz) ? p_msz : p_fsz);
        if (end > g_dump_sess.total_size)
            g_dump_sess.total_size = end;
    }
    if (g_dump_sess.load_count == 0 || g_dump_sess.total_size == 0) {
        kpm_log("dump begin: no load segments\n");
        ret = -KPM_E_INVAL;
        goto out_fail;
    }

    /* 6. 填充会话（FETCH 依赖 pid/base/load 布局） */
    g_dump_sess.pid = pid;
    g_dump_sess.base = base;
    g_dump_sess.missing = 0;
    g_dump_sess.seg_done = 0;
    kd_sha256_init(&g_dump_sess.sha);
    /* 字段已就绪，允许 FETCH */
    flags = kpm_spin_lock_irqsave(&g_dump_sess.lock);
    g_dump_sess.init = 0;
    kpm_spin_unlock_irqrestore(&g_dump_sess.lock, flags);

    /* 7. 填充 HDR（三信息 + 分块参数） */
    lib_memset(out, 0, sizeof(*out));
    out->magic = KPM_DUMP_MAGIC_HDR;
    out->version = KPM_DUMP_PROTO_VERSION;
    out->base = base;
    out->size = g_dump_sess.total_size;
    {
        int ml = name_len;
        if (ml > KPM_DUMP_MODULE_MAX - 1) ml = KPM_DUMP_MODULE_MAX - 1;
        lib_memcpy(out->module, modname, (size_t)ml);
        out->module[ml] = '\0';
    }
    out->chunk = KPM_DUMP_CHUNK_MAX;
    out->chunks = (uint32_t)((g_dump_sess.total_size + KPM_DUMP_CHUNK_MAX - 1) /
                             KPM_DUMP_CHUNK_MAX);
    out->segs = g_dump_sess.segs;
    out->algo = 1;  /* CRC32 块级 + SHA256 整体 */
    out->missing = 0;
    out->flags = 0;
    return 0;

out_fail:
    flags = kpm_spin_lock_irqsave(&g_dump_sess.lock);
    g_dump_sess.busy = 0;
    g_dump_sess.init = 0;
    g_dump_sess.last_activity = 0;
    kpm_spin_unlock_irqrestore(&g_dump_sess.lock, flags);
    return ret;
}

/* ===== API：FETCH（按文件偏移读一块） ===== */

long kpm_dump_fetch(uint64_t file_off, kpm_dump_chunk_t *chunk,
                    uint8_t *data_out, int max_len)
{
    int seg_idx;
    uint64_t seg_off;      /* 段内文件偏移 */
    uint64_t mem_addr;     /* 目标内存地址 */
    uint64_t avail;        /* 本块可读字节 */
    int want, got;
    unsigned long flags;

    if (!chunk || !data_out || max_len <= 0)
        return -KPM_E_INVAL;

    flags = kpm_spin_lock_irqsave(&g_dump_sess.lock);
    if (!g_dump_sess.busy || g_dump_sess.init) {
        kpm_spin_unlock_irqrestore(&g_dump_sess.lock, flags);
        return -KPM_E_NOTFOUND;   /* 无会话或正在初始化 */
    }
    g_dump_sess.last_activity = kd_cntpct();   /* 刷新活跃时间戳 */
    kpm_spin_unlock_irqrestore(&g_dump_sess.lock, flags);

    if (file_off >= g_dump_sess.total_size)
        return -KPM_E_INVAL;

    /* 定位段 */
    seg_idx = kd_find_seg(file_off);
    if (seg_idx < 0) {
        /* 段间空洞：补零（不会发生，LOAD 段连续覆盖，防御性处理） */
        uint64_t end = g_dump_sess.total_size - file_off;
        uint64_t toz = (end > (uint64_t)max_len) ? (uint64_t)max_len : end;
        lib_memset(data_out, 0, (size_t)toz);
        g_dump_sess.missing += toz;
        chunk->magic = KPM_DUMP_MAGIC_CHUNK;
        chunk->offset = (uint32_t)file_off;
        chunk->length = (uint32_t)toz;
        chunk->crc32 = kd_crc32(data_out, (int)toz);
        kd_sha256_update(&g_dump_sess.sha, data_out, (int)toz);
        return (long)toz;
    }

    seg_off = file_off - g_dump_sess.load_off[seg_idx];
    if (seg_off >= g_dump_sess.load_fsz[seg_idx]) {
        /* 纯 BSS 区（msz > fsz）：补零，不读内存 */
        uint64_t bss_avail = g_dump_sess.load_msz[seg_idx] - seg_off;
        uint64_t toz = bss_avail;
        uint64_t end = g_dump_sess.total_size - file_off;
        if (toz > end) toz = end;
        if (toz > (uint64_t)max_len) toz = (uint64_t)max_len;
        lib_memset(data_out, 0, (size_t)toz);
        g_dump_sess.missing += toz;
        chunk->magic = KPM_DUMP_MAGIC_CHUNK;
        chunk->offset = (uint32_t)file_off;
        chunk->length = (uint32_t)toz;
        chunk->crc32 = kd_crc32(data_out, (int)toz);
        kd_sha256_update(&g_dump_sess.sha, data_out, (int)toz);
        return (long)toz;
    }
    mem_addr = g_dump_sess.base + g_dump_sess.load_vaddr[seg_idx] + seg_off;
    avail = g_dump_sess.load_fsz[seg_idx] - seg_off;
    if (avail == 0) {
        /* 段尾：补零（防御，正常不会到这） */
        uint64_t bss_len = g_dump_sess.load_msz[seg_idx] -
                           g_dump_sess.load_fsz[seg_idx];
        uint64_t toz = bss_len;
        uint64_t end = g_dump_sess.total_size - file_off;
        if (toz > end) toz = end;
        if (toz > (uint64_t)max_len) toz = (uint64_t)max_len;
        lib_memset(data_out, 0, (size_t)toz);
        g_dump_sess.missing += toz;
        chunk->magic = KPM_DUMP_MAGIC_CHUNK;
        chunk->offset = (uint32_t)file_off;
        chunk->length = (uint32_t)toz;
        chunk->crc32 = kd_crc32(data_out, (int)toz);
        kd_sha256_update(&g_dump_sess.sha, data_out, (int)toz);
        return (long)toz;
    }

    want = (avail > (uint64_t)max_len) ? max_len : (int)avail;
    got = (int)kd_read(g_dump_sess.pid, mem_addr, data_out, want);
    if (got < 0) {
        /* 页表遍历失败（未驻留页）：补零到内存页边界。
         * 用 seg_off（段内偏移）而非文件偏移对齐 —— 32 位 ELF 的
         * p_vaddr 常非页对齐，文件偏移与内存页边界不一致会导致
         * 补零长度错位、破坏 ELF 结构。 */
        int pg_left = 4096 - (int)((g_dump_sess.load_vaddr[seg_idx] + seg_off) % 4096);
        if (pg_left > want) pg_left = want;
        if (pg_left <= 0) pg_left = 1;
        lib_memset(data_out, 0, (size_t)pg_left);
        got = pg_left;
        g_dump_sess.missing += (uint64_t)got;
    } else if (got == 0) {
        got = 1;  /* 防御：避免死循环 */
        data_out[0] = 0;
        g_dump_sess.missing++;
    }
    if (got > want) got = want;   /* 防溢出 */

    chunk->magic = KPM_DUMP_MAGIC_CHUNK;
    chunk->offset = (uint32_t)file_off;
    chunk->length = (uint32_t)got;
    chunk->crc32 = kd_crc32(data_out, got);
    kd_sha256_update(&g_dump_sess.sha, data_out, got);
    return (long)got;
}

/* ===== API：END（结束会话，返回整体 SHA256） ===== */

long kpm_dump_end(kpm_dump_done_t *out)
{
    unsigned long flags;

    if (!out)
        return -KPM_E_INVAL;

    flags = kpm_spin_lock_irqsave(&g_dump_sess.lock);
    if (!g_dump_sess.busy || g_dump_sess.init) {
        kpm_spin_unlock_irqrestore(&g_dump_sess.lock, flags);
        return -KPM_E_NOTFOUND;
    }
    kpm_spin_unlock_irqrestore(&g_dump_sess.lock, flags);

    lib_memset(out, 0, sizeof(*out));
    out->magic = KPM_DUMP_MAGIC_DONE;
    out->status = 0;
    out->bytes = g_dump_sess.total_size;
    out->missing = (g_dump_sess.missing > 0xFFFFFFFFULL) ?
                   0xFFFFFFFFU : (uint32_t)g_dump_sess.missing;
    out->flags = (g_dump_sess.missing > 0) ? 1 : 0;
    kd_sha256_final(&g_dump_sess.sha, out->sha256);

    /* 释放会话 */
    flags = kpm_spin_lock_irqsave(&g_dump_sess.lock);
    g_dump_sess.busy = 0;
    g_dump_sess.init = 0;
    g_dump_sess.last_activity = 0;
    kpm_spin_unlock_irqrestore(&g_dump_sess.lock, flags);
    return 0;
}

/* ===== 初始化 / 退出 ===== */

int kpm_dump_init(void)
{
    lib_memset(&g_dump_sess, 0, sizeof(g_dump_sess));
    g_dump_sess.lock.locked = 0;
    kpm_log_info("dump: proto init ok (begin/fetch/end)\n");
    return 0;
}

void kpm_dump_exit(void)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_dump_sess.lock);
    g_dump_sess.busy = 0;
    g_dump_sess.init = 0;
    kpm_spin_unlock_irqrestore(&g_dump_sess.lock, flags);
    kpm_log_info("dump: proto exit\n");
}
