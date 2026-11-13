/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_touch.c - Touch device discovery + TVF V2 Output Layer
 *
 * Responsibilities:
 *   1. Find the touch input device (node offset detection, name matching)
 *   2. Detect screen resolution from input_dev absinfo
 *   3. Output Layer: commit complete MT frames to input subsystem
 *
 * The output layer is the ONLY path that calls kf_input_event.
 * It reads from g_pending_frame (Transaction Buffer) and sends a
 * complete frame in a single SYN_REPORT.
 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <ksyms.h>
#include <kputils.h>
#include <ktypes.h>
#include <pgtable.h>

/* kpm_lib.c 提供，无头文件，此处显式声明 */
extern void *lib_memcpy(void *dst, const void *src, size_t n);

#include "LH_touch.h"
#include "LH_utils.h"
#include "LH_comm.h"
#include "LH_mem_rw.h"   /* kpm_is_safe_kern_addr（DEVAPC 防御） */
#include "LH_syms.h"
#include "LH_log.h"
#include "touch_manager.h"

/* ===== input_dev structure field offsets ===== */
#define INPUT_DEV_NAME_OFF  0

static int g_node_offset = -1;
static void *g_touch_dev = NULL;

/* Screen resolution (from input_dev absinfo, for boundary checks) */
static int g_screen_width = 0;
static int g_screen_height = 0;

/* Touch coordinate scale: hardware_coord = screen_coord * g_touch_scale
 * 动态检测：absinfo.maximum / 实际屏幕宽度 = scale（如 17280/1080=16）
 * 用户 API 使用屏幕像素坐标（1080x2392），驱动内部 ×scale 转为硬件坐标 */
static int g_touch_scale = 1;

/* Injection flag: prevents hook from processing our own injected events */
volatile int g_injecting = 0;
volatile int g_virtual_touch_count = 0;

/* Output layer: previous slot state for tracking_id change detection.
 * Used by tvf_output_commit_frame to implement correct MT Protocol B:
 * only send ABS_MT_TRACKING_ID on DOWN/UP, not on every MOVE frame. */
static int g_prev_tracking_id[MAX_OUTPUT_SLOTS];
static int g_prev_slot_active[MAX_OUTPUT_SLOTS];

/* ===== Safe read helpers ===== */
#define KPM_NODE_SCAN_MAX     8192
#define KPM_NODE_MAX_CAND     64
#define KPM_STR_MAX_LEN       48

/* 指针"可读"校验。
 * copy_from_kernel_nofault 只能捕获翻译错误，拦不住 MTK DEVAPC 硬件
 * 总线监控——必须读取前做物理域/vmalloc 白名单校验（kpm_is_safe_kern_addr：
 * 线性映射区转物理做 kpm_phys_is_safe_ram 校验；非线性仅接受
 * vmalloc_to_page 验证的分配页；ioremap/保护域/无效地址一律拒绝）。 */
static inline int is_safe_kern_ptr(uint64_t addr)
{
    return kpm_is_safe_kern_addr(addr);
}

static int kpm_safe_read_ptr(void *dst, const void *src, unsigned long size)
{
    if (!kf_copy_from_kernel_nofault)
        return 0;  /* 安全函数不可用，拒绝读取（与 safe_list_next 策略一致） */
    return (kf_copy_from_kernel_nofault(dst, src, size) == 0) ? 1 : 0;
}

static int kpm_safe_read_str(char *buf, int bufsize,
                              const char *kaddr, int *actual_len)
{
    int slen;
    char tmp[KPM_STR_MAX_LEN + 1];

    if (!buf || bufsize <= 0 || !kaddr) return 0;

    /* 读字符串前校验目标地址可安全读取——拒绝 ioremap 设备映射 /
     * MTK 保护域 / 无效地址（nofault 拦不住 DEVAPC）。48 字节可能跨页：
     * 起始页与末尾页都需通过校验。 */
    if (!is_safe_kern_ptr((uint64_t)kaddr))
        return 0;
    if ((((uint64_t)kaddr + KPM_STR_MAX_LEN - 1) & ~0xFFFULL) !=
        ((uint64_t)kaddr & ~0xFFFULL)) {
        if (!is_safe_kern_ptr((uint64_t)kaddr + KPM_STR_MAX_LEN - 1))
            return 0;
    }

    if (!kpm_safe_read_ptr(tmp, kaddr, KPM_STR_MAX_LEN)) return 0;

    for (slen = 0; slen < KPM_STR_MAX_LEN; slen++) {
        char c = tmp[slen];
        if (c == 0) break;
        if (c < 0x20 || c > 0x7E) return 0;
    }

    if (slen < 2) return 0;

    if (slen >= bufsize) slen = bufsize - 1;
    {
        int i;
        for (i = 0; i < slen; i++) buf[i] = tmp[i];
        buf[slen] = '\0';
    }
    if (actual_len) *actual_len = slen;
    return 1;
}

/* ===== 安全 list_head 遍历辅助函数 =====
 * 所有 list_head 访问通过 copy_from_kernel_nofault 安全读取，
 * 避免直接解引用可能导致 panic 的内核指针。
 *
 * kv_input_dev_list 语义（由 kpm_syms.c 设置）：
 *   存储 &input_dev_list（变量地址），不存储值
 *   遍历时需通过 safe_list_next 读取 list_head.next 字段
 */

/* 内核地址范围校验（ARM64）
 * 用户空间: 0x0000_0000_0000_0000 ~ 0x0000_FFFF_FFFF_FFFF
 * 内核空间: 0xFFFF_0000_0000_0000 ~ 0xFFFF_FFFF_FFFF_FFFF
 * vmalloc:  0xFFFF_8000_0000_0000 ~ 0xFFFF_BFFF_FFFF_FFFF
 * 注意：0x0 不是有效指针 */
static inline int is_valid_kern_ptr(uint64_t addr)
{
    return addr >= 0xFFFF000000000000ULL;
}

/* 安全读取 list_head 的 next 字段
 * head_addr: list_head 变量的地址（或节点的 node 字段地址）
 * next_addr: 输出 next 字段值
 * 返回: 1 成功且地址有效，0 失败
 * 安全性：通过 copy_from_kernel_nofault 读取，不会 panic */
static int safe_list_next(uint64_t head_addr, uint64_t *next_addr)
{
    if (!head_addr || !is_valid_kern_ptr(head_addr))
        return 0;
    if (!kf_copy_from_kernel_nofault)
        return 0;
    if (kf_copy_from_kernel_nofault(next_addr, (void *)head_addr, 8) != 0)
        return 0;
    /* 校验读出的指针是否在内核地址范围 */
    if (!is_valid_kern_ptr(*next_addr))
        return 0;
    return 1;
}

/* ===== input_dev node offset detection =====
 * 探测 input_dev 结构中 list_head node 字段的偏移
 * 两阶段扫描算法：
 *   Phase 1: 从 first_node 向前扫描，找所有可能是 name 指针的字段
 *   Phase 2: 在 second/third_node 上验证候选偏移
 *
 * 安全性：所有 list_head 访问通过 safe_list_next，
 *         所有字段读取通过 kpm_safe_read_ptr（基于 copy_from_kernel_nofault）。
 *         即使 input_dev_list 未初始化或链表损坏，也不会 panic。 */
static int kpm_detect_node_offset(void)
{
    uint64_t head = kv_input_dev_list;  /* &input_dev_list */
    uint64_t first_node = 0, second_node = 0, third_node = 0;
    uint64_t node;
    int num_nodes = 0;
    int cand[KPM_NODE_MAX_CAND];
    int num_cand = 0;
    int best_offset = -1;
    int best_score = 0;
    char best_name[KPM_STR_MAX_LEN + 1];
    int i, d;
    best_name[0] = '\0';

    if (!head) return -1;

    /* 安全读取前 3 个节点地址（不直接 head->next 解引用） */
    if (!safe_list_next(head, &first_node)) return -1;
    if (first_node == head) return -1;  /* 空链表 */

    num_nodes = 1;
    if (safe_list_next(first_node, &node) && node != head) {
        second_node = node;
        num_nodes = 2;
        if (safe_list_next(second_node, &node) && node != head) {
            third_node = node;
            num_nodes = 3;
        }
    }

    kpm_log("kpm: node addrs: 1st=%llx 2nd=%llx 3rd=%llx (num=%d)\n",
            first_node, second_node, third_node, num_nodes);

    /* Phase 1: 从 first_node 向前扫描，找所有可能是 name 指针的字段 */
    for (i = 0; i < KPM_NODE_SCAN_MAX; i += 8) {
        const char *ptr_val = NULL;
        char name_buf[KPM_STR_MAX_LEN + 1];
        int slen;

        /* 读取源地址 first_node - i 也必须通过 is_safe_kern_ptr 校验：
         * first_node 虽来自内核链表，但探测扫描其前方 8KB 时，若落在
         * 外设映射区，copy_from_kernel_nofault 只拦 page fault、拦不住
         * MTK DEVAPC 硬件总线监控。is_safe_kern_ptr 对线性映射区正常
         * 堆地址通过、外设地址拒绝。 */
        if (!is_safe_kern_ptr((uint64_t)(first_node - i)))
            continue;

        /* 安全读取 first_node - i 处的指针（潜在 name 字段） */
        if (!kpm_safe_read_ptr(&ptr_val,
                               (const void *)(first_node - i),
                               sizeof(ptr_val))) {
            continue;
        }

        if (!ptr_val || !is_safe_kern_ptr((uint64_t)ptr_val))
            continue;

        if (!kpm_safe_read_str(name_buf, sizeof(name_buf), ptr_val, &slen))
            continue;

        if (name_buf[0] == '.') continue;

        kpm_log("kpm: cand offset=%d: \"%s\"\n", i, name_buf);
        if (num_cand < KPM_NODE_MAX_CAND)
            cand[num_cand++] = i;
    }

    kpm_log("kpm: Phase1 found %d candidates\n", num_cand);

    if (num_cand == 0) {
        kpm_log("kpm: no string candidates found (scan range 0-%d)\n",
                KPM_NODE_SCAN_MAX);
        return -1;
    }

    /* Phase 2: 在 second/third_node 上验证候选偏移 */
    for (i = 0; i < num_cand; i++) {
        int offset = cand[i];
        int score = 1;
        uint64_t devs[2];
        char names[3][KPM_STR_MAX_LEN + 1];
        char first_name[KPM_STR_MAX_LEN + 1];
        int is_kobj_name = 0;

        /* 读取 first_node 的 name 字符串 */
        {
            const char *ptr_val = NULL;
            first_name[0] = '\0';
            if (is_safe_kern_ptr((uint64_t)(first_node - offset)) &&
                kpm_safe_read_ptr(&ptr_val,
                                  (const void *)(first_node - offset),
                                  sizeof(ptr_val)) && ptr_val) {
                kpm_safe_read_str(first_name, sizeof(first_name), ptr_val, NULL);
            }
            /* 检测 "inputN" 形式的 kobj 名称（跳过） */
            if (first_name[0] == 'i' && first_name[1] == 'n' &&
                first_name[2] == 'p' && first_name[3] == 'u' &&
                first_name[4] == 't' &&
                first_name[5] >= '0' && first_name[5] <= '9') {
                is_kobj_name = 1;
            }
            { int _j; for (_j = 0; _j < KPM_STR_MAX_LEN && first_name[_j]; _j++) names[0][_j] = first_name[_j]; names[0][_j] = '\0'; }
        }

        devs[0] = second_node;
        devs[1] = third_node;

        for (d = 0; d < 2; d++) {
            const char *ptr_val = NULL;
            char name_buf[KPM_STR_MAX_LEN + 1];
            name_buf[0] = '\0';

            if (!devs[d]) break;

            if (!is_safe_kern_ptr((uint64_t)(devs[d] - offset)))
                goto next_dev;

            if (!kpm_safe_read_ptr(&ptr_val,
                                   (const void *)(devs[d] - offset),
                                   sizeof(ptr_val)))
                goto next_dev;

            if (!ptr_val || !is_safe_kern_ptr((uint64_t)ptr_val))
                goto next_dev;

            if (!kpm_safe_read_str(name_buf, sizeof(name_buf), ptr_val, NULL))
                goto next_dev;

            if (name_buf[0] == '.') goto next_dev;
            score++;
            { int _j; for (_j = 0; _j < KPM_STR_MAX_LEN && name_buf[_j]; _j++) names[d+1][_j] = name_buf[_j]; names[d+1][_j] = '\0'; }
            continue;
next_dev:
            names[d + 1][0] = '\0';
        }

        kpm_log("kpm: Phase2 offset=%d score=%d kobj=%d names=[%s][%s][%s]\n",
                offset, score, is_kobj_name,
                names[0], names[1], names[2]);

        if (is_kobj_name) continue;

        if (score > best_score) {
            best_offset = offset;
            best_score = score;
        }
    }

    if (best_offset < 0) best_offset = cand[0];

    /* 读取最终选定的 first_node name */
    {
        const char *ptr_val = NULL;
        if (kpm_safe_read_ptr(&ptr_val,
                              (const void *)(first_node - best_offset),
                              sizeof(ptr_val)) && ptr_val) {
            kpm_safe_read_str(best_name, sizeof(best_name), ptr_val, NULL);
        }
    }

    g_node_offset = best_offset;
    kpm_log("kpm: detected node offset=%d, score=%d, first=\"%s\"\n",
            best_offset, best_score, best_name);
    return 0;
}

/* ===== Find touch screen device =====
 * 遍历 input_dev_list 链表，按名称/phys 匹配触摸设备
 * 若名称匹配失败，回退到第一个支持 EV_ABS 的设备
 *
 * 安全性：所有 list_head 访问通过 safe_list_next（基于 copy_from_kernel_nofault），
 *         不直接解引用链表指针。
 *         所有字段读取通过 kpm_safe_read_ptr。
 * 循环保护：最多遍历 50 个设备，防止链表循环导致死循环。 */
static void *kpm_find_touch_dev(void)
{
    uint64_t head = kv_input_dev_list;  /* &input_dev_list */
    uint64_t first_node, node;
    int count = 0;
    void *abs_dev = NULL;

    static const char *touch_patterns[] = {
        "touchpanel", "touch",
        "fts", "goodix", "synaptics", "dsx",
        "cyttsp", "atmel_mxt", "ili2", "himax",
        "novatek", "nt36", "gt1x", "gt9",
        "mtk-tpd", "tpd", "fts_ts", "sec_ts",
        NULL
    };

    if (!head || g_node_offset < 0) return NULL;

    /* 安全读取第一个节点地址 */
    if (!safe_list_next(head, &first_node)) return NULL;
    if (first_node == head) return NULL;  /* 空链表 */

    node = first_node;
    do {
        /* dev = node - g_node_offset（input_dev 起始地址） */
        uint64_t dev = node - g_node_offset;
        const char *name_ptr = NULL;
        const char *phys_ptr = NULL;
        char name_buf[KPM_STR_MAX_LEN + 1];
        char phys_buf[KPM_STR_MAX_LEN + 1];
        int has_ev_abs = 0;
        int evbit_off = -1;
        name_buf[0] = '\0';
        phys_buf[0] = '\0';

        /* dev 是 node - g_node_offset 推算出的地址，若 node_offset 探测
         * 错误或链表节点地址异常，dev 可能落在外设映射区/保护域物理地址
         * ——copy_from_kernel_nofault 只拦 page fault、拦不住 MTK DEVAPC。
         * 读取前先对源地址 dev 及 evbit 扫描范围（dev+0 ~ dev+96）做
         * is_safe_kern_ptr 白名单校验。 */
        if (!is_safe_kern_ptr(dev) || !is_safe_kern_ptr(dev + 96))
            goto next_node;

        /* 安全读取 name 指针（偏移 0）和 phys 指针（偏移 8） */
        if (!kpm_safe_read_ptr(&name_ptr, (void *)dev, sizeof(name_ptr)))
            name_ptr = NULL;

        if (!kpm_safe_read_ptr(&phys_ptr, (void *)(dev + 8), sizeof(phys_ptr)))
            phys_ptr = NULL;

        /* 扫描 evbit 字段，检测 EV_ABS 支持 */
        {
            int ei;
            static const int evbit_candidates[] = { 32, 40, 48, 56, 64, 72, 80, 88, 96 };
            for (ei = 0; ei < (int)(sizeof(evbit_candidates) / sizeof(evbit_candidates[0])); ei++) {
                uint64_t val = 0;
                if (kpm_safe_read_ptr(&val, (void *)(dev + evbit_candidates[ei]), sizeof(val))) {
                    if (val & 0x08) {  /* EV_ABS = bit 3 */
                        has_ev_abs = 1;
                        evbit_off = evbit_candidates[ei];
                        break;
                    }
                }
            }
        }

        /* 安全读取 name 和 phys 字符串：name/phys 指针可能指向任意
         * 内核地址（含保护域映射），读取前必须做物理域/vmalloc 白名单
         * 校验（nofault 拦不住 DEVAPC）。 */
        if (name_ptr && is_safe_kern_ptr((uint64_t)name_ptr)) {
            if (!kpm_safe_read_str(name_buf, sizeof(name_buf), name_ptr, NULL))
                name_buf[0] = '\0';
        }
        if (phys_ptr && is_safe_kern_ptr((uint64_t)phys_ptr)) {
            if (!kpm_safe_read_str(phys_buf, sizeof(phys_buf), phys_ptr, NULL))
                phys_buf[0] = '\0';
        }

        kpm_log("kpm: input_dev[%d]: name=%s phys=%s EV_ABS=%d evbit_off=%d\n",
                count,
                name_buf[0] ? name_buf : "(null)",
                phys_buf[0] ? phys_buf : "(null)",
                has_ev_abs, evbit_off);

        /* 名称匹配触摸设备：坐标触摸屏必须支持 EV_ABS（absinfo 才能换算）。
         * "xiaomi-touch" 等触摸特性/手势虚拟设备通常 EV_ABS=0，不是坐标层，
         * 若仅按 "touch" 子串匹配会误中而错过真正的触控 IC（nvt/fts/goodix）。 */
        if (has_ev_abs && (name_buf[0] || phys_buf[0])) {
            int pi;
            const char *check_strs[2];
            check_strs[0] = name_buf[0] ? name_buf : NULL;
            check_strs[1] = phys_buf[0] ? phys_buf : NULL;
            int ci;
            for (ci = 0; ci < 2; ci++) {
                const char *s = check_strs[ci];
                if (!s) continue;
                for (pi = 0; touch_patterns[pi] != NULL; pi++) {
                    if (kpm_strstr(s, touch_patterns[pi])) {
                        kpm_log("kpm: found touch device by name/phys: %s\n",
                                name_buf[0] ? name_buf : phys_buf);
                        return (void *)dev;
                    }
                }
            }
        }

        /* 回退：第一个支持 EV_ABS 的设备 */
        if (!abs_dev && has_ev_abs) {
            abs_dev = (void *)dev;
            kpm_log("kpm: input_dev[%d]: EV_ABS capable, candidate\n", count);
        }

next_node:
        if (++count >= 50) break;  /* 循环保护 */

        /* 安全读取下一个节点 */
        if (!safe_list_next(node, &node)) break;
    } while (node != first_node && node != head);

    if (abs_dev) {
        kpm_log("kpm: using EV_ABS device as touch\n");
        return abs_dev;
    }

    kpm_log("kpm: touch device not found in %d devices\n", count);
    return NULL;
}

/* Simple string contains search */
char *kpm_strstr(const char *s1, const char *s2)
{
    int len2 = 0;
    const char *p;
    if (!s1 || !s2) return NULL;
    while (s2[len2]) len2++;
    if (!len2) return (char *)s1;
    for (p = s1; *p; p++) {
        int i;
        for (i = 0; i < len2; i++) {
            if (p[i] != s2[i]) break;
        }
        if (i == len2) return (char *)p;
    }
    return NULL;
}

/* ===== Output Layer: Commit pending frame to input subsystem =====
 *
 * Reads from g_pending_frame[] (Transaction Buffer) and sends a
 * complete MT Protocol B frame in a single SYN_REPORT.
 *
 * Only dirty slots are sent. For each slot:
 *   - active=1 (DOWN/MOVE): send TRACKING_ID + coordinates
 *   - active=0 (UP): send TRACKING_ID=-1
 *
 * BTN_TOUCH/BTN_TOOL_FINGER reflect whether any slot is active.
 *
 * Touch coordinate scaling: screen coords × g_touch_scale = hardware touch coords
 * g_touch_scale is dynamically computed in kpm_detect_screen_size().
 */

/* EV_ABS event codes */
#define EV_ABS_CODE         0x03
#define ABS_MT_SLOT_CODE    0x2f
#define ABS_MT_TOUCH_MAJOR  0x30
#define ABS_MT_TOUCH_MINOR_CODE 0x31
#define ABS_MT_TOOL_TYPE_CODE   0x37
#define ABS_MT_TRACKING_ID  0x39
#define ABS_MT_PRESSURE     0x3a
#define ABS_MT_POSITION_X   0x35
#define ABS_MT_POSITION_Y   0x36

/* EV_KEY event codes */
#define EV_KEY_CODE         0x01
#define BTN_TOUCH_CODE      0x14a
#define BTN_TOOL_FINGER     0x145

/* EV_SYN */
#define EV_SYN_CODE         0x00
#define SYN_REPORT_CODE     0x00

/* Output function pointer: use input_handle_event (not input_event) to
 * avoid deadlocking on dev->event_lock when called from within the
 * input_handle_event hook context.
 *
 * input_event() acquires dev->event_lock then calls input_handle_event().
 * Our hook fires inside input_handle_event(), so dev->event_lock is already
 * held. Calling kf_input_event() again would try to re-acquire it → deadlock.
 *
 * kf_input_handle_event() processes the event directly without locking,
 * which is safe because the lock is already held by our caller.
 * In prctl context (virtual touches) the lock isn't held, but
 * input_handle_event is still safe to call (no double-lock crash).
 *
 * g_injecting 由 tvf_output_commit_frame 统一管理（循环前设 1，循环后清 0），
 * input_emit 宏本身不修改 g_injecting，避免在循环内反复重置破坏保护。
 */

/* ===== 触摸事件记录器 =====
 * 时间戳：CNTPCT_EL0 系统计数器 → 纳秒（零符号依赖、高精度、无锁）。
 * 缓冲：环形 2048 条，单写者（hook/输出串行），读在 STOP 后无竞争。
 * 竞争说明：hook 在 IRQ 上下文（input_event 已持锁），输出在 process
 * 上下文（tvf_lock 内）——两处不会同时写（hook 与输出由 g_injecting
 * 互斥：输出时 hook 跳过）；START/STOP 由 UDP workqueue 串行。 */
#define KPM_TVREC_ENTRY_SIZE  24   /* ts_ns(8)+slot(4)+code(4)+value(4)+src(4) */

typedef struct {
    uint64_t ts_ns;
    int32_t  slot;
    int32_t  code;
    int32_t  value;
    int32_t  src;
} kpm_tvrec_t;

static kpm_tvrec_t g_tvrec[KPM_TVREC_MAX];
static volatile int g_tvrec_head = 0;     /* 写位置 */
static volatile int g_tvrec_count = 0;    /* 有效条数（满后保持 MAX） */
static volatile int g_tvrec_enabled = 0;
static volatile int g_tvrec_srcmask = 0;  /* 1=hw, 2=out */
static volatile uint64_t g_tvrec_total = 0; /* 总写入条数（单调递增，push 序号用） */

static inline uint64_t kpm_cntvct_ns(void)
{
    uint64_t cnt, freq;
    asm volatile("mrs %0, cntpct_el0" : "=r"(cnt));
    asm volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    if (!freq) return 0;
    return (cnt * 1000000000ULL) / freq;
}

void kpm_tvrecord(int src, int slot, int code, int value)
{
    int idx;
    if (!g_tvrec_enabled || !(g_tvrec_srcmask & src))
        return;
    idx = g_tvrec_head;
    g_tvrec_head = (g_tvrec_head + 1) % KPM_TVREC_MAX;
    if (g_tvrec_count < KPM_TVREC_MAX)
        g_tvrec_count++;
    g_tvrec_total++;
    g_tvrec[idx].ts_ns = kpm_cntvct_ns();
    g_tvrec[idx].slot = (int32_t)slot;
    g_tvrec[idx].code = (int32_t)code;
    g_tvrec[idx].value = (int32_t)value;
    g_tvrec[idx].src = (int32_t)src;
    /* 事件到达即唤醒 UDP 推送 work（事件驱动，无定时器/忙等；
     * kpm_udp.c 提供 kpm_udp_tvpush_wakeup） */
    kpm_udp_tvpush_wakeup();
}

/* 从序号 from_seq 读取最多 max 条事件到 buf。
 * 落后（缓冲覆盖）自动跳到可读最旧处。返回实际条数，*next_seq 为下一序号。
 * 读取基于 (head,count,total) 快照，单次读窗口在 240Hz 下无覆盖风险。 */
int kpm_tvrecord_fetch(uint64_t from_seq, int max, void *buf,
                       uint64_t *next_seq)
{
    int head = g_tvrec_head;
    int count = g_tvrec_count;
    uint64_t total = g_tvrec_total;
    uint64_t first = total - (uint64_t)count;   /* 窗口第一条的序号 */
    int base = (head - count + KPM_TVREC_MAX) % KPM_TVREC_MAX;
    uint8_t *out = (uint8_t *)buf;
    int n = 0;

    if (from_seq < first)
        from_seq = first;                       /* 落后跳过 */
    while (from_seq < total && n < max) {
        uint64_t rel = from_seq - first;        /* 窗口内偏移 */
        int idx = (base + (int)(rel % (uint64_t)KPM_TVREC_MAX)) % KPM_TVREC_MAX;
        lib_memcpy(out + n * (int)sizeof(kpm_tvrec_t),
                   &g_tvrec[idx], sizeof(kpm_tvrec_t));
        from_seq++;
        n++;
    }
    if (next_seq)
        *next_seq = from_seq;
    return n;
}

uint64_t kpm_tvrecord_total(void)
{
    return g_tvrec_total;
}

int kpm_tvrecord_start(int src_mask)
{
    g_tvrec_enabled = 0;            /* 停写再清，防丢尾部 */
    g_tvrec_head = 0;
    g_tvrec_count = 0;
    g_tvrec_total = 0;              /* 必须重置序号，否则 fetch 序号错位
                                     * （旧 total 残留）返回 0 */
    g_tvrec_srcmask = (src_mask & 0x3) ? (src_mask & 0x3) : 3;
    /* 写入屏障后启用 */
    asm volatile("dmb ish" ::: "memory");
    g_tvrec_enabled = 1;
    return 0;
}

int kpm_tvrecord_stop(void)
{
    int n = g_tvrec_count;
    asm volatile("dmb ish" ::: "memory");
    g_tvrec_enabled = 0;
    return n;
}

/* 拷贝 [start_idx, start_idx+count) 到 dst（旧→新顺序），返回实际条数 */
int kpm_tvrecord_copy(int start_idx, int count, void *dst, int *total_out)
{
    int total, i, n = 0;
    kpm_tvrec_t *out = (kpm_tvrec_t *)dst;
    total = g_tvrec_count;
    if (total_out) *total_out = total;
    if (count <= 0) return 0;
    if (start_idx >= total) return 0;
    if (count > total - start_idx) count = total - start_idx;
    /* 环形起点：head-count（当满） */
    int base = (g_tvrec_head - total + KPM_TVREC_MAX) % KPM_TVREC_MAX;
    for (i = 0; i < count; i++) {
        int idx = (base + start_idx + i) % KPM_TVREC_MAX;
        out[n++] = g_tvrec[idx];
    }
    return n;
}

#define input_emit(dev, type, code, val) \
    do { \
        if (kf_input_handle_event) \
            kf_input_handle_event((dev), (type), (code), (val)); \
    } while (0)

void tvf_output_commit_frame(void)
{
    void *dev = g_touch_dev;
    int i;
    int any_active = 0;
    int has_dirty = 0;
    static int prev_any_active = 0;

    if (!dev || !kf_input_handle_event) return;

    /* Check if any slot needs output */
    for (i = 0; i < MAX_OUTPUT_SLOTS; i++) {
        if (g_pending_frame[i].dirty) {
            has_dirty = 1;
            break;
        }
    }
    if (!has_dirty) return;

    /* Set injection flag (prevents hook feedback loop) */
    asm volatile("dmb ish" ::: "memory");
    g_injecting = 1;
    asm volatile("dmb ish" ::: "memory");

    for (i = 0; i < MAX_OUTPUT_SLOTS; i++) {
        SlotState *ss = &g_pending_frame[i];

        if (!ss->dirty)
            continue;

        /* Select the MT slot */
        input_emit(dev, EV_ABS_CODE, ABS_MT_SLOT_CODE, i);
        kpm_tvrecord(KPM_TVREC_SRC_OUT, i, ABS_MT_SLOT_CODE, i);

        if (ss->active) {
            int scale = g_touch_scale;
            /* raw 模式（raw_x>=0）直接透传硬件最小单位坐标（不 ×scale），
             * 支持亚像素精度；像素模式保持 ×scale 换算。 */
            int tx = (ss->raw_x >= 0) ? ss->raw_x : ss->x * scale;
            int ty = (ss->raw_y >= 0) ? ss->raw_y : ss->y * scale;
            any_active = 1;

            /* MT Protocol B: only send ABS_MT_TRACKING_ID on state change. */
            if (!g_prev_slot_active[i] ||
                g_prev_tracking_id[i] != ss->tracking_id) {
                input_emit(dev, EV_ABS_CODE, ABS_MT_TRACKING_ID, ss->tracking_id);
                kpm_tvrecord(KPM_TVREC_SRC_OUT, i, ABS_MT_TRACKING_ID,
                             ss->tracking_id);
                kpm_log("kpm: out slot=%d DOWN tid=%d\n", i, ss->tracking_id);
            }

            input_emit(dev, EV_ABS_CODE, ABS_MT_TOUCH_MAJOR, ss->touch_major);
            kpm_tvrecord(KPM_TVREC_SRC_OUT, i, ABS_MT_TOUCH_MAJOR,
                         ss->touch_major);
            input_emit(dev, EV_ABS_CODE, ABS_MT_PRESSURE, ss->pressure);
            kpm_tvrecord(KPM_TVREC_SRC_OUT, i, ABS_MT_PRESSURE, ss->pressure);
            input_emit(dev, EV_ABS_CODE, ABS_MT_POSITION_X, tx);
            kpm_tvrecord(KPM_TVREC_SRC_OUT, i, ABS_MT_POSITION_X, tx);
            input_emit(dev, EV_ABS_CODE, ABS_MT_POSITION_Y, ty);
            kpm_tvrecord(KPM_TVREC_SRC_OUT, i, ABS_MT_POSITION_Y, ty);

            /* MOVE 日志限流 —— 高频滑动（240Hz+ 客户端 fire-and-forget）
             * 时每帧一条 kpm_log 导致日志锁竞争 + 环形缓冲刷屏，拖慢内核
             * 输出（轨迹呈离散点）。每 64 帧打一条，DOWN/UP 保持完整
             * （低频关键事件）。 */
            {
                static unsigned int g_move_log_cnt = 0;
                if ((g_move_log_cnt++ & 0x3F) == 0) {
                    kpm_log("kpm: out slot=%d MOVE (%d,%d)->(%d,%d) tid=%d\n",
                            i, ss->x, ss->y, tx, ty, ss->tracking_id);
                }
            }
        } else {
            /* UP: only send tracking_id = -1 if the slot was active in the
             * previous frame. If already inactive, skip to avoid redundant UP. */
            if (g_prev_slot_active[i]) {
                input_emit(dev, EV_ABS_CODE, ABS_MT_TRACKING_ID, -1);
                kpm_tvrecord(KPM_TVREC_SRC_OUT, i, ABS_MT_TRACKING_ID, -1);
                kpm_log("kpm: out slot=%d UP\n", i);
            }
        }

        /* Update prev state for next frame */
        g_prev_tracking_id[i] = ss->active ? ss->tracking_id : -1;
        g_prev_slot_active[i] = ss->active;

        ss->dirty = 0;
    }

    /* BTN_TOUCH + BTN_TOOL_FINGER: only send on state change.
     * Sending them on every frame can cause unnecessary processing. */
    if (any_active != prev_any_active) {
        if (any_active) {
            input_emit(dev, EV_KEY_CODE, BTN_TOUCH_CODE, 1);
            kpm_tvrecord(KPM_TVREC_SRC_OUT, 0, BTN_TOUCH_CODE, 1);
            input_emit(dev, EV_KEY_CODE, BTN_TOOL_FINGER, 1);
            kpm_tvrecord(KPM_TVREC_SRC_OUT, 0, BTN_TOOL_FINGER, 1);
        } else {
            input_emit(dev, EV_KEY_CODE, BTN_TOUCH_CODE, 0);
            kpm_tvrecord(KPM_TVREC_SRC_OUT, 0, BTN_TOUCH_CODE, 0);
            input_emit(dev, EV_KEY_CODE, BTN_TOOL_FINGER, 0);
            kpm_tvrecord(KPM_TVREC_SRC_OUT, 0, BTN_TOOL_FINGER, 0);
        }
        prev_any_active = any_active;
    }

    /* SYN_REPORT: commit the frame */
    input_emit(dev, EV_SYN_CODE, SYN_REPORT_CODE, 0);
    kpm_tvrecord(KPM_TVREC_SRC_OUT, 0, EV_SYN_CODE, 0);

    asm volatile("dmb ish" ::: "memory");
    g_injecting = 0;
    asm volatile("dmb ish" ::: "memory");
}

/* ===== Screen resolution detection ===== */
#define INPUT_ABSINFO_SIZE      24
#define ABS_MT_POSITION_X_OFF   0x35
#define ABS_MT_POSITION_Y_OFF   0x36
#define SCREEN_SCAN_MAX_OFF     4096
#define SCREEN_MIN_RES          100
#define SCREEN_MAX_RES          65535

static void kpm_detect_screen_size(void)
{
    const char *base = (const char *)g_touch_dev;
    int off;

    if (!base || !kf_copy_from_kernel_nofault) return;

    /* base（g_touch_dev）及扫描上界 base+4096 也需通过
     * is_safe_kern_ptr 校验（input_dev 结构跨页可能落到保护域）。 */
    if (!is_safe_kern_ptr((uint64_t)(uintptr_t)base) ||
        !is_safe_kern_ptr((uint64_t)(uintptr_t)base + SCREEN_SCAN_MAX_OFF)) {
        kpm_log("kpm: screen scan base unsafe dev=%llx\n",
                (uint64_t)(uintptr_t)base);
        g_touch_scale = 1;
        return;
    }

    for (off = 0; off < SCREEN_SCAN_MAX_OFF; off += 8) {
        void *candidate;
        int max_x, max_y;
        long ret;

        ret = kf_copy_from_kernel_nofault(&candidate, base + off, sizeof(void *));
        if (ret != 0 || !candidate) continue;

        /* candidate 是跟随读出的任意内核指针，必须通过 is_safe_kern_ptr
         * 物理域/vmalloc 白名单校验才能跟随：copy_from_kernel_nofault 只拦
         * page fault、拦不住 MTK DEVAPC 硬件总线监控。
         * 目标读取窗口：candidate+0x500（ABS_MT_POSITION_X maximum）~
         * +0x51C（ABS_MT_POSITION_Y maximum+4），最大约 0x520 字节，可能跨页：
         * 起始页与末尾页（candidate+0x520）都必须通过物理域校验。 */
        if (!is_safe_kern_ptr((uint64_t)(uintptr_t)candidate) ||
            !is_safe_kern_ptr((uint64_t)(uintptr_t)candidate + 0x520)) {
            kpm_log("kpm: screen scan off=%d reject unsafe ptr=%llx\n",
                    off, (uint64_t)(uintptr_t)candidate);
            continue;
        }

        ret = kf_copy_from_kernel_nofault(&max_x,
            (const char *)candidate + ABS_MT_POSITION_X_OFF * INPUT_ABSINFO_SIZE + 8,
            sizeof(int));
        if (ret != 0) continue;

        ret = kf_copy_from_kernel_nofault(&max_y,
            (const char *)candidate + ABS_MT_POSITION_Y_OFF * INPUT_ABSINFO_SIZE + 8,
            sizeof(int));
        if (ret != 0) continue;

        if (max_x >= SCREEN_MIN_RES && max_x <= SCREEN_MAX_RES &&
            max_y >= SCREEN_MIN_RES && max_y <= SCREEN_MAX_RES) {
            g_screen_width = max_x;
            g_screen_height = max_y;

            /* 检测 scale：raw / 实际屏幕宽度。
             * 触摸屏固件常以高精度坐标上报（如 17280=1080×16），
             * 通过匹配常见屏幕宽度找出 scale，用户 API 使用实际像素坐标。
             * 常见屏幕宽度：720/1080/1200/1440/1560/2340/2400 */
            {
                static const int common_widths[] = {1080, 1200, 1440, 720, 1560, 2340, 2400};
                int best_scale = 1;
                int i;
                for (i = 0; i < (int)(sizeof(common_widths) / sizeof(common_widths[0])); i++) {
                    if (max_x > common_widths[i] && (max_x % common_widths[i]) == 0) {
                        best_scale = max_x / common_widths[i];
                        break;
                    }
                }
                g_touch_scale = best_scale;
            }

            kpm_log("kpm: screen detected max=%dx%d scale=%d (abs off=%d)\n",
                    max_x, max_y, g_touch_scale, off);
            return;
        }
    }

    /* Detection failed — default to scale=1 (user coords = hardware coords) */
    g_touch_scale = 1;
    kpm_log("kpm: screen size detection failed, using scale=1\n");
}

/* ===== Init / Exit ===== */

int kpm_touch_ready(void)
{
    return g_touch_dev != NULL;
}

void *kpm_touch_get_dev(void)
{
    return g_touch_dev;
}

int kpm_touch_get_node_offset(void)
{
    return g_node_offset;
}

long kpm_touch_init(void)
{
    /* input_event: 虚拟触摸注入必需（全版本 EXPORT_SYMBOL）
     * input_handle_event: hook 目标（6.1 导出，<6.1 kallsyms_lookup_name 可解析）
     * 两者都必须可用，否则触摸功能不可用 */
    if (!kf_input_event) {
        kpm_log("kpm: input_event not found\n");
        kpm_log("kpm: touch init failed - input_event not found\n");
        return -1;
    }
    if (!kf_input_handle_event) {
        kpm_log("kpm: input_handle_event not found (hook target missing)\n");
        kpm_log("kpm: touch init failed - input_handle_event not found\n");
        return -1;
    }
    if (!kv_input_dev_list) {
        kpm_log("kpm: input_dev_list not found\n");
        kpm_log("kpm: touch init failed - input_dev_list not found\n");
        return -1;
    }

    kpm_log("kpm: touch symbols resolved: input_event=%llx, input_handle_event=%llx, input_dev_list=%llx\n",
            (uint64_t)kf_input_event, (uint64_t)kf_input_handle_event, (uint64_t)kv_input_dev_list);

    if (kpm_detect_node_offset() < 0) {
        kpm_log("kpm: node offset detection failed, touch disabled\n");
        kpm_log("kpm: touch init failed - node offset detection failed\n");
        return -1;
    }

    g_touch_dev = kpm_find_touch_dev();
    if (!g_touch_dev) {
        kpm_log("kpm: touchpanel not found, touch disabled\n");
        kpm_log("kpm: touch init failed - touchpanel not found\n");
        return -1;
    }

    /* Initialize TVF V2 pool, slot map, frame buffer */
    tvf_pool_init();

    /* Initialize prev slot state for tracking_id change detection */
    {
        int _i;
        for (_i = 0; _i < MAX_OUTPUT_SLOTS; _i++) {
            g_prev_tracking_id[_i] = -1;
            g_prev_slot_active[_i] = 0;
        }
    }

    kpm_detect_screen_size();

    kpm_set_state(KPM_STATE_TOUCH_FOUND);
    kpm_log("kpm: touch init ok\n");
    kpm_log("kpm: touch init ok, dev=%llx, node_offset=%d\n",
            (uint64_t)g_touch_dev, g_node_offset);
    return 0;
}

void kpm_touch_exit(void)
{
    /* Cancel all animations and release all objects */
    int i;
    for (i = 0; i < MAX_TOUCH_OBJECTS; i++) {
        if (g_touch_pool[i].owner != TVF_OWNER_FREE) {
            g_touch_pool[i].cancel = 1;
            if (g_touch_pool[i].output_slot >= 0) {
                /* Release the slot */
                int slot = g_touch_pool[i].output_slot;
                g_output_slot_owner[slot] = -1;
                g_touch_pool[i].output_slot = -1;
            }
            g_touch_pool[i].state = TVF_STATE_INACTIVE;
        }
    }
    kpm_udelay_range(5000, 10000);

    g_touch_dev = NULL;
    kpm_clear_state(KPM_STATE_TOUCH_FOUND);
    kpm_log("kpm: touch exit\n");
}

/* ===== Screen info query ===== */
void kpm_touch_get_screen_info(int *width, int *height)
{
    if (width) *width = g_screen_width;
    if (height) *height = g_screen_height;
}

int kpm_touch_get_scale(void)
{
    return g_touch_scale;
}
