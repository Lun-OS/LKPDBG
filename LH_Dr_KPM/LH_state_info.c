/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_state_info.c - 扩展状态信息填充
 *
 * 填充 kpm_state_info_t 结构体（256 字节），通过 KPM_CMD_HOOK_INFO 返回。
 * 包含：模块状态、内核版本、符号可用性 bitmap、回退状态、偏移探测结果、
 *       功能路径、框架变量、模块版本等完整诊断信息。
 *
 * 隐蔽性：仅在查询时填充，无副作用，不影响任何功能路径。
 */
#include <ktypes.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <baselib.h>
#include <linux/string.h>

#include "LH_comm.h"
#include "LH_version.h"   /* 单一版本源（kpm_build_version） */
#include "LH_syms.h"
#include "LH_mem_rw.h"
#include "LH_log.h"
#include "LH_state_info.h"
#include "LH_gyro.h"   /* kpm_gyro_get_state */
#include "LH_udp.h"  /* kf_sock_create_kern, kf_alloc_workqueue, kf_init_net 等 UDP 符号声明 */
#include "LH_utils.h"  /* kpm_get_state */

/* 模块版本与构建时间
 * kpm_build_version 编码：
 *   (major << 24) | (minor << 16) | (patch << 8)，低 8 位保留未用
 *   解码：major=(v>>24)&0xFF, minor=(v>>16)&0xFF, patch=(v>>8)&0xFF
 * kpm_build_time: 使用 __DATE__ + __TIME__ 编译时生成（非精确 Unix 时间戳，仅用于版本对比） */
__attribute__((weak)) uint32_t kpm_build_version = LH_VERSION_CODE;

/* 将 __DATE__ "Mmm dd yyyy" + __TIME__ "HH:MM:SS" 折叠为 32-bit 时间戳
 * 仅用于版本对比，非精确 Unix 时间 */
static uint32_t kpm_compute_build_time(void)
{
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const char *m = __DATE__;
    int mon = ((months[0] == m[0] && months[1] == m[1] && months[2] == m[2]) ? 1 :
               (months[3] == m[0] && months[4] == m[1] && months[5] == m[2]) ? 2 :
               (months[6] == m[0] && months[7] == m[1] && months[8] == m[2]) ? 3 :
               (months[9] == m[0] && months[10] == m[1] && months[11] == m[2]) ? 4 :
               (months[12] == m[0] && months[13] == m[1] && months[14] == m[2]) ? 5 :
               (months[15] == m[0] && months[16] == m[1] && months[17] == m[2]) ? 6 :
               (months[18] == m[0] && months[19] == m[1] && months[20] == m[2]) ? 7 :
               (months[21] == m[0] && months[22] == m[1] && months[23] == m[2]) ? 8 :
               (months[24] == m[0] && months[25] == m[1] && months[26] == m[2]) ? 9 :
               (months[27] == m[0] && months[28] == m[1] && months[29] == m[2]) ? 10 :
               (months[30] == m[0] && months[31] == m[1] && months[32] == m[2]) ? 11 : 12);
    int day = (m[4] == ' ') ? (m[5] - '0') : ((m[4] - '0') * 10 + (m[5] - '0'));
    int year = (m[7] - '0') * 1000 + (m[8] - '0') * 100 + (m[9] - '0') * 10 + (m[10] - '0');
    const char *t = __TIME__;
    int hh = (t[0] - '0') * 10 + (t[1] - '0');
    int mm = (t[3] - '0') * 10 + (t[4] - '0');
    /* 折叠为 32-bit: year(12)|mon(4)|day(5)|hh(5)|mm(6)
     * ss 未使用（32-bit 空间不足），仅用于精确到分钟级版本对比 */
    return ((uint32_t)(year & 0xFFF) << 20) | ((uint32_t)(mon & 0xF) << 16) |
           ((uint32_t)(day & 0x1F) << 11) | ((uint32_t)(hh & 0x1F) << 6) |
           (uint32_t)(mm & 0x3F);
}
__attribute__((weak)) uint32_t kpm_build_time = 0;

/* 设置单个符号 bit */
static inline void kpm_set_sym_bit(uint32_t bitmap[4], int idx, int available)
{
    if (idx < 0 || idx >= 128) return;
    if (available) {
        bitmap[idx / 32] |= (1u << (idx % 32));
    }
}

/* 设置 2-bit 回退字段 */
static inline void kpm_set_fb_field(uint32_t *fb, int field_idx, uint32_t value)
{
    if (field_idx < 0 || field_idx >= 16) return;
    uint32_t shift = field_idx * 2;
    uint32_t mask = 0x3u << shift;
    *fb = (*fb & ~mask) | ((value & 0x3) << shift);
}

/* 填充 kpm_state_info_t 结构体
 * info: 输出缓冲区（调用方负责分配，至少 256 字节）
 * touch_ready, node_offset, screen_w/h, raw_w/h, scale, intercept_on, active_count: 触摸/拦截实时数据
 * syms_init_ret: kpm_syms_init 返回值
 * mem_rw_path, touch_path, cmdline_path, put_task_path, vmemmap_source: 功能路径枚举
 */
void kpm_fill_state_info(kpm_state_info_t *info,
                         int syms_init_ret,
                         int touch_ready, int node_offset,
                         int screen_w, int screen_h,
                         int raw_w, int raw_h, int screen_scale,
                         int intercept_on, int active_count,
                         uint8_t mem_rw_path, uint8_t touch_path,
                         uint8_t cmdline_path, uint8_t put_task_path,
                         uint8_t vmemmap_source)
{
    if (!info) return;

    lib_memset(info, 0, sizeof(*info));

    /* [0] 头部 */
    info->magic = KPM_STATE_MAGIC;
    info->version = KPM_STATE_VERSION;

    /* [8] 基础状态 */
    info->state = kpm_get_state();
    {
        extern uint32_t kver;
        info->kver = kver;
    }
    info->syms_init_ret = syms_init_ret;

    /* [24] 触摸/屏幕 */
    info->touch_ready = touch_ready;
    info->node_offset = node_offset;
    info->screen_w = screen_w;
    info->screen_h = screen_h;
    info->raw_w = raw_w;
    info->raw_h = raw_h;
    info->screen_scale = screen_scale;

    /* [52] 拦截/活跃 */
    info->intercept_on = intercept_on;
    info->active_count = active_count;

    /* [60] 功能路径 */
    info->mem_rw_path = mem_rw_path;
    info->touch_path = touch_path;
    info->cmdline_path = cmdline_path;
    info->put_task_path = put_task_path;
    info->vmemmap_source = vmemmap_source;
    /* [65] task 取用路径：免引用可用则报 NOREF，否则按取引用路径上报。
     * 客户端据此判断"进程/maps 是否真的可用"（不再只看 put_task_path）。 */
    info->task_fetch_path = kpm_task_noref_available()
                                ? KPM_TASK_FETCH_NOREF
                                : KPM_TASK_FETCH_REF;

    /* [68] 符号可用性 bitmap */
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_CFU,           kf_copy_from_user != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_CTU,           kf_copy_to_user != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_CFKN,          kf_copy_from_kernel_nofault != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_MEMREMAP,      kf_memremap != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_MEMUNMAP,      kf_memunmap != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_VMAP,          kf_vmap != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_VUNMAP,        kf_vunmap != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_FILP_OPEN,     kf_filp_open != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_KERNEL_READ,   kf_kernel_read != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_KERNEL_WRITE,  kf_kernel_write != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_READ_ITER,     kf_kernel_read_iter != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_INPUT_HANDLE,  kf_input_handle_event != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_INPUT_EVENT,   kf_input_event != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_FIND_GET_PID,  kf_find_get_pid != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_GET_PID_TASK,  kf_get_pid_task != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_GET_TASK_MM,   kf_get_task_mm != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_MMPUT,         kf_mmput != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_FIND_VMA,      kf_find_vma != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_RCU_LOCK,      kf_rcu_read_lock != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_RCU_UNLOCK,    kf_rcu_read_unlock != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_INIT_TASK,     kf_init_task != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_PUT_TASK,      kf_put_task_struct != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_GET_CMDLINE,   kf_get_cmdline != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_GET_TASK_COMM, kf_get_task_comm != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_SOCK_CREATE,   kf_sock_create_kern != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_ALLOC_WQ,      kf_alloc_workqueue != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_INIT_NET,      kf_init_net != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_QUEUE_WORK,    kf_queue_work != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_VSNPRINTF,     kf_vsnprintf != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_PRINTK,        kf_printk != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_FIND_TASK_VPID, kf_find_task_by_vpid != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_TASK_PID_NR,   kf___task_pid_nr_ns != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_MM_READ_LOCK,  kf_mmap_read_lock != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_MM_READ_UNLOCK, kf_mmap_read_unlock != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_HW_BP_REG,     kf_register_user_hw_bp != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_HW_BP_UNREG,   kf_unregister_hw_bp != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_KMALLOC,       kf_kmalloc != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_KFREE,         kf_kfree != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_VMALLOC,       kf_vmalloc != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_VFREE,         kf_vfree != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_SNPRINTF,      kf_snprintf != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_STRTOULL,      kf_simple_strtoull != 0);
    kpm_set_sym_bit(info->sym_bitmap, KPM_SYM_SYNC_RCU,      kf_synchronize_rcu != 0);

    /* [84] 回退状态（简化版：仅记录关键符号是否走了回退）
     * 准确判断回退层级需要记录主符号是否可用，这里用近似：
     *   0 = 主符号可用（或无回退链）
     *   3 = 全缺失（符号为 NULL） */
    {
        /* copy_from_user: 主符号 copy_from_user，回退 _copy_from_user, __arch_copy_from_user */
        if (kf_copy_from_user) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_CFU, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_CFU, 3);

        if (kf_copy_to_user) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_CTU, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_CTU, 3);

        if (kf_copy_from_kernel_nofault) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_CFKN, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_CFKN, 3);

        if (kf_memremap) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_MEMREMAP, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_MEMREMAP, 3);

        if (kf_memunmap) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_MEMUNMAP, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_MEMUNMAP, 3);

        if (kf_find_get_pid) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_FIND_GET_PID, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_FIND_GET_PID, 3);

        if (kf_get_pid_task) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_GET_PID_TASK, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_GET_PID_TASK, 3);

        if (kf_mmput) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_MMPUT, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_MMPUT, 3);

        if (kf_printk) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_PRINTK, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_PRINTK, 3);

        /* put_task_struct: 0=原生,1=手动+__put(已标定),2=free_task(已禁用),3=泄漏
         * 注意：free_task 路径因 UAF 风险已禁用，不再作为回退。
         * 本 bitmap 只保留客户端既有的 0/1/3 三态语义；泄漏的**具体原因**
         * （4=标定未执行 / 5=标定失败 / 6=标定符号缺失）由 put_task_path 上报。 */
        {
            uint8_t ptp = kpm_put_task_path();
            kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_PUT_TASK,
                             (ptp == 0) ? 0 : (ptp == 1) ? 1 : 3);
        }

        if (kf_queue_work) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_QUEUE_WORK, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_QUEUE_WORK, 3);

        if (kf_flush_workqueue) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_FLUSH_WQ, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_FLUSH_WQ, 3);

        if (kf_vmalloc) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_VMALLOC, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_VMALLOC, 3);

        if (kf_kmalloc) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_KMALLOC, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_KMALLOC, 3);

        if (kf_kernel_read) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_KERNEL_READ, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_KERNEL_READ, 3);

        if (kf_kernel_write) kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_KERNEL_WRITE, 0);
        else kpm_set_fb_field(&info->fallback_bitmap, KPM_FB_KERNEL_WRITE, 3);
    }

    /* [88] task_struct / mm_struct / vm_area_struct 偏移 */
    info->tasks_offset        = (int16_t)g_tasks_offset;
    info->tgid_offset         = (int16_t)g_tgid_offset;
    info->mm_offset           = (int16_t)g_mm_offset;
    info->pid_offset          = (int16_t)g_pid_offset;
    info->real_parent_offset  = (int16_t)g_real_parent_offset;
    /* usage_offset: 未标定（-1）时按既有协议上报 0（未知）；
     * 是否可信由 fallback_bitmap.KPM_FB_PUT_TASK 表达（1=手动路径可用）。 */
    info->usage_offset        = (int16_t)(g_usage_offset < 0 ? 0 : g_usage_offset);
    info->arg_start_offset    = (int16_t)g_arg_start_offset;
    info->arg_end_offset      = (int16_t)g_arg_end_offset;
    /* -1 表示未探测，-2 表示探测失败（6.1+ 无此字段），都转换为 0 给用户态 */
    info->vm_start_offset     = (int16_t)(g_vm_start_offset < 0 ? 0 : g_vm_start_offset);
    info->vm_end_offset       = (int16_t)(g_vm_end_offset < 0 ? 0 : g_vm_end_offset);
    info->vm_next_offset      = (int16_t)(g_vm_next_offset < 0 ? 0 : g_vm_next_offset);
    info->mm_mmap_offset      = (int16_t)(g_mm_mmap_offset < 0 ? 0 : g_mm_mmap_offset);

    /* [112] 框架变量 */
    info->vmemmap_base   = g_vmemmap_base;
    info->memstart_addr  = g_memstart_addr;
    {
        extern uint64_t pgd_va;
        info->pgd_va = pgd_va;
    }
    info->mm_pgd_offset  = (uint32_t)g_mm_pgd_offset;
    /* VA 位宽参数：统一走 kpm_mem_rw.c 的 kpm_detect_va_params（TCR_EL1 探测）。
     * 由该函数统一管理（T0SZ 用户位宽 + T1SZ 内核位宽）。 */
    {
        kpm_detect_va_params();
        info->va_bits    = g_kpm_va_bits;
        info->page_shift = g_kpm_page_shift;
        info->page_level = g_kpm_page_level;
    }

    /* [156] 模块版本 */
    info->module_version = kpm_build_version;
    info->build_time     = kpm_compute_build_time();
    info->module_size    = 0;  /* 运行时无法获知自身大小，留 0 */

    /* [168] 陀螺仪/传感器（UDP/prctl 双通道 HOOK_INFO 输出） */
    kpm_gyro_get_state(&info->gyro_ready, &info->gyro_dev_count,
                       &info->gyro_locked_axes, &info->gyro_controlled_axes,
                       &info->gyro_client_alive);
}
