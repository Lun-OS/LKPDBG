/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <kputils.h>
#include <ksyms.h>
#include <pgtable.h>
#include <baselib.h>

#include "LH_comm.h"
#include "LH_hooks.h"
#include "LH_log.h"
#include "LH_stealth.h"
#include "LH_syms.h"
#include "LH_touch.h"
#include "LH_utils.h"
#include "LH_intercept.h"
#include "LH_gyro.h"
#include "touch_manager.h"
#include "LH_mem_scan.h"
#include "LH_mem_freeze.h"
#include "LH_ptr_scan.h"
#include "LH_debug.h"
#include "LH_hook_enhanced.h"
#include "LH_hide.h"
#include "LH_mem_rw.h"
#include "LH_proc.h"
#include "LH_udp.h"
#include "LH_state_info.h"
#include "LH_dump.h"
#include "LH_armor.h"
#include "LH_feat.h"
#include "LH_version.h"   /* 单一版本源：元数据/state_info/info 共用 */
#include "LH_suspend.h"
#include "LH_netctl.h"
#include "LH_filter.h"   /* kpm_filter_init（共享 filter 一次性清零） */
#include "LH_sysmon.h"
#include "LH_resctl.h"
#include "LH_hook2.h"
#include "LH_force.h"
#include "LH_trace.h"
#include "LH_memwatch.h"
#include "LH_wxshadow.h"









/* ===== 模块元数据 =====
 * 不用框架 KPM_NAME/KPM_VERSION 等：KPM_INFO 宏不带每个字段的前导 NUL
 * 分隔符。.kpm.str（加密段）与 .kpm.info 紧邻，若 str 尾字节为可打印字符，
 * strings 输出会与 name= 粘连成如 "5name=LH"，SukiSU 管理器按
 * strings|grep 'name=' + startsWith("name=") 提取模块名即失败 → UI 加载
 * 直接 return，load 从未发出（CLI 不走 strings 故不受影响）。
 * 此宏补上前导 NUL 分隔语义，内核侧解析（NUL 分割跳过空段）不受影响。 */
#define LH_KPM_INFO(key, val, limit)                                     \
    _Static_assert(sizeof(val) <= limit, "Info string too long");        \
    static const char __kpm_info_##key[] __attribute__((__used__))       \
    __attribute__((section(".kpm.info"), unused, aligned(1))) = "\0" #key "=" val

LH_KPM_INFO(name,        "LHDBG",           KPM_NAME_LEN);
LH_KPM_INFO(version,     LH_VERSION_STR, KPM_VERSION_LEN); //版本控制在LH_version.h中设置喵
LH_KPM_INFO(license,     "AGPL v3",     KPM_LICENSE_LEN);
LH_KPM_INFO(author,      "Lun.",         KPM_AUTHOR_LEN);
LH_KPM_INFO(description, "一个安卓内核驱动级调试工具喵~   GitHub@Lun-OS",    KPM_DESCRIPTION_LEN);




















/* GKI 兼容说明：Android 11+ GKI 内核将 filp_open 等 VFS 接口放入
 * VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver 命名空间。
 * 标准内核模块需 MODULE_IMPORT_NS(VFS_internal_I_am_really_a_
 * filesystem_and_am_NOT_a_driver) 才能链接期引用；但本模块通过
 * kallsyms_lookup_name 运行时解析符号（见 kpm_syms.c resolve_sym），
 * 不依赖链接期 EXPORT_SYMBOL 绑定，因此无需该宏（框架精简 module.h
 * 也不提供它）。 */

/* 调试标记函数：debug 与 release 均为空操作 —— 不写入
 * /data/local/tmp/kpm_debug.log（加载痕迹，0644 可读，致命检测向量）。
 * 调试信息由 kpm_log 内部环形缓冲承载（GET_LOG 命令读取，无文件痕迹）。 */
static void kpm_debug_mark(const char *msg) { (void)msg; }

/* ===== 功能单元 init/exit 包装 =====
 * 状态位置位职责由注册表负责（state_bit），
 * 单元内仅保留有条件置位（如 INTERCEPT_OK 必须在 hook 实际装上后）。
 * 包装存在的意义：FEAT_ENABLE/FEAT_DISABLE 与模块卸载共用同一条
 * 拆卸路径，行为唯一，不会出现"卸载一套逻辑、关闭另一套逻辑"。 */

/* --- MEM_RW：内存读写引擎（默认启用单元） --- */
static long feat_mem_rw_init(void)
{
    long ret = kpm_mem_rw_init();
    if (ret)
        kpm_log("kpm: mem_rw init failed (%ld), MEM disabled\n", ret);
    return ret;
}
static void feat_mem_rw_exit(void)
{
    kpm_mem_rw_exit();
}

/* --- UDP：协议接口（核心通道） --- */
static long feat_udp_init(void)
{
    long ret = kpm_udp_init(0);
    if (ret) {
        kpm_log("kpm: udp init failed (%ld), UDP disabled\n", ret);
        kpm_printk("LH_debug: udp init failed (%ld)\n", ret);
        return ret;
    }
    kpm_log("kpm: udp service started (port %d)\n", kpm_udp_get_port());
    kpm_printk("LH_debug: udp init ok (port %d)\n", kpm_udp_get_port());
    return 0;
}
static void feat_udp_exit(void)
{
    kpm_udp_exit();
}

/* --- DEBUG：硬件断点 + 命中通知 + regmod --- */
static long feat_debug_init(void)
{
    long ret = kpm_debug_init();
    uint32_t reason = 0;

    if (ret) {
        kpm_log("kpm: debug init failed (%ld)\n", ret);
        return ret;
    }
    /* 能力自检结论必须进入 FEAT 状态——硬件断点不可用时不能报 OK。 */
    if (kpm_debug_hwbp_status() != 1)
        reason |= KPM_DEBUG_DEG_HWBP;
    if (!kpm_debug_wq_ok())
        reason |= KPM_DEBUG_DEG_WQ;
    if (!kpm_debug_sync_ok())
        reason |= KPM_DEBUG_DEG_SYNC;
    if (reason) {
        kpm_feat_set_reason(KPM_FEAT_DEBUG, reason);
        kpm_log("kpm: debug DEGRADED (reason=0x%x, hwbp=%d wq=%d sync=%d)\n",
                reason, kpm_debug_hwbp_status(),
                kpm_debug_wq_ok(), kpm_debug_sync_ok());
        return KPM_FEATST_DEGRADED;
    }
    return 0;
}
static void feat_debug_exit(void)
{
    /* 断点是 UDP 通知的产生端，卸载序中必须先于 UDP 拆除
     * （注册表逆序保证：DEBUG 注册位次在 UDP 之后）。 */
    kpm_debug_exit();
}

/* --- TOUCH：触摸虚拟化 + 输入拦截（事件产生端） --- */
#ifdef KPM_FEATURE_TOUCH
static long feat_touch_init(void)
{
    long ret;
    /* 触摸偏移拦截状态初始化（hook 尚未安装）。KPM_STATE_INTERCEPT_OK
     * 不在此处置位——它表示 input_handle_event hook 已实际安装成功。 */
    kpm_intercept_init();
    ret = kpm_touch_init();
    if (ret) {
        kpm_log("kpm: touch init failed (%ld), continuing without touch\n", ret);
        return ret;
    }
    /* 输入捕获 hook（input_handle_event）：内核态函数入口 hook，
     * 非 root 不可检测（无法读内核指令）。失败仅影响触摸拦截。 */
    ret = kpm_intercept_hook_install();
    if (ret) {
        kpm_log("kpm: input capture hook install failed (%ld)\n", ret);
        return ret;
    }
    /* hook 真正安装成功后才置位，确保接口 state 与 info 一致 */
    kpm_set_state(KPM_STATE_INTERCEPT_OK);
    return 0;
}
static void feat_touch_pre_exit(void)
{
    /* 卸载前摇（最先执行）：先打 cancel 再销毁全部触摸
     * （动画在 prctl/UDP 回调内忙等，不先取消 → drain 超时 → UAF），
     * 随后停止拦截并卸载输入捕获 hook——杜绝卸载期间新触摸事件
     * 唤醒 UDP workqueue。 */
    touch_cancel_all();
    kpm_touch_destroy_all();
    kpm_intercept_stop();
    kpm_intercept_hook_uninstall();
    kpm_log("kpm: input hooks stopped\n");
}
static void feat_touch_exit(void)
{
    /* 触摸状态释放：必须在 prctl 排空之后——在途 prctl 命令可能正在操作
     * touch 对象，顺序颠倒致卸载 UAF panic。
     * 注册序保证 TOUCH 的 exit 晚于 PRCTL 的 exit。 */
    kpm_touch_exit();
    kpm_log("kpm: touch exit done\n");
}
#endif /* KPM_FEATURE_TOUCH */

/* --- GYRO：传感器控制 --- */
#ifdef KPM_FEATURE_GYRO
static long feat_gyro_init(void)
{
    long ret = kpm_gyro_init();
    if (ret)
        kpm_log("kpm: gyro control unavailable (uprobe not installed, non-fatal)\n");
    return ret;
}
static void feat_gyro_exit(void)
{
    kpm_gyro_exit();
}
#endif /* KPM_FEATURE_GYRO */

/* --- PRCTL：协议接口（核心通道） --- */
static long feat_prctl_init(void)
{
    long ret = kpm_hooks_init();
    if (ret)
        kpm_log("kpm: hooks init failed (%ld), FATAL\n", ret);
    return ret;
}
static void feat_prctl_exit(void)
{
    /* 移除 prctl FP Hook 并排空在途命令（kpm_hooks_exit 内部 drain）。
     * 必须在 touch 状态释放之前（注册序保证）。 */
    kpm_hooks_exit();
    kpm_log("kpm: hooks exit done\n");
}

/* --- MEM_SCAN：内存扫描（exit 前需先中止在跑扫描） --- */
static long feat_mem_scan_init(void)
{
    long ret = kpm_mem_scan_init();
    if (ret)
        kpm_log("kpm: mem_scan init failed (%ld)\n", ret);
    return ret;
}
static void feat_mem_scan_pre_exit(void)
{
    /* 先中止扫描（置 cancel）再拆 UDP——大范围扫描在 recv_work 中
     * 串行执行时会阻塞 workqueue 数十秒。 */
    kpm_mem_scan_abort();
}
static void feat_mem_scan_exit(void)
{
    kpm_mem_scan_exit();
}

/* --- 其余小单元：init/exit 直通 --- */
static long feat_mem_freeze_init(void)   { return kpm_mem_freeze_init(); }
static void feat_mem_freeze_exit(void)   { kpm_mem_freeze_exit(); }
static long feat_ptr_scan_init(void)     { return kpm_ptr_scan_init(); }
static void feat_ptr_scan_exit(void)     { kpm_ptr_scan_exit(); }
static long feat_proc_init(void)         { return kpm_proc_init(); }
static void feat_proc_exit(void)         { kpm_proc_exit(); }
static long feat_hide_init(void)         { return kpm_hide_init(); }
static void feat_hide_exit(void)         { kpm_hide_exit(); }
static long feat_dump_init(void)         { kpm_dump_init(); return 0; }
static void feat_dump_exit(void)         { kpm_dump_exit(); }

/* --- TRACE：syscall/kfunc trace（默认零初始化，FEAT_ENABLE 才注册） --- */
/* TRACE 降级原因位（FEAT_LIST.reason） */
#define KPM_TRACE_DEG_ENTER   0x1u  /* sys_enter tracepoint/注册符号缺失 */
#define KPM_TRACE_DEG_EXIT    0x2u  /* sys_exit tracepoint 缺失（只有 enter） */
#define KPM_TRACE_DEG_TIME    0x4u  /* ktime 缺失，ts=0 */
static long feat_trace_init(void)
{
    uint32_t reason = 0;

    if (!kf_tracepoint_probe_register || !kf_tracepoint_probe_unregister ||
        !kf_tp_sys_enter)
        reason |= KPM_TRACE_DEG_ENTER;
    if (!kf_tp_sys_exit)
        reason |= KPM_TRACE_DEG_EXIT;
    if (!kf_ktime_get_ns)
        reason |= KPM_TRACE_DEG_TIME;
    kpm_trace_init();
    if (reason) {
        kpm_feat_set_reason(KPM_FEAT_TRACE, reason);
        return KPM_FEATST_DEGRADED;
    }
    return 0;
}
static void feat_trace_exit(void)
{
    kpm_trace_exit();
}

/* --- MEMWATCH：PTE 内存断点 --- */
#define KPM_MW_DEG_FAULT   0x1u  /* do_mem_abort 缺失（无法捕获缺页） */
static long feat_memwatch_init(void)
{
    if (!kf_do_mem_abort) {
        kpm_feat_set_reason(KPM_FEAT_MEMWATCH, KPM_MW_DEG_FAULT);
        return -KPM_E_DISABLED;
    }
    kpm_memwatch_init();
    return 0;
}
static void feat_memwatch_exit(void)
{
    kpm_memwatch_exit();
}
static void feat_memwatch_pre_exit(void)
{
    kpm_memwatch_stop_all();
}

/* --- W^X shadow 无痕 hook（机制参考 kkkbbb/mkpms） --- */
static long feat_wx_init(void)
{
    long ret = kpm_wx_init();

    if (ret) {
        kpm_feat_set_reason(KPM_FEAT_WXSHADOW, (uint32_t)(-ret));
        return ret;
    }
    return 0;
}
static void feat_wx_exit(void)
{
    kpm_wx_exit();
}
static void feat_wx_pre_exit(void)
{
    kpm_wx_pre_exit();
}

/* --- SYSMON：失败时把具体 syscall nr 带入 FEAT reason --- */
static long feat_sysmon_init(void)
{
    long ret = kpm_sysmon_init();

    if (ret) {
        int nr = kpm_sysmon_last_err_nr();
        if (nr > 0)
            kpm_feat_set_reason(KPM_FEAT_SYSMON,
                                ((uint32_t)nr << 8) | (uint32_t)(-ret));
        kpm_log("kpm: sysmon init failed (%ld, nr=%d)\n", ret, nr);
        return ret;
    }
    return 0;
}

/* ===== 功能单元注册表 =====
 * 卸载顺序由 LH_feat.c 的 k_teardown_order 显式声明（事件产生端 →
 * 通道 → 数据面），注册顺序仅示意。
 * 拆卸总原则：事件产生端（触摸/陀螺仪/断点/监控·禁网·停靠）→
 * 命令通道（prctl 排空 → UDP 拆除）→ 数据面（mem_rw/proc/hide/dump/scan）。
 * 未编译单元传 NULL ops（FEAT_LIST 显示 cap=NONE，FEAT_ENABLE 拒绝）。 */
static void kpm_feat_register_all(void)
{
    static const kpm_feat_ops_t ops_scan   = { feat_mem_scan_init, feat_mem_scan_exit, feat_mem_scan_pre_exit };
    static const kpm_feat_ops_t ops_freeze = { feat_mem_freeze_init, feat_mem_freeze_exit, 0 };
    static const kpm_feat_ops_t ops_pscan  = { feat_ptr_scan_init, feat_ptr_scan_exit, 0 };
    static const kpm_feat_ops_t ops_dump   = { feat_dump_init, feat_dump_exit, 0 };
    static const kpm_feat_ops_t ops_hide   = { feat_hide_init, feat_hide_exit, 0 };
    static const kpm_feat_ops_t ops_proc   = { feat_proc_init, feat_proc_exit, 0 };
    static const kpm_feat_ops_t ops_memrw  = { feat_mem_rw_init, feat_mem_rw_exit, 0 };
    static const kpm_feat_ops_t ops_udp    = { feat_udp_init, feat_udp_exit, 0 };
    static const kpm_feat_ops_t ops_debug  = { feat_debug_init, feat_debug_exit, 0 };
    static const kpm_feat_ops_t ops_prctl  = { feat_prctl_init, feat_prctl_exit, 0 };
#ifdef KPM_FEATURE_TOUCH
    static const kpm_feat_ops_t ops_touch  = { feat_touch_init, feat_touch_exit, feat_touch_pre_exit };
#endif
#ifdef KPM_FEATURE_GYRO
    static const kpm_feat_ops_t ops_gyro   = { feat_gyro_init, feat_gyro_exit, 0 };
#endif

    /* 依赖掩码位 i = 依赖 KPM_FEAT_i */
    kpm_feat_register(KPM_FEAT_MEM_SCAN,    "scan",    1u << KPM_FEAT_MEM_RW, KPM_STATE_MEM_SCAN_OK,   &ops_scan);
    kpm_feat_register(KPM_FEAT_MEM_FREEZE,  "freeze",  1u << KPM_FEAT_MEM_RW, KPM_STATE_MEM_FREEZE_OK, &ops_freeze);
    kpm_feat_register(KPM_FEAT_PTR_SCAN,    "ptrscan", 1u << KPM_FEAT_MEM_RW, KPM_STATE_PTR_SCAN_OK,   &ops_pscan);
    kpm_feat_register(KPM_FEAT_DUMP,        "dump",    1u << KPM_FEAT_MEM_RW, 0,                       &ops_dump);
    kpm_feat_register(KPM_FEAT_HIDE,        "hide",    0,                     0,                       &ops_hide);
    kpm_feat_register(KPM_FEAT_PROC,        "proc",    0,                     KPM_STATE_PROC_OK,       &ops_proc);
    kpm_feat_register(KPM_FEAT_MEM_RW,      "memrw",   0,                     KPM_STATE_MEM_RW_OK,     &ops_memrw);
    kpm_feat_register(KPM_FEAT_UDP,         "udp",     0,                     KPM_STATE_UDP_OK,        &ops_udp);
    kpm_feat_register(KPM_FEAT_DEBUG,       "debug",   1u << KPM_FEAT_MEM_RW, KPM_STATE_DEBUG_OK,      &ops_debug);
#ifdef KPM_FEATURE_TOUCH
    kpm_feat_register(KPM_FEAT_TOUCH,       "touch",   0,                     0,                       &ops_touch);
#else
    kpm_feat_register(KPM_FEAT_TOUCH,       "touch",   0,                     0,                       NULL);
#endif
    kpm_feat_register(KPM_FEAT_PRCTL,       "prctl",   0,                     KPM_STATE_PRCTL_HOOK,    &ops_prctl);
#ifdef KPM_FEATURE_GYRO
    kpm_feat_register(KPM_FEAT_GYRO,        "gyro",    0,                     KPM_STATE_GYRO_OK,       &ops_gyro);
#else
    kpm_feat_register(KPM_FEAT_GYRO,        "gyro",    0,                     KPM_STATE_GYRO_OK,       NULL);
#endif
    /* hook 引擎双模式（普通=内核函数 hook_wrap；无痕=BRP 重定向，
     * 依赖 debug 单元的 perf 基础设施） */
    {
        static const kpm_feat_ops_t ops_hook = { kpm_hook2_init_kfunc, kpm_hook2_exit_kfunc, 0 };
        static const kpm_feat_ops_t ops_sthook = { kpm_hook2_init_stealth, kpm_hook2_exit_stealth, 0 };
        kpm_feat_register(KPM_FEAT_HOOK, "hook", 0,
                          KPM_STATE_HOOK_OK, &ops_hook);
        kpm_feat_register(KPM_FEAT_STEALTH_HOOK, "sthook",
                          1u << KPM_FEAT_DEBUG, KPM_STATE_STEALTHOOK_OK,
                          &ops_sthook);
    }
    /* 挂起单元（trap-park 主模式复用 task_work 基础设施；
     * exit 内全量恢复停靠线程——非睡眠，兼容 RCU 临界区卸载） */
    {
        static const kpm_feat_ops_t ops_suspend = { kpm_suspend_init, kpm_suspend_exit, 0 };
        kpm_feat_register(KPM_FEAT_SUSPEND, "suspend", 0,
                          KPM_STATE_SUSPEND_OK, &ops_suspend);
    }
    /* 禁网单元（hook 生命周期 = 单元 enable/disable） */
    {
        static const kpm_feat_ops_t ops_netctl = { kpm_netctl_init, kpm_netctl_exit, 0 };
        kpm_feat_register(KPM_FEAT_NETCTL, "netctl", 0,
                          KPM_STATE_NETCTL_OK, &ops_netctl);
    }
    /* sysmon 单元（监控/劫持 hook 生命周期 = 单元 enable/disable） */
    {
        static const kpm_feat_ops_t ops_sysmon = { feat_sysmon_init, kpm_sysmon_exit, 0 };
        kpm_feat_register(KPM_FEAT_SYSMON, "sysmon", 0,
                          KPM_STATE_SYSMON_OK, &ops_sysmon);
    }
    /* 资源控制单元（亲和性/uclamp，能力探测在 init 内） */
    {
        static const kpm_feat_ops_t ops_resctl = { kpm_resctl_init, kpm_resctl_exit, 0 };
        kpm_feat_register(KPM_FEAT_RESCTL, "resctl", 0,
                          KPM_STATE_RESCTL_OK, &ops_resctl);
    }
    /* 全量 trace / PTE 内存断点 */
    {
        static const kpm_feat_ops_t ops_trace = { feat_trace_init, feat_trace_exit, 0 };
        kpm_feat_register(KPM_FEAT_TRACE, "trace", 0,
                          KPM_STATE_TRACE_OK, &ops_trace);
    }
    {
        static const kpm_feat_ops_t ops_mw = { feat_memwatch_init, feat_memwatch_exit, feat_memwatch_pre_exit };
        kpm_feat_register(KPM_FEAT_MEMWATCH, "memwatch", 0,
                          KPM_STATE_MEMWATCH_OK, &ops_mw);
    }
    /* W^X shadow 无痕 hook */
    {
        static const kpm_feat_ops_t ops_wx = { feat_wx_init, feat_wx_exit, feat_wx_pre_exit };
        kpm_feat_register(KPM_FEAT_WXSHADOW, "wxshadow", 0,
                          KPM_STATE_WXSHADOW_OK, &ops_wx);
    }
}



/* ===== 生命周期函数 ===== */

/* 初始化：加载时执行
 * args: 加载参数（可指定功能子集）
 * event: 触发事件 ("load-file", "on-boot", "post-fs-data")
 */
static long kpm_drv_init(const char *args, const char *event, void *reserved)
{
    long ret;

    (void)reserved;  /* 框架预留参数，当前未使用 */

    /* 深度加固: 首句解密 .kpm.str(整节区字符串)。必须在任何用到字符串字面量的
     * 语句之前(下方第一个 printk 的格式串就在加密区), 否则读到密文。 */
    kpm_armor_init();

    /* 调试：在依赖任何符号之前输出，确认模块是否被加载 */
    kpm_printk("LH_debug: init entered, args=%s, event=%s\n",
           args ? args : "null", event ? event : "null");

    /* 第一步：解析所有内核符号（必须在其他子模块 init 之前）*/
    ret = kpm_syms_init();
    if (ret) {
        /* kpm_log 尚未初始化，暂不记录 */
    }
    kpm_printk("LH_debug: step1 syms_init done, ret=%ld\n", ret);

    /* 文件持久化日志：初始化时创建/清空日志文件
     * 这样可以记录后续所有步骤，即使崩溃重启仍可读取 */
    kpm_debug_mark("=== KPM INIT START ===");

    /* 第二步：尽早初始化内部日志缓冲区（在其他子模块 init 之前）
     * 这样后续所有子模块的 kpm_log 调用都能被记录。
     * kpm_log_init 之前不输出任何 pr_info，避免 dmesg 时间窗口泄漏 */
    kpm_log_init();
    kpm_log("kpm: hidden_driver init, event=%s, args=%s\n",
            event ? event : "(null)", args ? args : "(null)");
    kpm_log("kpm: page_shift=%lld, va_bits=%lld, page_level=%lld\n",
            page_shift, va_bits, page_level);
    kpm_log("kpm: kernel_va=0x%llx, kernel_pa=0x%llx, pgd_va=0x%llx\n",
            kernel_va, kernel_pa, pgd_va);
    if (ret) {
        kpm_log("kpm: some symbols missing (ret=%ld), continuing with reduced functionality\n", ret);
    }
    /* probe_rcu_nesting_offset 在 kpm_syms_init 内标定（早于 log_init），
     * 此处补报其值：决定直接 unload 时 RCU 救援走"借出"（>0）还是"跳过"
     * （0=退回 rcu_read_lock_any_held）路径。 */
    kpm_log("kpm: rcu_nesting_offset=%d (>0=borrow path, 0=any_held fallback)\n",
            g_rcu_nesting_offset);
    /* 安全 tasklist：双锚点推导真实 tasks 偏移（log 就绪后执行，
     * 失败仅降级 suspend-park/resctl 遍历，不致命） */
    kpm_tasklist_verify();
    kpm_debug_mark("1-syms_init+log_init");
    kpm_printk("LH_debug: step2 log_init done\n");

    kpm_set_state(KPM_STATE_INIT_OK);
    kpm_debug_mark("2-state_set");
    kpm_printk("LH_debug: step3 state OK\n");

    /* ===== 功能单元注册 =====
     * 默认仅启用：内存读写 + prctl/UDP 两协议接口 + 被动诊断（GET_LOG/
     * HOOK_INFO）。其余功能零初始化——不解析符号、不挂钩、不占硬件断点/
     * 工作队列/内存表，由客户端 FEAT_ENABLE 惰性开启（0x1200 命令组），
     * FEAT_DISABLE 完全拆卸。 */
    kpm_feat_init();
    kpm_filter_init();   /* 共享 filter 一次性清零 */
    kpm_force_init();    /* force 会话清零 */
    kpm_feat_register_all();

    /* 1. prctl FP hook（核心通道，失败致命——所有控制命令经此进入，
     *    且它是默认态下唯一的系统级 hook，即协议接口本身） */
    ret = kpm_feat_enable(KPM_FEAT_PRCTL);
    if (ret < 0) {
        kpm_log("kpm: prctl channel init failed (%ld), FATAL\n", ret);
        kpm_armor_seal();
        return ret;
    }
    kpm_debug_mark("5-prctl_channel");
    kpm_printk("LH_debug: step6 prctl channel ok\n");

    /* 2. UDP 通道（非致命：失败仅 UDP 不可用，prctl 仍正常） */
    kpm_feat_enable(KPM_FEAT_UDP);
    kpm_debug_mark("11-udp_start");

    /* 3. 内存读写引擎（默认启用，非致命） */
    kpm_feat_enable(KPM_FEAT_MEM_RW);
    kpm_debug_mark("9-mem_rw_init");
    kpm_printk("LH_debug: step10 mem_rw done\n");

    /* 初始化隐蔽性强化子模块
     * 隐蔽性完全依赖架构层自然方法（DMA/IN-PLACE MUTATION/UID过滤），
     * 不修改系统日志或 hook 安全子系统。
     * 非致命：失败不影响其他功能
     */
    ret = kpm_stealth_init(args);
    if (ret) {
        kpm_log("kpm: stealth init failed (%ld)\n", ret);
    } else {
        kpm_set_state(KPM_STATE_STEALTH_OK);
    }
    kpm_debug_mark("6-stealth_init");

    kpm_log("kpm: hidden_driver ready (minimal init), state=0x%x\n", kpm_get_state());
    kpm_debug_mark("=== KPM INIT DONE ===");
    kpm_printk("LH_debug: init complete\n");
    /* 深度加固: 末尾抹零 .kpm.once(一次性符号解析代码) */
    kpm_armor_seal();
    return 0;
}

/* ===== info 状态导出（SukiSU/FolkPatch UI 导出依赖） =====
 * 文件由 KPM_CTL0 "info" 命令写入（用户主动操作生成，非被动痕迹）。
 * 版本统一取 LH_version.h（LH_VERSION_STR / LH_VERSION_CODE）；
 * 输出为紧凑 key=value + 表格式，功能状态遍历 FEAT 注册表
 * （kpm_feat_list_fill），新增功能单元自动出现，info 格式化代码无需跟着改；
 * 数据源是 kpm_fill_state_info() 的 256B kpm_state_info_t（与 UDP
 * HOOK_INFO 同源）。
 * 写文件失败必须返回错误（否则 App 误判成功）。 */
#define KPM_INFO_FILE_PATH "/data/local/tmp/LH_info_test.txt"

/* 符号名称映射（索引 = KPM_SYM_*，与客户端 udp_test_mem.py sym_names 一致） */
static const char *const kpm_sym_names[] = {
    "copy_from_user", "copy_to_user",
    "copy_from_kernel_nofault", "copy_to_kernel_nofault",
    "memremap", "memunmap", "vmap", "vunmap",
    "filp_open", "kernel_read", "kernel_write", "kernel_read_iter",
    "input_handle_event", "input_event",
    "find_get_pid", "get_pid_task", "get_task_mm", "mmput",
    "find_vma", "rcu_read_lock", "rcu_read_unlock", "init_task",
    "put_task_struct", "get_cmdline", "get_task_comm",
    "sock_create_kern", "alloc_workqueue", "init_net", "queue_work",
    "vsnprintf", "printk", "find_task_by_vpid", "__task_pid_nr_ns",
    "mmap_read_lock", "mmap_read_unlock",
    "register_user_hw_bp", "unregister_hw_bp",
    "kmalloc", "kfree", "vmalloc", "vfree",
    "vsnprintf2", "snprintf", "simple_strtoull", "synchronize_rcu",
};
#define KPM_SYM_NAME_COUNT ((int)(sizeof(kpm_sym_names) / sizeof(kpm_sym_names[0])))

/* 逐符号“影响功能/缺失后果”说明表不参与编译（避免无用的静态数据与警告）。 */
#if 0
/* 非关键缺失符号（客户端同款：缺失时给出说明，不算关键缺失） */
static const char *const kpm_sym_noncritical[] = {
    "copy_to_kernel_nofault", "kernel_read_iter", "vsnprintf2",
};

/* ===== 符号缺失 → 受影响功能明细 =====
 * 目的：info 诊断（/data/local/tmp/LH_info_test.txt 与 PC 端 udp_test_mem.py）
 *       报"缺失了哪些符号"时，直接说清"具体哪个功能受影响、怎么回退"，
 *       避免只看符号名不知道后果。
 * feature = 该符号服务的功能（按各 .c 里的实际调用点归纳）
 * impact  = 缺失后的后果与回退链
 * ⚠ 顺序必须与 kpm_sym_names[] **逐项一一对应**（同索引同行）。 */
typedef struct {
    const char *feature;
    const char *impact;
} kpm_sym_impact_t;

static const kpm_sym_impact_t kpm_sym_impacts[] = {
/*  0 copy_from_user               */ { "用户态内存读写(断点调试/UDP 控制/拦截)", "回退 _copy_from_user → __arch_copy_from_user" },
/*  1 copy_to_user                 */ { "所有回传客户端的路径(UDP 结果/触摸/扫描/dump)", "回退 _copy_to_user → __arch_copy_to_user" },
/*  2 copy_from_kernel_nofault     */ { "内核内存读取底座(偏移探测/扫描/dump/断点)", "回退 probe_kernel_read → __probe_kernel_read" },
/*  3 copy_to_kernel_nofault       */ { "仅 DMA/WB 写入路径(读取不需要它)", "回退 probe_kernel_write；mem_rw 读取不受影响" },
/*  4 memremap                     */ { "物理内存映射(mem_rw 的 DMA 首选)", "回退 ioremap_cache→ioremap_prot→ioremap；再缺 mem_rw 降 WB" },
/*  5 memunmap                     */ { "物理内存解映射", "回退 iounmap" },
/*  6 vmap                         */ { "DMA 读写映射(mem_rw 走 DMA 的必要条件)", "vmap/vunmap 缺一个则 mem_rw 降为 WB" },
/*  7 vunmap                       */ { "DMA 读写解映射", "同上" },
/*  8 filp_open                    */ { "文件打开(cmdline filp 回退/info 导出/读取文件)", "回退 comm 或内存读路径" },
/*  9 kernel_read                  */ { "文件读(与 filp_open 同一批路径)", "缺则相关文件类命令失败" },
/* 10 kernel_write                 */ { "文件写(info 导出到 /data/local/tmp、dump 落盘)", "缺则 info 文件导出失败" },
/* 11 kernel_read_iter             */ { "仅 cmdline 的 procfs 回退路径", "非关键：get_cmdline 就绪时无影响" },
/* 12 input_handle_event           */ { "触摸注入(capture/hook 路径)", "回退 input_event；再缺则 touch 降为 inplace" },
/* 13 input_event                  */ { "触摸注入备用路径", "见 input_handle_event 行" },
/* 14 find_get_pid                 */ { "进程查找(进程列表/maps/隐藏/陀螺仪定位/按 pid 内存)", "回退 find_vpid" },
/* 15 get_pid_task                 */ { "pid → task_struct(同上那批功能)", "回退 pid_task" },
/* 16 get_task_mm                  */ { "取进程 mm(进程 maps/VMA、按 pid 内存读写、陀螺仪定位)", "缺则这些路径整体失败" },
/* 17 mmput                        */ { "mm 引用归还(与 get_task_mm 配对)", "缺则 mm 引用泄漏 → 进程内存无法释放" },
/* 18 find_vma                     */ { "VMA 查找(进程 maps/按地址查 region/页表遍历/触摸命中判定)", "缺则 maps/region 类功能失败" },
/* 19 rcu_read_lock                */ { "RCU 读锁(免引用 pid→task、页表遍历)", "回退 __rcu_read_lock(4.20+ 实际符号名)" },
/* 20 rcu_read_unlock              */ { "RCU 读解锁(与上配对)", "回退 __rcu_read_unlock" },
/* 21 init_task                    */ { "全部运行时偏移探测的锚点(usage/pid/mm/tgid)", "缺则偏移探测整体失效，功能大幅降级" },
/* 22 put_task_struct              */ { "task 引用归还(进程枚举/maps/隐藏/断点探测/按 pid 内存)", "回退 手动递减 usage+__put_task_struct(需已标定)；未标定则只泄漏" },
/* 23 get_cmdline                  */ { "完整命令行(cmdline 的 native 路径)", "回退 arg_start/end 内存 → filp_open → 16 字节 comm" },
/* 24 get_task_comm                */ { "进程名(进程列表/隐藏/断点上报)", "缺则进程名不可用" },
/* 25 sock_create_kern             */ { "内核 UDP 通道(常驻监听/命令收发)", "缺则 UDP 通道整体不可用" },
/* 26 alloc_workqueue              */ { "工作队列(UDP 异步发送/调试)", "缺则相关异步路径失败" },
/* 27 init_net                     */ { "内核 socket 网络命名空间(UDP 建 socket 用)", "缺则 UDP 通道不可用" },
/* 28 queue_work                   */ { "异步任务投递(UDP 发送队列/调试)", "缺则异步发送失败" },
/* 29 vsnprintf                    */ { "日志与状态文本格式化", "缺则日志/诊断文本缺失" },
/* 30 printk                       */ { "debug 版 dmesg 输出", "缺则 dmesg 无输出(不影响功能)" },
/* 31 find_task_by_vpid            */ { "按 vpid 找 task(隐藏进程回填/校验)", "缺则隐藏功能的 vpid 校验跳过" },
/* 32 __task_pid_nr_ns             */ { "task → pid(进程列表的 pid 字段)", "缺则进程列表 pid 字段不可用" },
/* 33 mmap_read_lock               */ { "mmap 读锁(VMA 遍历/页表操作，5.12+ 原生符号)", "回退 RCU 读锁/适配层" },
/* 34 mmap_read_unlock             */ { "mmap 读解锁(与上配对)", "见 mmap_read_lock 行" },
/* 35 register_user_hw_bp          */ { "硬件断点(断点功能)", "缺则硬件断点不可用(其余功能不受影响)" },
/* 36 unregister_hw_bp             */ { "硬件断点注销", "缺则已注册断点无法注销" },
/* 37 kmalloc                      */ { "内核小内存分配(扫描/进程枚举/陀螺仪/调试)", "缺则依赖它的路径失败" },
/* 38 kfree                        */ { "内核小内存释放(与上配对)", "见 kmalloc 行" },
/* 39 vmalloc                      */ { "大块内存分配(内存扫描/指针扫描/缓存池)", "缺则扫描类功能失败" },
/* 40 vfree                        */ { "大块内存释放(与上配对)", "见 vmalloc 行" },
/* 41 vsnprintf2                   */ { "全工程无调用点(索引占位)", "非关键：缺失无影响" },
/* 42 snprintf                     */ { "文本格式化(进程名/路径/日志)", "缺则相关文本构建失败" },
/* 43 simple_strtoull              */ { "命令参数解析(字符串 → 数字)", "缺则带数字参数的 UDP 命令失败" },
/* 44 synchronize_rcu              */ { "RCU 同步(卸载/拦截器 teardown 等待)", "缺则卸载路径改走轮询等待" },
};
#define KPM_SYM_IMPACT_COUNT ((int)(sizeof(kpm_sym_impacts) / sizeof(kpm_sym_impacts[0])))
#endif /* 0 */

static inline int kpm_sym_avail(const kpm_state_info_t *si, int idx)
{
    return (int)((si->sym_bitmap[idx / 32] >> (idx % 32)) & 1u);
}

#if 0 /* 逐符号分类/回退说明辅助函数 */
/* 该符号是否属于"非关键缺失"（缺失只降级不致命） */
static int kpm_sym_is_noncritical(int idx)
{
    int j;

    for (j = 0; j < (int)(sizeof(kpm_sym_noncritical) /
                          sizeof(kpm_sym_noncritical[0])); j++)
        if (!lib_strcmp(kpm_sym_names[idx], kpm_sym_noncritical[j]))
            return 1;
    return 0;
}

/* 该缺失符号是否已有运行期生效的回退路径（缺失 ≠ 功能不可用）。
 * 返回回退说明文本；返回 NULL = 真降级（该符号缺失确实砍功能）。 */
static const char *kpm_sym_fallback_active(int idx)
{
    if (idx < 0 || idx >= KPM_SYM_NAME_COUNT)
        return NULL;
    if (!lib_strcmp(kpm_sym_names[idx], "put_task_struct"))
        return (kpm_put_task_path() == 1)
                   ? "手动递减 usage + __put_task_struct（usage 已标定，功能不降级）"
                   : NULL;
    return NULL;
}
#endif /* 0 */

/* put_task 释放路径 → 文本（含"为什么不可用"） */
static const char *kpm_put_task_text(uint8_t p)
{
    switch (p) {
    case 0:  return "原生 put_task_struct";
    case 1:  return "手动+__put_task_struct(已标定)";
    case 2:  return "free_task(已禁用)";
    case 3:  return "泄漏(__put_task_struct 也缺)";
    case 4:  return "泄漏(usage 标定未执行)";
    case 5:  return "泄漏(usage 标定失败)";
    case 6:  return "泄漏(标定所需符号缺失)";
    default: return "泄漏(原因未知)";
    }
}

static long kpm_dump_info_to_file(const char *info_path)
{
    char buf[4096];
    int used = 0;
    struct file *fp;
    loff_t pos = 0;
    kpm_state_info_t si;
    int raw_w = 0, raw_h = 0;
    int scale, sw, sh;
    uint8_t mem_rw_path, touch_path, cmdline_path, put_task_path,
            vmemmap_source;
    int i, avail_count = 0;

    if (!kf_filp_open || !kf_filp_close || !kf_kernel_write || !kf_snprintf)
        return -KPM_E_NOTFOUND;

    /* ===== 与 UDP HOOK_INFO 完全一致的数据源 ===== */
    scale = kpm_touch_get_scale();
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

    /* ===== 紧凑状态输出（key=value + FEAT 表，无说明文字） ===== */
#define INFO_APPEND(fmt, ...) do { \
    int _r = kf_snprintf(buf + used, (size_t)(sizeof(buf) - (size_t)used), \
                         fmt, ##__VA_ARGS__); \
    if (_r < 0) _r = 0; \
    if (_r > (int)(sizeof(buf) - (size_t)used)) \
        _r = (int)(sizeof(buf) - (size_t)used); \
    used += _r; \
    if (used >= (int)sizeof(buf)) used = (int)sizeof(buf) - 1; \
} while (0)

    INFO_APPEND("===== KPM 模块状态信息 =====\n");

    /* ========== 顶部：版本 + 状态位图 + FEAT 注册表（新版本自动适配） ==========
     * 功能状态统一来自 FEAT 注册表，新增单元自动出现，
     * info 无需再改格式化代码。 */
    INFO_APPEND("LH %s (0x%08X)\n", LH_VERSION_STR, (unsigned int)LH_VERSION_CODE);
    INFO_APPEND("state=0x%08X init=%d syms=%d\n",
                (unsigned int)si.state,
                (si.state & KPM_STATE_INIT_OK) ? 1 : 0,
                (int)si.syms_init_ret);
    INFO_APPEND("core: prctl=%d udp=%d mem_rw=%d\n",
                (si.state & KPM_STATE_PRCTL_HOOK) ? 1 : 0,
                (si.state & KPM_STATE_UDP_OK) ? 1 : 0,
                (si.state & KPM_STATE_MEM_RW_OK) ? 1 : 0);

    {
        kpm_feat_entry_t feats[KPM_FEAT_MAX];
        long fn = kpm_feat_list_fill(feats, KPM_FEAT_MAX);
        int k;
        INFO_APPEND("features=%ld\n", fn > 0 ? fn : 0);
        for (k = 0; k < fn; k++)
            INFO_APPEND("  %2u %-8s state=%u cap=%u reason=0x%X\n",
                        (unsigned int)feats[k].id, feats[k].name,
                        (unsigned int)feats[k].state,
                        (unsigned int)feats[k].cap,
                        (unsigned int)feats[k].reason);
    }

    /* force 会话 + 断点容量（新增能力只加汇总行） */
    {
        kpm_force_info_t fi;
        kpm_bp_caps_t bc;
        lib_memset(&fi, 0, sizeof(fi));
        lib_memset(&bc, 0, sizeof(bc));
        (void)kpm_force_control(KPM_FORCE_OP_QUERY, 0, 0, 0, &fi);
        (void)kpm_debug_bp_info(&bc);
        INFO_APPEND("force: active=%u mask=0x%X remaining=%u caps=0x%X\n",
                    (unsigned int)fi.active, (unsigned int)fi.mask,
                    (unsigned int)fi.remaining_ms, (unsigned int)fi.caps);
        INFO_APPEND("debug: bp=%u/%u user=%u kernel=%u brp=%d wrp=%d "
                    "step=%u sync=%u\n",
                    (unsigned int)bc.used_slots, (unsigned int)bc.max_slots,
                    (unsigned int)bc.user_bps, (unsigned int)bc.kernel_bps,
                    (int)bc.brp, (int)bc.wrp,
                    (unsigned int)bc.step_ok, (unsigned int)bc.sync_ok);
    }


    /* 陀螺仪/传感器：仅汇总（逐轴明细属调试信息，需要时走 GET_LOG） */
    {
        uint64_t up_hits = 0, tp_hits = 0;
        int up_ok = 0, tp_ok = 0;
        kpm_gyro_get_stats(&up_hits, &tp_hits, &up_ok, &tp_ok);
        INFO_APPEND("gyro: ready=%d dev=%d lock=%d ctrl=%d client=%d "
                    "uprobe=%d/%llu tp=%d/%llu\n",
                    (int)si.gyro_ready, (int)si.gyro_dev_count,
                    (int)si.gyro_locked_axes, (int)si.gyro_controlled_axes,
                    (int)si.gyro_client_alive,
                    up_ok, (unsigned long long)up_hits,
                    tp_ok, (unsigned long long)tp_hits);
    }

    INFO_APPEND("kver=%u.%u.%u magic=0x%08X ver=%u\n",
                ((unsigned int)si.kver >> 16) & 0xFF,
                ((unsigned int)si.kver >> 8) & 0xFF,
                (unsigned int)si.kver & 0xFF,
                (unsigned int)si.magic, (unsigned int)si.version);
    INFO_APPEND("touch: ready=%d node=%d screen=%dx%d raw=%dx%d scale=%d "
                "intercept=%d active=%d\n",
                (int)si.touch_ready, (int)si.node_offset,
                (int)si.screen_w, (int)si.screen_h,
                (int)si.raw_w, (int)si.raw_h, (int)si.screen_scale,
                (int)si.intercept_on, (int)si.active_count);

    /* 功能路径：只给短值，不写“为什么/影响”说明 */
    INFO_APPEND("path: mem_rw=%s touch=%s cmdline=%s put_task=%s "
                "task_fetch=%s vmemmap=%s\n",
                (si.mem_rw_path == KPM_PATH_MEM_RW_DMA) ? "DMA" : "WB",
                (si.touch_path == KPM_PATH_TOUCH_CAPTURE) ? "capture" :
                (si.touch_path == KPM_PATH_TOUCH_INPLACE) ? "inplace" : "none",
                (si.cmdline_path == KPM_PATH_CMDLINE_NATIVE) ? "native" :
                (si.cmdline_path == KPM_PATH_CMDLINE_MEM) ? "mem" :
                (si.cmdline_path == KPM_PATH_CMDLINE_FILP) ? "filp" : "comm",
                kpm_put_task_text(si.put_task_path),
                (si.task_fetch_path == KPM_TASK_FETCH_NOREF) ? "noref" : "ref",
                (si.vmemmap_source == 0) ? "sym" :
                (si.vmemmap_source == 1) ? "var" : "calc");

    /* 符号可用性：只给计数 + 缺失名单（不写影响/后果说明） */
    for (i = 0; i < KPM_SYM_NAME_COUNT; i++)
        if (kpm_sym_avail(&si, i)) avail_count++;
    INFO_APPEND("symbols=%d/%d\n", avail_count, KPM_SYM_NAME_COUNT);
    if (avail_count < KPM_SYM_NAME_COUNT) {
        int shown = 0;
        INFO_APPEND("missing:");
        for (i = 0; i < KPM_SYM_NAME_COUNT && shown < 24; i++) {
            if (kpm_sym_avail(&si, i))
                continue;
            INFO_APPEND(" %s", kpm_sym_names[i]);
            shown++;
        }
        if (shown < KPM_SYM_NAME_COUNT - avail_count)
            INFO_APPEND(" ...");
        INFO_APPEND("\n");
    }

    /* 回退状态：compact key=value（0=主符号，1/2/3=回退级） */
    {
        static const char *const fb_names[] = {
            "copy_from_user", "copy_to_user", "copy_from_kernel_nofault",
            "memremap", "memunmap", "find_get_pid", "get_pid_task", "mmput",
            "printk", "put_task_struct", "queue_work", "flush_workqueue",
            "vmalloc", "kmalloc", "kernel_read", "kernel_write",
        };
        int issues = 0;
        INFO_APPEND("fallback:");
        for (i = 0; i < 16; i++) {
            int val = (int)((si.fallback_bitmap >> (i * 2)) & 3u);
            if (!val)
                continue;
            INFO_APPEND(" %s=%d", fb_names[i], val);
            issues++;
        }
        if (!issues)
            INFO_APPEND(" none");
        INFO_APPEND("\n");
    }

    /* task_struct 偏移：一行 key=value（0=未探测；pid 验证单列 0/1） */
    INFO_APPEND("offsets: tasks=%d tgid=%d mm=%d pid=%d rp=%d usage=%d "
                "arg_s=%d arg_e=%d vm_s=%d vm_e=%d vm_n=%d mm_mmap=%d\n",
                (int)si.tasks_offset, (int)si.tgid_offset,
                (int)si.mm_offset, (int)si.pid_offset,
                (int)si.real_parent_offset, (int)si.usage_offset,
                (int)si.arg_start_offset, (int)si.arg_end_offset,
                (int)si.vm_start_offset, (int)si.vm_end_offset,
                (int)si.vm_next_offset, (int)si.mm_mmap_offset);
    if (g_pid_offset > 0)
        INFO_APPEND("pid_verified=%d\n", g_pid_offset_verified ? 1 : 0);

    /* 框架变量 + 版本一致性（module_version 应等于 LH_VERSION_CODE） */
    INFO_APPEND("frame: vmemmap=0x%016llX memstart=0x%016llX pgd=0x%016llX "
                "mm_pgd=%u va_bits=%d ps=%d pl=%d\n",
                (unsigned long long)si.vmemmap_base,
                (unsigned long long)si.memstart_addr,
                (unsigned long long)si.pgd_va,
                (unsigned int)si.mm_pgd_offset,
                (int)si.va_bits, (int)si.page_shift, (int)si.page_level);
    {
        unsigned int bt = (unsigned int)si.build_time;
        INFO_APPEND("module_version=0x%08X build=",
                    (unsigned int)si.module_version);
        if (bt == 0)
            INFO_APPEND("unknown\n");
        else
            INFO_APPEND("%u-%02u-%02u %02u:%02u\n",
                        (bt >> 20) & 0xFFF, (bt >> 16) & 0xF,
                        (bt >> 11) & 0x1F, (bt >> 6) & 0x1F, bt & 0x3F);
    }
    INFO_APPEND("\n");

#undef INFO_APPEND

    fp = kf_filp_open(info_path,
                      1 /*O_WRONLY*/ | 0100 /*O_CREAT*/ | 01000 /*O_TRUNC*/,
                      0644);
    /* 内核指针判断用 IS_ERR_VALUE 语义（无符号 >= -4095），
     * 不能用 (long)fp < 0——有效内核地址 0xffffff... 高位置 1，
     * 作为 signed long 恒为负 → 把成功误判为失败。 */
    if (!fp || (unsigned long)fp >= (unsigned long)-4095) {
        /* 打印实际错误码（PTR_ERR）：EACCES=SELinux/权限，
         * ENOENT=路径，EINVAL=参数等。 */
        long ferr = (fp && (unsigned long)fp >= (unsigned long)-4095)
                        ? (long)(unsigned long)fp
                        : -5 /* ENOMEM(内核模块自定义 errno) */;
        kpm_log("kpm: info filp_open %s failed err=%ld (0x%llx)\n",
                info_path, ferr, (unsigned long long)(unsigned long)fp);
        kpm_printk("LH_debug: info filp_open %s failed err=%ld (0x%llx)\n",
                   info_path, ferr,
                   (unsigned long long)(unsigned long)fp);
        return -KPM_E_FAULT;
    }
    {
        ssize_t w = kf_kernel_write(fp, buf, (size_t)used, &pos);
        kf_filp_close(fp, NULL);
        if (w < 0) {
            kpm_log("kpm: info kernel_write failed err=%ld\n", (long)w);
            kpm_printk("LH_debug: info kernel_write failed err=%ld\n", (long)w);
            return -KPM_E_FAULT;
        }
    }
    return 0;
}


/* 控制函数0：字符串命令接口
 *
 * root 管理器通过 KPM_CTL0 发送字符串命令：
 *   "udp 1"  启动 UDP 调试服务（默认端口 17891）
 *   "udp 0"  关闭 UDP 调试服务
 *   "info"   返回模块状态（2026-08-06 起不落盘，诊断信息走 UDP GET_LOG）
 * 空参数/其他参数：返回模块状态码
 */
static long kpm_drv_control0(const char *args, char *out_msg, int outlen)
{
    kpm_log("kpm: control0, args=%s\n", args ? args : "(null)");

    if (args && args[0] != '\0') {
        char cmd[256];
        const char *cmd_path = NULL;
        long n;

        /* 拷贝到本地缓冲区并终止（args 来自框架 vmalloc，长度未保证）。
         * 支持 "info [path]"：path 可选，指定导出目标（App 自有可写目录），
         * 为空则用默认 /data/local/tmp/LH_info_test.txt（SukiSU root 场景）。 */
        n = 0;
        while (args[n] && n < (long)sizeof(cmd) - 1)
            n++;
        {
            int i;
            for (i = 0; i < n; i++)
                cmd[i] = args[i];
        }
        cmd[n] = '\0';
        {
            char *sp = cmd;
            while (*sp && *sp != ' ') sp++;
            if (*sp == ' ') {
                *sp = '\0';
                cmd_path = sp + 1;
                while (*cmd_path == ' ') cmd_path++;
                if (*cmd_path == '\0') cmd_path = NULL;
            }
        }

        /* 说明（2026-08-01）：udp 1 / udp 0 命令已移除。
         * UDP 服务改为模块加载时自动启动（kpm_drv_init 调用 kpm_udp_init），
         * 阻塞收包模式 + 来源 IP 过滤（仅非本机 IP 的内网 IP）。
         * 避免 SukiSU 传参格式差异与结构偏移探测导致的崩溃。 */

        /* "info" 命令：输出完整状态到文件
         * 2026-08-07 恢复：写 /data/local/tmp/LH_info_test.txt（SukiSU App
         * "info 导出"依赖）。修复 2026-08-01：SukiSU 将非 0 返回码显示为失败。
         * 2026-08-19：支持 "info <path>" 指定导出目录（FolkPatch App 场景
         * /data/local/tmp 在 untrusted_app 域下 EACCES，可改为 App 自己的
         * files 目录，如 /data/user/0/me.yuki.folk/files/LH_info.txt）。
         * 文件作为副作用生成，命令本身返回 0 表示成功（写文件失败才返回错误）。 */
        if (!lib_strcmp(cmd, "info")) {
            long r = kpm_dump_info_to_file(cmd_path ? cmd_path
                                                    : KPM_INFO_FILE_PATH);
            kpm_printk("LH_debug: info dump ret=%ld\n", r);
            return (r >= 0) ? 0 : r;
        }

        /* 未知命令：返回模块状态 */
        kpm_log("kpm: unknown cmd '%s'\n", cmd);
    }

    /* 返回模块状态信息 */
    if (out_msg && outlen > 0) {
        char buf[128];
        uint32_t state = kpm_get_state();
        buf[0] = '0' + ((state >> 4) & 0xF);
        buf[1] = '0' + (state & 0xF);
        buf[2] = '\0';
        if (outlen > 2) {
            compat_copy_to_user(out_msg, buf, 3);
        }
    }
    return 0;
}

/* 控制函数1：指针参数接口 */
static long kpm_drv_control1(void *a1, void *a2, void *a3)
{
    kpm_log("kpm: control1, a1=%llx, a2=%llx, a3=%llx\n", a1, a2, a3);
    return 0;
}

/* 退出：卸载时执行
 * 安全卸载策略（优先保障系统稳定性）：
 *   2026-10（v1.5 阶段 0）：拆卸路径统一收敛到功能注册表——
 *   kpm_feat_disable_all() 按注册逆序两阶段拆除：
 *     pass1 pre_exit：停一切事件产生端（触摸动画/输入捕获 hook/扫描中止）
 *       并强制恢复停靠/挂起线程——先于一切资源释放；
 *     pass2 exit（注册逆序 = 事件产生端 → 命令通道 → 数据面）：
 *       资源控制/监控/禁网/挂起/无痕hook → 陀螺仪 → prctl hook 排空
 *       → touch 释放 → 断点 disarm → UDP 拆除 → mem_rw/proc/hide/
 *       dump/ptrscan/freeze/scan。
 *   顺序完整保留 1.4.x 审计结论：
 *   - 输入捕获先拆（W1：queue_work 到已销毁 wq 的 UAF）
 *   - prctl 排空先于 touch 释放（审计 #3：在途命令操作 touch 对象）
 *   - 断点先于 UDP（D-A/D-B：通知 work 与 sock_release TOCTOU）
 *   - 扫描中止先于 UDP（审计 #9：flush_workqueue 数十秒卡死）
 *   FEAT_DISABLE 过的单元已处于 DISABLED，自动跳过（幂等，无双释放）。
 */
static long kpm_drv_exit(void *reserved)
{
    kpm_log("kpm: hidden_driver exit begin\n");

    (void)reserved;  /* 框架预留参数，当前未使用 */

    /* 0-3. 全部已启用功能单元逆序拆除（含新功能单元与核心通道） */
    kpm_feat_disable_all();
    kpm_log("kpm: all feature units torn down\n");
    kpm_force_exit();

    /* 4. 隐蔽性子模块退出（兼容性占位，当前无资源需释放） */
    kpm_stealth_exit();

    /* 5. 清除状态标志（含 v1.5 新增位；单元正常退出时已各自清除，
     *    此处兜底——FAILED/残留态也不影响下次加载） */
    kpm_clear_state(KPM_STATE_INIT_OK | KPM_STATE_PRCTL_HOOK |
                    KPM_STATE_TOUCH_FOUND | KPM_STATE_MEM_RW_OK |
                    KPM_STATE_INTERCEPT_OK | KPM_STATE_UDP_OK |
                    KPM_STATE_MEM_SCAN_OK | KPM_STATE_MEM_FREEZE_OK |
                    KPM_STATE_PTR_SCAN_OK | KPM_STATE_DEBUG_OK |
                    KPM_STATE_PROC_OK | KPM_STATE_STEALTH_OK |
                    KPM_STATE_GYRO_OK | KPM_STATE_HOOK_OK |
                    KPM_STATE_STEALTHOOK_OK | KPM_STATE_SUSPEND_OK |
                    KPM_STATE_NETCTL_OK | KPM_STATE_SYSMON_OK |
                    KPM_STATE_RESCTL_OK);

    /* 6. 最后退出日志模块（确保整个卸载过程都能被记录） */
    kpm_log("kpm: hidden_driver exit complete\n");
    kpm_log_exit();

    return 0;
}

/* ===== KPM 入口注册 ===== */
KPM_INIT(kpm_drv_init);
KPM_CTL0(kpm_drv_control0);
KPM_CTL1(kpm_drv_control1);
KPM_EXIT(kpm_drv_exit);
