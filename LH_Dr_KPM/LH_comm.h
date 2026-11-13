/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_COMM_H_
#define _KPM_COMM_H_

#include <stdint.h>

/* ===== User <-> Kernel communication command codes =====
 * Via prctl(option, arg2, arg3, arg4, arg5)
 * option = command code, arg2~arg5 are parameters
 *
 * Command codes are XOR-obfuscated with KPM_CMD_XOR_KEY at build time.
 * This prevents static analysis from identifying prctl command codes
 * by scanning the binary for known constants (0x1001-0x1182).
 * Both kernel module and kpmctl use the same key.
 */

/* XOR key: derived from timestamp-independent constant.
 * Chosen to produce values that don't collide with standard prctl options
 * (PR_SET_NAME=15, PR_GET_NAME=16, etc.) and don't look like typical
 * magic numbers to anti-cheat signature scanners. */
#define KPM_CMD_XOR_KEY  0xDEAD37F3

/* Obfuscation macro: XOR the command code with the key.
 * KPM_CMD(cmd) produces the obfuscated value sent over prctl.
 * Usage in kernel: case KPM_CMD(KPM_CMD_READ_MEM): ...
 * Usage in userspace: prctl(KPM_CMD(KPM_CMD_READ_MEM), ...) */
#define KPM_CMD(cmd)  ((cmd) ^ KPM_CMD_XOR_KEY)

/* General commands */
#define KPM_CMD_READ_MEM     0x1001   /* Read process memory: arg2=pid, arg3=remote_addr, arg4=local_buf, arg5=len */
#define KPM_CMD_WRITE_MEM    0x1002   /* Write process memory: arg2=pid, arg3=remote_addr, arg4=local_buf, arg5=len */
#define KPM_CMD_HOOK_INFO    0x1005   /* Query module state */
#define KPM_CMD_TOUCH_DEV    0x1006   /* Query touch device: arg2=0 auto-find */
#define KPM_CMD_GET_LOG      0x1007   /* Get internal log: arg2=user_buf, arg3=buf_size */
#define KPM_CMD_SCREEN_INFO  0x1008   /* Get screen resolution: arg2=&width, arg3=&height */

/* Intercept commands */
#define KPM_CMD_INTERCEPT_ON    0x1014  /* Start intercept: arg2=mode|scale<<8|max_offset<<16, arg4=target_slot<<16 */
#define KPM_CMD_INTERCEPT_OFF   0x1015  /* Stop intercept */
#define KPM_CMD_INTERCEPT_STATE 0x1016  /* Query intercept state */
#define KPM_CMD_INTERCEPT_SCALE 0x1017  /* Set offset scale: arg2=scale [1-100] */
#define KPM_CMD_INTERCEPT_SLOT_OFF 0x1018  /* Disable intercept for one slot: arg2=slot_id */
#define KPM_CMD_INTERCEPT_SLOT_STATE 0x1019  /* Get per-slot intercept state: arg2=user_buf */

/* ===== TVF V2 TouchHandle API commands ===== */

#define KPM_CMD_TOUCH_CREATE    0x1020  /* Create virtual touch: arg2=priority, returns handle */
#define KPM_CMD_TOUCH_MOVE      0x1021  /* Update coordinates: arg2=handle, arg3=x|y<<32 */
#define KPM_CMD_TOUCH_UP        0x1022  /* Lift touch (UP): arg2=handle */
#define KPM_CMD_TOUCH_DESTROY   0x1023  /* Destroy touch (force release): arg2=handle */
#define KPM_CMD_TOUCH_MOVE_TO   0x1024  /* Animated move to: arg2=handle, arg3=tx|ty<<32, arg4=major|pressure<<16, arg5=duration|interrupt<<32 */
#define KPM_CMD_TOUCH_MOVE_DIR  0x1025  /* Delta move: arg2=handle, arg3=dx|dy<<32, arg4=major|pressure<<16, arg5=duration|interrupt<<32 */
#define KPM_CMD_TOUCH_GET       0x1026  /* Get touch info: arg2=handle, arg3=user_buf */
#define KPM_CMD_TOUCH_GET_ALL   0x1027  /* Get all active touches: arg2=user_buf, arg3=max_count */
#define KPM_CMD_TOUCH_COUNT     0x1028  /* Get active touch count */
#define KPM_CMD_TOUCH_SUSPEND   0x1029  /* Suspend touch: arg2=handle */
#define KPM_CMD_TOUCH_RESUME    0x102a  /* Resume touch: arg2=handle */
#define KPM_CMD_TOUCH_TAKEOVER  0x102b  /* Takeover real touch: arg2=handle, arg3=real_tracking_id */
#define KPM_CMD_TOUCH_POLICY    0x102c  /* Set scheduler policy: arg2=policy */
#define KPM_CMD_TOUCH_SET_PARAMS 0x102d /* Set touch params: arg2=handle, arg3=major|(pressure<<16)|(mask<<32), mask: 0x1=major, 0x2=pressure */
#define KPM_CMD_TOUCH_KEEPALIVE 0x102f /* 触摸心跳：客户端周期调用（≤5s 一次），
                                          * 超时视为客户端离线 → 内核自动销毁全部虚拟触摸
                                          * （防测试中断残留导致 CAPTURE 代理用户触摸） */

/* ===== 触摸坐标单位 =====
 * 协议 arg4 高 32 位低字节携带 unit 标志（旧客户端 arg4=0 → PIXEL，向后兼容）：
 *   - TOUCH_MOVE    : arg4 = unit<<32
 *   - TOUCH_MOVE_TO : arg4 = major | (pressure<<16) | (unit<<32)
 *   - TOUCH_MOVE_DIR: 同 MOVE_TO
 * 两种单位：
 *   - PIXEL: 屏幕逻辑像素坐标（默认），执行层 ×scale 转硬件 raw
 *   - RAW  : 硬件最小单位（1 raw = 1/scale 像素），直接透传不缩放，
 *            可表达亚像素（scale=16 时可达 1/16 像素精度） */
#define KPM_TOUCH_UNIT_PIXEL    0
#define KPM_TOUCH_UNIT_RAW      1
#define KPM_TOUCH_UNIT_MASK     0xFF
#define KPM_CMD_TOUCH_RECORD_START 0x1030 /* 触摸事件记录开始: arg2=src_mask(1=hw,2=out,3=both) */
#define KPM_CMD_TOUCH_RECORD_STOP  0x1031 /* 记录停止: 返回缓冲条数 */
#define KPM_CMD_TOUCH_RECORD_GET   0x1032 /* 拉取记录: arg3=start_idx, arg4=count(≤400) → [u32 total][28B×n] */

/* ===== 陀螺仪/加速度传感器控制命令 =====
 * 轴映射：ABS_X/Y/Z=平移，ABS_RX/RY/RZ=旋转。
 * type: 0=平移(tran), 1=旋转(rot)；axis: 0=X, 1=Y, 2=Z, 0xFF=全轴。
 * 参数统一经 arg2 打包 type|(axis<<8)。
 * 锁定：输出强制为固定值；控制：叠加虚拟力（不覆盖用户输入，非死锁）。
 * 控制 mode（arg5）：0=RAMP 力/爬升（易被校准回正，不推荐）、
 *                   1=DIRECT 直接偏移（一步置位，校准不回正，推荐）。 */
#define KPM_CMD_GYRO_LOCK         0x1040  /* 锁定: arg2=type|axis<<8, arg3=value */
#define KPM_CMD_GYRO_UNLOCK       0x1041  /* 解锁: arg2=type|axis<<8 (axis=0xFF 全轴) */
#define KPM_CMD_GYRO_LOCK_LIST    0x1042  /* 获取锁定/控制列表: arg2=max_count → kpm_gyro_entry_t[] */
#define KPM_CMD_GYRO_CONTROL      0x1043  /* 虚拟力: arg2=type|axis<<8, arg3=speed, arg4=offset, arg5=mode */
#define KPM_CMD_GYRO_CONTROL_STOP 0x1044  /* 停止虚拟力: arg2=type|axis<<8 (axis=0xFF 全轴) */
#define KPM_CMD_GYRO_STATE        0x1045  /* 查询陀螺仪模块状态: 返回 [ready][dev_count] */
#define KPM_CMD_GYRO_KEEPALIVE    0x1046  /* 客户端心跳（≤5s 一次；操作命令自动刷新，无需专门发） */

/* Touch info struct (shared with userspace, 8 bytes) */
typedef struct {
    int16_t  x;            /* current X coordinate */
    int16_t  y;            /* current Y coordinate */
    uint8_t  touch_major;  /* touch size */
    uint8_t  pressure;     /* pressure value */
    uint8_t  is_user;      /* 1=real user touch, 0=virtual */
    uint8_t  handle;       /* TouchHandle (pool index) */
} kpm_touch_info_t;

/* Per-slot intercept state (shared with userspace) */
#define KPM_MAX_SLOTS 10
typedef struct {
    uint16_t slot_mask;                              /* which slots are intercepted (bit i = slot i) */
    uint8_t  enabled;                                /* 0=off, 1=on */
    uint8_t  mode;                                   /* 0=off, 1=redirect, 2=offset, 3=mirror, 4=pin */
    int16_t  offset_x[KPM_MAX_SLOTS];                /* current applied offset X per slot */
    int16_t  offset_y[KPM_MAX_SLOTS];                /* current applied offset Y per slot */
    int16_t  pin_x[KPM_MAX_SLOTS];                   /* PIN target X per slot */
    int16_t  pin_y[KPM_MAX_SLOTS];                   /* PIN target Y per slot */
    uint8_t  finger_down[KPM_MAX_SLOTS];             /* 1=finger down on slot */
    uint8_t  reserved[6];                            /* padding to 8-byte boundary */
} kpm_intercept_slot_state_t;

/* Module state flags */
#define KPM_STATE_INIT_OK      0x01
#define KPM_STATE_PRCTL_HOOK   0x02
#define KPM_STATE_TOUCH_FOUND  0x04
#define KPM_STATE_MEM_RW_OK    0x08
/* 扩展状态位（bit 4-11）：子模块启用状态 */
#define KPM_STATE_INTERCEPT_OK 0x010
#define KPM_STATE_UDP_OK       0x020
#define KPM_STATE_MEM_SCAN_OK  0x040
#define KPM_STATE_MEM_FREEZE_OK 0x080
#define KPM_STATE_PTR_SCAN_OK  0x100
#define KPM_STATE_DEBUG_OK     0x200
#define KPM_STATE_PROC_OK      0x400
#define KPM_STATE_STEALTH_OK   0x800
#define KPM_STATE_GYRO_OK      0x1000
/* 子模块状态位（bit 13+，与 FEAT 单元一一对应） */
#define KPM_STATE_HOOK_OK      0x2000
#define KPM_STATE_STEALTHOOK_OK 0x4000
#define KPM_STATE_SUSPEND_OK   0x8000
#define KPM_STATE_NETCTL_OK    0x10000
#define KPM_STATE_SYSMON_OK    0x20000
#define KPM_STATE_RESCTL_OK    0x40000
#define KPM_STATE_TRACE_OK     0x80000
#define KPM_STATE_MEMWATCH_OK  0x100000
#define KPM_STATE_FORCE        0x200000
/* W^X shadow 无痕 hook */
#define KPM_STATE_WXSHADOW_OK  0x400000

/* ===== 扩展状态信息结构体（256 字节定长） =====
 * 通过 KPM_CMD_HOOK_INFO 命令返回，UDP 通道放在 resp_data 中。
 * prctl 通道保持兼容：ret 仍为 state 位图，arg2 可选传用户缓冲区接收完整结构。
 *
 * 设计原则：
 *   - 向后兼容：state 在偏移 0，旧客户端仍可读 ret
 *   - 定长结构：便于内核/用户态二进制对齐
 *   - 版本化：magic + version 便于未来扩展 */
#define KPM_STATE_MAGIC      0x4B504D53  /* "KMPS" */
#define KPM_STATE_VERSION    1

/* 符号 bitmap 索引（sym_bitmap[4] 共 128 bit，每 bit 对应一个 kf_xxx 是否非 NULL） */
#define KPM_SYM_CFU            0   /* kf_copy_from_user */
#define KPM_SYM_CTU            1   /* kf_copy_to_user */
#define KPM_SYM_CFKN           2   /* kf_copy_from_kernel_nofault */
#define KPM_SYM_CTKN           3   /* kf_copy_to_kernel_nofault */
#define KPM_SYM_MEMREMAP       4   /* kf_memremap */
#define KPM_SYM_MEMUNMAP       5   /* kf_memunmap */
#define KPM_SYM_VMAP           6   /* kf_vmap */
#define KPM_SYM_VUNMAP         7   /* kf_vunmap */
#define KPM_SYM_FILP_OPEN      8   /* kf_filp_open */
#define KPM_SYM_KERNEL_READ    9   /* kf_kernel_read */
#define KPM_SYM_KERNEL_WRITE   10  /* kf_kernel_write */
#define KPM_SYM_READ_ITER      11  /* kf_kernel_read_iter */
#define KPM_SYM_INPUT_HANDLE   12  /* kf_input_handle_event */
#define KPM_SYM_INPUT_EVENT    13  /* kf_input_event */
#define KPM_SYM_FIND_GET_PID   14
#define KPM_SYM_GET_PID_TASK   15
#define KPM_SYM_GET_TASK_MM    16
#define KPM_SYM_MMPUT          17
#define KPM_SYM_FIND_VMA       18
#define KPM_SYM_RCU_LOCK       19
#define KPM_SYM_RCU_UNLOCK     20
#define KPM_SYM_INIT_TASK      21
#define KPM_SYM_PUT_TASK       22
#define KPM_SYM_GET_CMDLINE    23
#define KPM_SYM_GET_TASK_COMM  24
#define KPM_SYM_SOCK_CREATE    25
#define KPM_SYM_ALLOC_WQ       26
#define KPM_SYM_INIT_NET       27
#define KPM_SYM_QUEUE_WORK     28
#define KPM_SYM_VSNPRINTF      29
#define KPM_SYM_PRINTK         30
#define KPM_SYM_FIND_TASK_VPID 31
#define KPM_SYM_TASK_PID_NR    32
#define KPM_SYM_MM_READ_LOCK   33
#define KPM_SYM_MM_READ_UNLOCK 34
#define KPM_SYM_HW_BP_REG      35
#define KPM_SYM_HW_BP_UNREG    36
#define KPM_SYM_KMALLOC        37
#define KPM_SYM_KFREE          38
#define KPM_SYM_VMALLOC        39
#define KPM_SYM_VFREE          40
#define KPM_SYM_VSNPRINTF2     41
#define KPM_SYM_SNPRINTF       42
#define KPM_SYM_STRTOULL       43
#define KPM_SYM_SYNC_RCU      44   /* kf_synchronize_rcu (卸载排空备用) */
/* 剩余 bit 45-127 保留 */

/* 回退状态（fallback_bitmap，16 个 2-bit 字段，0=主符号,1=第一回退,2=第二回退,3=全缺失） */
#define KPM_FB_CFU            0
#define KPM_FB_CTU            1
#define KPM_FB_CFKN           2
#define KPM_FB_MEMREMAP       3
#define KPM_FB_MEMUNMAP       4
#define KPM_FB_FIND_GET_PID   5
#define KPM_FB_GET_PID_TASK   6
#define KPM_FB_MMPUT          7
#define KPM_FB_PRINTK         8
#define KPM_FB_PUT_TASK       9   /* 0=原生,1=手动+__put,2=free_task,3=泄漏 */
#define KPM_FB_QUEUE_WORK     10
#define KPM_FB_FLUSH_WQ       11
#define KPM_FB_VMALLOC        12
#define KPM_FB_KMALLOC        13
#define KPM_FB_KERNEL_READ    14
#define KPM_FB_KERNEL_WRITE   15

/* 功能路径枚举 */
#define KPM_PATH_MEM_RW_WB_ONLY    0
#define KPM_PATH_MEM_RW_DMA        1
#define KPM_PATH_TOUCH_NONE        0
#define KPM_PATH_TOUCH_INPLACE     1
#define KPM_PATH_TOUCH_CAPTURE     2
#define KPM_PATH_CMDLINE_NATIVE    0  /* get_cmdline */
#define KPM_PATH_CMDLINE_MEM       1  /* arg_start/arg_end 纯内存 */
#define KPM_PATH_CMDLINE_FILP      2  /* filp_open */
#define KPM_PATH_CMDLINE_COMM      3  /* 16 字节 comm 回退 */

/* task 取用路径（LH_comm.h 状态结构体 [65] task_fetch_path） */
#define KPM_TASK_FETCH_REF     0  /* 取引用：find_get_pid + get_pid_task（需可归还） */
#define KPM_TASK_FETCH_NOREF   1  /* 免引用：__rcu_read_lock + find_vpid + pid_task */


#pragma pack(push, 1)
typedef struct {
    /* [0] 头部 (8 字节) */
    uint32_t magic;       /* KPM_STATE_MAGIC */
    uint32_t version;     /* KPM_STATE_VERSION */

    /* [8] 基础状态 (16 字节) */
    uint32_t state;       /* 位图：bit0-3 旧状态，bit4-11 子模块启用 */
    uint32_t kver;        /* major<<16|minor<<8|patch */
    int32_t  syms_init_ret;  /* kpm_syms_init 返回值 */
    int32_t  reserved1;

    /* [24] 触摸/屏幕 (28 字节) */
    int32_t touch_ready;
    int32_t node_offset;   /* -1 = 未探测 */
    int32_t screen_w;
    int32_t screen_h;
    int32_t raw_w;
    int32_t raw_h;
    int32_t screen_scale;

    /* [52] 拦截/触摸活跃 (8 字节) */
    int32_t intercept_on;
    int32_t active_count;

    /* [60] 功能路径 (8 字节) */
    uint8_t  mem_rw_path;    /* KPM_PATH_MEM_RW_* */
    uint8_t  touch_path;     /* KPM_PATH_TOUCH_* */
    uint8_t  cmdline_path;   /* KPM_PATH_CMDLINE_* */
    uint8_t  put_task_path;  /* 0=原生,1=手动,2=free_task,3=泄漏 */
    uint8_t  vmemmap_source; /* 0=符号,1=vmemmap_base,2=推算 */
    /* [65] task 取用路径：
     *   0 = 取引用路径（find_get_pid + get_pid_task + 归还）
     *   1 = 免引用路径（__rcu_read_lock + find_vpid + pid_task）
     * 意义：进程列表/maps/隐藏 这些"要拿 task"的功能，**是否可用不再由
     * put_task_path 单独决定**——免引用路径与 put_task_struct/usage 标定
     * 彻底解耦。诊断里据此给出"进程/maps 到底能不能用"的准确结论。
     * 老客户端读到 0 会保守地认为走取引用路径，语义安全。 */
    uint8_t  task_fetch_path; /* KPM_TASK_FETCH_* */
    uint8_t  reserved2[2];

    /* [68] 符号可用性 bitmap (16 字节) */
    uint32_t sym_bitmap[4];   /* 128 bit，每 bit 对应一个 kf_xxx */

    /* [84] 回退状态 (4 字节，16 个 2-bit 字段) */
    uint32_t fallback_bitmap; /* 16 字段 × 2 bit */

    /* [88] task_struct 偏移 (24 字节) */
    int16_t tasks_offset;
    int16_t tgid_offset;
    int16_t mm_offset;
    int16_t pid_offset;
    int16_t real_parent_offset;
    int16_t usage_offset;
    int16_t arg_start_offset;
    int16_t arg_end_offset;
    int16_t vm_start_offset;
    int16_t vm_end_offset;
    int16_t vm_next_offset;
    int16_t mm_mmap_offset;  /* mm_struct.mmap 偏移（回退路径使用，-1=未探测,-2=6.1+无此字段） */

    /* [112] 框架变量 (44 字节) */
    uint64_t vmemmap_base;
    uint64_t memstart_addr;
    uint64_t pgd_va;
    uint32_t mm_pgd_offset;
    int32_t  va_bits;
    int32_t  page_shift;
    int32_t  page_level;
    int32_t  reserved4;

    /* [156] 模块版本 (12 字节) */
    uint32_t module_version;   /* 编译时填充 */
    uint32_t build_time;       /* 编译时间戳 */
    uint32_t module_size;      /* kpm 文件大小 */

    /* [168] 陀螺仪/传感器 (28 字节) */
    int32_t gyro_ready;          /* 1 = 已发现传感器设备并安装 hook */
    int32_t gyro_dev_count;      /* 发现的传感器设备数 */
    int32_t gyro_locked_axes;    /* 锁定的轴数（0-6） */
    int32_t gyro_controlled_axes;/* 有虚拟力控制的轴数（0-6） */
    int32_t gyro_client_alive;   /* 1 = 客户端在线（最近 5s 有保活/操作） */
    int32_t gyro_reserved1;
    int32_t gyro_reserved2;

    /* [196] reserved 至 256 字节 */
    uint8_t  reserved5[60];
} kpm_state_info_t;  /* sizeof = 256 */
#pragma pack(pop)

/* 编译时断言：确保结构体大小为 256 字节 */
typedef char kpm_state_info_size_check[sizeof(kpm_state_info_t) == 256 ? 1 : -1];

/* Touch action types (used by intercept) */
#define KPM_TOUCH_DOWN      0
#define KPM_TOUCH_MOVE      1
#define KPM_TOUCH_UP        2

/* Max touch points (= max output slots) */
#define KPM_MAX_TOUCH_POINTS 10

/* ===== Memory scanner commands ===== */
#define KPM_CMD_MEM_SCAN_START   0x1100  /* Start scan: arg2=pid, arg3=type|mode<<8, arg4=value, arg5=range */
#define KPM_CMD_MEM_SCAN_NEXT    0x1101  /* Next round: arg2=type|mode<<8, arg3=value */
#define KPM_CMD_MEM_SCAN_RESULT  0x1102  /* Get results: arg2=user_buf, arg3=max_count, arg4=offset */
#define KPM_CMD_MEM_SCAN_CLEAR   0x1103  /* Clear scan session */
#define KPM_CMD_MEM_SCAN_STATUS  0x1104  /* 扫描会话状态（结果数/截断标志/进度） */
#define KPM_CMD_MEM_SCAN_AOB_START 0x1105 /* 长 AOB 特征扫描（>8B，特征放 payload，arg2=pid, arg3=mode<<8, arg5=len, ≤KPM_SCAN_AOB_MAX） */
#define KPM_CMD_MEM_SCAN_KERNEL_START 0x1106 /* 内核线性映射范围扫描
    arg2=0(pid 保留), arg3=type|mode<<8, arg4=value, arg5=range(字节数, ≤KPM_SCAN_KERNEL_MAX)
    扫描范围 = [PAGE_OFFSET + 0, PAGE_OFFSET + range)，线性映射直读（页级容错）。 */

/* ===== 扫描模式 =====
 * 模式与数值类型组合使用（字节类型仍仅 EXACT）：
 *   UNKNOWN:     未知初始值（首轮恒真建集，之后用 CHANGED/±X 过滤收敛）
 *   NOT_EQUAL:   当前值 != value
 *   INCREASED_BY/DECREASED_BY: 与上轮差值 == value（无符号模 2^64 差，防溢出）
 *   INCREASED_GE/DECREASED_GE: 差值 >= value
 */
#define KPM_SCAN_MODE_UNKNOWN     6
#define KPM_SCAN_MODE_NOT_EQUAL   7
#define KPM_SCAN_MODE_INCREASED_BY 8
#define KPM_SCAN_MODE_DECREASED_BY 9
#define KPM_SCAN_MODE_INCREASED_GE 10
#define KPM_SCAN_MODE_DECREASED_GE 11

/* 内核空间扫描范围上限：64GB（16GB RAM 设备的线性映射 + 余量）。
 * 防御误传超大 range 导致长时间扫描。 */
#define KPM_SCAN_KERNEL_MAX  (64ULL * 1024 * 1024 * 1024)

/* ===== Memory freeze commands ===== */
#define KPM_CMD_FREEZE_ADD       0x1110  /* Add freeze: arg2=pid, arg3=addr, arg4=value, arg5=size */
#define KPM_CMD_FREEZE_REMOVE    0x1111  /* Remove freeze: arg2=index */
#define KPM_CMD_FREEZE_LIST      0x1112  /* List freezes: arg2=user_buf, arg3=max_count */
#define KPM_CMD_FREEZE_TOGGLE    0x1113  /* Toggle freeze: arg2=index, arg3=enable */
#define KPM_CMD_FREEZE_CLEAR     0x1114  /* Clear all freezes */

/* ===== Pointer scanner commands ===== */
#define KPM_CMD_PTR_SCAN         0x1120  /* Pointer scan: arg2=pid, arg3=target_addr, arg4=range */
#define KPM_CMD_PTR_SCAN_CHAIN   0x1121  /* Chain scan: arg2=pid, arg3=target_addr, arg4=depth */
#define KPM_CMD_PTR_RESULT       0x1122  /* Get ptr results: arg2=user_buf, arg3=max_count, arg4=offset */

/* ===== Debug/breakpoint commands ===== */
#define KPM_CMD_DEBUG_BP_SET      0x1130  /* Set breakpoint: arg2=pid, arg3=type, arg4=addr, arg5=size */
#define KPM_CMD_DEBUG_BP_CLEAR    0x1131  /* Clear breakpoint: arg2=index */
#define KPM_CMD_DEBUG_BP_LIST     0x1132  /* List breakpoints: arg2=user_buf, arg3=max_count */
#define KPM_CMD_DEBUG_BP_HIT      0x1133  /* Get hit info: arg2=user_buf */
#define KPM_CMD_DEBUG_SINGLE_STEP 0x1134  /* Single step: arg2=pid, arg3=tid */
#define KPM_CMD_DEBUG_CONTINUE    0x1135  /* Continue: arg2=pid, arg3=tid */
#define KPM_CMD_DEBUG_BP_NOTIFY   0x1136  /* 断点命中通知: arg2=1/0 启用/停用。
                                           * UDP 通道用 recvfrom 源地址作为通知目标；
                                           * prctl 通道用上次记录的地址（无源地址）。 */
/* ===== 断点寄存器篡改命令 =====
 * 全部标量参数（prctl arg2-5），转换模块经 raw_syscall5 直接调用，无需用户空间中转。
 * 采用「regmod 窗口」模式：先 REGMOD 预置篡改规则，再 SET_EX/MODIFY 消费。
 *   DEBUG_BP_REGMOD:     arg2=reg_mask, arg3=fp_mask, arg4=regs_to_set_ptr(用户指针,可空)
 *   DEBUG_BP_SET_EX:     arg2=pid, arg3=type(KPM_BP_TYPE_*), arg4=addr, arg5=size
 *                        → 用窗口规则安装断点 → ret=index（安装后清窗口）
 *   DEBUG_BP_MODIFY:     arg2=index → 用窗口规则更新篡改 → ret=0（更新后清窗口）
 *   DEBUG_BP_HIT_COUNT:  arg2=handle → ret=累计命中数（标量；待读条目由客户端按差值算）
 * reg_mask: bit i(0-30)=X0-X30；bit31=SP；bit32=PC；bit33=PSTATE
 * fp_mask:  bit i(0-31)=V0-V31（受 LH fpsimd 偏移门控）
 * regs_to_set_ptr: 用户态寄存器快照指针（布局 regs[31]@0/sp@248/pc@256/pstate@264/
 *   vregs@288，可空）；LH 在执行上下文 copy_from_user。
 * 仅 prctl 通道（含用户指针语义；UDP 返回 UNHANDLED）。 */
#define KPM_CMD_DEBUG_BP_SET_EX   0x1137
#define KPM_CMD_DEBUG_BP_MODIFY   0x1138
#define KPM_CMD_DEBUG_BP_HIT_COUNT 0x1139
#define KPM_CMD_DEBUG_BP_REGMOD   0x113A
/* 内核/宽硬件断点（force；arg2=addr, arg3=type, arg4=size, arg5=flags） */
#define KPM_CMD_DEBUG_BP_SET_KERNEL 0x113B
/* 带 flags 的用户断点：arg2=pid, arg3=type, arg4=addr,
 * arg5=size | (flags<<32)。
 * flags: bit0 EXEC_INST（执行断点保留指令语义）、bit1 AUTO_CLEAR（命中即拆）、
 *        bit2 KERNEL_ACCESS（允许内核 copy_to_user 命中，force）、
 *        bit3 NO_NOTIFY（不推送 KBPN，仅计数/事件环）、
 *        bits8-15 MAX_HITS（达到后自动拆，0=不限）。 */
#define KPM_CMD_DEBUG_BP_SET_FLAGS 0x113C
/* 断点能力/容量：兩通道返回 kpm_bp_caps_t（32B） */
#define KPM_CMD_DEBUG_BP_INFO      0x113D
/* 用户单步 / 指令级 step trace（依赖 register_user_step_hook，
 * <5.10 内核不可用）。
 * STEP_TRACE: arg2=pid, arg3=tid, arg4=count(1..256), arg5=flags（保留）
 *             → 在目标返回用户态时置 PSTATE.SS，逐条记录 34 寄存器快照
 * STEP_FETCH: arg2=buf(prctl)/max(UDP), arg3=max(prctl)
 *             → kpm_trap_regs_t[]（272B/条）
 * DEBUG_CONTINUE(0x1135) 可提前取消该线程的步进。 */
#define KPM_CMD_STEP_TRACE         0x113E
#define KPM_CMD_STEP_FETCH         0x113F
#define KPM_STEP_RING_MAX          256

#define KPM_BP_FLAG_EXEC_INST      0x1u
#define KPM_BP_FLAG_AUTO_CLEAR     0x2u
#define KPM_BP_FLAG_KERNEL_ACCESS  0x4u
#define KPM_BP_FLAG_NO_NOTIFY      0x8u
#define KPM_BP_FLAG_MAX_HITS(f)    (((f) >> 8) & 0xFFu)
#define KPM_BP_FLAG_PACK(f, n)     (((uint64_t)(f) & 0xFFu) | \
                                    ((uint64_t)((n) & 0xFFu) << 8))
/* BP_INFO 返回值（32B，定长） */
typedef struct {
    uint32_t max_slots;     /* KPM_DEBUG_MAX_BREAKPOINTS */
    uint32_t used_slots;    /* 当前启用断点数 */
    int32_t  brp;           /* 硬件执行断点寄存器数（探测值） */
    int32_t  wrp;           /* 硬件观察点寄存器数（探测值） */
    uint32_t user_bps;      /* 用户断点数 */
    uint32_t kernel_bps;    /* 宽/内核断点数 */
    uint32_t step_ok;       /* 1=软件单步（user_step_hook）可用 */
    uint32_t sync_ok;       /* 1=同步停靠可用 */
} kpm_bp_caps_t;            /* sizeof = 32 */
typedef char kpm_bp_caps_size_check[sizeof(kpm_bp_caps_t) == 32 ? 1 : -1];

/* ===== Process enumeration commands ===== */
#define KPM_CMD_PROC_LIST         0x1145  /* List processes: arg2=user_buf, arg3=max_count, arg4=offset */
#define KPM_CMD_PROC_MAPS         0x1146  /* Get process memory maps: arg2=pid, arg3=user_buf, arg4=max_count */
#define KPM_CMD_PROC_QUERY_REGION 0x1147  /* Query single region by addr: arg2=pid, arg3=addr, arg4=user_buf(kpm_map_entry_t*) */
#define KPM_CMD_READ_FILE         0x1148  /* 文件回退读取: data=完整路径, arg5=offset, 返回文件内容(<=16KB) */
#define KPM_CMD_PROC_FULLPATH     0x1149  /* VMA 完整路径: arg2=pid, arg3=addr, 返回完整路径字符串 */

/* ===== 按名查询命令 =====
 * prctl 布局（转换模块经 raw_syscall5 调用）：
 *   PROC_PID_BY_NAME: arg2=进程名用户指针 → ret=pid（或负错误码）
 *   PROC_MODULE_BASE: arg2=pid, arg3=模块名用户指针 → ret=基址
 *   PROC_MODULE_BSS:  arg2=pid, arg3=模块名用户指针 → ret=BSS 地址
 * 仅 prctl 通道（名字经用户指针传；UDP 无 req_data 承载，返回 UNHANDLED）。 */
#define KPM_CMD_PROC_PID_BY_NAME  0x114A
#define KPM_CMD_PROC_MODULE_BASE  0x114B
#define KPM_CMD_PROC_MODULE_BSS   0x114C

/* ===== Memory dump commands (ELF rebuild, for IDA/unpacking analysis) =====
 * 队列语义：同一时间仅允许一个 dump 操作（busy 互斥）。
 * 协议化传输（3 阶段：BEGIN/FETCH/END）。
 * 纯内存读取（页表遍历，无 VFS 痕迹），数据分块经 UDP 回传，
 * 块级 CRC32 + 整体 SHA256 双重完整性校验。
 *   DUMP_BEGIN:  arg2=pid, data=模块名 → 返回 kpm_dump_hdr_t (128B)
 *   DUMP_FETCH:  arg2=offset → 返回 kpm_dump_chunk_t + data (≤15872B)
 *   DUMP_END:    结束会话 → 返回 kpm_dump_done_t (56B, 含整体 SHA256)
 *   DUMP_STREAM: arg2=file_off, arg3=len → 流式拉取（零往返）
 */
#define KPM_CMD_DUMP_BEGIN    0x1153
#define KPM_CMD_DUMP_FETCH    0x1154
#define KPM_CMD_DUMP_END      0x1155

/* ===== 通用批量读 =====
 * 一次请求读取多个任意地址（对象头/结构体分析用，避免逐条 UDP 往返）。
 * 请求 payload: [u32 count][u32 per_len] + count × u64 地址
 *    count   1..2048 条地址
 *    per_len 每条目字节数（1..256）
 * 约束: count × per_len ≤ KPM_UDP_MAX_PAYLOAD(16384)
 * 响应 payload: count × per_len 字节（成功=真实数据；失败=全 0xFF）
 * 返回 ret = 成功读取的条目数。
 */
#define KPM_CMD_MEM_READ_BATCH   0x1160
#define KPM_READ_BATCH_MAX       2048    /* 单次最大地址数 */
#define KPM_READ_BATCH_LEN_MIN   1
#define KPM_READ_BATCH_LEN_MAX   256     /* 每条目最大字节数 */

/* ===== 变长批量读 =====
 * 每条目独立长度，支持结构体链式读取（如 对象头40B + 指针8B 混合）。
 * 请求 payload: [u32 count] + count × {u32 len, u64 addr}
 *    count  1..512 条
 *    len    每条目 1..256 字节
 * 约束: Σ len ≤ KPM_UDP_MAX_PAYLOAD(16384)
 * 响应 payload: 按请求顺序拼接每条目 len 字节（成功=真实数据；失败=全 0xFF）
 * 返回 ret = 成功读取的条目数。
 */
#define KPM_CMD_MEM_READ_BATCH2  0x1164
#define KPM_READ_BATCH2_MAX      512     /* 单次最大条目数 */
#define KPM_READ_BATCH2_LEN_MAX  256     /* 每条目最大字节数 */

/* 读取虚拟地址的原始 PTE（zram swap 换出页解析）。
 * arg2=pid, arg3=addr; 响应 payload = {u64 entry, u32 level, u32 rsvd}
 * level: 1=PMD块映射, 2=PTE表项; entry 为原始页表项（不判断有效位，
 * 换出页 entry bit0=0 且含 swp_entry 编码，客户端解析后读 /dev/zram0）。
 * ret=0 成功, <0 失败 */
#define KPM_CMD_MEM_GET_PTE      0x1163
#define KPM_GET_PTE_RESP_LEN     16

#define KPM_DUMP_MAGIC_HDR    0x31504D44  /* 'DMP1' */
#define KPM_DUMP_MAGIC_CHUNK  0x43504D44  /* 'DMPC' */
#define KPM_DUMP_MAGIC_DONE   0x45504D44  /* 'DMPE' */
#define KPM_DUMP_PROTO_VERSION 1
#define KPM_DUMP_CHUNK_MAX    15872       /* 单块最大数据字节（UDP 载荷 16384 - 头余量） */
#define KPM_DUMP_MODULE_MAX   64          /* 模块名最大长度 */

/* Dump 协议头（128 字节，DUMP_BEGIN 响应） */
typedef struct {
    uint32_t magic;        /* KPM_DUMP_MAGIC_HDR */
    uint32_t version;      /* KPM_DUMP_PROTO_VERSION */
    uint64_t base;         /* 模块加载基址 */
    uint64_t size;         /* dump 总大小（含 bss 补零） */
    char     module[KPM_DUMP_MODULE_MAX]; /* 模块名 */
    uint32_t chunk;        /* 单块最大字节 KPM_DUMP_CHUNK_MAX */
    uint32_t chunks;       /* 总块数 */
    uint32_t segs;         /* PT_LOAD 段数 */
    uint32_t algo;         /* 校验算法: 1=CRC32(块) + SHA256(整体) */
    uint64_t missing;      /* 缺失页补零字节数 */
    uint32_t flags;        /* bit0=存在缺失页 */
    uint8_t  reserved[8];
} kpm_dump_hdr_t;          /* sizeof = 128 */

/* Dump 数据块头（16 字节，DUMP_FETCH 响应，后跟 data[length]） */
typedef struct {
    uint32_t magic;        /* KPM_DUMP_MAGIC_CHUNK */
    uint32_t offset;       /* 本块起始文件偏移（连续性校验） */
    uint32_t length;       /* 实际数据长度 */
    uint32_t crc32;        /* 本块数据 CRC32 */
} kpm_dump_chunk_t;        /* sizeof = 16 */

/* Dump 完成（56 字节，DUMP_END 响应） */
typedef struct {
    uint32_t magic;        /* KPM_DUMP_MAGIC_DONE */
    uint32_t status;       /* 0=成功 */
    uint64_t bytes;        /* 内核提供总字节 */
    uint8_t  sha256[32];   /* 内核侧整体 SHA256 */
    uint32_t missing;      /* 缺失页补零字节 */
    uint32_t flags;
} kpm_dump_done_t;         /* sizeof = 56 */

/* Dump 状态 */
#define KPM_DUMP_STATE_IDLE     0   /* 无任务 */
#define KPM_DUMP_STATE_RUNNING  1   /* 进行中 */
#define KPM_DUMP_STATE_DONE     2   /* 完成 */
#define KPM_DUMP_STATE_ERROR    3   /* 出错（err 为错误码） */
#define KPM_DUMP_STATE_CANCELED 4   /* 已取消 */

/* Dump 进度结构（168 字节，UDP resp_data 直接返回） */
typedef struct {
    uint32_t state;        /* KPM_DUMP_STATE_* */
    uint32_t err;          /* 错误码 (KPM_E_*) */
    uint64_t total_bytes;  /* 输出文件总字节数（含 bss 补零） */
    uint64_t done_bytes;   /* 已写字节数 */
    uint32_t region_count; /* 匹配模块名的内存区域数 */
    uint32_t seg_count;    /* 已完成的 PT_LOAD 段数 */
    uint32_t seg_total;    /* 总 PT_LOAD 段数 */
    uint32_t reserved;
    char     path[128];    /* 输出文件路径 */
} kpm_dump_progress_t;     /* sizeof = 168 */

/* ===== 流式传输协议 =====
 *
 * 背景：KPM_UDP_MAX_PAYLOAD=16384 限制所有命令单次响应 ≤ 16KB，
 * 大数据（模块 dump 60MB、进程列表 268KB）需上千次请求-响应往返，
 * 吞吐受 RTT 限制（WiFi 约 0.5~2 MB/s）。
 *
 * 方案："流式"层——一次请求，内核连续发送 N 个 ≤16KB 数据报，
 * 零往返等待（吞吐 = 链路带宽）。数据报保持 16KB 尺寸，不增加 IP
 * 分片风险；每块带 CRC32 + offset，客户端重组校验。
 * 兼容性：所有旧命令/旧客户端不受影响（独立路径）。
 *
 * 命令：
 *   STREAM_BEGIN (0x1180): 任意地址范围流式读（≤ KPM_STREAM_MAX）
 *     arg2=pid, arg3=addr, arg4=total_len(1..64MB), arg5=flags
 *     flags bit0=1: 内核地址直读（pid 忽略，copy_from_kernel_nofault）
 *     响应: 标准响应头 + kpm_stream_hdr_t(40B)，随后 chunks 个数据报
 *     （数据报格式见 kpm_stream_dgram_t，session = 请求 seq）
 *   STREAM_WRITE (0x1181): 分片写（切片自包含，可独立重试）
 *     arg2=pid, arg3=addr(基址), arg4=total_len(区域总长, 校验用),
 *     payload = [u32 slice_off][data...] → 写入 addr+slice_off
 *     响应: ret = 实际写入字节数
 *   DUMP_STREAM  (0x1182): 模块 dump 流式 fetch（复用 dump 会话语义）
 *     arg2=file_off, arg3=本批字节数(1..64MB)
 *     响应: 直接发送数据报（无头报；total 由 DUMP_BEGIN 提供）
 */
#define KPM_CMD_STREAM_BEGIN   0x1180
#define KPM_CMD_STREAM_WRITE   0x1181
#define KPM_CMD_DUMP_STREAM    0x1182

#define KPM_STREAM_MAGIC_HDR    0x314D5453  /* 'STM1' */
#define KPM_STREAM_MAGIC_CHUNK  0x434D5453  /* 'STMC' */
#define KPM_STREAM_VERSION      1
#define KPM_STREAM_MAX          (64 * 1024 * 1024)  /* 单请求最大 64MB */
#define KPM_STREAM_CHUNK        KPM_DUMP_CHUNK_MAX  /* 15872，每数据报数据字节 */
#define KPM_STREAM_FLAG_KERNEL  0x1                /* STREAM_BEGIN: 内核地址直读 */
#define KPM_STREAM_WRITE_SLICE_MAX (KPM_UDP_MAX_PAYLOAD - 4)  /* 切片数据上限 */

#pragma pack(push, 1)
/* 流式头（40 字节，STREAM_BEGIN 响应 payload） */
typedef struct {
    uint32_t magic;       /* KPM_STREAM_MAGIC_HDR */
    uint32_t version;     /* KPM_STREAM_VERSION */
    uint64_t total;       /* 本次流总字节数（= 请求 len；读失败页补零） */
    uint32_t chunk;       /* 每数据报数据字节 KPM_STREAM_CHUNK */
    uint32_t chunks;      /* 数据报数量 */
    uint32_t crc32;       /* 保留 0（完整性以块级 CRC32 为准） */
    uint32_t flags;       /* 保留 0（失败页补零，不可区分真实 0） */
    uint32_t session;     /* 会话号 = 请求 seq（客户端过滤乱序/旧流） */
    uint32_t reserved;
} kpm_stream_hdr_t;       /* sizeof = 40 */

/* 流式数据报头（20 字节，后接 data[len]） */
typedef struct {
    uint32_t magic;       /* KPM_STREAM_MAGIC_CHUNK */
    uint32_t session;     /* 请求 seq */
    uint32_t offset;      /* 本块数据在流中的起始偏移 */
    uint32_t len;         /* 本块数据长度 */
    uint32_t crc32;       /* 本块数据 CRC32 */
} kpm_stream_dgram_t;     /* sizeof = 20 */
#pragma pack(pop)

typedef char kpm_stream_hdr_size_check[sizeof(kpm_stream_hdr_t) == 40 ? 1 : -1];
typedef char kpm_stream_dgram_size_check[sizeof(kpm_stream_dgram_t) == 20 ? 1 : -1];

/* ===== Hook commands =====
 * 本命令族为禁用壳，保留接口签名但全部返回 -KPM_E_INVAL。
 * 驱动现役内核态 hook 仅：input_handle_event 输入捕获（touch）、传感器 uprobe
 * +sys_enter tracepoint（gyro）、prctl FP hook（通信通道）、硬件断点（debug）——
 * 需要"运行时整体下线驱动 hook"的接口见下方 KPM_CMD_UN_HOOK（0x1156）。
 */
#define KPM_CMD_HOOK_INSTALL      0x1140  /* Install hook: arg2=type, arg3=target_name(ptr), arg4=replace_addr */
#define KPM_CMD_HOOK_REMOVE       0x1141  /* Remove hook: arg2=index */
#define KPM_CMD_HOOK_LIST         0x1142  /* List hooks: arg2=user_buf, arg3=max_count */
#define KPM_CMD_HOOK_TOGGLE       0x1143  /* Toggle hook: arg2=index, arg3=enable */
#define KPM_CMD_HOOK_PLT_SET      0x1144  /* PLT hook: arg2=pid, arg3=module_name(ptr), arg4=func_name(ptr), arg5=replace_addr */

/* ===== 进程隐藏 / 反检测命令 =====
 *
 * HIDE_PROCESS 原理（回退链，P0 优先 / P1 按需 / P2 如实降级）：
 *   P0（首选，纯数据级，A 级隐蔽）：
 *     Linux 5.0+ 各 pid namespace 用 idr 树登记进程（kernel/pid.c），/proc 枚举
 *     （find_ge_pid）、按 pid 查找（find_pid_ns/find_vpid）与 kill(pid) 全部经
 *     struct pid_namespace.idr（GKI/主流内核该 idr 为 ns 结构首成员，偏移 0，
 *     运行时 pid1 双向自检门控）。本命令把目标进程在 init_pid_ns.idr 中的登记
 *     条目【摘除】（idr_remove），进程照常运行，但 /proc、ps、getdents 枚举、
 *     按 pid kill 全部"查无此进程"——同时实现 防枚举 与 防按 pid 杀。
 *     进程退出后由内核 free_pid 自然清理（条目已不在表中，idr_remove 幂等）。
 *     恢复 = 原 nr 槽位空闲时 idr_alloc 占位 + idr_replace 回填（同 alloc_pid）。
 *   L1 自检（每次新隐藏后自动）：RCU 读锁内经原始入口调用
 *     find_task_by_pid_ns(pid, init_pid_ns) 探测——返回 NULL = 该内核仅此一条
 *     通道（主流内核），P0 已彻底（枚举+直连+kill 全隐），零 hook 定版；
 *     返回 task = 存在 idr 外第二解析通道（个别魔改内核）→ 自动进入 P1。
 *   P1（回退，仅"第二通道"内核、且仅隐藏窗口内生效）：
 *     登记表不动，框架 hook(find_task_by_pid_ns, stub, &backup)：stub 对
 *     (ns==init_pid_ns && pid∈隐藏表) 返回 NULL → /proc/<pid> 直连 ENOENT，
 *     与 P0 视图一致；其余调用经 trampoline 保真。RECOVER 全部清空即 unhook，
 *     生命周期与隐藏窗口绑定，命令驱动，不常驻。
 *   P2（降级，不静默）：P1 符号缺失/安装失败 → 该记录 state=LIMITED
 *     （仅枚举级，直连仍可能可达），HIDE_LIST 明示，客户端知情决策。
 *   已知边界（记录在案，勿对关键进程使用）：
 *     - 被隐藏进程自身的 /proc/self 系列读取也会失败（同表查找 + stub 同源）；
 *       适合后台常驻的辅助进程，勿隐藏依赖 /proc/self 的应用。
 *     - 隐藏期间该 pid 号可被新进程复用；恢复时若原号已被占用则无法恢复
 *       （返回 -KPM_E_BUSY，记录 conflict 状态，HIDE_LIST 可见）。
 *     - 负 pgid 组信号/遍历 tasklist 的检测方式不受本机制影响。
 *     - 4.19 及更早 pid_hash 时代：P0 idr 自检失败即禁用返回 -KPM_E_NOTFOUND
 *       （该形态需 pid_hash 摘链路径）。
 *
 * 参数（UDP 与 prctl 布局一致）：
 *   HIDE_PROCESS:     arg2=pid → ret=隐藏槽位(1..KPM_HIDE_MAX) 或负错误码
 *   RECOVER_PROCESS:  arg2=pid → 恢复该进程（ret=恢复条数 0/1）；
 *                     arg2=0   → 恢复全部（ret=恢复条数）
 *   HIDE_LIST:        arg2=buf, arg3=max_count → kpm_hide_entry_t[]（ret=条数）
 *   UN_HOOK:          arg2=卸载掩码（0=全部）→ ret=实际下线的 hook 类数
 *                     bit0=输入捕获 hook(0x1) bit1=传感器 uprobe/tp(0x2)
 *                     bit2=prctl FP hook(0x4，仅 UDP 通道可请求)
 *                     bit3=硬件断点+通知(0x8)
 *                     下线后如需恢复请重新加载模块（单向"收尾"语义）。
 */
#define KPM_CMD_HIDE_PROCESS     0x114D
#define KPM_CMD_RECOVER_PROCESS  0x114E
#define KPM_CMD_HIDE_LIST        0x114F
#define KPM_CMD_UN_HOOK          0x1156
#define KPM_CMD_HIDE_P1          0x1157  /* P1 兜底开关: arg2=0关/1开(缺省0关) → ret=当前开关 */

/* ===== 同步断点 =====
 * 命中语义升级：目标线程在 task_work 边界（进程上下文，可睡眠）停靠，
 * 客户端收通知后 GET_CONTEXT → SET_CONTEXT → RESUME 读-改-写闭环，
 * 替代 regmod"盲写"。停靠期间目标【不执行任何用户指令】（命中指令
 * 不提交，eret 尚未发生），与 Frida onEnter/onLeave 语义对齐。
 * 风险注释（必然暴露面）：
 *   - 停靠窗口内目标线程冻结（/proc 显示 S，非 T；比 SIGSTOP 隐蔽）；
 *   - 命中→停靠有 µs 级时序差，可被高精度计时侧信道察觉；
 *   - 客户端失联时超时自动恢复（默认 2s，0xFFFFFFFF=无限等待=永久
 *     卡死风险，需显式指定）。
 * TRAP_GET:    arg2=trap_id, arg3=buf → kpm_trap_regs_t(272B，快照+SET覆盖)
 * TRAP_SET:    arg2=trap_id, arg3=reg_mask, arg4=buf(272B；UDP 走 payload)
 *              reg_mask 位义与 regmod 相同：0-30=X0-X30, 31=SP, 32=PC, 33=PSTATE
 * TRAP_RESUME: arg2=trap_id（0xFFFFFFFF=全部）
 * TRAP_LIST:   arg2=max_count → kpm_trap_info_t[](40B×N)
 * DEBUG_BP_SET_SYNC: arg2=pid, arg3=type(仅 HW 1/2/3), arg4=addr,
 *              arg5=size(低32) | timeout_ms<<32（0=默认2000，
 *              0xFFFFFFFF=无限等待）
 * 兼容性：task_work/schedule_timeout_interruptible 等符号缺失或槽满时
 * 自动回退 async 语义（PC+4 + 合并通知），功能不丢失。 */
#define KPM_CMD_TRAP_GET          0x1158
#define KPM_CMD_TRAP_SET          0x1159
#define KPM_CMD_TRAP_RESUME       0x115A
#define KPM_CMD_TRAP_LIST         0x115B
#define KPM_CMD_DEBUG_BP_SET_SYNC 0x115C

/* ===== 进程挂起/恢复 =====
 * SUSPEND_PROC: arg2=tgid, arg3=mode(0=trap-park默认 1=sigstop兜底
 *               2=freezer预留 0xFF=auto), arg4=timeout_ms(0=无限)
 *               → ret=记录id；机制不可用 → -KPM_E_DISABLED
 * RESUME_PROC:  arg2=tgid(0=全部) → ret=恢复线程数
 * SUSPEND_LIST: arg2=max_count → kpm_suspend_entry_t[](48B×N)
 * 风险注释（必然暴露面，详见 LH_suspend.h）：
 *   - trap-park：停靠线程 /proc 显示 S（最隐蔽）；阻塞在长系统调用的
 *     线程下次到达边界才停；挂起期间新建线程不受控；
 *   - sigstop：父进程（zygote）收到停止通知、目标可捕获 SIGCONT、
 *     /proc 显示 T——暴露面最大；
 *   - 两模式 /proc 自查均可感知"自己被停了"（功能固有语义）。 */
#define KPM_CMD_SUSPEND_PROC      0x1165
#define KPM_CMD_RESUME_PROC       0x1166
#define KPM_CMD_SUSPEND_LIST      0x1167

/* ===== 进程禁止联网 =====
 * 机制/拒绝码/风险注释见 LH_netctl.h。规则经 kpm_filter（uid 位图
 * [10000,19999] + tgid 小表）与 sysmon 共享。
 * NETCTL_RULE: arg2=op(0=add,1=del,2=clear), arg3=type(0=uid,1=pid,
 *              2=all_apps), arg4=value → ret=0
 *              uid 传 0 表示"全部 app uid"（all_apps 开关）
 * NETCTL_SET:  arg2=enable(0/1), arg3=errno_mode(0=ENETUNREACH默认,
 *              1=EACCES, 2=EPERM) → ret=0
 * NETCTL_LIST: arg2=buf → kpm_netctl_info_t（148B） */
#define KPM_CMD_NETCTL_RULE       0x116B
#define KPM_CMD_NETCTL_SET        0x116C
#define KPM_CMD_NETCTL_LIST       0x116D

/* 共享过滤器规则：
 * FILTER_RULE 独立于两功能，netctl/sysmon 任一启用即可管理共享过滤。
 * arg2=op(0=add,1=del,2=clear), arg3=type(0=uid,1=pid,2=all_apps),
 * arg4=value → ret=0 */
#define KPM_CMD_FILTER_RULE       0x116E

#define KPM_NETCTL_PID_MAX        32
typedef struct {
    uint32_t enabled;
    uint32_t errno_mode;      /* KPM_NETCTL_ERRNO_* */
    uint32_t all_apps;
    uint32_t uid_count;
    uint32_t pid_count;
    pid_t    pids[KPM_NETCTL_PID_MAX];
} kpm_netctl_info_t;          /* sizeof = 148 */
typedef char kpm_netctl_info_size_check[sizeof(kpm_netctl_info_t) == 148 ? 1 : -1];

/* ===== syscall/ioctl 监控与劫持 =====
 * SYSMON_SET:   arg2=enable(0/1), arg3=flags(bit0=监控事件入环) → ret=0
 * SYSMON_RULE:  arg2=op(0=add,1=del,2=clear)
 *               arg3=nr(低16)|action<<16|arg_idx<<24|errno_mode<<28
 *               arg4=cmd_match(0=任意；ioctl=cmd 精确值)
 *               arg5=arg_value(TAMPER 写入值 / del 时=槽位id) → ret=槽位id
 * SYSMON_FETCH: arg2=max_count, arg3=buf, arg4=dropped接收指针(可0)
 *               → ret=事件数（kpm_sysmon_event_t 56B×N）
 * SYSMON_RULES: arg2=max_count, arg3=buf → ret=规则数（40B×N）
 * 动作/延迟/风险注释见 LH_sysmon.h。 */
#define KPM_CMD_SYSMON_SET        0x116F
#define KPM_CMD_SYSMON_RULE       0x1170
#define KPM_CMD_SYSMON_FETCH      0x1171
#define KPM_CMD_SYSMON_RULES      0x1172

#define KPM_SYSMON_RULE_MAX       16
#define KPM_SYSMON_RING_MAX       128

typedef struct {
    uint32_t used;
    uint32_t nr;              /* 0 = 任意 syscall */
    uint32_t action;          /* KPM_SYSMON_ACTION_* */
    uint32_t arg_idx;         /* TAMPER：参数下标 0-5 */
    uint32_t errno_mode;      /* DENY：0=ENETUNREACH 1=EACCES 2=EPERM */
    uint32_t reserved;
    uint64_t cmd_match;       /* 0=任意 */
    uint64_t arg_value;       /* TAMPER：写入值 */
} kpm_sysmon_rule_t;          /* sizeof = 40 */
typedef char kpm_sysmon_rule_size_check[sizeof(kpm_sysmon_rule_t) == 40 ? 1 : -1];

typedef struct {
    uint64_t seq;
    uint64_t ts_jiffies;      /* 预留（当前 0） */
    int32_t  pid;             /* tgid */
    uint32_t uid;
    uint32_t nr;
    uint32_t arg_idx_dump;    /* 0xFF=MONITOR 事件 */
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
} kpm_sysmon_event_t;         /* sizeof = 56 */
typedef char kpm_sysmon_event_size_check[sizeof(kpm_sysmon_event_t) == 56 ? 1 : -1];

/* ===== CPU 亲和性/频率控制 =====
 * RESCTL_AFFINITY: arg2=tgid, arg3=cpu_mask64（bit n=CPU n；全 1=恢复）
 *                  → ret=0；无亲和性能力 → -KPM_E_DISABLED
 * RESCTL_FREQ:     arg2=tgid, arg3=util_max(0-1024；0xFFFFFFFF=恢复1024)
 *                  → ret=0；无 uclamp 设备（4.19）→ -KPM_E_DISABLED
 *                  （DEGRADED：仅亲和性压小核可用）
 * RESCTL_GLOBAL:   arg2=affinity_mask(0=跳过), arg3=util_max(0=跳过)
 *                  → 应用到全部 app 进程（立即生效一次；新进程不自动
 *                  追加——文档标注）；ret=应用线程数
 * RESCTL_CAPS:     ret=bit0 亲和性 | bit1 uclamp
 * 风险注释见 LH_resctl.h。 */
#define KPM_CMD_RESCTL_AFFINITY   0x1178
#define KPM_CMD_RESCTL_FREQ       0x1179
#define KPM_CMD_RESCTL_GLOBAL     0x117A
#define KPM_CMD_RESCTL_CAPS       0x117B

/* ===== hook 引擎双模式 =====
 * 命令语义/风险注释见 LH_hook2.h。
 * HOOK2_SET_STEALTH: arg2=pid, arg3=func_addr,
 *     arg4=arg_mask(低8位,改X0-X7)|action<<16|auto_apply<<24,
 *     arg5=aux(RET_MOD=x0伪返回值 / REDIRECT=trampoline地址)
 *     → ret=hook id（0..7）；ARG_MOD 需先 HOOK2_ARGS 预置窗口
 * HOOK2_SET_KFUNC: arg2=func_addr, arg3=action<<48|arg_idx<<40|errno<<32,
 *     arg4=value → ret=hook id（0x100+）
 * HOOK2_ARGS: arg2=user_buf(8×u64) → ARG_MOD 值窗口
 * HOOK2_DEL:  arg2=id → ret=0
 * HOOK2_LIST: arg2=max_count → kpm_hook2_entry_t[](32B×N) */
#define KPM_CMD_HOOK2_SET_STEALTH 0x1173
#define KPM_CMD_HOOK2_SET_KFUNC   0x1174
#define KPM_CMD_HOOK2_ARGS        0x1175
#define KPM_CMD_HOOK2_DEL         0x1176
#define KPM_CMD_HOOK2_LIST        0x1177

typedef struct {
    uint32_t id;
    uint32_t mode;            /* 0=normal(kfunc) 1=stealth(BRP) */
    pid_t    pid;
    uint32_t action;          /* KPM_HOOK_ACT_* */
    uint64_t addr;
    uint64_t hit_count;
} kpm_hook2_entry_t;          /* sizeof = 32 */
typedef char kpm_hook2_entry_size_check[sizeof(kpm_hook2_entry_t) == 32 ? 1 : -1];

/* 寄存器快照（272B 定长，用户态布局与 regmod 快照一致：
 * regs[31]@0 / sp@248 / pc@256 / pstate@264） */
typedef struct {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
} kpm_trap_regs_t;                                /* sizeof = 272 */
typedef char kpm_trap_regs_size_check[sizeof(kpm_trap_regs_t) == 272 ? 1 : -1];

/* 同步停靠条目摘要（40B，TRAP_LIST 输出） */
#pragma pack(push, 1)
typedef struct {
    uint32_t trap_id;         /* 停靠槽位 id（0..KPM_SYNC_TRAP_MAX-1） */
    uint32_t state;           /* KPM_TRAP_ST_* */
    int32_t  bp_index;        /* 来源断点槽位 */
    pid_t    pid;             /* 目标进程 */
    uint64_t addr;            /* 命中地址 */
    uint64_t pc;              /* 命中 PC */
    uint64_t hit_count;       /* 该断点累计命中 */
} kpm_trap_info_t;            /* sizeof = 40 */
#pragma pack(pop)
typedef char kpm_trap_info_size_check[sizeof(kpm_trap_info_t) == 40 ? 1 : -1];

#define KPM_SYNC_TRAP_MAX       8
#define KPM_TRAP_REGS_LEN       34  /* 内核侧快照数组：regs[31]+sp+pc+pstate */
#define KPM_TRAP_ST_FREE        0   /* 空闲 */
#define KPM_TRAP_ST_TRAPPED     1   /* 已停靠（等待客户端） */
#define KPM_TRAP_ST_RELEASE     2   /* 客户端已请求放行 */
#define KPM_TRAP_TIMEOUT_DEFAULT 2000     /* ms，超时自动放行 */
#define KPM_TRAP_TIMEOUT_INF    0xFFFFFFFFu /* 无限等待（显式指定，永久卡死风险） */

#define KPM_HIDE_MAX             16      /* 同时隐藏的进程数上限 */
#define KPM_HIDE_NAME_MAX        48      /* 隐藏记录 name 长度 */
#define KPM_HIDE_STATE_HIDDEN    1       /* 隐藏中（P0 彻底 或 P0+P1 兜底） */
#define KPM_HIDE_STATE_CONFLICT  2       /* 隐藏中且原 pid 号已被占用（不可恢复） */
#define KPM_HIDE_STATE_EXITED    3       /* 目标已退出（残留记录，自动清理） */
#define KPM_HIDE_STATE_LIMITED   4       /* 降级：仅枚举级（P1 不可用，直连仍可见） */

#define KPM_UNHOOK_INPUT         0x01
#define KPM_UNHOOK_GYRO          0x02
#define KPM_UNHOOK_PRCTL         0x04
#define KPM_UNHOOK_BP            0x08
#define KPM_UNHOOK_ALL           0x0F

/* 隐藏记录（共享于用户态，80 字节，HIDE_LIST 输出） */
#pragma pack(push, 1)
typedef struct {
    pid_t    pid;                       /* 被隐藏进程 TGID */
    pid_t    tid;                       /* 隐藏时刻主线程 tid（= tgid） */
    int32_t  state;                     /* KPM_HIDE_STATE_* */
    int32_t  slot;                      /* 记录槽位 1..KPM_HIDE_MAX */
    char     name[KPM_HIDE_NAME_MAX];   /* 隐藏时刻进程 comm */
    uint8_t  reserved[16];              /* 预留（对齐 80 字节） */
} kpm_hide_entry_t;                     /* sizeof = 80 */
#pragma pack(pop)

typedef char kpm_hide_entry_size_check[sizeof(kpm_hide_entry_t) == 80 ? 1 : -1];

/* Process entry (shared with userspace, 536 bytes)
 * name 容量 512 字节，容纳完整 cmdline（包名 + 参数） */
#define KPM_PROC_NAME_MAX 512
typedef struct {
    pid_t    pid;                             /* process ID */
    pid_t    ppid;                            /* parent PID */
    char     name[KPM_PROC_NAME_MAX];         /* process name (cmdline, 完整包名) */
    uint64_t start_time;                      /* process start time (ns) */
    uint32_t state;                           /* process state */
    uint32_t mem_size_pages;                  /* 进程虚拟内存总大小（mm->total_vm，单位页，×4096=字节） */
} kpm_proc_entry_t;

/* Memory map entry (shared with userspace, 288 bytes) */
#define KPM_MAP_PATH_MAX 256
typedef struct {
    uint64_t start;                           /* start address */
    uint64_t end;                             /* end address */
    uint64_t offset;                          /* file offset */
    uint8_t  perms;                           /* rwx permissions: bit0=r, bit1=w, bit2=x */
    uint8_t  reserved[7];                     /* padding */
    char     path[KPM_MAP_PATH_MAX];          /* mapped file path (empty if anonymous) */
} kpm_map_entry_t;

/* Error codes */
#define KPM_E_INVAL        1
#define KPM_E_NOMEM        2
#define KPM_E_NOTFOUND     3
#define KPM_E_FAULT        4
#define KPM_E_PERM         5
#define KPM_E_BUSY         6
/* 功能未启用：命令所属功能单元未 FEAT_ENABLE（或已 FEAT_DISABLE）。
 * 所有功能命令在 dispatch 入口统一门控返回本码，客户端据此判断"需先开启功能"。 */
#define KPM_E_DISABLED     7

/* ===== 功能单元开关命令 =====
 * 设计：默认仅开启内存读写与两协议接口；其余功能
 * 零初始化（不解析符号、不挂钩、不占资源），必须显式 FEAT_ENABLE。
 *
 * 双通道参数布局：
 *   FEAT_LIST UDP:   arg2=max_count → kpm_feat_entry_t[]（ret=条数）
 *   FEAT_LIST prctl: arg2=buf, arg3=max_count, arg4=buf_size（可选，
 *                    0=不限）；兼容旧 lhctl 的 arg2=max_count/arg3=buf
 *                    布局（arg2<=4096 且 arg3>=0x10000 时判定）。
 *   FEAT_ENABLE/DISABLE/STATE（两通道一致）：arg2=功能id，禁止按
 *                    指针翻译（否则会出现“id 变成 0”的假成功）。
 *
 * FEAT_ENABLE:  arg2=功能id → ret=启用后状态（1=OK 2=DEGRADED）
 *               越界/未注册 → -KPM_E_INVAL；依赖未启用/未编译 →
 *               -KPM_E_DISABLED；进行中 → -KPM_E_BUSY
 * FEAT_DISABLE: arg2=功能id → ret=0；核心传输通道拒绝 → -KPM_E_PERM
 *               被其他已启用功能依赖 → -KPM_E_BUSY
 * FEAT_STATE:   arg2=功能id → ret=KPM_FEATST_*；越界 id → -KPM_E_INVAL
 * FEAT_LIST.reason: 最近一次 enable 的失败/降级原因（0=无；DEBUG 原因位
 *               见 LH_debug.h，SYSMON 为 (syscall_nr<<8)|errno） */
#define KPM_CMD_FEAT_LIST     0x1200
#define KPM_CMD_FEAT_ENABLE   0x1201
#define KPM_CMD_FEAT_DISABLE  0x1202
#define KPM_CMD_FEAT_STATE    0x1203

/* 功能单元 id（KPM_FEAT_*，FEAT_ENABLE/DISABLE 的 arg2）。
 * 注册顺序即卸载逆序（先注册后卸载），见 LH_feat.c 注册表注释。 */
#define KPM_FEAT_MEM_RW       0   /* 内存读写（DMA/WB 双路径）——默认启用 */
#define KPM_FEAT_UDP          1   /* UDP 协议接口 —— 核心通道，禁拒 */
#define KPM_FEAT_PRCTL        2   /* prctl 协议接口 —— 核心通道，禁拒 */
#define KPM_FEAT_PROC         3   /* 进程信息（LIST/MAPS/QUERY/READ_FILE） */
#define KPM_FEAT_MEM_SCAN     4   /* 内存扫描 */
#define KPM_FEAT_MEM_FREEZE   5   /* 数值冻结 */
#define KPM_FEAT_PTR_SCAN     6   /* 指针扫描 */
#define KPM_FEAT_DEBUG        7   /* 调试断点（硬件 BP + 命中通知 + regmod） */
#define KPM_FEAT_DUMP         8   /* so dump */
#define KPM_FEAT_HIDE         9   /* 进程隐藏 */
#define KPM_FEAT_TOUCH        10  /* 触摸虚拟化 + 输入拦截 */
#define KPM_FEAT_GYRO         11  /* 传感器控制 */
#define KPM_FEAT_HOOK         12  /* 普通 hook（GOT/PLT/inline/内核函数） */
#define KPM_FEAT_STEALTH_HOOK 13  /* 无痕 hook（BRP 重定向） */
#define KPM_FEAT_SUSPEND      14  /* 进程挂起/恢复 */
#define KPM_FEAT_NETCTL       15  /* 进程禁网 */
#define KPM_FEAT_SYSMON       16  /* syscall/ioctl 监控与劫持 */
#define KPM_FEAT_RESCTL       17  /* CPU 亲和性/频率控制 */
#define KPM_FEAT_TRACE        18  /* syscall/kfunc/step trace */
#define KPM_FEAT_MEMWATCH     19  /* PTE 内存断点 */
#define KPM_FEAT_WXSHADOW     20  /* W^X shadow 无痕 hook */
#define KPM_FEAT_MAX          21

/* 功能单元状态（FEAT_LIST/FEAT_STATE 返回值语义） */
#define KPM_FEATST_DISABLED   0   /* 未启用（零初始化） */
#define KPM_FEATST_OK         1   /* 已启用，自检全过 */
#define KPM_FEATST_DEGRADED   2   /* 已启用但降级（reason 说明能力缺口） */
#define KPM_FEATST_FAILED     3   /* 启用失败（init 返回非 0，零残留） */
#define KPM_FEATST_TRANSITION 4   /* 启用/关闭进行中 */

/* 功能单元能力等级（决定机制档位） */
#define KPM_FEATCAP_FULL      0   /* 内核机制全量可用 */
#define KPM_FEATCAP_PARTIAL   1   /* 部分机制可用（如 4.19 无 uclamp：仅亲和性） */
#define KPM_FEATCAP_NONE      2   /* 编译未包含 / 内核机制缺失 */

/* 功能单元条目（FEAT_LIST 输出，32 字节定长） */
#pragma pack(push, 1)
typedef struct {
    uint32_t id;                /* KPM_FEAT_* */
    uint32_t state;             /* KPM_FEATST_* */
    uint32_t cap;               /* KPM_FEATCAP_* */
    uint32_t reason;            /* 失败/降级原因（init 返回值或原因码，0=无） */
    char     name[16];          /* 单元名（明文短名，仅诊断用） */
} kpm_feat_entry_t;             /* sizeof = 32 */
#pragma pack(pop)
typedef char kpm_feat_entry_size_check[sizeof(kpm_feat_entry_t) == 32 ? 1 : -1];

/* ===== 强制提权（Force Mode） =====
 * 语义：带 force 会话时不受驱动安全限制，允许可能崩溃的操作；
 * 不带的危险命令统一返回 -KPM_E_PERM（权限不足）。
 * force 只跳过驱动安全限制，不跳过符号/硬件存在性检查。 */
#define KPM_CMD_FORCE          0x1230
#define KPM_FORCE_OP_UNLOCK    0
#define KPM_FORCE_OP_LOCK      1
#define KPM_FORCE_OP_QUERY     2
#define KPM_FORCE_OP_PROBE     3   /* ret=能力 bitmap */
#define KPM_FORCE_OP_BYPASS    4   /* 尝试 lockdown/CFI bypass，ret=已应用 bit */
#define KPM_FORCE_MAGIC        0x4C484652u  /* 'LHFR' */
#define KPM_FORCE_DEFAULT_MS   60000u
#define KPM_FORCE_MAX_MS       600000u
#define KPM_FORCE_INF          0xFFFFFFFFu

#define KPM_FORCE_KERNEL_BP        0x0001u
#define KPM_FORCE_KERNEL_RW        0x0002u
#define KPM_FORCE_MEMWATCH_UNSAFE  0x0004u
#define KPM_FORCE_STEP             0x0008u
#define KPM_FORCE_HOT_TRACE        0x0010u
#define KPM_FORCE_CFI              0x0020u
#define KPM_FORCE_ETM              0x0040u
#define KPM_FORCE_ALL              0x007Fu

/* FORCE_QUERY / PROBE 返回结构 */
typedef struct {
    uint32_t active;        /* 1=force 会话有效 */
    uint32_t mask;          /* 已授予的 force 能力 */
    uint32_t remaining_ms;  /* 0xFFFFFFFF=无限 */
    uint32_t caps;          /* PROBE：底层能力 bitmap */
} kpm_force_info_t;

/* ===== 全量 trace ===== */
#define KPM_CMD_TRACE_CTRL     0x1210
#define KPM_CMD_TRACE_FETCH    0x1211
#define KPM_CMD_TRACE_INFO     0x1212

#define KPM_TRACE_OP_SET       0
#define KPM_TRACE_OP_STOP      1
#define KPM_TRACE_OP_CLEAR     2
#define KPM_TRACE_MODE_SYSCALL 0
#define KPM_TRACE_MODE_KFUNC   1
#define KPM_TRACE_MAX_EVENTS   1024
#define KPM_TRACE_KT_FUNC_MAX  8
#define KPM_TRACE_TYPE_SYSCALL 0
#define KPM_TRACE_TYPE_KFUNC   1
#define KPM_TRACE_TYPE_BP      2
#define KPM_TRACE_TYPE_MEMWATCH 3
#define KPM_TRACE_FLAG_ENTER   0x1
#define KPM_TRACE_FLAG_EXIT    0x2

#pragma pack(push, 1)
typedef struct {
    uint64_t seq;
    uint64_t ts;            /* ns；0=未知 */
    uint32_t type;          /* KPM_TRACE_TYPE_* */
    int32_t  pid;           /* tgid */
    int32_t  tid;
    uint32_t uid;
    uint32_t nr;            /* syscall nr 或 kfunc id */
    uint32_t flags;         /* ENTER/EXIT */
    uint32_t reserved;
    uint32_t reserved2;     /* 对齐到 8 字节（args 偏移 48） */
    uint64_t args[6];
    int64_t  ret;
    uint64_t aux;           /* kfunc=func_addr；BP=addr；保留 */
} kpm_trace_event_t;        /* 112B */
typedef char kpm_trace_event_size_check[sizeof(kpm_trace_event_t) == 112 ? 1 : -1];

typedef struct {
    uint32_t active;        /* 1=已启用 */
    uint32_t mode;          /* KPM_TRACE_MODE_* */
    uint32_t capacity;      /* ring 容量 */
    uint32_t events;        /* 当前可读事件数 */
    uint64_t dropped;       /* ring 满丢弃数 */
    uint32_t kfunc_hooks;   /* 当前 kfunc hook 数 */
    uint32_t syscall_ok;    /* 1=sys_enter 已注册，2=sys_exit 也注册 */
    uint32_t force_hot;     /* 1=force 允许热函数 */
    uint32_t reserved;
} kpm_trace_info_t;

typedef struct {
    uint64_t func_addr;
    int32_t  argno;         /* 0-6 */
    uint32_t flags;         /* bit0=force_hot */
    uint32_t id;
    uint32_t reserved;
} kpm_trace_kfunc_cfg_t;

typedef struct {
    int32_t  pid;           /* 0=全部 */
    uint32_t uid;           /* 0xFFFFFFFF=全部 */
    uint64_t nr_mask;       /* bit nr；0=全部（仅 nr<64） */
    uint32_t flags;
    uint32_t reserved;
} kpm_trace_syscall_cfg_t;
#pragma pack(pop)

/* ===== PTE 内存断点 ===== */
#define KPM_CMD_MEMWATCH_SET   0x1220
#define KPM_CMD_MEMWATCH_CLEAR 0x1221
#define KPM_CMD_MEMWATCH_LIST  0x1222
#define KPM_CMD_MEMWATCH_FETCH 0x1223
#define KPM_CMD_MEMWATCH_REARM 0x1224

#define KPM_MEMWATCH_MAX       256
#define KPM_MEMWATCH_MODE_WRITE 0x1u
#define KPM_MEMWATCH_MODE_READ  0x2u
#define KPM_MEMWATCH_MODE_EXEC  0x4u
#define KPM_MEMWATCH_FLAG_FORCE     0x1u  /* 允许危险页/block/ro/COW */
#define KPM_MEMWATCH_FLAG_RAW_COW   0x2u  /* force：不为 COW 让路，直接改回写权限 */
#define KPM_MEMWATCH_FLAG_COARSE    0x4u  /* force：允许 block mapping 粗粒度 */

#define KPM_MEMWATCH_ST_FREE    0
#define KPM_MEMWATCH_ST_ARMED   1
#define KPM_MEMWATCH_ST_HIT     2      /* one-shot 命中，待 REARM */
#define KPM_MEMWATCH_ST_DISABLED 3

#pragma pack(push, 1)
typedef struct {
    uint32_t id;
    uint32_t pid;
    uint64_t page;
    uint64_t addr;          /* 原始请求地址 */
    uint32_t mode;          /* KPM_MEMWATCH_MODE_* */
    uint32_t state;         /* KPM_MEMWATCH_ST_* */
    uint64_t hits;
    uint32_t flags;
    uint32_t reserved;
} kpm_memwatch_entry_t;     /* 48B */
typedef char kpm_memwatch_entry_size_check[sizeof(kpm_memwatch_entry_t) == 48 ? 1 : -1];

typedef struct {
    uint64_t seq;
    uint64_t ts;
    int32_t  pid;
    int32_t  tid;
    uint64_t addr;          /* fault address */
    uint64_t pc;
    uint32_t mode;          /* 命中的 mode */
    uint32_t flags;
    uint64_t hits;
    uint64_t reserved;
} kpm_memwatch_event_t;     /* 64B */
typedef char kpm_memwatch_event_size_check[sizeof(kpm_memwatch_event_t) == 64 ? 1 : -1];
#pragma pack(pop)

/* ===== W^X shadow 无痕 hook =====
 * 原理：把目标用户代码页复制到 kernel 内存
 * shadow 页，在 shadow 上写入 BRK/自定义 patch；把用户 PTE 改成
 * execute-only（AP=00 + UXN=0）指向 shadow。执行走 shadow，读取
 * 触发 permission fault → 切回原始页 r--，下次取指再切回 shadow --x。
 * BRK 命中：映射原始页 r-x + PSTATE.SS 单步执行原指令，步进回调里
 * 再切回 shadow。这样进程内读取/CRC 看到的始终是原始代码。
 *
 * 限制：同一页不能同时读与执行；自读代码区
 * 不要设 BRK；patch 不能跨页；4.19 无 user_step_hook 时 BP 不可用
 * （PATCH 仍可用）。
 */
#define KPM_CMD_WX_SET_BP   0x1240  /* arg2=pid, arg3=addr → ret=page id */
#define KPM_CMD_WX_SET_REG  0x1241  /* arg2=pid, arg3=addr, arg4=reg(0-30), arg5=value */
#define KPM_CMD_WX_DEL_BP   0x1242  /* arg2=pid, arg3=addr(0=all) */
#define KPM_CMD_WX_PATCH    0x1243  /* UDP: arg2=pid,arg3=addr,payload=bytes;
                                      * prctl: arg2=pid,arg3=addr,arg4=buf,arg5=len */
#define KPM_CMD_WX_RELEASE  0x1244  /* arg2=pid, arg3=addr(0=all) */
#define KPM_CMD_WX_LIST     0x1245  /* arg2=buf(prctl)/max(UDP), arg3=max(prctl) */
#define KPM_CMD_WX_INFO     0x1246  /* 总览：kpm_wx_info_t */

#define KPM_WX_MAX_PAGES    32
#define KPM_WX_MAX_BPS      32
#define KPM_WX_MAX_PATCH    8
#define KPM_WX_MAX_PATCH_LEN 256      /* 单次 patch 字节上限（同页内） */
#define KPM_WX_BRK_IMM      0x7       /* 自定义 BRK 立即数（避让内核已用） */
#define KPM_WX_BRK_INSN     (0xD4200000u | (KPM_WX_BRK_IMM << 5))

#define KPM_WX_ST_NONE      0
#define KPM_WX_ST_SHADOW_X  1         /* shadow --x（默认武装态） */
#define KPM_WX_ST_ORIGINAL  2         /* 原始 r--（读触发后） */
#define KPM_WX_ST_STEPPING  3         /* 原始 r-x（BRK 单步中） */
#define KPM_WX_ST_DORMANT   4         /* 已释放，保留槽位 */

#pragma pack(push, 1)
typedef struct {
    uint64_t addr;        /* 断点地址 */
    uint64_t value;       /* REG_MOD 写入值 */
    uint32_t reg_idx;     /* 0-30 = x0-x30 */
    uint32_t flags;       /* bit0=active */
} kpm_wx_bp_t;            /* 24B */

typedef struct {
    uint32_t id;
    uint32_t pid;
    uint32_t state;       /* KPM_WX_ST_* */
    uint32_t nr_bps;
    uint64_t page;
    uint32_t nr_patches;
    uint32_t hits;
    uint64_t last_pc;
} kpm_wx_page_info_t;     /* 40B */

typedef struct {
    uint32_t active;      /* 1=单元已启用 */
    uint32_t pages;       /* 当前 shadow 页数 */
    uint32_t bps;         /* 断点数 */
    uint32_t patches;     /* patch 数 */
    uint32_t brk_ok;      /* 1=register_user_break_hook 可用 */
    uint32_t step_ok;     /* 1=register_user_step_hook 可用 */
    uint32_t fault_ok;    /* 1=do_mem_abort 可用 */
    uint32_t reserved;
} kpm_wx_info_t;          /* 32B */
#pragma pack(pop)
typedef char kpm_wx_bp_size_check[sizeof(kpm_wx_bp_t) == 24 ? 1 : -1];
typedef char kpm_wx_page_info_size_check[sizeof(kpm_wx_page_info_t) == 40 ? 1 : -1];
typedef char kpm_wx_info_size_check[sizeof(kpm_wx_info_t) == 32 ? 1 : -1];

#endif /* _KPM_COMM_H_ */
