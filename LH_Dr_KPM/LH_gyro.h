/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_gyro.h - Gyro/Accel Sensor control via uprobe on libsensorservice
 *
 * 通过 uprobe 挂载 libsensorservice.so 的 convertToSensorEvent() 函数，
 * 在"传感器事件转换完成、尚未上报给应用"的返回点改写 sensors_event_t
 * 输出缓冲（data[0..2] 对应 x/y/z float），实现陀螺仪/加速度计等
 * 相关传感器数据的控制（锁定/虚拟力偏移）。
 *
 * 控制方法：锁定（lock）+ 虚拟力（control: RAMP/DIRECT）+ 客户端保活（keepalive）。
 *
 * 兼容性：
 *   - AIDL 优先 + HIDL 回退双符号解析，运行时 ELF 动态解析偏移（不反编译）
 *   - uprobe_register 固定 3 参；≥6.12 禁用该路径并回退 tracepoint
 *   - 全符号经 kallsyms_lookup_name 自解析，厂商/内核无关
 */
#ifndef _KPM_GYRO_H_
#define _KPM_GYRO_H_

#include <ktypes.h>
#include <stdint.h>

/* 类型选择 */
#define KPM_GYRO_TRANSLATION  0   /* 平移：加速度/线性加速度/重力等 */
#define KPM_GYRO_ROTATION     1   /* 旋转：陀螺仪/旋转矢量等 */
#define KPM_GYRO_TYPE_MAX     2

/* 轴索引 */
#define KPM_GYRO_AXIS_X  0
#define KPM_GYRO_AXIS_Y  1
#define KPM_GYRO_AXIS_Z  2
#define KPM_GYRO_AXIS_MAX 3

/* 全轴（解锁/停止控制时用） */
#define KPM_GYRO_ALL_AXIS  0xFF

/* 虚拟力控制模式 */
#define KPM_GYRO_FORCE_RAMP     0
#define KPM_GYRO_FORCE_DIRECT   1

/* 锁定语义（lock 的 value 参数特殊值）：
 * value == KPM_GYRO_LOCK_CURRENT(0x7F800001, IEEE754 NaN 位模式) 表示
 * "锁定当前读数"——驱动在下一事件捕获该轴真实读数作为锁定锚点并冻结。
 * 用于交互式场景：用户把设备转到任意位置后发送 lock，冻结在实际位置。
 * 注意：0（float 0.0 位模式）是合法的"锁定到 0"目标值，不可用作哨兵。 */
#define KPM_GYRO_LOCK_CURRENT   0x7F800001

/* ===== sensors_event_t 布局（AOSP 固定，本模块访问字段偏移） =====
 * struct sensors_event_t {
 *   int32_t version;   // +0x00
 *   int32_t sensor;    // +0x04
 *   int32_t type;      // +0x08  ← 传感器类型（ACCEL=1, GYRO=4, ...）
 *   int32_t reserved0; // +0x0C
 *   int64_t timestamp; // +0x10
 *   union { float data[16]; ... }  // +0x18 起：data[0]=x, data[1]=y, data[2]=z
 * };
 * 本模块通过 uprobe ret handler 在此偏移改写 x/y/z（float） */
#define KPM_SEV_TYPE_OFF    8
#define KPM_SEV_DATA_OFF    24   /* 0x18 */
#define KPM_SEV_DATA_STRIDE 4    /* float 4 字节 */

/* ===== Android sensor type → 本项目 (type, axis) 映射 =====
 * 支持控制"相关传感器"：陀螺仪/未校准陀螺仪/旋转矢量 → ROTATION；
 * 加速度计/线性加速度/重力 → TRANSLATION。 */
#define KPM_STYPE_ACCELEROMETER            1
#define KPM_STYPE_MAGNETIC_FIELD           2
#define KPM_STYPE_ORIENTATION              3
#define KPM_STYPE_GYROSCOPE                4
#define KPM_STYPE_GRAVITY                  9
#define KPM_STYPE_LINEAR_ACCELERATION      10
#define KPM_STYPE_ROTATION_VECTOR          11
#define KPM_STYPE_GYROSCOPE_UNCALIBRATED   16
#define KPM_STYPE_ACCELEROMETER_UNCALIBRATED 35

/* sensor type 映射表条目：将 Android sensor type 映射到本项目 type */
typedef struct {
    int32_t s_type;   /* sensors_event_t.type 值 */
    uint8_t k_type;   /* KPM_GYRO_TRANSLATION / ROTATION */
} kpm_gyro_stype_map_t;

extern const kpm_gyro_stype_map_t kpm_gyro_stype_map[];
extern const int kpm_gyro_stype_map_cnt;

/* ===== 每轴控制状态 =====
 *
 * 最终输出 = 基值 + 叠加偏移
 *   基值（base）：
 *     锁定   → lock_anchor（硬锁定锚点，用户输入完全被替换为锚点）
 *     未锁定 → 用户实时读数 value_bits（透传，用户控制始终有效）
 *   叠加偏移（offset）：由 control 命令产生，以"速度"逐步逼近"目标偏移"。
 *     注意：偏移是【叠加】在基值之上，绝不可【替换】基值——否则
 *     用户转动设备时输入被覆盖（表现为"向左转无效、持续往右漂移"）。
 *     偏移在 float 域通过软浮点加法实现（模块 -mgeneral-regs-only
 *     禁用 FP 指令，用整数位运算模拟 IEEE754 单精度加法）。
 *
 * 锁定语义（硬锁定）：
 *     value == KPM_GYRO_LOCK_CURRENT → 捕获下一帧真实角速度，冻结角度
 *       （输出锚点 = 捕获时角度对应的"零角速度"，即 lock_anchor=0，
 *        用户后续转动被替换为 0 角速度 → 角度不再变化 → 冻结在该位置）
 *     value != 哨兵 → lock_anchor = value（float 位模式目标值）
 *
 * 控制语义（虚拟力，不覆盖用户）：
 *     输出 = base + force_offset
 *     DIRECT: force_offset 一步置为 target（叠加量）
 *     RAMP:   force_offset 以 speed 步长逼近 target（平滑叠加） */
typedef struct {
    /* 硬锁定 */
    int locked;          /* 1 = 轴输出强制为 lock_anchor */
    int lock_anchor;     /* 锁定锚点（float 位模式）：锁定后输出的固定基值 */
    int lock_current;    /* 1 = 待捕获当前读数（value==KPM_GYRO_LOCK_CURRENT 置位） */
    /* 虚拟力（叠加偏移） */
    int force_mode;      /* KPM_GYRO_FORCE_RAMP / DIRECT */
    int force_active;    /* 1 = 虚拟力正在向目标爬升 */
    int force_target;    /* 虚拟力目标偏移（float 位模式，叠加量） */
    int force_speed;     /* 每事件的爬升/衰减步长（float 位模式） */
    int force_offset;    /* 当前虚拟力偏移（float 位模式累加器，叠加量） */
} kpm_gyro_axis_t;

/* 陀螺仪全局状态：2 类型 × 3 轴 */
typedef struct {
    kpm_gyro_axis_t tran[KPM_GYRO_AXIS_MAX];
    kpm_gyro_axis_t rot[KPM_GYRO_AXIS_MAX];
} kpm_gyro_state_t;

/* 锁定列表条目（与用户态共享，GET_LOCK_LIST 返回） */
typedef struct {
    uint8_t  type;        /* KPM_GYRO_TRANSLATION / ROTATION */
    uint8_t  axis;        /* KPM_GYRO_AXIS_X/Y/Z */
    uint8_t  locked;      /* 0/1 */
    uint8_t  force_mode;  /* KPM_GYRO_FORCE_RAMP / DIRECT */
    int32_t  lock_value;
    int32_t  force_active;
    int32_t  force_target;
    int32_t  force_speed;
    int32_t  force_offset;
    uint8_t  lock_current; /* 1 = 该轴锁定位待捕获当前读数（GET_LOCK_LIST 反馈） */
    uint8_t  reserved[3];  /* 显式填充至 28 字节，保证 UDP 协议布局固定 */
} kpm_gyro_entry_t;      /* sizeof = 28 */

/* 编译期断言：确保协议布局固定为 28 字节（与文档/客户端一致） */
typedef char kpm_gyro_entry_size_check[(sizeof(kpm_gyro_entry_t) == 28) ? 1 : -1];

/* 全局状态（供 cmd 层访问） */
extern kpm_gyro_state_t g_gyro;

/* ===== uprobe 相关（自包含定义，避免依赖框架缺失头） =====
 * struct uprobe_consumer 内核定义（include/linux/uprobes.h，6.1 无 ref_ctr 字段）：
 *   struct uprobe_consumer {
 *       int (*handler)(struct uprobe_consumer *self, struct pt_regs *regs);
 *       int (*ret_handler)(struct uprobe_consumer *self,
 *                           unsigned long func, struct pt_regs *regs);
 *       bool (*filter)(struct uprobe_consumer *self, struct task_struct *task);
 *       struct uprobe_consumer *next;
 *   };
 * handler 由内核回调，regs 为内核真实 struct pt_regs *（框架已定义）。 */

/* 生命周期 */
long kpm_gyro_init(void);   /* ELF 解析 + uprobe 注册，0 成功 */
void kpm_gyro_exit(void);   /* uprobe 注销 + 资源释放 */
int  kpm_gyro_ready(void);  /* 1 = uprobe 已安装 */

/* 传感器 hook 安装状态查询（UN_HOOK 用），
 * 1 = uprobe 或 sys_enter tracepoint 任一已注册 */
int  kpm_gyro_hook_active(void);

/* 锁定 / 解锁 */
long kpm_gyro_lock(int type, int axis, int value);
long kpm_gyro_unlock(int type, int axis);          /* axis=KPM_GYRO_ALL_AXIS 全轴 */
long kpm_gyro_get_locks(void *buf, int max, int *count_out);  /* 填充 kpm_gyro_entry_t[] */

/* 虚拟力控制 */
long kpm_gyro_control(int type, int axis, int speed, int offset, int mode); /* speed<=0 视为停止 */
long kpm_gyro_control_stop(int type, int axis);                  /* axis=ALL 全轴 */

/* 客户端心跳保活 */
long kpm_gyro_keepalive(void);                 /* 刷新保活时间戳 */
int  kpm_gyro_purge_if_idle(void);             /* 检查超时并自动释放/回正，返回 1=已清理 */

/* 状态查询（供 HOOK_INFO 输出，UDP/prctl 双通道） */
void kpm_gyro_get_state(int *ready, int *dev_count,
                        int *locked_axes, int *controlled_axes,
                        int *client_alive);

/* 自动侦测：各拦截路径启用状态与命中计数 */
void kpm_gyro_get_stats(uint64_t *up_hits, uint64_t *tp_hits,
                        int *up_ready, int *tp_ready);

#endif /* _KPM_GYRO_H_ */