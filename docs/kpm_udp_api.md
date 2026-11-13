# KPM UDP 接口文档

## 1. 概述

KPM 隐藏驱动内置一个**完全内核态**的 UDP 服务，供 PC / 局域网客户端与驱动交互（供设备内进程使用的 prctl 通道见配套文档）。


| 项           | 值                                                                                         |
| ------------ | ------------------------------------------------------------------------------------------ |
| 协议         | 二进制 UDP（小端）                                                                         |
| 端口         | `17891`（`KPM_UDP_DEFAULT_PORT`，可模块参数覆盖）                                          |
| 绑定         | `0.0.0.0`（INADDR_ANY，局域网可访问）                                                      |
| 单包最大载荷 | `16384` B（`KPM_UDP_MAX_PAYLOAD`）                                                         |
| 隐蔽性       | 无守护进程 / 无`/proc/pid` 与文件痕迹；workqueue + 阻塞 recvmsg 事件驱动；未知命令静默丢弃 |
| 混淆         | 命令码与`0xDEAD37F3` 异或后上线                                                            |

**通道分工**（依据 `LH_cmd.c` dispatch case 全集标定）：

- **公共命令（66）**（通用/内存读写/进程列表/触摸/拦截/扫描 START·NEXT·RESULT·CLEAR/冻结/指针/断点/陀螺仪/进程隐藏）经协议层 `kpm_cmd_dispatch` 统一分发，双通道行为一致；HOOK 族（0x1140-1144）保留标签但已整体删除（返 -1，见 §4.12）；
- **prctl 专用（7）**：0x1137-113A、0x114A-114C（用户指针语义，UDP 分发返 -1）；
- **UDP 独有（17，LH_udp.c 本地处理，prctl 不可用）**：触摸推送 0x1030-32、扫描 STATUS/AOB/KERNEL 0x1104-06、READ_FILE 0x1148、PROC_FULLPATH 0x1149、DUMP 0x1153-55、MEM_READ_BATCH/BATCH2/GET_PTE 0x1160/64/63、STREAM 0x1180-82；
- 依赖内核缓冲回传（写 `g_resp_buf`），客户端无需关心实现差异。

---

## 2. 报文格式

### 2.1 请求头（48 B）

```
偏移  大小  字段        类型        说明
0     4    cmd         uint32      XOR 编码后的命令码（= 命令码 ^ 0xDEAD37F3）
4     4    seq         uint32      序列号（响应匹配用）
8     8    arg2        uint64      参数 1（与 prctl arg2 对应）
16    8    arg3        uint64      参数 2
24    8    arg4        uint64      参数 3
32    8    arg5        uint64      参数 4
40    4    data_len    uint32      附加数据长度（紧跟头部之后）
44    4    reserved    uint32      对齐保留
```

附加数据紧跟头部，长度 `data_len` ≤ 16384（如 `WRITE_MEM` 的写入数据、`READ_FILE` 的完整路径、`MEM_SCAN_AOB_START` 的特征、PLT_SET 的模块/函数名）。

### 2.2 响应头（16 B）

```
偏移  大小  字段        类型        说明
0     4    seq         uint32      与请求 seq 匹配
4     4    ret         int32       返回值（>=0 成功，<0 错误）
8     4    data_len    uint32      响应数据长度（紧跟头部之后）
12    4    reserved    uint32      对齐保留
```

> 未知命令码（解码后不在已知范围）**不返回任何响应**（静默丢弃）——端口对扫描器表现为"无响应"。客户端一律用超时处理。

### 2.3 命令码 XOR 编码

```c
#define KPM_CMD_XOR_KEY  0xDEAD37F3
#define KPM_CMD(cmd)     ((cmd) ^ KPM_CMD_XOR_KEY)
```

发送：`wire_cmd = code ^ 0xDEAD37F3`；接收：`code = wire_cmd ^ 0xDEAD37F3`。防静态扫描识别 0x1001~0x1182 常量。

### 2.4 错误码（响应头 ret）


| ret | 宏名             | 含义                                                        |
| --- | ---------------- | ----------------------------------------------------------- |
| -1  | `KPM_E_INVAL`    | 无效参数 / 该命令不适用于本通道                             |
| -2  | `KPM_E_NOMEM`    | 内存不足                                                    |
| -3  | `KPM_E_NOTFOUND` | 未找到目标（pid/addr/符号/会话未启动）                      |
| -4  | `KPM_E_FAULT`    | 内存访问错误                                                |
| -6  | `KPM_E_BUSY`     | 忙 / 会话状态不符（如推送 PING 时未启动、UN_HOOK prctl 位） |

> `KPM_E_PERM=5`、`KPM_E_BUSY=6` 常见于 prctl 通道。`-9999`（UNHANDLED）仅内部使用。

---

## 3. 命令总览（对齐 LH_comm.h，v1.6.0）

`详` = 本章有参考小节。`prctl` = 仅设备端 prctl 通道（见 `kpm_driver_api.md` §4）。v1.5 新增七族（TRAP/SUSPEND/NETCTL/SYSMON/HOOK2/RESCTL/FEAT，共 28 命令）UDP/prctl 双通道一致，参数细节见 `kpm_v15_api.md`；HOOK2 无痕引擎另见本章 §4.14。


| 命令码 | 名称                  | 通道       | 说明 / 文档位置                                                 |
| ------ | --------------------- | ---------- | --------------------------------------------------------------- |
| 0x1001 | READ_MEM              | 公共       | 读进程内存，§4.4                                               |
| 0x1002 | WRITE_MEM             | 公共       | 写进程内存，§4.4                                               |
| 0x1005 | HOOK_INFO             | 公共       | 模块状态（256 B），§4.1                                        |
| 0x1006 | TOUCH_DEV             | 公共       | 触摸设备就绪，§4.1                                             |
| 0x1007 | GET_LOG               | 公共       | 取内部日志，§4.1                                               |
| 0x1008 | SCREEN_INFO           | 公共       | 屏幕分辨率，§4.1                                               |
| 0x1014 | INTERCEPT_ON          | 公共       | 启动拦截，§4.3                                                 |
| 0x1015 | INTERCEPT_OFF         | 公共       | 关闭拦截，§4.3                                                 |
| 0x1016 | INTERCEPT_STATE       | 公共       | 拦截状态，§4.3                                                 |
| 0x1017 | INTERCEPT_SCALE       | 公共       | 偏移缩放，§4.3                                                 |
| 0x1018 | INTERCEPT_SLOT_OFF    | 公共       | 单 slot 关闭，§4.3                                             |
| 0x1019 | INTERCEPT_SLOT_STATE  | 公共       | per-slot 状态，§4.3                                            |
| 0x1020 | TOUCH_CREATE          | 公共       | 创建虚拟触摸，§4.2                                             |
| 0x1021 | TOUCH_MOVE            | 公共       | 移动触摸，§4.2                                                 |
| 0x1022 | TOUCH_UP              | 公共       | 抬起，§4.2                                                     |
| 0x1023 | TOUCH_DESTROY         | 公共       | 销毁，§4.2                                                     |
| 0x1024 | TOUCH_MOVE_TO         | 公共       | 动画移动到，§4.2                                               |
| 0x1025 | TOUCH_MOVE_DIR        | 公共       | 增量移动，§4.2                                                 |
| 0x1026 | TOUCH_GET             | 公共       | 单触摸信息，§4.2                                               |
| 0x1027 | TOUCH_GET_ALL         | 公共       | 全部活跃触摸，§4.2                                             |
| 0x1028 | TOUCH_COUNT           | 公共       | 活跃触摸数，§4.2                                               |
| 0x1029 | TOUCH_SUSPEND         | 公共       | 挂起，§4.2                                                     |
| 0x102a | TOUCH_RESUME          | 公共       | 恢复，§4.2                                                     |
| 0x102b | TOUCH_TAKEOVER        | 公共       | 接管真实触摸，§4.2                                             |
| 0x102c | TOUCH_POLICY          | 公共       | 调度策略，§4.2                                                 |
| 0x102d | TOUCH_SET_PARAMS      | 公共       | 设触摸参数，§4.2                                               |
| 0x102f | TOUCH_KEEPALIVE       | 公共       | 触摸心跳，§4.2                                                 |
| 0x1030 | TOUCH_RECORD_START    | UDP独有    | 事件推送会话启动（推送协议），§5.3                             |
| 0x1031 | TOUCH_RECORD_PING     | UDP独有    | 推送保活 PING，§5.3                                            |
| 0x1032 | TOUCH_RECORD_STOP     | UDP独有    | 停止推送，§5.3                                                 |
| 0x1040 | GYRO_LOCK             | 公共       | 锁定轴，§4.9                                                   |
| 0x1041 | GYRO_UNLOCK           | 公共       | 解锁轴，§4.9                                                   |
| 0x1042 | GYRO_LOCK_LIST        | 公共       | 锁定/控制列表，§4.9                                            |
| 0x1043 | GYRO_CONTROL          | 公共       | 虚拟力控制，§4.9                                               |
| 0x1044 | GYRO_CONTROL_STOP     | 公共       | 停止虚拟力，§4.9                                               |
| 0x1045 | GYRO_STATE            | 公共       | 陀螺仪状态，§4.9                                               |
| 0x1046 | GYRO_KEEPALIVE        | 公共       | 陀螺仪心跳，§4.9                                               |
| 0x1100 | MEM_SCAN_START        | 公共       | 扫描启动，§4.6                                                 |
| 0x1101 | MEM_SCAN_NEXT         | 公共       | 过滤下一轮，§4.6                                               |
| 0x1102 | MEM_SCAN_RESULT       | 公共       | 扫描结果，§4.6                                                 |
| 0x1103 | MEM_SCAN_CLEAR        | 公共       | 清除会话，§4.6                                                 |
| 0x1104 | MEM_SCAN_STATUS       | UDP独有    | 会话状态（不在协议层，本地处理），§4.6                         |
| 0x1105 | MEM_SCAN_AOB_START    | UDP独有    | 长 AOB 扫描（payload 特征），§4.6                              |
| 0x1106 | MEM_SCAN_KERNEL_START | UDP独有    | 内核映射扫描，§4.6                                             |
| 0x1110 | FREEZE_ADD            | 公共       | 添加冻结，§4.7                                                 |
| 0x1111 | FREEZE_REMOVE         | 公共       | 删除冻结，§4.7                                                 |
| 0x1112 | FREEZE_LIST           | 公共       | 冻结列表，§4.7                                                 |
| 0x1113 | FREEZE_TOGGLE         | 公共       | 切换冻结，§4.7                                                 |
| 0x1114 | FREEZE_CLEAR          | 公共       | 清空冻结，§4.7                                                 |
| 0x1120 | PTR_SCAN              | 公共       | 指针扫描，§4.8                                                 |
| 0x1121 | PTR_SCAN_CHAIN        | 公共       | 指针链扫描，§4.8                                               |
| 0x1122 | PTR_RESULT            | 公共       | 指针结果，§4.8                                                 |
| 0x1130 | DEBUG_BP_SET          | 公共       | 设置断点，§4.10                                                |
| 0x1131 | DEBUG_BP_CLEAR        | 公共       | 清除断点，§4.10                                                |
| 0x1132 | DEBUG_BP_LIST         | 公共       | 断点列表，§4.10                                                |
| 0x1133 | DEBUG_BP_HIT          | 公共       | 断点命中信息，§4.10                                            |
| 0x1134 | DEBUG_SINGLE_STEP     | 公共       | 单步，§4.10                                                    |
| 0x1135 | DEBUG_CONTINUE        | 公共       | 继续，§4.10                                                    |
| 0x1136 | DEBUG_BP_NOTIFY       | 公共       | 断点命中通知开关，§4.10                                        |
| 0x1137 | DEBUG_BP_SET_EX       | prctl      | 安装断点+应用篡改窗口（仅 prctl）                               |
| 0x1138 | DEBUG_BP_MODIFY       | prctl      | 更新断点篡改规则（仅 prctl）                                    |
| 0x1139 | DEBUG_BP_HIT_COUNT    | 公共       | 单断点命中计数（2026-10-08 放开双通道，原 prctl-only 为误限制） |
| 0x113A | DEBUG_BP_REGMOD       | prctl      | 预置篡改规则窗口（仅 prctl）                                    |
| 0x1140 | HOOK_INSTALL          | 公共(已删) | **已整体删除**（2026-08-07），返 -1，§4.12                     |
| 0x1141 | HOOK_REMOVE           | 公共(已删) | 同上                                                            |
| 0x1142 | HOOK_LIST             | 公共(已删) | 同上                                                            |
| 0x1143 | HOOK_TOGGLE           | 公共(已删) | 同上                                                            |
| 0x1144 | HOOK_PLT_SET          | 公共(已删) | 同上                                                            |
| 0x1145 | PROC_LIST             | 公共       | 进程列表，§4.5                                                 |
| 0x1146 | PROC_MAPS             | 公共       | 进程映射，§4.5                                                 |
| 0x1147 | PROC_QUERY_REGION     | 公共       | 单区域查询，§4.5                                               |
| 0x1148 | READ_FILE             | UDP独有    | 文件回退读（VFS，payload 路径），§4.13                         |
| 0x1149 | PROC_FULLPATH         | UDP独有    | VMA 完整路径，§4.13                                            |
| 0x114A | PROC_PID_BY_NAME      | prctl      | 按名查 pid（仅 prctl）                                          |
| 0x114B | PROC_MODULE_BASE      | prctl      | 按名查模块基址（仅 prctl）                                      |
| 0x114C | PROC_MODULE_BSS       | prctl      | 按名查 BSS 地址（仅 prctl）                                     |
| 0x114D | HIDE_PROCESS          | 公共       | 隐藏进程，§4.11                                                |
| 0x114E | RECOVER_PROCESS       | 公共       | 恢复隐藏进程，§4.11                                            |
| 0x114F | HIDE_LIST             | 公共       | 隐藏记录列表，§4.11                                            |
| 0x1153 | DUMP_BEGIN            | UDP独有    | dump 开始（ELF 会话），§5.1                                    |
| 0x1154 | DUMP_FETCH            | UDP独有    | dump 取块，§5.1                                                |
| 0x1155 | DUMP_END              | UDP独有    | dump 结束（SHA256），§5.1                                      |
| 0x1156 | UN_HOOK               | 公共       | 下线驱动 hook（收尾），§4.11                                   |
| 0x1157 | HIDE_P1               | 公共       | P1 兜底开关，§4.11                                             |
| 0x1160 | MEM_READ_BATCH        | UDP独有    | 通用批量读，§4.13                                              |
| 0x1163 | MEM_GET_PTE           | UDP独有    | 读原始 PTE，§4.13                                              |
| 0x1164 | MEM_READ_BATCH2       | UDP独有    | 变长批量读，§4.13                                              |
| 0x1180 | STREAM_BEGIN          | UDP独有    | 流式读（≤64 MB），§5.2                                        |
| 0x1181 | STREAM_WRITE          | UDP独有    | 分片写，§5.2                                                   |
| 0x1182 | DUMP_STREAM           | UDP独有    | dump 流式 fetch，§5.2                                          |
| 0x1158 | TRAP_GET              | 公共(v1.5) | 同步停靠寄存器快照读取（272 B），见 kpm_v15_api.md §1          |
| 0x1159 | TRAP_SET              | 公共(v1.5) | 停靠寄存器改写（UDP 走 payload）                                |
| 0x115A | TRAP_RESUME           | 公共(v1.5) | 停靠放行（0xFFFFFFFF=全部）                                     |
| 0x115B | TRAP_LIST             | 公共(v1.5) | 停靠条目列表（40 B）                                            |
| 0x115C | DEBUG_BP_SET_SYNC     | 公共(v1.5) | 同步断点安装（task_work 停靠 + 2 s 超时兜底）                   |
| 0x1165 | SUSPEND_PROC          | 公共(v1.5) | 进程挂起（trap-park/sigstop），见 kpm_v15_api.md §2            |
| 0x1166 | RESUME_PROC           | 公共(v1.5) | 进程恢复（0=全部）                                              |
| 0x1167 | SUSPEND_LIST          | 公共(v1.5) | 挂起记录列表（48 B）                                            |
| 0x116B | NETCTL_RULE           | 公共(v1.5) | 禁网规则增删（uid/pid/all_apps），见 kpm_v15_api.md §4         |
| 0x116C | NETCTL_SET            | 公共(v1.5) | 禁网总开关 + 拒绝码模式                                         |
| 0x116D | NETCTL_LIST           | 公共(v1.5) | 禁网状态查询（148 B）                                           |
| 0x116F | SYSMON_SET            | 公共(v1.5) | syscall 监控总开关，见 kpm_v15_api.md §5                       |
| 0x1170 | SYSMON_RULE           | 公共(v1.5) | 监控/拒绝/改参规则（MONITOR/DENY/TAMPER）                       |
| 0x1171 | SYSMON_FETCH          | 公共(v1.5) | 拉取监控事件（56 B）                                            |
| 0x1172 | SYSMON_RULES          | 公共(v1.5) | 规则列表（40 B）                                                |
| 0x1173 | HOOK2_SET_STEALTH     | 公共(v1.5) | 无痕 hook 安装（packed 参数语义，§4.14）                       |
| 0x1174 | HOOK2_SET_KFUNC       | 公共(v1.5) | 内核函数 hook（hook_wrap），见 kpm_v15_api.md §3               |
| 0x1175 | HOOK2_ARGS            | 公共(v1.5) | ARG_MOD 值窗口（UDP=64 B payload）                              |
| 0x1176 | HOOK2_DEL             | 公共(v1.5) | 删除 hook 条目                                                  |
| 0x1177 | HOOK2_LIST            | 公共(v1.5) | hook 条目列表（32 B，§4.14）                                   |
| 0x1178 | RESCTL_AFFINITY       | 公共(v1.5) | 进程 CPU 亲和性，见 kpm_v15_api.md §6                          |
| 0x1179 | RESCTL_FREQ           | 公共(v1.5) | uclamp util_max 限频（4.19 返 -7）                              |
| 0x117A | RESCTL_GLOBAL         | 公共(v1.5) | 全局亲和性/限频一次下发                                         |
| 0x117B | RESCTL_CAPS           | 公共(v1.5) | 能力位图（bit0 亲和性 bit1 uclamp）                             |
| 0x1200 | FEAT_LIST             | 公共(v1.5) | 功能单元列表（32 B ×N），见 kpm_v15_api.md §0                 |
| 0x1201 | FEAT_ENABLE           | 公共(v1.5) | 启用功能单元（依赖未启用 → -7）                                |
| 0x1202 | FEAT_DISABLE          | 公共(v1.5) | 停用功能单元（核心通道 → -5）                                  |
| 0x1203 | FEAT_STATE            | 公共(v1.5) | 单元状态查询                                                    |

> **已删除勿用**：`DUMP_START/PROGRESS/CANCEL (0x1150-0x1152)` 旧异步 dump 方案已移除。

---

## 4. 命令参考（含修改效果）

> 说明：每条命令按「请求参数 / 返回 / 响应数据 / **效果**」描述。效果 = 该命令对设备/目标进程产生的可观察修改。

### 4.1 通用命令

#### HOOK_INFO (0x1005) — 查询模块状态

- 参数：无（arg2~arg5 忽略）；prctl 通道可传 `arg2=buf, arg3=size` 换取完整结构（见 kpm_driver_api.md §2.2）
- 返回：`ret = state` 位图；resp_data = 256 B `kpm_state_info_t` 定长结构（magic `"KMPS"` + version）
- 布局要点（packed）：`state(8) / kver+syms_ret(12) / 触摸屏幕 7×i32[24,28] / intercept+active(8) / 功能路径 8B[60] / sym_bitmap[4]=128bit 符号可用性(68) / fallback_bitmap(84) / task_struct 偏移 12×i16(88) / 框架变量 vmemmap/memstart/pgd_va/mm_pgd/va_bits/page_shift/page_level(112,44B) / 模块版本 build_time size(156) / **gyro 段 7×i32(168,28B：ready/dev_count/locked/controlled/client_alive)** / reserved 至 256`
- `[60]` 功能路径 8B 逐字节：`0 mem_rw / 1 touch / 2 cmdline / 3 put_task_path / 4 vmemmap_source / 5 task_fetch_path / 6-7 reserved`
  - `put_task_path` 0..6：0 原生 / 1 手动+`__put_task_struct`(已标定) / 2 free_task(禁用) / 3 泄漏(`__put_task_struct` 缺) / 4 泄漏(标定未执行) / 5 泄漏(标定失败) / 6 泄漏(标定符号缺失)。
  - `task_fetch_path`（2026-09-19 启用，占原 `reserved2` 首字节 —— **尺寸 256B 与后续偏移不变**，老客户端读 0 语义安全）：0 = 取引用（`find_get_pid`+`get_pid_task`），1 = 免引用（`__rcu_read_lock`+`find_vpid`+`pid_task`）。
  - ⚠ **判"进程列表/maps 能否用"要看 `task_fetch_path` 而不是 `put_task_path`**：免引用路径与 `put_task_struct`/usage 标定彻底解耦，`put_task_path>=3` ≠ 进程/maps 被禁用。
- **效果**：只读查询，无修改。客户端用 state 位图（§7.2 架构文档）判断各子模块就绪；用功能路径字段判断实际采用路径（mem_rw DMA vs WB-only、touch CAPTURE vs IN-PLACE、cmdline 4 级回退等）。

#### TOUCH_DEV (0x1006) — 触摸设备就绪

- 返回：`ret = 1` 就绪 / `0` 未就绪（无 resp_data）
- **效果**：只读。

#### SCREEN_INFO (0x1008) — 屏幕分辨率

- 返回：`ret = 0`；resp_data = 20 B（5 × int32）：`screen_w, screen_h, raw_w, raw_h, scale`
- **效果**：只读。`screen_w/h` = raw/scale（用户坐标空间 1080×2392），`raw_w/h` = 硬件原始（17280×38272），`scale` = 放大倍数（16，1 raw = 1/16 像素）。所有触摸/拦截像素坐标均在此用户空间解释。

#### GET_LOG (0x1007) — 内部日志

- 参数：无
- 返回：`ret = 0`；resp_data = 环形日志文本（`kpm_log`，不走 dmesg）
- 加载期固定输出行（2026-10-08 补报）：`kpm: rcu_nesting_offset=%d (>0=borrow path, 0=any_held fallback)`——probe 在 `kpm_syms_init` 内运行且早于 log_init，标定成功日志原本被静默丢弃，故在符号解析收尾补报。`>0` = 卸载 RCU 救援走"借出"路径；`0` = 退回 `rcu_read_lock_any_held` 探测路径。客户端可据此判断卸载宽限路径。
- **效果**：只读（内部缓冲拷贝，UDP 走 `kpm_log_copy_to_kernel`）。

### 4.2 触摸命令（0x1020-0x102f）

虚拟触摸池 TVF 模型：每个虚拟触摸由 `handle`（池索引）标识。**坐标默认屏幕像素空间；`unit=RAW` 时可表达亚像素**（见 4.2 末）。

#### TOUCH_CREATE (0x1020)

- 参数：`arg2=priority`(int32，0=最低)；`arg4 = touch_major(uint16) | (pressure << 16)`，0=默认（10/30）
- 返回：`ret = handle`（≥0 成功，<0 失败）
- **效果**：在池中创建对象，**不产生 DOWN 帧**（坐标初始 -1，TVF 跳过 x<0 对象防 (0,0) 幻影触摸）。创建后必须 `TOUCH_MOVE` 设有效坐标才真正按下。

#### TOUCH_MOVE (0x1021)

- 参数：`arg2=handle`；`arg3 = x | (y << 32)`；`arg4` 高 32 位 `unit`：`0`=像素（×scale 输出）/ `1`=raw 最小单位（透传）
- 返回：`ret = 0`
- **效果**：输出一帧 MOVE 到新坐标；对象无有效坐标时首次 MOVE 触发 DOWN 帧。raw 模式直接透传不缩放（可 1/16 像素精度慢速漂移）。

#### TOUCH_UP (0x1022)

- 参数：`arg2=handle`；返回 `ret = 0`
- **效果**：发送 UP 事件；对象保留在池中（可 RESUME 复用）。

#### TOUCH_DESTROY (0x1023)

- 参数：`arg2=handle`；返回 `ret = 0`
- **效果**：强制销毁对象，**不输出 UP 事件**（直接摘除，槽位即刻回收）。异常清理慎用——正常结束请走 UP；模块卸载/心跳超时的整体清理由 `kpm_touch_destroy_all` 发完整 UP 帧，不在此命令范围。

#### TOUCH_MOVE_TO (0x1024) / TOUCH_MOVE_DIR (0x1025) — 动画移动

- 参数：`arg2=handle`；`arg3 = x|(y<<32)`（MOVE_TO 目标）或 `dx|(dy<<32)`（MOVE_DIR 增量）；`arg4 = major|(pressure<<16)|(unit<<32)`；`arg5 = duration | (interrupt<<32)`
- 返回：`ret = 0`/`1`(被 interrupt)/负值错误
- **效果**：MOVE_TO 在内核同步线性插帧直到完成或被 interrupt（阻塞命令上下文，期间占用接口 work 线程）；MOVE_DIR 增量即时帧（高频调用路径）。raw 域同理（arg4 unit=RAW）。

#### TOUCH_GET (0x1026) / TOUCH_GET_ALL (0x1027)

- GET：`arg2=handle`，resp = `kpm_touch_info_t`(8B: x,y,major,pressure,is_user,handle)
- GET_ALL：`arg3=max_count`（内核封顶 10），resp = 8B×N；`ret = N` 活跃触摸数
- **效果**：只读（查询对象坐标/参数，raw 模式下为 raw/scale 取整近似）。

#### TOUCH_COUNT (0x1028)

- 返回：`ret = 活跃触摸数`（= 虚拟对象数 + 真实手指数，IN-PLACE 下真实手指不注册对象仍被计入）
- **效果**：只读。客户端用其判断触摸是否还挂着。

#### TOUCH_SUSPEND (0x1029) / TOUCH_RESUME (0x102A)

- 参数：`arg2=handle`
- **效果**：暂停/恢复输出该 handle 的事件（状态保留）。SUSPEND 后对象不再发事件，RESUME 恢复。

#### TOUCH_TAKEOVER (0x102b) — 接管真实触摸

- 参数：`arg2=handle`，`arg3=real_tracking_id`
- **效果**：把当前屏幕上的真实手指（tracking_id）转为虚拟对象控制——该手指后续坐标由接管者决定（用户手指失去控制权，常用于"摸到就算我按到"场景）。

#### TOUCH_POLICY (0x102c)

- 参数：`arg2=policy`
- **效果**：设置虚拟触摸调度策略（多虚拟对象并发时的仲裁优先级）。

#### TOUCH_SET_PARAMS (0x102d)

- 参数：`arg2=handle`；`arg3 = major | (pressure<<16) | (mask<<32)`；mask `0x1`=major、`0x2`=pressure
- **效果**：运行时改对象 major/pressure（防常量特征）。

#### TOUCH_KEEPALIVE (0x102f) — 心跳（保活语义定稿）

- 参数：无（fire-and-forget）
- 返回：`ret = 0`
- **效果**：**无直接触摸修改**。保活机制：
  - 任何触摸命令（0x1020–0x102f）**或拦截命令（0x1014–0x1019，会改动用户触摸）**在协议层入口统一刷新保活时间戳 → 客户端**操作中无需发本命令**；
  - 空闲客户端周期发本命令（≤5 s 一次）；
  - 内核 >5 s 无操作也无 ping → 判定客户端离线 → **自动销毁全部虚拟触摸 + 释放 USER 对象 + 关闭拦截（恢复用户触摸原样）**（发完整 UP 帧，TRACKING_ID=-1 + BTN_TOUCH 0），防止"测试中断残留"导致触摸被代理/卡死。

> **修改效果要点（客户端侧设计影响）**：CREATE 不 DOWN；需补同坐标 MOVE 触发真实按下；UP 失败可重试再 DESTROY；模块卸载自动发 UP 清场，无需手动清理。

### 4.3 拦截命令（0x1014-0x1019）

拦截作用于**真实硬件触摸事件**（非虚拟触摸）。模式：


| 模式值 | 名称     | 效果                                              |
| ------ | -------- | ------------------------------------------------- |
| 1      | REDIRECT | 反向偏移（触摸点向操作方向反移，max_offset 限制） |
| 2      | OFFSET   | 固定偏移（全部触摸点平移 (ox,oy)）                |
| 3      | MIRROR   | 镜像（沿指定轴 mx/my）                            |
| 4      | PIN      | 固定位置（改写坐标，可能有 1 帧抖动）             |
| 5      | PIN_ZERO | 零方向固定（**丢弃 X/Y 事件**，零抖动）           |

`target_slot`：`0xFF`=所有 slot，`0~9`=指定 slot。

#### INTERCEPT_ON (0x1014)

- 参数：`arg2 = mode(u8) | (scale<<8) | (max_offset<<16)`；`arg3` 视 mode（见下）；`arg4` bits[16-23] = `target_slot`
- 返回：`ret = 0` / <0
- **效果**：开启后真实手指坐标被按模式改写/平移/固定，应用层看到的触摸行为变化。
- arg3 按 mode：


| mode       | arg3       | 说明                |
| ---------- | ---------- | ------------------- |
| 1 REDIRECT | 无需       | 用 scale/max_offset |
| 2 OFFSET   | `ox(int16) | (oy<<16)`           |
| 3 MIRROR   | `mx(u8)    | (my<<8)`            |
| 4 PIN      | `px(int16) | (py<<16)`           |
| 5 PIN_ZERO | 同 PIN     | 丢弃 X/Y 事件       |

#### INTERCEPT_OFF (0x1015)

- **效果**：关闭全部 slot 坐标变换，用户触摸恢复原样。注意：输入捕获 hook 本体保持安装（常驻，驱动功能基础），仅坐标变换停止。

#### INTERCEPT_STATE (0x1016)

- resp_data = 20 B（5×int32）：`enabled, mode, slot_mask, offset_x, offset_y`
- **效果**：只读。

#### INTERCEPT_SCALE (0x1017)

- 参数：`arg2=scale`(1-100)
- **效果**：改 REDIRECT 灵敏度（越界安全：强制最小 1）。

#### INTERCEPT_SLOT_OFF (0x1018)

- 参数：`arg2=slot_id`
- **效果**：仅关指定 slot（其他保持）。

#### INTERCEPT_SLOT_STATE (0x1019)

- resp_data = 100 B `kpm_intercept_slot_state_t`：`slot_mask(2) enabled(1) mode(1) offset_x[10]×int16 offset_y[10] pin_x[10] pin_y[10] finger_down[10] reserved[6]`
- **效果**：只读。finger_down 反映真实手指按下位图。

> 重要语义（CAPTURE 相关）：有活跃虚拟触摸时 hook 进入 CAPTURE；真实手指先于 CAPTURE 存在（未注册 USER 对象）时原事件**必须放行**否则手指被吞（坐标固定不动 bug）。机制详见 `kpm_architecture.md` §2.4。

### 4.4 内存读写命令

#### READ_MEM (0x1001)

- 参数：`arg2=pid`，`arg3=remote_addr`(u64)，`arg5=len`(≤16384 受 UDP 单包限制)
- 返回：`ret = 实际读取字节数`；resp_data = 读到的字节
- **效果**：只读目标进程内存（DMA/WB 页表直读，见架构 §2.1）。超长读取走 STREAM_BEGIN（§5.2）。

#### WRITE_MEM (0x1002)

- 参数：`arg2=pid`，`arg3=remote_addr`(u64)，附加数据 = 要写入的字节（`data_len`=len）
- 返回：`ret = 实际写入字节数`
- **效果**：写目标进程内存——这是"修改游戏数据/补丁"的最基础命令（配合扫描结果地址使用）。修改走物理页映射直写（目标进程不可见拦截，见架构）。

### 4.5 进程枚举命令

#### PROC_LIST (0x1145)

- 参数：`arg2=max_count`(默认 32)，`arg3=offset`(分页)
- 返回：`ret = 进程数`；resp_data = `kpm_proc_entry_t` 数组
- `kpm_proc_entry_t`（536 B，packed）：`pid(4) ppid(4) name[512] start_time(8) state(4) mem_size_pages(4)`。name = 完整 cmdline（Android 包名，如 com.tencent.mm）；分页：16384/536 ≈ **30 条/包**，循环调用直到返回数 < max_count。
- **效果**：只读。进程隐藏生效后，被隐藏进程不在此列表出现。

#### PROC_MAPS (0x1146)

- 参数：`arg2=pid`，`arg3=max_count`(默认 32)，`arg4=offset`(分页，UDP)
- 返回：`ret = 映射数`；resp_data = `kpm_map_entry_t` 数组（288 B：start/end/offset 各 8B + perms(1, bit0=r bit1=w bit2=x) + reserved[7] + path[256]）。16384/288 ≈ **56 条/包**。
- **效果**：只读。prctl 通道无分页（arg4 忽略，单次 max 条）。
- **2026-09-21（vmap/回退收敛）**：
  - `/proc/pid/maps` VFS 兜底仅在 VMA 主路径**确实不可用**（`kf_find_vma` 与 vm_next 偏移均缺）时启用。VMA 可用但目标进程 churn/anti-tamper 导致瞬态空（count==0）时直接返回 0（不再落回 /proc）——部分设备（MTK 无 `override_creds`）内核态打不开其它进程的 `/proc/pid/maps`（`ptrace_may_access` 拒绝），落回 /proc 会误报 `-3`（NOT_FOUND）。
  - `-3` 仍可表示进程真不存在/权限；客户端 `proc_maps_all` 对 `-3` 做 50ms 退避重试一次，区分瞬态与真失败。
  - 客户端 `proc_list_all` 由一次性预取全部 offset 改为顺序分页、不满页即停（内核单 workqueue 串行 + 每页从 PID=1 重扫，预取会放大到数十秒级；顺序分页通常仅需 ceil(user_proc/30) 页）。
- **2026-09-21（B 方案：cursor 续扫提速）**：
  - 新增参数 `arg5=start_addr`：上一页最后一个 `vm_end` 作为**续扫起点**。内核 `kpm_proc_maps_kernel` 从该地址直接 `find_vma` 续扫，**不再每页从地址 0 重扫并跳过 offset 个区域**——大进程（数千 VMA）全量拉取由每页 O(n) 累计的 O(n²) 降为 O(n)；单页实测由数十秒级（偶发超时被 `retries×timeout` 放大）收敛到毫秒级。
  - `start_addr>0` 时 `arg4=offset` 退化为从该地址之后的相对跳过（客户端配合传 0）。`start_addr=0` 保持原 offset 语义（内部调用如 dump/scan 均传 0，行为不变）。
  - 客户端 `proc_maps_all` 改用 cursor 续扫；进程 churn 致 VMA 漂移时若某页返回空且已取到区域，回退 offset 语义再取一次兜底防漏。

#### PROC_QUERY_REGION (0x1147)

- 参数：`arg2=pid`，`arg3=addr`
- 返回：`ret = 0`；resp_data = 单个 `kpm_map_entry_t`（288 B）
- **效果**：只读。返回包含 addr 的 [start,end) 区域；无匹配 -3。

### 4.6 内存扫描命令（0x1100-0x1106）

会话模型：START 建集 → NEXT 逐轮过滤 → RESULT 拉取 → CLEAR 结束（每 pid 同时 1 个会话）。

**类型 type**：`0`=INT8 `1`=INT16 `2`=INT32 `3`=INT64 `4`=FLOAT `5`=DOUBLE `6`=BYTEARRAY `7`=STRING

**模式 mode**（数值类型）：


| 模式码 | 名称         | 语义                                         |
| ------ | ------------ | -------------------------------------------- |
| 0      | EXACT        | == value                                     |
| 1      | RANGE        | value ≤ x ≤ value+range                    |
| 2      | CHANGED      | 与上轮不同                                   |
| 3      | UNCHANGED    | 与上轮相同                                   |
| 4      | INCREASED    | 比上轮大                                     |
| 5      | DECREASED    | 比上轮小                                     |
| 6      | UNKNOWN      | 首轮建集（值快照作基线），配合 NEXT 差值模式 |
| 7      | NOT_EQUAL    | != value                                     |
| 8      | INCREASED_BY | 差值 == value                                |
| 9      | DECREASED_BY | 差值 == -value                               |
| 10     | INCREASED_GE | 差值 >= value                                |
| 11     | DECREASED_GE | 差值 <= -value                               |

差值模式实现为 uint64 无符号差后按类型宽度截断为有符号（负值环绕不误判，溢出安全），见架构 §2.2。

#### MEM_SCAN_START (0x1100)

- 参数：`arg2=pid`；`arg3 = type | (mode<<8)`；`arg4=value`(≤8B)；`arg5 = value_len(u16) | (range<<32)`
- 返回：`ret = 0` / <0
- **效果**：开启会话（mm/pgd 缓存），value 类型对齐读取；扫描范围=目标进程可读用户内存（VMA 遍历），步进=type_size。

#### MEM_SCAN_NEXT (0x1101)

- 参数：`arg2 = type | (mode<<8)`；`arg3=value`；`arg5 = value_len | (range<<32)`
- 返回：`ret = 本轮匹配数`（0 表示集合清空可结束）
- **效果**：按新条件过滤上一轮结果集（只读进程当前值比对）。

#### MEM_SCAN_RESULT (0x1102)

- 参数：`arg2=max_count`，`arg3=offset`
- 返回：`ret = N`；resp_data = `kpm_scan_result_t`(24B：addr(8) value(8) prev_value(8)) 数组
- **效果**：只读拉取结果。客户端得到地址后配合 READ_MEM/WRITE_MEM/READ_BATCH2 读写。

#### MEM_SCAN_CLEAR (0x1103)

- **效果**：销毁会话、释放 mm/pgd 缓存与结果集。

#### MEM_SCAN_STATUS (0x1104)（UDP 本地）

- 参数：无；返回：resp_data = `kpm_scan_status_t`（48 B）
- 字段：`active / pid / region_count / result_count / result_capacity(1M) / truncated / scanned_bytes / total_bytes / failed_pages / swap_pages`
- **效果**：只读。truncated=1 表示结果缓冲已满有区域未记录（客户端应视为"部分结果"，勿误判为范围小）；swap_pages = swap/zram 换出页统计。

#### MEM_SCAN_AOB_START (0x1105) — 长 AOB（UDP 本地，payload 承载特征）

- 参数：`arg2=pid`；`arg3=mode<<8`（仅 EXACT）；`arg5=plen`(1..64)；附加数据两种格式：
  - 新格式（带通配）：`[u32 len][pattern(plen)][mask(plen)]`，`mask[i]==0` = 该字节通配（data_len = 4+2×plen 时识别）；
  - 旧格式（兼容）：`[pattern(plen)]`，全精确。
- **效果**：>8 B 特征走此命令（type 固定 BYTEARRAY 语义；≤8 B 自动走打包路径）。扫描复用 SCAN 会话主体（maps/批量/结果缓冲），结果经 MEM_SCAN_RESULT 拉取。

#### MEM_SCAN_KERNEL_START (0x1106) — 内核映射扫描（UDP 本地）

- 参数：`arg2=0`（pid 保留，必须 0）；`arg3 = type | (mode<<8) | (range_hi<<32)`；`arg4=value`（全 64 位）；`arg5 = value_len(u16) | (range_lo<<32)`
- range(64 位) = `range_hi<<32 | range_lo`，≤64 GB（`KPM_SCAN_KERNEL_MAX`）
- **效果**：扫 `[PAGE_OFFSET, PAGE_OFFSET+range)` 内核线性映射（copy_from_kernel_nofault 逐 4 KB 容错）。结果地址为内核 VA，结果经 SCAN_RESULT 拉取。

### 4.7 内存冻结命令（0x1110-0x1114）

#### FREEZE_ADD (0x1110)

- 参数：`arg2=pid`，`arg3=addr`，`arg4=value`，`arg5=size`(1/2/4/8)
- 返回：`ret = index`(≥0)
- **效果**：登记冻结项后由驱动周期性把 addr 处改写回 value（UDP 收包循环驱动 `kpm_mem_freeze_tick`，默认 50 ms 一轮，**不依赖客户端轮询**），实现"数值锁定"。槽位上限 32。

#### FREEZE_REMOVE (0x1111) / FREEZE_TOGGLE (0x1113) / FREEZE_CLEAR (0x1114)

- REMOVE：`arg2=index`；TOGGLE：`arg2=index, arg3=1/0`；CLEAR：清全部
- **效果**：停止/启停/全部停止对应冻结写入。

#### FREEZE_LIST (0x1112)

- 参数：`arg2=max_count`；resp_data = `kpm_freeze_entry_t`(32B：enabled/pid/addr/value/size/hit_count) 数组；`ret=N`
- **效果**：只读。

### 4.8 指针扫描（0x1120-0x1122）

#### PTR_SCAN (0x1120) / PTR_SCAN_CHAIN (0x1121)

- 参数：`arg2=pid`，`arg3=target_addr`；SCAN：`arg4=range`(允许偏差)；CHAIN：`arg4=depth`(多级链)
- 返回：`ret = 0` / <0
- **效果**：找进程内存中所有指向 target±range 的指针（CE 指针扫描语义）；CHAIN 从内向外逐级（找"指向指针的指针"）。

#### PTR_RESULT (0x1122)

- 参数：`arg2=max_count`，`arg3=offset`；resp_data = `kpm_ptr_result_t`(16B：addr(8) value(8)) 数组
- **效果**：只读。

### 4.9 陀螺仪 / 传感器控制命令（0x1040-0x1046）

> 实现为 **libsensorservice 拦截双路径**（uprobe `convertToSensorEvent()` 主路径 + sys_enter tracepoint read/pread64 兼容路径，2026-08-16），在传感器事件转换完成/读出、上报应用前改写数据。机制与架构合法性见 `kpm_architecture.md` §2.5。

**type/轴 语义**：

- type：`0`=TRANSLATION（加速度/线性加速度/重力/磁场），`1`=ROTATION（陀螺/未校准陀螺/旋转矢量/方向）
- axis：`0`=X `1`=Y `2`=Z（对应 `sensors_event_t.data[0..2]`）；`axis=0xFF`=全轴（仅 UNLOCK/STOP 支持）
- `arg2 = type | (axis<<8)`

**控制模型（锚点 + 叠加偏移）**：输出 = base + force_offset。

- **锁定**：锁定后该轴基值被替换为锚点 `lock_anchor`（硬锁/冻结）。`value == 0x7F800001`（NaN 位模式哨兵）→ 捕获下一帧真实读数作为锚点冻结在当前位置；`value` 为其它（含 `0` = float 0.0 合法目标"锁定到 0"）→ 锚点=value。
- **虚拟力**：`force_offset` **叠加**在基值之上，绝不替换用户实时输入（非死锁保证：用户操控始终生效，只是被叠加偏置）。停止时以 speed 平滑衰减回 0。

**虚拟力模式（arg5=mode）**：


| mode | 名称   | 效果                                                  | 建议                                           |
| ---- | ------ | ----------------------------------------------------- | ---------------------------------------------- |
| 0    | RAMP   | force_offset 以 speed 步长爬升到 offset，模拟持续施力 | 不推荐（爬升易被传感器校准识别为漂移自动回正） |
| 1    | DIRECT | force_offset 一步置为 offset                          | 推荐（校准视为真实读数不回正）                 |

#### GYRO_LOCK (0x1040)

- 参数：`arg2 = type|axis<<8`；`arg3=value`（float 位模式）
- 返回：`ret = 0` / <0
- **效果**：冻结该轴读数为锚点值。场景：把游戏视角固定在某角度/数值。

#### GYRO_UNLOCK (0x1041)

- 参数：`arg2 = type|axis<<8`（axis=0xFF 全轴解锁）
- **效果**：解除锁定，恢复用户实时读数。

#### GYRO_LOCK_LIST (0x1042)

- 参数：`arg2=max_count`（内核封顶 6）；resp_data = `kpm_gyro_entry_t`(28B) 数组（仅受控轴）
- 布局：`type(1) axis(1) locked(1) force_mode(1) lock_value(4) force_active(4) force_target(4) force_speed(4) force_offset(4) lock_current(1) reserved(3)`
  （共享条目字段名为 `lock_value`（float 位模式锚点）；内部轴状态模型中的对应字段为 `lock_anchor`。）
- **效果**：只读。lock_current=1 表示该轴处于"待捕获当前读数"状态（哨兵锁定）。

#### GYRO_CONTROL (0x1043)

- 参数：`arg2 = type|axis<<8`；`arg3=speed`（≤0=停止）；`arg4=offset`（目标偏移）；`arg5=mode`(0/1)
- **效果**：给该轴叠加虚拟力偏置 → 应用看到的读数 = 用户真实转动 + 偏置（如"视角缓慢向右漂"或"恒定偏置辅助"）。

#### GYRO_CONTROL_STOP (0x1044)

- 参数：`arg2 = type|axis<<8`（axis=0xFF 全轴）
- **效果**：force_offset 平滑回正到 0（不跳变）。

#### GYRO_STATE (0x1045)

- 返回：UDP resp = `int32[1]`：`[ready]`；prctl = 标量 `ret = ready`（1 = 任一拦截路径已安装可用）
- **效果**：只读。**完整传感器状态不在此命令**——`ready / dev_count / locked_axes / controlled_axes / client_alive` 在 `HOOK_INFO` 256 B 状态结构的 gyro 段（偏移 168，28 B）读取（dev_count = `convertToSensorEvent` 符号偏移，诊断用）。双路径命中计数经 state_info/诊断接口获取。

#### GYRO_KEEPALIVE (0x1046)

- **效果**：心跳（无直接传感器修改）。任意 GYRO 命令（0x1040–0x1046）自动刷新保活时间戳；空闲须 ≤5 s 一次；>5 s 无操作无 ping → 判定客户端离线 → **自动释放全部锁 + 回正偏移**（防离线残留锁死/偏移卡死）。

### 4.10 断点 / 调试命令（0x1130-0x1136 公共；0x1137/0x1138/0x113A 仅 prctl；0x1139 公共）

基于 ARM64 硬件调试寄存器（perf_event `register_user_hw_breakpoint`，per-task）与内存断点（PTE 只读）。**真机（6.1.134 GKI）实测可用**。机制见架构 §2.6。

**类型（BP_SET arg3=type）**：


| type | 名称           | 说明 / 效果                                           |
| ---- | -------------- | ----------------------------------------------------- |
| 0    | 软件断点       | **已禁用**（返 -1，防破坏代码段 + 无 Debug 异常处理） |
| 1    | 硬件执行断点   | 命中=目标地址执行                                     |
| 2    | 硬件写观察点   | 命中=目标地址写                                       |
| 3    | 硬件读写观察点 | 读写都命中                                            |
| 4    | 内存断点       | PTE 只读（页级，命中=该页写）                         |

槽位 = ARM64 硬件调试寄存器（4-6 个），驱动软件槽上限 16（`KPM_DEBUG_MAX_BREAKPOINTS`）。

#### DEBUG_BP_SET (0x1130)

- 参数：`arg2=pid`，`arg3=type`，`arg4=addr`，`arg5=size`(watch 尺寸 1/2/4/8；执行断点强制 1；内存断点页对齐)
- 返回：`ret = index`（槽位号 ≥0）/<0（-1 参数 / -3 pid 不存在 / -6 PMU 不可用或槽位满）
- **效果**：安装断点。命中后：
  - 单次命中通过 DEBUG_BP_HIT 查询 / BP_NOTIFY 异步推送；
  - **命中即暂停式捕获**（perf overflow），配合 SINGLE_STEP/CONTINUE 控制目标线程；
  - 命中语义 = 目标进程执行流被观测/暂停，这是客户端做"条件断点→读内存→改内存→继续"调试循环的基础。

#### DEBUG_BP_CLEAR (0x1131)

- 参数：`arg2=index`；**效果**：移除断点，恢复原状。

#### DEBUG_BP_LIST (0x1132)

- 参数：`arg2=max_count`；resp_data = `kpm_breakpoint_t`(72 B) 数组
- 布局：`enabled(4) pid(4) addr(8) size(8) type(4) hit_count(4) saved_orig(4) saved_pte(8) saved_pgd(8) perf_event(8) hw_reg_idx(4) notify(4)`
- **效果**：只读（含累计命中数）。

#### DEBUG_BP_HIT (0x1133)

- 参数：无；resp_data = `kpm_bp_hit_t`（32 B packed：`bp_index(4) pid(4) addr(8) pc(8) value(8)`）
- **效果**：取最近一次命中详情（哪个断点/哪条 PC/写观察点写入值）。

#### DEBUG_SINGLE_STEP (0x1134) / DEBUG_CONTINUE (0x1135)

- 参数：`arg2=pid, arg3=tid`；**效果**：单步执行 / 继续（ARM64 MDSCR_EL1.SS）。

#### DEBUG_BP_NOTIFY (0x1136)

- 参数：`arg2=1/0`（启用/停用），`arg3=通知端口`(0=默认)
- **效果**：启用后任何 `notify=1` 的断点命中经 workqueue 异步推送 **`kpm_bp_notify_t`（32 B：magic 'KBPN'/bp_index/pid/addr/hit_count）** 到记录的通知目标地址——客户端无需轮询即可获得命中事件。记录目标：UDP 通道 = recvfrom 源地址；prctl 通道 = NULL（复用上次记录地址，若先前经 UDP 启用过则仍可达）。新建断点默认 notify=1（受本总开关门控）。

> **0x1137/0x1138/0x113A（regmod 篡改）/ 0x114A-0x114C（按名查询）仅 prctl 通道可用**（含用户指针语义，需执行上下文 copy_from_user），UDP 分发返 -1。**0x1139（DEBUG_BP_HIT_COUNT）已于 2026-10-08 放开双通道**——原通道检查是从相邻需 regmod 窗口上下文的命令复制来的遗留（真机矩阵实证：UDP 装 async bp 成功但查询命中计数恒 -EINVAL；该命令实为只读计数查询，与 BP_LIST 同信息级别）。UDP 客户端如需命中寄存器篡改，仍走 prctl 通道（设备端转换模块 raw_syscall5 直调）。详见 `kpm_driver_api.md` §4。

### 4.11 进程隐藏 / 反检测命令（0x114D-0x114F / 0x1156-0x1157，v1.3.1）

> 实现=回退链 P0/P1/P2（详见 `kpm_architecture.md` §2.7 与专项文档）。效果目标：对用户态进程隐藏（防检测 / 防被杀）。

#### HIDE_PROCESS (0x114D) — 隐藏进程

- 参数：`arg2=pid`（目标 TGID，宿主 /proc 视角）
- 返回：`ret = 槽位`(1..16) / <0（-2 参数 / -3 pid 不存在或 idr 不可用 / -6 忙或槽位满）；幂等（重复隐藏返回既有槽位）
- **效果**：目标在 `/proc` 枚举（ps/getdents/readdir）、按 pid kill 中"查无此进程"，进程照常运行。P0（idr 摘除）默认实现：枚举级彻底；P1 开启时 /proc/<pid> 直连也 ENOENT。见下方边界。

#### RECOVER_PROCESS (0x114E) — 恢复

- 参数：`arg2=pid`（恢复该 pid）或 `0`（恢复全部）
- 返回：`ret = 恢复条数`
- **效果**：原 pid 号空闲则回填（进程在 /proc 重新可见、可 kill）；原号已被新进程占用 → 记录转 CONFLICT（引用保留，列表可见）。生效记录清空且 P1 已装时自动 unhook + 排空，零残留。

#### HIDE_LIST (0x114F) — 列表

- 参数：`arg2=max_count`（默认/上限 16）；resp_data = `kpm_hide_entry_t`(80 B ×N)；`ret = N`（= min(max_count,16)，全槽输出）
- 布局：`pid(4) tid(4) state(4) slot(4) name[48] reserved[16]`；name = **隐藏时刻 task comm**（≤15 字符，非 cmdline）；tid=pid（隐藏时刻主线程）
- state：`0`=槽位空闲（未使用）`1`=HIDDEN `2`=CONFLICT（原 pid 号被新进程占用，不可恢复）`3`=EXITED（目标已退出/残留记录）`4`=LIMITED（仅枚举级，直连仍可达——P1 不可用时如实降级）
- **效果**：只读（客户端按 state 过滤显示）。

#### UN_HOOK (0x1156) — 下线驱动 hook（收尾）

- 参数：`arg2=mask`（0=全部）：`bit0=0x1` 输入捕获（input_handle_event）｜`bit1=0x2` 传感器 uprobe（gyro）｜`bit2=0x4` prctl FP hook（**仅 UDP 可请求**；prctl 通道内自卸死锁 → 返 -6）｜`bit3=0x8` 硬件断点+通知
- 返回：`ret = 实际下线 hook 类数`
- **效果**：**单向收尾**——下线即清对应状态位（防 info 假可用）；恢复需重载模块。目的：彻底清场交付/退出时消除 B 级检测向量。

#### HIDE_P1 (0x1157) — P1 兜底开关

- 参数：`arg2=1` 启用 / `0` 关闭（默认）/ `<0` 查询；返回：`ret = 当前开关`
- **效果**：启用后下一个 HIDE_PROCESS 额外安装 proc_pid_lookup 兜底 stub（直连 ENOENT）；关闭立即拆 stub（幂等）。
  **⚠ 内核稳定性风险**：P1 需改写内核函数头，部分内核（本台 LunOS 6.1 实测）触发确定性 panic → **默认 gate=0**，仅对经验证内核显式开启。本台默认语义 = P0（枚举+防杀断；已知 pid 直连残留可读——如实呈现）。

**已知边界**（记录在案）：被隐藏进程自身 `/proc/self` 失效（勿隐藏依赖 /proc/self 的应用）；隐藏前已存在的子进程仍可见且 PPID 指向父进程（存在性泄露）；负 pgid 组信号/直接遍历 tasklist 的检测不受覆盖；4.19-（pid_hash 形态）P0 自检禁用（隐藏返 -3）。

### 4.12 HOOK 命令族（0x1140-0x1144）—— 已整体删除（禁用壳）

> **状态（源码实证，2026-08-07）**：PLT/GOT/inline/stealth hook 已按隐蔽性要求**整体删除**（改用户态 GOT 属 C 级持久残留：卸载不恢复 GOT 可被持久化扫描发现，与本项目隐蔽目标冲突）。`LH_hook_enhanced.c` 保留**最小禁用壳**——接口签名不变（命令分发接线零改动），全部导出函数返回 `-KPM_E_INVAL`。


| 命令码 | 名称         | 行为            |
| ------ | ------------ | --------------- |
| 0x1140 | HOOK_INSTALL | 返 -1（禁用壳） |
| 0x1141 | HOOK_REMOVE  | 返 -1           |
| 0x1142 | HOOK_LIST    | 返 -1           |
| 0x1143 | HOOK_TOGGLE  | 返 -1           |
| 0x1144 | HOOK_PLT_SET | 返 -1           |

- 驱动现役内核态 hook 仅 4 类：`input_handle_event` 输入捕获（touch）、传感器 uprobe + sys_enter tracepoint（gyro）、prctl FP hook（通信）、硬件断点（debug）——需要"运行时整体下线"用 `UN_HOOK (0x1156)`。
- **替代手段**（客户端对目标进程实现"拦截函数调用"类需求）：硬件执行断点 + 单步观察（0x1130/0x1134/0x1135）、命中寄存器篡改 regmod（prctl 0x1137-113A）、内存补丁（WRITE_MEM/批量写改写目标地址）、或对目标进程关键函数地址直接 `WRITE_MEM` 打补丁。
- 隐蔽性结论：HOOK 族删除后**无 GOT 残留向量**（原"C 级残留待修 P2-1"问题随之消除，见架构 §4.2）。

### 4.13 文件 / 批量 / 杂项命令（全部 UDP 独有，prctl 不可用）

#### READ_FILE (0x1148) — VFS 文件回退读

- 参数：`arg5=文件偏移`(loff)；附加数据 = 完整路径（data_len ≤ 255）
- 返回：`ret = 读取字节数`；resp_data = 文件内容（≤16 KB）；`-3`（open 失败/EOF 越界）、`-4`（读错误）
- **效果**：内核 VFS 读任意路径文件（`filp_open` O_RDONLY + `kernel_read`）。SELinux 限制：kernel 域可读 /system 类，block_device（zram）与 /data 部分路径被拒（-3）——已放弃 override_creds 绕过（曾 panic），zram 补读走 MEM_GET_PTE + READ_FILE("/dev/block/zram0", swp_off<<12) 仅对 SELinux 放行的路径有效，其余属已知边界。

#### PROC_FULLPATH (0x1149) — VMA 完整路径

- 参数：`arg2=pid`，`arg3=addr`；返回：`ret = 0`；resp_data = 完整路径字符串（含 NUL，如 `/system/lib64/libx.so`）
- **效果**：只读。RCU 锁内解析 addr 所在 VMA 完整文件路径（d_parent 纯内存，防 UAF）。

#### MEM_READ_BATCH (0x1160) — 通用批量读

- 请求 payload：`[u32 count][u32 per_len] + count × u64 地址`；`count ≤ 2048`，`per_len ∈ 1..256`（任意长度，非 2 的幂），`count×per_len ≤ 16384`
- 响应 payload：`count×per_len` 字节（成功=真实数据；**失败条目=全 0xFF**）；`ret = 成功读取条目数`
- **效果**：一批地址统一长度读取（会话级 pgd 缓存 + 线性映射批量，消除逐条往返）。扫描结果集中多个固定长度偏移一次性取回。

#### MEM_READ_BATCH2 (0x1164) — 变长批量读

- 请求 payload：`[u32 count] + count × {u32 len, u64 addr}`；`count ≤ 512`，`len ∈ 1..256`，Σlen ≤ 16384
- 响应 payload：按请求顺序拼接（失败条目全 0xFF）；`ret = 成功条目数`
- **效果**：每条目独立长度，支持结构体链式读取（如对象头 40B + 指针 8B 混合）。

#### MEM_GET_PTE (0x1163) — 原始 PTE

- 参数：`arg2=pid`，`arg3=vaddr`；响应 payload = 16 B：`{u64 entry, u32 level, u32 rsvd}`
- level：`1`=PMD 块映射、`2`=PTE 表项；entry = 原始页表项（不判断有效位）
- **效果**：只读。客户端判断 present / **swap 换出**（entry bit0=0 且含 swp_entry 编码 → 解析 swp_offset → READ_FILE(zram) 补读）。swap 页不触发目标进程缺页（无 fault 痕迹）。

---

### 4.14 hook 引擎双模式 HOOK2（0x1173-0x1177，v1.5，公共通道）

> 机制与锁序设计详见 `kpm_architecture.md` §2.11；全族参数详见 `kpm_v15_api.md` §3。普通（kfunc，0x1174）= 框架 hook_wrap 改内核文本（可被完整性校验发现，风险注释）；无痕（stealth，0x1173）= 硬件断点 BRP 重定向，**代码零修改**，EL0 读不到调试寄存器。

#### HOOK2_SET_STEALTH (0x1173) — 无痕 hook 安装


| arg  | 含义                                                                                                                                                                 |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| arg2 | `pid`（目标进程，0=不限定走同步停靠的进程语义仍按 pid 校验）                                                                                                         |
| arg3 | `func_addr`（命中地址；PC+4 跳过语义下须保证跳过该指令安全，见下）                                                                                                   |
| arg4 | `packed`：bit0-7=`arg_mask`（ARG_MOD 生效的 X0-X7）｜bit16-23=`action`（0=OBSERVE 1=ARG_MOD 2=RET_MOD 3=REDIRECT）｜bit24=`auto`（1=异步命中即应用，0=同步停靠闭环） |
| arg5 | `aux`（RET_MOD=x0 写值；REDIRECT=跳转目标）                                                                                                                          |

- 返回：`ret = id(0..7)` / <0。
- **packed 语义（2026-10-08 真机定稿）**：
  - `packed=0`（缺省）→ auto=0 → **同步停靠闭环**：命中后目标线程在 task_work 边界停靠，客户端 TRAP_GET → TRAP_SET → TRAP_RESUME 读改放行（低频控制流用）；
  - `auto=1`（如 `(0<<16)|(1<<24)`）→ **异步命中即应用**（µs 级不停靠，命中风暴场景用）：命中时按 action 改写寄存器后 **统一 PC+4 跳过触发指令**（命中指令不提交，ARG_MOD 在跳过前生效）。RET_MOD/REDIRECT 本身改写 PC，不受影响。
  - ⚠ PC+4 跳过语义要求 BP 落点"跳过一条指令仍安全"（如函数第 2 条指令处下点，或命中地址本就可跳过）；需要真执行命中指令的语义请用 auto=0 同步停靠放行路径。
- **效果**：目标进程对该函数的调用被按 action 改写（ARG_MOD 改参数 / RET_MOD 伪造返回值 / REDIRECT 改流程），进程内无任何指令/内存修改痕迹。

#### HOOK2_DEL (0x1176) / HOOK2_LIST (0x1177)

- DEL：`arg2=id` → `ret=0`。注意**门控顺序随内核代次不同**：6.1 在未 enable sthook 时先参数校验（未找到 id 返 -1）；4.19 先 sthook 门控（返 -7=-E_DISABLED）——错误码不同，语义一致（均未删除任何条目）。
- LIST：`arg2=max(≤16)`；resp_data = `kpm_hook2_entry_t`(32 B：id/mode/pid/act/addr/hits) ×N；`ret = N`。**效果**：只读。

---

## 5. 大数据通道：DUMP 与流式协议（UDP 独有）

### 5.1 ELF 模块 dump（0x1153 DUMP_BEGIN / 0x1154 DUMP_FETCH / 0x1155 DUMP_END）

3 阶段会话协议，用于把目标进程已加载模块（如 libUE4.so）**从内存重建 ELF**：


| 阶段 | 命令       | 说明                                                                                                                                                                                |
| ---- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | DUMP_BEGIN | `arg2=pid` + payload 模块名（≤63B，basename 包含匹配），内核解析 ELF 头/段表 → 会话 + 返回 `kpm_dump_hdr_t`(128B：magic 'DMP1'/base/size(含 bss 补零)/chunk/chunks/segs/缺失统计) |
| 2    | DUMP_FETCH | `arg2=文件偏移`（无 arg3），逐块取 → 返回 `kpm_dump_chunk_t`(16B 'DMPC'：offset/length/crc32) + data(≤15872B)；`ret` = 数据字节数                                                 |
| 3    | DUMP_END   | 结束会话 → 返回`kpm_dump_done_t`(48B 'DMPE'：bytes + 整体 SHA256 + 缺失补零统计)                                                                                                   |

**效果**：把运行中的模块完整 dump 成可离线分析的 ELF（重定位数据从进程内存直读）。客户端推荐直接走 DUMP_STREAM（快 10-30×），失败自动回退 DUMP_FETCH 传统模式。

### 5.2 流式协议（0x1180 STREAM_BEGIN / 0x1181 STREAM_WRITE / 0x1182 DUMP_STREAM）

**背景**：单请求-响应 = 1 个 RTT，吞吐 = 载荷/RTT（16 KB/次）。流式层 = 一次请求、内核连续发送 N 个 ≤16 KB 数据报（零往返等待），吞吐 = 链路带宽；数据报保持 16 KB 尺寸（IP 分片不增加），每块带 CRC32+offset，客户端重组校验。

#### STREAM_BEGIN (0x1180) — 任意地址流式读（≤64 MB）

- 参数：`arg2=pid`（flags bit0=1 时忽略=内核地址直读），`arg3=起始地址`，`arg4=总长`(1..64 MB)，`arg5=flags`(bit0=1 内核地址，copy_from_kernel_nofault)
- 响应两阶段（无额外往返）：① 流式头（响应头 + `kpm_stream_hdr_t` 40 B：magic 'STM1'/version/total/chunk/chunks/session）；② 数据报 × chunks：`kpm_stream_dgram_t` 20 B（magic 'STMC'/session/offset/len/crc32）+ data。
- **可靠性**：每块 CRC32（表驱动）；session=请求 seq（客户端过滤乱序/旧流）；非阻塞发送（DONTWAIT）+ 2-4 ms 退避 + 10000 次预算（~30 s，客户端消失不挂死 UDP 服务）；失败页补零（数据报总数不变）。
- **效果**：大段进程/内核内存高速拉取（libUE4 60 MB dump 场景）。客户端应设 SO_RCVBUF=8 MB + crc32 校验 + 看门狗重发。

#### STREAM_WRITE (0x1181) — 分片写

- 参数：`arg2=pid`，`arg3=addr`（基址），`arg4=total_len`；payload = `[u32 slice_off][data...]`（单片 ≤16380 B，区域 ≤64 MB）
- 返回：`ret = 实际写入字节数`
- **效果**：大片写目标进程内存。切片自包含可独立重试（幂等）。**仅允许进程用户内存**（拒绝内核地址，-5）。吞吐受 RTT 约束（每片确认后才发下一片）——超大写优先用连续切片流水。

#### DUMP_STREAM (0x1182) — dump 流式 fetch

- 参数：`arg2=file_off, arg3=本批字节数`（复用 DUMP_BEGIN 会话）
- 响应 = 直接发送数据报（无头报；total/chunk 由 DUMP_BEGIN 提供），offset=绝对文件偏移。
- **效果**：模块 dump 的流式通道（快 10-30×）。DUMP_END 仍返回整体 SHA256。

### 5.3 触摸事件推送会话（0x1030/0x1031/0x1032，UDP 独有）

事件推送 = 内核把触摸事件**主动推送**给客户端（非拉取），供实时显示/分析真实触摸流。


| 命令码 | 实际语义                 | 说明                                             |
| ------ | ------------------------ | ------------------------------------------------ |
| 0x1030 | START（建会话+启动记录） | `arg2=src_mask`（1=hw 2=out 3=both）；记住源地址 |
| 0x1031 | PING（保活）             | 刷新最后活跃时间；返回`0`=会话活跃 / `-6`=未启动 |
| 0x1032 | STOP                     | 停止推送+记录                                    |

- 推送数据报复用流式 dgram（'STMC'+session+起始序号+crc），payload = 事件数组（24 B×≤32/包）。
- 事件条目 24 B：`ts_ns(CNTPCT_EL0,8) slot(4) code(4) value(4) src(4)`。
- 客户端每 5 s PING，**>15 s 无 ping 自动停推**（防孤儿会话）。
- 客户端参考：`touch_stream.py`（实时推送显示/导出）、`touch_console.py --user`（真实触摸绿点叠加）。

---

## 6. 客户端速参

### 6.1 协议常量与核心收发

```python
import socket, struct
XOR_KEY = 0xDEAD37F3
PORT    = 17891
REQ_SZ, RESP_SZ = 48, 16          # 请求头 / 响应头
CMD = lambda c: (c ^ XOR_KEY) & 0xFFFFFFFF

def send(sock, host, seq, code, a2=0, a3=0, a4=0, a5=0, payload=b""):
    hdr = struct.pack("<IIQQQQII", CMD(code), seq,
                      a2 & 0xFFFFFFFFFFFFFFFF, a3 & 0xFFFFFFFFFFFFFFFF,
                      a4 & 0xFFFFFFFFFFFFFFFF, a5 & 0xFFFFFFFFFFFFFFFF,
                      len(payload), 0)
    sock.sendto(hdr + payload, (host, PORT))
    data, _ = sock.recvfrom(65536)
    seq_r, ret, dlen, _ = struct.unpack("<IiII", data[:RESP_SZ])
    return ret, data[RESP_SZ:RESP_SZ + dlen]
```

约定：seq 单调递增并校验回包 seq；超时 5 s；按命令码分别处理（未知命令无响应）；**共享结构体长度必须与内核同步**（见 LH_comm.h，改结构需两端同改）。

### 6.2 坐标打包（触摸/拦截）

```python
xy = (x & 0xFFFFFFFF) | ((y & 0xFFFFFFFF) << 32)          # arg3 打包坐标
mp = (major & 0xFFFF) | ((pressure & 0xFFFF) << 16)        # arg4 major|pressure
# TOUCH_MOVE raw 亚像素：arg4 |= (1 << 32)（unit=RAW）
```

### 6.3 分页上限速查（UDP 单包 16384 B）


| 命令                     | 单包条目   | 单条目      |
| ------------------------ | ---------- | ----------- |
| PROC_LIST                | 30         | 536 B       |
| PROC_MAPS                | 56         | 288 B       |
| SCAN_RESULT / PTR_RESULT | 683 / 1024 | 24 B / 16 B |
| HIDE_LIST                | 16         | 80 B        |
| BP_LIST / GYRO_LIST      | 16 / 585   | 72 B / 28 B |

### 6.4 配套客户端工具（工作区根）


| 脚本                                   | 用途 / 子命令                                                                                                                  |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `udp_test_mem.py`                      | 内存读写/扫描：read/write/scan/scan_next/result/clear/status/kscan/aob/swapread/group/export/dumpmem/**bigread/bigwrite**/dump |
| `udp_test_touch.py`                    | 触摸：create/move/up/destroy/count/…（-s 半自动滑屏）                                                                         |
| `udp_test_hide.py`                     | 隐藏：hide/recover/list/unhook/p1/info/log                                                                                     |
| `udp_test_gyro.py`                     | 陀螺仪：lock/unlock/list/control/state/…                                                                                      |
| `udp_test_bp.py`                       | 断点：set/clear/list/hit/step/cont/notify                                                                                      |
| `touch_console.py`                     | PC 触控台（鼠标模拟触摸 / 双指 / 真实触摸叠加 / 实时屏幕）                                                                     |
| `touch_stream.py` / `record_stream.py` | 触摸事件推送显示 / 录制                                                                                                        |

> `touch_console.py` 完整客户端接口文档：原 `kpm_touch_console_api.md`（未归档，接口以源码与 §5.3 为准）。

---

## 7. 注意事项

1. **包大小**：附加数据/响应 ≤ 16384 B；READ_MEM len 实际受此限制。
2. **字节序**：全部小端（ARM64 Linux ABI）；Python 用 `<` 前缀。
3. **未知命令**：静默丢弃不响应；客户端必须超时处理。
4. **共享结构体**：内核（LH_comm.h）与客户端必须同步布局/长度（曾错位乱码事故）。
5. **`_kernel` 拷贝**：UDP 响应写内核缓冲 `g_resp_buf`，`copy_to_user` 不可用 → 内部走 `*_copy_results_kernel`（SCAN_RESULT/FREEZE_LIST/PTR_RESULT/GET_LOG/BP_HIT）；客户端无需感知。
6. **推送/冻结保活依赖 UDP 流量**：冻结刷新由收包循环驱动（每轮处理 ≤64 空包）；长时间无流量刷新会停滞——可周期发 HOOK_INFO 保持 work 活跃。
7. **保活双通道一致**：触摸/陀螺仪心跳语义在两通道共用协议层入口，行为相同。
