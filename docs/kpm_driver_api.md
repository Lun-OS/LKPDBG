# KPM 设备端驱动接口文档（prctl 通道）

## 1. 通道与调用面


| 项       | 值                                                                                       |
| -------- | ---------------------------------------------------------------------------------------- |
| 系统调用 | `prctl`（`__NR_prctl=167`，ARM64）                                                       |
| 调用方式 | `prctl(option, arg2, arg3, arg4, arg5)`                                                  |
| 鉴权     | 仅 UID 0（root）→ 非 root 调用直接放行原始 prctl，无感                                  |
| 命令识别 | `option` = 命令码 ^ `KPM_CMD_XOR_KEY (0xDEAD37F3)`                                       |
| 输出     | 列表/数据经**用户态缓冲区指针**由驱动 `copy_to_user` 回填（在调用进程上下文执行）        |
| 数据源   | 需要数据块/名字的命令以用户指针传入（驱动`copy_from_user`）——**UDP 无此能力**（返 -1） |

**通道关系**：公共命令（v1.3.1 的 66 个 + v1.5 新增 28 个 + DEBUG_BP_HIT_COUNT 0x1139 于 2026-10-08 由 prctl 专用改回公共）经协议层 `kpm_cmd_dispatch` 统一分发，双通道同语义；prctl 专用命令剩 6 个（用户指针语义：0x1137/0x1138/0x113A 篡改窗口、0x114A-0x114C 按名查询）。**其余命令（UDP 独有，prctl 放行原始 syscall 不可用）**：触摸推送 0x1030-32、扫描 STATUS/AOB/KERNEL 0x1104-06、READ_FILE/FULLPATH 0x1148-49、DUMP 0x1153-55、BATCH/PTE 0x1160/63/64、STREAM 0x1180-82。HOOK 族 0x1140-44 保留标签但已整体删除（返 -1，见 kpm_udp_api.md §4.12）。v1.5 新增族（TRAP 0x1158-115C、SUSPEND 0x1165-67、NETCTL 0x116B-D、SYSMON 0x116F-72、HOOK2 0x1173-77、RESCTL 0x1178-B、FEAT 0x1200-03）双通道一致，参数详见 `kpm_v15_api.md`。全命令码总览见 `kpm_udp_api.md` §3。

> 设计确认：prctl 只拦截 `option` 命中 XOR 命令码的调用，普通 prctl（非 root 或未识别 option）一律放行原 syscall（skip_origin=0），设备上正常应用行为无感知。

---

## 2. 调用约定

### 2.1 命令码编码

```c
#define KPM_CMD_XOR_KEY  0xDEAD37F3
#define KPM_CMD(cmd)     ((cmd) ^ KPM_CMD_XOR_KEY)
// 用户态：prctl(KPM_CMD(0x1020), ...)   —— 驱动侧 switch 用 KPM_CMD(KPM_CMD_TOUCH_CREATE)
```

### 2.2 参数布局（prctl → 协议层翻译）

prctl 的 5 个参数在驱动入口（LH_hooks.c）翻译成通道无关的协议层上下文，随后经 `kpm_cmd_dispatch` 统一分发。**布局按命令族分三类**（与 UDP 报文的 arg2~arg5 不完全一致，注意区分）：


| 命令族         | prctl 布局（arg2,arg3,arg4,arg5）                                                                          | 翻译后协议层                        |
| -------------- | ---------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| 内存读写       | READ_MEM：`pid, addr, local_buf(出), len`；WRITE_MEM：`pid, addr, local_buf(入), len`                      | 执行层直接读写 user_buf             |
| 列表类         | PROC_LIST / SCAN_RESULT / PTR_RESULT / FREEZE_LIST / BP_LIST / HOOK_LIST：`user_buf, max_count, offset, _` | arg2=max, arg3=offset, user_out=buf |
| 标量类         | BP_SET：`pid, type, addr, size`；FREEZE_ADD：`pid, addr, value, size`；TOUCH_*：`handle, x                 | y<<32, major                        |
| 指针类（专用） | 0x113A 快照指针在 arg4；0x114A 名字在 arg2；0x114B/0x114C 名字在 arg3                                      | copy_from_user 于当前进程上下文     |
| 特例           | HOOK_INFO：`buf, size, _, _`（传 buf 才回 256 B 完整结构，否则仅 state 位图）；SCREEN_INFO：`&w, &h, _, _` | —                                  |

> **双通道一致性原则**：同一命令码在两通道产生**相同的修改效果**；差异仅限数据入口/出口形态（UDP=报文 payload/resp，prctl=用户指针）。2026-08-07 曾修复列表类返回 0/错位等不一致，见 §5 差异表。

### 2.3 返回语义

- `ret >= 0`：成功（handle / 槽位 / 数量 / 字节数 / state 位图等，含义随命令）；
- `ret < 0`：错误码。


| ret   | 宏             | 含义                                                     |
| ----- | -------------- | -------------------------------------------------------- |
| -1    | KPM_E_INVAL    | 无效参数 / 需用户指针的命令在 UDP 通道（prctl 无此场景） |
| -2    | KPM_E_NOMEM    | 内存不足                                                 |
| -3    | KPM_E_NOTFOUND | pid/addr/名字/会话未找到                                 |
| -4    | KPM_E_FAULT    | 用户指针拷贝失败 / 内存访问错误                          |
| -5    | KPM_E_PERM     | 权限拒绝（如 STREAM_WRITE 拒绝内核地址）                 |
| -6    | KPM_E_BUSY     | 忙（如 prctl 通道内请求自卸 prctl hook）                 |
| -9999 | UNHANDLED      | 未识别命令 → 放行原始 syscall                           |

> 失败时不会写用户缓冲或写空（0 长度），客户端按 ret 分支即可。

### 2.4 执行上下文约束

- 全部命令在**调用进程（syscall）上下文**执行：可 sleep/copy_from_user（非中断/uprobe 上下文）；
- 名字/快照指针必须在调用进程**自身地址空间**（驱动不做跨进程用户指针解析）；
- 跨进程内存操作目标用 pid 指定，由驱动走内核页表遍历 + 引用计数保护（见 `kpm_architecture.md` §2.1）。

## 4. prctl 专用命令（UDP 分发返 -1；0x1139 已于 2026-10-08 改回公共，见下）

### 4.1 断点命中寄存器篡改（0x1137-0x113A）

> 语义：安装断点后，命中时（perf overflow 异常上下文）按预置规则改写目标线程 `pt_regs` / `fpsimd_state`，**异常返回后生效**。PC+=4 跳过触发指令后进入下一轮命中，新数据经 REGMOD 窗口重新预置——**一次性覆写，无需回滚旧值**。
> 适用：把目标进程内某比较/分支条件的结果改成恒定（如把命中处的寄存器覆写为期望值），每次断点命中都按窗口规则刷新。
> 机制详见 `kpm_architecture.md` §2.6。

#### DEBUG_BP_REGMOD (0x113A) — 预置篡改规则窗口


| arg  | 含义                                                                                                                                          |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| arg2 | `reg_mask`：bit0-30 = 篡改 X0-X30；bit31=SP；bit32=PC；bit33=PSTATE                                                                           |
| arg3 | `fp_mask`：bit0-31 = 篡改 V0-V31（受 `g_fpsimd_vregs_offset` 门控：未确认=0 时忽略，仅 GP/SP/PC/PSTATE 生效——稳定性红线）                   |
| arg4 | `regs_to_set_ptr`：用户态寄存器快照指针（仅拷贝 mask 对应字段；NULL=全 0）。快照布局：`regs[31]@0 / sp@248 / pc@256 / pstate@264 / vregs@288` |

返回：`ret = 0` / <0。行为：预置窗口规则，由 SET_EX / MODIFY 消费（消费后清空窗口）。

#### DEBUG_BP_SET_EX (0x1137) — 安装断点 + 应用窗口


| arg                 | 含义                                        |
| ------------------- | ------------------------------------------- |
| arg2/arg3/arg4/arg5 | `pid, type(1/2/3), addr, size`（同 BP_SET） |

返回：`ret = index`（槽位号 ≥0）。行为：用 REGMOD 窗口规则安装断点；窗口无效则等同普通 BP_SET；安装后清空窗口。

#### DEBUG_BP_MODIFY (0x1138) — 动态更新断点篡改规则


| arg  | 含义                  |
| ---- | --------------------- |
| arg2 | `index`（断点槽位号） |

返回：`ret = 0` / <0。行为：用窗口规则更新该断点篡改配置（不动断点本身），更新后清空窗口。

#### DEBUG_BP_HIT_COUNT (0x1139) — 单断点命中计数


| arg  | 含义                  |
| ---- | --------------------- |
| arg2 | `index`（断点槽位号） |

返回：`ret = 自安装以来累计命中数`（标量；增量由客户端按差值计算）。

> **通道变更（2026-10-08 真机修正）**：本命令原被误标 prctl-only——通道检查是从相邻 SET_EX/MODIFY/REGMOD（需 regmod 窗口上下文，真需用户指针）复制来的遗留。实际它是只读计数查询（与 BP_LIST 同信息级别），UDP 已放行（真机矩阵实证：UDP 装 async bp 成功但查询命中计数恒 -EINVAL）。现双通道同语义；本节其余三命令（SET_EX/MODIFY/REGMOD）仍仅 prctl。

> 使用流：`REGMOD(mask, fp_mask, 快照)` → `BP_SET_EX`（或对已有断点 `BP_MODIFY`）→ 命中自动覆写 → 需要新值再 REGMOD + MODIFY。常见模式：把命中寄存器改写为目标值实现"定向强改"（一次命中即生效，无需每帧轮询）。命中计数另可用于 HOOK2 无痕 hook（0x1173 auto=1，异步命中即应用后统一 PC+4 跳过）的命中率轮询。

### 4.2 按名查询（0x114A-0x114C）

> 名字经用户指针传入（当前进程空间，copy_from_user），故仅 prctl 通道。2026-08-15 随 TWT 转换层需求实施（设备内 agent 需按模块名定位基址补丁）。


| 命令码 | 名称             | 参数                                | 返回                      | 效果                           |
| ------ | ---------------- | ----------------------------------- | ------------------------- | ------------------------------ |
| 0x114A | PROC_PID_BY_NAME | arg2 = 进程名字符串指针             | `ret = pid` / <0          | 按完整包名/进程名解析 pid      |
| 0x114B | PROC_MODULE_BASE | arg2 = pid，arg3 = 模块名字符串指针 | `ret = 模块加载基址` / <0 | 定位模块基址（内存补丁起点）   |
| 0x114C | PROC_MODULE_BSS  | arg2 = pid，arg3 = 模块名指针       | `ret = BSS 段地址` / <0   | 定位模块 BSS（全局变量区改写） |

---

## 5. 全部命令效果速查（prctl 侧）

公共命令在 prctl 通道的调用形态（XOR option + 按 §2.2 布局传参），效果语义与 `kpm_udp_api.md` §4 完全一致，不重复罗列。引用关系：


| 族                                                                                            | prctl 传参要点                                                                                                                                                    | 效果参考         |
| --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| 通用 0x1005/06/08                                                                             | HOOK_INFO 需传`buf,size` 才回 256 B                                                                                                                               | udp §4.1        |
| 触摸 0x1020-102F                                                                              | 标量直传（同 UDP arg 语义，无 unit 高 32 位差异）                                                                                                                 | udp §4.2        |
| 拦截 0x1014-1019                                                                              | 同 UDP arg（INTERCEPT_STATE 用`arg2=buf` 出）                                                                                                                     | udp §4.3        |
| 内存读写 0x1001/02                                                                            | 用户缓冲指针在 arg4                                                                                                                                               | udp §4.4        |
| 进程 0x1145-47                                                                                | 列表类`buf,max,offset`                                                                                                                                            | udp §4.5        |
| 扫描/冻结/指针                                                                                | 仅 SCAN START/NEXT/RESULT/CLEAR（列表类输出走 buf）；FREEZE/PTR 标量同 UDP                                                                                        | udp §4.6-4.8    |
| 陀螺仪 0x1040-46                                                                              | 标量同 UDP；GYRO_STATE = 标量 ready（完整状态在 HOOK_INFO 256B gyro 段）                                                                                          | udp §4.9        |
| 断点 0x1130-36                                                                                | 标量同 UDP；命中详情 BP_HIT 用 arg2=buf；BP_NOTIFY prctl 传 NULL 复用上次记录地址                                                                                 | udp §4.10       |
| 断点 0x1130-36 + HIT_COUNT 0x1139                                                             | 标量同 UDP；命中详情 BP_HIT 用 arg2=buf；BP_NOTIFY prctl 传 NULL 复用上次记录地址；**0x1139 命中计数 2026-10-08 起双通道可用**（标量返回累计值）                  | udp §4.10       |
| v1.5 新增族 0x1158-115C / 0x1165-67 / 0x116B-D / 0x116F-72 / 0x1173-77 / 0x1178-B / 0x1200-03 | TRAP / SUSPEND / NETCTL / SYSMON / HOOK2 / RESCTL / FEAT，双通道一致（例外：HOOK2_ARGS prctl=arg2 用户指针，UDP=64 B payload；SYSMON_FETCH dropped 指针仅 prctl） | kpm_v15_api.md   |
| 隐藏 0x114D-57                                                                                | HIDE_LIST 列表类（buf,max）；UN_HOOK prctl 位自卸返 -6                                                                                                            | udp §4.11       |
| HOOK 0x1140-44                                                                                | **已整体删除**（2026-08-07，禁用壳返 -1），无 prctl 侧用法                                                                                                        | udp §4.12       |
| UDP 独有命令                                                                                  | 0x1030-32 / 0x1104-06 / 0x1148-49 / 0x1153-55 / 0x1160·63·64 / 0x1180-82**prctl 不可用**（dispatch UNHANDLED → 放行原始 syscall）                              | udp §4.6/4.13/5 |

---

## 6. 典型调用示例

### 6.1 设备端 agent / 转换模块（raw_syscall5 直调）

```c
#include <sys/prctl.h>
#define KPM_XOR 0xDEAD37F3u
#define KPM_CMD(c) ((unsigned long)(c) ^ KPM_XOR)

/* 查询模块状态位图（不需 buf → 只回 state） */
long state = syscall(__NR_prctl, KPM_CMD(0x1005), 0, 0, 0, 0);

/* 创建虚拟触摸 → handle */
long h = syscall(__NR_prctl, KPM_CMD(0x1020), 0 /*priority*/, 0, 0, 0);

/* 读进程内存（arg4 = 本地缓冲，arg5 = len） */
uint8_t buf[64];
long n = syscall(__NR_prctl, KPM_CMD(0x1001),
                 pid, addr, (long)buf, 64);

/* 预置篡改窗口 + 安装带篡改的断点 */
uint64_t snapshot[37];  /* regs[31]+sp+pc+pstate+vregs(最小 264B) */
syscall(__NR_prctl, KPM_CMD(0x113A),
        0x1 /*篡改 X0*/, 0, (long)snapshot, 0);
syscall(__NR_prctl, KPM_CMD(0x1137), pid, 1 /*hw exec*/, bp_addr, 1);
```

> TWT 转换桥即按此协议把 TWT ioctl 请求翻译为 prctl 调用（pack(1) twt_request_t → KPM_CMD(cmd)）。KPM 模块间不能互调（simplify_symbols 只解析框架 `.kp.symbol` 段），转换模块只能走本接口。

### 6.2 调用结果判定

```c
if (ret >= 0) { /* 成功，语义随命令 */ }
else { /* -1..-6，见 §2.3 */ }
```

---

## 7. 约束与边界

1. **UID 0**：非 root 进程调用被放行（无任何驱动处理痕迹）。
2. **option 编码**：必须是 `cmd ^ 0xDEAD37F3`；错误 option 放行原始 prctl。
3. **用户指针**：仅解析调用进程自身地址空间；跨进程一律用 pid 指定目标。
4. **不能在中断/uprobe handler 上下文调用**（syscall 语义）：驱动内部为 uprobe/触摸事件路径设计的分支（如 WB-only 读写）不暴露为 prctl 命令面。
5. **结构体同步**：prctl 出参结构体（proc_entry 536B / map_entry 288B / breakpoint 72B / hide_entry 80B / gyro_entry 28B / scan_result 24B 等）以 LH_comm.h 为准，与 UDP 侧共用同一布局。
6. **UN_HOOK 是单向收尾**（input/gyro/bp/prctl 类下线后恢复需重载模块）；HIDE_P1 开关**可逆**（关闭=立即拆 stub，可再开启，下一 HIDE 生效）。prctl 侧不要请求自卸 prctl hook（返 -6）。

---

## 8. 多内核行为差异实测（v1.5.0，2026-10-08）

同一模块二进制（`LH_1.5.0_debug.kpm`，框架 KernelPatch 0.13.9）在两代内核各跑一轮 `tools/test_full_matrix.py`：**均 54 PASS / 0 FAIL / 1 WARN**（WARN = wp 命中数记录项）。差异点如下：


| 项                                                 | GKI 6.1.134（Ace5 / MT6989）                                                                                      | QGKI 4.19.157（elish / SD870）                                                                                                                                 |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 硬件调试资源上限                                   | BRP=6 / WRP=4（ARMv8.2 真实上限；ID_AA64DFR0 被 EL2 虚报，直读 WVR4+ 触发 UNDEF，上限经 undef_hook 逐槽探测得出） | 同（BRP=6 / WRP=4，双设备一致）                                                                                                                                |
| 软件单步（undef 探测路径）                         | 可用                                                                                                              | **禁用（fail-closed）**：4.19 内核态 undef 异常不咨询 hook（`call_undef_hook` 直接 return 1）→ undef 逐槽探测无法工作 → `step=0`。debug 单元其余能力不受影响 |
| 同步停靠（BP_SET_SYNC / TRAP / SUSPEND trap-park） | 可用                                                                                                              | 可用——停靠不依赖 step：task_work=1 / sched_to=1 / ms2j=1 / wake=1 / ref=1 探测全通过                                                                         |
| HOOK2_DEL（未 enable sthook 时的错误码）           | 返 -1（先参数校验后门控）                                                                                         | 返 -7（sthook 门控先于参数校验）——错误码顺序不同，语义一致                                                                                                   |
| vm_file 偏移自标定（probe）                        | `vm_file_off=136 / dentry=24 / name=40`                                                                           | `vm_file_off=160 / dentry=24 / name=40`（qstr len 偏移 off-by-4 修复后，两代内核各自标定正确，dentry 链解析验证命中）                                          |
| RESCTL_FREQ（uclamp）                              | 可用                                                                                                              | 返 -7（4.19 无 uclamp，符号缺失自动降级）                                                                                                                      |
| 加载方式                                           | ksud 命令行                                                                                                       | APatch 系管理器 UI 手动（管理器不支持命令加载；adb push 不保留执行位，推送可执行文件需 chmod 755）                                                             |

---

## 附录 A. 执行层 C 函数清单（内部接口速查）

> 模块内部执行层函数（供协议层 case 调用）。机制、符号解析与回退详见 `kpm_architecture.md`。下表为"哪个文件提供什么能力"，新增功能按此落位。


| 文件                         | 提供（节选）                                                                                                                                                                          | 架构章节     |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| LH_touch.c / touch_manager.c | `touch_move/move_raw/up/destroy/takeover/suspend/resume/move_to/move_dir/get_info/get_all/get_active_count/set_policy/keepalive/purge_if_idle/destroy_all`；事件记录 `kpm_tvrecord_*` | §2.3        |
| LH_intercept.c               | `kpm_intercept_start_redirect/offset/mirror/pin/pin_zero/slot_off/stop/get_state/get_slot_state/set_scale`；真实手指计数                                                              | §2.4        |
| LH_mem_rw.c                  | `kpm_mem_rw_process / read_kernel / write_kernel / get_pte / read_kernel_pages(_cached) / read_batch(_2) / open/close_scan_session / read_kernel_wb / write_kernel_wb`                | §2.1        |
| LH_mem_scan.c                | `kpm_mem_scan_*`（START/NEXT/RESULT/CLEAR/STATUS/AOB/KERNEL + abort）                                                                                                                 | §2.2        |
| LH_ptr_scan.c                | `kpm_ptr_scan / chain / result`                                                                                                                                                       | §2.2        |
| LH_mem_freeze.c              | `kpm_mem_freeze_add/remove/list/toggle/clear/tick`                                                                                                                                    | §2.2        |
| LH_gyro.c                    | `kpm_gyro_init/exit/ready/lock/unlock/get_locks/control/control_stop/keepalive/purge_if_idle/get_state`                                                                               | §2.5        |
| LH_debug.c                   | `kpm_debug_bp_set/clear/list/copy_hit(_kernel)/single_step/continue/notify_set/bp_count_active` + regmod（SET_EX/MODIFY/HIT_COUNT/REGMOD）                                            | §2.6        |
| LH_proc.c                    | `kpm_proc_list(_kernel)/maps(_kernel)/query_region(_kernel)/fullpath`；按名查询（pid/base/bss）                                                                                       | §2.8        |
| LH_hide.c                    | `kpm_hide_init/process/recover/list/unhook/p1_set/exit`                                                                                                                               | §2.7        |
| LH_hook2.c                   | hook 引擎双模式：`kpm_hook2_set_stealth/set_kfunc/args_window(_kernel)/del/list(_kernel)`；锁序铁律见架构 §2.11                                                                      | 架构 §2.11  |
| LH_feat.c / LH_filter.c      | 功能单元开关`kpm_feat_list/enable/disable/state`；进程过滤共享层 kpm_filter（netctl/sysmon 复用）                                                                                     | v15 §0/§4  |
| LH_suspend.c                 | 进程挂起/恢复：`kpm_suspend_*`（trap-park/sigstop）+ tasklist 双锚点偏移推导                                                                                                          | v15 §2      |
| LH_netctl.c                  | 禁止联网：`kpm_netctl_rule/set/list`（socket 族拦截，uid [10000,19999]）                                                                                                              | v15 §4      |
| LH_sysmon.c                  | syscall/ioctl 监控劫持：`kpm_sysmon_set/rule/fetch/rules`（MONITOR/DENY/TAMPER）                                                                                                      | v15 §5      |
| LH_resctl.c                  | CPU 亲和性/uclamp：`kpm_resctl_affinity/freq/global/caps`（4.19 无 uclamp 返 -7）                                                                                                     | v15 §6      |
| LH_hook_enhanced.c           | `kpm_hook_enhanced_init/exit`（**禁用壳**：2026-08-07 整体删除，导出签名保壳全返 -1）                                                                                                 | —（已移除） |
| LH_dump.c                    | ELF dump 会话（BEGIN/FETCH/END/STREAM，UDP 本地）                                                                                                                                     | §2.10       |
| LH_syms.c                    | `kf_*` 符号函数指针表 + `g_*` 运行时偏移探测 + 三级回退                                                                                                                               | §3          |
| LH_cmd.c                     | 协议层：`kpm_cmd_dispatch` / `kpm_cmd_out_write` / `kpm_cmd_ctx_t`                                                                                                                    | §6          |
| LH_hooks.c                   | prctl 接口层（syscall hook → 参数翻译 → dispatch）                                                                                                                                  | §1/§6      |
| LH_udp.c                     | UDP 接口层 + 本地特有命令 + 推送 work                                                                                                                                                 | §2.10       |
| LH_main.c                    | `kpm_drv_init/exit`（子模块 init 顺序 + 状态位 + 卸载时序）                                                                                                                           | §5          |
| LH_state_info.c              | `kpm_fill_state_info`（256 B 状态结构填充）                                                                                                                                           | §7          |
| LH_log.c                     | 环形日志（GET_LOG）                                                                                                                                                                   | —           |

---

## 附件 调用示例SDK

```C++
#ifndef _KPM_COMM_H_
#define _KPM_COMM_H_

#include <stdint.h>

/* ===== 用户态 <-> 内核通信命令码 =====
 * 通过 prctl(option, arg2, arg3, arg4, arg5) 传递
 * option = 命令码，arg2~arg5 为参数
 *
 * 命令码在编译时使用 KPM_CMD_XOR_KEY 进行异或混淆。
 * 这可以防止静态分析通过扫描二进制文件中的已知常量（0x1001-0x1182）来识别 prctl 命令码。
 * 内核模块和 kpmctl 使用相同的密钥。
 */

/* XOR 密钥：基于时间无关常量。
 * 选择该值以产生不会与标准 prctl 选项（PR_SET_NAME=15, PR_GET_NAME=16 等）冲突的值，
 * 并且不会像典型的魔数那样被检测器签名扫描器检测到。 */
#define KPM_CMD_XOR_KEY  0xDEAD37F3

/* 混淆宏：将命令码与密钥进行异或。
 * KPM_CMD(cmd) 生成通过 prctl 发送的混淆值。
 * 内核中使用：case KPM_CMD(KPM_CMD_READ_MEM): ...
 * 用户态中使用：prctl(KPM_CMD(KPM_CMD_READ_MEM), ...) */
#define KPM_CMD(cmd)  ((cmd) ^ KPM_CMD_XOR_KEY)

/* 通用命令 */
#define KPM_CMD_READ_MEM     0x1001   /* 读取进程内存：arg2=pid, arg3=remote_addr, arg4=local_buf, arg5=len */
#define KPM_CMD_WRITE_MEM    0x1002   /* 写入进程内存：arg2=pid, arg3=remote_addr, arg4=local_buf, arg5=len */
#define KPM_CMD_HOOK_INFO    0x1005   /* 查询模块状态 */
#define KPM_CMD_TOUCH_DEV    0x1006   /* 查询触摸设备：arg2=0 自动查找 */
#define KPM_CMD_GET_LOG      0x1007   /* 获取内部日志：arg2=user_buf, arg3=buf_size */
#define KPM_CMD_SCREEN_INFO  0x1008   /* 获取屏幕分辨率：arg2=&width, arg3=&height */

/* 拦截命令 */
#define KPM_CMD_INTERCEPT_ON    0x1014  /* 开始拦截：arg2=mode|scale<<8|max_offset<<16, arg4=target_slot<<16 */
#define KPM_CMD_INTERCEPT_OFF   0x1015  /* 停止拦截 */
#define KPM_CMD_INTERCEPT_STATE 0x1016  /* 查询拦截状态 */
#define KPM_CMD_INTERCEPT_SCALE 0x1017  /* 设置偏移缩放：arg2=scale [1-100] */
#define KPM_CMD_INTERCEPT_SLOT_OFF 0x1018  /* 禁用某个槽位的拦截：arg2=slot_id */
#define KPM_CMD_INTERCEPT_SLOT_STATE 0x1019  /* 获取每个槽位的拦截状态：arg2=user_buf */

/* ===== TVF V2 TouchHandle API 命令 ===== */

#define KPM_CMD_TOUCH_CREATE    0x1020  /* 创建虚拟触摸：arg2=priority, 返回 handle */
#define KPM_CMD_TOUCH_MOVE      0x1021  /* 更新坐标：arg2=handle, arg3=x|y<<32 */
#define KPM_CMD_TOUCH_UP        0x1022  /* 抬起触摸（UP）：arg2=handle */
#define KPM_CMD_TOUCH_DESTROY   0x1023  /* 销毁触摸（强制释放）：arg2=handle */
#define KPM_CMD_TOUCH_MOVE_TO   0x1024  /* 动画移动到：arg2=handle, arg3=tx|ty<<32, arg4=major|pressure<<16, arg5=duration|interrupt<<32 */
#define KPM_CMD_TOUCH_MOVE_DIR  0x1025  /* 增量移动：arg2=handle, arg3=dx|dy<<32, arg4=major|pressure<<16, arg5=duration|interrupt<<32 */
#define KPM_CMD_TOUCH_GET       0x1026  /* 获取触摸信息：arg2=handle, arg3=user_buf */
#define KPM_CMD_TOUCH_GET_ALL   0x1027  /* 获取所有活跃触摸：arg2=user_buf, arg3=max_count */
#define KPM_CMD_TOUCH_COUNT     0x1028  /* 获取活跃触摸数量 */
#define KPM_CMD_TOUCH_SUSPEND   0x1029  /* 挂起触摸：arg2=handle */
#define KPM_CMD_TOUCH_RESUME    0x102a  /* 恢复触摸：arg2=handle */
#define KPM_CMD_TOUCH_TAKEOVER  0x102b  /* 接管真实触摸：arg2=handle, arg3=real_tracking_id */
#define KPM_CMD_TOUCH_POLICY    0x102c  /* 设置调度策略：arg2=policy */
#define KPM_CMD_TOUCH_SET_PARAMS 0x102d /* 设置触摸参数：arg2=handle, arg3=major|(pressure<<16)|(mask<<32), mask: 0x1=major, 0x2=pressure */
#define KPM_CMD_TOUCH_KEEPALIVE 0x102f /* 触摸心跳：客户端周期调用（≤5s 一次），
                                          * 超时视为客户端离线 → 内核自动销毁全部虚拟触摸
                                          * （防测试中断残留导致 CAPTURE 代理用户触摸） */

/* ===== 触摸坐标单位（2026-08-07 增强：支持最小单位） =====
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

/* ===== 陀螺仪/加速度传感器控制命令（2026-08-14，与触摸同机制） =====
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

/* Touch info 结构体（与用户态共享，8 字节） */
typedef struct {
    int16_t  x;            /* 当前 X 坐标 */
    int16_t  y;            /* 当前 Y 坐标 */
    uint8_t  touch_major;  /* 触摸大小 */
    uint8_t  pressure;     /* 压力值 */
    uint8_t  is_user;      /* 1=真实用户触摸, 0=虚拟触摸 */
    uint8_t  handle;       /* TouchHandle（池索引） */
} kpm_touch_info_t;

/* 每个槽位的拦截状态（与用户态共享） */
#define KPM_MAX_SLOTS 10
typedef struct {
    uint16_t slot_mask;                              /* 哪些槽位被拦截（bit i = slot i） */
    uint8_t  enabled;                                /* 0=关, 1=开 */
    uint8_t  mode;                                   /* 0=关, 1=重定向, 2=偏移, 3=镜像, 4=固定 */
    int16_t  offset_x[KPM_MAX_SLOTS];                /* 每个槽位当前应用的 X 偏移 */
    int16_t  offset_y[KPM_MAX_SLOTS];                /* 每个槽位当前应用的 Y 偏移 */
    int16_t  pin_x[KPM_MAX_SLOTS];                   /* 每个槽位的固定目标 X */
    int16_t  pin_y[KPM_MAX_SLOTS];                   /* 每个槽位的固定目标 Y */
    uint8_t  finger_down[KPM_MAX_SLOTS];             /* 1=槽位上手指按下 */
    uint8_t  reserved[6];                            /* 填充至 8 字节对齐 */
} kpm_intercept_slot_state_t;

/* 模块状态标志 */
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
#define KPM_SYM_CTKN           3   /* kf_copy_to_kernel_nofault (新增) */
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
    uint8_t  reserved2[3];

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

    /* [168] 陀螺仪/传感器 (28 字节，2026-08-14) */
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

/* Touch action 类型（旧式，供 intercept 使用） */
#define KPM_TOUCH_DOWN      0
#define KPM_TOUCH_MOVE      1
#define KPM_TOUCH_UP        2

/* 最大触摸点数（= 最大输出槽位数） */
#define KPM_MAX_TOUCH_POINTS 10

/* ===== 内存扫描命令 ===== */
#define KPM_CMD_MEM_SCAN_START   0x1100  /* 开始扫描：arg2=pid, arg3=type|mode<<8, arg4=value, arg5=range */
#define KPM_CMD_MEM_SCAN_NEXT    0x1101  /* 下一轮：arg2=type|mode<<8, arg3=value */
#define KPM_CMD_MEM_SCAN_RESULT  0x1102  /* 获取结果：arg2=user_buf, arg3=max_count, arg4=offset */
#define KPM_CMD_MEM_SCAN_CLEAR   0x1103  /* 清除扫描会话 */
#define KPM_CMD_MEM_SCAN_STATUS  0x1104  /* 2026-08-04: 扫描会话状态（结果数/截断标志/进度） */
#define KPM_CMD_MEM_SCAN_AOB_START 0x1105 /* 2026-08-04: 长 AOB 特征扫描（>8B，特征放 payload，arg2=pid, arg3=mode<<8, arg5=len, ≤KPM_SCAN_AOB_MAX） */
#define KPM_CMD_MEM_SCAN_KERNEL_START 0x1106 /* 2026-08-06: 内核线性映射范围扫描
    arg2=0(pid 保留), arg3=type|mode<<8, arg4=value, arg5=range(字节数, ≤KPM_SCAN_KERNEL_MAX)
    扫描范围 = [PAGE_OFFSET + 0, PAGE_OFFSET + range)，线性映射直读（页级容错）。 */

/* ===== 扫描模式（2026-08-06 扩展，CE 风格完整过滤集） =====
 * 新增模式与数值类型组合使用（字节类型仍仅 EXACT）：
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

/* ===== 内存冻结命令 ===== */
#define KPM_CMD_FREEZE_ADD       0x1110  /* 添加冻结：arg2=pid, arg3=addr, arg4=value, arg5=size */
#define KPM_CMD_FREEZE_REMOVE    0x1111  /* 移除冻结：arg2=index */
#define KPM_CMD_FREEZE_LIST      0x1112  /* 列出冻结：arg2=user_buf, arg3=max_count */
#define KPM_CMD_FREEZE_TOGGLE    0x1113  /* 切换冻结：arg2=index, arg3=enable */
#define KPM_CMD_FREEZE_CLEAR     0x1114  /* 清除所有冻结 */

/* ===== 指针扫描命令 ===== */
#define KPM_CMD_PTR_SCAN         0x1120  /* 指针扫描：arg2=pid, arg3=target_addr, arg4=range */
#define KPM_CMD_PTR_SCAN_CHAIN   0x1121  /* 链扫描：arg2=pid, arg3=target_addr, arg4=depth */
#define KPM_CMD_PTR_RESULT       0x1122  /* 获取指针结果：arg2=user_buf, arg3=max_count, arg4=offset */

/* ===== 调试/断点命令 ===== */
#define KPM_CMD_DEBUG_BP_SET      0x1130  /* 设置断点：arg2=pid, arg3=type, arg4=addr, arg5=size */
#define KPM_CMD_DEBUG_BP_CLEAR    0x1131  /* 清除断点：arg2=index */
#define KPM_CMD_DEBUG_BP_LIST     0x1132  /* 列出断点：arg2=user_buf, arg3=max_count */
#define KPM_CMD_DEBUG_BP_HIT      0x1133  /* 获取命中信息：arg2=user_buf */
#define KPM_CMD_DEBUG_SINGLE_STEP 0x1134  /* 单步：arg2=pid, arg3=tid */
#define KPM_CMD_DEBUG_CONTINUE    0x1135  /* 继续：arg2=pid, arg3=tid */
#define KPM_CMD_DEBUG_BP_NOTIFY   0x1136  /* 2026-08-06: 断点命中通知：arg2=1/0 启用/停用。
                                           * UDP 通道用 recvfrom 源地址作为通知目标；
                                           * prctl 通道用上次记录的地址（无源地址）。 */
/* ===== 2026-08-15：断点寄存器篡改命令 =====
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

/* ===== 进程枚举命令 ===== */
#define KPM_CMD_PROC_LIST         0x1145  /* 列出进程：arg2=user_buf, arg3=max_count, arg4=offset */
#define KPM_CMD_PROC_MAPS         0x1146  /* 获取进程内存映射：arg2=pid, arg3=user_buf, arg4=max_count */
#define KPM_CMD_PROC_QUERY_REGION 0x1147  /* 按地址查询单个区域：arg2=pid, arg3=addr, arg4=user_buf(kpm_map_entry_t*) */
#define KPM_CMD_READ_FILE         0x1148  /* 文件回退读取：data=完整路径, arg5=offset, 返回文件内容(<=16KB) */
#define KPM_CMD_PROC_FULLPATH     0x1149  /* VMA 完整路径：arg2=pid, arg3=addr, 返回完整路径字符串 */

/* ===== 2026-08-15：按名查询命令 =====
 * prctl 布局（转换模块经 raw_syscall5 调用）：
 *   PROC_PID_BY_NAME: arg2=进程名用户指针 → ret=pid（或负错误码）
 *   PROC_MODULE_BASE: arg2=pid, arg3=模块名用户指针 → ret=基址
 *   PROC_MODULE_BSS:  arg2=pid, arg3=模块名用户指针 → ret=BSS 地址
 * 仅 prctl 通道（名字经用户指针传；UDP 无 req_data 承载，返回 UNHANDLED）。 */
#define KPM_CMD_PROC_PID_BY_NAME  0x114A
#define KPM_CMD_PROC_MODULE_BASE  0x114B
#define KPM_CMD_PROC_MODULE_BSS   0x114C

/* ===== 内存转储命令（ELF 重建，用于 IDA/解包分析） =====
 * 队列语义：同一时间仅允许一个 dump 操作（busy 互斥）。
 * 协议化传输（3 阶段：BEGIN/FETCH/END，2026-08-04 起替代旧异步 START/
 * PROGRESS/CANCEL 方案；旧命令码 0x1150-52 已删除，不再保留）。
 * 纯内存读取（页表遍历，无 VFS 痕迹），数据分块经 UDP 回传，
 * 块级 CRC32 + 整体 SHA256 双重完整性校验。
 *   DUMP_BEGIN:  arg2=pid, data=模块名 → 返回 kpm_dump_hdr_t (128B)
 *   DUMP_FETCH:  arg2=offset → 返回 kpm_dump_chunk_t + data (≤15872B)
 *   DUMP_END:    结束会话 → 返回 kpm_dump_done_t (48B, 含整体 SHA256)
 *   DUMP_STREAM: arg2=file_off, arg3=len → 流式拉取（2026-08-06，零往返）
 */
#define KPM_CMD_DUMP_BEGIN    0x1153
#define KPM_CMD_DUMP_FETCH    0x1154
#define KPM_CMD_DUMP_END      0x1155

/* ===== 通用批量读（2026-08-05）=====
 * 一次请求读取多个任意地址（对象头/结构体分析用，避免逐条 UDP 往返）。
 * 请求 payload: [u32 count][u32 per_len] + count × u64 地址
 *    count   1..2048 条地址
 *    per_len 每条目字节数（2026-08-06 起任意 1..256，不再限 2 的幂）
 * 约束: count × per_len ≤ KPM_UDP_MAX_PAYLOAD(16384)
 * 响应 payload: count × per_len 字节（成功=真实数据；失败=全 0xFF）
 * 返回 ret = 成功读取的条目数。
 */
#define KPM_CMD_MEM_READ_BATCH   0x1160
#define KPM_READ_BATCH_MAX       2048    /* 单次最大地址数 */
#define KPM_READ_BATCH_LEN_MIN   1       /* 2026-08-06：放开为任意长度 */
#define KPM_READ_BATCH_LEN_MAX   256     /* 每条目最大字节数（原 64） */

/* ===== 变长批量读（2026-08-06 新增，高可扩展） =====
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

/* 2026-08-06: 读取虚拟地址的原始 PTE（zram swap 换出页解析）。
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

/* Dump 完成（48 字节，DUMP_END 响应） */
typedef struct {
    uint32_t magic;        /* KPM_DUMP_MAGIC_DONE */
    uint32_t status;       /* 0=成功 */
    uint64_t bytes;        /* 内核提供总字节 */
    uint8_t  sha256[32];   /* 内核侧整体 SHA256 */
    uint32_t missing;      /* 缺失页补零字节 */
    uint32_t flags;
} kpm_dump_done_t;         /* sizeof = 48 */

/* Dump 状态 */
#define KPM_DUMP_STATE_IDLE     0   /* 无任务 */
#define KPM_DUMP_STATE_RUNNING  1   /* 进行中 */
#define KPM_DUMP_STATE_DONE     2   /* 完成 */
#define KPM_DUMP_STATE_ERROR    3   /* 出错（err 为错误码） */
#define KPM_DUMP_STATE_CANCELED 4   /* 已取消 */

/* Dump 进度结构（160 字节，UDP resp_data 直接返回） */
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
} kpm_dump_progress_t;     /* sizeof = 160 */

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


#define KPM_CMD_HOOK_INSTALL      0x1140  /* 安装 hook：arg2=type, arg3=target_name(ptr), arg4=replace_addr */
#define KPM_CMD_HOOK_REMOVE       0x1141  /* 移除 hook：arg2=index */
#define KPM_CMD_HOOK_LIST         0x1142  /* 列出 hook：arg2=user_buf, arg3=max_count */
#define KPM_CMD_HOOK_TOGGLE       0x1143  /* 切换 hook：arg2=index, arg3=enable */
#define KPM_CMD_HOOK_PLT_SET      0x1144  /* PLT hook：arg2=pid, arg3=module_name(ptr), arg4=func_name(ptr), arg5=replace_addr */

#define KPM_CMD_HIDE_PROCESS     0x114D
#define KPM_CMD_RECOVER_PROCESS  0x114E
#define KPM_CMD_HIDE_LIST        0x114F
#define KPM_CMD_UN_HOOK          0x1156
#define KPM_CMD_HIDE_P1          0x1157  /* P1 兜底开关: arg2=0关/1开(缺省0关) → ret=当前开关 */

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

/* 进程条目（与用户态共享，536 字节）
 * name 容量 512 字节，容纳完整 cmdline（包名 + 参数） */
#define KPM_PROC_NAME_MAX 512
typedef struct {
    pid_t    pid;                             /* 进程 ID */
    pid_t    ppid;                            /* 父进程 ID */
    char     name[KPM_PROC_NAME_MAX];         /* 进程名（cmdline，完整包名） */
    uint64_t start_time;                      /* 进程启动时间（ns） */
    uint32_t state;                           /* 进程状态 */
    uint32_t mem_size_pages;                  /* 进程虚拟内存总大小（mm->total_vm，单位页，×4096=字节） */
} kpm_proc_entry_t;

/* 内存映射条目（与用户态共享，320 字节） */
#define KPM_MAP_PATH_MAX 256
typedef struct {
    uint64_t start;                           /* 起始地址 */
    uint64_t end;                             /* 结束地址 */
    uint64_t offset;                          /* 文件偏移 */
    uint8_t  perms;                           /* rwx 权限：bit0=r, bit1=w, bit2=x */
    uint8_t  reserved[7];                     /* 填充 */
    char     path[KPM_MAP_PATH_MAX];          /* 映射的文件路径（匿名映射则为空） */
} kpm_map_entry_t;

/* 错误码 */
#define KPM_E_INVAL        1
#define KPM_E_NOMEM        2
#define KPM_E_NOTFOUND     3
#define KPM_E_FAULT        4
#define KPM_E_PERM         5
#define KPM_E_BUSY         6

#endif /* _KPM_COMM_H_ */
```
