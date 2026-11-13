/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_HIDE_H_
#define _KPM_HIDE_H_

#include <ktypes.h>
#include "LH_comm.h"

/* ===== 进程隐藏 / 反检测子模块 =====
 * HIDE_PROCESS / RECOVER_PROCESS / HIDE_LIST / UN_HOOK 命令的执行层。
 *
 * P0 摘除域为"整个线程组（组长 + 全部线程 tid）"。恢复以**原 struct pid
 * 指针**回填（不重算 nr，保证 stat 字段 == 目录名）；成员超限整槽拒绝、
 * 遍历基础设施缺失退化 leader-only 并 state=LIMITED 如实降级，绝不半隐藏。
 *
 * 回退链机制（P0 优先 / P1 按需 / P2 如实降级）：
 *   P0：从目标 pid 所在 pid namespace 登记表摘除**线程组全部成员**条目
 *       （5.0+ = struct pid_namespace.idr，主流内核首成员偏移 0；运行时
 *       pid1 双向自检门控，失败即禁用，绝不猜布局）——/proc 枚举、
 *       直连 /proc/<pid|tid>、按 pid/tid kill（kill/tkill/tgkill）均失效。
 *   P1：框架 hook(proc_pid_lookup, stub, &backup)，stub 对隐藏表命中
 *       返回 NULL（/proc/<pid> 直连 ENOENT），其余走 trampoline 保真；
 *       生命周期=隐藏窗口：RECOVER 清空生效记录即 unhook + inflight
 *       排空，零残留。默认关闭（g_hide_p1=0），仅客户端显式启用才安装。
 *       stub 全程无睡眠（锁内不睡眠、不调可睡眠路径）。
 *   P2：P1 符号缺失/安装失败 → 记录 state=KPM_HIDE_STATE_LIMITED（仅枚举级，
 *       直连仍可能可达），HIDE_LIST 如实明示，不静默。
 * 详见 LH_comm.h 中 0x114D/0x114E/0x114F/0x1156 命令注释。
 */

/* 初始化（惰性：首次隐藏命令时才解析符号并自检，失败返回负错误码） */
long kpm_hide_init(void);

/* 退出（模块卸载前自动恢复全部隐藏进程；conflict 记录保留说明日志） */
void kpm_hide_exit(void);

/* HIDE_PROCESS 执行层：隐藏 pid 对应进程。
 * 返回隐藏槽位 1..KPM_HIDE_MAX；重复隐藏返回既有槽位（幂等）。
 * 负值 = 错误（-KPM_E_*）。 */
long kpm_hide_process(pid_t pid);

/* RECOVER_PROCESS 执行层：pid<=0 恢复全部，否则恢复该 pid。
 * 返回恢复条数；未隐藏返回 0；pid 号被占用无法恢复返回 -KPM_E_BUSY
 * （该条记录转 conflict 状态，可经 HIDE_LIST 查询）。 */
long kpm_hide_recover(pid_t pid);

/* HIDE_LIST 执行层：把隐藏记录数组拷到内核缓冲 entries。
 * 返回记录条数（含空/历史记录，客户端按 state 过滤）。 */
long kpm_hide_list(kpm_hide_entry_t *entries, int max_count);

/* UN_HOOK 执行层：按掩码下线驱动自身用户态可见 hook（单向"收尾"）。
 * mask 位见 KPM_UNHOOK_*（0=全部）。返回实际下线的 hook 类数。
 * 注：KPM_UNHOOK_PRCTL 仅允许在非 prctl 上下文调用（UDP 通道），
 * prctl 通道请求返回 -KPM_E_BUSY（防在回调内自卸导致的死锁）。 */
long kpm_hide_unhook(unsigned long mask, int from_prctl);

/* P1 兜底开关（KPM_CMD_HIDE_P1 执行层）：
 * enable=0 关闭（默认，纯 P0 稳定语义；若 stub 已装立即拆除）
 * enable=1 启用（下一 HIDE 起安装 proc_pid_lookup stub，覆盖 /proc 直连）
 * enable<0 仅查询。返回当前开关。⚠ 启用有内核稳定性风险，
 * 请在目标内核先行验证。 */
long kpm_hide_p1_set(int enable);

#endif /* _KPM_HIDE_H_ */
