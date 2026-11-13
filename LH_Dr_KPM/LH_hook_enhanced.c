/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * kpm_hook_enhanced.c — PLT/GOT / inline / stealth hook 模块（禁用壳）
 *
 * 本文件保留为最小禁用壳：导出接口签名不变（命令分发/接线零改动），
 * 全部返回 -KPM_E_INVAL，不产生任何运行时行为。
 */
#include <ktypes.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <baselib.h>
#include "LH_comm.h"
#include "LH_hook_enhanced.h"
#include "LH_log.h"

/* Initialize hook module：空操作（保持 init 返回 0，调用方逻辑不变） */
long kpm_hook_enhanced_init(void)
{
    kpm_log("kpm: PLT/GOT/inline hook REMOVED (2026-08-07, disabled shell only)\n");
    return 0;
}

/* Exit hook module：空操作 */
void kpm_hook_enhanced_exit(void)
{
}

/* ===== 导出接口：全部返回 -KPM_E_INVAL ===== */

long kpm_hook_install(int type, const char *target_name, void *replace_addr)
{
    (void)type; (void)target_name; (void)replace_addr;
    return -KPM_E_INVAL;
}

long kpm_hook_remove(int index)
{
    (void)index;
    return -KPM_E_INVAL;
}

long kpm_hook_copy_list(kpm_hook_entry_t *user_buf, int max_count)
{
    (void)user_buf; (void)max_count;
    return -KPM_E_INVAL;
}

long kpm_hook_copy_list_kernel(kpm_hook_entry_t *kbuf, int max_count)
{
    (void)kbuf; (void)max_count;
    return -KPM_E_INVAL;
}

long kpm_hook_toggle(int index, int enable)
{
    (void)index; (void)enable;
    return -KPM_E_INVAL;
}

long kpm_hook_plt_set(pid_t pid, const char *module_name,
                      const char *func_name, void *replace_addr)
{
    (void)pid; (void)module_name; (void)func_name; (void)replace_addr;
    return -KPM_E_INVAL;
}

long kpm_hook_plt_set_kernel(pid_t pid, const char *module_name,
                             const char *func_name, void *replace_addr)
{
    (void)pid; (void)module_name; (void)func_name; (void)replace_addr;
    return -KPM_E_INVAL;
}
