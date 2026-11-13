/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_HOOK_ENHANCED_H_
#define _KPM_HOOK_ENHANCED_H_

#include <ktypes.h>
#include <stdint.h>

/* ===== Enhanced Hook System =====
 * Unified hook management: inline hook, traceless hook (page remap), PLT hook.
 * Builds on the low-trace inline hook from kpm_stealth.c.
 */

#define KPM_HOOK_MAX_ENTRIES 32
#define KPM_HOOK_TARGET_NAME_MAX 64

/* Hook types */
#define KPM_HOOK_TYPE_INLINE    0   /* inline hook (BR X16, 5 insns) */
#define KPM_HOOK_TYPE_STEALTH   1   /* traceless hook (page remap) */
#define KPM_HOOK_TYPE_PLT       2   /* PLT/GOT hook (user-space process) */

/* A single hook entry */
typedef struct {
    int      enabled;
    int      type;           /* KPM_HOOK_TYPE_* */
    void    *target_addr;    /* target function address */
    void    *replacement;    /* replacement function address */
    void    *trampoline;     /* trampoline (for inline hook) */
    char     target_name[KPM_HOOK_TARGET_NAME_MAX]; /* target function name */
    uint64_t orig_insns[8];  /* saved original instructions (inline) */
    int      hit_count;
    pid_t    pid;            /* target PID (for PLT hook) */
} kpm_hook_entry_t;

/* Initialize hook module */
long kpm_hook_enhanced_init(void);

/* Exit hook module (remove all hooks) */
void kpm_hook_enhanced_exit(void);

/* Install a hook.
 * type: KPM_HOOK_TYPE_*
 * target_name: name of the target function (for kernel symbol lookup)
 * replace_addr: address of the replacement function
 * Returns hook index >= 0, or negative on error */
long kpm_hook_install(int type, const char *target_name, void *replace_addr);

/* Remove a hook by index.
 * Returns 0 on success, negative on error */
long kpm_hook_remove(int index);

/* Copy hook list to user buffer.
 * Returns number of entries, or negative on error */
long kpm_hook_copy_list(kpm_hook_entry_t *user_buf, int max_count);

/* 拷贝 hook 列表到内核缓冲（UDP 通道 resp_data 用，lib_memcpy）。
 * 与 kpm_hook_copy_list 的区别：不走 copy_to_user，供内核态调用方使用。 */
long kpm_hook_copy_list_kernel(kpm_hook_entry_t *kbuf, int max_count);

/* Toggle a hook on/off.
 * Returns 0 on success, negative on error */
long kpm_hook_toggle(int index, int enable);

/* Install a PLT hook (user-space process).
 * pid: target process PID
 * module_name: module/so name containing the function
 * func_name: function name to hook
 * replace_addr: replacement function address in the target process
 * Returns hook index >= 0, or negative on error */
long kpm_hook_plt_set(pid_t pid, const char *module_name,
                      const char *func_name, void *replace_addr);

/* 内核指针版 PLT hook（UDP 通道 payload 字符串用）。
 * module_name/func_name 为内核空间已 NUL 终止的字符串（不走 copy_from_user）。
 * 其余语义与 kpm_hook_plt_set 一致。 */
long kpm_hook_plt_set_kernel(pid_t pid, const char *module_name,
                             const char *func_name, void *replace_addr);

#endif /* _KPM_HOOK_ENHANCED_H_ */