/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <ktypes.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <baselib.h>
#include "LH_comm.h"
#include "LH_mem_freeze.h"
#include "LH_syms.h"
#include "LH_mem_rw.h"
#include "LH_log.h"
#include "LH_utils.h"  /* kpm_spinlock_t 等 */

/* Freeze entries array (vmalloc'd) */
static kpm_freeze_entry_t *g_entries = NULL;
static int g_entry_count = 0;

/* ===== 会话互斥 =====
 * busy 标志模式：
 *   - 锁内仅做 busy 检查/置位；
 *   - freeze_tick 与 freeze_add/remove/toggle/clear/copy_list 互斥，
 *     防止 tick 遍历 g_entries 时被 clear 的 memset 打断。
 */
static kpm_spinlock_t g_freeze_lock = KPM_SPINLOCK_INIT;
static volatile int g_freeze_busy = 0;

static int freeze_enter(void)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_freeze_lock);
    if (g_freeze_busy) {
        kpm_spin_unlock_irqrestore(&g_freeze_lock, flags);
        return -1;
    }
    g_freeze_busy = 1;
    kpm_spin_unlock_irqrestore(&g_freeze_lock, flags);
    return 0;
}

static void freeze_leave(void)
{
    unsigned long flags = kpm_spin_lock_irqsave(&g_freeze_lock);
    g_freeze_busy = 0;
    kpm_spin_unlock_irqrestore(&g_freeze_lock, flags);
}

long kpm_mem_freeze_init(void)
{
    g_entries = kf_vmalloc(KPM_FREEZE_MAX_ENTRIES * sizeof(kpm_freeze_entry_t));
    if (!g_entries)
        return -KPM_E_NOMEM;

    lib_memset(g_entries, 0, KPM_FREEZE_MAX_ENTRIES * sizeof(kpm_freeze_entry_t));
    g_entry_count = 0;
    g_freeze_busy = 0;   /* 锁静态初始化，busy 复位 */
    return 0;
}

void kpm_mem_freeze_exit(void)
{
    kpm_mem_freeze_clear();
    if (g_entries) {
        kf_vfree(g_entries);
        g_entries = NULL;
    }
}

/* Perform a freeze tick: write all enabled entries.
 * This is called from kpm_udp_recv_work periodically. */
void kpm_mem_freeze_tick(void)
{
    int i;
    int limit;

    if (!g_entries)
        return;

    /* 会话互斥：与 freeze_add/remove/clear 互斥，防止遍历中条目被清除 */
    if (freeze_enter() < 0)
        return;

    /* g_entry_count 是最大已用索引+1，所有 enabled 项必在此范围内；
     * 用它限制遍历上界，避免扫描空槽位。 */
    limit = g_entry_count;
    if (limit > KPM_FREEZE_MAX_ENTRIES)
        limit = KPM_FREEZE_MAX_ENTRIES;

    for (i = 0; i < limit; i++) {
        if (!g_entries[i].enabled)
            continue;

        /* 源地址 &g_entries[i].value 是内核地址，须用
         * kpm_mem_write_kernel（内核到内核，无 access_ok 校验）；
         * 走 copy_from_user 的接口会对内核地址做 access_ok 校验而失败。 */
        kpm_mem_write_kernel(g_entries[i].pid, g_entries[i].addr,
                             (const void *)&g_entries[i].value,
                             g_entries[i].size);
        g_entries[i].hit_count++;
    }

    freeze_leave();
}

long kpm_mem_freeze_add(pid_t pid, uint64_t addr, uint64_t value, int size)
{
    int idx;
    long ret;

    if (!g_entries)
        return -KPM_E_NOMEM;

    if (freeze_enter() < 0)
        return -KPM_E_BUSY;

    /* Validate size */
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        freeze_leave();
        return -KPM_E_INVAL;
    }

    /* Find empty slot */
    for (idx = 0; idx < KPM_FREEZE_MAX_ENTRIES; idx++) {
        if (!g_entries[idx].enabled)
            break;
    }
    if (idx >= KPM_FREEZE_MAX_ENTRIES) {
        freeze_leave();
        return -KPM_E_NOMEM;
    }

    g_entries[idx].enabled = 1;
    g_entries[idx].pid = pid;
    g_entries[idx].addr = addr;
    g_entries[idx].value = value;
    g_entries[idx].size = size;
    g_entries[idx].hit_count = 0;

    if (idx >= g_entry_count)
        g_entry_count = idx + 1;

    /* Immediately write the value. */
    ret = kpm_mem_write_kernel(pid, addr, (const void *)&value, size);
    if (ret < 0) {
        /* 写入失败：回滚条目，避免残留无效冻结项 */
        lib_memset(&g_entries[idx], 0, sizeof(kpm_freeze_entry_t));
        if (g_entry_count == idx + 1)
            g_entry_count = idx;
        freeze_leave();
        kpm_log("freeze: add write failed pid=%d addr=0x%llx ret=%ld\n",
                pid, addr, ret);
        return -KPM_E_FAULT;
    }

    freeze_leave();
    kpm_log("freeze: added entry %d (pid=%d, addr=0x%llx, val=0x%llx, sz=%d)\n",
            idx, pid, addr, value, size);
    return idx;
}

long kpm_mem_freeze_remove(int index)
{
    long ret = 0;

    if (!g_entries)
        return -KPM_E_NOMEM;

    if (freeze_enter() < 0)
        return -KPM_E_BUSY;

    if (index < 0 || index >= KPM_FREEZE_MAX_ENTRIES) {
        ret = -KPM_E_INVAL;
        goto out;
    }
    if (!g_entries[index].enabled) {
        ret = -KPM_E_NOTFOUND;
        goto out;
    }

    lib_memset(&g_entries[index], 0, sizeof(kpm_freeze_entry_t));
    /* 收缩 g_entry_count（可选，保持 tick 高效） */
    if (index == g_entry_count - 1)
        g_entry_count--;

out:
    freeze_leave();
    return ret;
}

long kpm_mem_freeze_copy_list(kpm_freeze_entry_t *user_buf, int max_count)
{
    int to_copy = KPM_FREEZE_MAX_ENTRIES;
    long ret;

    if (!user_buf || max_count <= 0)
        return -KPM_E_INVAL;
    if (to_copy > max_count)
        to_copy = max_count;

    if (!g_entries)
        return -KPM_E_NOMEM;

    if (freeze_enter() < 0)
        return -KPM_E_BUSY;

    ret = 0;
    if (kf_copy_to_user(user_buf, g_entries, to_copy * sizeof(kpm_freeze_entry_t)))
        ret = -KPM_E_FAULT;
    else
        ret = to_copy;

    freeze_leave();
    return ret;
}

/* UDP 通道传入 resp_data（内核空间），copy_to_user 失败。
 * 此函数使用 lib_memcpy，仅供内核态调用方使用（如 UDP 处理）。 */
long kpm_mem_freeze_copy_list_kernel(kpm_freeze_entry_t *kbuf, int max_count)
{
    int to_copy = KPM_FREEZE_MAX_ENTRIES;
    long ret;

    if (!kbuf || max_count <= 0)
        return -KPM_E_INVAL;
    if (to_copy > max_count)
        to_copy = max_count;

    if (!g_entries)
        return -KPM_E_NOMEM;

    if (freeze_enter() < 0)
        return -KPM_E_BUSY;

    /* 用 g_entry_count 限制遍历范围，避免拷贝大量空槽位 */
    if (to_copy > g_entry_count)
        to_copy = g_entry_count;

    lib_memcpy(kbuf, g_entries, (size_t)to_copy * sizeof(kpm_freeze_entry_t));
    ret = to_copy;

    freeze_leave();
    return ret;
}

long kpm_mem_freeze_toggle(int index, int enable)
{
    long ret = 0;

    if (!g_entries)
        return -KPM_E_NOMEM;

    if (freeze_enter() < 0)
        return -KPM_E_BUSY;

    if (index < 0 || index >= KPM_FREEZE_MAX_ENTRIES) {
        ret = -KPM_E_INVAL;
        goto out;
    }

    g_entries[index].enabled = enable ? 1 : 0;

out:
    freeze_leave();
    return ret;
}

long kpm_mem_freeze_clear(void)
{
    int i;
    long ret = 0;

    if (!g_entries)
        return -KPM_E_NOMEM;

    if (freeze_enter() < 0)
        return -KPM_E_BUSY;

    for (i = 0; i < KPM_FREEZE_MAX_ENTRIES; i++)
        lib_memset(&g_entries[i], 0, sizeof(kpm_freeze_entry_t));

    g_entry_count = 0;

    freeze_leave();
    return ret;
}