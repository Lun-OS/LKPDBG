/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_netctl.c - 进程禁止联网实现
 *
 * hook 生命周期：FEAT_ENABLE(NETCTL) → kpm_netctl_init 安装 9 个网络
 * syscall 的 fp 链 hook；FEAT_DISABLE/卸载 → 排空在途回调后摘除。
 * before 回调热路径：kpm_filter_hit()（未匹配 ≈ 十几 ns）→ 直接放行；
 * 匹配 → ret=-errno + skip_origin=1（原 syscall 不执行）。
 * 隐蔽性：热路径无日志、无分配、无锁；规则最终一致（管理操作粒度）。
 */
#include <compiler.h>
#include <kpmodule.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <hook.h>
#include <linux/string.h>
#include <ksyms.h>
#include <baselib.h>
#include "LH_comm.h"
#include "LH_netctl.h"
#include "LH_filter.h"
#include "LH_syms.h"
#include "LH_utils.h"
#include "LH_log.h"

#ifndef ENETUNREACH
#define ENETUNREACH 114
#endif
#ifndef EACCES
#define EACCES 13
#endif
#ifndef EPERM
#define EPERM 1
#endif

/* 拦截集合（arm64）：建联/收发全拦，已建连接实效中断 */
static const int k_net_nr[] = {
    __NR_socket,   /* 198 */
    __NR_bind,     /* 200 */
    __NR_connect,  /* 203 */
    __NR_sendto,   /* 206 */
    __NR_recvfrom, /* 207 */
    __NR_sendmsg,  /* 211 */
    __NR_recvmsg,  /* 212 */
    __NR_sendmmsg, /* 269 */
    __NR_recvmmsg, /* 270 */
};
#define KPM_NETCTL_NR_COUNT ((int)(sizeof(k_net_nr) / sizeof(k_net_nr[0])))

static volatile int g_net_installed = 0;
static volatile int g_net_enabled = 0;
static volatile int g_net_errno_mode = KPM_NETCTL_ERRNO_UNREACH;
static volatile int g_net_inflight = 0;      /* 在途回调计数（排空用） */

static long net_errno_from_mode(void)
{
    switch (g_net_errno_mode) {
    case KPM_NETCTL_ERRNO_EACCES: return -EACCES;
    case KPM_NETCTL_ERRNO_EPERM:  return -EPERM;
    case KPM_NETCTL_ERRNO_UNREACH:
    default:                      return -ENETUNREACH;
    }
}

/* before 回调（全部网络 syscall 共用）：命中过滤器 → 伪造返回。
 * 热路径约束：无锁/无分配/无日志；过滤未命中立即返回。
 * fargs 布局（hook.h）：{chain, skip_origin, local, ret, args[]}。 */
static void kpm_netctl_before(void *fargs, void *udata)
{
    hook_fargs4_t *fa = (hook_fargs4_t *)fargs;

    (void)udata;
    asm volatile("" ::: "memory");
    g_net_inflight++;

    if (g_net_enabled && kpm_filter_hit()) {
        fa->ret = (uint64_t)net_errno_from_mode();
        fa->skip_origin = 1;   /* 原 syscall 不执行 */
    }

    g_net_inflight--;
}

long kpm_netctl_init(void)
{
    int i, installed = 0;

    /* 共享 filter 的使用者登记（不清规则：sysmon 可能已在用） */
    kpm_filter_user_register(KPM_FILTER_USER_NETCTL);

    for (i = 0; i < KPM_NETCTL_NR_COUNT; i++) {
        int err = (int)fp_hook_syscalln(k_net_nr[i], 6,
                                        kpm_netctl_before, 0, 0);
        if (err != HOOK_NO_ERR) {
            kpm_log("netctl: hook nr=%d failed (%d)\n", k_net_nr[i], err);
            /* 已装的部分回滚（部分可用不如整体一致） */
            for (--i; i >= 0; i--)
                fp_unhook_syscalln(k_net_nr[i], kpm_netctl_before, 0);
            kpm_filter_user_unregister(KPM_FILTER_USER_NETCTL);
            return -KPM_E_FAULT;
        }
        installed++;
    }
    g_net_installed = 1;
    kpm_log("netctl: %d network syscalls hooked\n", installed);
    return 0;
}

void kpm_netctl_exit(void)
{
    int i;
    if (!g_net_installed)
        return;
    g_net_enabled = 0;
    /* 排空在途回调（有界非睡眠自旋——兼容 RCU 临界区卸载） */
    {
        unsigned long spins = 0;
        while (g_net_inflight > 0 && spins++ < 200000000UL)
            asm volatile("yield" ::: "memory");
    }
    for (i = 0; i < KPM_NETCTL_NR_COUNT; i++)
        fp_unhook_syscalln(k_net_nr[i], kpm_netctl_before, 0);
    g_net_installed = 0;
    kpm_filter_request_on(KPM_FILTER_USER_NETCTL, 0);
    kpm_filter_user_unregister(KPM_FILTER_USER_NETCTL);
    kpm_log("netctl: unhooked\n");
}

long kpm_netctl_rule(int op, int type, uint64_t value)
{
    if (!g_net_installed)
        return -KPM_E_DISABLED;
    switch (op) {
    case 0: /* add */
        if (type == 0)
            return kpm_filter_uid_add(value);
        if (type == 1)
            return kpm_filter_pid_add(value);
        if (type == 2) {
            kpm_filter_set_all_apps(1);
            return 0;
        }
        return -KPM_E_INVAL;
    case 1: /* del */
        if (type == 0)
            return kpm_filter_uid_del(value);
        if (type == 1)
            return kpm_filter_pid_del(value);
        if (type == 2) {
            kpm_filter_set_all_apps(0);
            return 0;
        }
        return -KPM_E_INVAL;
    case 2: /* clear */
        return kpm_filter_clear();
    default:
        return -KPM_E_INVAL;
    }
}

long kpm_netctl_set(int enable, int errno_mode)
{
    if (!g_net_installed)
        return -KPM_E_DISABLED;
    if (enable != 0 && enable != 1)
        return -KPM_E_INVAL;
    if (errno_mode < KPM_NETCTL_ERRNO_UNREACH ||
        errno_mode > KPM_NETCTL_ERRNO_EPERM)
        return -KPM_E_INVAL;
    g_net_errno_mode = errno_mode;
    g_net_enabled = enable ? 1 : 0;
    /* 按使用者请求总开关：sysmon 同时开启时不会被本单元关掉 */
    kpm_filter_request_on(KPM_FILTER_USER_NETCTL, enable);
    kpm_log("netctl: %s (errno_mode=%d)\n",
            enable ? "enabled" : "disabled", errno_mode);
    return 0;
}

long kpm_netctl_list_kernel(void *kbuf, int max_count)
{
    kpm_netctl_info_t info;

    if (!kbuf)
        return -KPM_E_INVAL;
    lib_memset(&info, 0, sizeof(info));
    info.enabled = (uint32_t)(g_net_enabled && g_net_installed);
    info.errno_mode = (uint32_t)g_net_errno_mode;
    kpm_filter_counts(&info.uid_count, &info.pid_count, (int *)&info.all_apps);
    kpm_filter_pids_copy(info.pids, KPM_NETCTL_PID_MAX);
    (void)max_count;
    lib_memcpy(kbuf, &info, sizeof(info));
    return 0;
}

long kpm_netctl_list(void *user_buf, int max_count)
{
    kpm_netctl_info_t info;
    long ret;

    if (!user_buf)
        return -KPM_E_INVAL;
    ret = kpm_netctl_list_kernel(&info, max_count);
    if (ret == 0) {
        if (!kf_copy_to_user ||
            kf_copy_to_user(user_buf, &info, sizeof(info)))
            return -KPM_E_FAULT;
    }
    return ret;
}
