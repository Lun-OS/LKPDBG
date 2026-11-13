/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_proc.c - Process enumeration and memory map reading
 *
 * Process list: traverses kernel task_struct list (via task_struct_offset
 *                from KernelPatch framework). Only visits existing processes,
 *                avoiding PID space scanning overhead. Falls back to PID
 *                iteration when tasklist symbols are unavailable.
 * Memory maps:  reads /proc/<pid>/maps via kernel file ops (filp_open +
 *                kernel_read). Done entirely in kernel context — no userspace
 *                process sees these file operations.
 *
 * Stealth: all operations use kpm_log (internal buffer), no dmesg/printk.
 *          No new kernel symbols exposed. No /proc entries modified.
 */
#include <ktypes.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <baselib.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/list.h>

#include "LH_comm.h"
#include "LH_proc.h"
#include "LH_syms.h"
#include "LH_log.h"
#include "LH_mem_rw.h"  /* kpm_mem_read_kernel */
#include "LH_utils.h"   /* kpm_udelay_range（VMA 瞬态失败重试等待） */

/* PID iteration limit —— 运行时读内核 pid_max（见 LH_syms.h: kpm_pid_max()）。 */

/* KPM_NEXT_TASK 宏已移至 kpm_syms.h（kpm_probe_arg_offsets 也需使用） */

/* 判断 task 是否为内核线程（mm == NULL）
 * 使用运行时探测的 g_mm_offset，返回 1=内核线程, 0=用户进程, -1=无法判断 */
static inline int kpm_is_kernel_thread(struct task_struct *task)
{
    uint64_t mm_val = 0;
    if (g_mm_offset == 0 || !kf_copy_from_kernel_nofault)
        return -1;
    if (kf_copy_from_kernel_nofault(&mm_val,
            (void *)((unsigned long)task + g_mm_offset), 8) != 0)
        return -1;
    return (mm_val == 0) ? 1 : 0;
}

/* Buffer for reading /proc/pid/maps (should be large enough for typical maps) */
#define KPM_MAPS_BUF_SIZE 65536

/* GFP_KERNEL：这些调用点都在任何锁之前完成，且后续 filp_open/kernel_read
 * 是可睡眠操作，故用 GFP_KERNEL。不带 gfp 标志（flags=0）时分配器不回收/压缩，
 * 本文件 16~64KB（order 2~4）高阶请求易失败。源文件不含框架 gfp 头
 * （与 LH_mem_rw.c / LH_udp.c 同款处理，手动定义）。 */
#ifndef GFP_KERNEL
#define GFP_KERNEL 0xcc0u
#endif
/* /proc/maps 回退路径大缓冲（vmalloc）：2MB 足以装下全部 maps
 * （VMA 数极端场景可再调大）。 */
#define KPM_MAPS_BUF_LARGE (2 * 1024 * 1024)

/* Buffer for reading /proc/pid/cmdline (256 bytes = KPM_PROC_NAME_MAX) */
#define KPM_CMDLINE_BUF_SIZE 256

long kpm_proc_init(void)
{
    kpm_log("proc: init\n");
    return 0;
}

void kpm_proc_exit(void)
{
    kpm_log("proc: exit\n");
}

/* kpm_read_file - 内核态读取文件内容（cmdline/maps 等 procfs seq_file）
 *
 * 5.10+ 的 kernel_read() 内部已用 iov_iter_kvec() 自构造 ITER_KVEC 并调用
 * f_op->read_iter()，原生支持 procfs seq_file，无需手工构造 iov_iter；
 * 直接用 kernel_read 即可，5.10+/6.1 全版本安全。
 */
ssize_t kpm_read_file(struct file *fp, void *buf, size_t count, loff_t *pos)
{
    ssize_t nread = -1;

    if (kf_kernel_read)
        nread = kf_kernel_read(fp, buf, count, pos);

    return nread;
}

/*
 * read_process_cmdline - 读取 /proc/<pid>/cmdline 获取完整进程名
 * 返回读取的字节数，失败返回 -1
 * Android 应用的 cmdline 包含完整包名（如 "com.android.chrome"），
 * 不会被 task_struct->comm 的 16 字节限制截断。
 *
 * 注意：此函数仅供 kpm_probe_arg_offsets 探测偏移时使用（一次性）。
 * 探测成功后，kpm_proc_list_kernel 走纯内存路径（kpm_mem_read_kernel
 * 直接读 arg_start~arg_end），不再调用此函数。
 */
int read_process_cmdline(pid_t pid, char *buf, int buf_size)
{
    char path[64];
    struct file *fp = 0;
    loff_t pos = 0;
    ssize_t nread;
    int len = 0;

    /* 安全检查: 确保 kf_snprintf 和 kf_filp_open 可用，否则无法读取 cmdline */
    if (!kf_snprintf || !kf_filp_open || !kf_filp_close)
        return -1;

    kf_snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    fp = kf_filp_open(path, 0 /* O_RDONLY */, 0);
    /* 使用 IS_ERR_OR_NULL 正确检查 filp_open 返回值（与 kpm_mem_scan.c 一致）。
     * 旧代码手工 fp < 0xFFFF000000000000 判断在 ARM64 VA_BITS=48 上可能误判
     * 合法内核指针，导致 cmdline 读取失败、回退到 16 字节的 get_task_comm。 */
    if (IS_ERR_OR_NULL(fp))
        return -1;

    nread = kpm_read_file(fp, buf, buf_size - 1, &pos);
    kf_filp_close(fp, 0);

    if (nread <= 0)
        return -1;

    /* cmdline 使用 \0 分隔参数，替换首个 \0 为空格以便显示 */
    buf[nread] = '\0';
    len = 0;
    while (len < nread && buf[len] != '\0')
        len++;

    /* 如果首个参数后还有更多参数，用空格替换第一个 \0 */
    if (len < nread - 1) {
        buf[len] = ' ';
        /* 再找下一个 \0 截断（只取前两个参数，避免过长） */
        len++;
        while (len < nread && buf[len] != '\0')
            len++;
        buf[len] = '\0';
    }

    return len;
}

long kpm_proc_list(kpm_proc_entry_t *user_buf, int max_count, int offset)
{
    kpm_proc_entry_t *stack_buf = 0;
    int count = 0;
    int skipped = 0;
    long ret = 0;
    int use_rcu = 0;

    if (!user_buf || max_count <= 0 || max_count > 1024)
        return -KPM_E_INVAL;

    /* 分配内核缓冲区（必须在任何锁之前完成，mmap_read_lock/RCU 持锁期禁止睡眠 */
    stack_buf = (kpm_proc_entry_t *)kf_kmalloc(
        max_count * sizeof(kpm_proc_entry_t), GFP_KERNEL);
    if (!stack_buf)
        return -KPM_E_NOMEM;
    lib_memset(stack_buf, 0, max_count * sizeof(kpm_proc_entry_t));

    /* ===== 主路径：RCU 任务链表遍历（性能最优，约 3-5ms / 500 进程） =====
     * 条件：g_tasks_offset > 0 且 g_mm_offset > 0（运行时探测成功）
     * 优势：仅遍历实际存在的进程（约 500 个），无需 32768 次 PID 扫描
     *       RCU 读锁不增加引用计数，无 get_task_mm 副作用
     *       内核线程通过 mm == NULL 过滤（NOT tgid <= 0，内核线程有合法正 PID） */
    if (g_tasks_offset > 0 && g_mm_offset > 0 && kf_init_task &&
        kf_get_task_comm &&
        kf_copy_from_kernel_nofault && g_pid_offset > 0) {
        use_rcu = 1;
    }

    if (use_rcu) {
        struct task_struct *task, *first;
        int iter_count = 0;
        const int MAX_ITER = 65536;  /* 安全上限，防止链表环路死循环 */

        KPM_RCU_READ_LOCK();
        first = KPM_NEXT_TASK(kf_init_task);
        task = first;
        if (!first) { KPM_RCU_READ_UNLOCK(); goto rcu_done_1; }

        do {
            int is_kthread;
            pid_t pid;

            /* 安全限制：防止链表损坏导致死循环 */
            if (++iter_count > MAX_ITER)
                break;

            /* 读取 PID（使用探测的 g_pid_offset） */
            if (kf_copy_from_kernel_nofault(&pid,
                    (void *)((unsigned long)task + g_pid_offset), 4) != 0)
                goto next_task;

            /* PID 合法性检查（上限用运行时内核 pid_max，非硬编码） */
            if (pid <= 0 || pid > kpm_pid_max())
                goto next_task;

            /* 内核线程过滤：mm == NULL 即内核线程（kthreadd、kworker 等有合法正 PID） */
            is_kthread = kpm_is_kernel_thread(task);
            if (is_kthread == 1)
                goto next_task;

            /* 跳过 offset 前的条目 */
            if (skipped < offset) {
                skipped++;
                goto next_task;
            }

            /* 填充条目 */
            stack_buf[count].pid = pid;
            stack_buf[count].ppid = 0;
            stack_buf[count].state = 0;
            stack_buf[count].start_time = 0;

            /* 读取进程名（get_task_comm 在 RCU 锁下安全，仅读 task->comm）
             * 防御性校验：task 指针必须在内核地址范围，防止 kpm_next_task
             * 返回的指针虽然非 NULL 但实际无效导致 kf_get_task_comm 内部
             * 直接解引用引发 translation fault */
            if ((uint64_t)task < 0xFFFF000000000000ULL)
                goto next_task;
            kf_get_task_comm(stack_buf[count].name, KPM_PROC_NAME_MAX, task);
            stack_buf[count].name[KPM_PROC_NAME_MAX - 1] = '\0';

            count++;
            if (count >= max_count)
                break;

        next_task:
            task = KPM_NEXT_TASK(task);
        } while (task && task != first && task != kf_init_task);

        KPM_RCU_READ_UNLOCK();
rcu_done_1:
        kpm_log("proc: RCU traversal: %d processes (skipped %d)\n", count, skipped);
        if (count > 0) {
            /* RCU 遍历成功，直接进入拷贝阶段 */
            goto proc_list_copy;
        }
        /* RCU 遍历返回 0（偏移探测失效或链表读取失败）时回退 PID 扫描，
         * 否则 prctl 通道 ps 恒为空。 */
        kpm_log("proc: RCU traversal empty, falling back to PID scan\n");
    }

    {
        /* ===== PID 扫描（RCU 不可用或遍历为空时的回退路径） =====
         * 性能：pid_max 次 find_vpid + 约 500 个存在进程 × get_task_comm。
         * 走 kpm_task_acquire —— 免引用优先（RCU+find_vpid+pid_task，零引用计数），
         * 只有免引用不可用时才回退取引用路径；本路径不依赖 put_task_struct /
         * usage 偏移，只要 pid_task 在 kallsyms 里就能枚举进程。
         * 本循环体内只有 copy_from_kernel_nofault / get_task_comm（均为不睡眠原语），
         * 故可安全处于 RCU 读临界区。 */
        if (!kpm_task_fetch_available()) {
            kpm_log("proc: FATAL no task-fetch path: noref=%d put_task=%d "
                    "(find_get_pid=%llx get_pid_task=%llx put_pid=%llx)\n",
                    kpm_task_noref_available(), kpm_put_task_available(),
                    (uint64_t)kf_find_get_pid, (uint64_t)kf_get_pid_task,
                    (uint64_t)kf_put_pid);
            ret = -KPM_E_NOTFOUND;
            kf_kfree(stack_buf);
            return ret;
        }

        kpm_log("proc: using PID scan (pid_max=%d tasks_offset=%d mm_offset=%d)\n",
                kpm_pid_max(), g_tasks_offset, g_mm_offset);

        {
            pid_t pid;
            for (pid = 1; pid < kpm_pid_max() && count < max_count; pid++) {
                struct task_struct *task;
                int needs_put = 0;
                int is_kthread;
                pid_t tgid = 0;

                if (kpm_task_acquire(pid, &task, &needs_put) != 0)
                    continue;

                /* 过滤内核线程（mm == NULL）——与 kpm_proc_list_kernel 一致，
                 * 否则 kthreadd/kworker 等全部计入 */
                is_kthread = kpm_is_kernel_thread(task);
                if (is_kthread == 1) {
                    if (needs_put) kpm_put_task_struct(task); else kpm_task_end();
                    continue;
                }

                /* 过滤用户态线程：仅保留进程 leader（pid == tgid） */
                if (g_tgid_offset > 0) {
                    if (kf_copy_from_kernel_nofault(&tgid,
                            (void *)((unsigned long)task + g_tgid_offset), 4) != 0 ||
                        tgid != pid) {
                        if (needs_put) kpm_put_task_struct(task); else kpm_task_end();
                        continue;
                    }
                }

                /* Skip offset entries */
                if (skipped < offset) {
                    skipped++;
                    if (needs_put) kpm_put_task_struct(task); else kpm_task_end();
                    continue;
                }

                /* Fill entry */
                stack_buf[count].pid = pid;
                stack_buf[count].ppid = 0;
                stack_buf[count].state = 0;
                stack_buf[count].start_time = 0;

                if (kf_get_task_comm) {
                    kf_get_task_comm(stack_buf[count].name, KPM_PROC_NAME_MAX, task);
                } else {
                    stack_buf[count].name[0] = '\0';
                }
                stack_buf[count].name[KPM_PROC_NAME_MAX - 1] = '\0';

                count++;

                if (needs_put) kpm_put_task_struct(task); else kpm_task_end();
            }
        }
    }

proc_list_copy:
    /* Copy to userspace */
    if (count > 0) {
        unsigned long nbytes = (unsigned long)count * sizeof(kpm_proc_entry_t);
        if (kf_copy_to_user) {
            if (kf_copy_to_user(user_buf, stack_buf, nbytes))
                ret = -KPM_E_FAULT;
            else
                ret = count;
        } else {
            ret = -KPM_E_FAULT;
        }
    } else {
        ret = 0;
    }

    kf_kfree(stack_buf);
    return ret;
}

/* Parse one line of /proc/pid/maps:
 * format: "start-end perms offset dev inode path"
 * Example: "7fcb000000-7fcb100000 r--p 00000000 fd:01 12345 /system/lib64/libc.so"
 */
static int parse_maps_line(char *line, kpm_map_entry_t *entry)
{
    char *p = line;
    char *endptr;
    char perms[5];
    int i;

    /* Parse start address */
    entry->start = kf_simple_strtoull(p, &endptr, 16);
    if (endptr == p || *endptr != '-')
        return -1;
    p = endptr + 1;

    /* Parse end address */
    entry->end = kf_simple_strtoull(p, &endptr, 16);
    if (endptr == p)
        return -1;
    p = endptr;

    /* Skip whitespace */
    while (*p == ' ' || *p == '\t') p++;

    /* Parse permissions (4 chars: rwx[p/s]) */
    for (i = 0; i < 4 && *p && *p != ' '; i++, p++)
        perms[i] = *p;
    perms[i] = '\0';

    entry->perms = 0;
    if (perms[0] == 'r') entry->perms |= 0x1;
    if (perms[1] == 'w') entry->perms |= 0x2;
    if (perms[2] == 'x') entry->perms |= 0x4;

    /* Skip whitespace */
    while (*p == ' ' || *p == '\t') p++;

    /* Parse offset */
    entry->offset = kf_simple_strtoull(p, &endptr, 16);
    p = endptr;

    /* Skip dev and inode fields */
    while (*p == ' ' || *p == '\t') p++;
    while (*p && *p != ' ' && *p != '\t') p++; /* dev */
    while (*p == ' ' || *p == '\t') p++;
    while (*p && *p != ' ' && *p != '\t') p++; /* inode */

    /* Parse path (optional) */
    while (*p == ' ' || *p == '\t') p++;
    if (*p && *p != '\n' && *p != '\r') {
        int path_len = 0;
        char *path_start = p;
        while (*p && *p != '\n' && *p != '\r') {
            p++;
            path_len++;
        }
        if (path_len > KPM_MAP_PATH_MAX - 1)
            path_len = KPM_MAP_PATH_MAX - 1;
        lib_memcpy(entry->path, path_start, path_len);
        entry->path[path_len] = '\0';
    } else {
        entry->path[0] = '\0';
    }

    return 0;
}

long kpm_proc_maps(pid_t pid, kpm_map_entry_t *user_buf, int max_count)
{
    kpm_map_entry_t *stack_buf = 0;
    int count = 0;
    long ret = 0;
    int use_vma = 0;

    if (!user_buf || max_count <= 0 || max_count > 1024)
        return -KPM_E_INVAL;
    if (pid <= 0)
        return -KPM_E_INVAL;

    /* 分配内核缓冲区（必须在任何锁之前完成） */
    stack_buf = (kpm_map_entry_t *)kf_kmalloc(
        max_count * sizeof(kpm_map_entry_t), GFP_KERNEL);
    if (!stack_buf)
        return -KPM_E_NOMEM;
    lib_memset(stack_buf, 0, max_count * sizeof(kpm_map_entry_t));

    /* ===== 主路径：VMA 链表遍历（无文件 I/O，性能提升 10 倍以上） =====
     * 条件：find_vma + RCU + get_task_mm + mmput + copy_from_kernel_nofault
     * 优势：无 VFS 痕迹，无文件操作，直接读 mm_struct 的 VMA 链表
     *       通过 vm_next 指针顺序遍历，无需红黑树查找
     * 用 RCU 读锁替代 mmap_read_lock（全版本兼容）
     * 隐蔽性: A 级（纯内核操作，无 VFS、无文件 IO、无用户态参与） */
    if ((kf_find_vma ||
         (g_mm_mmap_offset >= 0 && g_vm_next_offset >= 0)) &&
        kf_get_task_mm && kf_mmput &&
        kpm_task_fetch_available() && kf_copy_from_kernel_nofault) {
        use_vma = 1;
    }

    if (use_vma) {
        struct task_struct *task;
        struct mm_struct *mm;
        void *vma;
        int iter_count = 0;
        int needs_put = 0;
        const int MAX_VMA_ITER = 65536;  /* 安全上限 */
        /* kpm_mm_read_lock 返回 1 = 原生 mmap 读锁，
         * 0 = RCU 读锁（或无 RCU 符号）。遍历期间树/链表稳定，
         * find_vma 持锁契约满足；解锁以同值配对。 */
        int mm_locked = 0;

        /* 免引用优先取 task（不依赖 put_task_struct/usage 偏移）。
         * 取到 mm 后立刻退出 RCU —— mm 自带引用，之后才允许做可睡眠的
         * mmap 读锁/惰性探测；此后不再使用 task。 */
        if (kpm_task_acquire(pid, &task, &needs_put) != 0) {
            ret = -KPM_E_NOTFOUND;
            goto out_vma;
        }

        mm = kf_get_task_mm(task);
        if (!mm) {
            if (needs_put) kpm_put_task_struct(task); else kpm_task_end();
            ret = -KPM_E_NOTFOUND;
            goto out_vma;
        }
        if (!needs_put)
            kpm_task_end();

        mm_locked = kpm_mm_read_lock(mm);

        /* 惰性探测 VMA 偏移（首次调用时） */
        if (g_vm_start_offset == -1) {
            kpm_probe_vma_offsets(mm);
        }

        if (g_vm_start_offset == -1 || g_vm_end_offset == -1) {
            /* 探测失败，回退到 /proc/maps */
            kpm_mm_read_unlock(mm, mm_locked);
            kf_mmput(mm);
            use_vma = 0;
        } else {
            /* 惰性探测 vm_file/dentry/name 偏移（首次调用时）。
             * 失败时 path 保持为空（模块列表拿不到名字，但 maps 布局不受影响） */
            if (g_vm_file_offset == -1)
                kpm_probe_vm_file_offsets(mm);

            /* 高兼容性方案：kpm_find_vma_next 统一接口
             * 路径 1: find_vma（原生锁主路径，5.12+）
             * 路径 2: vm_next 链表遍历（无锁主路径，4.14-6.0） */
            vma = kpm_find_vma_next(mm, 0);
            while (vma && count < max_count) {
                uint64_t vma_start = 0, vma_end = 0;
                uint64_t vflags = 0;
                uint8_t perms;

                if (++iter_count > MAX_VMA_ITER)
                    break;

                /* 读取 vm_start 和 vm_end */
                if (kf_copy_from_kernel_nofault(&vma_start,
                        (void *)((unsigned long)vma + g_vm_start_offset), 8) != 0)
                    break;
                if (kf_copy_from_kernel_nofault(&vma_end,
                        (void *)((unsigned long)vma + g_vm_end_offset), 8) != 0)
                    break;

                /* 合法性检查 */
                if (vma_start == 0 || vma_end == 0 || vma_start >= vma_end)
                    break;

                /* 读取 vm_flags（如果偏移已探测） */
                if (g_vm_flags_offset != -1) {
                    if (kf_copy_from_kernel_nofault(&vflags,
                            (void *)((unsigned long)vma + g_vm_flags_offset), 8) == 0) {
                        perms = 0;
                        if (vflags & 0x1) perms |= 0x1;
                        if (vflags & 0x2) perms |= 0x2;
                        if (vflags & 0x4) perms |= 0x4;
                    } else {
                        perms = 0x3;
                    }
                } else {
                    perms = 0x3;
                }

                stack_buf[count].start = vma_start;
                stack_buf[count].end = vma_end;
                stack_buf[count].offset = 0;
                stack_buf[count].perms = perms;
                stack_buf[count].path[0] = '\0';
                /* 直接从 vm_file 解析文件名（纯内存，无 VFS）。
                 * 失败（匿名映射/偏移未探测）时 path 保持为空 */
                kpm_vma_get_path(vma, stack_buf[count].path,
                                 KPM_MAP_PATH_MAX);
                count++;

                /* 查找下一个 VMA：kpm_find_vma_next 统一接口
                 * find_vma 路径：O(1) 查找，不依赖 vm_next
                 * vm_next 链表路径：顺序遍历，5.x-6.0 兼容 */
                vma = kpm_find_vma_next(mm, vma_end);
            }

            kpm_mm_read_unlock(mm, mm_locked);
            kf_mmput(mm);

            kpm_log("proc: VMA traversal: %d regions for pid %d\n", count, pid);
        }
        /* out_vma 前的统一收尾：needs_put 路径归还 task 引用（免引用路径已退 RCU） */
        if (needs_put)
            kpm_put_task_struct(task);

    out_vma:
        if (use_vma) {
            /* Copy to userspace */
            if (count > 0) {
                unsigned long nbytes = (unsigned long)count * sizeof(kpm_map_entry_t);
                if (kf_copy_to_user) {
                    if (kf_copy_to_user(user_buf, stack_buf, nbytes))
                        ret = -KPM_E_FAULT;
                    else
                        ret = count;
                } else {
                    ret = -KPM_E_FAULT;
                }
            }
            kf_kfree(stack_buf);
            return ret;
        }
    }

    /* ===== 回退路径：/proc/<pid>/maps 文件读取 ===== */
    {
        char path[64];
        struct file *fp = 0;
        char *buf = 0;
        loff_t pos = 0;
        ssize_t nread;
        char *line_start, *line_end, *scan;

        kpm_log("proc: using /proc/maps fallback for pid %d\n", pid);

        if (!kf_snprintf || !kf_filp_open || !kf_filp_close) {
            ret = -KPM_E_NOTFOUND;
            kf_kfree(stack_buf);
            return ret;
        }

        buf = (char *)kf_kmalloc(KPM_MAPS_BUF_SIZE, GFP_KERNEL);
        if (!buf) {
            kf_kfree(stack_buf);
            return -KPM_E_NOMEM;
        }

        kf_snprintf(path, sizeof(path), "/proc/%d/maps", pid);
        fp = kf_filp_open(path, 0 /* O_RDONLY */, 0);
        if (IS_ERR_OR_NULL(fp)) {
            ret = -KPM_E_NOTFOUND;
            goto out_fb;
        }

        nread = kpm_read_file(fp, buf, KPM_MAPS_BUF_SIZE - 1, &pos);
        if (nread <= 0) {
            ret = -KPM_E_FAULT;
            goto out_close_fb;
        }
        buf[nread] = '\0';

        scan = buf;
        while (count < max_count && *scan) {
            while (*scan == '\n' || *scan == '\r') scan++;
            if (!*scan) break;

            line_start = scan;
            line_end = scan;
            while (*line_end && *line_end != '\n' && *line_end != '\r')
                line_end++;

            {
                char saved = *line_end;
                *line_end = '\0';
                if (parse_maps_line(line_start, &stack_buf[count]) == 0)
                    count++;
                *line_end = saved;
            }
            scan = line_end + 1;
        }

    out_close_fb:
        kf_filp_close(fp, 0);
    out_fb:
        kf_kfree(buf);
    }

    /* Copy to userspace */
    if (count > 0) {
        unsigned long nbytes = (unsigned long)count * sizeof(kpm_map_entry_t);
        if (kf_copy_to_user) {
            if (kf_copy_to_user(user_buf, stack_buf, nbytes))
                ret = -KPM_E_FAULT;
            else
                ret = count;
        } else {
            ret = -KPM_E_FAULT;
        }
    } else if (ret == 0) {
        ret = 0;
    }

    kf_kfree(stack_buf);
    return ret;
}

/*
 * kpm_proc_query_region - 查询单个地址所属的内存区域
 * 主路径：VMA 链表遍历，找到第一个 [start,end) 包含 addr 的区域即返回。
 * 回退：内核态读取 /proc/pid/maps 逐行解析。
 * 替代 CE 端 procmaps 全量缓存，每次查询都是 fresh 数据，无缓存列表。
 */
long kpm_proc_query_region(pid_t pid, uint64_t addr, kpm_map_entry_t *out)
{
    kpm_map_entry_t entry;
    long ret = -KPM_E_NOTFOUND;
    int use_vma = 0;

    if (!out || pid <= 0)
        return -KPM_E_INVAL;

    /* ===== 主路径：VMA 链表遍历（无文件 I/O，RCU 读锁） =====
     * 隐蔽性: A 级（纯内核操作，无 VFS 痕迹） */
    if ((kf_find_vma ||
         (g_mm_mmap_offset >= 0 && g_vm_next_offset >= 0)) &&
        kf_get_task_mm && kf_mmput &&
        kpm_task_fetch_available() && kf_copy_from_kernel_nofault) {
        use_vma = 1;
    }

    if (use_vma) {
        struct task_struct *task;
        struct mm_struct *mm;
        void *vma;
        int needs_put = 0;
        /* kpm_mm_read_lock 统一加锁（1=原生 mmap 读锁，
         * 0=RCU），解锁同值配对 */
        int mm_locked = 0;

        /* 免引用优先；取到 mm 后退出 RCU（此后不再用 task） */
        if (kpm_task_acquire(pid, &task, &needs_put) != 0) {
            ret = -KPM_E_NOTFOUND;
            goto out_qr;
        }

        mm = kf_get_task_mm(task);
        if (!mm) {
            if (needs_put) kpm_put_task_struct(task); else kpm_task_end();
            ret = -KPM_E_NOTFOUND;
            goto out_qr;
        }
        if (!needs_put)
            kpm_task_end();

        mm_locked = kpm_mm_read_lock(mm);

        /* 惰性探测 VMA 偏移 */
        if (g_vm_start_offset == -1) {
            kpm_probe_vma_offsets(mm);
        }

        if (g_vm_start_offset == -1 || g_vm_end_offset == -1) {
            /* 探测失败，回退 */
            kpm_mm_read_unlock(mm, mm_locked);
            kf_mmput(mm);
            use_vma = 0;
        } else {
            /* 高兼容性方案：kpm_find_vma_next 统一接口定位包含 addr 的 VMA
             * 路径 1: find_vma(mm, addr) — O(1) 查找，5.1+ 全版本
             * 路径 2: vm_next 链表遍历 — O(n) 查找，5.x-6.5 回退 */
            vma = kpm_find_vma_next(mm, addr);
            if (vma) {
                uint64_t vma_start = 0, vma_end = 0;
                uint64_t vflags = 0;
                uint8_t perms;

                if (kf_copy_from_kernel_nofault(&vma_start,
                        (void *)((unsigned long)vma + g_vm_start_offset), 8) == 0 &&
                    kf_copy_from_kernel_nofault(&vma_end,
                        (void *)((unsigned long)vma + g_vm_end_offset), 8) == 0 &&
                    vma_start != 0 && vma_end != 0 && vma_start < vma_end &&
                    addr >= vma_start && addr < vma_end) {

                    if (g_vm_flags_offset != -1) {
                        if (kf_copy_from_kernel_nofault(&vflags,
                                (void *)((unsigned long)vma + g_vm_flags_offset), 8) == 0) {
                            perms = 0;
                            if (vflags & 0x1) perms |= 0x1;
                            if (vflags & 0x2) perms |= 0x2;
                            if (vflags & 0x4) perms |= 0x4;
                        } else {
                            perms = 0x3;
                        }
                    } else {
                        perms = 0x3;
                    }

                    entry.start = vma_start;
                    entry.end = vma_end;
                    entry.offset = 0;
                    entry.perms = perms;
                    entry.path[0] = '\0';
                    /* 直接从 vm_file 解析文件名（纯内存，无 VFS） */
                    kpm_vma_get_path(vma, entry.path, KPM_MAP_PATH_MAX);

                    if (kf_copy_to_user) {
                        if (kf_copy_to_user(out, &entry, sizeof(kpm_map_entry_t)))
                            ret = -KPM_E_FAULT;
                        else
                            ret = 0;
                    } else {
                        ret = -KPM_E_FAULT;
                    }
                }
            }

            kpm_mm_read_unlock(mm, mm_locked);
            kf_mmput(mm);
        }
        if (needs_put)
            kpm_put_task_struct(task);

    out_qr:
        if (use_vma)
            return ret;
    }

    /* ===== 回退路径：/proc/<pid>/maps 文件读取 ===== */
    {
        char path[64];
        struct file *fp = 0;
        char *buf = 0;
        loff_t pos = 0;
        ssize_t nread;
        char *line_start, *line_end, *scan;

        kpm_log("proc: query_region using /proc/maps fallback for pid %d\n", pid);

        buf = (char *)kf_kmalloc(KPM_MAPS_BUF_SIZE, GFP_KERNEL);
        if (!buf)
            return -KPM_E_NOMEM;

        if (!kf_snprintf || !kf_filp_open || !kf_filp_close) {
            ret = -KPM_E_NOTFOUND;
            goto out_fb2;
        }

        kf_snprintf(path, sizeof(path), "/proc/%d/maps", pid);
        fp = kf_filp_open(path, 0 /* O_RDONLY */, 0);
        if (IS_ERR_OR_NULL(fp)) {
            ret = -KPM_E_NOTFOUND;
            goto out_fb2;
        }

        nread = kpm_read_file(fp, buf, KPM_MAPS_BUF_SIZE - 1, &pos);
        if (nread <= 0) {
            ret = -KPM_E_FAULT;
            goto out_close_fb2;
        }
        buf[nread] = '\0';

        /* 逐行解析，找到包含 addr 的第一行即返回 */
        scan = buf;
        while (*scan) {
            while (*scan == '\n' || *scan == '\r') scan++;
            if (!*scan) break;

            line_start = scan;
            line_end = scan;
            while (*line_end && *line_end != '\n' && *line_end != '\r')
                line_end++;

            {
                char saved = *line_end;
                *line_end = '\0';

                if (parse_maps_line(line_start, &entry) == 0) {
                    if (addr >= entry.start && addr < entry.end) {
                        if (kf_copy_to_user) {
                            if (kf_copy_to_user(out, &entry, sizeof(kpm_map_entry_t)))
                                ret = -KPM_E_FAULT;
                            else
                                ret = 0;
                        } else {
                            ret = -KPM_E_FAULT;
                        }
                        *line_end = saved;
                        goto out_close_fb2;
                    }
                }
                *line_end = saved;
            }
            scan = line_end + 1;
        }

        ret = -KPM_E_NOTFOUND;

    out_close_fb2:
        kf_filp_close(fp, 0);
    out_fb2:
        kf_kfree(buf);
    }

    return ret;
}

/* ===== 内核空间版本（不涉及 copy_to_user，供 UDP 服务使用） =====
 *
 * 性能优化（纯内核内存路径，无 filp_open）：
 *   1. RCU 锁内：读取 pid、ppid（via real_parent->pid）、mm 指针、
 *      arg_start、arg_end、comm（16字节回退名）
 *   2. RCU 锁外：通过 kpm_mem_read_kernel 直接读 arg_start~arg_end
 *      内存区域获取完整 cmdline（纯内存操作，无文件 IO）
 *   3. arg_start/arg_end 偏移首次惰性探测（仅 1 次 filp_open）
 *
 * 隐蔽性：探测完成后，全部操作纯内核内存，无任何文件系统/用户态参与。
 */

/* RCU 锁内收集的进程信息（锁外用于读 cmdline） */
typedef struct {
    pid_t      pid;
    pid_t      ppid;
    uint64_t   mm_ptr;        /* task->mm 指针 */
    uint64_t   arg_start;     /* mm->arg_start（用户态地址） */
    uint64_t   arg_end;       /* mm->arg_end（用户态地址） */
} kpm_proc_snapshot_t;

long kpm_proc_list_kernel(kpm_proc_entry_t *kbuf, int max_count, int offset)
{
    int count = 0;
    int skipped = 0;
    int i;
    /* 快照缓冲区：动态分配，避免栈溢出（max_count <= 64，约 2KB） */
    kpm_proc_snapshot_t *snaps;

    if (!kbuf || max_count <= 0 || max_count > 64)
        return -KPM_E_INVAL;

    /* 动态分配快照数组 */
    snaps = (kpm_proc_snapshot_t *)kf_kmalloc(max_count * sizeof(kpm_proc_snapshot_t), GFP_KERNEL);
    if (!snaps) {
        snaps = NULL;  /* kmalloc 失败，回退到不读 cmdline 的简化路径 */
    }

    /* 惰性探测 arg_start/arg_end 偏移（首次调用触发） */
    if (g_arg_start_offset == 0 || g_arg_end_offset == 0) {
        kpm_probe_arg_offsets();
    }
    /* ===== 阶段 1：PID 扫描（主路径） =====
     * 按 PID 顺序直查（find_get_pid），offset 分页语义精确、必然覆盖全部 PID；
     * 过滤内核线程（mm==NULL）与用户态线程（pid != tgid，仅保留进程 leader）。
     * 走 kpm_task_acquire（免引用优先），不依赖 put_task_struct/usage 偏移；
     * 上限用运行时 pid_max。循环体内只有 nofault 读取与 get_task_comm，
     * 可安全处于 RCU 读临界区。 */
        if (kpm_task_fetch_available()) {
                pid_t pid;
                for (pid = 1; pid < kpm_pid_max() && count < max_count; pid++) {
                    struct task_struct *task;
                    uint64_t mm_val = 0;
                    int needs_put = 0;
                    int is_kthread2;
                    pid_t tgid = 0;

                if (kpm_task_acquire(pid, &task, &needs_put) != 0) continue;

                /* 过滤内核线程（mm==NULL） */
                is_kthread2 = kpm_is_kernel_thread(task);
                if (is_kthread2 == 1) { if (needs_put) kpm_put_task_struct(task); else kpm_task_end(); continue; }
                /* 过滤用户态线程：仅保留进程 leader（pid == tgid） */
                if (g_tgid_offset > 0) {
                    if (kf_copy_from_kernel_nofault(&tgid,
                            (void *)((unsigned long)task + g_tgid_offset), 4) != 0 ||
                        tgid != pid) {
                        if (needs_put) kpm_put_task_struct(task); else kpm_task_end();
                        continue;
                    }
                }

                if (skipped < offset) { skipped++; if (needs_put) kpm_put_task_struct(task); else kpm_task_end(); continue; }

                kbuf[count].pid = pid;
                kbuf[count].ppid = 0;
                kbuf[count].state = 0;
                kbuf[count].start_time = 0;
                kbuf[count].mem_size_pages = 0;
                if (kf_get_task_comm)
                    kf_get_task_comm(kbuf[count].name, KPM_PROC_NAME_MAX, task);
                else
                    kbuf[count].name[0] = '\0';
                kbuf[count].name[KPM_PROC_NAME_MAX - 1] = '\0';

                /* 快照 */
                if (snaps) {
                    snaps[count].pid = pid;
                    snaps[count].ppid = 0;
                    snaps[count].mm_ptr = 0;
                    snaps[count].arg_start = 0;
                    snaps[count].arg_end = 0;
                }
                /* 读取 mm 指针和 arg_start/arg_end 和 total_vm */
                if (snaps && g_mm_offset > 0 &&
                    kf_copy_from_kernel_nofault(&mm_val,
                        (void *)((unsigned long)task + g_mm_offset), 8) == 0 &&
                    mm_val != 0) {
                    snaps[count].mm_ptr = mm_val;
                    if (g_arg_start_offset > 0 && g_arg_end_offset > 0) {
                        uint64_t a = 0, b = 0;
                        if (kf_copy_from_kernel_nofault(&a,
                                (void *)(mm_val + g_arg_start_offset), 8) == 0)
                            snaps[count].arg_start = a;
                        if (kf_copy_from_kernel_nofault(&b,
                                (void *)(mm_val + g_arg_end_offset), 8) == 0)
                            snaps[count].arg_end = b;
                    }
                    /* 读取 total_vm（进程虚拟内存总大小，单位页） */
                    if (g_total_vm_offset > 0) {
                        uint64_t total_vm = 0;
                        if (kf_copy_from_kernel_nofault(&total_vm,
                                (void *)(mm_val + g_total_vm_offset), 8) == 0)
                            kbuf[count].mem_size_pages = (uint32_t)total_vm;
                    }
                }

                count++;
                if (needs_put) kpm_put_task_struct(task); else kpm_task_end();
            }
        }
    /* ===== 阶段 2：RCU 锁外，纯内存读取 cmdline（主路径，最高隐蔽性） =====
     * 使用 kpm_mem_read_kernel 直接读 arg_start~arg_end 用户态内存：
     *   - 通过页表遍历 + DMA Device-nGnRnE 读取，绕过所有缓存
     *   - 不调用 access_process_vm / get_user_pages_remote
     *   - 不触发目标进程 PTE AF bit 置位
     *   - 不递增 mm->mm_users / task->majflt
     *   - 完全无副作用，目标进程无法感知
     *
     * 条件：arg_start/arg_end 偏移探测成功（g_arg_start_offset > 0）
     *
     * Android 16 的 comm 存储末尾 15 字符（非首 15），完全无用，
     * 必须通过本路径或阶段3回退获取完整包名。 */
    if (snaps && g_arg_start_offset > 0 && g_arg_end_offset > 0) {
        for (i = 0; i < count; i++) {
            uint64_t a = snaps[i].arg_start;
            uint64_t b = snaps[i].arg_end;
            int cmdline_len;
            long n;

            if (a == 0 || b == 0 || b <= a)
                continue;
            cmdline_len = (int)(b - a);
            if (cmdline_len <= 0 || cmdline_len >= KPM_PROC_NAME_MAX)
                continue;

            /* 纯内存读取：通过页表遍历 + DMA，无 access_process_vm 副作用 */
            n = kpm_mem_read_kernel(snaps[i].pid, a,
                                     kbuf[i].name, cmdline_len);
            if (n > 0) {
                kbuf[i].name[n] = '\0';
                /* 仅取首个参数（包名），\0 之后的参数截断 */
                {
                    int first_arg_len = 0;
                    while (first_arg_len < n &&
                           kbuf[i].name[first_arg_len] != '\0')
                        first_arg_len++;
                    kbuf[i].name[first_arg_len] = '\0';
                }
            }
            /* 读取失败时保留 comm（已由 get_task_comm 填充），阶段3会尝试 get_cmdline 回退 */
        }
    }

    /* ===== 阶段 3：get_cmdline 回退（兼容性路径） =====
     * 仅在阶段2失败（偏移未探测 / 内存读取失败）时启用。
     * get_cmdline 内部调用 access_process_vm，会触发目标进程 PTE AF 置位，
     * 隐蔽性低于阶段2，但兼容性更好（无需偏移探测）。
     *
     * 启用条件：
     *   - 阶段2未成功覆盖（name 仍是 16 字节 comm，即末尾15字符）
     *   - get_cmdline 符号可用
     *
     * 兼容性：Linux 4.x+ 全版本存在 get_cmdline（kernel/sys.c），
     *         但部分厂商内核（如 Samsung Knox）可能将其 static 化。
     *
     * 本段以 kpm_put_task_available() 为门，不能改用免引用：
     * kf_get_cmdline() 内部会走 access_process_vm（可睡眠 + 缺页），必须持有
     * task 引用跨过它，而 RCU 临界区内不允许睡眠。替代路径是同函数的
     * 「阶段 2」（用 kpm_mem_read_kernel 读 arg_start~arg_end，纯页表遍历、
     * 无引用），它在没有 put_task 的设备上照常工作，故此处降级不影响主功能。 */
    if (kf_get_cmdline && kf_find_get_pid && kf_get_pid_task &&
        kf_put_pid && kpm_put_task_available()) {
        for (i = 0; i < count; i++) {
            int need_fallback = 1;
            char cmdline_buf[KPM_PROC_NAME_MAX];
            int cmdline_len;

            /* 判断阶段2是否已成功：若 name 包含 '.' 或 '/' 则认为是完整包名/路径 */
            if (snaps && g_arg_start_offset > 0 && g_arg_end_offset > 0) {
                int j;
                for (j = 0; j < 32 && kbuf[i].name[j] != '\0'; j++) {
                    if (kbuf[i].name[j] == '.' || kbuf[i].name[j] == '/') {
                        need_fallback = 0;
                        break;
                    }
                }
            }
            if (!need_fallback)
                continue;

            /* get_cmdline 回退读取 */
            {
                struct pid *pid_struct;
                struct task_struct *task;

                pid_struct = kf_find_get_pid(kbuf[i].pid);
                if (!pid_struct) continue;
                task = kf_get_pid_task(pid_struct, PIDTYPE_PID);
                if (!task) { kf_put_pid(pid_struct); continue; }

                cmdline_len = kf_get_cmdline(task, cmdline_buf, KPM_PROC_NAME_MAX - 1);
                if (cmdline_len > 0) {
                    cmdline_buf[cmdline_len] = '\0';
                    /* 仅取首个参数（包名） */
                    {
                        int first_arg_len = 0;
                        while (first_arg_len < cmdline_len &&
                               cmdline_buf[first_arg_len] != '\0')
                            first_arg_len++;
                        cmdline_buf[first_arg_len] = '\0';
                    }
                    if (cmdline_buf[0] != '\0') {
                        lib_memcpy(kbuf[i].name, cmdline_buf, KPM_PROC_NAME_MAX);
                    }
                }

                kf_put_pid(pid_struct);
                kpm_put_task_struct(task);
            }
        }
    }

    if (snaps) kf_kfree(snaps);
    return count;
}

long kpm_proc_maps_kernel(pid_t pid, kpm_map_entry_t *kbuf, int max_count,
                          int offset, uint64_t start_addr)
{
    int count = 0;
    int skipped = 0;
    int vma_attempted = 0;   /* 标记 VMA 主路径是否被尝试（决定可否落回 /proc） */
    uint64_t scan_from;      /* cursor 续扫起点。start_addr>0 时直接续扫 */

    if (!kbuf || max_count <= 0 || max_count > 1024 || pid <= 0)
        return -KPM_E_INVAL;
    if (offset < 0)
        offset = 0;

    /* 同 PID 分页续扫：客户端把上一页最后一个 vm_end 作为
     * start_addr 传回，内核从该地址 find_vma 续扫，避免每页从地址 0 重扫并跳过
     * offset 个区域（大进程 O(n²) 累计慢）。start_addr>0 时 offset 语义退化为从该
     * 地址之后的相对跳过（客户端配合传 offset=0）。 */
    scan_from = (start_addr > 0) ? start_addr : 0;

    /* VMA 链表遍历（高兼容性方案：三级回退链）
     *
     * 回退链：
     *   1. find_vma（主路径）: Linux 5.1+ 全版本 EXPORT_SYMBOL
     *   2. vm_next 链表遍历（回退）: 5.x-6.0 链表模式
     *   3. 功能禁用: 6.1+ 且 find_vma 不可用（实际不可达）
     *
     * 隐蔽性: A 级（纯内核操作，无 VFS、无文件 IO、无用户态参与）
     *   - find_vma 调用不产生任何可观测痕迹
     *   - vm_next 链表遍历仅 copy_from_kernel_nofault 读取
     *   - RCU 读锁是 Linux 原生同步原语 */
    if ((kf_find_vma ||
         (g_mm_mmap_offset >= 0 && g_vm_next_offset >= 0)) &&
        kf_get_task_mm && kf_mmput &&
        kpm_task_fetch_available() && kf_copy_from_kernel_nofault) {

        vma_attempted = 1;
        struct task_struct *task;
        struct mm_struct *mm;
        void *vma;
        uint64_t last_end = 0;
        int iter_count = 0;
        int needs_put = 0;
        const int MAX_VMA_ITER = 65536;
        /* kpm_mm_read_lock 统一加锁（1=原生 mmap 读锁，
         * 0=RCU），主遍历与下方重试遍历各自加锁/解锁配对 */
        int mm_locked = 0;

        /* 免引用优先；取到 mm 后退出 RCU（此后不再使用 task） */
        if (kpm_task_acquire(pid, &task, &needs_put) != 0)
            return -KPM_E_NOTFOUND;
        mm = kf_get_task_mm(task);
        if (!mm) {
            if (needs_put) kpm_put_task_struct(task); else kpm_task_end();
            return -KPM_E_NOTFOUND;
        }
        if (!needs_put)
            kpm_task_end();

        mm_locked = kpm_mm_read_lock(mm);
        if (g_vm_start_offset == -1) kpm_probe_vma_offsets(mm);

        if (g_vm_start_offset != -1 && g_vm_end_offset != -1) {
            /* 惰性探测 vm_file/dentry/name 偏移（首次调用时）。
             * 失败时 path 保持为空（模块列表拿不到名字，但 maps 布局不受影响） */
            if (g_vm_file_offset == -1)
                kpm_probe_vm_file_offsets(mm);

            /* 从 scan_from 开始查找第一个 VMA（cursor 续扫时非 0） */
            last_end = scan_from;
            vma = kpm_find_vma_next(mm, scan_from);
            while (vma && count < max_count) {
                uint64_t vs = 0, ve = 0;
                uint64_t vflags = 0;
                uint8_t perms;

                if (++iter_count > MAX_VMA_ITER) break;
                if (kf_copy_from_kernel_nofault(&vs,
                        (void *)((unsigned long)vma + g_vm_start_offset), 8) != 0) break;
                if (kf_copy_from_kernel_nofault(&ve,
                        (void *)((unsigned long)vma + g_vm_end_offset), 8) != 0) break;
                if (!vs || !ve || vs >= ve) break;

                /* UDP 分页：跳过前 offset 个区域 */
                if (skipped < offset) {
                    skipped++;
                    last_end = ve;
                    vma = kpm_find_vma_next(mm, last_end);
                    continue;
                }

                /* 读取 vm_flags（如果偏移已探测）。
                 * vm_flags 值为 VM_READ(1)|VM_WRITE(2)|VM_EXEC(4)|VM_SHARED(8) 等的组合 */
                if (g_vm_flags_offset != -1) {
                    if (kf_copy_from_kernel_nofault(&vflags,
                            (void *)((unsigned long)vma + g_vm_flags_offset), 8) != 0)
                        vflags = 0;
                    perms = 0;
                    if (vflags & 0x1) perms |= 0x1;  /* VM_READ */
                    if (vflags & 0x2) perms |= 0x2;  /* VM_WRITE */
                    if (vflags & 0x4) perms |= 0x4;  /* VM_EXEC */
                } else {
                    /* 偏移未知，默认可读写 */
                    perms = 0x3;
                }

                kbuf[count].start = vs;
                kbuf[count].end = ve;
                kbuf[count].offset = 0;
                kbuf[count].perms = perms;
                kbuf[count].path[0] = '\0';
                /* 直接从 vm_file 解析文件名（纯内存，无 VFS）。
                 * 失败（匿名映射/偏移未探测）时 path 保持为空 */
                kpm_vma_get_path(vma, kbuf[count].path, KPM_MAP_PATH_MAX);
                count++;

                /* 通用方案：用 find_vma(mm, last_end) 查找下一个 VMA
                 * find_vma(mm, addr) 返回第一个 vm_end > addr 的 VMA，
                 * 传入当前 VMA 的 vm_end 即可获取下一个 VMA。
                 * 完全不依赖 vm_next 偏移（6.1+ 已移除）。 */
                last_end = ve;
                vma = kpm_find_vma_next(mm, last_end);
            }
        }
        kpm_mm_read_unlock(mm, mm_locked);

        /* 高负载进程下 find_vma 偶发瞬态返回 NULL —— 6.1 maple tree 被 mmap
         * 写者并发修改时，RCU 读者可能看到半更新状态导致首次遍历为空。
         * 处理：锁外忙等 1-2ms（kpm_udelay_range 任意上下文安全）让树稳定后
         * 重试；仍失败才走 /proc 回退。持原生 mmap 读锁时树为稳定快照，瞬态
         * NULL 概率大幅降低；RCU/无锁回退路径仍受益于本重试。每次重试独立
         * 加锁/解锁（忙等留在锁外，避免拉长写者等待）。
         * 隐蔽性：忙等 + 只读遍历，无任何系统修改痕迹。 */
        if (count == 0 && kf_find_vma) {
            int retry;
            for (retry = 0; retry < 2 && count == 0; retry++) {
                kpm_udelay_range(1000, 2000);   /* 1-2ms 忙等 */
                skipped = 0;
                last_end = scan_from;
                iter_count = 0;
                mm_locked = kpm_mm_read_lock(mm);
                vma = kpm_find_vma_next(mm, scan_from);
                while (vma && count < max_count) {
                    uint64_t vs = 0, ve = 0;
                    uint64_t vflags = 0;
                    uint8_t perms;

                    if (++iter_count > MAX_VMA_ITER) break;
                    if (kf_copy_from_kernel_nofault(&vs,
                            (void *)((unsigned long)vma + g_vm_start_offset), 8) != 0) break;
                    if (kf_copy_from_kernel_nofault(&ve,
                            (void *)((unsigned long)vma + g_vm_end_offset), 8) != 0) break;
                    if (!vs || !ve || vs >= ve) break;

                    if (skipped < offset) {
                        skipped++;
                        last_end = ve;
                        vma = kpm_find_vma_next(mm, last_end);
                        continue;
                    }

                    if (g_vm_flags_offset != -1) {
                        if (kf_copy_from_kernel_nofault(&vflags,
                                (void *)((unsigned long)vma + g_vm_flags_offset), 8) != 0)
                            vflags = 0;
                        perms = 0;
                        if (vflags & 0x1) perms |= 0x1;
                        if (vflags & 0x2) perms |= 0x2;
                        if (vflags & 0x4) perms |= 0x4;
                    } else {
                        perms = 0x3;
                    }

                    kbuf[count].start = vs;
                    kbuf[count].end = ve;
                    kbuf[count].offset = 0;
                    kbuf[count].perms = perms;
                    kbuf[count].path[0] = '\0';
                    kpm_vma_get_path(vma, kbuf[count].path, KPM_MAP_PATH_MAX);
                    count++;

                    last_end = ve;
                    vma = kpm_find_vma_next(mm, last_end);
                }
                kpm_mm_read_unlock(mm, mm_locked);
            }
        }

        kf_mmput(mm);
        if (needs_put)
            kpm_put_task_struct(task);

        if (count > 0) return count;
        /* 若 VMA 路径返回 0 条，记录日志便于诊断 */
        kpm_log("LH_proc: maps_kernel VMA path returned 0 for pid %d "
                "(find_vma=%llx mm_mmap_off=%d vm_next_off=%d vm_start_off=%d)\n",
                pid, (uint64_t)kf_find_vma,
                g_mm_mmap_offset, g_vm_next_offset, g_vm_start_offset);
    } else {
        kpm_log("LH_proc: maps_kernel VMA path disabled "
                "(find_vma=%llx mm_mmap_off=%d vm_next_off=%d rcu=%llx mm=%llx)\n",
                (uint64_t)kf_find_vma,
                g_mm_mmap_offset, g_vm_next_offset,
                (uint64_t)kf_rcu_read_lock, (uint64_t)kf_get_task_mm);
    }

    /* 回退：/proc/maps（支持 offset 分页语义 + 全量读取）
     *
     * vmalloc 2MB 循环读取完整 maps 文件（kpm_read_file 连续推进 pos）；
     * 解析时跳过前 offset 个有效区域（与 VMA 路径 offset 语义一致），
     * 保证循环分页在回退路径同样返回全量区域。
     *
     * /proc/maps 属 VFS 文件 IO，仅作 VMA 路径（find_vma）失败时的兜底，
     * 隐蔽性弱于纯内核路径，但保证功能完整（不丢区域）。
     * 仅当 VMA 主路径确实不可用（vma_attempted==0）时才落回 /proc：
     * VMA 可用但瞬态为空（count==0，目标进程 churn/anti-tamper 窗口）时直接
     * 返回 0 交由客户端重试——部分设备（如 MTK 无 override_creds）内核态打不开
     * 其它进程的 /proc/pid/maps（ptrace_may_access 拒绝），落回 /proc 会误报 -3。
     */
    if (!vma_attempted) {
        char path[64];
        struct file *fp;
        char *buf;
        loff_t pos = 0;
        int total = 0;
        int skipped = 0;
        char *scan;

        if (!kf_snprintf || !kf_filp_open || !kf_filp_close) return -KPM_E_NOTFOUND;
        buf = (char *)kf_vmalloc(KPM_MAPS_BUF_LARGE);
        if (!buf) return -KPM_E_NOMEM;
        kf_snprintf(path, sizeof(path), "/proc/%d/maps", pid);
        fp = kf_filp_open(path, 0, 0);
        if (IS_ERR_OR_NULL(fp)) { kf_vfree(buf); return -KPM_E_NOTFOUND; }
        /* 循环读取直至装满缓冲（大进程 maps 可超 64KB） */
        while (total < KPM_MAPS_BUF_LARGE - 1) {
            ssize_t nread = kpm_read_file(fp, buf + total,
                                          KPM_MAPS_BUF_LARGE - total - 1, &pos);
            if (nread <= 0)
                break;
            total += (int)nread;
        }
        kf_filp_close(fp, 0);
        if (total <= 0) { kf_vfree(buf); return -KPM_E_FAULT; }
        buf[total] = '\0';
        scan = buf;
        while (count < max_count && *scan) {
            char *line_start, *line_end;
            char saved;
            while (*scan == '\n' || *scan == '\r') scan++;
            if (!*scan) break;
            line_start = scan;
            line_end = scan;
            while (*line_end && *line_end != '\n' && *line_end != '\r') line_end++;
            saved = *line_end;
            *line_end = '\0';
            if (skipped < offset) {
                /* 跳过阶段：解析到临时槽（kbuf[0]），仅计数成功区域 */
                if (parse_maps_line(line_start, &kbuf[0]) == 0)
                    skipped++;
            } else {
                if (parse_maps_line(line_start, &kbuf[count]) == 0)
                    count++;
            }
            *line_end = saved;
            scan = line_end + 1;
        }
        kf_vfree(buf);
    }
    return count;
}

/* 按 PID + 地址查找包含该地址的 VMA（供 UDP FULLPATH 命令使用）。
 * 返回 VMA 指针（RCU 锁外有效，调用方不得跨锁保存），失败返回 NULL。
 * 隐蔽性 A 级：纯 find_vma + copy_from_kernel_nofault，无 VFS 痕迹 */
void *kpm_find_vma_for_pid(pid_t pid, uint64_t addr)
{
    struct task_struct *task;
    struct mm_struct *mm;
    void *vma = NULL;
    int needs_put = 0;
    /* kpm_mm_read_lock 统一加锁（1=原生 mmap 读锁，0=RCU） */
    int mm_locked = 0;

    if (pid <= 0 || !kf_get_task_mm || !kf_mmput || !kpm_task_fetch_available())
        return NULL;

    /* 免引用优先；取到 mm 后退出 RCU（此后不再用 task） */
    if (kpm_task_acquire(pid, &task, &needs_put) != 0)
        return NULL;
    mm = kf_get_task_mm(task);
    if (!mm) {
        if (needs_put) kpm_put_task_struct(task); else kpm_task_end();
        return NULL;
    }
    if (!needs_put)
        kpm_task_end();

    mm_locked = kpm_mm_read_lock(mm);
    if (g_vm_start_offset == -1)
        kpm_probe_vma_offsets(mm);
    if (g_vm_start_offset != -1 && g_vm_end_offset != -1) {
        vma = kpm_find_vma_next(mm, addr);
        if (vma) {
            uint64_t vs = 0, ve = 0;
            if (kf_copy_from_kernel_nofault(&vs,
                    (void *)((unsigned long)vma + g_vm_start_offset), 8) != 0 ||
                kf_copy_from_kernel_nofault(&ve,
                    (void *)((unsigned long)vma + g_vm_end_offset), 8) != 0 ||
                vs == 0 || ve == 0 || vs >= ve || addr < vs || addr >= ve) {
                vma = NULL;
            }
        }
    }
    kpm_mm_read_unlock(mm, mm_locked);
    kf_mmput(mm);
    if (needs_put)
        kpm_put_task_struct(task);
    return vma;
}

/* 按 PID + 地址查找 VMA 并解析完整路径（锁内完成，无锁外指针泄漏）。
 * 在 RCU 读临界区内完成 find + 校验 + 路径解析，只返回字符串：vma 指针不跨
 * 锁使用，避免目标进程并发 munmap/exit 时 vma 已释放导致 UAF。
 * 隐蔽性 A 级：纯内存解析（d_parent 链），无 VFS 痕迹。
 * 返回 0 = 成功（out 为 '/'-开头完整路径），负值 = 失败 */
int kpm_find_vma_path_for_pid(pid_t pid, uint64_t addr, char *out, int out_size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    void *vma = NULL;
    int rc = -KPM_E_NOTFOUND;
    int needs_put = 0;
    /* kpm_mm_read_lock 统一加锁（1=原生 mmap 读锁，0=RCU） */
    int mm_locked = 0;

    if (pid <= 0 || !out || out_size <= 1 ||
        !kf_get_task_mm || !kf_mmput || !kpm_task_fetch_available())
        return -KPM_E_INVAL;

    /* 免引用优先；取到 mm 后退出 RCU（此后不再用 task） */
    if (kpm_task_acquire(pid, &task, &needs_put) != 0)
        return -KPM_E_NOTFOUND;
    mm = kf_get_task_mm(task);
    if (!mm) {
        if (needs_put) kpm_put_task_struct(task); else kpm_task_end();
        return -KPM_E_NOTFOUND;
    }
    if (!needs_put)
        kpm_task_end();

    mm_locked = kpm_mm_read_lock(mm);
    if (g_vm_start_offset == -1)
        kpm_probe_vma_offsets(mm);
    if (g_vm_start_offset != -1 && g_vm_end_offset != -1) {
        vma = kpm_find_vma_next(mm, addr);
        if (vma) {
            uint64_t vs = 0, ve = 0;
            if (kf_copy_from_kernel_nofault(&vs,
                    (void *)((unsigned long)vma + g_vm_start_offset), 8) != 0 ||
                kf_copy_from_kernel_nofault(&ve,
                    (void *)((unsigned long)vma + g_vm_end_offset), 8) != 0 ||
                vs == 0 || ve == 0 || vs >= ve || addr < vs || addr >= ve) {
                vma = NULL;
            }
        }
        /* 锁内解析完整路径（与 vma 生命周期绑定的操作全在临界区内） */
        if (vma && kpm_vma_get_fullpath(vma, out, out_size) == 0)
            rc = 0;
    }
    kpm_mm_read_unlock(mm, mm_locked);
    kf_mmput(mm);
    if (needs_put)
        kpm_put_task_struct(task);
    return rc;
}

long kpm_proc_query_region_kernel(pid_t pid, uint64_t addr, kpm_map_entry_t *out)
{
    long ret = -KPM_E_NOTFOUND;

    if (!out || pid <= 0) return -KPM_E_INVAL;

    /* VMA 遍历查找（高兼容性方案：三级回退链）
     * 隐蔽性: A 级（纯内核操作，无 VFS 痕迹） */
    if ((kf_find_vma ||
         (g_mm_mmap_offset >= 0 && g_vm_next_offset >= 0)) &&
        kf_get_task_mm && kf_mmput &&
        kpm_task_fetch_available() && kf_copy_from_kernel_nofault) {

        struct task_struct *task;
        struct mm_struct *mm;
        void *vma;
        uint64_t last_end = 0;
        int iter_count = 0;
        int needs_put = 0;
        /* kpm_mm_read_lock 统一加锁（1=原生 mmap 读锁，0=RCU） */
        int mm_locked = 0;

        /* 免引用优先；取到 mm 后退出 RCU（此后不再使用 task） */
        if (kpm_task_acquire(pid, &task, &needs_put) != 0)
            return -KPM_E_NOTFOUND;
        mm = kf_get_task_mm(task);
        if (!mm) {
            if (needs_put) kpm_put_task_struct(task); else kpm_task_end();
            return -KPM_E_NOTFOUND;
        }
        if (!needs_put)
            kpm_task_end();

        mm_locked = kpm_mm_read_lock(mm);
        if (g_vm_start_offset == -1) kpm_probe_vma_offsets(mm);

        if (g_vm_start_offset != -1 && g_vm_end_offset != -1) {
            /* 优化：直接用 find_vma(mm, addr) 定位包含 addr 的 VMA，
             * 无需从头遍历。find_vma 返回第一个 vm_end > addr 的 VMA。 */
            vma = kpm_find_vma_next(mm, addr);
            if (vma) {
                uint64_t vs = 0, ve = 0;
                if (kf_copy_from_kernel_nofault(&vs,
                        (void *)((unsigned long)vma + g_vm_start_offset), 8) == 0 &&
                    kf_copy_from_kernel_nofault(&ve,
                        (void *)((unsigned long)vma + g_vm_end_offset), 8) == 0 &&
                    vs != 0 && ve != 0 && vs < ve) {
                    /* find_vma 返回的是 vm_end > addr 的第一个 VMA，
                     * 还需检查 addr >= vs（addr 可能在 VMA 起始之前的空洞） */
                    if (addr >= vs && addr < ve) {
                        uint64_t vflags = 0;
                        uint8_t perms;
                        if (g_vm_flags_offset != -1) {
                            if (kf_copy_from_kernel_nofault(&vflags,
                                    (void *)((unsigned long)vma + g_vm_flags_offset), 8) == 0) {
                                perms = 0;
                                if (vflags & 0x1) perms |= 0x1;
                                if (vflags & 0x2) perms |= 0x2;
                                if (vflags & 0x4) perms |= 0x4;
                            } else {
                                perms = 0x3;
                            }
                        } else {
                            perms = 0x3;
                        }
                        out->start = vs; out->end = ve;
                        out->offset = 0; out->perms = perms;
                        out->path[0] = '\0';
                        /* 直接从 vm_file 解析文件名（纯内存，无 VFS） */
                        kpm_vma_get_path(vma, out->path, KPM_MAP_PATH_MAX);
                        ret = 0;
                    }
                }
            }
            (void)last_end;
            (void)iter_count;
        }
        kpm_mm_read_unlock(mm, mm_locked);   /* 与加锁同值配对 */
        kf_mmput(mm);
        if (needs_put)
            kpm_put_task_struct(task);
        if (ret == 0) return 0;
    }

    /* 回退：/proc/maps 查找 */
    {
        char path[64]; struct file *fp; char *buf; loff_t pos = 0;
        ssize_t nread; char *line_start, *line_end, *scan;
        if (!kf_snprintf || !kf_filp_open || !kf_filp_close) return ret;
        buf = (char *)kf_kmalloc(KPM_MAPS_BUF_SIZE, GFP_KERNEL);
        if (!buf) return -KPM_E_NOMEM;
        kf_snprintf(path, sizeof(path), "/proc/%d/maps", pid);
        fp = kf_filp_open(path, 0, 0);
        if (IS_ERR_OR_NULL(fp)) { kf_kfree(buf); return -KPM_E_NOTFOUND; }
        nread = kpm_read_file(fp, buf, KPM_MAPS_BUF_SIZE - 1, &pos);
        kf_filp_close(fp, 0);
        if (nread <= 0) { kf_kfree(buf); return -KPM_E_FAULT; }
        buf[nread] = '\0';
        scan = buf;
        while (*scan) {
            while (*scan == '\n' || *scan == '\r') scan++;
            if (!*scan) break;
            line_start = scan; line_end = scan;
            while (*line_end && *line_end != '\n' && *line_end != '\r') line_end++;
            { char saved = *line_end; *line_end = '\0';
              if (parse_maps_line(line_start, out) == 0 && addr >= out->start && addr < out->end) {
                  ret = 0; *line_end = saved; break;
              }
              *line_end = saved; }
            scan = line_end + 1;
        }
        kf_kfree(buf);
    }
    return ret;
}