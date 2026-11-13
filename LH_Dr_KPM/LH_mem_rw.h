/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_MEM_RW_H_
#define _KPM_MEM_RW_H_

#include <ktypes.h>

/* 大内存扫描单次批量上限；该量级 vmalloc 安全，无连续物理内存分配压力 */
#define KPM_SCAN_BATCH_MAX 262144

/* 初始化内存读写子模块：解析所需内核符号 */
long kpm_mem_rw_init(void);

/* 退出清理 */
void kpm_mem_rw_exit(void);

/* 跨进程物理内存直读直写
 * pid: 目标进程 PID
 * remote_addr: 目标进程虚拟地址
 * user_buf: 调用者用户态缓冲区
 * len: 读写长度
 * is_write: 0=读, 1=写
 * 返回: 成功传输的字节数，负值表示错误
 */
long kpm_mem_rw_process(pid_t pid, uint64_t remote_addr, void *user_buf, int len, int is_write);

/* 内核内部跨进程内存读取（不涉及用户态拷贝）
 * 用于 PLT hook 等内核模块内部调用
 * 返回: 成功读取的字节数，负值表示错误
 */
long kpm_mem_read_kernel(pid_t pid, uint64_t remote_addr, void *kbuf, int len);

/* uprobe handler 安全读取：强制 WB 路径，无 vmap、无睡眠。
 * 回调运行于 RCU 读临界区，DMA 路径的 vmap 可能睡眠并延长临界区，
 * 导致卸载时 synchronize_rcu 超时；此接口仅走线性映射直读。 */
long kpm_mem_read_kernel_wb(pid_t pid, uint64_t remote_addr, void *kbuf, int len);

/* 读虚拟地址的原始 PTE（zram swap 换出页解析，不判断有效位）。
 * level: 1=PMD块, 2=PTE表项; 换出页 entry bit0=0 含 swp_entry 编码。 */
long kpm_mem_get_pte(pid_t pid, uint64_t vaddr, uint64_t *out_entry,
                     uint32_t *out_level);

/* 由调用方已持有的 pgd（kpm_mem_open_scan_session 返回）直接定位
 * PTE 表项的内核虚拟地址（供 memwatch 改 PTE 权限用）。
 * 不依赖框架 pgtable_entry 符号（多符号回退：只用已加载的页表 + koffsets）。
 * 返回 0 成功并输出 PTE 槽地址；块映射/无效表返回 -KPM_E_DISABLED。 */
long kpm_mem_get_pte_va(uint64_t pgd_va, uint64_t vaddr, uint64_t *out_pte_va);

/* 页级容错批量读取：
 * 与 kpm_mem_read_kernel 的区别：
 *   - 逐页处理（页大小 = 用户空间页大小，自动适配 4K/16K/64K），失败页
 *     （walk 失败或读失败）填充 0 并继续下一页，不中断整块读取；
 *   - fail_map：bit i 置 1 表示第 i 个用户页区间读取失败（块起点需页对齐，
 *     调用方保证），调用方扫描时跳过失败页避免假命中；
 *   - 返回 len（始终完整），buf 中失败页为全 0。
 * 用途：内存扫描 / 指针扫描等需要"完整覆盖所有可读页"的批量读取场景。 */
long kpm_mem_read_kernel_pages(pid_t pid, uint64_t remote_addr, void *kbuf,
                               int len, uint32_t *fail_map);

/* ===== 大内存扫描：会话级缓存 + PMD/PTE 表项缓存 =====
 *
 * 机制：
 *   1. 会话级缓存：调用方在 scan_start 时一次性获取 task + mm + pgd_va，
 *      整个会话期间复用，避免重复进程查找。
 *   2. PMD/PTE 表项缓存：同一 2MB 范围内（512 个 4KB 页）复用 PMD/PTE
 *      表项地址，仅在跨 2MB 边界时重新走一次 PMD/PUD。
 *   3. 单次调用上限 256KB（KPM_SCAN_BATCH_MAX）。
 *
 * 隐蔽性：
 *   - mm_users 引用计数为原子操作（atomic_inc），不修改任何内核数据结构。
 *   - 整个会话期间持有 mm 引用，无任何可观测痕迹。
 *   - pgd_va 通过 copy_from_kernel_nofault 只读读取，纯内核操作。
 *
 * 稳定性：
 *   - mm 引用计数保护 mm_struct 整个会话期间不被释放（即使目标进程 fork/exec/exit）。
 *   - pgd_va 指向旧 mm 的页表全局目录，扫描针对该时间点的内存视图。
 *
 * 兼容性：
 *   - get_task_mm / mmput / put_task_struct / put_pid 全版本（Linux 4.x+）稳定可用。
 *   - copy_from_kernel_nofault 在 5.4+ 可用（项目最低版本约束）。 */

/* walk_page_table 缓存上下文
 * 持有 PMD/PTE 表项的虚拟地址缓存，跨页复用。
 * 调用方按连续地址区间顺序调用 walk_page_table_cached，
 * 跨 PTE 表边界（2MB/32MB/512MB，视页大小）自动重新解析 PGD/PUD/PMD。
 * 支持任意用户页大小（4K/16K/64K），所有移位动态计算。 */
typedef struct {
    uint64_t pgd_va;         /* 进程 PGD 虚拟地址（会话级缓存，跨整个会话不变） */
    uint64_t cached_pmd_va;  /* 上次 PMD 表项虚拟地址（线性映射） */
    uint64_t cached_pte_va;  /* 上次 PTE 表项虚拟地址（线性映射） */
    uint64_t cached_pmd_idx; /* 上次 PMD 索引（用于检测是否跨 PMD 边界） */
    uint64_t cached_pte_idx; /* 上次 PTE 索引（用于检测是否跨 PTE 表边界） */
    uint64_t cached_pmd_entry; /* 上次 PMD 表项值（表映射时指向 PTE 表） */
    /* 大页块映射缓存（PMD/PUD 块，物理连续）。
     * cached_block_shift > 0 表示当前处于块映射区间，块内任意 vaddr
     * 直接由 cached_block_entry 计算 phys，无需重走 PGD/PUD/PMD。 */
    uint64_t cached_block_shift;  /* 块大小 log2（如 21=2MB / 30=1GB），0=无块缓存 */
    uint64_t cached_block_entry;  /* 块映射页表项值（含物理地址基址） */
    uint64_t last_map_granule;    /* 最近一次 walk 的映射粒度（字节；batch 读取用它
                                    扩大物理连续区段的 chunk，大页一次线性读） */
} kpm_walk_ctx_t;

/* 会话级缓存版批量读取：使用调用方提供的 pgd_va，跳过 find_get_pid/get_task_mm。
 * 与 kpm_mem_read_kernel_pages 的区别：
 *   - 不重复 find_get_pid/get_pid_task/get_task_mm/read_mm_pgd/mmput/put_task_struct/put_pid；
 *   - 使用 walk_page_table_cached 跨页复用 PMD/PTE；
 *   - 支持单次 len ≤ 256KB（KPM_SCAN_BATCH_MAX）。
 * 返回 len（始终完整），buf 中失败页为全 0。
 * 失败页在 fail_map 标记，调用方扫描时跳过。 */
long kpm_mem_read_kernel_pages_cached(uint64_t pgd_va, uint64_t remote_addr,
                                       void *kbuf, int len,
                                       uint64_t *fail_map);

/* ===== 批量线性映射读取 =====
 *
 * 实现：
 *   1. PTE 表级缓存（walk_ctx 跨调用保持）：同 PTE 表内不再重走 PGD/PUD/PMD；
 *   2. 批量 PTE 解析：一次 copy_from_kernel_nofault 读整段 PTE（≤64 项），
 *      仅对有效页做物理计算；
 *   3. 线性映射 WB 读取：copy_from_kernel_nofault(linear_va) 每页 1 次
 *      （架构层自然方法，项目约束明确允许），无 vmap/vunmap 开销；
 *   4. 读取后 DC CIVAC 清洗（DSB 合并），压缩缓存残留窗口；
 *   5. PMD/PUD 块映射（大页）→ 物理连续，整块一次线性读取。
 *
 * 隐蔽性：copy_from_kernel_nofault 是内核标准安全拷贝 API；
 *          DC CIVAC 是特权 cache 维护指令，用户态不可执行不可观测。
 * 稳定性：失败页补零 + fail_map；所有读取经 copy_from_kernel_nofault
 *          安全包装，绝不 panic。
 * 兼容性：页大小自动适配 4K/16K/64K；fail_map bit i = 第 i 个用户页
 *          （256KB 块 = 64 个 4K 页 / 16 个 16K 页 / 4 个 64K 页，均 ≤ 64）。
 *
 * ctx: 会话级 walk 上下文（调用方分配并清零一次，跨调用保持，
 *       ctx->pgd_va 由 kpm_mem_open_scan_session 填充）。
 * 返回 len（始终完整），buf 中失败页为全 0。 */
long kpm_mem_read_batch(kpm_walk_ctx_t *ctx, uint64_t remote_addr,
                        void *kbuf, int len, uint64_t *fail_map);

/* 批量读取扩展版，额外输出 swap 换出页位图。
 * swap_map: bit i = 第 i 个用户页是 swap/zram 换出页（walk 时 PTE 原始
 * 条目 bit0=0 且 bit1=1，非空条目）。换出页与失败页一样补零并置 fail_map，
 * 调用方用 swap_map 区分"换出"与"真失败"，可经客户端 recover_swap 补读。
 * swap_map 传 NULL 时行为与 kpm_mem_read_batch 完全一致。 */
long kpm_mem_read_batch2(kpm_walk_ctx_t *ctx, uint64_t remote_addr,
                         void *kbuf, int len, uint64_t *fail_map,
                         uint64_t *swap_map);

/* ===== 会话级进程引用管理 =====
 *
 * 设计目标：scan_start 一次性获取 task + mm + pgd_va 引用，整个会话期间复用，
 * scan_clear 时释放。避免每次批量读取重复 find_get_pid → get_pid_task →
 * get_task_mm → read_mm_pgd → mmput → put_task_struct → put_pid 全套流程。
 *
 * 隐蔽性：
 *   - get_task_mm 内部仅 atomic_inc(&mm->mm_users)，不修改任何内核数据结构。
 *   - find_get_pid / get_pid_task 仅增加 PID/task 引用计数（atomic 操作）。
 *   - 整个会话期间持有引用，无任何可观测痕迹。
 *
 * 稳定性：
 *   - mm_users 引用计数保护 mm_struct 整个会话期间不被释放（即使目标进程
 *     fork/exec/exit，mm_struct 仍存在）。
 *   - pgd_va 指向旧 mm 的页表全局目录，扫描针对 scan_start 时间点的内存视图。
 *
 * 兼容性：
 *   - find_get_pid / get_pid_task / get_task_mm / mmput / put_task_struct /
 *     put_pid 全版本（Linux 4.x+）稳定可用。
 *   - read_mm_pgd 内部用 copy_from_kernel_nofault，5.4+ 可用。
 *   - kpm_mmap_read_lock 适配层支持 PREEMPT/非 PREEMPT 内核。 */

/* 打开扫描会话：一次性获取 pid_struct + task + mm + pgd_va 引用。
 * 调用方需在不再使用时调用 kpm_mem_close_scan_session 释放。
 * 失败时已获取的引用会自动释放，调用方无需处理。
 * 返回 0 成功，<0 失败。 */
int kpm_mem_open_scan_session(pid_t pid, void **out_pid_struct,
                                void **out_task, void **out_mm,
                                uint64_t *out_pgd_va);

/* 关闭扫描会话：释放 pid_struct + task + mm 引用。
 * 与 kpm_mem_open_scan_session 配对调用，参数可为 NULL（自动跳过）。 */
void kpm_mem_close_scan_session(void *pid_struct, void *task, void *mm);

/* 内核内部跨进程内存写入（不涉及用户态拷贝）
 * 用于断点等内核模块内部调用
 * 返回: 成功写入的字节数，负值表示错误
 */
long kpm_mem_write_kernel(pid_t pid, uint64_t remote_addr, const void *kbuf, int len);

/* uprobe handler 安全写入：强制 WB 路径，无 vmap、无睡眠。
 * 同上：RCU 读临界区内禁止 DMA/vmap；仅走线性映射直写 + DC CIVAC。 */
long kpm_mem_write_kernel_wb(pid_t pid, uint64_t remote_addr,
                             const void *kbuf, int len);

/* 反推 mm_struct.pgd 字段偏移（用已知有效用户 VA 校验）。
 * 扫描 mm 前若干字节的每个 8 字节字段，若该字段是 4K 对齐内核地址，
 * 则用 walk_page_table 尝试解析 known_va；成功则该字段即 pgd，
 * 写入全局 g_mm_pgd_offset。用于框架 pgd_offset 不可用时避免 walk-fail。
 * 返回 0 成功，-1 失败。 */
int kpm_probe_pgd_offset(struct mm_struct *mm, uint64_t known_va);

/* VA 位宽参数（由 kpm_detect_va_params 通过 TCR_EL1 探测，供 state_info 诊断显示） */
extern int g_kpm_va_bits;
extern int g_kpm_kernel_va_bits;
extern int g_kpm_page_shift;
extern int g_kpm_page_level;

/* 用户空间（TTBR0）参数 —— 遍历用户进程页表必须用用户空间参数。
 * 用内核空间 T1SZ/TG1 推断用户页表结构，会在 T0SZ!=T1SZ 或
 * TG0!=TG1 的内核上索引错位。 */
extern int g_kpm_user_va_bits;
extern int g_kpm_user_page_shift;

/* 探测 VA 位宽/页大小（TCR_EL1 寄存器，幂等）。
 * 用户空间用 T0SZ/TG0（遍历用户页表），内核空间用 T1SZ（PAGE_OFFSET 计算）。 */
void kpm_detect_va_params(void);

/* 获取内核线性映射 PAGE_OFFSET（TCR_EL1 位宽探测，39/48 位）。
 * 供内核空间扫描（kpm_mem_scan_kernel_start）等模块计算扫描起点。 */
uint64_t kpm_get_page_offset(void);

/* 内核虚拟地址安全校验。
 * 供触摸探测等"读取任意内核地址"场景使用——仅放行
 * ① 线性映射区的安全 RAM 物理页（kpm_phys_is_safe_ram 物理域守卫）
 * ② vmalloc_to_page 验证通过的 vmalloc 分配页（模块/驱动数据）。
 * 拒绝 ioremap 设备映射 / MTK 保护域 / 无效地址（读取这些会触发
 * DEVAPC IRQ30 → HW_Reboot，nofault 无法拦截）。返回 1 安全 0 拒绝。 */
int kpm_is_safe_kern_addr(uint64_t addr);

/* 探测用户空间（TTBR0）VA 位宽/页大小（T0SZ/TG0，幂等）。
 * 遍历用户进程页表时使用；get_page_offset（线性映射）仍用内核参数。 */
void kpm_detect_user_va_params(void);

/* ===== 内核虚拟地址读写（READ_MEM/WRITE_MEM 的 pid=0 通道） =====
 * 语义：
 *   读 force=0：仅 kpm_is_safe_kern_addr() 白名单页（线性映射安全 RAM /
 *               vmalloc 分配页）；越界/设备映射返回 -KPM_E_PERM。
 *   读 force=1：允许任意 kernel VA，逐页 copy_from_kernel_nofault；
 *               失败页返回 -KPM_E_FAULT（已读部分返回字节数）。
 *   写：force=0 一律 -KPM_E_PERM；force=1 时：
 *       - 内核镜像 text（is_kimg_range）：aarch64_insn_patch_text
 *         （含 flush_icache_range），地址/长度需 4 字节对齐；
 *       - 其它内核 VA：copy_to_kernel_nofault 分块直写。
 * kbuf 为内核缓冲区（调用方负责用户态拷贝）。
 */
long kpm_mem_read_kernel_va(uint64_t addr, void *kbuf, int len, int force);
long kpm_mem_write_kernel_va(uint64_t addr, const void *kbuf, int len,
                             int force);

#endif /* _KPM_MEM_RW_H_ */
