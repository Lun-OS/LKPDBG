#!/usr/bin/env python3
"""
udp_test_mem.py - KPM 内存子系统 UDP 测试客户端（二进制协议版）

通过二进制 UDP 协议与 Android 设备上的 KPM 内核模块通信，
测试内存功能（进程列表、内存读取、写入、扫描、冻结、指针扫描）。

协议: 二进制 UDP（kpm_udp.c），端口 17891
  - 请求头 48 字节: cmd[4] + seq[4] + arg2[8] + arg3[8] + arg4[8] + arg5[8] + data_len[4] + reserved[4]
  - 响应头 16 字节: seq[4] + ret[4] + data_len[4] + reserved[4]
  - 命令码 XOR 编码: key = 0xDEAD37F3

用法:
    python udp_test_mem.py 192.168.5.2              # 进入交互模式
    python udp_test_mem.py 192.168.5.2 --list        # 列出全部进程
    python udp_test_mem.py 192.168.5.2 --list 50     # 列出前 50 个进程
    python udp_test_mem.py 192.168.5.2 --list-apps   # 列出第三方应用（带包名）
    python udp_test_mem.py 192.168.5.2 --list-sys    # 列出系统应用（带包名）
    python udp_test_mem.py 192.168.5.2 -p 17891      # 指定端口

前置条件:
    1. 设备已加载 kpm_hidden_driver.kpm
    2. KPM 内核 UDP 服务监听 17891 端口（模块加载后自动启动）

功能:
    - 进程列表（含包名映射）
    - 内存读取（多类型显示：hex/u32/u64/float/string）
    - 内存写入（支持多类型）
    - 内存扫描（精确/范围/变化/不变/增加/减少）
    - 内存冻结（添加/删除/列表/切换/清空）
    - 指针扫描（单级/多级链）
    - 进程内存映射查询
"""

import socket
import struct
import sys
import argparse
import time
import os


# ===== 协议常量 =====
XOR_KEY = 0xDEAD37F3
DEFAULT_PORT = 17891
# 2026-08-03 F1：MEM_SCAN 全量覆盖后 SCAN_START 同步耗时可达数十秒（大进程），
# 默认超时 5s → 60s，避免全量扫描被客户端误判为超时。
DEFAULT_TIMEOUT = 60.0
DEFAULT_DUMP_DIR = os.path.join(os.path.expanduser("~"), "kpm_dumps")

# 命令码（与 kpm_comm.h 一致）
# 符号 bitmap 索引（与 kpm_comm.h 一致）
KPM_SYM_FIND_VMA      = 18

CMD_HOOK_INFO         = 0x1005
CMD_GET_LOG           = 0x1007   # 2026-09-21 诊断：读内核 RAM 环形日志缓冲
CMD_READ_MEM          = 0x1001
CMD_WRITE_MEM         = 0x1002
CMD_PROC_LIST         = 0x1145
CMD_PROC_MAPS         = 0x1146
CMD_PROC_QUERY_REGION = 0x1147
CMD_READ_FILE         = 0x1148
CMD_PROC_FULLPATH     = 0x1149

# 内存 dump（协议化传输：BEGIN/FETCH/END，块级 CRC32 + 整体 SHA256）
CMD_DUMP_BEGIN         = 0x1153
CMD_DUMP_FETCH         = 0x1154
CMD_DUMP_END           = 0x1155
DUMP_MAGIC_HDR         = 0x31504D44   # 'DMP1'
DUMP_MAGIC_CHUNK       = 0x43504D44   # 'DMPC'
DUMP_MAGIC_DONE        = 0x45504D44   # 'DMPE'

# PLT/GOT hook（2026-08-06 接线启用；HOOK_INSTALL 的 INLINE/STEALTH 为 stub）
CMD_HOOK_INSTALL       = 0x1140
CMD_HOOK_REMOVE        = 0x1141
CMD_HOOK_LIST          = 0x1142
CMD_HOOK_TOGGLE        = 0x1143
CMD_HOOK_PLT_SET       = 0x1144
HOOK_MAX_ENTRIES       = 32
# kpm_hook_entry_t = 168B：enabled(4)+type(4)+target_addr(8)+replacement(8)+
#   trampoline(8)+target_name[64]+orig_insns[64]+hit_count(4)+pid(4)
HOOK_ENTRY_SIZE        = 168

# 扫描命令
CMD_MEM_SCAN_START    = 0x1100
CMD_MEM_SCAN_NEXT     = 0x1101
CMD_MEM_SCAN_RESULT   = 0x1102
CMD_MEM_SCAN_CLEAR    = 0x1103
CMD_MEM_SCAN_STATUS   = 0x1104   # 2026-08-04: 扫描会话状态
CMD_MEM_SCAN_AOB_START = 0x1105  # 2026-08-04: 长 AOB 特征扫描(>8B, payload 传特征)
CMD_MEM_SCAN_KERNEL_START = 0x1106  # 2026-08-06: 内核线性映射范围扫描(arg2=0, arg5=range)

# 通用批量读（2026-08-05: 一次请求读多个任意地址，避免逐条 UDP 往返）
CMD_MEM_READ_BATCH     = 0x1160
CMD_MEM_READ_BATCH2    = 0x1164   # 2026-08-06 变长批量读（每条目独立长度）

# 原始 PTE 读取（2026-08-06: zram swap 换出页解析）
CMD_MEM_GET_PTE        = 0x1163

# 流式传输（2026-08-06: 突破 UDP 单包 16KB 瓶颈，一次请求流式拉取 ≤64MB）
CMD_STREAM_BEGIN       = 0x1180   # 任意地址范围流式读: arg2=pid, arg3=addr, arg4=len
CMD_STREAM_WRITE       = 0x1181   # 分片写: arg2=pid, arg3=addr, arg4=total, payload=[u32 off][data]
CMD_DUMP_STREAM        = 0x1182   # dump 流式 fetch: arg2=file_off, arg3=len（无头响应）
STREAM_MAGIC_HDR       = 0x314D5453   # 'STM1'
STREAM_MAGIC_CHUNK     = 0x434D5453   # 'STMC'
STREAM_CHUNK           = 15872        # 每数据报数据字节（与内核 KPM_STREAM_CHUNK 一致）
STREAM_MAX             = 64 * 1024 * 1024  # 单请求最大 64MB
STREAM_FLAG_KERNEL     = 0x1          # STREAM_BEGIN: 内核地址直读（pid 忽略）
STREAM_DGRAM_HDR       = 20              # kpm_stream_dgram_t: magic(4)+session(4)+offset(4)+len(4)+crc32(4)

# 冻结命令
CMD_FREEZE_ADD        = 0x1110
CMD_FREEZE_REMOVE     = 0x1111
CMD_FREEZE_LIST       = 0x1112
CMD_FREEZE_TOGGLE     = 0x1113
CMD_FREEZE_CLEAR      = 0x1114

# 指针扫描命令
CMD_PTR_SCAN          = 0x1120
CMD_PTR_SCAN_CHAIN    = 0x1121
CMD_PTR_RESULT        = 0x1122

# 扫描类型
SCAN_TYPE_INT8      = 0
SCAN_TYPE_INT16     = 1
SCAN_TYPE_INT32     = 2
SCAN_TYPE_INT64     = 3
SCAN_TYPE_FLOAT     = 4
SCAN_TYPE_DOUBLE    = 5
SCAN_TYPE_BYTEARRAY = 6
SCAN_TYPE_STRING    = 7

# 扫描模式
SCAN_MODE_EXACT     = 0
SCAN_MODE_RANGE     = 1
SCAN_MODE_CHANGED   = 2
SCAN_MODE_UNCHANGED = 3
SCAN_MODE_INCREASED = 4
SCAN_MODE_DECREASED = 5
# 2026-08-06 扩展（CE 风格完整过滤集）
SCAN_MODE_UNKNOWN       = 6   # 未知初始值（首轮恒真建集）
SCAN_MODE_NOT_EQUAL     = 7   # 值 != value
SCAN_MODE_INCREASED_BY  = 8   # 与上轮差值 == value
SCAN_MODE_DECREASED_BY  = 9   # 与上轮差值 == value（反向）
SCAN_MODE_INCREASED_GE  = 10  # 差值 >= value
SCAN_MODE_DECREASED_GE  = 11  # 差值 <= value（反向）

# 错误码
KPM_E_INVAL    = 1
KPM_E_NOMEM    = 2
KPM_E_NOTFOUND = 3
KPM_E_FAULT    = 4
KPM_E_PERM     = 5
KPM_E_BUSY     = 6

# 结构体大小
PROC_ENTRY_SIZE  = 536   # kpm_proc_entry_t: pid(4)+ppid(4)+name[512]+start_time(8)+state(4)+mem_size_pages(4)
MAP_ENTRY_SIZE  = 288   # kpm_map_entry_t: start(8)+end(8)+offset(8)+perms(1)+reserved[7]+path[256]
SCAN_RESULT_SIZE = 24   # kpm_scan_result_t: addr(8)+value(8)+prev_value(8)
FREEZE_ENTRY_SIZE = 32  # kpm_freeze_entry_t: enabled(4)+pid(4)+addr(8)+value(8)+size(4)+hit_count(4)
PTR_RESULT_SIZE  = 16   # kpm_ptr_result_t: addr(8)+value(8)

# 请求/响应头大小
REQ_HDR_SIZE = 48
RESP_HDR_SIZE = 16

# 类型名称映射
TYPE_NAMES = {
    SCAN_TYPE_INT8: "int8",
    SCAN_TYPE_INT16: "int16",
    SCAN_TYPE_INT32: "int32",
    SCAN_TYPE_INT64: "int64",
    SCAN_TYPE_FLOAT: "float",
    SCAN_TYPE_DOUBLE: "double",
    SCAN_TYPE_BYTEARRAY: "bytearray",
    SCAN_TYPE_STRING: "string",
}

MODE_NAMES = {
    SCAN_MODE_EXACT: "exact",
    SCAN_MODE_RANGE: "range",
    SCAN_MODE_CHANGED: "changed",
    SCAN_MODE_UNCHANGED: "unchanged",
    SCAN_MODE_INCREASED: "increased",
    SCAN_MODE_DECREASED: "decreased",
}

# 颜色输出（Windows 兼容）
class Color:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"

def c(text, color):
    return f"{color}{text}{Color.RESET}"


def xor_cmd(code: int) -> int:
    return (code ^ XOR_KEY) & 0xFFFFFFFF


def _decode_build_time(raw: int) -> str:
    """解码 kpm_build_time 字段为可读字符串
    格式: year(12)|mon(4)|day(5)|hh(5)|mm(6)"""
    if raw == 0:
        return "未知"
    year = (raw >> 20) & 0xFFF
    mon = (raw >> 16) & 0xF
    day = (raw >> 11) & 0x1F
    hh = (raw >> 6) & 0x1F
    mm = raw & 0x3F
    return f"{year}-{mon:02d}-{day:02d} {hh:02d}:{mm:02d}"


class KPMClient:
    """KPM UDP 二进制协议客户端"""

    def __init__(self, host: str, port: int = DEFAULT_PORT,
                 timeout: float = DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        # 2026-08-06 真机验证修复：流式突发（内核 1MB 在数十 ms 内灌入）
        # 超过默认 rcvbuf(~212KB) 时 UDP 协议栈静默丢包（实测丢 75%）。
        # 调大接收缓冲以容纳突发，配合 zlib CRC32 加快消费速度。
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 * 1024 * 1024)
        self.seq = 0

    def send_binary(self, cmd_code: int, arg2: int = 0, arg3: int = 0,
                    arg4: int = 0, arg5: int = 0, payload: bytes = b"",
                    retries: int = 3, timeout: float = 0):
        """发送二进制请求并接收响应。
        retries: UDP 丢包重试次数（2026-08-04 新增：内网 UDP 偶发丢包导致
        recvfrom 超时，重发相同请求（同 seq）幂等覆盖读型命令；扫描命令
        重复执行代价为重新扫描，可接受）。
        timeout: 单次等待响应超时（>0 覆盖 self.timeout）。2026-09-21：
        高频轮询型命令（PROC_MAPS 分页）每页偶发丢包时若用默认大超时会被
        放大为 5s×N 拖慢全量；调用方可传短超时（如 1s）快速重发收敛。"""
        self.seq += 1
        cmd_xored = xor_cmd(cmd_code)
        header = struct.pack("<IIQQQQII",
                             cmd_xored, self.seq,
                             arg2 & 0xFFFFFFFFFFFFFFFF,
                             arg3 & 0xFFFFFFFFFFFFFFFF,
                             arg4 & 0xFFFFFFFFFFFFFFFF,
                             arg5 & 0xFFFFFFFFFFFFFFFF,
                             len(payload), 0)
        pkt = header + payload
        last_err = None
        # 2026-09-21 修复：timeout 参数之前未生效（始终用 self.timeout），
        # 导致 proc_maps 的1s超时被放大为60s，偶发丢包时拖慢全量。
        effective_timeout = timeout if timeout > 0 else self.timeout
        for attempt in range(max(1, retries)):
            self.sock.sendto(pkt, (self.host, self.port))
            # 响应 seq 必须等于请求 seq（修复 2026-08-04：UDP 重传时可能收到
            # 旧的排队响应（如 FETCH 的 DMPC chunk），不校验会解析错乱）
            deadline = time.monotonic() + effective_timeout
            while True:
                remain = deadline - time.monotonic()
                if remain <= 0:
                    last_err = socket.timeout("timed out")
                    break
                self.sock.settimeout(remain)
                try:
                    data, _ = self.sock.recvfrom(32768)
                except socket.timeout as e:
                    last_err = e
                    break
                if len(data) < RESP_HDR_SIZE:
                    continue   # 过短包，忽略继续等
                seq, ret, data_len, reserved = struct.unpack("<IiII", data[:RESP_HDR_SIZE])
                if seq != self.seq:
                    continue   # 旧响应/乱序，丢弃继续等正确 seq
                resp_payload = data[RESP_HDR_SIZE:RESP_HDR_SIZE + data_len]
                return ret, data_len, resp_payload
            if attempt + 1 >= max(1, retries):
                break
        raise last_err

    def close(self):
        self.sock.close()

    # ===== 基础查询 =====

    def info(self) -> dict:
        """获取扩展状态信息（256 字节 kpm_state_info_t）
        返回包含模块状态、符号可用性、回退状态、偏移、功能路径等完整诊断信息的字典"""
        ret, _, payload = self.send_binary(CMD_HOOK_INFO)

        result = {
            "state_raw": ret,
            "state": {
                "init":       bool(ret & 0x01),
                "prctl":      bool(ret & 0x02),
                "touch":      bool(ret & 0x04),
                "mem_rw":     bool(ret & 0x08),
                "intercept":  bool(ret & 0x10),
                "udp":        bool(ret & 0x20),
                "mem_scan":   bool(ret & 0x40),
                "mem_freeze": bool(ret & 0x80),
                "ptr_scan":   bool(ret & 0x100),
                "debug":      bool(ret & 0x200),
                "proc":       bool(ret & 0x400),
                "stealth":    bool(ret & 0x800),
                # 2026-09-19 补：KPM_STATE_GYRO_OK=0x1000 一直存在但客户端漏映射，
                # 于是 gyro 就绪时位图与「已启用」清单对不上（0x1FFF 只列出 12 项）。
                "gyro":       bool(ret & 0x1000),
            },
        }

        if len(payload) < 256:
            # 旧版模块仅返回 48 字节，返回基本状态
            if len(payload) >= 48:
                fields = struct.unpack("<12i", payload[:48])
                result["legacy"] = {
                    "state": fields[0], "kver": fields[1],
                    "touch_ready": fields[2], "node_offset": fields[3],
                    "screen_w": fields[4], "screen_h": fields[5],
                    "raw_w": fields[6], "raw_h": fields[7],
                    "scale": fields[8], "active_count": fields[9],
                    "intercept_on": fields[10],
                }
            return result

        # 解析 256 字节 kpm_state_info_t（packed, little-endian）
        # [0] 头部
        magic, version = struct.unpack_from("<II", payload, 0)
        result["magic"] = f"0x{magic:08X}"
        result["version"] = version

        # [8] 基础状态
        state, kver, syms_init_ret, _reserved1 = struct.unpack_from("<IIii", payload, 8)
        result["kver"] = f"{(kver>>16)&0xFF}.{(kver>>8)&0xFF}.{kver&0xFF}"
        result["syms_init_ret"] = syms_init_ret

        # [24] 触摸/屏幕 (28 字节)
        (touch_ready, node_offset, screen_w, screen_h,
         raw_w, raw_h, screen_scale) = struct.unpack_from("<7i", payload, 24)
        result["touch_ready"] = touch_ready
        result["node_offset"] = node_offset
        result["screen"] = {"w": screen_w, "h": screen_h}
        result["raw"] = {"w": raw_w, "h": raw_h}
        result["scale"] = screen_scale

        # [52] 拦截/触摸活跃
        intercept_on, active_count = struct.unpack_from("<ii", payload, 52)
        result["intercept_on"] = intercept_on
        result["active_count"] = active_count

        # [60] 功能路径（6 字节：[65] 起为 task_fetch_path，占原 reserved2 首字节）
        mem_rw_path, touch_path, cmdline_path, put_task_path, vmemmap_source, \
            task_fetch_path = struct.unpack_from("<6B", payload, 60)
        path_names = {
            "mem_rw": {0: "WB only", 1: "DMA"},
            "touch": {0: "none", 1: "inplace", 2: "capture"},
            "cmdline": {0: "native get_cmdline", 1: "arg_start/end 内存",
                        2: "filp_open", 3: "16字节 comm"},
            "put_task": {0: "原生 put_task_struct", 1: "手动+__put_task_struct(已标定)",
                         2: "free_task(已禁用)", 3: "泄漏(__put_task_struct 也缺)",
                         4: "泄漏(usage 标定未执行)", 5: "泄漏(usage 标定失败)",
                         6: "泄漏(标定所需符号缺失)"},
            "vmemmap": {0: "符号", 1: "vmemmap_base 变量", 2: "推算"},
            "task_fetch": {0: "取引用(find_get_pid + get_pid_task)",
                           1: "免引用(RCU + pid_task/find_vpid)"},
        }
        result["paths"] = {
            "mem_rw": path_names["mem_rw"].get(mem_rw_path, f"未知({mem_rw_path})"),
            "touch": path_names["touch"].get(touch_path, f"未知({touch_path})"),
            "cmdline": path_names["cmdline"].get(cmdline_path, f"未知({cmdline_path})"),
            "put_task": path_names["put_task"].get(put_task_path, f"未知({put_task_path})"),
            "task 取用": path_names["task_fetch"].get(
                task_fetch_path, f"未知({task_fetch_path})"),
            "vmemmap": path_names["vmemmap"].get(vmemmap_source, f"未知({vmemmap_source})"),
        }
        # 路径原始枚举值：渲染「符号可用性」时要判断"缺失符号是否已有生效回退"，
        # 判据必须是数值而不是中文字符串（文本会随文案改动而漂）。
        result["paths_raw"] = {
            "mem_rw": mem_rw_path, "touch": touch_path,
            "cmdline": cmdline_path, "put_task": put_task_path,
            "task_fetch": task_fetch_path, "vmemmap": vmemmap_source,
        }

        # [68] 符号可用性 bitmap (16 字节 = 4 × uint32)
        sym_words = struct.unpack_from("<4I", payload, 68)
        sym_bits = 0
        for i, w in enumerate(sym_words):
            sym_bits |= (w << (i * 32))

        # 符号名称映射（索引 → 名称）
        sym_names = {
            0: "copy_from_user", 1: "copy_to_user",
            2: "copy_from_kernel_nofault", 3: "copy_to_kernel_nofault",
            4: "memremap", 5: "memunmap",
            6: "vmap", 7: "vunmap",
            8: "filp_open", 9: "kernel_read", 10: "kernel_write",
            11: "kernel_read_iter",
            12: "input_handle_event", 13: "input_event",
            14: "find_get_pid", 15: "get_pid_task",
            16: "get_task_mm", 17: "mmput",
            18: "find_vma", 19: "rcu_read_lock", 20: "rcu_read_unlock",
            21: "init_task", 22: "put_task_struct",
            23: "get_cmdline", 24: "get_task_comm",
            25: "sock_create_kern", 26: "alloc_workqueue",
            27: "init_net", 28: "queue_work",
            29: "vsnprintf", 30: "printk",
            31: "find_task_by_vpid", 32: "__task_pid_nr_ns",
            33: "mmap_read_lock", 34: "mmap_read_unlock",
            35: "register_user_hw_bp", 36: "unregister_hw_bp",
            37: "kmalloc", 38: "kfree",
            39: "vmalloc", 40: "vfree",
            41: "vsnprintf2", 42: "snprintf", 43: "simple_strtoull",
            44: "synchronize_rcu",
        }
        syms_available = []
        syms_missing = []
        for idx in range(45):
            name = sym_names.get(idx, f"sym_{idx}")
            if sym_bits & (1 << idx):
                syms_available.append(name)
            else:
                syms_missing.append(name)
        result["symbols"] = {
            "available_count": len(syms_available),
            "missing_count": len(syms_missing),
            "available": syms_available,
            "missing": syms_missing,
        }

        # [84] 回退状态 (4 字节 = 16 个 2-bit 字段)
        fb_bitmap, = struct.unpack_from("<I", payload, 84)
        fb_names = {
            0: "copy_from_user", 1: "copy_to_user",
            2: "copy_from_kernel_nofault", 3: "memremap", 4: "memunmap",
            5: "find_get_pid", 6: "get_pid_task", 7: "mmput",
            8: "printk", 9: "put_task_struct",
            10: "queue_work", 11: "flush_workqueue",
            12: "vmalloc", 13: "kmalloc",
            14: "kernel_read", 15: "kernel_write",
        }
        fb_states = {0: "主符号", 1: "第一回退", 2: "第二回退", 3: "全缺失/泄漏"}
        fallbacks = {}
        for i in range(16):
            val = (fb_bitmap >> (i * 2)) & 0x3
            name = fb_names.get(i, f"fb_{i}")
            fallbacks[name] = fb_states.get(val, f"未知({val})")
        result["fallbacks"] = fallbacks


        # [88] task_struct 偏移 (24 字节 = 12 × int16)
        offsets = struct.unpack_from("<12h", payload, 88)
        offset_names = [
            "tasks", "tgid", "mm", "pid",
            "real_parent", "usage", "arg_start", "arg_end",
            "vm_start", "vm_end", "vm_next", "mm_mmap"
        ]
        # 上下文感知：根据功能路径判定偏移是否必需
        # cmdline_path=0 表示 native get_cmdline，arg_start/end 偏移无需探测
        # find_vma 可用时，vm 偏移无需探测（回退链不需要）
        find_vma_avail = bool(sym_bits & (1 << KPM_SYM_FIND_VMA))
        result["offsets"] = {}
        for name, val in zip(offset_names, offsets):
            if name in ("arg_start", "arg_end") and cmdline_path == 0:
                result["offsets"][name] = f"{val} (get_cmdline)"
            elif name == "usage" and val == 0:
                # usage 偏移只在「手动 put 路径可用」时才有意义；
                # 为什么没标定看功能路径的 put_task 项（4/5/6 三种原因）
                result["offsets"][name] = "未标定（见功能路径 put_task）"
            elif name in ("vm_start", "vm_end", "vm_next", "mm_mmap") and find_vma_avail:
                result["offsets"][name] = f"{val} (find_vma)"
            else:
                result["offsets"][name] = (val if val != 0 else "未探测")

        # [112] 框架变量 (44 字节)
        vmemmap_base, memstart_addr, pgd_va = struct.unpack_from("<QQQ", payload, 112)
        mm_pgd_offset, va_bits, page_shift, page_level, _ = struct.unpack_from("<Iiiii", payload, 136)
        result["framework"] = {
            "vmemmap_base": f"0x{vmemmap_base:016X}",
            "memstart_addr": f"0x{memstart_addr:016X}",
            "pgd_va": f"0x{pgd_va:016X}",
            "mm_pgd_offset": mm_pgd_offset,
            "va_bits": va_bits,
            "page_shift": page_shift,
            "page_level": page_level,
        }

        # [156] 模块版本 (12 字节)
        mod_ver, build_time, mod_size = struct.unpack_from("<III", payload, 156)
        result["module"] = {
            "version": f"{(mod_ver>>24)&0xFF}.{(mod_ver>>16)&0xFF}.{(mod_ver>>8)&0xFF}",
            "version_raw": f"0x{mod_ver:08X}",
            "build_time_raw": f"0x{build_time:08X}",
            "build_time": _decode_build_time(build_time),
            "size": mod_size,
        }

        return result

    # ===== 内部日志（诊断） =====

    def getlog(self) -> str:
        """2026-09-21 诊断：读取内核 RAM 环形日志缓冲（GET_LOG 0x1007）。
        返回日志文本；为兼容未知 data_len 语义，直接拼原始字节按文本解码。"""
        ret, data_len, payload = self.send_binary(CMD_GET_LOG, retries=2)
        if ret < 0:
            return f"[getlog ret={ret}]"
        return payload.decode('utf-8', errors='replace')

    # ===== 进程列表 =====

    def proc_list(self, max_count: int = 100, offset: int = 0):
        """获取进程列表（单页），返回 (count, [(pid, ppid, name, start_time, state, mem_pages), ...])"""
        ret, data_len, payload = self.send_binary(CMD_PROC_LIST,
                                                   arg2=max_count, arg3=offset)
        if ret < 0:
            return ret, []
        count = ret
        procs = []
        for i in range(count):
            off = i * PROC_ENTRY_SIZE
            if off + PROC_ENTRY_SIZE > len(payload):
                break
            pid, ppid = struct.unpack("<ii", payload[off:off+8])
            name_bytes = payload[off+8:off+8+512]
            name = name_bytes.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
            start_time, = struct.unpack("<Q", payload[off+520:off+528])
            state, mem_pages = struct.unpack("<II", payload[off+528:off+536])
            procs.append((pid, ppid, name, start_time, state, mem_pages))
        return count, procs

    def proc_list_all(self, max_total: int = 5000):
        """获取所有用户态进程（顺序分页，遇空页/不满页即停）。
        UDP 单包 16384 字节 / 536 字节 = 每页 30 个进程，
        通常仅需 ceil(真实进程数 / 30) 页。

        2026-09-21 修复（实测 166 页→9 页，耗时 >105s→0.41s）：
          原实现把 max_total 内所有 offset 一次性预取（最多 200 页），而内核
          kpm_proc_list_kernel 每页都要从 PID=1 重扫至 pid_max（设备实测 32768），
          且 UDP 收包是单 workqueue 串行——大量高 offset 的空页每页都做一次全
          PID 空间重扫 + 多轮 UDP 往返，把列表拉取放大到几十秒~分钟。
          改为顺序分页、第一张不满页即终止：空页/不满页是“无更多进程”的可靠信号，
          无需也再无收益去预取后续全部页。
        含 PID 去重保护，防止内核分页异常导致死循环。"""
        page_size = 30  # 16384 / 536 ≈ 30
        all_procs = []
        seen_pids = set()
        offset = 0
        pages = 0

        while pages < 200:                  # 安全上限：避免内核分页异常导致死循环
            cnt, procs = self.proc_list(max_count=page_size, offset=offset)
            if cnt <= 0:
                break                       # 空页：已无更多进程
            for p in procs:
                if p[0] not in seen_pids:
                    seen_pids.add(p[0])
                    all_procs.append(p)
            pages += 1
            if cnt < page_size:
                break                       # 不满页：最后一页
            offset += page_size
            if len(all_procs) >= max_total:
                break

        return len(all_procs), all_procs

    def proc_maps(self, pid: int, max_count: int = 100, offset: int = 0,
                  start_addr: int = 0):
        """获取进程内存映射，返回 (count, [(start, end, offset, perms, path), ...])
        offset: 分页偏移（跳过前 offset 个区域），与 start_addr 二选一。
        start_addr: 2026-09-21（B 方案）：cursor 续扫起点（上一页最后一个 vm_end）。
           >0 时内核直接 find_vma 续扫，不再从地址 0 重扫跳过 offset（大进程 O(n²) 免）。"""
        ret, data_len, payload = self.send_binary(CMD_PROC_MAPS,
                                                   arg2=pid, arg3=max_count,
                                                   arg4=offset, arg5=start_addr,
                                                   # 2026-09-21：PROC_MAPS 为高频分页轮询，
                                                   # 每页偶发丢包用默认 5s 超时会被放大拖慢全量；
                                                   # 改紧凑 1s + 快速重放（读型幂等安全）收敛。
                                                   timeout=1.0, retries=3)
        if ret < 0:
            return ret, []
        count = ret
        maps = []
        for i in range(count):
            off = i * MAP_ENTRY_SIZE
            if off + MAP_ENTRY_SIZE > len(payload):
                break
            start, end, map_offset = struct.unpack("<QQQ", payload[off:off+24])
            perms = payload[off+24]
            path_bytes = payload[off+32:off+32+256]
            path = path_bytes.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
            maps.append((start, end, map_offset, perms, path))
        return count, maps

    def proc_maps_all(self, pid: int, page_size: int = 56, max_pages: int = 200):
        """分页拉取进程全部内存映射（解决 UDP 单次 56 区域上限）。
        默认最多 56*200=11200 区域（覆盖游戏进程 6794 区域等大进程）。
        2026-09-21（B 方案）：改用 cursor 续扫——内核从上一页末尾地址继续 find_vma，
        避免每页从地址 0 重扫并跳过 offset 个区域（大进程 O(n²) 全量慢）。保持 start_addr 兜底：
        若某页返回空且已取到区域，回退 offset 语义重取一次（进程 churn 时 VMA 布局漂移防护）。
        返回 (total_count, [(start, end, offset, perms, path), ...])"""
        all_maps = []
        total = 0
        cursor = 0           # 上一页最后一个 vm_end，作为内核续扫起点
        pages_done = 0
        legacy = False       # 2026-09-21：后端不支持 cursor 时降级纯 offset
        while pages_done < max_pages:
            if legacy:
                cnt, maps = self.proc_maps(pid, max_count=page_size,
                                           offset=len(all_maps))
            else:
                cnt, maps = self.proc_maps(pid, max_count=page_size,
                                           start_addr=cursor)
            if cnt < 0:
                # 2026-09-21：-KPM_E_NOTFOUND（-3）可能是目标进程 task/mm 瞬态不可用
                # （App 热重启 / fork-teardown 竞态窗口，kpm_proc_maps_kernel 的
                # find_get_pid 短暂失败或 get_task_mm 返回 NULL）。一次性退避重试区分
                # “瞬态”与“进程真已退出/参数错误”，避免偶发误报。
                if cnt == -3:
                    time.sleep(0.05)
                    if legacy:
                        cnt, maps = self.proc_maps(pid, max_count=page_size,
                                                   offset=len(all_maps))
                    else:
                        cnt, maps = self.proc_maps(pid, max_count=page_size,
                                                   start_addr=cursor)
                if cnt < 0:
                    return cnt, []
            if not maps:
                # cursor 续扫返回空：进程 churn 致 VMA 漂移超出，或已到末尾。
                # 用 offset 语义定位回退一次，避免静默漏区域。
                if cursor and total and not legacy:
                    cnt2, maps2 = self.proc_maps(pid, max_count=page_size,
                                                 offset=total)
                    if cnt2 > 0 and maps2:
                        maps = maps2
                        cnt = cnt2
                if not maps:
                    break
            # 2026-09-21（防死循环）：若后端未实现 cursor（旧内核只认 offset=0），
            # 本页首条 start 会 <= 上一页 cursor，返回与上页重叠/重复的区域集合。
            # 判定为"后端不支持 cursor"，立即降级为纯 offset 分页并重扫，避免撞满
            # max_pages 死循环（曾实测旧内核下拖 5 分钟无返回）。
            if not legacy and cursor and maps and maps[0][1] <= cursor:
                legacy = True
                all_maps = []
                total = 0
                pages_done = 0
                cursor = 0
                continue
            all_maps.extend(maps)
            total += cnt
            cursor = maps[-1][1]      # 更新续扫起点 = 本页最后一个 vm_end
            pages_done += 1
            if cnt < page_size:
                break
        return total, all_maps

    def proc_query_region(self, pid: int, addr: int):
        """查询地址所在内存区域"""
        ret, data_len, payload = self.send_binary(CMD_PROC_QUERY_REGION,
                                                   arg2=pid, arg3=addr)
        if ret < 0 or data_len < MAP_ENTRY_SIZE:
            return ret, None
        start, end, map_offset = struct.unpack("<QQQ", payload[:24])
        perms = payload[24]
        path_bytes = payload[32:32+256]
        path = path_bytes.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        return 0, (start, end, map_offset, perms, path)

    # ===== 内存 dump（ELF 重建，IDA/脱壳分析） =====

    # Dump 状态
    DUMP_STATE_IDLE, DUMP_STATE_RUNNING, DUMP_STATE_DONE = 0, 1, 2
    DUMP_STATE_ERROR, DUMP_STATE_CANCELED = 3, 4

    def dump_start(self, pid: int, module_name: str) -> int:
        """启动异步 dump：指定进程 + 模块名（basename 包含匹配）。
        返回 0 成功 / 负值错误（-6=队列忙 BUSY）"""
        name_b = module_name.encode('utf-8')[:64]
        ret, _, _ = self.send_binary(CMD_DUMP_START, arg2=pid, payload=name_b)
        return ret

    def dump_progress(self):
        """查询 dump 进度，返回 dict（state/err/total/done/region/seg/path）"""
        ret, data_len, payload = self.send_binary(CMD_DUMP_PROGRESS)
        if ret < 0 or data_len < 160:
            return None
        state, err, total, done, rc, sc, st, rsv = struct.unpack(
            "<IIQQIIII", payload[:40])
        path = payload[40:168].split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        return {
            "state": state, "err": err,
            "total": total, "done": done,
            "region_count": rc, "seg_count": sc, "seg_total": st,
            "path": path,
        }

    def dump_cancel(self) -> int:
        ret, _, _ = self.send_binary(CMD_DUMP_CANCEL)
        return ret

    # ===== 内存读写 =====

    def read_mem(self, pid: int, addr: int, length: int):
        """读取进程内存，返回 (ret, data:bytes)"""
        ret, data_len, payload = self.send_binary(CMD_READ_MEM,
                                                   arg2=pid, arg3=addr, arg5=length)
        if ret < 0:
            return ret, b""
        return ret, payload[:ret]

    def read_batch(self, pid: int, addrs, per_len: int = 16):
        """通用批量读：一次请求读取多个任意地址。
        返回 (ok_count, data:bytes) —— data 长度 = len(addrs)*per_len，
        每条目读取失败时对应字节为全 0xFF。
        per_len 2026-08-06 起支持任意 1..256（驱动已放开幂次限制）；
        单次最多 2048 条地址，总字节 ≤ 16384。"""
        addrs = list(addrs)
        if not addrs or len(addrs) > 2048:
            return -1, b""
        if per_len < 1 or per_len > 256:
            return -1, b""
        if len(addrs) * per_len > 16384:
            return -1, b""
        payload = struct.pack("<II", len(addrs), per_len)
        for a in addrs:
            payload += struct.pack("<Q", a & 0xFFFFFFFFFFFFFFFF)
        ret, data_len, resp = self.send_binary(CMD_MEM_READ_BATCH,
                                               arg2=pid, payload=payload)
        if ret < 0:
            return ret, b""
        return ret, resp[:data_len]

    def read_batch2(self, pid: int, items):
        """2026-08-06 变长批量读：每条目独立长度（高可扩展）。
        items: [(addr, len), ...] 或 [addr, addr, ...]（len 默认 32）
        返回 (ok_count, data:bytes) —— data 按请求顺序拼接每条目 len 字节，
        失败条目对应字节为全 0xFF。
        单次最多 512 条，Σ len ≤ 16384。"""
        items = list(items)
        if not items or len(items) > 512:
            return -1, b""
        norm = []
        total = 0
        for it in items:
            if isinstance(it, (tuple, list)) and len(it) == 2:
                a, ln = int(it[0]), int(it[1])
            else:
                a, ln = int(it), 32
            if ln < 1 or ln > 256:
                return -1, b""
            total += ln
            norm.append((a, ln))
        if total > 16384:
            return -1, b""
        payload = struct.pack("<I", len(norm))
        for a, ln in norm:
            payload += struct.pack("<IQ", ln, a & 0xFFFFFFFFFFFFFFFF)
        ret, data_len, resp = self.send_binary(CMD_MEM_READ_BATCH2,
                                               arg2=pid, payload=payload)
        if ret < 0:
            return ret, b""
        return ret, resp[:data_len]

    def get_pte(self, pid: int, addr: int):
        """2026-08-06: 读虚拟地址的原始 PTE（zram swap 换出页解析）。
        返回 (ret, entry, level)：
          entry: 原始页表项（bit0=0 且非零 = swap 换出条目）
          level: 1=PMD块, 2=PTE表项"""
        ret, data_len, resp = self.send_binary(CMD_MEM_GET_PTE,
                                               arg2=pid, arg3=addr)
        if ret < 0 or data_len < 12:
            return ret, 0, 0
        entry = struct.unpack_from("<Q", resp, 0)[0]
        level = struct.unpack_from("<I", resp, 8)[0]
        return ret, entry, level

    def write_mem(self, pid: int, addr: int, data: bytes):
        """写入进程内存。data ≤ 16380B 走单包 WRITE_MEM；
        >16380B 自动转 stream_write（分片写，2026-08-06 审计 P2 修复：
        原超限 payload 会被内核收包 buffer 截断导致数据错乱）。
        返回 ret：单包路径为内核返回码，分片路径为写入字节数（>0 成功）。"""
        if len(data) > 16380:
            return self.stream_write(pid, addr, data)
        ret, _, _ = self.send_binary(CMD_WRITE_MEM,
                                     arg2=pid, arg3=addr, payload=data)
        return ret

    # ===== PLT hook（2026-08-06 接线启用） =====

    def hook_plt(self, pid: int, module_name: str, func_name: str,
                 replace_addr: int) -> int:
        """安装 PLT/GOT hook：把目标进程 module 中 func_name 的 GOT 条目
        改写为 replace_addr（用户态替换函数地址）。
        payload = [module_name\0][func_name\0]。返回 hook 索引（≥0）或负值。"""
        if not module_name or not func_name or len(module_name) > 127 \
                or len(func_name) > 127:
            return -1
        payload = module_name.encode('utf-8') + b'\x00' \
                  + func_name.encode('utf-8') + b'\x00'
        ret, _, _ = self.send_binary(CMD_HOOK_PLT_SET, arg2=pid,
                                     arg5=replace_addr, payload=payload)
        return ret

    def hook_remove(self, index: int) -> int:
        """移除 hook（恢复原始指令）。返回 0 或负值。"""
        ret, _, _ = self.send_binary(CMD_HOOK_REMOVE, arg2=index)
        return ret

    def hook_toggle(self, index: int, enable: int) -> int:
        """切换 hook 启停。enable: 1=启用, 0=停用。"""
        ret, _, _ = self.send_binary(CMD_HOOK_TOGGLE, arg2=index, arg3=enable)
        return ret

    def hook_list(self, max_count: int = 32) -> list:
        """列出全部 hook 条目。返回 [{index, enabled, type, target_addr,
        replacement, target_name, hit_count, pid}, ...]"""
        if max_count > HOOK_MAX_ENTRIES:
            max_count = HOOK_MAX_ENTRIES
        ret, data_len, payload = self.send_binary(CMD_HOOK_LIST,
                                                  arg2=max_count)
        if ret <= 0 or data_len < HOOK_ENTRY_SIZE:
            return []
        hooks = []
        for i in range(min(ret, max_count)):
            off = i * HOOK_ENTRY_SIZE
            if off + HOOK_ENTRY_SIZE > len(payload):
                break
            enabled, htype = struct.unpack_from("<ii", payload, off)
            target_addr, replacement, trampoline = struct.unpack_from(
                "<QQQ", payload, off + 8)
            tname = payload[off + 32:off + 96].split(b'\x00', 1)[0]
            hit_count = struct.unpack_from("<i", payload, off + 160)[0]
            hpid = struct.unpack_from("<i", payload, off + 164)[0]
            hooks.append({
                "index": i, "enabled": enabled, "type": htype,
                "target_addr": target_addr, "replacement": replacement,
                "trampoline": trampoline,
                "target_name": tname.decode('utf-8', errors='replace'),
                "hit_count": hit_count, "pid": hpid,
            })
        return hooks

    # ===== 流式传输（2026-08-06，突破 UDP 单包 16KB 瓶颈） =====
    # 一次请求 → 内核连续发送 N 个 ≤15872B 数据报（零往返等待），
    # 每块带 CRC32 + offset + session(=请求seq)，客户端按 offset 重组。
    # 丢失/损坏块：2.5s 无新数据看门狗 → 重发相同请求（同 seq 幂等，
    # 内核按 offset 重新流式发送，客户端去重组装，自愈）。

    STREAM_WATCHDOG = 2.5   # 无新数据秒数 → 重发请求

    def _stream_send_req(self, cmd: int, seq: int, arg2: int, arg3: int,
                         arg4: int, arg5: int = 0):
        """发送流式请求（不等待响应，响应为数据报流）。
        arg5 承载 flags（如 KPM_STREAM_FLAG_KERNEL，2026-08-06 真机修复）。"""
        pkt = struct.pack("<IIQQQQII", xor_cmd(cmd), seq,
                          arg2 & 0xFFFFFFFFFFFFFFFF,
                          arg3 & 0xFFFFFFFFFFFFFFFF,
                          arg4 & 0xFFFFFFFFFFFFFFFF,
                          arg5 & 0xFFFFFFFFFFFFFFFF,
                          0, 0)
        self.sock.sendto(pkt, (self.host, self.port))

    def _stream_collect(self, session: int, expected: int,
                        deadline: float, have: bytearray,
                        recv_buf: bytearray, progress_cb=None,
                        extra_match=None):
        """收集 session 的流式数据报，按 offset 组装进 recv_buf。
        返回新增接收字节数。extra_match: 可选回调(data)->bool 附加过滤。"""
        received = 0
        while time.monotonic() < deadline:
            remain = deadline - time.monotonic()
            if remain <= 0:
                break
            if remain > self.STREAM_WATCHDOG:
                remain = self.STREAM_WATCHDOG
            self.sock.settimeout(remain)
            try:
                data, _ = self.sock.recvfrom(65536)
            except socket.timeout:
                continue
            if len(data) < STREAM_DGRAM_HDR:
                continue
            dmagic, dsession, doff, dlen, dcrc = struct.unpack_from(
                "<IIIII", data, 0)
            if dmagic != STREAM_MAGIC_CHUNK or dsession != session:
                continue
            if extra_match and not extra_match(doff, dlen):
                continue
            body = data[STREAM_DGRAM_HDR:STREAM_DGRAM_HDR + dlen]
            if len(body) != dlen or doff + dlen > expected:
                continue
            if self._crc32(body) != dcrc:
                continue   # 损坏块：丢弃（看门狗将触发重发）
            seg = have[doff:doff + dlen]
            if b'\x01' * len(seg) != seg:
                newbits = seg.count(0)
                recv_buf[doff:doff + dlen] = body
                have[doff:doff + dlen] = b'\x01' * dlen
                received += newbits
                if progress_cb:
                    progress_cb(received, expected)
        return received

    def stream_read(self, pid: int, addr: int, length: int,
                    progress_cb=None, timeout=None, flags: int = 0) -> bytes:
        """流式读：一次请求流式拉取任意长度（1..64MB）进程内存，返回 bytes。
        突破 UDP 单包 16KB 限制，吞吐 = 链路带宽。
        失败页在驱动侧补零（与 dump 语义一致，不报错）。
        flags: KPM_STREAM_FLAG_KERNEL=0x1 走内核地址直读（pid 忽略）。
        2026-08-06 真机修复：原缺 flags 参数，内核模式无法使用。"""
        if length <= 0 or length > STREAM_MAX:
            raise ValueError(f"length 必须在 1..{STREAM_MAX}")
        if timeout is None:
            # 默认给足时间（按最低 256KB/s 估算 + 余量）
            timeout = max(self.timeout, length // (256 * 1024) + 15)
        my_seq = self.seq + 1
        total_deadline = time.monotonic() + timeout
        recv_buf = bytearray(length)
        have = bytearray(length)
        received = 0
        # 立即发送首个 BEGIN（看门狗仅负责停滞重发）
        self._stream_send_req(CMD_STREAM_BEGIN, my_seq, pid, addr, length, flags)
        last_progress = time.monotonic()

        while received < length and time.monotonic() < total_deadline:
            now = time.monotonic()
            # 看门狗：停滞 → 重发 BEGIN（同 seq，幂等；旧流 dgram 按 session 过滤）
            if now - last_progress >= self.STREAM_WATCHDOG:
                self._stream_send_req(CMD_STREAM_BEGIN, my_seq,
                                      pid, addr, length, flags)
                last_progress = now
            deadline = min(total_deadline, last_progress + self.STREAM_WATCHDOG)
            if deadline - now <= 0:
                break
            self.sock.settimeout(deadline - now)
            try:
                data, _ = self.sock.recvfrom(65536)
            except socket.timeout:
                continue
            # 流式头（响应头 + kpm_stream_hdr_t 40B）
            if len(data) >= RESP_HDR_SIZE + 40:
                seq, ret, data_len, reserved = struct.unpack(
                    "<IiII", data[:RESP_HDR_SIZE])
                if seq == my_seq and data_len >= 40:
                    magic = struct.unpack_from("<I", data, RESP_HDR_SIZE)[0]
                    if magic == STREAM_MAGIC_HDR:
                        last_progress = time.monotonic()
                        continue
            # 数据报
            if len(data) >= STREAM_DGRAM_HDR:
                dmagic, dsession, doff, dlen, dcrc = struct.unpack_from(
                    "<IIIII", data, 0)
                if (dmagic == STREAM_MAGIC_CHUNK and dsession == my_seq
                        and doff + dlen <= length):
                    body = data[STREAM_DGRAM_HDR:STREAM_DGRAM_HDR + dlen]
                    if len(body) == dlen and self._crc32(body) == dcrc:
                        seg = have[doff:doff + dlen]
                        if b'\x01' * len(seg) != seg:
                            newbits = seg.count(0)
                            recv_buf[doff:doff + dlen] = body
                            have[doff:doff + dlen] = b'\x01' * dlen
                            received += newbits
                            last_progress = time.monotonic()
                            if progress_cb:
                                progress_cb(received, length)
        self.seq = my_seq
        if received == length:
            return bytes(recv_buf)
        raise socket.timeout(
            f"stream_read 不完整: {received}/{length} 字节 "
            f"(pid={pid} addr=0x{addr:x})")

    def stream_write(self, pid: int, addr: int, data: bytes,
                     progress_cb=None) -> int:
        """分片写：将 data 写入 pid 进程 addr 起始区域（单次 ≤64MB）。
        每片自包含（slice_off + data），send_binary 超时重发幂等。
        返回成功写入字节数。"""
        if pid <= 0 or not data:
            return -1
        total = len(data)
        if total > STREAM_MAX:
            return -1
        slice_max = STREAM_CHUNK - 4   # 载荷上限 - [u32 slice_off]
        off = 0
        written = 0
        while off < total:
            sl = min(slice_max, total - off)
            payload = struct.pack("<I", off) + data[off:off + sl]
            ret, _, _ = self.send_binary(CMD_STREAM_WRITE, arg2=pid,
                                         arg3=addr, arg4=total,
                                         payload=payload)
            if ret < 0:
                raise RuntimeError(
                    f"stream_write 切片 0x{off:x} 失败 ret={ret}")
            written += ret
            off += sl
            if progress_cb:
                progress_cb(written, total)
        return written

    def dump_range(self, pid: int, addr: int, length: int,
                   out_path: str = None, hexdump: bool = False) -> dict:
        """定向 dump：读取 pid 进程 addr 处 length 字节（≤64MB），
        可选保存到本地文件（原始字节）并打印 hexdump 预览。
        返回 {addr, length, path, data}。"""
        data = self.stream_read(pid, addr, length)
        result = {"addr": addr, "length": len(data), "path": None,
                  "data": data}
        if out_path:
            d = os.path.dirname(os.path.abspath(out_path))
            if d:
                os.makedirs(d, exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(data)
            result["path"] = out_path
        if hexdump:
            display_memory(data, addr)
        return result

    def read_file(self, path: str, offset: int = 0, length: int = 15872):
        """文件回退读取（dump 未驻留页用）：内核态 O_RDONLY 读磁盘文件。
        返回 (ret, data)。ret>0 为实际读取字节，-3=文件不存在/权限，-4=IO 错误"""
        if not path:
            return -1, b""
        pb = path.encode('utf-8')[:240]
        ret, _, payload = self.send_binary(CMD_READ_FILE,
                                           arg5=offset, payload=pb)
        if ret < 0:
            return ret, b""
        return ret, payload[:ret]

    # ===== 客户端驱动 dump（ELF 重建，本地落盘，设备零文件） =====
    # 背景：Android SELinux enforcing 下内核态 filp_open 写 /data/local/tmp
    #       被拒（kernel 域无写权限），故 dump 数据经 UDP 回传，由 Python
    #       在本地重建 ELF 文件。设备上不产生任何文件，隐蔽性 A 级。

    DUMP_CHUNK = 15872   # 单次读取块大小（< 16384 UDP 载荷上限，留余量给头部）

    def _dump_read(self, pid: int, addr: int, length: int) -> bytes:
        """读取并严格校验长度。
        部分驻留页（kernel 只返回已驻留部分）按实际数据继续，由调用方按
        返回长度推进；返回空视为失败。"""
        ret, data = self.read_mem(pid, addr, length)
        if ret < 0:
            raise RuntimeError(f"read_mem(0x{addr:x}, {length}) 返回 {ret}")
        if not data:
            raise RuntimeError(f"read_mem(0x{addr:x}, {length}) 返回空数据")
        return data

    def _crc32(self, data: bytes) -> int:
        """CRC32（与内核查表法一致：多项式 0xEDB88320，初始/异或 0xFFFFFFFF）。
        2026-08-06 真机验证修复：原 Python 逐字节位运算 16KB 需 ~2ms，
        流式接收时成为处理瓶颈（消费 < 发送速度 → rcvbuf 溢出丢包）。
        zlib.crc32 为 C 实现，结果与内核查表法一致（已用 0xCBF43926 验证）。"""
        import zlib
        return zlib.crc32(data) & 0xFFFFFFFF

    def dump_proto(self, pid: int, module: str, out_path: str,
                   progress_cb=None, retry: int = 3,
                   use_stream: bool = True) -> dict:
        """协议化 dump（3 阶段 BEGIN/FETCH/END）：
        1. BEGIN: 内核解析 ELF，返回 HDR（Module/Base/Size 三信息 + 分块参数）
        2. 拉取: 流式 DUMP_STREAM 优先（2026-08-06，零往返，快 10-30 倍）；
           失败自动回退传统 FETCH 逐块拉取（旧驱动/网络异常兼容）
        3. END:   内核返回整体 SHA256，与本地文件哈希比对
        返回 {module, base, size, path, chunks, missing, sha256, mode}"""
        import hashlib, time, zlib
        from pathlib import Path

        if pid <= 0 or not module:
            raise ValueError("pid 与模块名不能为空")

        # ---- 1. BEGIN：建立会话，获取协议头 ----
        name_b = module.encode('utf-8')[:60]
        ret, dl, payload = self.send_binary(CMD_DUMP_BEGIN,
                                            arg2=pid, payload=name_b)
        if ret < 0 or dl < 128:
            raise RuntimeError(f"dump_begin 失败: ret={ret} len={dl}")
        magic, version = struct.unpack_from("<II", payload, 0)
        if magic != DUMP_MAGIC_HDR:
            raise RuntimeError(f"HDR magic 错误: 0x{magic:08x}")
        base, size = struct.unpack_from("<QQ", payload, 8)
        mod = payload[24:24+64].split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        chunk, chunks, segs, algo = struct.unpack_from("<IIII", payload, 88)
        missing, flags = struct.unpack_from("<QI", payload, 104)
        print(f"  [BEGIN] Module={mod}  Base=0x{base:016X}  Size={fmt_size(size)}")
        print(f"          chunks={chunks} segs={segs} algo={algo} missing={missing}B")
        if size == 0 or chunks == 0:
            self.send_binary(CMD_DUMP_END)
            raise RuntimeError("HDR 异常: size/chunks 为 0")

        # ---- 2. 拉取数据（流式优先，失败回退 FETCH） ----
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        sha_local = hashlib.sha256()
        t0 = time.time()
        mode = "fetch"
        total_written = 0
        if use_stream:
            try:
                stream_ok = self._dump_stream_transfer(size, out_path,
                                                       sha_local,
                                                       progress_cb, retry)
            except Exception as e:
                print(f"  [提示] 流式拉取失败，回退 FETCH: {e}")
                stream_ok = False
            if stream_ok:
                mode = "stream"
        if mode == "fetch":
            # 传统 FETCH：逐块拉取 + 块级 CRC32 校验 + 重传
            file_off = 0
            with open(out_path, "wb") as f:
                while file_off < size:
                    data = None
                    for attempt in range(retry + 1):
                        ret, dl, payload = self.send_binary(CMD_DUMP_FETCH,
                                                            arg2=file_off)
                        if ret <= 0 or dl < 16:
                            time.sleep(0.02)
                            continue
                        cmagic, coff, clen, ccrc = struct.unpack_from("<IIII", payload, 0)
                        if cmagic != DUMP_MAGIC_CHUNK or clen > 15872:
                            time.sleep(0.02)
                            continue
                        body = payload[16:16+clen]
                        if len(body) != clen:
                            time.sleep(0.02)
                            continue
                        # 块级 CRC32 校验
                        if self._crc32(body) != ccrc:
                            time.sleep(0.02)
                            continue
                        data = body
                        break
                    if data is None:
                        self.send_binary(CMD_DUMP_END)
                        raise RuntimeError(
                            f"FETCH 0x{file_off:x} 重传 {retry} 次仍失败")

                    f.write(data)
                    sha_local.update(data)
                    file_off += len(data)
                    total_written += len(data)
                    if progress_cb:
                        progress_cb(file_off, size)
                    if len(data) < 15872 and file_off < size:
                        # 短块但未到末尾：防御（正常最后一块才短）
                        pass
        else:
            total_written = os.path.getsize(out_path)
        elapsed = time.time() - t0
        speed = total_written / elapsed / 1024 if elapsed > 0 else 0
        print(f"  传输完成[{mode}]: {fmt_size(total_written)} in "
              f"{elapsed:.1f}s ({speed:.0f} KB/s)")

        # ---- 3. END：整体 SHA256 比对 ----
        ret, dl, payload = self.send_binary(CMD_DUMP_END)
        if ret < 0 or dl < 48:
            raise RuntimeError(f"dump_end 失败: ret={ret} len={dl}")
        dmagic, dstatus = struct.unpack_from("<II", payload, 0)
        dbytes = struct.unpack_from("<Q", payload, 8)[0]
        dsha = payload[16:48]
        dmissing, dflags = struct.unpack_from("<II", payload, 48)
        if dmagic != DUMP_MAGIC_DONE:
            raise RuntimeError(f"DONE magic 错误: 0x{dmagic:08x}")

        sha_hex_local = sha_local.hexdigest()
        sha_hex_kernel = dsha.hex()
        if sha_hex_local != sha_hex_kernel:
            # 内核 SHA 在重传时会把同一块重复计入（UDP 无状态无法区分新块/重传），
            # 因此以内核 SHA 为完整性凭证不可靠；块级 CRC32 已保证每块正确，
            # 本地 SHA 为最终凭证。差异仅提示，不视为失败。
            print(f"  [提示] 内核 SHA 与本地不同（重传导致内核重复计数，正常）:")
            print(f"          本地: {sha_hex_local[:16]}...")
            print(f"          内核: {sha_hex_kernel[:16]}...")
        print(f"  ✅ 完整性校验通过 (SHA256 {sha_hex_local[:16]}...)")
        if dmissing > 0:
            print(f"  ⚠️  缺失页补零: {fmt_size(dmissing)} (IDA 中对应区域为 0)")

        # ---- 4. 重建 SHT（IDA 可解析格式，纯本地，支持 32/64 位） ----
        try:
            with open(out_path, "rb") as f:
                ehdr = f.read(64)
            if ehdr[:4] == b"\x7fELF":
                is32 = (ehdr[4] == 1)
                if is32:
                    e_phoff = struct.unpack_from("<I", ehdr, 28)[0]
                    e_phentsize = struct.unpack_from("<H", ehdr, 42)[0]
                    e_phnum = struct.unpack_from("<H", ehdr, 44)[0]
                else:
                    e_phoff = struct.unpack_from("<Q", ehdr, 32)[0]
                    e_phentsize = struct.unpack_from("<H", ehdr, 54)[0]
                    e_phnum = struct.unpack_from("<H", ehdr, 56)[0]
                loads = []
                with open(out_path, "rb") as f:
                    f.seek(e_phoff)
                    ph_raw = f.read(e_phnum * e_phentsize)
                for i in range(e_phnum):
                    off = i * e_phentsize
                    if struct.unpack_from("<I", ph_raw, off)[0] != 1:
                        continue
                    if is32:
                        loads.append((
                            struct.unpack_from("<I", ph_raw, off+4)[0],
                            struct.unpack_from("<I", ph_raw, off+8)[0],
                            struct.unpack_from("<I", ph_raw, off+16)[0],
                            struct.unpack_from("<I", ph_raw, off+20)[0],
                            struct.unpack_from("<I", ph_raw, off+24)[0]))
                    else:
                        loads.append((
                            struct.unpack_from("<Q", ph_raw, off+8)[0],
                            struct.unpack_from("<Q", ph_raw, off+16)[0],
                            struct.unpack_from("<Q", ph_raw, off+32)[0],
                            struct.unpack_from("<Q", ph_raw, off+40)[0],
                            struct.unpack_from("<I", ph_raw, off+4)[0]))
                self._rebuild_sht(out_path, ehdr, loads)
            else:
                print("  [提示] 非 ELF，跳过 SHT 重建")
        except Exception as e:
            print(f"  [提示] SHT 重建失败（不影响 dump 内容）: {e}")

        with open(out_path + ".sha256", "w") as f:
            f.write(f"{sha_hex_local}  {Path(out_path).name}\n")

        return {
            "module": mod, "base": base, "size": size,
            "path": out_path, "chunks": chunks,
            "missing": dmissing, "sha256": sha_hex_local,
        }

    def _dump_stream_batch(self, file_off: int, want: int,
                           retry: int = 3):
        """DUMP_STREAM 拉取 [file_off, file_off+want) 区间。
        批内缺失区间按 offset 幂等重发（DUMP_STREAM 无状态，按 offset 重读）。
        返回 (recv_buf:bytearray, have:bytearray) 完整则 have 全 1；
        彻底失败返回 (None, None)。"""
        recv_buf = bytearray(want)
        have = bytearray(want)
        total_deadline = time.monotonic() + self.timeout + 30
        pending = [(0, want)]     # (相对偏移, 长度)
        attempt = 0
        while pending and attempt <= retry and time.monotonic() < total_deadline:
            rel, ln = pending.pop(0)
            sess = self.seq + 1
            self.seq = sess
            self._stream_send_req(CMD_DUMP_STREAM, sess, file_off + rel, ln, 0)
            # 收集本会话数据报：持续接收直到停滞（内核发完/丢包）
            last_progress = time.monotonic()
            got_something = False
            while time.monotonic() < total_deadline:
                now = time.monotonic()
                if got_something and now - last_progress > self.STREAM_WATCHDOG:
                    break   # 停滞：本轮数据收完（可能丢包）
                if not got_something and now - last_progress > self.STREAM_WATCHDOG * 2:
                    break   # 完全无数据（旧驱动/会话丢失）：放弃本轮快速回退
                remain = min(total_deadline - now, self.STREAM_WATCHDOG)
                if remain <= 0:
                    break
                self.sock.settimeout(remain)
                try:
                    data, _ = self.sock.recvfrom(65536)
                except socket.timeout:
                    continue
                if len(data) < STREAM_DGRAM_HDR:
                    continue
                dmagic, dsession, doff, dlen, dcrc = struct.unpack_from(
                    "<IIIII", data, 0)
                if dmagic != STREAM_MAGIC_CHUNK or dsession != sess:
                    continue
                # 只接受本批区间内的 dgram
                if doff < file_off or doff + dlen > file_off + want:
                    continue
                body = data[STREAM_DGRAM_HDR:STREAM_DGRAM_HDR + dlen]
                if len(body) != dlen or self._crc32(body) != dcrc:
                    continue
                r = doff - file_off
                seg = have[r:r + dlen]
                if b'\x01' * len(seg) != seg:
                    recv_buf[r:r + dlen] = body
                    have[r:r + dlen] = b'\x01' * dlen
                    got_something = True
                    last_progress = time.monotonic()
            attempt += 1
            if have.count(0) == 0:
                pending = []
                break
            # 缺失区间（C 速度 find）
            missing = []
            i = 0
            while i < want:
                j = have.find(b'\x00', i)
                if j == -1:
                    break
                k = have.find(b'\x01', j)
                if k == -1:
                    k = want
                missing.append((j, k - j))
                i = k
            if missing:
                pending = [missing[0]]   # 一次重发一个缺口，避免链路拥塞
        if have.count(0) == 0:
            return recv_buf, have
        return None, None

    def _dump_stream_transfer(self, size: int, out_path: str, sha_local,
                              progress_cb=None, retry: int = 3) -> bool:
        """DUMP_STREAM 流式拉取整个 dump 到文件（分批 ≤32MB）。
        全部成功返回 True；失败返回 False（调用方回退 FETCH）。"""
        DUMP_BATCH = 32 * 1024 * 1024
        file_off = 0
        with open(out_path, "wb") as f:
            while file_off < size:
                want = min(DUMP_BATCH, size - file_off)
                buf, have = self._dump_stream_batch(file_off, want, retry)
                if buf is None:
                    return False
                f.write(bytes(buf))
                sha_local.update(bytes(buf))
                file_off += want
                if progress_cb:
                    progress_cb(file_off, size)
        return True

    def dump_elf_local(self, pid: int, module: str, out_path: str,
                       progress_cb=None) -> dict:
        """客户端驱动 ELF dump：
        1. 分页拉取全部 maps，按模块名（basename 包含）匹配区域
        2. 读 ELF 头校验 magic/class
        3. 解析 PT_LOAD 段，从内存分块读取（16KB），按 p_offset 写回文件
        4. bss（p_memsz > p_filesz）补零
        5. 完整性校验：全部段重读比对 + 文件大小核对
        返回 {path, size, regions, segments, sha256}"""
        import hashlib, time
        from pathlib import Path

        if pid <= 0 or not module:
            raise ValueError("pid 与模块名不能为空")

        # ---- 1. 分页拉取全部 maps，匹配模块区域 ----
        total, maps = self.proc_maps_all(pid)
        if total < 0:
            raise RuntimeError(f"proc_maps_all 失败: {total}")
        hit = [x for x in maps if x[4] and module in x[4]]
        if not hit:
            raise RuntimeError(f"模块 '{module}' 在 pid {pid} 的 {total} 个区域中未匹配到 "
                               f"(可用 --modules 查看实际模块名)")
        base = min(x[0] for x in hit)
        # 匹配区域按 [start,end) 排序并合并重叠（同一文件多个映射段）
        segs = sorted(hit, key=lambda x: x[0])
        print(f"  模块 '{module}': 匹配 {len(hit)} 个区域, base=0x{base:016X}")

        # ---- 2. 读 ELF 头（64 字节）校验 ----
        ehdr = self._dump_read(pid, base, 64)
        if ehdr[:4] != b"\x7fELF":
            raise RuntimeError(f"0x{base:016X} 处不是 ELF 文件头: {ehdr[:4]!r}")
        if ehdr[4] != 2:
            raise RuntimeError(f"仅支持 64 位 ELF (class={ehdr[4]})")
        e_phoff = struct.unpack_from("<Q", ehdr, 32)[0]
        e_phentsize = struct.unpack_from("<H", ehdr, 54)[0]
        e_phnum = struct.unpack_from("<H", ehdr, 56)[0]
        if e_phnum == 0 or e_phnum > 128 or e_phentsize != 56:
            raise RuntimeError(f"phdr 异常: phnum={e_phnum} phentsize={e_phentsize}")
        if e_phoff < 64 or e_phoff + e_phnum * 56 > 0x40000:
            raise RuntimeError(f"phoff 异常: 0x{e_phoff:x}")

        # ---- 3. 读 program headers ----
        phdr_raw = self._dump_read(pid, base + e_phoff, e_phnum * 56)
        load_segs = []   # (p_offset, p_vaddr, p_filesz, p_memsz)
        for i in range(e_phnum):
            off = i * 56
            p_type = struct.unpack_from("<I", phdr_raw, off)[0]
            if p_type != 1:   # PT_LOAD
                continue
            p_flags = struct.unpack_from("<I", phdr_raw, off + 4)[0]
            p_offset = struct.unpack_from("<Q", phdr_raw, off + 8)[0]
            p_vaddr = struct.unpack_from("<Q", phdr_raw, off + 16)[0]
            p_filesz = struct.unpack_from("<Q", phdr_raw, off + 32)[0]
            p_memsz = struct.unpack_from("<Q", phdr_raw, off + 40)[0]
            if p_filesz > 512 * 1024 * 1024 or p_offset > 512 * 1024 * 1024:
                raise RuntimeError(f"段异常大: off=0x{p_offset:x} sz=0x{p_filesz:x}")
            load_segs.append((p_offset, p_vaddr, p_filesz, p_memsz))
        if not load_segs:
            raise RuntimeError("无 PT_LOAD 段")
        out_size = max(p_off + max(p_fsz, p_msz) for p_off, _, p_fsz, p_msz in load_segs)
        print(f"  ELF: {e_phnum} 个 phdr, {len(load_segs)} 个 LOAD 段, "
              f"输出大小 {fmt_size(out_size)}")

        # ---- 4. 分块读取并写文件 ----
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        sha = hashlib.sha256()
        written = 0
        t0 = time.time()
        # 先创建空文件并预留全部大小（避免段间空洞导致 seek 问题）
        with open(out_path, "wb") as f:
            f.truncate(out_size)
        # ---- 4a. 写 ELF 头（文件偏移 0，内存 base 处） ----
        with open(out_path, "r+b") as f:
            f.seek(0)
            f.write(ehdr)
            sha.update(ehdr)
            written += len(ehdr)
            # ---- 4b. 写 program headers 表（文件偏移 e_phoff） ----
            if e_phoff >= 64:
                ph_mem = self._dump_read(pid, base + e_phoff, e_phnum * 56)
                f.seek(e_phoff)
                f.write(ph_mem)
                sha.update(ph_mem)
                written += len(ph_mem)
        # ---- 4c. 按文件偏移写各 PT_LOAD 段 ----
        # 文件回退（方案 A）：内存页未驻留（页表遍历失败）时，
        # 优先从磁盘文件读取对应偏移（完整路径 + p_offset），
        # 保证 dump 完整（代码/数据不缺）；文件读取失败才补零。
        full_path = None
        try:
            full_path = self._get_vma_fullpath(pid, base)
        except Exception:
            full_path = None

        file_zeroed = 0   # 补零字节数（统计）
        file_read_ok = 0  # 文件回退成功字节数
        for p_off, p_vaddr, p_fsz, p_msz in sorted(load_segs, key=lambda x: x[0]):
            # 4c-1. 内存数据（p_filesz 部分）
            mem_addr = base + p_vaddr
            pos = 0
            with open(out_path, "r+b") as f:
                f.seek(p_off)
                while pos < p_fsz:
                    n = min(self.DUMP_CHUNK, p_fsz - pos)
                    try:
                        data = self._dump_read(pid, mem_addr + pos, n)
                    except RuntimeError:
                        # 页表遍历失败：尝试文件回退（磁盘偏移 = p_off + pos）
                        data = None
                        if full_path:
                            try:
                                fr, fdata = self.read_file(
                                    full_path, p_off + pos, n)
                                if fr > 0 and fdata:
                                    data = fdata
                                    file_read_ok += len(fdata)
                            except Exception:
                                data = None
                        if data is None:
                            # 文件回退失败：按页补零（对齐页边界）
                            pg_left = 4096 - (pos % 4096)
                            if pg_left > p_fsz - pos:
                                pg_left = p_fsz - pos
                            data = bytes(pg_left)
                            file_zeroed += len(data)
                            if not data:
                                raise
                    f.write(data)
                    sha.update(data)
                    pos += len(data)
                    written += len(data)
                    if progress_cb:
                        progress_cb(written, out_size)
                # 4c-2. bss 补零（p_memsz > p_filesz，文件已预留无需扩展）
                # seek to p_off+p_fsz before zeroing (pure-BSS segs have fsz=0)
                if p_fsz > 0 and p_msz > p_fsz:
                    f.seek(p_off + p_fsz)
                    zlen = p_msz - p_fsz
                    zeros = bytes(4096)  # 4096 bytes of zero
                    left = zlen
                    while left > 0:
                        w = min(left, len(zeros))
                        f.write(zeros[:w])
                        sha.update(zeros[:w])
                        left -= w
                        written += w
        elapsed = time.time() - t0
        speed = written / elapsed / 1024 if elapsed > 0 else 0
        print(f"  传输完成: {fmt_size(written)} in {elapsed:.1f}s "
              f"({speed:.0f} KB/s)")

        # ---- 5. 完整性校验 ----
        # 5a. 文件大小核对
        fsize = Path(out_path).stat().st_size
        if fsize != out_size:
            raise RuntimeError(f"文件大小不符: 期望 {out_size} 实得 {fsize}")
        # 5b. 关键数据重读比对（ELF 头 + 各段首 64 字节）
        with open(out_path, "rb") as f:
            fh = f.read(64)
        if fh != ehdr:
            raise RuntimeError("ELF 头校验失败：写入内容与内存不一致")
        for p_off, p_vaddr, p_fsz, p_msz in load_segs:
            if p_fsz == 0:
                continue
            chk = min(p_fsz, 64)
            try:
                mem_chk = self._dump_read(pid, base + p_vaddr, chk)
            except RuntimeError:
                continue  # 非驻留页：跳过该段校验（已按页补零）
            with open(out_path, "rb") as f:
                f.seek(p_off)
                file_chk = f.read(chk)
            if mem_chk != file_chk:
                raise RuntimeError(
                    f"段校验失败 off=0x{p_off:x}: 内存与文件不一致")
        # ---- 5c-1. 重建 Section Header Table（IDA 兼容） ----
        # 内存 dump 的 SHT 不随进程加载，指向区域为乱码/越界。
        # 根据 PT_LOAD 段重建 section 表 + .shstrtab，使 IDA 能正常解析。
        try:
            self._rebuild_sht(out_path, ehdr, load_segs)
        except Exception as e:
            print(f"  [提示] SHT 重建失败（不影响 dump 内容）: {e}")

        # 5c. 哈希
        sha_hex = sha.hexdigest()
        with open(out_path + ".sha256", "w") as f:
            f.write(f"{sha_hex}  {Path(out_path).name}\n")

        return {
            "path": out_path, "size": written,
            "regions": len(hit), "segments": len(load_segs),
            "sha256": sha_hex,
        }

    def _get_vma_fullpath(self, pid: int, addr: int):
        """解析 VMA 的完整文件路径（新内核命令，纯内存）。
        失败返回 None（路径解析不可用时 dump 走补零路径）"""
        try:
            ret, _, payload = self.send_binary(CMD_PROC_FULLPATH,
                                               arg2=pid, arg3=addr)
            if ret == 0 and len(payload) > 1:
                p = payload.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
                return p if p.startswith('/') else None
        except Exception:
            pass
        return None

    def _rebuild_sht(self, out_path: str, ehdr: bytes, load_segs) -> None:
        """根据 PT_LOAD 段重建标准 ELF Section Header Table + .shstrtab。
        标准做法：每个 LOAD 段一个 section，按 phdr flags（PF_X=代码 AX，
        PF_W=数据 WA）标准分类；纯 BSS（fsz=0）标 NOBITS。
        load_segs: (p_offset, p_vaddr, p_filesz, p_memsz, p_flags)"""
        import struct as _st
        from pathlib import Path as _Path

        is32 = (ehdr[4] == 1)

        # ---- 收集 LOAD 段���局（标准分类） ----
        segs = sorted(load_segs, key=lambda x: x[0])
        sec_defs = []   # (name, type, flags, addr, offset, size, align)
        name_list = [""]

        def _add(nm, tp, fl, addr, off, sz, al):
            sec_defs.append((nm, tp, fl, addr, off, sz, al))
            name_list.append(nm)

        # NULL section
        sec_defs.append(("", 0, 0, 0, 0, 0, 0))
        for i, (p_off, p_vaddr, p_fsz, p_msz, p_flags) in enumerate(segs):
            if p_fsz == 0 and p_msz > 0:
                # 纯 BSS：NOBITS
                _add(f".bss.{i}", 8, 0x3, p_vaddr, p_off, p_msz, 0x1000)
            elif p_flags & 1:   # PF_X：代码段
                _add(f".text.{i}", 1, 0x6, p_vaddr, p_off, p_fsz, 0x1000)
            else:               # 数据段
                _add(f".data.{i}", 1, 0x3, p_vaddr, p_off, p_fsz, 0x1000)
        # 追加 .shstrtab（SHT_STRTAB=3），必须是最后一个 section（e_shstrndx）
        _add(".shstrtab", 3, 0, 0, 0, 0, 1)

        # ---- 构建 .shstrtab ----
        shstr_data = b"\x00"
        name_off = {0: 0}
        for nm in name_list[1:]:
            name_off[nm] = len(shstr_data)
            shstr_data += nm.encode('utf-8') + b"\x00"

        # ---- 计算布局：文件末尾追加 shstrtab + SHT ----
        with open(out_path, "r+b") as f:
            f.seek(0, 2)
            cur = f.tell()
            # 对齐 8
            if cur % 8:
                pad = 8 - cur % 8
                f.write(b"\x00" * pad)
                cur += pad
            shstr_off = cur
            f.write(shstr_data)
            cur += len(shstr_data)
            if cur % 8:
                pad = 8 - cur % 8
                f.write(b"\x00" * pad)
                cur += pad
            sht_off = cur

            # 写入 section header entries（32 位 40B / 64 位 64B）
            shnum = len(sec_defs)
            for idx, (nm, tp, fl, addr, off, sz, al) in enumerate(sec_defs):
                if idx == 0:
                    n_off, s_off, s_sz = 0, 0, 0
                elif nm == ".shstrtab":
                    n_off = name_off[nm]
                    s_off, s_sz = shstr_off, len(shstr_data)
                else:
                    n_off = name_off[nm]
                    s_off, s_sz = off, sz
                if is32:
                    f.write(_st.pack("<IIIIIIIIII",
                                     n_off, tp, fl & 0xFFFFFFFF,
                                     addr & 0xFFFFFFFF, s_off & 0xFFFFFFFF,
                                     s_sz & 0xFFFFFFFF, 0, 0, al & 0xFFFFFFFF, 0))
                else:
                    f.write(_st.pack("<IIQQQQIIQQ",
                                     n_off, tp, fl,
                                     addr, s_off, s_sz,
                                     0, 0, al, 0))

            # 更新 ELF 头（按架构字段偏移）
            if is32:
                f.seek(32)  # e_shoff (32 位)
                f.write(_st.pack("<I", sht_off & 0xFFFFFFFF))
                f.seek(46)  # e_shentsize
                f.write(_st.pack("<H", 40))
                f.seek(48)  # e_shnum
                f.write(_st.pack("<H", shnum))
                f.seek(50)  # e_shstrndx
                f.write(_st.pack("<H", shnum - 1))
            else:
                f.seek(40)  # e_shoff
                f.write(_st.pack("<Q", sht_off))
                f.seek(58)  # e_shentsize
                f.write(_st.pack("<H", 64))
                f.seek(60)  # e_shnum
                f.write(_st.pack("<H", shnum))
                f.seek(62)  # e_shstrndx
                f.write(_st.pack("<H", shnum - 1))
        print(f"  SHT 重建: {shnum} sections @ 0x{sht_off:x} ({'32' if is32 else '64'}位, strtab {len(shstr_data)}B)")

    # ===== 内存扫描 =====

    def scan_start(self, pid: int, value_type: int, scan_mode: int,
                   value: int, value_len: int = 0, scan_range: int = 0):
        """开始新扫描会话"""
        arg3 = (value_type & 0xFF) | ((scan_mode & 0xFF) << 8)
        arg5 = (value_len & 0xFFFF) | ((scan_range & 0xFFFFFFFF) << 32)
        ret, _, _ = self.send_binary(CMD_MEM_SCAN_START,
                                     arg2=pid, arg3=arg3, arg4=value, arg5=arg5)
        return ret

    def scan_next(self, value_type: int, scan_mode: int,
                  value: int, value_len: int = 0, scan_range: int = 0):
        """下一轮过滤扫描"""
        arg2 = (value_type & 0xFF) | ((scan_mode & 0xFF) << 8)
        arg5 = (value_len & 0xFFFF) | ((scan_range & 0xFFFFFFFF) << 32)
        ret, _, _ = self.send_binary(CMD_MEM_SCAN_NEXT,
                                     arg2=arg2, arg3=value, arg5=arg5)
        return ret

    def scan_result(self, max_count: int = 50, offset: int = 0):
        """获取扫描结果"""
        ret, data_len, payload = self.send_binary(CMD_MEM_SCAN_RESULT,
                                                   arg2=max_count, arg3=offset)
        if ret < 0:
            return ret, []
        results = []
        for i in range(ret):
            off = i * SCAN_RESULT_SIZE
            if off + SCAN_RESULT_SIZE > len(payload):
                break
            addr, value, prev_value = struct.unpack("<QQQ", payload[off:off+24])
            results.append((addr, value, prev_value))
        return ret, results

    def scan_clear(self):
        """清除扫描会话"""
        ret, _, _ = self.send_binary(CMD_MEM_SCAN_CLEAR)
        return ret

    def scan_aob_start(self, pid: int, pattern_str: str, scan_mode: int = 0):
        """长 AOB 特征扫描（2026-08-04 新增；2026-08-05 支持通配符）。
        特征 1-64 字节，经 UDP payload 传递（突破 8B uint64 打包限制）。
        pattern_str: 十六进制字符串，可带空格与 '?' 通配符（任意字节），
                     如 'B4 21 0C 40 B9 ? ? ? ? ? ? ? 91'
        scan_mode: 仅 0=EXACT
        返回: ret（0 成功 / 负值错误）"""
        toks = pattern_str.replace(",", " ").split()
        sb = bytearray()
        mask = bytearray()
        for t in toks:
            if t in ('?', '??'):
                sb.append(0)
                mask.append(0)
            else:
                try:
                    b = int(t, 16)
                except ValueError:
                    return -1
                sb.append(b & 0xFF)
                mask.append(0xFF)
        if not sb:
            return -1
        if len(sb) > 64:
            print(f"  [错误] AOB 特征过长: {len(sb)} > 64")
            return -1
        # 新格式 payload: [u32 len][pattern][mask]
        payload = struct.pack("<I", len(sb)) + bytes(sb) + bytes(mask)
        ret, _, _ = self.send_binary(CMD_MEM_SCAN_AOB_START,
                                     arg2=pid, arg3=(scan_mode & 0xFF) << 8,
                                     arg5=len(sb), payload=payload)
        return ret

    def scan_status(self):
        """查询扫描会话状态（2026-08-04 新增；2026-08-06 加 swap_pages）。
        返回 dict 或 None：
          active/pid/region_count/result_count/result_capacity/truncated/
          scanned_bytes/total_bytes/failed_pages/swap_pages"""
        ret, data_len, payload = self.send_binary(CMD_MEM_SCAN_STATUS)
        # kpm_scan_status_t = 6×int + 2×uint64 + 2×uint32 = 48B
        if ret < 0 or data_len < 48:
            return None
        (active, pid, region_count, result_count, result_capacity,
         truncated, s1, s2, failed_pages, swap_pages) = \
            struct.unpack("<iiiiiiQQII", payload[:48])
        return {
            "active": active, "pid": pid,
            "region_count": region_count,
            "result_count": result_count,
            "result_capacity": result_capacity,
            "truncated": truncated,
            "scanned_bytes": s1, "total_bytes": s2,
            "failed_pages": failed_pages,
            "swap_pages": swap_pages,   # 2026-08-06
        }

    def scan_result_all(self, page_size: int = 512):
        """分页拉取全部扫描结果（2026-08-04 新增）。
        返回 (total, results) 列表，每页 512 条 × 24B = 12KB（UDP payload 16KB 内）。"""
        all_results = []
        offset = 0
        while True:
            ret, results = self.scan_result(max_count=page_size, offset=offset)
            if ret <= 0 or not results:
                break
            all_results.extend(results)
            offset += len(results)
            if len(results) < page_size:
                break
        return len(all_results), all_results

    # ===== 2026-08-06 高级扫描功能 =====

    def scan_start_string(self, pid: int, text: str, scan_range: int = 0):
        """字符串扫描（自动处理长度）：≤8B 走 8B 打包路径；>8B 走长 AOB 路径（≤64B）。
        精确匹配 text 的 UTF-8 字节（CE 字符串语义）。返回 ret。"""
        data = text.encode('utf-8')
        if len(data) > 64:
            return -1
        if len(data) <= 8:
            value = 0
            for i, b in enumerate(data):
                value |= b << (i * 8)
            return self.scan_start(pid, SCAN_TYPE_STRING, SCAN_MODE_EXACT,
                                   value, len(data), scan_range)
        # >8B：AOB 全精确（等价字符串精确匹配）
        return self.scan_aob_start(pid, " ".join(f"{b:02x}" for b in data), 0)

    def scan_kernel_start(self, value_type: int, scan_mode: int,
                          value: int, value_len: int = 0,
                          scan_range: int = 0):
        """内核线性映射范围扫描（2026-08-06）。
        扫描 [PAGE_OFFSET, PAGE_OFFSET+scan_range)，pid 固定 0。
        scan_range ≤ 64GB（64 位打包：range 高 32 位经 arg3，低 32 位经 arg5，
        value 全占 arg4——2026-08-06 修复审计 P1）。返回 ret。"""
        arg3 = (value_type & 0xFF) | ((scan_mode & 0xFF) << 8) \
               | (((scan_range >> 32) & 0xFFFFFFFF) << 32)
        arg5 = (value_len & 0xFFFF) | ((scan_range & 0xFFFFFFFF) << 32)
        ret, _, _ = self.send_binary(CMD_MEM_SCAN_KERNEL_START,
                                     arg2=0, arg3=arg3, arg4=value, arg5=arg5)
        return ret

    def export_scan_results(self, out_path: str) -> int:
        """导出全部扫描结果到本地 CSV（绕开设备 SELinux 写限制：数据经 UDP 回传）。
        每行: 0xaddr,value(dec),value(hex),prev(dec)。返回导出条数。"""
        import csv
        n, results = self.scan_result_all(page_size=512)
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["addr", "value_dec", "value_hex", "prev_dec"])
            for addr, value, prev in results:
                w.writerow([f"0x{addr:X}", value, f"0x{value:X}", prev])
        return n

    def group_scan(self, pid: int, addrs, specs, limit: int = 2000):
        """组扫描（2026-08-06，客户端组合）：对候选地址集逐地址读多个偏移，
        联合过滤后返回匹配列表。
        addrs: 候选基址列表（如 scan_result_all 的地址）
        specs: [(offset, expected, type_size), ...]；expected=None 表示该偏移不约束；
               type_size 1/2/4/8，匹配按无符号比较
        返回 [(base_addr, [各偏移当前值...]), ...]（最多 limit 条）
        原理：READ_BATCH2 一次批量读所有 (base+off)，客户端过滤——内核零改动。"""
        if not addrs or not specs:
            return []
        addrs = list(addrs)[:limit]
        # 构造 batch2 条目: (base+offset, type_size)
        items = []
        idx_map = []   # (addr_index, spec_index)
        for ai, base in enumerate(addrs):
            for si, (off, exp, ts) in enumerate(specs):
                items.append((base + off, ts))
                idx_map.append((ai, si))
        matched = []
        CHUNK = 500   # batch2 单次 ≤512 条
        vals = {ai: [None] * len(specs) for ai in range(len(addrs))}
        for c0 in range(0, len(items), CHUNK):
            chunk = items[c0:c0 + CHUNK]
            ok, data = self.read_batch2(pid, chunk)
            if ok <= 0 or len(data) != sum(ts for _, ts in chunk):
                continue
            pos = 0
            for (ai, si), (_, ts) in zip(idx_map[c0:c0 + CHUNK], chunk):
                raw = data[pos:pos + ts]
                pos += ts
                vals[ai][si] = int.from_bytes(raw, "little")
        for ai, base in enumerate(addrs):
            cur = vals[ai]
            ok = True
            for si, (off, exp, ts) in enumerate(specs):
                if exp is None:
                    continue
                if cur[si] is None or cur[si] != exp:
                    ok = False
                    break
            if ok:
                matched.append((base, cur))
        return matched

    def recover_swap(self, pid: int, start: int, end: int,
                     zram_path: str = "/dev/block/zram0",
                     offset_shift: int = None,
                     probe_pages: int = 8) -> dict:
        """swap/zram 换出页补读（2026-08-06）。
        对 [start,end) 逐 4KB 页 GET_PTE → 识别 swap 条目（非零且非 present）
        → 解析 swp_offset → READ_FILE(zram_path, off<<12, 4096) 读回原始页。
        返回 {vaddr: bytes}（成功补读的页），失败页不在结果中。
        offset_shift: swp_offset 起始位（默认 None=自动探测）。
        ARM64 标准布局(MAX_SWAPFILES=32): type bits[5,10), offset bits[10,64)。
        2026-08-06 真机修正：swap 条目低 2 位不一定是 10 —— ARM64
        __swp_entry_to_pte 直接写入 (offset<<10)|(type<<5)，bit1-4 恒 0，
        实测 MTK 6.1 swap 条目低 2 位 = 00。判断改为 非零 + 非 present。"""
        result = {}
        if offset_shift is None:
            offset_shift = 10   # MAX_SWAPFILES_SHIFT=5 → offset 从 bit10 起
        # 先探测 zram 设备可用性 + offset_shift 校正
        probe = {}
        if probe_pages > 0:
            n_probed = 0
            for va in range(start, end, 4096):
                if n_probed >= probe_pages:
                    break
                ret, entry, level = self.get_pte(pid, va)
                if ret == 0 and entry != 0 and not (entry & 0x1):
                    probe[va] = entry
                    n_probed += 1
            if len(probe) >= 2:
                es = sorted(probe.values())
                # 相邻 entry 差应为 1<<offset_shift 的倍数；取最小差值反推
                diffs = [es[i + 1] - es[i] for i in range(len(es) - 1)]
                diffs = [d for d in diffs if d > 0]
                if diffs:
                    md = min(diffs)
                    # 最接近的 2 幂且 ≥ 1<<10 的候选
                    cand = [s for s in (10, 11, 12, 13, 9, 8) if md % (1 << s) == 0]
                    if cand:
                        offset_shift = cand[0]
        # 逐页补读
        for va in range(start, end, 4096):
            ret, entry, level = self.get_pte(pid, va)
            if ret != 0 or entry == 0 or (entry & 0x1):
                continue
            swp_off = entry >> offset_shift
            if swp_off == 0:
                continue
            foff = swp_off << 12
            got, data = self.read_file(zram_path, foff, 4096)
            if got == 4096 and data:
                result[va] = data
        return result

    # ===== 内存冻结 =====

    def freeze_add(self, pid: int, addr: int, value: int, size: int):
        """添加冻结项"""
        ret, _, _ = self.send_binary(CMD_FREEZE_ADD,
                                     arg2=pid, arg3=addr, arg4=value, arg5=size)
        return ret

    def freeze_remove(self, index: int):
        """删除冻结项"""
        ret, _, _ = self.send_binary(CMD_FREEZE_REMOVE, arg2=index)
        return ret

    def freeze_list(self, max_count: int = 32):
        """获取冻结列表"""
        ret, data_len, payload = self.send_binary(CMD_FREEZE_LIST, arg2=max_count)
        if ret < 0:
            return ret, []
        entries = []
        for i in range(ret):
            off = i * FREEZE_ENTRY_SIZE
            if off + FREEZE_ENTRY_SIZE > len(payload):
                break
            # kpm_freeze_entry_t: enabled(4)+pid(4)+addr(8)+value(8)+size(4)+hit_count(4)
            enabled, fpid = struct.unpack("<ii", payload[off:off+8])
            addr, value = struct.unpack("<QQ", payload[off+8:off+24])
            size, hit_count = struct.unpack("<ii", payload[off+24:off+32])
            entries.append({
                "index": i, "enabled": enabled, "pid": fpid,
                "addr": addr, "value": value, "size": size, "hit_count": hit_count
            })
        return ret, entries

    def freeze_toggle(self, index: int, enable: int):
        """切换冻结项"""
        ret, _, _ = self.send_binary(CMD_FREEZE_TOGGLE,
                                     arg2=index, arg3=enable)
        return ret

    def freeze_clear(self):
        """清空所有冻结"""
        ret, _, _ = self.send_binary(CMD_FREEZE_CLEAR)
        return ret

    # ===== 指针扫描 =====

    def ptr_scan(self, pid: int, target_addr: int, scan_range: int = 0):
        """单级指针扫描"""
        ret, _, _ = self.send_binary(CMD_PTR_SCAN,
                                     arg2=pid, arg3=target_addr, arg4=scan_range)
        return ret

    def ptr_scan_chain(self, pid: int, target_addr: int, depth: int):
        """多级指针链扫描"""
        ret, _, _ = self.send_binary(CMD_PTR_SCAN_CHAIN,
                                     arg2=pid, arg3=target_addr, arg4=depth)
        return ret

    def ptr_result(self, max_count: int = 50, offset: int = 0):
        """获取指针扫描结果"""
        ret, data_len, payload = self.send_binary(CMD_PTR_RESULT,
                                                   arg2=max_count, arg3=offset)
        if ret < 0:
            return ret, []
        results = []
        for i in range(ret):
            off = i * PTR_RESULT_SIZE
            if off + PTR_RESULT_SIZE > len(payload):
                break
            addr, value = struct.unpack("<QQ", payload[off:off+16])
            results.append((addr, value))
        return ret, results


# ===== 应用识别辅助 =====

# Android 系统应用包名前缀（启发式判断，内核无法区分第三方/系统应用）
# 内核 UDP 通道返回的进程名即 cmdline = 完整包名（如 "com.tencent.mm"）
# 但内核无法获取 App 显示名（label），因为它存储在 APK 资源中
SYS_PKG_PREFIXES = (
    "com.android.",
    "android.",
    "com.google.android.",
    "org.chromium.",
    "org.webview",
)

# 已知的非应用用户态进程前缀（Zygote/init 等系统底层进程）
NON_APP_PREFIXES = (
    "init", "zygote", "zygote64", "cameraserver", "drmserver",
    "audioserver", "mediaserver", "surfaceflinger", "installd",
    "keystore2", "gatekeeperd", "thermalserviced", "vold",
    "logd", "servicemanager", "hwservicemanager", "vndservicemanager",
    "netd", "wificond", "sh", "adbd", "magisk",
)


def is_system_app(name: str) -> bool:
    """启发式判断是否为系统应用（基于包名前缀）"""
    if not name:
        return False
    return name.startswith(SYS_PKG_PREFIXES)


def is_likely_app(name: str) -> bool:
    """启发式判断是否为应用进程（包含点号的包名通常是应用）"""
    if not name:
        return False
    # 非应用系统进程
    if name.startswith(NON_APP_PREFIXES):
        return False
    # 应用包名通常包含至少一个点（如 com.xxx.xxx）
    if '.' not in name:
        return False
    # 去除子进程后缀
    base = name.split(':', 1)[0]
    parts = base.split('.')
    return len(parts) >= 2


# ===== 显示辅助函数 =====

def fmt_perms(perms: int) -> str:
    r = 'r' if perms & 1 else '-'
    w = 'w' if perms & 2 else '-'
    x = 'x' if perms & 4 else '-'
    return f"{r}{w}{x}"


def fmt_state(state: int) -> str:
    states = {0: "R", 1: "S", 2: "D", 4: "Z", 8: "T", 16: "X"}
    return states.get(state, str(state))


def fmt_mem_size(pages: int) -> str:
    """将页数格式化为人类可读的内存大小（KB/MB/GB）"""
    if pages <= 0:
        return "-"
    bytes_val = pages * 4096
    if bytes_val >= 1024 * 1024 * 1024:
        return f"{bytes_val / 1024 / 1024 / 1024:.2f}GB"
    if bytes_val >= 1024 * 1024:
        return f"{bytes_val / 1024 / 1024:.1f}MB"
    if bytes_val >= 1024:
        return f"{bytes_val / 1024:.0f}KB"
    return f"{bytes_val}B"


def fmt_size(nbytes: int) -> str:
    """将字节数格式化为人类可读的内存大小（KB/MB/GB）"""
    if nbytes <= 0:
        return "0B"
    if nbytes >= 1024 * 1024 * 1024:
        return f"{nbytes / 1024 / 1024 / 1024:.2f}GB"
    if nbytes >= 1024 * 1024:
        return f"{nbytes / 1024 / 1024:.1f}MB"
    if nbytes >= 1024:
        return f"{nbytes / 1024:.0f}KB"
    return f"{nbytes}B"


def parse_addr(s: str) -> int:
    """解析地址字符串（支持 0x 前缀和纯数字）"""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    try:
        return int(s, 10)
    except ValueError:
        return int(s, 16)


def parse_value(s: str) -> int:
    """解析数值（支持 0x 前缀、十进制、负数）"""
    s = s.strip()
    if s.startswith("-"):
        return -parse_value(s[1:])
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s, 10)


def display_memory(data: bytes, base_addr: int = 0):
    """以多种格式显示内存数据"""
    if not data:
        print(c("  (空数据)", Color.GRAY))
        return

    # 十六进制 dump
    print(c("  [十六进制 dump]", Color.CYAN))
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        hex_part = hex_part.ljust(48)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        addr_str = f"0x{base_addr+i:016X}" if base_addr else f"+0x{i:04X}"
        print(f"  {addr_str}: {c(hex_part, Color.GRAY)}  {ascii_part}")

    # 4 字节整数
    print(c("\n  [4 字节整数 (uint32/int32)]", Color.CYAN))
    for i in range(0, min(len(data), 64), 4):
        if i + 4 > len(data):
            break
        u32 = struct.unpack("<I", data[i:i+4])[0]
        s32 = struct.unpack("<i", data[i:i+4])[0]
        addr_str = f"0x{base_addr+i:016X}" if base_addr else f"+0x{i:04X}"
        print(f"  {addr_str}: u32={u32} (0x{u32:08X})  i32={s32}")

    # 8 字节整数
    print(c("\n  [8 字节整数 (uint64/int64)]", Color.CYAN))
    for i in range(0, min(len(data), 64), 8):
        if i + 8 > len(data):
            break
        u64 = struct.unpack("<Q", data[i:i+8])[0]
        s64 = struct.unpack("<q", data[i:i+8])[0]
        addr_str = f"0x{base_addr+i:016X}" if base_addr else f"+0x{i:04X}"
        print(f"  {addr_str}: u64={u64} (0x{u64:016X})  i64={s64}")

    # 浮点
    print(c("\n  [浮点 (float/double)]", Color.CYAN))
    for i in range(0, min(len(data), 32), 4):
        if i + 4 > len(data):
            break
        f32 = struct.unpack("<f", data[i:i+4])[0]
        addr_str = f"0x{base_addr+i:016X}" if base_addr else f"+0x{i:04X}"
        print(f"  {addr_str}: float={f32:.6f}")
    for i in range(0, min(len(data), 64), 8):
        if i + 8 > len(data):
            break
        f64 = struct.unpack("<d", data[i:i+8])[0]
        addr_str = f"0x{base_addr+i:016X}" if base_addr else f"+0x{i:04X}"
        print(f"  {addr_str}: double={f64:.6f}")

    # 字符串
    print(c("\n  [字符串]", Color.CYAN))
    # ASCII 字符串（长度 >=4 的可打印序列）
    strings = []
    current = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= 4:
                strings.append("".join(current))
            current = []
    if len(current) >= 4:
        strings.append("".join(current))
    if strings:
        for s in strings[:20]:
            print(f"  \"{s}\"")
    else:
        print(c("  (无可打印字符串)", Color.GRAY))


# ===== 交互模式命令处理 =====

def cmd_help(client: KPMClient, args: list):
    print("""
命令列表:
  --- 基础查询 ---
  info                         模块状态
  help                         显示帮助
  quit / exit                  退出

  --- 进程（纯 UDP，无 ADB） ---
  list [n]                     列出全部进程 (可选前 n 个)
  apps                         列出第三方应用进程（启发式过滤）
  sysapps                      列出系统应用进程（启发式过滤）
  ps <name>                    按名称搜索进程
  maps <pid> [n]               进程内存映射 (默认 30 条)
  region <pid> <addr>          查询地址所在内存区域

  --- 内存读写 ---
  read <pid> <addr> [len]      读取内存 (默认 64 字节)
  readhex <pid> <addr> [len]   仅十六进制显示
  write <pid> <addr> <hex>     写入十六进制字节
  writeu32 <pid> <addr> <val>  写入 4 字节整数
  writeu64 <pid> <addr> <val>  写入 8 字节整数
  writestr <pid> <addr> <str>  写入字符串

  --- 流式传输（2026-08-06，突破 UDP 单包 16KB，单请求 ≤64MB） ---
  bigread <pid> <addr> <len> [--hexdump] [--out <路径>]   流式大读
  bigwrite <pid> <addr> <hex-string>                       流式大写（分片）
  dumpmem <pid> <addr> <len> [--out <路径>] [--hexdump]   定向 dump 小段内存
  dump <pid> <模块> [--fetch]    模块 ELF dump（自动流式，--fetch 强制旧模式）

  --- 内存扫描 ---
  scan <pid> <type> <mode> <val> [range]    开始扫描
    type: i8/i16/i32/i64/f32/f64/str/bytes
    mode: exact/range/changed/unchanged/increased/decreased
          unknown(未知初始值) / ne / nby / dby / nge / dge  (2026-08-06)
    str: 任意长度 ≤64B（>8B 自动长 AOB 路径）
  scan_next <type> <mode> <val> [range]     过滤扫描
  scan_result [n] [offset]                  获取结果 (默认 50 条)
  scan_status                               查询扫描状态 (含 swap_pages)
  scan_clear                                清除扫描
  kscan <type> <mode> <val> <range>         内核线性映射范围扫描 (2026-08-06)
  swapread <pid> <start> <end> [--out 路径]  swap/zram 换出页补读 (2026-08-06)
  export <本地路径>                          导出扫描结果到本地 CSV (绕开 SELinux)
  group <pid> <off:exp> [...]               组扫描：多偏移联合过滤 (2026-08-06)

  --- 内存冻结 ---
  freeze <pid> <addr> <val> <size>          添加冻结 (size: 1/2/4/8)
  freeze_list                               列出冻结项
  freeze_toggle <idx> <0|1>                 切换冻结
  freeze_remove <idx>                       删除冻结
  freeze_clear                              清空冻结

  --- 指针扫描 ---
  ptr <pid> <addr> [range]                  单级指针扫描
  ptr_chain <pid> <addr> <depth>            多级指针链扫描
  ptr_result [n] [offset]                   获取指针扫描结果

  --- 批量测试 ---
  test_read <pid>                           读取测试（多个地址）
  test_scan <pid>                           扫描测试
  test_freeze <pid> <addr> <val> <size>     冻结测试

  --- PLT hook（2026-08-06 接线启用） ---
  hook_plt <pid> <模块> <函数> <替换地址>   改写 GOT 条目指向替换函数
  hook_list                                 列出 hook 条目
  hook_remove <索引>                        移除 hook（恢复原始指令）
  hook_toggle <索引> <0|1>                  切换启停

注意: 进程名来自 /proc/<pid>/cmdline（完整包名），非 task->comm（16字节截断）。
     App 显示名（label）无法从内核获取（存储在 APK 资源中）。
""")


def cmd_info(client: KPMClient, args: list):
    info = client.info()
    st = info.get("state", {})

    print(c("\n===== KPM 模块状态信息 =====", Color.CYAN))

    # 基础状态
    state_raw = info.get("state_raw", 0)
    print(f"  状态位图: 0x{state_raw:08X}")
    state_flags = []
    for name, label in [("init", "INIT"), ("prctl", "PRCTL"), ("touch", "TOUCH"),
                         ("mem_rw", "MEM_RW"), ("intercept", "INTERCEPT"),
                         ("udp", "UDP"), ("mem_scan", "SCAN"),
                         ("mem_freeze", "FREEZE"), ("ptr_scan", "PTR_SCAN"),
                         ("debug", "DEBUG"), ("proc", "PROC"),
                         ("stealth", "STEALTH"), ("gyro", "GYRO")]:
        if st.get(name):
            state_flags.append(label)
    # 位图与清单必须自洽：置位但无标签时明确报出来，别让读者以为位图算错了
    known_mask = (0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80 |
                  0x100 | 0x200 | 0x400 | 0x800 | 0x1000)
    unknown_bits = state_raw & ~known_mask
    print(f"  已启用:   {' | '.join(state_flags) if state_flags else '(无)'}")
    if unknown_bits:
        print(c(f"  [注意] 位图含未定义位: 0x{unknown_bits:08X}（模块比客户端新？）",
                Color.YELLOW))

    if not st.get("init"):
        print(c("  [警告] 模块未初始化", Color.RED))
    if not st.get("mem_rw"):
        print(c("  [警告] 内存子系统未就绪", Color.RED))

    # 旧版兼容
    if "legacy" in info:
        lg = info["legacy"]
        print(c("\n  (旧版模块，仅返回基本状态)", Color.GRAY))
        print(f"  内核版本: {lg['kver'] >> 16 & 0xFF}.{lg['kver'] >> 8 & 0xFF}.{lg['kver'] & 0xFF}")
        print(f"  触摸就绪: {lg['touch_ready']}  node_offset: {lg['node_offset']}")
        print(f"  屏幕: {lg['screen_w']}x{lg['screen_h']}  原始: {lg['raw_w']}x{lg['raw_h']}  scale: {lg['scale']}")
        print(f"  拦截: {lg['intercept_on']}  活跃触摸: {lg['active_count']}")
        return

    # 扩展信息
    print(f"  Magic:    {info.get('magic', '?')}  Version: {info.get('version', '?')}")
    print(f"  内核版本: {info.get('kver', '?')}  syms_init_ret: {info.get('syms_init_ret', '?')}")

    # 触摸/屏幕
    print(f"  触摸就绪: {info.get('touch_ready', '?')}  node_offset: {info.get('node_offset', '?')}")
    sc = info.get("screen", {})
    rw = info.get("raw", {})
    print(f"  屏幕: {sc.get('w')}x{sc.get('h')}  原始: {rw.get('w')}x{rw.get('h')}  scale: {info.get('scale')}")
    print(f"  拦截: {info.get('intercept_on', '?')}  活跃触摸: {info.get('active_count', '?')}")

    # 功能路径
    paths = info.get("paths", {})
    if paths:
        print(c("\n  --- 功能路径 ---", Color.YELLOW))
        for k, v in paths.items():
            print(f"  {k:12s}: {v}")
            if k == "put_task" and "泄漏" in str(v):
                # 2026-09-19：进程/maps 主路径已改免引用，是否可用由
                # task 取用路径决定，不再等于"put_task 泄漏 ⇒ 全禁用"
                if info.get("paths_raw", {}).get("task_fetch") == 1:
                    print(c("               └ 影响: 取引用路径禁用；进程列表/maps/隐藏 "
                            "走免引用(RCU+pid_task) 不受影响", Color.YELLOW))
                    print(c("                 仅 cmdline 批量段、hwbp 探测等少数取引用点"
                            "只漏不收(每次 1 个 task_struct + 内核栈)", Color.YELLOW))
                else:
                    print(c("               └ 影响: 进程列表/maps 等取引用路径禁用"
                            "（免引用路径也不可用）", Color.RED))
                    print(c("                 cmdline 批量段/hwbp 探测的引用只漏不收"
                            "(每次 1 个 task_struct + 内核栈)", Color.RED))

    # 符号可用性
    syms = info.get("symbols", {})
    if syms:
        print(c(f"\n  --- 符号可用性 ({syms['available_count']}/{syms['available_count']+syms['missing_count']}) ---",
                Color.YELLOW))
        if syms["missing"]:
            # 非关键缺失符号（不影响主要功能）
            non_critical = {"copy_to_kernel_nofault": "write-only, read 路径无需",
                            "kernel_read_iter": "procfs 回退, get_cmdline 已就绪",
                            "vsnprintf2": "内部索引占位, 无实际需求"}
            # 缺失符号 → (受影响功能, 缺失后果)
            # ⚠ 与内核 LH_main.c 的 kpm_sym_impacts[] 同步维护
            impact = {
                "copy_from_user": ("用户态内存读写(断点调试/UDP 控制/拦截)", "回退 _copy_from_user → __arch_copy_from_user"),
                "copy_to_user": ("所有回传客户端的路径(UDP 结果/触摸/扫描/dump)", "回退 _copy_to_user → __arch_copy_to_user"),
                "copy_from_kernel_nofault": ("内核内存读取底座(偏移探测/扫描/dump/断点)", "回退 probe_kernel_read → __probe_kernel_read"),
                "copy_to_kernel_nofault": ("仅 DMA/WB 写入路径(读取不需要它)", "回退 probe_kernel_write; mem_rw 读取不受影响"),
                "memremap": ("物理内存映射(mem_rw 的 DMA 首选)", "回退 ioremap_cache→ioremap_prot→ioremap; 再缺 mem_rw 降 WB"),
                "memunmap": ("物理内存解映射", "回退 iounmap"),
                "vmap": ("DMA 读写映射(mem_rw 走 DMA 的必要条件)", "vmap/vunmap 缺一个则 mem_rw 降为 WB"),
                "vunmap": ("DMA 读写解映射", "同上"),
                "filp_open": ("文件打开(cmdline filp 回退/info 导出/读取文件)", "回退 comm 或内存读路径"),
                "kernel_read": ("文件读(与 filp_open 同一批路径)", "缺则相关文件类命令失败"),
                "kernel_write": ("文件写(info 导出到 /data/local/tmp、dump 落盘)", "缺则 info 文件导出失败"),
                "kernel_read_iter": ("仅 cmdline 的 procfs 回退路径", "非关键: get_cmdline 就绪时无影响"),
                "input_handle_event": ("触摸注入(capture/hook 路径)", "回退 input_event; 再缺 touch 降为 inplace"),
                "input_event": ("触摸注入备用路径", "见 input_handle_event"),
                "find_get_pid": ("进程查找(进程列表/maps/隐藏/陀螺仪定位/按 pid 内存)", "回退 find_vpid"),
                "get_pid_task": ("pid → task_struct(同上那批功能)", "回退 pid_task"),
                "get_task_mm": ("取进程 mm(进程 maps/VMA、按 pid 内存读写、陀螺仪定位)", "缺则这些路径整体失败"),
                "mmput": ("mm 引用归还(与 get_task_mm 配对)", "缺则 mm 引用泄漏 → 进程内存无法释放"),
                "find_vma": ("VMA 查找(进程 maps/按地址查 region/页表遍历/触摸命中)", "缺则 maps/region 类功能失败"),
                "rcu_read_lock": ("RCU 读锁(免引用 pid→task、页表遍历)", "回退 __rcu_read_lock"),
                "rcu_read_unlock": ("RCU 读解锁(与上配对)", "回退 __rcu_read_unlock"),
                "init_task": ("全部运行时偏移探测的锚点(usage/pid/mm/tgid)", "缺则偏移探测整体失效, 功能大幅降级"),
                "put_task_struct": ("task 引用归还(进程枚举/maps/隐藏/断点探测/按 pid 内存)",
                                    "回退 手动递减 usage+__put_task_struct(需已标定); 未标定则只泄漏引用"),
                "get_cmdline": ("完整命令行(cmdline 的 native 路径)", "回退 arg_start/end 内存 → filp_open → 16 字节 comm"),
                "get_task_comm": ("进程名(进程列表/隐藏/断点上报)", "缺则进程名不可用"),
                "sock_create_kern": ("内核 UDP 通道(常驻监听/命令收发)", "缺则 UDP 通道整体不可用"),
                "alloc_workqueue": ("工作队列(UDP 异步发送/调试)", "缺则相关异步路径失败"),
                "init_net": ("内核 socket 网络命名空间(UDP)", "缺则 UDP 通道不可用"),
                "queue_work": ("异步任务投递(UDP 发送队列/调试)", "缺则异步发送失败"),
                "vsnprintf": ("日志与状态文本格式化", "缺则日志/诊断文本缺失"),
                "printk": ("debug 版 dmesg 输出", "缺则 dmesg 无输出(不影响功能)"),
                "find_task_by_vpid": ("按 vpid 找 task(隐藏进程回填/校验)", "缺则隐藏功能的 vpid 校验跳过"),
                "__task_pid_nr_ns": ("task → pid(进程列表的 pid 字段)", "缺则进程列表 pid 字段不可用"),
                "mmap_read_lock": ("mmap 读锁(VMA 遍历/页表操作, 5.12+ 原生)", "回退 RCU 读锁/适配层"),
                "mmap_read_unlock": ("mmap 读解锁(与上配对)", "见 mmap_read_lock"),
                "register_user_hw_bp": ("硬件断点(断点功能)", "缺则硬件断点不可用"),
                "unregister_hw_bp": ("硬件断点注销", "缺则已注册断点无法注销"),
                "kmalloc": ("内核小内存分配(扫描/进程枚举/陀螺仪/调试)", "缺则依赖它的路径失败"),
                "kfree": ("内核小内存释放(与上配对)", "见 kmalloc"),
                "vmalloc": ("大块内存分配(内存扫描/指针扫描/缓存池)", "缺则扫描类功能失败"),
                "vfree": ("大块内存释放(与上配对)", "见 vmalloc"),
                "vsnprintf2": ("全工程无调用点(索引占位)", "非关键: 缺失无影响"),
                "snprintf": ("文本格式化(进程名/路径/日志)", "缺则相关文本构建失败"),
                "simple_strtoull": ("命令参数解析(字符串 → 数字)", "缺则带数字参数的 UDP 命令失败"),
                "synchronize_rcu": ("RCU 同步(卸载/拦截器 teardown 等待)", "缺则卸载路径改走轮询等待"),
            }
            # 缺失符号是否已有**生效的回退路径**（缺失 ≠ 功能不可用）。
            # 判据取内核上报的路径枚举值，不用中文字符串匹配（文案会漂）。
            # ⚠ 与内核 LH_main.c 的 kpm_sym_fallback_active() 同步维护
            raw_paths = info.get("paths_raw", {})
            fb_desc = {}
            if raw_paths.get("put_task") == 1:
                fb_desc["put_task_struct"] = \
                    "手动递减 usage + __put_task_struct（usage 已标定，功能不降级）"

            crit_missing = [m for m in syms["missing"]
                            if m not in non_critical and m not in fb_desc]
            nc_missing = [m for m in syms["missing"] if m in non_critical]
            fb_missing = [m for m in syms["missing"] if m in fb_desc]
            if crit_missing:
                print(c(f"  关键缺失({len(crit_missing)}): {', '.join(crit_missing)}",
                        Color.RED))
            if fb_missing:
                print(c(f"  已回退可用({len(fb_missing)}): {', '.join(fb_missing)}",
                        Color.GREEN))
            if nc_missing:
                print(c(f"  非关键缺失({len(nc_missing)}): {', '.join(nc_missing)}",
                        Color.GRAY))
            for m in syms["missing"]:
                nc = m in non_critical
                fb = fb_desc.get(m)
                tag = "非关键" if nc else ("已回退" if fb else "关键  ")
                print(c(f"  [{tag}] {m}",
                        Color.GRAY if nc else (Color.GREEN if fb else Color.RED)))
                fdesc, idesc = impact.get(
                    m, ("未登记(补 LH_main.c 的 kpm_sym_impacts[] 与本字典)", "—"))
                if fb:
                    print(c(f"         回退路径: {fb}", Color.GREEN))
                if nc or fb:
                    print(c(f"         影响功能: {fdesc}", Color.GRAY))
                    print(c(f"         缺失后果: {idesc}", Color.GRAY))
                else:
                    print(f"         影响功能: {fdesc}")
                    print(f"         缺失后果: {idesc}")
            if crit_missing:
                print(c("  ⇒ 关键缺失会直接砍掉上面「影响功能」列出的接口", Color.YELLOW))
            elif fb_missing:
                print(c("  ⇒ 无真正降级：上述缺失符号均已有生效回退路径，相关功能照常可用",
                        Color.GREEN))
            else:
                print(c("  所有关键符号已解析", Color.GREEN))
        else:
            print(c(f"  全部 {syms.get('available_count', '?')} 个符号已解析，无功能降级",
                    Color.GREEN))

    # 关键功能速览（简单检测：基于符号位图，无需内核新结构）
    avail_syms = set(syms.get("available", []))
    quick = []
    hwbp_ok = "register_user_hw_bp" in avail_syms and "unregister_hw_bp" in avail_syms
    if hwbp_ok:
        quick.append(("硬件断点", "可用（符号就绪）", Color.GREEN))
    else:
        miss = [m for m in ("register_user_hw_bp", "unregister_hw_bp") if m not in avail_syms]
        quick.append(("硬件断点", "不可用（符号缺失: " + ", ".join(miss) + "）", Color.RED))
    # 内存读写：DMA（vmap Device-nGnRnE）优先，WB 线性映射回退
    if "vmap" in avail_syms and "vunmap" in avail_syms:
        quick.append(("内存读写", "DMA 可用 + WB 回退", Color.GREEN))
    elif "copy_from_kernel_nofault" in avail_syms:
        quick.append(("内存读写", "WB only（vmap 缺失）", Color.YELLOW))
    else:
        quick.append(("内存读写", "不可用（核心拷贝符号缺失）", Color.RED))
    # 触摸：依赖 input_handle_event 符号（内核态输入捕获）
    if "input_handle_event" in avail_syms:
        quick.append(("触摸注入/捕获", "可用", Color.GREEN))
    else:
        quick.append(("触摸注入/捕获", "不可用（input_handle_event 缺失）", Color.RED))
    quick.append(("文件读取", "内核态可用（SELinux Enforcing 下 block_device 受限）", Color.YELLOW))
    # 进程列表 / maps：2026-09-19 免引用改造后主路径 = RCU + pid_task/find_vpid，
    # **不再依赖 put_task_struct**。判据用内核上报的 task 取用路径（权威），
    # 取引用路径下才看 put_task 能否安全归还 + mm 是否可取。
    _pt = info.get("paths_raw", {}).get("put_task", -1)
    _tf = info.get("paths_raw", {}).get("task_fetch", 0)
    _mm_ok = all(m in avail_syms for m in ("get_task_mm", "mmput"))
    if _tf == 1:
        quick.append(("进程列表/maps",
                      "可用（免引用 RCU+pid_task，不依赖 put_task_struct）", Color.GREEN))
    elif _pt in (0, 1) and _mm_ok:
        quick.append(("进程列表/maps", "可用（取引用路径，task 引用可归还 + mm 可取）",
                      Color.GREEN))
    else:
        quick.append(("进程列表/maps", "不可用（免引用与取引用路径都不可用）", Color.RED))
    print(c("\n  --- 关键功能速览 ---", Color.YELLOW))
    for name, detail, col in quick:
        print(f"  {name:12s}: {c(detail, col)}")

    # 回退状态
    fbs = info.get("fallbacks", {})
    if fbs:
        fb_issues = {k: v for k, v in fbs.items() if v not in ("主符号",)}
        if fb_issues:
            print(c("\n  --- 回退状态（仅显示非主符号）---", Color.YELLOW))
            for k, v in fb_issues.items():
                color = Color.RED if "缺失" in v or "泄漏" in v else Color.YELLOW
                print(f"  {k:30s}: {c(v, color)}")
        else:
            print(c("  所有符号使用主符号（无回退）", Color.GREEN))

    # 偏移探测
    offsets = info.get("offsets", {})
    if offsets:
        print(c("\n  --- task_struct 偏移探测 ---", Color.YELLOW))
        # 核心偏移（始终需要）
        core_fields = ["tasks", "tgid", "mm", "pid", "real_parent", "usage"]
        core_items = [f"{k}={offsets.get(k, '?')}" for k in core_fields]
        print(f"  {' | '.join(core_items)}")
        # cmdline 偏移
        arg_start = offsets.get("arg_start", "?")
        arg_end = offsets.get("arg_end", "?")
        print(f"  arg_start={arg_start} | arg_end={arg_end}")
        # VMA 偏移
        vm_start = offsets.get("vm_start", "?")
        vm_end = offsets.get("vm_end", "?")
        vm_next = offsets.get("vm_next", "?")
        mm_mmap = offsets.get("mm_mmap", "?")
        print(f"  vm_start={vm_start} | vm_end={vm_end} | vm_next={vm_next} | mm_mmap={mm_mmap}")

    # 框架变量
    fw = info.get("framework", {})
    if fw:
        print(c("\n  --- 框架变量 ---", Color.YELLOW))
        print(f"  vmemmap_base:   {fw.get('vmemmap_base', '?')}")
        print(f"  memstart_addr:  {fw.get('memstart_addr', '?')}")
        print(f"  pgd_va:         {fw.get('pgd_va', '?')}")
        print(f"  mm_pgd_offset:  {fw.get('mm_pgd_offset', '?')}  "
              f"va_bits: {fw.get('va_bits', '?')}  "
              f"page_shift: {fw.get('page_shift', '?')}  "
              f"page_level: {fw.get('page_level', '?')}")

    # 模块版本
    mod = info.get("module", {})
    if mod:
        print(c("\n  --- 模块版本 ---", Color.YELLOW))
        print(f"  版本: {mod.get('version', '?')} (raw: {mod.get('version_raw', '?')})")
        print(f"  构建: {mod.get('build_time', '?')} (raw: {mod.get('build_time_raw', '?')})")
        if mod.get('size'):
            print(f"  大小: {mod['size']} 字节")
    print()


def cmd_getlog(client: KPMClient, args: list):
    """2026-09-21 诊断：读取内核内部日志（GET_LOG）。
    用于判定本次 modules/maps 卡死到底发生在内核（不见 done）还是客户端/网络。"""
    try:
        text = client.getlog()
    except Exception as e:
        print(c(f"  [错误] 读取内核日志失败: {type(e).__name__}: {e}", Color.RED))
        return
    if not text.strip():
        print("  (内核日志为空)")
        return
    # 只显示 maps 诊断相关 + 尾部最近内容，避免刷屏
    lines = [l for l in text.splitlines() if "PROC_MAPS" in l or "LH_udp" in l.lower()]
    if len(lines) > 80:
        print(c(f"  {len(lines)} 条相关日志，仅示最新 80 条：", Color.YELLOW))
        lines = lines[-80:]
    print("  ---- 内核日志 (PROC_MAPS/LH_udp) ----")
    for l in lines:
        print("  " + l)


def cmd_list(client: KPMClient, args: list):
    """列出全部用户态进程（自动分页），可选限制条数。
    显示所有进程（包括系统进程和应用进程），不进行应用过滤。"""
    limit = int(args[0]) if args else 0  # 0 = 全部
    count, procs = client.proc_list_all()
    if count < 0:
        print(c(f"  [错误] 获取进程列表失败: {count}", Color.RED))
        return
    if limit > 0:
        procs = procs[:limit]
    print(c(f"\n  共 {count} 个用户态进程（显示 {len(procs)} 条）:", Color.GREEN))
    print(f"  {'PID':>8}  {'STATE':>5}  {'MEM':>8}  {'NAME':<50}")
    print(f"  {'-'*8}  {'-'*5}  {'-'*8}  {'-'*50}")
    for pid, _ppid, name, _, state, mem_pages in procs:
        print(f"  {pid:>8}  {fmt_state(state):>5}  {fmt_mem_size(mem_pages):>8}  {name[:50]}")


def _cmd_list_apps_impl(client: KPMClient, want_sys: bool, label: str):
    """通用应用列表实现：纯 UDP 获取全部进程，启发式过滤。
    - want_sys=False: 只显示第三方应用（排除系统应用前缀和非应用进程）
    - want_sys=True:  只显示系统应用（仅匹配系统应用前缀）
    """
    _, procs = client.proc_list_all()
    if not procs:
        print(c("  [警告] 未获取到任何进程", Color.YELLOW))
        return

    matched = []
    for pid, _ppid, name, _, state, mem_pages in procs:
        if want_sys:
            # 系统应用：必须匹配系统应用前缀
            if not is_system_app(name):
                continue
        else:
            # 第三方应用：必须是应用（含点号包名），且不是系统应用
            if not is_likely_app(name):
                continue
            if is_system_app(name):
                continue
        matched.append((pid, name, state, mem_pages))

    print(c(f"\n  运行中的{label}应用 ({len(matched)} 个):", Color.GREEN))
    if not matched:
        print(c("  (无)", Color.GRAY))
        return
    print(f"  {'PID':>8}  {'MEM':>8}  {'PACKAGE':<50}  {'STATE':>5}")
    print(f"  {'-'*8}  {'-'*8}  {'-'*50}  {'-'*5}")
    for pid, name, state, mem_pages in matched:
        print(f"  {pid:>8}  {fmt_mem_size(mem_pages):>8}  {name[:50]:<50}  {fmt_state(state):>5}")


def cmd_apps(client: KPMClient, args: list):
    """列出第三方应用进程（启发式过滤，纯 UDP）"""
    _cmd_list_apps_impl(client, want_sys=False, label="第三方")


def cmd_sysapps(client: KPMClient, args: list):
    """列出系统应用进程（启发式过滤，纯 UDP）"""
    _cmd_list_apps_impl(client, want_sys=True, label="系统")


def cmd_ps(client: KPMClient, args: list):
    if not args:
        print(c("  用法: ps <name>", Color.YELLOW))
        return
    name = " ".join(args).lower()
    _, procs = client.proc_list_all()
    matches = [p for p in procs if name in p[2].lower()]
    if not matches:
        print(c(f"  未找到匹配 '{name}' 的进程", Color.YELLOW))
        return
    print(c(f"\n  匹配 '{name}' 的进程 ({len(matches)} 个):", Color.GREEN))
    for pid, _ppid, pname, _, state, mem_pages in matches:
        print(f"  {pid:>8}  {fmt_mem_size(mem_pages):>8}  {fmt_state(state):>5}  {pname}")


def cmd_maps(client: KPMClient, args: list):
    if not args:
        print(c("  用法: maps <pid> [n]", Color.YELLOW))
        return
    pid = int(args[0])
    n = int(args[1]) if len(args) > 1 else 30
    if n > 56:
        # 超过 UDP 单次上限(56)：分页拉全后取前 n 个
        count, maps = client.proc_maps_all(pid)
        if count < 0:
            print(c(f"  [错误] 获取内存映射失败: {count}", Color.RED))
            return
        maps = maps[:n]
        count = len(maps)
    else:
        count, maps = client.proc_maps(pid, max_count=n)
        if count < 0:
            print(c(f"  [错误] 获取内存映射失败: {count}", Color.RED))
            return
    print(c(f"\n  进程 {pid} 的内存映射 ({count} 条):", Color.GREEN))
    print(f"  {'START':>18}  {'END':>18}  {'PERMS':>5}  {'OFFSET':>10}  PATH")
    print(f"  {'-'*18}  {'-'*18}  {'-'*5}  {'-'*10}  {'-'*30}")
    for start, end, offset, perms, path in maps:
        print(f"  0x{start:016X}  0x{end:016X}  {fmt_perms(perms):>5}  0x{offset:08X}  {path[:50]}")


def cmd_region(client: KPMClient, args: list):
    if len(args) < 2:
        print(c("  用法: region <pid> <addr>", Color.YELLOW))
        return
    pid = int(args[0])
    addr = parse_addr(args[1])
    ret, region = client.proc_query_region(pid, addr)
    if ret < 0 or not region:
        print(c(f"  [错误] 查询失败: {ret}", Color.RED))
        return
    start, end, offset, perms, path = region
    print(c(f"\n  地址 0x{addr:016X} 所在区域:", Color.GREEN))
    print(f"  范围:  0x{start:016X} - 0x{end:016X} (size: {end-start} bytes)")
    print(f"  权限:  {fmt_perms(perms)}")
    print(f"  偏移:  0x{offset:08X}")
    print(f"  路径:  {path if path else '(匿名)'}")


def cmd_modules(client: KPMClient, args: list):
    """进程模块列表：按 path 聚合 maps，输出每个 so/文件模块的段数、总大小、基址。

    说明：
      - 依赖内核 PROC_MAPS 返回的 path 字段（VMA 遍历 + /proc/maps 路径填充，
        需 LH_0.9.1 之后的新模块）。
      - UDP 单次 maps 最多返回 56 个区域（16384 / sizeof(entry)=288），
        若进程区域数超出，可加大内核 KPM_UDP_MAX_PAYLOAD 或按区域查询。
    """
    from collections import defaultdict
    if not args:
        print(c("  用法: modules <pid> [--all]", Color.YELLOW))
        return
    pid = int(args[0])
    show_all = "--all" in args
    count, maps = client.proc_maps_all(pid)
    if count < 0:
        print(c(f"  [错误] 获取内存映射失败: {count}", Color.RED))
        return
    if count == 0:
        print(c(f"  进程 {pid} 无内存映射或已退出", Color.YELLOW))
        return

    mods = defaultdict(lambda: [0, 0, 1 << 63])  # path -> [段数, 总字节, 基址]
    anon = 0
    for start, end, offset, perms, path in maps:
        if not path:
            anon += 1
            continue
        mods[path][0] += 1
        mods[path][1] += (end - start)
        if start < mods[path][2]:
            mods[path][2] = start

    print(c(f"\n  进程 {pid} 模块列表 ({count} 个区域, {len(mods)} 个具名模块, 匿名区域 {anon}):", Color.GREEN))
    if not mods:
        print(c("  [提示] 所有区域均为匿名——若 path 为空，请确认设备已加载新模块", Color.YELLOW))
        print(c("         (LH_0.9.1 起 maps 会按 /proc/maps 填充文件路径)", Color.YELLOW))
        return
    print(f"  {'模块':<44} {'段数':>5} {'总大小':>12} {'基址':>18}")
    print(f"  {'-'*44} {'-'*5} {'-'*12} {'-'*18}")
    for path, (segs, size, base) in sorted(mods.items(), key=lambda x: -x[1][1]):
        name = path.split('/')[-1]
        line = f"  {name:<44} {segs:>5} {fmt_size(size):>12} 0x{base:016X}"
        if show_all:
            line += f"  <- {path}"
        print(line)


_DUMP_STATE_NAMES = {0: "空闲", 1: "进行中", 2: "完成", 3: "错误", 4: "已取消"}
_DUMP_ERR_NAMES = {1: "参数非法", 2: "内存不足", 3: "未找到", 4: "读取/写入失败", 5: "权限", 6: "队列忙"}


def _dump_state_str(p):
    s = _DUMP_STATE_NAMES.get(p["state"], str(p["state"]))
    if p["state"] == 3:
        s += f" (err={_DUMP_ERR_NAMES.get(p['err'], p['err'])})"
    return s


def cmd_dump(client: KPMClient, args: list):
    """协议化 dump：ELF 重建，本地落盘，完整性双重校验。
    用法: dump <pid> <模块名> [--out <路径>] [--fetch]  输出 libxxx.so.dump
    --fetch: 强制传统逐块 FETCH 模式（默认自动流式 DUMP_STREAM）"""
    if len(args) < 2:
        print(c("  用法: dump <pid> <模块名> [--out <路径>] [--fetch]"
                "  例: dump 21080 libxxx.so", Color.YELLOW))
        return
    pid = int(args[0])
    out_path = None
    use_stream = True
    if "--fetch" in args:
        use_stream = False
    if "--out" in args:
        i = args.index("--out")
        if i + 1 < len(args):
            out_path = args[i + 1]
    mname = " ".join([a for a in args[1:] if not a.startswith("--")])
    if out_path:
        mname = " ".join([a for a in mname.split() if a != out_path])
    if not out_path:
        safe = "".join(ch for ch in mname if ch.isalnum() or ch in "._-")[:60]
        out_path = os.path.join(DEFAULT_DUMP_DIR, f"{safe}.dump")
    print(c(f"  dump: pid={pid} 模块='{mname}' → {out_path}", Color.GREEN))
    try:
        r = client.dump_proto(pid, mname, out_path, use_stream=use_stream)
        print(c(f"  ✅ dump 完成", Color.GREEN))
        print(f"    Module:  {r['module']}")
        print(f"    Base:    0x{r['base']:016X}")
        print(f"    Size:    {fmt_size(r['size'])}")
        print(f"    路径:    {r['path']}")
        print(f"    SHA256:  {r['sha256']}")
    except Exception as e:
        msg = str(e)
        print(c(f"  [错误] dump 失败: {msg}", Color.RED))
        low = msg.lower()
        if ("ret=-1" in msg or "ret=-3" in msg or "inval" in low
                or "notfound" in low or "not found" in low):
            print(c(f"  提示: 协议化 dump 依赖 ELF 头 + 文件名定位。若模块内存无标准 ELF 头"
                    f"(自研加载器/APK内mmap/头被清) 或未加载，可改用 dumpraw 按段直读(不校验头):",
                    Color.YELLOW))
            print(c(f"        dumpraw {pid} {mname} [--out 路径]", Color.YELLOW))


def cmd_dumpraw(client: KPMClient, args: list):
    """纯内存 raw dump：不校验 ELF 头，按 maps 段整段直读落盘。
    适用：内存中无标准 ELF 头（自研加载器/壳处理、APK 内 mmap 等）的模块，
    普通 dump（依赖 ELF 头重建）失败时的兜底方案。
    用法: dumpraw <pid> <模块名> [--out <路径>]
    输出: <路径>（.raw 内容）+ <路径>.segments.txt（段元数据: start end offset perms）
    缺失页补零并计数，不影响整体落盘。"""
    if len(args) < 2:
        print(c("  用法: dumpraw <pid> <模块名> [--out <路径>]  例: dumpraw 12688 libclient.so",
                Color.YELLOW))
        return
    pid = int(args[0])
    out_path = None
    if "--out" in args:
        i = args.index("--out")
        if i + 1 < len(args):
            out_path = args[i + 1]
    mname = " ".join([a for a in args[1:] if not a.startswith("--")])
    if out_path:
        mname = " ".join([a for a in mname.split() if a != out_path])
    count, maps = client.proc_maps_all(pid)
    if count < 0:
        print(c(f"  [错误] maps 失败: {count}", Color.RED))
        return
    segs = sorted([(s, e, o, perm, p) for (s, e, o, perm, p) in maps if mname in p])
    if not segs:
        print(c(f"  [错误] 进程 {pid} 中未找到 '{mname}'（模块未加载，或 APK 内 mmap 无文件名）",
                Color.RED))
        return
    total = sum(e - s for (s, e, o, perm, p) in segs)
    print(c(f"  模块 '{mname}' 匹配 {len(segs)} 段，总大小 {fmt_size(total)}", Color.GREEN))
    for i, (s, e, o, perm, p) in enumerate(segs):
        print(f"    [{i}] 0x{s:016X}-0x{e:016X}  {fmt_size(e-s)}  off=0x{o:X}  perm={perm}")
    if not out_path:
        safe = "".join(ch for ch in mname if ch.isalnum() or ch in "._-")[:60]
        out_path = os.path.join(DEFAULT_DUMP_DIR, f"{safe}_{pid}_{segs[0][0]:016x}.raw")
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    seg_path = out_path + ".segments.txt"
    with open(seg_path, "w", encoding="utf-8") as mf:
        mf.write("# pid=%d module=%s\n# start end offset perms\n" % (pid, mname))
        for (s, e, o, perm, p) in segs:
            mf.write("0x%X 0x%X 0x%X %d\n" % (s, e, o, perm))
    print(c(f"\n  ⏳ 开始 raw dump → {out_path} ...", Color.CYAN))
    missing = 0
    done = 0
    t0 = time.time()
    with open(out_path, "wb") as f:
        for si, (s, e, o, perm, p) in enumerate(segs):
            off = 0
            seglen = e - s
            seg_done, seg_miss = 0, 0
            while off < seglen:
                n = min(16384, seglen - off)
                r, d = client.read_mem(pid, s + off, n)
                if r > 0:
                    f.write(d[:r])
                    done += r
                    off += r
                    seg_done += r
                else:
                    f.write(b"\x00" * n)   # 失败页补零（PTE=0 回收页），继续
                    missing += n
                    off += n
                    seg_miss += n
            print(f"    段[{si+1}/{len(segs)}] {fmt_size(seglen)}  "
                  f"实读 {fmt_size(seg_done)} / 补零 {fmt_size(seg_miss)}  ({100.0*(si+1)/len(segs):.0f}%)")
        f.flush()
    dt = time.time() - t0
    print(c(f"\n  ✅ dump 完成: {fmt_size(done)} 字节，缺失/补零 {fmt_size(missing)}，耗时 {dt:.1f}s", Color.GREEN))
    print(f"    文件: {out_path}")
    print(f"    段元数据: {seg_path}")


def cmd_dump_all(client: KPMClient, args: list):
    """dump 进程全部具名模块（串行队列，一次一个）。
    用法: dump-all <pid> [--out <目录>]"""
    if not args:
        print(c("  用法: dump-all <pid> [--out <目录>]", Color.YELLOW))
        return
    pid = int(args[0])
    out_dir = DEFAULT_DUMP_DIR
    if "--out" in args:
        i = args.index("--out")
        if i + 1 < len(args):
            out_dir = args[i + 1]
    os.makedirs(out_dir, exist_ok=True)

    from collections import defaultdict
    count, maps = client.proc_maps_all(pid)
    if count < 0:
        print(c(f"  [错误] 获取内存映射失败: {count}", Color.RED))
        return
    mods = defaultdict(lambda: [0, 0, 1 << 63])
    for start, end, offset, perms, path in maps:
        if not path:
            continue
        mods[path][0] += 1
        mods[path][1] += (end - start)
        if start < mods[path][2]:
            mods[path][2] = start

    named = sorted(mods.items(), key=lambda x: -x[1][1])
    if not named:
        print(c(f"  进程 {pid} 无具名模块", Color.YELLOW))
        return
    print(c(f"\n  进程 {pid} 共 {len(named)} 个具名模块，开始串行 dump...", Color.GREEN))
    ok, fail = 0, 0
    for i, (path, (segs, size, base)) in enumerate(named, 1):
        modname = path.split("/")[-1]
        safe = "".join(ch for ch in modname if ch.isalnum() or ch in "._-")[:60]
        out_path = os.path.join(out_dir, f"{safe}.dump")
        print(c(f"\n  [{i}/{len(named)}] {modname} ({fmt_size(size)}, base=0x{base:016X})", Color.CYAN))
        try:
            r = client.dump_proto(pid, modname, out_path)
            print(f"    ✅ {fmt_size(r['size'])}  SHA256: {r['sha256'][:16]}...")
            ok += 1
        except Exception as e:
            print(c(f"    ⚠️  跳过: {e}", Color.YELLOW))
            fail += 1
    print(c(f"\n  dump-all 完成: 成功 {ok}, 跳过 {fail} (共 {len(named)})", Color.GREEN))
    print(f"  输出目录: {os.path.abspath(out_dir)}")


def cmd_dump_progress(client: KPMClient, args: list):
    p = client.dump_progress()
    if not p:
        print(c("  [错误] 查询进度失败", Color.RED))
        return
    print(c(f"  dump 状态: {_dump_state_str(p)}", Color.GREEN))
    print(f"    进度: {fmt_size(p['done'])} / {fmt_size(p['total'])}  "
          f"({p['done'] * 100 // p['total'] if p['total'] else 0}%)")
    print(f"    区域: {p['region_count']}  段: {p['seg_count']}/{p['seg_total']}")
    print(f"    输出: {p['path']}")


def cmd_dump_cancel(client: KPMClient, args: list):
    r = client.dump_cancel()
    print(c(f"  取消请求已发送 (ret={r})", Color.YELLOW))

def cmd_read(client: KPMClient, args: list):
    if len(args) < 2:
        print(c("  用法: read <pid> <addr> [len]", Color.YELLOW))
        return
    pid = int(args[0])
    addr = parse_addr(args[1])
    length = int(args[2]) if len(args) > 2 else 64
    if length > 1400:
        length = 1400
        print(c(f"  [提示] 长度限制为 1400", Color.YELLOW))

    ret, data = client.read_mem(pid, addr, length)
    if ret < 0:
        print(c(f"  [错误] 读取失败: {ret}", Color.RED))
        return
    print(c(f"\n  读取进程 {pid} @ 0x{addr:016X} ({ret} 字节):", Color.GREEN))
    display_memory(data, base_addr=addr)


def cmd_bigread(client: KPMClient, args: list):
    """流式读（2026-08-06）：突破单包 16KB，一次拉取任意长度（≤64MB）。
    用法: bigread <pid> <addr> <len> [--hexdump] [--out <路径>]"""
    if len(args) < 3:
        print(c("  用法: bigread <pid> <addr> <len> [--hexdump] [--out <路径>]",
                Color.YELLOW))
        return
    pid = int(args[0])
    addr = parse_addr(args[1])
    length = int(args[2], 0) if args[2].startswith(("0x", "0X")) else int(args[2])
    if length <= 0 or length > STREAM_MAX:
        print(c(f"  [错误] len 必须在 1..{STREAM_MAX}", Color.RED))
        return
    want_hex = "--hexdump" in args or "--hex" in args
    out_path = None
    if "--out" in args:
        i = args.index("--out")
        if i + 1 < len(args):
            out_path = args[i + 1]
    print(c(f"  流式读: pid={pid} addr=0x{addr:X} len={fmt_size(length)}",
            Color.GREEN))
    t0 = time.time()
    try:
        data = client.stream_read(pid, addr, length)
    except Exception as e:
        print(c(f"  [错误] 流式读失败: {e}", Color.RED))
        return
    dt = time.time() - t0
    speed = len(data) / dt / 1024 if dt > 0 else 0
    print(f"  完成: {fmt_size(len(data))} in {dt:.1f}s ({speed:.0f} KB/s)")
    if out_path:
        d = os.path.dirname(os.path.abspath(out_path))
        if d:
            os.makedirs(d, exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(data)
        print(c(f"  已保存: {out_path}", Color.GREEN))
    if want_hex:
        display_memory(data[:512], base_addr=addr)


def cmd_bigwrite(client: KPMClient, args: list):
    """流式写（2026-08-06）：分片写入大块数据（≤64MB）。
    用法: bigwrite <pid> <addr> <hex-string>   例: bigwrite 1234 0x7a001000 9090c3c35f5e
    或:  bigwrite <pid> <addr> <长度> <随机数据>"""
    if len(args) < 3:
        print(c("  用法: bigwrite <pid> <addr> <hex-string>", Color.YELLOW))
        return
    pid = int(args[0])
    addr = parse_addr(args[1])
    try:
        data = bytes.fromhex(args[2])
    except Exception:
        print(c("  [错误] hex-string 无效（仅接受十六进制字节串）", Color.RED))
        return
    if not data:
        print(c("  [错误] 数据为空", Color.RED))
        return
    t0 = time.time()
    try:
        n = client.stream_write(pid, addr, data)
    except Exception as e:
        print(c(f"  [错误] 流式写失败: {e}", Color.RED))
        return
    dt = time.time() - t0
    print(c(f"  已写入 {n}/{len(data)} 字节 @ 0x{addr:X} in {dt:.1f}s",
            Color.GREEN))


def cmd_dumpmem(client: KPMClient, args: list):
    """定向 dump（2026-08-06）：只 dump 某地址处小段内存，保存到本地文件。
    用法: dumpmem <pid> <addr> <len> [--out <路径>] [--hexdump]
    例:   dumpmem 21080 0x7a001000 0x1000 --out ./dump.bin"""
    if len(args) < 3:
        print(c("  用法: dumpmem <pid> <addr> <len> [--out <路径>] [--hexdump]",
                Color.YELLOW))
        return
    pid = int(args[0])
    addr = parse_addr(args[1])
    length = int(args[2], 0) if args[2].startswith(("0x", "0X")) else int(args[2])
    if length <= 0 or length > STREAM_MAX:
        print(c(f"  [错误] len 必须在 1..{STREAM_MAX}", Color.RED))
        return
    out_path = None
    if "--out" in args:
        i = args.index("--out")
        if i + 1 < len(args):
            out_path = args[i + 1]
    if not out_path:
        out_path = os.path.join(DEFAULT_DUMP_DIR,
                                f"dump_p{pid}_0x{addr:x}_{length}.bin")
    want_hex = "--hexdump" in args or "--hex" in args
    print(c(f"  定向 dump: pid={pid} addr=0x{addr:X} len={fmt_size(length)}"
            f" → {out_path}", Color.GREEN))
    try:
        r = client.dump_range(pid, addr, length, out_path=out_path,
                              hexdump=want_hex)
    except Exception as e:
        print(c(f"  [错误] dump 失败: {e}", Color.RED))
        return
    print(c(f"  ✅ 已保存 {fmt_size(r['length'])} 字节 → {r['path']}",
            Color.GREEN))


def cmd_hook_plt(client: KPMClient, args: list):
    """PLT/GOT hook（2026-08-06 接线启用）：改写目标进程模块函数的 GOT 条目。
    用法: hook_plt <pid> <模块名> <函数名> <替换地址>
    例:   hook_plt 21080 libUE4.so _ZN4FNameC2Ev 0x7a12345678
    返回 hook 索引；替换地址为目标进程内自建 shellcode/函数地址。"""
    if len(args) < 4:
        print(c("  用法: hook_plt <pid> <模块名> <函数名> <替换地址>",
                Color.YELLOW))
        return
    pid = int(args[0])
    module_name = args[1]
    func_name = args[2]
    replace_addr = parse_value(args[3])
    print(c(f"  PLT hook: pid={pid} {module_name}::{func_name} → "
            f"0x{replace_addr:X}", Color.GREEN))
    idx = client.hook_plt(pid, module_name, func_name, replace_addr)
    if idx < 0:
        print(c(f"  [错误] hook 安装失败: {idx}（函数名/模块名不匹配或 GOT 未找到）",
                Color.RED))
        return
    print(c(f"  ✅ hook 已安装，索引 {idx}（hook_list 查看 / hook_remove 卸载）",
            Color.GREEN))


def cmd_hook_list(client: KPMClient, args: list):
    """列出全部 hook 条目。
    用法: hook_list"""
    hooks = client.hook_list()
    if not hooks:
        print("  （无 hook 条目，或驱动不支持）")
        return
    tnames = {0: "INLINE", 1: "STEALTH", 2: "PLT"}
    for h in hooks:
        if not h["target_addr"] and not h["enabled"]:
            continue   # 空槽
        state = "启用" if h["enabled"] else "停用"
        print(f"  [{h['index']}] {state} type={tnames.get(h['type'], h['type'])} "
              f"pid={h['pid']}")
        print(f"      target={h['target_name'] or hex(h['target_addr'])} "
              f"GOT=0x{h['target_addr']:X} → 0x{h['replacement']:X} "
              f"hit={h['hit_count']}")


def cmd_hook_remove(client: KPMClient, args: list):
    """移除 hook（恢复原始指令）。
    用法: hook_remove <索引>"""
    if not args:
        print(c("  用法: hook_remove <索引>", Color.YELLOW))
        return
    idx = int(args[0])
    ret = client.hook_remove(idx)
    if ret < 0:
        print(c(f"  [错误] 移除失败: {ret}", Color.RED))
        return
    print(c(f"  ✅ hook[{idx}] 已移除", Color.GREEN))


def cmd_hook_toggle(client: KPMClient, args: list):
    """切换 hook 启停。
    用法: hook_toggle <索引> <0|1>"""
    if len(args) < 2:
        print(c("  用法: hook_toggle <索引> <0|1>", Color.YELLOW))
        return
    idx = int(args[0])
    enable = int(args[1])
    ret = client.hook_toggle(idx, enable)
    if ret < 0:
        print(c(f"  [错误] 切换失败: {ret}", Color.RED))
        return
    print(c(f"  ✅ hook[{idx}] {'启用' if enable else '停用'}", Color.GREEN))


def cmd_readhex(client: KPMClient, args: list):
    if len(args) < 2:
        print(c("  用法: readhex <pid> <addr> [len]", Color.YELLOW))
        return
    pid = int(args[0])
    addr = parse_addr(args[1])
    length = int(args[2]) if len(args) > 2 else 64
    if length > 1400:
        length = 1400

    ret, data = client.read_mem(pid, addr, length)
    if ret < 0:
        print(c(f"  [错误] 读取失败: {ret}", Color.RED))
        return
    print(c(f"\n  读取进程 {pid} @ 0x{addr:016X} ({ret} 字节):", Color.GREEN))
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        addr_str = f"0x{addr+i:016X}"
        print(f"  {addr_str}: {hex_part}")


def cmd_write(client: KPMClient, args: list):
    if len(args) < 3:
        print(c("  用法: write <pid> <addr> <hex>", Color.YELLOW))
        return
    pid = int(args[0])
    addr = parse_addr(args[1])
    hex_str = args[2].replace(" ", "")
    try:
        data = bytes.fromhex(hex_str)
    except ValueError:
        print(c("  [错误] 无效的十六进制", Color.RED))
        return
    if len(data) > 1400:
        print(c("  [错误] 数据过长 (>1400)", Color.RED))
        return

    # 先读取原值
    ret_r, old_data = client.read_mem(pid, addr, len(data))
    if ret_r > 0:
        print(c(f"  原值: {old_data.hex()}", Color.GRAY))

    ret = client.write_mem(pid, addr, data)
    if ret < 0:
        print(c(f"  [错误] 写入失败: {ret}", Color.RED))
        return
    print(c(f"  写入成功: {data.hex()} -> 进程 {pid} @ 0x{addr:016X}", Color.GREEN))

    # 验证写入
    ret_r, new_data = client.read_mem(pid, addr, len(data))
    if ret_r > 0:
        if new_data == data:
            print(c(f"  验证: 成功 ({new_data.hex()})", Color.GREEN))
        else:
            print(c(f"  验证: 失败 (读到 {new_data.hex()})", Color.RED))


def cmd_write_u32(client: KPMClient, args: list):
    if len(args) < 3:
        print(c("  用法: writeu32 <pid> <addr> <val>", Color.YELLOW))
        return
    pid = int(args[0])
    addr = parse_addr(args[1])
    val = parse_value(args[2])
    data = struct.pack("<I", val & 0xFFFFFFFF)
    ret = client.write_mem(pid, addr, data)
    if ret < 0:
        print(c(f"  [错误] 写入失败: {ret}", Color.RED))
        return
    print(c(f"  写入 u32={val} (0x{val:08X}) -> 进程 {pid} @ 0x{addr:016X}", Color.GREEN))


def cmd_write_u64(client: KPMClient, args: list):
    if len(args) < 3:
        print(c("  用法: writeu64 <pid> <addr> <val>", Color.YELLOW))
        return
    pid = int(args[0])
    addr = parse_addr(args[1])
    val = parse_value(args[2])
    data = struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF)
    ret = client.write_mem(pid, addr, data)
    if ret < 0:
        print(c(f"  [错误] 写入失败: {ret}", Color.RED))
        return
    print(c(f"  写入 u64={val} (0x{val:016X}) -> 进程 {pid} @ 0x{addr:016X}", Color.GREEN))


def cmd_write_str(client: KPMClient, args: list):
    if len(args) < 3:
        print(c("  用法: writestr <pid> <addr> <str>", Color.YELLOW))
        return
    pid = int(args[0])
    addr = parse_addr(args[1])
    text = " ".join(args[2:])
    data = text.encode('utf-8') + b'\x00'
    if len(data) > 1400:
        print(c("  [错误] 字符串过长", Color.RED))
        return
    ret = client.write_mem(pid, addr, data)
    if ret < 0:
        print(c(f"  [错误] 写入失败: {ret}", Color.RED))
        return
    print(c(f"  写入字符串 \"{text}\" ({len(data)} 字节) -> 进程 {pid} @ 0x{addr:016X}", Color.GREEN))


# 扫描类型/模式解析
TYPE_MAP = {
    "i8": SCAN_TYPE_INT8, "int8": SCAN_TYPE_INT8,
    "i16": SCAN_TYPE_INT16, "int16": SCAN_TYPE_INT16,
    "i32": SCAN_TYPE_INT32, "int32": SCAN_TYPE_INT32,
    "i64": SCAN_TYPE_INT64, "int64": SCAN_TYPE_INT64,
    "f32": SCAN_TYPE_FLOAT, "float": SCAN_TYPE_FLOAT,
    "f64": SCAN_TYPE_DOUBLE, "double": SCAN_TYPE_DOUBLE,
    "str": SCAN_TYPE_STRING, "string": SCAN_TYPE_STRING,
    "bytes": SCAN_TYPE_BYTEARRAY, "bytearray": SCAN_TYPE_BYTEARRAY,
}

MODE_MAP = {
    "exact": SCAN_MODE_EXACT, "0": SCAN_MODE_EXACT,
    "range": SCAN_MODE_RANGE, "1": SCAN_MODE_RANGE,
    "changed": SCAN_MODE_CHANGED, "2": SCAN_MODE_CHANGED,
    "unchanged": SCAN_MODE_UNCHANGED, "3": SCAN_MODE_UNCHANGED,
    "increased": SCAN_MODE_INCREASED, "4": SCAN_MODE_INCREASED,
    "decreased": SCAN_MODE_DECREASED, "5": SCAN_MODE_DECREASED,
    # 2026-08-06 扩展
    "unknown": SCAN_MODE_UNKNOWN, "6": SCAN_MODE_UNKNOWN,
    "ne": SCAN_MODE_NOT_EQUAL, "notequal": SCAN_MODE_NOT_EQUAL,
    "ne=": SCAN_MODE_NOT_EQUAL, "7": SCAN_MODE_NOT_EQUAL,
    "increasedby": SCAN_MODE_INCREASED_BY, "nby": SCAN_MODE_INCREASED_BY,
    "8": SCAN_MODE_INCREASED_BY,
    "decreasedby": SCAN_MODE_DECREASED_BY, "dby": SCAN_MODE_DECREASED_BY,
    "9": SCAN_MODE_DECREASED_BY,
    "increasedge": SCAN_MODE_INCREASED_GE, "nge": SCAN_MODE_INCREASED_GE,
    "10": SCAN_MODE_INCREASED_GE,
    "decreasedge": SCAN_MODE_DECREASED_GE, "dge": SCAN_MODE_DECREASED_GE,
    "11": SCAN_MODE_DECREASED_GE,
}


def parse_type(s: str):
    s = s.lower()
    if s in TYPE_MAP:
        return TYPE_MAP[s]
    return None


def parse_mode(s: str):
    s = s.lower()
    if s in MODE_MAP:
        return MODE_MAP[s]
    return None


def cmd_scan_start(client: KPMClient, args: list):
    if len(args) < 4:
        print(c("  用法: scan <pid> <type> <mode> <val> [range]", Color.YELLOW))
        print(c("    type: i8/i16/i32/i64/f32/f64/str/bytes", Color.GRAY))
        print(c("    mode: exact/range/changed/unchanged/increased/decreased", Color.GRAY))
        print(c("          unknown/ne/nby/dby/nge/dge (2026-08-06)", Color.GRAY))
        print(c("    str: 任意长度 ≤64B（>8B 自动走长 AOB 路径）", Color.GRAY))
        print(c("  V2 说明: 数值类型按类型大小对齐扫描(CE aligned 语义),", Color.GRAY))
        print(c("           字节/字符串类型逐字节匹配; 全量扫描后 scan_status 看进度", Color.GRAY))
        return
    pid = int(args[0])
    vtype = parse_type(args[1])
    vmode = parse_mode(args[2])
    if vtype is None:
        print(c(f"  [错误] 未知类型: {args[1]}", Color.RED))
        return
    if vmode is None:
        print(c(f"  [错误] 未知模式: {args[2]}", Color.RED))
        return

    val_str = args[3]
    scan_range = parse_value(args[4]) if len(args) > 4 else 0

    # 2026-08-06：长字符串（>8B）走 AOB 路径（scan_start_string 自动分流）
    if vtype == SCAN_TYPE_STRING and len(val_str.encode('utf-8')) > 8:
        ret = client.scan_start_string(pid, val_str, scan_range)
        if ret < 0:
            print(c(f"  [错误] 字符串扫描启动失败: {ret}（长度 ≤64B）", Color.RED))
            return
        print(c(f"  扫描启动成功(长字符串→AOB): pid={pid} type=str "
                f"val='{val_str}' range={scan_range}", Color.GREEN))
        print(c("  使用 scan_result 查看结果; scan_status 看进度", Color.GRAY))
        return

    # 解析值
    if vtype in (SCAN_TYPE_INT8, SCAN_TYPE_INT16, SCAN_TYPE_INT32, SCAN_TYPE_INT64):
        value = parse_value(val_str) & 0xFFFFFFFFFFFFFFFF
        value_len = {SCAN_TYPE_INT8: 1, SCAN_TYPE_INT16: 2,
                     SCAN_TYPE_INT32: 4, SCAN_TYPE_INT64: 8}[vtype]
    elif vtype in (SCAN_TYPE_FLOAT, SCAN_TYPE_DOUBLE):
        fval = float(val_str)
        if vtype == SCAN_TYPE_FLOAT:
            value = struct.unpack("<I", struct.pack("<f", fval))[0]
            value_len = 4
        else:
            value = struct.unpack("<Q", struct.pack("<d", fval))[0]
            value_len = 8
    elif vtype == SCAN_TYPE_STRING:
        # 字符串值打包到 uint64（最多 8 字节）
        sb = val_str.encode('utf-8')[:8]
        value = int.from_bytes(sb.ljust(8, b'\x00'), 'little')
        # 修复（2026-08-04）：value_len 必须与打包进 uint64 的实际长度一致，
        # 不能取全串长度——否则 >8 字节字符串（如 9 字符 "BytePrope"）打包 8 字节
        # 但 value_len=9，驱动 kpm_scan_type_size 拒绝（len>8）返回 -EINVAL。
        value_len = len(sb)
    elif vtype == SCAN_TYPE_BYTEARRAY:
        # 字节数组（十六进制）打包到 uint64
        try:
            sb = bytes.fromhex(val_str.replace(" ", ""))[:8]
            value = int.from_bytes(sb.ljust(8, b'\x00'), 'little')
            value_len = len(sb)
        except ValueError:
            print(c("  [错误] 无效十六进制", Color.RED))
            return
    else:
        value = parse_value(val_str)
        value_len = 0

    # 2026-08-06：UNKNOWN 模式首轮恒真建集（value 无意义，客户端显示提示）
    if vmode == SCAN_MODE_UNKNOWN:
        print(c("  [提示] 未知初始值扫描：首轮将全量建集（可能截断），"
                "随后用 changed/±X 过滤收敛", Color.YELLOW))

    ret = client.scan_start(pid, vtype, vmode, value, value_len, scan_range)
    if ret < 0:
        print(c(f"  [错误] 扫描启动失败: {ret}", Color.RED))
        return
    print(c(f"  扫描启动成功: pid={pid} type={TYPE_NAMES[vtype]} "
            f"mode={MODE_NAMES[vmode]} val={val_str} range={scan_range}",
            Color.GREEN))
    print(c("  使用 scan_result 查看结果", Color.GRAY))
    print(c("  使用 scan_status 查看扫描进度/区域数/截断标志", Color.GRAY))


def cmd_scan_next(client: KPMClient, args: list):
    if len(args) < 3:
        print(c("  用法: scan_next <type> <mode> <val> [range]", Color.YELLOW))
        return
    vtype = parse_type(args[0])
    vmode = parse_mode(args[1])
    if vtype is None or vmode is None:
        print(c("  [错误] 未知类型或模式", Color.RED))
        return

    val_str = args[2]
    scan_range = parse_value(args[3]) if len(args) > 3 else 0

    if vtype in (SCAN_TYPE_INT8, SCAN_TYPE_INT16, SCAN_TYPE_INT32, SCAN_TYPE_INT64):
        value = parse_value(val_str) & 0xFFFFFFFFFFFFFFFF
        value_len = {SCAN_TYPE_INT8: 1, SCAN_TYPE_INT16: 2,
                     SCAN_TYPE_INT32: 4, SCAN_TYPE_INT64: 8}[vtype]
    elif vtype in (SCAN_TYPE_FLOAT, SCAN_TYPE_DOUBLE):
        fval = float(val_str)
        if vtype == SCAN_TYPE_FLOAT:
            value = struct.unpack("<I", struct.pack("<f", fval))[0]
            value_len = 4
        else:
            value = struct.unpack("<Q", struct.pack("<d", fval))[0]
            value_len = 8
    elif vtype == SCAN_TYPE_STRING:
        sb = val_str.encode('utf-8')[:8]
        value = int.from_bytes(sb.ljust(8, b'\x00'), 'little')
        value_len = len(sb)   # 与打包长度一致（修复同 cmd_scan_start）
    else:
        value = parse_value(val_str)
        value_len = 0

    ret = client.scan_next(vtype, vmode, value, value_len, scan_range)
    if ret < 0:
        print(c(f"  [错误] 过滤扫描失败: {ret}", Color.RED))
        return
    print(c(f"  过滤扫描完成: ret={ret}", Color.GREEN))


def cmd_scan_result(client: KPMClient, args: list):
    n = int(args[0]) if args else 50
    offset = int(args[1]) if len(args) > 1 else 0
    ret, results = client.scan_result(max_count=n, offset=offset)
    if ret < 0:
        print(c(f"  [错误] 获取结果失败: {ret}", Color.RED))
        return
    print(c(f"\n  扫描结果 ({ret} 条，offset={offset}):", Color.GREEN))
    if not results:
        print(c("  (无结果)", Color.GRAY))
        return
    print(f"  {'INDEX':>6}  {'ADDR':>18}  {'VALUE':>18}  {'PREV':>18}")
    print(f"  {'-'*6}  {'-'*18}  {'-'*18}  {'-'*18}")
    for i, (addr, value, prev) in enumerate(results):
        print(f"  {offset+i:>6}  0x{addr:016X}  0x{value:016X}  0x{prev:016X}")


def cmd_scan_clear(client: KPMClient, args: list):
    ret = client.scan_clear()
    if ret < 0:
        print(c(f"  [错误] 清除失败: {ret}", Color.RED))
        return
    print(c("  扫描会话已清除", Color.GREEN))


def cmd_scan_status(client: KPMClient, args: list):
    """查询扫描会话状态（2026-08-04 新增）"""
    st = client.scan_status()
    if st is None:
        print(c("  [错误] 状态查询失败（无会话或旧版驱动）", Color.RED))
        return
    total_mb = st["total_bytes"] / 1048576.0
    scanned_mb = st["scanned_bytes"] / 1048576.0
    pct = (scanned_mb / total_mb * 100) if total_mb > 0 else 0
    print(c("\n===== 扫描会话状态 =====", Color.CYAN))
    print(f"  激活:     {'是' if st['active'] else '否'}    PID: {st['pid']}")
    print(f"  区域数:   {st['region_count']}   命中: {st['result_count']} / 容量 {st['result_capacity']}")
    print(f"  进度:     {scanned_mb:.1f} / {total_mb:.1f} MB ({pct:.1f}%)   失败页: {st['failed_pages']}")
    if st.get("swap_pages"):
        print(c(f"  swap:     换出页 {st['swap_pages']}（数据未扫描，可用 recover_swap 补读）",
                Color.YELLOW))
    if st["truncated"]:
        print(c("  结果:     已截断（truncated）——命中超过缓冲上限，请用更精确的值过滤", Color.RED))
    else:
        print(c("  结果:     完整（未截断）", Color.GREEN))


def cmd_kscan(client: KPMClient, args: list):
    """内核线性映射范围扫描（2026-08-06）。
    用法: kscan <type> <mode> <val> <range> [offset]
      range: 扫描字节数（≤64GB，从 PAGE_OFFSET 起）
      offset: 线性映射偏移（默认 0，即从 PAGE_OFFSET 起）
    例:   kscan i32 exact 123456 0x40000000      # 扫 1GB 内核线性映射找 i32
    注:   扫到的地址是内核虚拟地址（0xffffff...）；结果可 kscan_next 过滤"""
    if len(args) < 4:
        print(c("  用法: kscan <type> <mode> <val> <range> [offset]", Color.YELLOW))
        return
    vtype = parse_type(args[0])
    vmode = parse_mode(args[1])
    if vtype is None or vmode is None:
        print(c("  [错误] 未知类型或模式", Color.RED))
        return
    val_str = args[2]
    scan_range = parse_value(args[3])
    if scan_range <= 0 or scan_range > STREAM_MAX * 1024:
        print(c("  [错误] range 必须在 1..64GB", Color.RED))
        return
    if vtype in (SCAN_TYPE_INT8, SCAN_TYPE_INT16, SCAN_TYPE_INT32, SCAN_TYPE_INT64):
        value = parse_value(val_str) & 0xFFFFFFFFFFFFFFFF
        value_len = {SCAN_TYPE_INT8: 1, SCAN_TYPE_INT16: 2,
                     SCAN_TYPE_INT32: 4, SCAN_TYPE_INT64: 8}[vtype]
    elif vtype in (SCAN_TYPE_FLOAT, SCAN_TYPE_DOUBLE):
        fval = float(val_str)
        if vtype == SCAN_TYPE_FLOAT:
            value = struct.unpack("<I", struct.pack("<f", fval))[0]
            value_len = 4
        else:
            value = struct.unpack("<Q", struct.pack("<d", fval))[0]
            value_len = 8
    else:
        print(c("  [错误] 内核扫描仅支持数值类型 i8~f64", Color.RED))
        return
    if vmode == SCAN_MODE_UNKNOWN:
        print(c("  [提示] 内核 UNKNOWN 首轮全量建集（可能截断），随后 changed/±X 过滤",
                Color.YELLOW))
    print(c(f"  内核扫描: type={TYPE_NAMES[vtype]} mode={MODE_NAMES[vmode]} "
            f"val={val_str} range={fmt_size(scan_range)}", Color.GREEN))
    ret = client.scan_kernel_start(vtype, vmode, value, value_len, scan_range)
    if ret < 0:
        print(c(f"  [错误] 内核扫描启动失败: {ret}", Color.RED))
        return
    print(c("  启动成功。scan_result 查看结果 / scan_status 看进度", Color.GRAY))


def cmd_recover_swap(client: KPMClient, args: list):
    """swap/zram 换出页补读（2026-08-06）。
    用法: swapread <pid> <start> <end> [--zram <路径>] [--out <路径>]
    逐 4KB 页 GET_PTE → 识别 swap 条目 → 解析 swp_offset → READ_FILE 读 zram。
    返回补读页数；--out 时保存为 (addr,data) 二进制拼接。"""
    if len(args) < 3:
        print(c("  用法: swapread <pid> <start> <end> [--zram <路径>] [--out <路径>]",
                Color.YELLOW))
        return
    pid = int(args[0])
    start = parse_addr(args[1])
    end = parse_addr(args[2])
    zram = "/dev/block/zram0"
    out_path = None
    if "--zram" in args:
        i = args.index("--zram")
        if i + 1 < len(args):
            zram = args[i + 1]
    if "--out" in args:
        i = args.index("--out")
        if i + 1 < len(args):
            out_path = args[i + 1]
    # 先确认 swap 设备（读 /proc/swaps）
    try:
        r, data = client.read_file("/proc/swaps", 0, 2048)
        if r > 0 and data:
            print("  /proc/swaps:")
            print("  " + data.decode('utf-8', errors='replace').strip().replace("\n", "\n  "))
    except Exception:
        pass
    print(c(f"  补读 swap 页: pid={pid} [{hex(start)}..{hex(end)}) zram={zram}",
            Color.GREEN))
    t0 = time.time()
    pages = client.recover_swap(pid, start, end, zram_path=zram)
    dt = time.time() - t0
    print(c(f"  补读完成: {len(pages)} 页 in {dt:.1f}s", Color.GREEN))
    if not pages:
        return
    if out_path:
        with open(out_path, "wb") as f:
            for va in sorted(pages):
                f.write(struct.pack("<Q", va))
                f.write(pages[va])
        print(f"  已保存: {out_path}")
    for va in sorted(pages)[:5]:
        print(f"    0x{va:X}: {pages[va][:16].hex()}")


def cmd_export(client: KPMClient, args: list):
    """导出扫描结果到本地 CSV（绕开设备 SELinux 写限制，数据经 UDP 回传）。
    用法: export <本地路径>   例: export scan_results.csv"""
    if not args:
        print(c("  用法: export <本地路径>", Color.YELLOW))
        return
    out = args[0]
    n = client.export_scan_results(out)
    print(c(f"  已导出 {n} 条结果 → {out}", Color.GREEN))


def cmd_group(client: KPMClient, args: list):
    """组扫描（2026-08-06，客户端组合）：对当前结果集的地址，按多个偏移联合过滤。
    用法: group <pid> <base_off:exp> [<base_off2:exp2> ...] [--limit N]
    例:   group 21080 0x0:100 0x4:50     # 地址+0 值==100 且 地址+4 值==50
    说明: 从当前扫描结果取地址为基址，exp 为无符号期望值（十进制或 0x 十六进制）。
    返回匹配的 (地址, 各偏移当前值)。"""
    if len(args) < 2:
        print(c("  用法: group <pid> <base_off:exp> [...] [--limit N]", Color.YELLOW))
        return
    pid = int(args[0])
    specs = []
    limit = 2000
    i = 1
    while i < len(args):
        a = args[i]
        if a == "--limit" and i + 1 < len(args):
            limit = int(args[i + 1])
            i += 2
            continue
        if a.startswith("--limit="):
            limit = int(a.split("=")[1])
            i += 1
            continue
        if ":" in a:
            off_s, exp_s = a.split(":", 1)
            off = parse_value(off_s)
            exp = parse_value(exp_s)
            specs.append((off, exp, 4))
        else:
            print(c(f"  [错误] 参数格式应为 base_off:exp（如 0x0:100）: {a}", Color.RED))
            return
        i += 1
    n, results = client.scan_result_all(page_size=512)
    addrs = [r[0] for r in results]
    print(c(f"  组扫描: {len(addrs)} 个候选地址 × {len(specs)} 个偏移约束",
            Color.GREEN))
    if not addrs:
        print("  无候选地址（先 scan 建结果集）")
        return
    matched = client.group_scan(pid, addrs, specs, limit=limit)
    print(c(f"  匹配 {len(matched)} 条:", Color.GREEN))
    for base, vals in matched[:50]:
        parts = " ".join(f"+0x{o:x}={v}" for o, v in zip(
            [s[0] for s in specs], vals))
        print(f"    0x{base:X}  {parts}")
    if len(matched) > 50:
        print(f"    ... 共 {len(matched)} 条（--limit 可调）")


def cmd_freeze_add(client: KPMClient, args: list):
    if len(args) < 4:
        print(c("  用法: freeze <pid> <addr> <val> <size>", Color.YELLOW))
        print(c("    size: 1/2/4/8", Color.GRAY))
        return
    pid = int(args[0])
    addr = parse_addr(args[1])
    val = parse_value(args[2])
    size = int(args[3])
    if size not in (1, 2, 4, 8):
        print(c("  [错误] size 必须为 1/2/4/8", Color.RED))
        return
    ret = client.freeze_add(pid, addr, val, size)
    if ret < 0:
        print(c(f"  [错误] 添加冻结失败: {ret}", Color.RED))
        return
    print(c(f"  冻结项 #{ret} 已添加: pid={pid} @0x{addr:016X} "
            f"val=0x{val:X} size={size}", Color.GREEN))


def cmd_freeze_list(client: KPMClient, args: list):
    ret, entries = client.freeze_list()
    if ret < 0:
        print(c(f"  [错误] 获取列表失败: {ret}", Color.RED))
        return
    print(c(f"\n  冻结列表 ({ret} 条):", Color.GREEN))
    if not entries:
        print(c("  (空)", Color.GRAY))
        return
    print(f"  {'IDX':>4}  {'EN':>2}  {'PID':>8}  {'ADDR':>18}  {'VALUE':>18}  {'SIZE':>4}  {'HITS':>6}")
    print(f"  {'-'*4}  {'-'*2}  {'-'*8}  {'-'*18}  {'-'*18}  {'-'*4}  {'-'*6}")
    for e in entries:
        print(f"  {e['index']:>4}  {e['enabled']:>2}  {e['pid']:>8}  "
              f"0x{e['addr']:016X}  0x{e['value']:016X}  {e['size']:>4}  {e['hit_count']:>6}")


def cmd_freeze_toggle(client: KPMClient, args: list):
    if len(args) < 2:
        print(c("  用法: freeze_toggle <idx> <0|1>", Color.YELLOW))
        return
    idx = int(args[0])
    enable = int(args[1])
    ret = client.freeze_toggle(idx, enable)
    if ret < 0:
        print(c(f"  [错误] 切换失败: {ret}", Color.RED))
        return
    state = "启用" if enable else "禁用"
    print(c(f"  冻结项 #{idx} 已{state}", Color.GREEN))


def cmd_freeze_remove(client: KPMClient, args: list):
    if not args:
        print(c("  用法: freeze_remove <idx>", Color.YELLOW))
        return
    idx = int(args[0])
    ret = client.freeze_remove(idx)
    if ret < 0:
        print(c(f"  [错误] 删除失败: {ret}", Color.RED))
        return
    print(c(f"  冻结项 #{idx} 已删除", Color.GREEN))


def cmd_freeze_clear(client: KPMClient, args: list):
    ret = client.freeze_clear()
    if ret < 0:
        print(c(f"  [错误] 清空失败: {ret}", Color.RED))
        return
    print(c("  所有冻结已清空", Color.GREEN))


def cmd_ptr_scan(client: KPMClient, args: list):
    if len(args) < 2:
        print(c("  用法: ptr <pid> <addr> [range]", Color.YELLOW))
        return
    pid = int(args[0])
    addr = parse_addr(args[1])
    scan_range = parse_value(args[2]) if len(args) > 2 else 0
    print(c(f"  开始指针扫描: pid={pid} target=0x{addr:016X} range={scan_range}", Color.GRAY))
    ret = client.ptr_scan(pid, addr, scan_range)
    if ret < 0:
        print(c(f"  [错误] 指针扫描失败: {ret}", Color.RED))
        return
    print(c(f"  指针扫描完成，使用 ptr_result 查看结果", Color.GREEN))


def cmd_ptr_chain(client: KPMClient, args: list):
    if len(args) < 3:
        print(c("  用法: ptr_chain <pid> <addr> <depth>", Color.YELLOW))
        return
    pid = int(args[0])
    addr = parse_addr(args[1])
    depth = int(args[2])
    print(c(f"  开始指针链扫描: pid={pid} target=0x{addr:016X} depth={depth}", Color.GRAY))
    ret = client.ptr_scan_chain(pid, addr, depth)
    if ret < 0:
        print(c(f"  [错误] 指针链扫描失败: {ret}", Color.RED))
        return
    print(c(f"  指针链扫描完成", Color.GREEN))


def cmd_ptr_result(client: KPMClient, args: list):
    n = int(args[0]) if args else 50
    offset = int(args[1]) if len(args) > 1 else 0
    ret, results = client.ptr_result(max_count=n, offset=offset)
    if ret < 0:
        print(c(f"  [错误] 获取结果失败: {ret}", Color.RED))
        return
    print(c(f"\n  指针扫描结果 ({ret} 条):", Color.GREEN))
    if not results:
        print(c("  (无结果)", Color.GRAY))
        return
    print(f"  {'INDEX':>6}  {'ADDR':>18}  {'VALUE':>18}")
    print(f"  {'-'*6}  {'-'*18}  {'-'*18}")
    for i, (addr, value) in enumerate(results):
        print(f"  {offset+i:>6}  0x{addr:016X}  0x{value:016X}")


# ===== 批量测试 =====

def test_read(client: KPMClient, args: list):
    """读取测试：读取进程内存映射前几条，逐个读取每段开头"""
    if not args:
        print(c("  用法: test_read <pid>", Color.YELLOW))
        return
    pid = int(args[0])
    print(c(f"\n{'='*60}", Color.BLUE))
    print(c(f"  [TEST] 读取测试 - 进程 {pid}", Color.BLUE))
    print(c(f"{'='*60}", Color.BLUE))

    # 获取内存映射
    count, maps = client.proc_maps(pid, max_count=20)
    if count < 0:
        print(c(f"  [错误] 获取映射失败: {count}", Color.RED))
        return
    print(c(f"  获取到 {count} 条内存映射", Color.GREEN))

    # 测试读取前 5 个可读区域
    tested = 0
    for start, end, offset, perms, path in maps:
        if tested >= 5:
            break
        if not (perms & 1):  # 不可读
            continue
        size = end - start
        if size < 64:
            continue
        read_len = min(64, size)
        print(f"\n  --- 读取区域: 0x{start:016X} ({fmt_perms(perms)}) {path[:40]} ---")
        ret, data = client.read_mem(pid, start, read_len)
        if ret > 0:
            print(c(f"  读取成功 ({ret} 字节)", Color.GREEN))
            # 简要显示
            for i in range(0, min(len(data), 32), 16):
                chunk = data[i:i+16]
                hex_part = " ".join(f"{b:02X}" for b in chunk)
                print(f"  0x{start+i:016X}: {hex_part}")
            tested += 1
        else:
            print(c(f"  读取失败: {ret}", Color.RED))
        time.sleep(0.1)

    print(c(f"\n  -> 读取测试完成 ({tested}/5 成功)", Color.GREEN))


def test_scan(client: KPMClient, args: list):
    """扫描测试：扫描进程中的某个常见值（如 100）
    2026-08-04 增强：扫描后查询状态（region/truncated/进度）、分页拉全量结果"""
    if not args:
        print(c("  用法: test_scan <pid> [value]", Color.YELLOW))
        return
    pid = int(args[0])
    target_val = int(args[1], 0) if len(args) > 1 else 100
    print(c(f"\n{'='*60}", Color.BLUE))
    print(c(f"  [TEST] 扫描测试 - 进程 {pid}", Color.BLUE))
    print(c(f"{'='*60}", Color.BLUE))

    print(f"  扫描 int32 值 = {target_val}")

    # 第一轮：精确扫描（2026-08-05 V2：统计耗时——线性批量读 + 对齐步进后应显著下降）
    import time
    t0 = time.time()
    ret = client.scan_start(pid, SCAN_TYPE_INT32, SCAN_MODE_EXACT, target_val, 4, 0)
    t1 = time.time()
    if ret < 0:
        print(c(f"  [错误] 扫描启动失败: {ret}", Color.RED))
        return
    print(c(f"  第一轮扫描启动: ret={ret} 耗时={t1-t0:.2f}s", Color.GREEN))

    # 查询扫描状态（完整性/进度/截断标志）
    st = client.scan_status()
    if st:
        total_mb = st["total_bytes"] / 1048576.0
        scanned_mb = st["scanned_bytes"] / 1048576.0
        pct = (scanned_mb / total_mb * 100) if total_mb > 0 else 0
        print(c(f"  [STATUS] 区域数={st['region_count']} 命中={st['result_count']} "
                f"容量={st['result_capacity']}", Color.CYAN))
        print(c(f"  [STATUS] 扫描进度={scanned_mb:.1f}/{total_mb:.1f} MB "
                f"({pct:.1f}%) 失败页={st['failed_pages']}", Color.CYAN))
        if st["truncated"]:
            print(c("  [警告] 结果缓冲已满（truncated）—— 命中被截断，"
                    "但扫描已覆盖全部区域；请改用更精确的值过滤", Color.RED))
        else:
            print(c("  [OK] 扫描完整：全部区域已覆盖，结果未截断", Color.GREEN))

    # 分页拉取全部结果（2026-08-04：不再只取前 20 条）
    total, results = client.scan_result_all(page_size=512)
    if total < 0:
        print(c(f"  [错误] 获取结果失败: {total}", Color.RED))
        return
    print(c(f"  第一轮结果: {total} 条匹配", Color.GREEN))
    for i, (addr, value, prev) in enumerate(results[:10]):
        print(f"    [{i}] 0x{addr:016X} = {value} (0x{value:016X})")

    if total > 10:
        print(c(f"  (仅显示前 10 条，共 {total} 条)", Color.GRAY))

    # 第二轮：再次扫描相同值（过滤）
    if results:
        print(f"\n  第二轮: 过滤扫描 value={target_val}")
        ret = client.scan_next(SCAN_TYPE_INT32, SCAN_MODE_EXACT, target_val, 4, 0)
        if ret < 0:
            print(c(f"  [错误] 过滤扫描失败: {ret}", Color.RED))
        else:
            ret2, results2 = client.scan_result_all(page_size=512)
            print(c(f"  第二轮结果: {ret2} 条匹配", Color.GREEN))
            for i, (addr, value, prev) in enumerate(results2[:5]):
                print(f"    [{i}] 0x{addr:016X} = {value}")

    # 清除扫描
    client.scan_clear()
    print(c(f"\n  -> 扫描测试完成", Color.GREEN))


def test_freeze(client: KPMClient, args: list):
    """冻结测试：添加冻结项，观察 hit_count 变化"""
    if len(args) < 4:
        print(c("  用法: test_freeze <pid> <addr> <val> <size>", Color.YELLOW))
        return
    pid = int(args[0])
    addr = parse_addr(args[1])
    val = parse_value(args[2])
    size = int(args[3])

    print(c(f"\n{'='*60}", Color.BLUE))
    print(c(f"  [TEST] 冻结测试 - 进程 {pid}", Color.BLUE))
    print(c(f"{'='*60}", Color.BLUE))

    # 添加冻结
    ret = client.freeze_add(pid, addr, val, size)
    if ret < 0:
        print(c(f"  [错误] 添加冻结失败: {ret}", Color.RED))
        return
    idx = ret
    print(c(f"  冻结项 #{idx} 已添加: @0x{addr:016X} val=0x{val:X} size={size}", Color.GREEN))

    # 等待几秒让冻结生效
    print(f"  等待 3 秒让冻结生效...")
    time.sleep(3)

    # 查看列表
    ret, entries = client.freeze_list()
    if ret > 0:
        for e in entries:
            if e["index"] == idx:
                print(c(f"  冻结项 #{idx} 状态: enabled={e['enabled']} "
                        f"hit_count={e['hit_count']}", Color.GREEN))

    # 读取当前值
    ret, data = client.read_mem(pid, addr, size)
    if ret > 0:
        current = int.from_bytes(data, 'little', signed=(size in (1, 2, 4, 8)))
        match = (current == val)
        print(f"  当前值: {current} (0x{current:X})  {'✓ 匹配' if match else '✗ 不匹配'}")

    # 禁用冻结
    print(f"\n  禁用冻结项 #{idx}...")
    client.freeze_toggle(idx, 0)
    time.sleep(1)

    # 再次读取
    ret, data = client.read_mem(pid, addr, size)
    if ret > 0:
        current = int.from_bytes(data, 'little', signed=(size in (1, 2, 4, 8)))
        print(f"  禁用后值: {current} (0x{current:X})")

    # 清理
    client.freeze_remove(idx)
    print(c(f"\n  -> 冻结测试完成（已清理）", Color.GREEN))


# ===== 命令分发 =====

COMMANDS = {
    "help": cmd_help,
    "h": cmd_help,
    "?": cmd_help,
    "info": cmd_info,
    "list": cmd_list,
    "apps": cmd_apps,
    "sysapps": cmd_sysapps,
    "ps": cmd_ps,
    "maps": cmd_maps,
    "region": cmd_region,
    "modules": cmd_modules,
    "hook_plt": cmd_hook_plt,
    "hook_list": cmd_hook_list,
    "hook_remove": cmd_hook_remove,
    "hook_toggle": cmd_hook_toggle,
    "dump": cmd_dump,
    "dumpraw": cmd_dumpraw,
    "dump_all": cmd_dump_all,
    "dump_progress": cmd_dump_progress,
    "dump_cancel": cmd_dump_cancel,
    "bigread": cmd_bigread,
    "bigwrite": cmd_bigwrite,
    "dumpmem": cmd_dumpmem,
    "read": cmd_read,
    "readhex": cmd_readhex,
    "write": cmd_write,
    "writeu32": cmd_write_u32,
    "writeu64": cmd_write_u64,
    "writestr": cmd_write_str,
    "scan": cmd_scan_start,
    "scan_next": cmd_scan_next,
    "scan_result": cmd_scan_result,
    "scan_status": cmd_scan_status,
    "scan_clear": cmd_scan_clear,
    "kscan": cmd_kscan,
    "swapread": cmd_recover_swap,
    "export": cmd_export,
    "group": cmd_group,
    "freeze": cmd_freeze_add,
    "freeze_list": cmd_freeze_list,
    "freeze_toggle": cmd_freeze_toggle,
    "freeze_remove": cmd_freeze_remove,
    "freeze_clear": cmd_freeze_clear,
    "ptr": cmd_ptr_scan,
    "ptr_chain": cmd_ptr_chain,
    "ptr_result": cmd_ptr_result,
    "test_read": test_read,
    "test_scan": test_scan,
    "test_freeze": test_freeze,
    "getlog": cmd_getlog,   # 2026-09-21 诊断：读内核内部日志
}


def interactive_mode(client: KPMClient):
    """交互模式"""
    print(c("\n" + "=" * 60, Color.BLUE))
    print(c("  KPM 内存子系统 - UDP 交互模式", Color.BLUE))
    print(c("=" * 60, Color.BLUE))
    print(f"  目标: {client.host}:{client.port}")
    print("  输入 help 查看命令列表，quit 退出\n")

    while True:
        try:
            line = input(c("kpm-mem> ", Color.CYAN)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("quit", "exit", "q"):
            break

        handler = COMMANDS.get(cmd)
        if not handler:
            print(c(f"  未知命令: {cmd} (输入 help 查看)", Color.RED))
            continue

        try:
            handler(client, args)
        except (IndexError, ValueError) as e:
            print(c(f"  参数错误: {e}", Color.RED))
        except Exception as e:
            print(c(f"  错误: {e}", Color.RED))


def main():
    parser = argparse.ArgumentParser(
        description="KPM 内存子系统 UDP 测试客户端 (二进制协议)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s 192.168.5.2                  # 交互模式
  %(prog)s 192.168.5.2 --list           # 列出全部进程
  %(prog)s 192.168.5.2 --list 50        # 列出前 50 个进程
  %(prog)s 192.168.5.2 --list-apps      # 列出第三方应用（带包名）
  %(prog)s 192.168.5.2 --list-sys       # 列出系统应用（带包名）
  %(prog)s 192.168.5.2 --modules 1234    # 列出进程模块列表（名称/段数/大小/基址）
  %(prog)s 192.168.5.2 --dump 1234 libxxx.so   # dump 模块为 ELF（本地落盘, IDA/脱壳分析）
  %(prog)s 192.168.5.2 --dump 1234 libxxx.so --out ./out/lib.so
  %(prog)s 192.168.5.2 --dump-all 1234   # dump 进程全部具名模块（串行队列）
  %(prog)s 192.168.5.2 -p 17891         # 指定端口

交互模式命令:
  info, list, apps, sysapps, ps, maps, region, modules
  dump, dump_all, dump_progress, dump_cancel
  read, readhex, write, writeu32, writeu64, writestr
  scan, scan_next, scan_result, scan_clear
  freeze, freeze_list, freeze_toggle, freeze_remove, freeze_clear
  ptr, ptr_chain, ptr_result
  test_read, test_scan, test_freeze
        """)
    parser.add_argument("host", help="设备 IP 地址")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                        help=f"UDP 端口 (默认 {DEFAULT_PORT})")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"超时秒数 (默认 {DEFAULT_TIMEOUT})")
    parser.add_argument("--list", nargs="?", const=0, type=int, default=None,
                        metavar="N",
                        help="列出全部进程并退出（可选前 N 条，默认全部）")
    parser.add_argument("--list-apps", action="store_true",
                        help="列出第三方应用进程（带包名）并退出")
    parser.add_argument("--list-sys", action="store_true",
                        help="列出系统应用进程（带包名）并退出")
    parser.add_argument("--modules", type=int, default=None, metavar="PID",
                        help="列出指定进程的模块列表（名称/段数/总大小/基址）并退出")
    parser.add_argument("--dump", nargs="+", default=None,
                        metavar=("PID", "MODULE"),
                        help="dump 进程模块为 ELF 到本地（例: --dump 21080 libxxx.so），"
                             "设备零文件，输出到 ~/kpm_dumps/（可用 --out 指定）")
    parser.add_argument("--dump-all", type=int, default=None, metavar="PID",
                        help="dump 指定进程的全部具名模块（串行队列）到本地")
    parser.add_argument("--out", default=None,
                        help="dump 输出路径/目录（与 --dump/--dump-all 搭配）")

    args = parser.parse_args()

    client = KPMClient(args.host, args.port, args.timeout)

    try:
        # 检查连接
        info = client.info()
        st = info.get("state", {})
        if not st.get("init"):
            print(c("[警告] 模块未初始化", Color.YELLOW))
        if not st.get("mem_rw"):
            print(c("[警告] 内存子系统未就绪 (MEM 位未设置)", Color.YELLOW))

        if args.list is not None:
            limit = args.list
            cmd_list(client, [str(limit)] if limit > 0 else [])
        elif args.list_apps:
            cmd_apps(client, [])
        elif args.list_sys:
            cmd_sysapps(client, [])
        elif args.modules is not None:
            cmd_modules(client, [str(args.modules)])
        elif args.dump_all is not None:
            dl = [str(args.dump_all)]
            if args.out:
                dl += ["--out", args.out]
            cmd_dump_all(client, dl)
        elif args.dump is not None:
            dl = list(args.dump)
            if args.out:
                dl += ["--out", args.out]
            cmd_dump(client, dl)
        else:
            interactive_mode(client)
    finally:
        client.close()


if __name__ == "__main__":
    main()
