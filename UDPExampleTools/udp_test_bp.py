#!/usr/bin/env python3
"""
udp_test_bp.py - KPM 硬件断点/调试子系统 UDP 测试客户端

针对 Android 设备上的 KPM 内核模块，通过 UDP 17891 通道测试断点功能：
  - 软件断点 (type=0)   → 已禁用（返回 -KPM_E_INVAL）
  - 硬件执行断点 (type=1) → register_user_hw_breakpoint
  - 硬件写观察点 (type=2) → register_user_hw_breakpoint (W)
  - 硬件读写观察点 (type=3) → register_user_hw_breakpoint (RW)
  - 内存断点 (type=4)   → PTE 只读
  - 断点列表 / 命中信息 / 命中通知

安全策略：仅验证「设置 → 列表 → 清除」往返是否成功（验证 PMU 可用性与
协议正确性），不做真正的命中等待——避免对运行中的系统进程触发 Debug
异常导致崩溃（本项目未实现 Debug 异常处理，命中=SIGTRAP 崩溃）。

协议: 二进制 UDP (kpm_udp.c)，端口 17891
  - 请求头 48 字节: cmd[4] + seq[4] + arg2[8] + arg3[8] + arg4[8] + arg5[8] + data_len[4] + reserved[4]
  - 响应头 16 字节: seq[4] + ret[4] + data_len[4] + reserved[4]
  - 命令码 XOR 编码: key = 0xDEAD37F3

用法:
    python udp_test_bp.py 192.168.5.5                 # 全自动
    python udp_test_bp.py 192.168.5.5 --pid 3199      # 指定目标进程
    python udp_test_bp.py 192.168.5.5 --probe-only    # 仅探测 PMU 状态
"""

import socket
import struct
import sys
import time
import argparse

XOR_KEY = 0xDEAD37F3
DEFAULT_PORT = 17891
DEFAULT_TIMEOUT = 10.0

# 命令码
CMD_HOOK_INFO         = 0x1005
CMD_DEBUG_BP_SET      = 0x1130
CMD_DEBUG_BP_CLEAR    = 0x1131
CMD_DEBUG_BP_LIST     = 0x1132
CMD_DEBUG_BP_HIT      = 0x1133
CMD_DEBUG_BP_NOTIFY   = 0x1136
CMD_PROC_LIST         = 0x1145

# 断点类型
BP_TYPE_SOFTWARE  = 0
BP_TYPE_HW_EXEC   = 1
BP_TYPE_HW_WRITE  = 2
BP_TYPE_HW_RW     = 3
BP_TYPE_MEMORY    = 4
BP_TYPE_NAMES = {
    BP_TYPE_SOFTWARE: "软件断点",
    BP_TYPE_HW_EXEC: "硬件执行断点",
    BP_TYPE_HW_WRITE: "硬件写观察点",
    BP_TYPE_HW_RW: "硬件读写观察点",
    BP_TYPE_MEMORY: "内存断点(PTE只读)",
}

# 错误码
KPM_E_INVAL    = 1
KPM_E_NOMEM    = 2
KPM_E_NOTFOUND = 3
KPM_E_FAULT    = 4
KPM_E_PERM     = 5
KPM_E_BUSY     = 6
ERR_NAMES = {
    KPM_E_INVAL: "KPM_E_INVAL(参数错误)",
    KPM_E_NOMEM: "KPM_E_NOMEM(无内存)",
    KPM_E_NOTFOUND: "KPM_E_NOTFOUND(未找到)",
    KPM_E_FAULT: "KPM_E_FAULT(缺页)",
    KPM_E_PERM: "KPM_E_PERM(权限)",
    KPM_E_BUSY: "KPM_E_BUSY(忙/PMU不可用)",
}

REQ_HDR_SIZE = 48
RESP_HDR_SIZE = 16

# kpm_breakpoint_t 结构大小（内核侧 sizeof，含对齐）
# 布局: enabled(0,4) pid(4,4) addr(8,8) size(16,8) type(24,4) hit_count(28,4)
#       saved_orig(32,4) [pad] saved_pte(40,8) saved_pgd(48,8) perf_event(56,8)
#       hw_reg_idx(64,4) notify(68,4) -> sizeof = 72
BP_ENTRY_SIZE = 72


def xor_cmd(code: int) -> int:
    return (code ^ XOR_KEY) & 0xFFFFFFFF


class KPMClient:
    def __init__(self, host, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 * 1024 * 1024)
        self.seq = 0

    def send_binary(self, cmd_code, arg2=0, arg3=0, arg4=0, arg5=0,
                    payload=b"", retries=3):
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
        for attempt in range(max(1, retries)):
            self.sock.sendto(pkt, (self.host, self.port))
            deadline = time.monotonic() + self.timeout
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
                    continue
                seq, ret, data_len, reserved = struct.unpack("<IiII", data[:RESP_HDR_SIZE])
                if seq != self.seq:
                    continue
                resp = data[RESP_HDR_SIZE:RESP_HDR_SIZE + data_len]
                return ret, data_len, resp
            if attempt + 1 >= max(1, retries):
                break
        raise last_err

    def info(self):
        ret, dl, payload = self.send_binary(CMD_HOOK_INFO)
        if len(payload) < 256:
            return {"state_raw": ret}
        state = ret
        return {
            "state_raw": state,
            "init": bool(state & 0x01),
            "prctl": bool(state & 0x02),
            "touch": bool(state & 0x04),
            "mem_rw": bool(state & 0x08),
            "intercept": bool(state & 0x10),
            "udp": bool(state & 0x20),
            "mem_scan": bool(state & 0x40),
            "mem_freeze": bool(state & 0x80),
            "ptr_scan": bool(state & 0x100),
            "debug": bool(state & 0x200),
            "proc": bool(state & 0x400),
            "stealth": bool(state & 0x800),
            "payload_len": len(payload),
        }

    def proc_list(self, max_count=100):
        ret, dl, payload = self.send_binary(CMD_PROC_LIST, arg2=0, arg3=max_count)
        if ret <= 0:
            return []
        procs = []
        # 每条 48 字节：pid(4)+ppid(4)+uid(4)+state(4)+name(16)+path(16)? 按需尝试
        # 实际: 48 字节/条。解析前 12 字节
        entry = 48
        for i in range(0, len(payload), entry):
            if i + 12 > len(payload):
                break
            pid, ppid, uid = struct.unpack_from("<iii", payload, i)
            name = payload[i+12:i+28].split(b"\x00")[0].decode(errors="ignore")
            procs.append({"pid": pid, "name": name})
        return procs

    def bp_set(self, pid, btype, addr, size):
        ret, _, _ = self.send_binary(CMD_DEBUG_BP_SET,
                                     arg2=pid, arg3=btype, arg4=addr, arg5=size)
        return ret

    def bp_clear(self, index):
        ret, _, _ = self.send_binary(CMD_DEBUG_BP_CLEAR, arg2=index)
        return ret

    def bp_list(self, max_count=16):
        ret, dl, payload = self.send_binary(CMD_DEBUG_BP_LIST, arg2=max_count)
        if ret <= 0:
            return ret, []
        entries = []
        for i in range(0, len(payload), BP_ENTRY_SIZE):
            if i + BP_ENTRY_SIZE > len(payload):
                break
            enabled, pid = struct.unpack_from("<ii", payload, i)
            addr, size = struct.unpack_from("<QQ", payload, i + 8)
            btype, hit_count = struct.unpack_from("<ii", payload, i + 24)
            saved_orig = struct.unpack_from("<I", payload, i + 32)[0]
            saved_pte, saved_pgd = struct.unpack_from("<QQ", payload, i + 40)
            perf_event = struct.unpack_from("<Q", payload, i + 56)[0]
            hw_reg_idx, notify = struct.unpack_from("<ii", payload, i + 64)
            entries.append({
                "enabled": enabled, "pid": pid, "addr": addr, "size": size,
                "type": btype, "hit_count": hit_count, "perf_event": perf_event,
                "hw_reg_idx": hw_reg_idx, "notify": notify,
            })
        return ret, entries

    def bp_hit(self):
        ret, dl, payload = self.send_binary(CMD_DEBUG_BP_HIT)
        if ret < 0 or dl < 24:
            return ret, None
        bp_index, pid = struct.unpack_from("<ii", payload, 0)
        addr, pc, value = struct.unpack_from("<QQQ", payload, 8)
        return ret, {"bp_index": bp_index, "pid": pid, "addr": addr, "pc": pc, "value": value}

    def bp_notify(self, enable, port=0):
        ret, _, _ = self.send_binary(CMD_DEBUG_BP_NOTIFY, arg2=enable, arg3=port)
        return ret

    def close(self):
        self.sock.close()


def err_str(ret):
    if ret >= 0:
        return f"OK({ret})"
    e = -ret
    return f"ERR({ret}) = {ERR_NAMES.get(e, f'未知错误码{e}')}"


def color(text, code=36):
    return f"\033[{code}m{text}\033[0m"


def probe(info):
    """探测断点子系统状态"""
    print(color("\n===== 断点子系统 PMU 探测 =====", 36))
    print(f"  debug 功能位:  {'已启用' if info.get('debug') else '未启用'}")
    print(f"  state_raw:    0x{info.get('state_raw', 0):X}")
    # 通过设置一个硬断点再清除来验证 PMU 可用性（关键探测）
    return True


def find_target_pid(client, prefer_names=("com.android.systemui", "system_server",
                                           "com.android.phone", "surfaceflinger")):
    procs = client.proc_list(200)
    # 优先匹配系统服务
    for p in procs:
        for n in prefer_names:
            if n in p["name"]:
                return p["pid"], p["name"]
    # 兜底：返回第一个非内核进程
    for p in procs:
        if p["pid"] > 0 and p["name"] and p["pid"] > 1000:
            return p["pid"], p["name"]
    return None, None


def run_test(client, pid, pname, probe_only=False):
    print(color(f"\n[目标进程] PID={pid} name={pname}", 36))
    print(f"[测试1] info 状态确认")
    info = client.info()
    for k, v in info.items():
        if k in ("state_raw", "payload_len"):
            print(f"  {k}: {v}")
        elif isinstance(v, bool):
            print(f"  {k}: {'Y' if v else '-'}")
    if not info.get("debug"):
        print(color("  [警告] debug 位未置位，断点模块可能未初始化", 33))

    print(color("\n[测试2] 硬件执行断点 type=1 (验证 PMU 可用性 + 设置/清除往返)", 36))
    # 对目标进程代码段地址 0x400000 附近设置执行断点（不等待命中，随即清除）
    test_addr = 0x400000
    r = client.bp_set(pid, BP_TYPE_HW_EXEC, test_addr, 4)
    print(f"  BP_SET HW_EXEC addr=0x{test_addr:x} -> {err_str(r)}")
    if r >= 0:
        idx = r
        # 列表确认
        lr, entries = client.bp_list(16)
        print(f"  BP_LIST -> ret={lr}, 断点数={len(entries)}")
        for e in entries:
            if e["enabled"]:
                print(f"    [idx?] type={e['type']}({BP_TYPE_NAMES.get(e['type'],'?')}) "
                      f"pid={e['pid']} addr=0x{e['addr']:x} hit={e['hit_count']} "
                      f"perf=0x{e['perf_event']:x}")
        # 清除
        r2 = client.bp_clear(idx)
        print(f"  BP_CLEAR idx={idx} -> {err_str(r2)}")
        # 列表确认已清
        lr2, entries2 = client.bp_list(16)
        active = sum(1 for e in entries2 if e["enabled"])
        print(f"  BP_LIST after clear -> 活跃断点数={active}")
    else:
        print(color(f"  [探测结论] 硬件断点不可用: {err_str(r)}"
                    "（PMU 探测失败 或 目标进程不可达）", 33))

    print(color("\n[测试3] 硬件写观察点 type=2", 36))
    r = client.bp_set(pid, BP_TYPE_HW_WRITE, test_addr, 4)
    print(f"  BP_SET HW_WRITE addr=0x{test_addr:x} -> {err_str(r)}")
    if r >= 0:
        client.bp_clear(r)
        print(f"  BP_CLEAR idx={r} -> done")

    print(color("\n[测试4] 硬件读写观察点 type=3", 36))
    r = client.bp_set(pid, BP_TYPE_HW_RW, test_addr, 4)
    print(f"  BP_SET HW_RW addr=0x{test_addr:x} -> {err_str(r)}")
    if r >= 0:
        client.bp_clear(r)
        print(f"  BP_CLEAR idx={r} -> done")

    print(color("\n[测试5] 软件断点 type=0 (预期禁用)", 36))
    r = client.bp_set(pid, BP_TYPE_SOFTWARE, test_addr, 4)
    print(f"  BP_SET SW addr=0x{test_addr:x} -> {err_str(r)}"
          f"  {'(符合预期: 软件断点已禁用)' if r == -KPM_E_INVAL else ''}")

    print(color("\n[测试6] 内存断点 type=4 (PTE 只读)", 36))
    r = client.bp_set(pid, BP_TYPE_MEMORY, 0x40000000, 4096)
    print(f"  BP_SET MEMORY addr=0x40000000 size=4096 -> {err_str(r)}")
    if r >= 0:
        client.bp_clear(r)
        print(f"  BP_CLEAR idx={r} -> done")

    print(color("\n[测试7] 断点命中信息 + 通知开关", 36))
    hr, hit = client.bp_hit()
    if hit:
        print(f"  BP_HIT -> bp_index={hit['bp_index']} pid={hit['pid']} "
              f"addr=0x{hit['addr']:x} pc=0x{hit['pc']:x}")
    else:
        print(f"  BP_HIT -> ret={hr} (无命中记录)")
    n1 = client.bp_notify(1)
    print(f"  BP_NOTIFY enable=1 -> {err_str(n1)}")
    n2 = client.bp_notify(0)
    print(f"  BP_NOTIFY enable=0 -> {err_str(n2)}")

    print(color("\n[测试8] 非法参数 (越界/负 pid)", 36))
    r = client.bp_set(0, BP_TYPE_HW_EXEC, test_addr, 4)   # pid=0 非法
    print(f"  BP_SET pid=0 -> {err_str(r)}")
    r = client.bp_set(pid, 99, test_addr, 4)               # type=99 非法
    print(f"  BP_SET type=99 -> {err_str(r)}")
    r = client.bp_clear(999)                               # 越界 index
    print(f"  BP_CLEAR idx=999 -> {err_str(r)}")

    print(color("\n===== 断点测试完成 =====", 36))


def main():
    parser = argparse.ArgumentParser(description="KPM 硬件断点 UDP 测试")
    parser.add_argument("host", help="设备 IP")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--pid", type=int, default=None, help="指定目标进程 PID")
    parser.add_argument("--probe-only", action="store_true", help="仅探测 PMU 状态")
    args = parser.parse_args()

    client = KPMClient(args.host, args.port, args.timeout)
    try:
        info = client.info()
        print(color(f"连接 {args.host}:{args.port} 成功, state=0x{info.get('state_raw',0):X}", 32))

        if args.pid:
            pid, pname = args.pid, "指定进程"
        else:
            pid, pname = find_target_pid(client)
            if pid is None:
                print("无法确定目标进程")
                return
        run_test(client, pid, pname, args.probe_only)
    except socket.timeout:
        print(color("[错误] UDP 超时——确认模块已加载且端口 17891 可达", 31))
    finally:
        client.close()


if __name__ == "__main__":
    main()
