#!/usr/bin/env python3
"""
udp_test_gyro.py - KPM 陀螺仪/传感器子系统 UDP 测试客户端（二进制协议版）

通过二进制 UDP 协议与 Android 设备上的 KPM 内核模块通信，
测试陀螺仪/传感器功能（lock/unlock/control/control_stop/state/lock_list/keepalive）。

协议: 二进制 UDP（kpm_udp.c），端口 17891
  - 请求头 48 字节: cmd[4] + seq[4] + arg2[8] + arg3[8] + arg4[8] + arg5[8] + data_len[4] + reserved[4]
  - 响应头 16 字节: seq[4] + ret[4] + data_len[4] + reserved[4]
  - 命令码 XOR 编码: key = 0xDEAD37F3

用法:
    python udp_test_gyro.py 192.168.5.2              # 全自动运行所有测试
    python udp_test_gyro.py 192.168.5.2 -s           # 半自动模式 (每步按回车)
    python udp_test_gyro.py 192.168.5.2 -i           # 交互模式 (手动输入命令)
    python udp_test_gyro.py 192.168.5.2 --test damp_direct  # 只测阻尼叠加
    python udp_test_gyro.py 192.168.5.2 -p 17891     # 指定端口

前置条件:
    1. 设备已加载 kpm_hidden_driver.kpm
    2. KPM 内核 UDP 服务监听 17891 端口（模块加载后自动启动）
    3. 已通过 SukiSU Ultra APP 手动加载模块（禁止命令加载）

注意:
    - 测试体系核心是【用户交互阻尼】：控制 = 虚拟偏移叠加在用户实时读数上
      （输出 = 用户值 + 偏移），用户转动设备始终有效，绝不覆盖。
    - 锁定（强锁）作为对照基线保留：锚点冻结 = 用户转动无效。
    - 建议使用 -s 半自动模式，边转动设备边验证阻尼手感。
    - 全部命令均通过 UDP 通道：陀螺仪 + 状态查询
"""

import socket
import struct
import sys
import time
import argparse
import threading


# ===== 协议常量 =====
XOR_KEY = 0xDEAD37F3
DEFAULT_PORT = 17891
DEFAULT_TIMEOUT = 5.0

# 命令码（与 kpm_comm.h 一致）
CMD_HOOK_INFO       = 0x1005

# 陀螺仪命令码（与 kpm_comm.h 一致）
CMD_GYRO_LOCK          = 0x1040   # 锁定: arg2=type|axis<<8, arg3=value
CMD_GYRO_UNLOCK        = 0x1041   # 解锁: arg2=type|axis<<8 (axis=0xFF 全轴)
CMD_GYRO_LOCK_LIST     = 0x1042   # 获取锁定/控制列表: arg2=max_count → kpm_gyro_entry_t[]
CMD_GYRO_CONTROL       = 0x1043   # 虚拟力: arg2=type|axis<<8, arg3=speed, arg4=offset, arg5=mode
CMD_GYRO_CONTROL_STOP  = 0x1044   # 停止虚拟力: arg2=type|axis<<8 (axis=0xFF 全轴)
CMD_GYRO_STATE         = 0x1045   # 查询陀螺仪模块状态: 返回 [ready]
CMD_GYRO_KEEPALIVE     = 0x1046   # 客户端心跳（≤5s 一次；操作命令自动刷新）

# 类型 / 轴
GYRO_TRANSLATION = 0   # 平移: 加速度/线性加速度/重力等 (ABS_X/Y/Z)
GYRO_ROTATION    = 1   # 旋转: 陀螺仪/旋转矢量等 (ABS_RX/RY/RZ)
GYRO_AXIS_X = 0
GYRO_AXIS_Y = 1
GYRO_AXIS_Z = 2
GYRO_ALL_AXIS = 0xFF

# 控制模式
GYRO_FORCE_RAMP   = 0  # 力/爬升模式（易被校准回正，不推荐）
GYRO_FORCE_DIRECT = 1  # 直接偏移模式（一步置位，不回正，推荐）

# 锁定哨兵（与 LH_gyro.h KPM_GYRO_LOCK_CURRENT 一致，2026-08-15 修改：
# 原为 0，与"锁定到 0.0f"冲突；改为 IEEE754 NaN 位模式）
GYRO_LOCK_CURRENT = 0x7F800001  # lock value 传此值 = 锁定当前读数

# 错误码（与 kpm_comm.h 一致）
KPM_E_INVAL    = 1
KPM_E_NOMEM    = 2
KPM_E_NOTFOUND = 3
KPM_E_FAULT    = 4

# 请求/响应头大小
REQ_HDR_SIZE = 48
RESP_HDR_SIZE = 16

# kpm_state_info_t 陀螺仪字段偏移（结构 256B，int32 数组）
INFO_GYRO_IDX = 42  # 偏移 168 / 4

TYPE_NAMES = {GYRO_TRANSLATION: "平移", GYRO_ROTATION: "旋转"}
AXIS_NAMES = {GYRO_AXIS_X: "X", GYRO_AXIS_Y: "Y", GYRO_AXIS_Z: "Z"}
MODE_NAMES = {GYRO_FORCE_RAMP: "RAMP(力/爬升)", GYRO_FORCE_DIRECT: "DIRECT(直接偏移)"}


def xor_cmd(code: int) -> int:
    """XOR 编码命令码（与 kpm_comm.h KPM_CMD 宏一致）"""
    return (code ^ XOR_KEY) & 0xFFFFFFFF


def pack_type_axis(type_: int, axis: int) -> int:
    """打包 type | (axis << 8) 到 arg2"""
    return (type_ & 0xFF) | ((axis & 0xFF) << 8)


def fbits(value: float) -> int:
    """float → IEEE754 32 位模式（int32）。

    驱动把 lock/control 值当作 float 位模式存储（模块 -mgeneral-regs-only
    禁用 FP，只能以整数位模式承载 float）。因此测试必须发送目标读数对应的
    位模式，而非普通整数。例如 5.0 rad/s → 0x40A00000。"""
    return struct.unpack('<i', struct.pack('<f', float(value)))[0]


def parse_gyro_entry(data: bytes) -> dict:
    """解析 kpm_gyro_entry_t（28 字节）"""
    if len(data) < 28:
        raise ValueError(f"entry 过短: {len(data)} < 28")
    type_, axis, locked, force_mode = struct.unpack("<4B", data[:4])
    lock_value, force_active, force_target, force_speed, force_offset = \
        struct.unpack("<5i", data[4:24])
    lock_current = data[24] if len(data) >= 25 else 0  # kpm_gyro_entry_t +24
    return {
        "type": type_, "type_name": TYPE_NAMES.get(type_, f"type{type_}"),
        "axis": axis, "axis_name": AXIS_NAMES.get(axis, f"axis{axis}"),
        "axis_label": (TYPE_NAMES.get(type_, "?") + " " +
                       AXIS_NAMES.get(axis, f"axis{axis}")),
        "locked": locked,
        "force_mode": force_mode,
        "mode_name": MODE_NAMES.get(force_mode, f"mode{force_mode}"),
        "lock_value": lock_value,
        "force_active": force_active,
        "force_target": force_target,
        "force_speed": force_speed,
        "force_offset": force_offset,
        "lock_current": lock_current,
    }


class KPMClient:
    """KPM UDP 二进制协议客户端"""

    def __init__(self, host: str, port: int = DEFAULT_PORT,
                 timeout: float = DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.seq = 0
        self._tx_lock = threading.Lock()
        self._ka_thread = None
        self._ka_stop = None

    def start_keepalive(self, interval: float = 1.0) -> None:
        """后台线程周期发送 KEEPALIVE，保证手动观察期间锁/控制不被 5s 保活超时释放"""
        if self._ka_thread and self._ka_thread.is_alive():
            return
        self._ka_stop = threading.Event()
        def run():
            while not self._ka_stop.is_set():
                try:
                    self.gyro_keepalive()
                except Exception:
                    pass
                time.sleep(interval)
        self._ka_thread = threading.Thread(target=run, daemon=True)
        self._ka_thread.start()

    def stop_keepalive(self) -> None:
        if self._ka_stop:
            self._ka_stop.set()
        if self._ka_thread:
            self._ka_thread.join(timeout=1.0)

    def send_binary(self, cmd_code: int, arg2: int = 0, arg3: int = 0,
                    arg4: int = 0, arg5: int = 0, payload: bytes = b""):
        """发送二进制请求并接收响应
        返回: (ret:int, data_len:int, payload:bytes)
        失败时 ret < 0"""
        with self._tx_lock:
            self.seq += 1
            cmd_xored = xor_cmd(cmd_code)
            header = struct.pack("<IIQQQQII",
                                 cmd_xored, self.seq,
                                 arg2 & 0xFFFFFFFFFFFFFFFF,
                                 arg3 & 0xFFFFFFFFFFFFFFFF,
                                 arg4 & 0xFFFFFFFFFFFFFFFF,
                                 arg5 & 0xFFFFFFFFFFFFFFFF,
                                 len(payload), 0)
            self.sock.sendto(header + payload, (self.host, self.port))
            data, _ = self.sock.recvfrom(8192)
            if len(data) < RESP_HDR_SIZE:
                raise ValueError(f"响应过短: {len(data)} < {RESP_HDR_SIZE}")
            seq, ret, data_len, reserved = struct.unpack("<IiII", data[:RESP_HDR_SIZE])
            payload = data[RESP_HDR_SIZE:RESP_HDR_SIZE + data_len]
            return ret, data_len, payload

    def close(self):
        self.sock.close()

    # ===== 基础查询命令 =====

    def info(self) -> dict:
        """HOOK_INFO: 返回模块状态（含陀螺仪字段）"""
        ret, data_len, payload = self.send_binary(CMD_HOOK_INFO)
        d = {"state": ret, "raw": f"0x{ret:X}",
             "gyro_ready": -1, "gyro_dev_count": -1,
             "gyro_locked_axes": -1, "gyro_controlled_axes": -1,
             "gyro_client_alive": -1}
        if data_len >= 256:
            fields = struct.unpack("<64i", payload[:256])
            d["gyro_ready"] = fields[INFO_GYRO_IDX + 0]
            d["gyro_dev_count"] = fields[INFO_GYRO_IDX + 1]
            d["gyro_locked_axes"] = fields[INFO_GYRO_IDX + 2]
            d["gyro_controlled_axes"] = fields[INFO_GYRO_IDX + 3]
            d["gyro_client_alive"] = fields[INFO_GYRO_IDX + 4]
        return d

    # ===== 陀螺仪命令 =====

    def gyro_lock(self, type_: int, axis: int, value: int) -> int:
        """GYRO_LOCK: 锁定轴输出为固定值
        arg2=type|axis<<8, arg3=value
        value == GYRO_LOCK_CURRENT (0x7F800001) 表示锁定当前读数：驱动捕获
        下一事件真实读数作为锚点，输出零角速度（角度冻结在当前朝向）。
        value 为其他值（含 0 = float 0.0 位模式）表示锁定到指定的 float 位
        模式目标值（0 即锁定为 0.0，2026-08-15 修复语义冲突）。
        返回: 0=成功, <0=失败"""
        ret, _, _ = self.send_binary(CMD_GYRO_LOCK, arg2=pack_type_axis(type_, axis),
                                     arg3=value & 0xFFFFFFFFFFFFFFFF)
        return ret

    def gyro_unlock(self, type_: int, axis: int) -> int:
        """GYRO_UNLOCK: 解锁轴（axis=0xFF 全轴解锁）"""
        ret, _, _ = self.send_binary(CMD_GYRO_UNLOCK, arg2=pack_type_axis(type_, axis))
        return ret

    def gyro_lock_list(self, max_count: int = 6) -> list:
        """GYRO_LOCK_LIST: 获取锁定/控制列表
        arg2=max_count → kpm_gyro_entry_t[]
        返回: 条目 dict 列表"""
        ret, data_len, payload = self.send_binary(CMD_GYRO_LOCK_LIST, arg2=max_count)
        if ret <= 0 or data_len == 0:
            return []
        entries = []
        off = 0
        while off + 28 <= data_len:
            entries.append(parse_gyro_entry(payload[off:off + 28]))
            off += 28
        return entries

    def gyro_control(self, type_: int, axis: int, speed: int, offset: int,
                     mode: int = GYRO_FORCE_DIRECT) -> int:
        """GYRO_CONTROL: 虚拟力控制
        arg2=type|axis<<8, arg3=speed, arg4=offset, arg5=mode
        speed<=0 视为停止
        返回: 0=成功, <0=失败"""
        ret, _, _ = self.send_binary(CMD_GYRO_CONTROL,
                                     arg2=pack_type_axis(type_, axis),
                                     arg3=speed & 0xFFFFFFFFFFFFFFFF,
                                     arg4=offset & 0xFFFFFFFFFFFFFFFF,
                                     arg5=mode & 0xFFFFFFFFFFFFFFFF)
        return ret

    def gyro_control_stop(self, type_: int, axis: int) -> int:
        """GYRO_CONTROL_STOP: 停止虚拟力（axis=0xFF 全轴）"""
        ret, _, _ = self.send_binary(CMD_GYRO_CONTROL_STOP,
                                     arg2=pack_type_axis(type_, axis))
        return ret

    def gyro_state(self) -> int:
        """GYRO_STATE: 查询陀螺仪模块状态，返回 ready（1=已发现传感器+hook）"""
        ret, data_len, payload = self.send_binary(CMD_GYRO_STATE)
        if ret == 0 and data_len >= 4:
            return struct.unpack("<i", payload[:4])[0]
        return ret

    def gyro_keepalive(self) -> int:
        """GYRO_KEEPALIVE: 客户端心跳（刷新保活时间戳）"""
        ret, _, _ = self.send_binary(CMD_GYRO_KEEPALIVE)
        return ret


# ===== 测试辅助函数 =====

def _wait_user(prompt: str, semi_auto: bool, auto_wait: float = 3.0):
    """提示用户操作并等待
    semi_auto=True 时等待回车，False 时自动等待 auto_wait 秒"""
    print(prompt)
    if semi_auto:
        try:
            input("  完成后按回车继续 (Ctrl+C 跳过)... ")
        except (EOFError, KeyboardInterrupt):
            print(f"  跳过等待，自动等待 {auto_wait:.0f} 秒...")
            time.sleep(auto_wait)
    else:
        time.sleep(auto_wait)


def _assert_ok(ret: int, op: str):
    """断言操作返回值 >= 0"""
    assert ret >= 0, f"{op} 失败: ret={ret}"


def _print_axis_status(entries: list):
    """打印轴状态列表"""
    if not entries:
        print("  (无锁定/控制中的轴)")
        return
    for e in entries:
        status = []
        if e["locked"]:
            if e["lock_current"]:
                status.append("锁定=待捕获当前读数")
            else:
                status.append(f"锁定={e['lock_value']}")
        if e["force_active"]:
            status.append(f"控制={e['mode_name']} 目标={e['force_target']} "
                          f"当前={e['force_offset']} speed={e['force_speed']}")
        print(f"  {e['axis_label']:>6}: {' | '.join(status) if status else '空闲'}")


# ===== 测试用例 =====

def test_connection(client: KPMClient, semi_auto: bool = False):
    """测试 1: 基本连接 + 陀螺仪状态"""
    print("=" * 60)
    print("[TEST] 基本连接 + 陀螺仪状态")
    print("=" * 60)

    info = client.info()
    print(f"  state:      {info['raw']}")
    print(f"  gyro_ready: {info['gyro_ready']}  (1=已发现传感器+hook)")
    print(f"  传感器设备: {info['gyro_dev_count']}")
    print(f"  锁定轴:     {info['gyro_locked_axes']}")
    print(f"  控制轴:     {info['gyro_controlled_axes']}")
    print(f"  客户端在线: {info['gyro_client_alive']}")
    assert info["gyro_ready"] == 1, f"陀螺仪模块未就绪: gyro_ready={info['gyro_ready']}"
    assert info["gyro_dev_count"] > 0, f"未发现传感器设备: {info['gyro_dev_count']}"

    ready = client.gyro_state()
    print(f"  gyro_state: {ready}")
    assert ready == 1, f"GYRO_STATE 异常: {ready}"

    print("  -> 连接测试通过\n")
    return info


def test_keepalive(client: KPMClient, semi_auto: bool):
    """测试 2: 客户端心跳保活"""
    print("=" * 50)
    print("[TEST] 客户端心跳保活 (KEEPALIVE)")
    print("=" * 50)

    ret = client.gyro_keepalive()
    print(f"  gyro_keepalive: ret={ret}")
    _assert_ok(ret, "gyro_keepalive")

    info = client.info()
    print(f"  保活后客户端在线: {info['gyro_client_alive']}")
    assert info["gyro_client_alive"] == 1, "保活后客户端应在线"

    print("  -> 心跳保活测试完成\n")


def test_lock_zero(client: KPMClient, semi_auto: bool):
    """测试 3: 锁定旋转轴为 0（强锁语义，对照阻尼用）"""
    print("=" * 50)
    print("[TEST] 锁定旋转轴为 0 (ROTATION, 强锁对照)")
    print("=" * 50)

    # 锁定旋转 X 轴为 0（陀螺仪 X 角速度固定为 0）
    # 2026-08-15: value=0 现在表示锁定为 0.0f（float 位模式），不再触发
    # "锁定当前"（哨兵已改为 0x7F800001）
    ret = client.gyro_lock(GYRO_ROTATION, GYRO_AXIS_X, fbits(0.0))
    print(f"  lock rot.X=0:     ret={ret}")
    _assert_ok(ret, "lock rot.X")

    _wait_user(
        "  >>> 锁定旋转 X 轴为 0（强锁） <<<\n"
        "  >>> 旋转设备，X 角速度应固定为 0——用户操作完全无效（Z 轴仍变化）",
        semi_auto, auto_wait=3.0)

    entries = client.gyro_lock_list()
    print(f"  当前锁定/控制列表 ({len(entries)} 项):")
    _print_axis_status(entries)
    assert any(e["locked"] for e in entries), "应有已锁定的轴"

    # 解锁单轴
    ret = client.gyro_unlock(GYRO_ROTATION, GYRO_AXIS_X)
    print(f"  unlock rot.X:     ret={ret}")
    _assert_ok(ret, "unlock rot.X")

    entries = client.gyro_lock_list()
    assert not any(e["locked"] for e in entries), "解锁后不应有锁定"
    print("  -> 锁定为 0 测试完成（强锁对照基线）\n")


def test_lock_anchor(client: KPMClient, semi_auto: bool):
    """测试 4: 交互式锁定当前读数 = 锚点冻结（核心锁定语义）

    锁"当前"不是锁一个固定值，而是把【当前朝向】作为锚点冻结：
    此后用户转动该轴完全无效（输出锚点），直到解锁。这是后续
    "锁定锚点 + 阻尼叠加"测试的基础。"""
    print("=" * 50)
    print("[TEST] 交互式锁定当前读数 = 锚点冻结 (LOCK_CURRENT)")
    print("=" * 50)

    _wait_user(
        "  >>> 请实际操作设备：沿某个轴转动到任意一个角度后稳稳停住 <<<\n"
        "  >>> 注意：左边/右边/任意角度都行，脚本会在你停稳的位置冻结 <<<\n"
        "  >>> 停稳后按回车，脚本将发送【锁定当前】命令冻结该朝向",
        semi_auto, auto_wait=3.0)

    # value=GYRO_LOCK_CURRENT（哨兵）→ 锁定用户当前实际停住的位置
    ret = client.gyro_lock(GYRO_ROTATION, GYRO_AXIS_X, GYRO_LOCK_CURRENT)
    print(f"  lock-current rot.X:   ret={ret}")
    _assert_ok(ret, "lock-current rot.X")

    _wait_user(
        "  >>> 已冻结旋转 X 轴当前朝向（锚点） <<<\n"
        "  >>> 现在继续转动设备：X 轴应完全无效（锚点冻结）——这就是强锁",
        semi_auto, auto_wait=3.0)

    entries = client.gyro_lock_list()
    print(f"  当前锁定/控制列表 ({len(entries)} 项):")
    _print_axis_status(entries)
    x_entry = next((e for e in entries
                    if e["type"] == GYRO_ROTATION and e["axis"] == GYRO_AXIS_X), None)
    assert x_entry and x_entry["locked"], "旋转 X 轴应处于锁定状态"
    assert not x_entry["lock_current"], \
        f"锁定当前后应已捕获锚点，不应仍处于待捕获状态: lock_current={x_entry['lock_current']}"
    print(f"  -> 已冻结 X 轴锚点 (lock_value={x_entry['lock_value']} 位模式)")

    # 清理
    ret = client.gyro_unlock(GYRO_ROTATION, GYRO_AXIS_X)
    _assert_ok(ret, "unlock rot.X after anchor")
    print("  -> 锚点冻结测试完成\n")


def test_lock_translation(client: KPMClient, semi_auto: bool):
    """测试 5: 锁定平移轴（加速度，强锁对照）"""
    print("=" * 50)
    print("[TEST] 锁定平移轴 (TRANSLATION, 强锁对照)")
    print("=" * 50)

    # 锁定平移 Z 轴（重力轴）为 0（正常静止时应约 ±9.8 m/s²）
    ret = client.gyro_lock(GYRO_TRANSLATION, GYRO_AXIS_Z, fbits(0.0))
    print(f"  lock tran.Z=0:   ret={ret}")
    _assert_ok(ret, "lock tran.Z")

    _wait_user(
        "  >>> 锁定平移 Z 轴为 0 (强锁) <<<\n"
        "  >>> 移动设备，Z 读数应固定为 0（用户操作无效）",
        semi_auto, auto_wait=3.0)

    entries = client.gyro_lock_list()
    _print_axis_status(entries)

    ret = client.gyro_unlock(GYRO_TRANSLATION, GYRO_AXIS_Z)
    print(f"  unlock tran.Z:    ret={ret}")
    _assert_ok(ret, "unlock tran.Z")

    print("  -> 平移锁定测试完成\n")


def test_damp_direct(client: KPMClient, semi_auto: bool):
    """测试 6（核心）: DIRECT 阻尼叠加 —— 用户交互有效

    控制 = 虚拟偏移叠加在【用户实时读数】上：
        输出 = 用户真实读数 + 偏移
    验证重点：
      - 施加 +5.0 偏移后，转动设备 → 读数 = 你的转动 + 5.0（跟随你的手，
        有偏置感 = "阻尼/虚拟力推着"），【绝不】覆盖成固定 5.0；
      - 停住不动 → 读数停在 5.0（虚拟力推动）；
      - 向左转/向右转都能感知变化（用户控制全程有效）。"""
    print("=" * 50)
    print("[TEST] DIRECT 阻尼叠加 (用户交互有效，核心)")
    print("=" * 50)

    # 旋转 X 轴叠加偏移 +5.0（float 位模式）：
    # 2026-08-15 语义重构：control 的 offset 是【叠加量】不是绝对读数。
    # 输出 = 真实读数 + 5.0 —— 用户转动设备时读数 = 用户值+5.0（控制有效，
    # 不覆盖用户），用户停止转动时读数 = 0+5.0 = 5.0（虚拟力推动）。
    # 注意：offset 必须用 fbits() 包装（float 位模式），speed 同理。
    ret = client.gyro_control(GYRO_ROTATION, GYRO_AXIS_X,
                              speed=fbits(1.0), offset=fbits(5.0), mode=GYRO_FORCE_DIRECT)
    print(f"  control rot.X +5.0 direct: ret={ret}")
    _assert_ok(ret, "control direct")

    _wait_user(
        "  >>> 已对旋转 X 轴叠加 +5.0 虚拟偏移 (DIRECT 阻尼) <<<\n"
        "  >>> 现在【慢慢转动设备】：\n"
        "  >>>   - 向左转：X 读数应【跟随你】向左变化（偏置 +5.0 仍在）\n"
        "  >>>   - 向右转：X 读数应【跟随你】向右变化\n"
        "  >>>   - 停住：读数停在 5.0（虚拟力推着，不回正）\n"
        "  >>> 关键：你的转动始终有效——绝不锁死成固定 5.0",
        semi_auto, auto_wait=5.0)

    entries = client.gyro_lock_list()
    print(f"  当前锁定/控制列表 ({len(entries)} 项):")
    _print_axis_status(entries)
    x_entry = next((e for e in entries
                    if e["type"] == GYRO_ROTATION and e["axis"] == GYRO_AXIS_X), None)
    assert x_entry and x_entry["force_active"], "旋转 X 轴应处于阻尼控制中"
    assert x_entry["force_offset"] == fbits(5.0), \
        f"DIRECT 偏移应一步到位 = fbits(5.0)={fbits(5.0):#x}, 实际 {x_entry['force_offset']:#x}"

    # 反向偏移：验证负方向叠加（向左的阻尼）
    ret = client.gyro_control(GYRO_ROTATION, GYRO_AXIS_X,
                              speed=fbits(1.0), offset=fbits(-3.0), mode=GYRO_FORCE_DIRECT)
    print(f"  control rot.X -3.0 direct: ret={ret}")
    _assert_ok(ret, "control direct -3.0")

    _wait_user(
        "  >>> 偏移已改为 -3.0（反向阻尼） <<<\n"
        "  >>> 转动设备：读数 = 你的转动 + (-3.0)（偏置方向翻转，你仍可操控）",
        semi_auto, auto_wait=4.0)

    # 停止控制（偏移归零，恢复纯用户值）
    ret = client.gyro_control_stop(GYRO_ROTATION, GYRO_AXIS_X)
    print(f"  control_stop rot.X: ret={ret}")
    _assert_ok(ret, "control_stop")

    entries = client.gyro_lock_list()
    x_entry = next((e for e in entries
                    if e["type"] == GYRO_ROTATION and e["axis"] == GYRO_AXIS_X), None)
    assert not (x_entry and x_entry["force_active"]), "停止后不应有阻尼激活"

    print("  -> DIRECT 阻尼叠加测试完成（用户交互全程有效）\n")


def test_damp_no_override(client: KPMClient, semi_auto: bool):
    """测试 7（核心）: 强锁 vs 阻尼 对照 —— 证明控制不覆盖用户

    同屏对照：Y 轴强锁（用户无效）+ X 轴阻尼（用户有效），
    直观验证"控制 = 叠加而非替换"。"""
    print("=" * 50)
    print("[TEST] 强锁 vs 阻尼对照 (不覆盖用户)")
    print("=" * 50)

    # Y 轴强锁为 0（对照）
    ret = client.gyro_lock(GYRO_ROTATION, GYRO_AXIS_Y, fbits(0.0))
    _assert_ok(ret, "lock rot.Y=0")

    # X 轴阻尼叠加 +4.0
    ret = client.gyro_control(GYRO_ROTATION, GYRO_AXIS_X,
                              speed=fbits(1.0), offset=fbits(4.0), mode=GYRO_FORCE_DIRECT)
    _assert_ok(ret, "control rot.X +4.0")

    _wait_user(
        "  >>> 对照设置完成 <<<\n"
        "  >>>   Y 轴 = 强锁 0（固定，用户无效）\n"
        "  >>>   X 轴 = 阻尼 +4.0（跟随你的转动）\n"
        "  >>> 转动设备，观察对比：Y 不动、X 跟随你 —— 阻尼不覆盖用户",
        semi_auto, auto_wait=5.0)

    entries = client.gyro_lock_list()
    print(f"  对照列表 ({len(entries)} 项):")
    _print_axis_status(entries)
    y_entry = next((e for e in entries
                    if e["type"] == GYRO_ROTATION and e["axis"] == GYRO_AXIS_Y), None)
    x_entry = next((e for e in entries
                    if e["type"] == GYRO_ROTATION and e["axis"] == GYRO_AXIS_X), None)
    assert y_entry and y_entry["locked"], "Y 轴应处于强锁"
    assert x_entry and x_entry["force_active"] and not x_entry["locked"], \
        "X 轴应处于阻尼（非强锁）"

    # 清理
    client.gyro_unlock(GYRO_ROTATION, GYRO_AXIS_Y)
    client.gyro_control_stop(GYRO_ROTATION, GYRO_AXIS_X)
    print("  -> 强锁 vs 阻尼对照测试完成\n")


def test_damp_ramp(client: KPMClient, semi_auto: bool):
    """测试 8: RAMP 阻尼渐变 —— 偏移爬升期间用户仍可操控

    RAMP 模式：偏移以 speed 步长从 0 缓慢爬升到 target，期间
    输出 = 用户真实值 + 当前偏移（渐变阻尼，用户操作始终叠加有效）。"""
    print("=" * 50)
    print("[TEST] RAMP 阻尼渐变 (mode=0)")
    print("=" * 50)

    # 旋转 Y 轴 RAMP 逼近 +5.0 偏移（float 位模式步进）
    ret = client.gyro_control(GYRO_ROTATION, GYRO_AXIS_Y,
                              speed=fbits(1.0), offset=fbits(5.0), mode=GYRO_FORCE_RAMP)
    print(f"  control rot.Y +5.0 ramp: ret={ret}")
    _assert_ok(ret, "control ramp")

    _wait_user(
        "  >>> 已对旋转 Y 轴施加 RAMP 阻尼（偏移缓慢爬升到 +5.0） <<<\n"
        "  >>> 观察：Y 读数像被一股力慢慢推偏（渐变），同时转动设备——\n"
        "  >>> 你的转动仍叠加生效（阻尼渐变但不覆盖用户）",
        semi_auto, auto_wait=5.0)

    entries = client.gyro_lock_list()
    _print_axis_status(entries)
    y_entry = next((e for e in entries
                    if e["type"] == GYRO_ROTATION and e["axis"] == GYRO_AXIS_Y), None)
    assert y_entry and y_entry["force_active"], "Y 轴应处于阻尼激活状态"

    # 停止（回正）
    ret = client.gyro_control_stop(GYRO_ROTATION, GYRO_ALL_AXIS)
    print(f"  control_stop rot.all: ret={ret}")
    _assert_ok(ret, "control_stop all")

    entries = client.gyro_lock_list()
    assert not any(e["force_active"] for e in entries), "停止后不应有阻尼激活"
    print("  -> RAMP 阻尼渐变测试完成\n")


def test_lock_plus_damp(client: KPMClient, semi_auto: bool):
    """测试 9（核心）: 锁定锚点 + 阻尼叠加 —— 冻结位置上的虚拟力

    场景：先锁"当前"（锚点冻结，用户转动无效），再叠加控制偏移。
    输出 = 锁定锚点 + 偏移：位置被冻结，但虚拟力仍能推动偏置——
    符合"硬锁定时控制命令依然生效（在锁定锚点基础上叠加偏移）"。"""
    print("=" * 50)
    print("[TEST] 锁定锚点 + 阻尼叠加")
    print("=" * 50)

    _wait_user(
        "  >>> 请把设备转到任意角度停稳 <<<",
        semi_auto, auto_wait=3.0)

    # 先冻结锚点（锁当前）
    ret = client.gyro_lock(GYRO_ROTATION, GYRO_AXIS_X, GYRO_LOCK_CURRENT)
    print(f"  lock-current rot.X:   ret={ret}")
    _assert_ok(ret, "lock-current")

    # 再叠加偏移（锚点基础上 +3.0）
    ret = client.gyro_control(GYRO_ROTATION, GYRO_AXIS_X,
                              speed=fbits(1.0), offset=fbits(3.0), mode=GYRO_FORCE_DIRECT)
    print(f"  control rot.X +3.0:   ret={ret}")
    _assert_ok(ret, "control on locked")

    _wait_user(
        "  >>> 已冻结 X 轴锚点并叠加 +3.0 偏移 <<<\n"
        "  >>> 转动设备：X 完全无效（锚点冻结）；但读数 = 锚点 + 3.0\n"
        "  >>> （位置被锁，虚拟力仍可推动偏置）",
        semi_auto, auto_wait=4.0)

    entries = client.gyro_lock_list()
    print(f"  锚点+阻尼列表 ({len(entries)} 项):")
    _print_axis_status(entries)
    x_entry = next((e for e in entries
                    if e["type"] == GYRO_ROTATION and e["axis"] == GYRO_AXIS_X), None)
    assert x_entry and x_entry["locked"] and x_entry["force_active"], \
        "X 轴应同时处于锁定与阻尼控制"
    assert x_entry["force_offset"] == fbits(3.0), \
        f"锁定锚点上的偏移应 = fbits(3.0), 实际 {x_entry['force_offset']:#x}"

    # 清理
    client.gyro_unlock(GYRO_ROTATION, GYRO_AXIS_X)
    client.gyro_control_stop(GYRO_ROTATION, GYRO_AXIS_X)
    print("  -> 锁定锚点 + 阻尼叠加测试完成\n")


def test_multi_axis(client: KPMClient, semi_auto: bool):
    """测试 10: 多轴阻尼组合"""
    print("=" * 50)
    print("[TEST] 多轴阻尼组合")
    print("=" * 50)

    # 同时阻尼控制旋转 X(+5.0)/Y(-2.0) + 锁定平移 Z(锚点)
    for axis, off in ((GYRO_AXIS_X, 5.0), (GYRO_AXIS_Y, -2.0)):
        ret = client.gyro_control(GYRO_ROTATION, axis, speed=fbits(1.0),
                                  offset=fbits(off), mode=GYRO_FORCE_DIRECT)
        _assert_ok(ret, f"control rot.{AXIS_NAMES[axis]} {off}")
    ret = client.gyro_lock(GYRO_TRANSLATION, GYRO_AXIS_Z, fbits(0.0))
    _assert_ok(ret, "lock tran.Z")

    _wait_user(
        "  >>> 旋转 X(+5.0) Y(-2.0) 阻尼 + 平移 Z 锁定 <<<\n"
        "  >>> 转动设备：X/Y 跟随你（带偏置），Z 固定",
        semi_auto, auto_wait=4.0)

    entries = client.gyro_lock_list()
    print(f"  多轴操作后列表 ({len(entries)} 项):")
    _print_axis_status(entries)
    assert len(entries) >= 3, f"应有至少 3 个轴被操作: {len(entries)}"

    # 全轴清理
    client.gyro_unlock(GYRO_ROTATION, GYRO_ALL_AXIS)
    client.gyro_unlock(GYRO_TRANSLATION, GYRO_ALL_AXIS)
    client.gyro_control_stop(GYRO_ROTATION, GYRO_ALL_AXIS)
    client.gyro_control_stop(GYRO_TRANSLATION, GYRO_ALL_AXIS)

    entries = client.gyro_lock_list()
    assert not entries, f"清理后应无控制轴: {len(entries)}"
    print("  -> 多轴阻尼组合测试完成\n")


def test_stop_cleanup(client: KPMClient, semi_auto: bool):
    """测试 11: 停止/回正后偏移归零，恢复纯用户值"""
    print("=" * 50)
    print("[TEST] 停止/回正清理")
    print("=" * 50)

    # 施加控制再停止
    client.gyro_control(GYRO_ROTATION, GYRO_AXIS_X, speed=fbits(1.0),
                        offset=fbits(5.0), mode=GYRO_FORCE_DIRECT)
    ret = client.gyro_control_stop(GYRO_ROTATION, GYRO_ALL_AXIS)
    print(f"  control_stop rot.all: ret={ret}")
    _assert_ok(ret, "control_stop")
    client.gyro_unlock(GYRO_ROTATION, GYRO_ALL_AXIS)
    client.gyro_unlock(GYRO_TRANSLATION, GYRO_ALL_AXIS)

    entries = client.gyro_lock_list()
    print(f"  清理后列表条目数: {len(entries)}")
    assert not entries, f"清理后应无控制轴: {entries}"
    print("  -> 停止/回正清理测试完成（偏移归零，用户控制恢复纯值）\n")


def test_error_paths(client: KPMClient, semi_auto: bool):
    """测试 12: 异常命令（无效 type/axis，驱动应静默拒绝不崩溃）"""
    print("=" * 50)
    print("[TEST] 异常命令")
    print("=" * 50)

    # 无效 type=5
    ret = client.gyro_lock(5, GYRO_AXIS_X, 0)
    print(f"  lock type=5 invalid:      ret={ret}")

    # 无效 axis=10
    ret = client.gyro_control(1, 10, 5, 100, GYRO_FORCE_DIRECT)
    print(f"  control axis=10 invalid:  ret={ret}")

    # speed<=0 视为停止（不报错）
    ret = client.gyro_control(GYRO_ROTATION, GYRO_AXIS_X, speed=0, offset=100,
                              mode=GYRO_FORCE_DIRECT)
    print(f"  control speed=0 (stop):   ret={ret}")
    _assert_ok(ret, "control speed=0")

    # 未知命令码（静默丢弃，可能超时）
    print("  发送未知命令 0x10FF（应无响应，驱动静默丢弃）...")
    try:
        ret, _, _ = client.send_binary(0x10FF)
        print(f"  未知命令返回: ret={ret}")
    except socket.timeout:
        print("  未知命令无响应（符合预期，端口静默）")

    print("  -> 异常命令测试完成\n")


def run_all_tests(client: KPMClient, semi_auto: bool = False):
    """运行所有测试"""
    print("\n" + "=" * 60)
    print("  KPM 陀螺仪/传感器子系统 - UDP 二进制协议测试")
    if semi_auto:
        print("  模式: 半自动 (每项测试后按回车继续，输入 s 跳过)")
    else:
        print("  模式: 全自动")
    print("=" * 60 + "\n")
    print("  注意: 测试会锁定/阻尼控制陀螺仪轴，结束后自动全部清理\n")

    tests = [
        ("连接+状态", test_connection),
        ("心跳保活", test_keepalive),
        ("锁定为0(强锁对照)", test_lock_zero),
        ("锁定当前=锚点冻结", test_lock_anchor),
        ("锁定平移", test_lock_translation),
        ("DIRECT阻尼叠加", test_damp_direct),
        ("强锁vs阻尼对照", test_damp_no_override),
        ("RAMP阻尼渐变", test_damp_ramp),
        ("锚点+阻尼叠加", test_lock_plus_damp),
        ("多轴阻尼组合", test_multi_axis),
        ("停止回正", test_stop_cleanup),
        ("异常命令", test_error_paths),
    ]

    passed = 0
    failed = 0
    skipped = 0
    total = len(tests)

    for i, (name, test_fn) in enumerate(tests, 1):
        if semi_auto:
            print(f"\n  [{i}/{total}] 即将测试: {name}")
            try:
                user_input = input("  按回车继续 / 输入 s 跳过 / 输入 q 退出 > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if user_input == "q":
                print("  用户退出")
                break
            if user_input == "s":
                print(f"  [SKIP] {name}")
                skipped += 1
                continue

        try:
            test_fn(client, semi_auto)
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {name}: {e}\n")
            failed += 1

    # 最终清理：确保所有轴解锁/停止
    print("\n  最终清理: 解锁/停止所有轴...")
    try:
        client.gyro_unlock(GYRO_ROTATION, GYRO_ALL_AXIS)
        client.gyro_unlock(GYRO_TRANSLATION, GYRO_ALL_AXIS)
        client.gyro_control_stop(GYRO_ROTATION, GYRO_ALL_AXIS)
        client.gyro_control_stop(GYRO_TRANSLATION, GYRO_ALL_AXIS)
        print("  清理完成")
    except Exception as e:
        print(f"  清理失败: {e}")

    print("=" * 60)
    result_str = f"  结果: {passed} 通过, {failed} 失败"
    if skipped > 0:
        result_str += f", {skipped} 跳过"
    print(result_str)
    print("=" * 60)


def interactive_mode(client: KPMClient):
    """交互模式 - 手动输入命令"""
    print("\nKPM 陀螺仪 UDP 交互模式 (二进制协议)")
    print("输入 help 查看命令列表，quit 退出\n")

    while True:
        try:
            line = input("kpm-gyro> ").strip()
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

        try:
            if cmd == "help":
                print("命令列表:")
                print("  info                    陀螺仪模块状态")
                print("  state                   查询陀螺仪就绪")
                print("  list [max]              锁定/控制列表")
                print("  keepalive               客户端心跳")
                print("  lock <type> <axis> <value>   锁定轴 (value 为 float 位模式；0x7F800001=锁定当前/锚点)")
                print("  unlock <type> [axis]        解锁轴 (省略axis=全轴)")
                print("  ctrl <type> <axis> <speed> <offset> [mode]  虚拟力控制")
                print("  stop <type> [axis]          停止虚拟力 (省略axis=全轴)")
                print("  clean                     全轴清理")
                print("  quit                    退出")
                print("  type: 0=平移 1=旋转 | axis: 0=X 1=Y 2=Z")

            elif cmd == "info":
                info = client.info()
                print(f"  state={info['raw']} gyro_ready={info['gyro_ready']} "
                      f"dev={info['gyro_dev_count']} locked={info['gyro_locked_axes']} "
                      f"ctrl={info['gyro_controlled_axes']} alive={info['gyro_client_alive']}")

            elif cmd == "state":
                print(f"  ready={client.gyro_state()}")

            elif cmd == "keepalive":
                print(f"  ret={client.gyro_keepalive()}")

            elif cmd == "list":
                max_count = int(args[0]) if len(args) >= 1 else 6
                entries = client.gyro_lock_list(max_count)
                _print_axis_status(entries)

            elif cmd == "lock":
                t = int(args[0]); a = int(args[1]); v = int(args[2])
                print(f"  ret={client.gyro_lock(t, a, v)}")

            elif cmd == "unlock":
                t = int(args[0])
                a = int(args[1]) if len(args) >= 2 else GYRO_ALL_AXIS
                print(f"  ret={client.gyro_unlock(t, a)}")

            elif cmd == "ctrl":
                t = int(args[0]); a = int(args[1]); s = int(args[2])
                o = int(args[3])
                m = int(args[4]) if len(args) >= 5 else GYRO_FORCE_DIRECT
                print(f"  ret={client.gyro_control(t, a, s, o, m)}")

            elif cmd == "stop":
                t = int(args[0])
                a = int(args[1]) if len(args) >= 2 else GYRO_ALL_AXIS
                print(f"  ret={client.gyro_control_stop(t, a)}")

            elif cmd == "clean":
                client.gyro_unlock(GYRO_ROTATION, GYRO_ALL_AXIS)
                client.gyro_unlock(GYRO_TRANSLATION, GYRO_ALL_AXIS)
                client.gyro_control_stop(GYRO_ROTATION, GYRO_ALL_AXIS)
                client.gyro_control_stop(GYRO_TRANSLATION, GYRO_ALL_AXIS)
                print("  已全轴清理")

            else:
                print(f"  未知命令: {cmd} (输入 help 查看)")

        except (IndexError, ValueError) as e:
            print(f"  参数错误: {e}")
        except Exception as e:
            print(f"  错误: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="KPM 陀螺仪/传感器子系统 UDP 测试客户端 (二进制协议)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s 192.168.5.2              # 全自动运行所有测试
  %(prog)s 192.168.5.2 -s           # 半自动模式 (每步按回车)
  %(prog)s 192.168.5.2 -i           # 交互模式 (手动输入命令)
  %(prog)s 192.168.5.2 --test lock  # 只测试锁定
  %(prog)s 192.168.5.2 -p 17891     # 指定端口

测试选项 (--test):
  connection  基本连接 + 陀螺仪状态
  keepalive   客户端心跳保活
  lock_zero   锁定为 0（强锁对照基线）
  lock_anchor 交互式锁定当前 = 锚点冻结
  lock_tran   锁定平移轴
  damp_direct DIRECT 阻尼叠加（核心：用户交互有效）
  damp_override 强锁 vs 阻尼对照（不覆盖用户）
  damp_ramp   RAMP 阻尼渐变
  anchor_damp 锁定锚点 + 阻尼叠加
  multi       多轴阻尼组合
  cleanup     停止/回正清理
  error       异常命令
  all         全部测试 (默认)

命令列表 (交互模式):
  info, state, list, keepalive
  lock, unlock, ctrl, stop, clean
        """)
    parser.add_argument("host", help="设备 IP 地址")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                        help=f"UDP 端口 (默认 {DEFAULT_PORT})")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"超时秒数 (默认 {DEFAULT_TIMEOUT})")
    parser.add_argument("-i", "--interactive", action="store_true",
                        help="交互模式 (手动输入命令)")
    parser.add_argument("-s", "--semi-auto", action="store_true",
                        help="半自动模式 (每项测试后按回车继续，输入 s 跳过)")
    parser.add_argument("--test", choices=[
        "connection", "keepalive", "lock_zero", "lock_anchor", "lock_tran",
        "damp_direct", "damp_override", "damp_ramp", "anchor_damp",
        "multi", "cleanup", "error", "all"
    ], default="all", help="运行指定测试")

    args = parser.parse_args()

    client = KPMClient(args.host, args.port, args.timeout)
    client.start_keepalive()

    try:
        if args.interactive:
            interactive_mode(client)
        elif args.test == "all":
            run_all_tests(client, semi_auto=args.semi_auto)
        else:
            test_map = {
                "connection": test_connection,
                "keepalive": test_keepalive,
                "lock_zero": test_lock_zero,
                "lock_anchor": test_lock_anchor,
                "lock_tran": test_lock_translation,
                "damp_direct": test_damp_direct,
                "damp_override": test_damp_no_override,
                "damp_ramp": test_damp_ramp,
                "anchor_damp": test_lock_plus_damp,
                "multi": test_multi_axis,
                "cleanup": test_stop_cleanup,
                "error": test_error_paths,
            }
            test_map[args.test](client, semi_auto=args.semi_auto)
    finally:
        client.stop_keepalive()
        client.close()


if __name__ == "__main__":
    main()