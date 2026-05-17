#!/usr/bin/env python3
# 使用 Python3 运行；板子上需有 python3

"""
将板载触摸屏 (/dev/input/event0) 转发到 USB HID Gadget (/dev/hidg0)。

数据流: Goodix 本地屏 -> Linux input 子系统 -> 本程序 -> hidg0 -> USB 主机

默认单点 (TOUCH_MODE=single)；报告长度 8 字节，与 usb-gadget-touch.sh 一致。
多点: TOUCH_MODE=multi，gadget 须为 5 点描述符且 report_length=64。
"""

import errno
# 标准 errno 常量，用于判断 USB 写失败类型

import fcntl
# ioctl，用于 EVIOCGRAB 独占本地触摸屏

import os
# 打开 hidg、读 configfs、os.write

import struct
# 解析 input_event、打包 HID 坐标 (uint16 LE)

import select
# 非阻塞等待 /dev/input/event0 可读

import time
# monotonic 计时：限频、等待主机枚举

# --- Linux input 事件类型与常用码 (linux/input-event-codes.h) ---
EV_SYN = 0x00
# 同步类事件

EV_KEY = 0x01
# 按键类（含 BTN_TOUCH）

EV_ABS = 0x03
# 绝对坐标类（触摸 X/Y、多点槽位等）

SYN_REPORT = 0
# 标志本帧 input 事件结束，应在此后发送 HID 报告

ABS_X = 0x00
# 单点绝对 X（部分驱动在 SYN 时同步给出）

ABS_Y = 0x01
# 单点绝对 Y

ABS_MT_SLOT = 0x2F
# 多点协议：当前正在更新哪个 slot (0~4)

ABS_MT_TRACKING_ID = 0x39
# 多点：>=0 表示按下并分配 tracking id，-1 表示该 slot 抬起

ABS_MT_POSITION_X = 0x35
# 多点：当前 slot 的 X

ABS_MT_POSITION_Y = 0x36
# 多点：当前 slot 的 Y

BTN_TOUCH = 0x14A
# 单点触摸按下(1)/抬起(0)，作 build_report 的辅助

# --- 设备路径与运行参数 ---
INPUT_DEV = "/dev/input/event0"
# 板载 Goodix 电容屏对应的 input 节点

HIDG_DEV = "/dev/hidg0"
# USB gadget HID 字符设备；写入字节数须等于 report_length

GADGET_DIR = "/sys/kernel/config/usb_gadget/touch"
# gadget 的 configfs 路径，用于读 UDC 状态与 report_length

TOUCH_MODE = os.environ.get("TOUCH_MODE", "single").lower()
# 环境变量 TOUCH_MODE：single（默认）或 multi

NUM_SLOTS = 5
# 与 Goodix 最多 5 点一致；单点模式只取第一个 active 触点

SRC_X_MAX = 1023
# 本地触摸屏 X 逻辑最大值（evtest 中 Max）

SRC_Y_MAX = 599
# 本地触摸屏 Y 逻辑最大值

HID_X_MAX = 4095
# HID 描述符中 X 逻辑最大值

HID_Y_MAX = 4095
# HID 描述符中 Y 逻辑最大值

INVERT_Y = False
# True 时 Y 轴翻转（部分 Windows 坐标系上下颠倒）

GRAB_INPUT = True
# True：独占 event0，触摸只发 USB，板子 UI 不再响应

HOST_WAIT_SEC = 15
# 启动后等待 USB 主机进入 configured 的最长秒数

MIN_WRITE_INTERVAL = 0.008
# 两次写 hidg 最小间隔（秒），降低 STM32 dwc2 端点错误风险

SELECT_TIMEOUT = 1.0
# select 超时，便于响应 Ctrl+C

EVENT_FMT = "llHHi"
# struct input_event: time.tv_sec, time.tv_usec, type, code, value

EVENT_SIZE = struct.calcsize(EVENT_FMT)
# 单个 input_event 结构体字节数（通常 24）


def read_report_len():
    """从 configfs 读取 report_length；每次 write(hidg) 必须写满该长度。"""
    path = os.path.join(GADGET_DIR, "functions/hid.usb0/report_length")
    try:
        with open(path, "r") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 8 if TOUCH_MODE == "single" else 64
        # 读失败时的默认值：单点 8(Win10)，多点 64


REPORT_LEN = read_report_len()
# 模块加载时读一次；main() 中会再次刷新


def scale(v, src_max, dst_max):
    """将本地坐标 [0,src_max] 线性映射到 [0,dst_max]。"""
    v = max(0, min(int(v), src_max))
    return int(v * dst_max / src_max)


def host_configured():
    """读 UDC state；为 configured 时表示 USB 主机已完成枚举，可以写 hidg。"""
    try:
        with open(os.path.join(GADGET_DIR, "UDC"), "r") as f:
            udc = f.read().strip()
        if not udc:
            return False
        with open(f"/sys/class/udc/{udc}/state", "r") as f:
            return f.read().strip() == "configured"
    except OSError:
        return False


def wait_for_host():
    """启动时轮询等待主机 configured，避免过早写 hidg 导致 -108/断线。"""
    deadline = time.monotonic() + HOST_WAIT_SEC
    while time.monotonic() < deadline:
        if host_configured():
            return True
        time.sleep(0.1)
    return False


class Slot:
    """Type B 多点协议中一个 slot 的状态。"""

    __slots__ = ("active", "x", "y")
    # 限制属性，节省内存

    def __init__(self):
        self.active = False
        # 该 slot 是否有手指（TRACKING_ID >= 0）
        self.x = 0
        self.y = 0
        # 当前坐标（本地分辨率）


def build_report_single(slots, btn_touch=False):
    """组单点 HID 报告：8 字节，含 Report ID（与 usb-gadget-touch.sh 默认描述符一致）。"""
    tip = btn_touch
    x = y = 0
    for s in slots:
        if s.active:
            tip = True
            x, y = s.x, s.y
            break
    hx = scale(x, SRC_X_MAX, HID_X_MAX) if tip else 0
    hy = scale(y, SRC_Y_MAX, HID_Y_MAX) if tip else 0
    if tip and INVERT_Y:
        hy = HID_Y_MAX - hy

    buf = bytearray(REPORT_LEN)
    buf[0] = 0x01
    buf[1] = 0x01 if tip else 0x00
    buf[2] = 0x00
    if tip:
        struct.pack_into("<HH", buf, 3, hx, hy)
    buf[7] = 0x01 if tip else 0x00
    return bytes(buf)


def build_report_multi(slots):
    """
    5 点 HID 报告：每指 6 字节，byte30 为 contact count。
    仅 TOUCH_MODE=multi 且 gadget report_length=64 时使用。
    """
    buf = bytearray(REPORT_LEN)
    count = 0
    for i, s in enumerate(slots):
        off = i * 6
        if s.active:
            count += 1
            buf[off] = 0x03
            x = scale(s.x, SRC_X_MAX, HID_X_MAX)
            y = scale(s.y, SRC_Y_MAX, HID_Y_MAX)
            if INVERT_Y:
                y = HID_Y_MAX - y
            struct.pack_into("<HH", buf, off + 1, x, y)
            buf[off + 5] = i
    if REPORT_LEN > 30:
        buf[30] = count
    return bytes(buf)


def build_report(slots, btn_touch=False):
    if TOUCH_MODE == "multi":
        return build_report_multi(slots)
    return build_report_single(slots, btn_touch)


class HidgWriter:
    """封装对 /dev/hidg0 的写操作：检查 configured、限速、断线重开。"""

    def __init__(self, path):
        self.path = path
        self.fd = None
        self.last_write = 0.0
        self.open()

    def open(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
        self.fd = os.open(self.path, os.O_WRONLY)

    def write(self, report):
        if not host_configured():
            return False
        now = time.monotonic()
        if now - self.last_write < MIN_WRITE_INTERVAL:
            return False
        try:
            n = os.write(self.fd, report)
            if n != len(report):
                raise OSError("short write", n, len(report))
            self.last_write = now
            return True
        except OSError as e:
            if e.errno in (errno.EPIPE, errno.ESHUTDOWN, errno.ECONNRESET, 108):
                time.sleep(0.3)
                if host_configured():
                    try:
                        self.open()
                    except OSError:
                        pass
            return False


def main():
    global REPORT_LEN
    REPORT_LEN = read_report_len()
    print("mode=%s report_length=%d" % (TOUCH_MODE, REPORT_LEN), flush=True)

    if not wait_for_host():
        print("warn: USB host not configured; touch after Windows enumerates", flush=True)

    ev = open(INPUT_DEV, "rb")
    hid = HidgWriter(HIDG_DEV)

    if GRAB_INPUT:
        fcntl.ioctl(ev, 0x40044590, 1)
        # EVIOCGRAB：独占触摸屏

    slots = [Slot() for _ in range(NUM_SLOTS)]
    cur_slot = 0
    btn_touch = False
    last_report = None

    while True:
        try:
            r, _, _ = select.select([ev], [], [], SELECT_TIMEOUT)
        except (KeyboardInterrupt, OSError):
            break
        if not r:
            continue
        data = ev.read(EVENT_SIZE)
        if not data or len(data) < EVENT_SIZE:
            continue
        _, _, typ, code, val = struct.unpack(EVENT_FMT, data)

        if typ == EV_ABS:
            if code == ABS_MT_SLOT:
                cur_slot = val
            elif code == ABS_MT_TRACKING_ID:
                if 0 <= cur_slot < NUM_SLOTS:
                    slots[cur_slot].active = val >= 0
            elif code in (ABS_MT_POSITION_X, ABS_X):
                if code == ABS_MT_POSITION_X and 0 <= cur_slot < NUM_SLOTS:
                    slots[cur_slot].x = val
                elif code == ABS_X:
                    slots[0].x = val
            elif code in (ABS_MT_POSITION_Y, ABS_Y):
                if code == ABS_MT_POSITION_Y and 0 <= cur_slot < NUM_SLOTS:
                    slots[cur_slot].y = val
                elif code == ABS_Y:
                    slots[0].y = val
        elif typ == EV_KEY and code == BTN_TOUCH:
            btn_touch = bool(val)
        elif typ == EV_SYN and code == SYN_REPORT:
            if not host_configured():
                continue
            report = build_report(slots, btn_touch)
            if report == last_report:
                continue
            if hid.write(report):
                last_report = report

    try:
        os.close(hid.fd)
        ev.close()
    except OSError:
        pass


if __name__ == "__main__":
    main()
