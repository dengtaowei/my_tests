#!/usr/bin/env python3
"""
Test USB HID touch gadget without local touchscreen forwarding.
Sends a synthetic click to /dev/hidg0 so you can verify Windows sees touch input.

Usage (gadget must be started, USB connected to PC):
  python3 test-hidg.py          # one click at screen center
  python3 test-hidg.py --hold   # press down 2s then release
  python3 test-hidg.py --loop   # click every 3s (Ctrl+C to stop)
"""

import argparse
import os
import struct
import sys
import time

HIDG_DEV = "/dev/hidg0"
GADGET_DIR = "/sys/kernel/config/usb_gadget/touch"

# HID logical range (must match gadget report descriptor)
HID_X_MAX = 4095
HID_Y_MAX = 4095


def read_report_len():
    path = os.path.join(GADGET_DIR, "functions/hid.usb0/report_length")
    try:
        with open(path, "r") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 8


def host_configured():
    try:
        with open(os.path.join(GADGET_DIR, "UDC"), "r") as f:
            udc = f.read().strip()
        if not udc:
            return False
        with open(f"/sys/class/udc/{udc}/state", "r") as f:
            return f.read().strip() == "configured"
    except OSError:
        return False


def build_single(tip, x, y, report_len):
    """8-byte report: [ReportID][Tip][ContactID][X][Y][ContactCount]."""
    buf = bytearray(report_len)
    buf[0] = 0x01  # Report ID (matches descriptor 0x85, 0x01)
    buf[1] = 0x01 if tip else 0x00
    buf[2] = 0x00  # Contact Identifier
    struct.pack_into("<HH", buf, 3, x, y)
    buf[7] = 0x01 if tip else 0x00
    return bytes(buf)


def build_multi(tip, x, y, report_len):
    """First finger in 5-finger layout + contact count at byte 30."""
    buf = bytearray(report_len)
    if tip:
        buf[0] = 0x03
        struct.pack_into("<HH", buf, 1, x, y)
        buf[5] = 0
        if report_len > 30:
            buf[30] = 1
    return bytes(buf)


def build_report(tip, x, y, report_len):
    if report_len > 16:
        return build_multi(tip, x, y, report_len)
    return build_single(tip, x, y, report_len)


def send_click(fd, report_len, x=None, y=None, hold_sec=0.05):
    if x is None:
        x = HID_X_MAX // 2
    if y is None:
        y = HID_Y_MAX // 2

    down = build_report(True, x, y, report_len)
    up = build_report(False, x, y, report_len)

    os.write(fd, down)
    print("sent touch DOWN at (%d, %d), %d bytes" % (x, y, len(down)))
    time.sleep(hold_sec)
    os.write(fd, up)
    print("sent touch UP")


def main():
    parser = argparse.ArgumentParser(description="Test USB HID touch gadget (hidg0)")
    parser.add_argument("--hold", action="store_true", help="hold press for 2 seconds")
    parser.add_argument("--loop", action="store_true", help="click every 3 seconds")
    parser.add_argument("-x", type=int, default=HID_X_MAX // 2, help="HID X (0-4095)")
    parser.add_argument("-y", type=int, default=HID_Y_MAX // 2, help="HID Y (0-4095)")
    args = parser.parse_args()

    if not os.path.exists(HIDG_DEV):
        print("error: %s not found — run: ./usb-gadget-touch.sh start" % HIDG_DEV, file=sys.stderr)
        sys.exit(1)

    if not host_configured():
        print("warn: UDC state is not 'configured' — plug USB to PC and wait", file=sys.stderr)

    report_len = read_report_len()
    print("report_length=%d (from gadget)" % report_len)

    fd = os.open(HIDG_DEV, os.O_WRONLY)
    hold = 2.0 if args.hold else 0.05

    try:
        if args.loop:
            print("loop mode: click every 3s, Ctrl+C to stop")
            while True:
                send_click(fd, report_len, args.x, args.y, hold)
                time.sleep(3.0)
        else:
            send_click(fd, report_len, args.x, args.y, hold)
            print("done — check if Windows reacted (cursor jump / click)")
    except OSError as e:
        print("write failed: %s" % e, file=sys.stderr)
        print("hint: replug USB; ensure no other process uses hidg0", file=sys.stderr)
        sys.exit(1)
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
