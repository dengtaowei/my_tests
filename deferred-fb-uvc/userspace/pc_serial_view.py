#!/usr/bin/env python3
import struct
import sys

import cv2
import numpy as np
import serial

MAGIC = 0x31424644  # DFB1
HDR_FMT = "<11I"
HDR_SIZE = struct.calcsize(HDR_FMT)


def read_exact(ser: serial.Serial, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = ser.read(n - len(out))
        if not chunk:
            continue
        out.extend(chunk)
    return bytes(out)


def decode_frame(width: int, height: int, bpp: int, line_length: int, framebuffer: bytes) -> np.ndarray:
    if bpp == 16:
        arr = np.frombuffer(framebuffer, dtype=np.uint8).reshape((height, line_length))
        pix = arr[:, : width * 2].view(np.uint16)
        r = ((pix >> 11) & 0x1F).astype(np.uint8) << 3
        g = ((pix >> 5) & 0x3F).astype(np.uint8) << 2
        b = (pix & 0x1F).astype(np.uint8) << 3
        return np.dstack((b, g, r))
    if bpp == 32:
        arr = np.frombuffer(framebuffer, dtype=np.uint8).reshape((height, line_length))
        arr = arr[:, : width * 4].reshape((height, width, 4))
        return arr[:, :, :3].copy()
    raise ValueError(f"unsupported bpp={bpp}")


def main() -> int:
    port = sys.argv[1] if len(sys.argv) > 1 else "COM5"
    baud = int(sys.argv[2]) if len(sys.argv) > 2 else 2000000
    fb_cache = None
    cache_meta = None

    with serial.Serial(port=port, baudrate=baud, timeout=0.2) as ser:
        print(f"listening on {port} ...")
        while True:
            hdr_raw = read_exact(ser, HDR_SIZE)
            hdr = struct.unpack(HDR_FMT, hdr_raw)
            magic, seq, width, height, bpp, line_length, x1, y1, x2, y2, payload_size = hdr
            if magic != MAGIC:
                continue

            bpp_bytes = 2 if bpp == 16 else (4 if bpp == 32 else 0)
            if bpp_bytes == 0:
                continue
            if line_length < width * bpp_bytes:
                continue
            if y2 < y1 or x2 < x1 or x2 >= width or y2 >= height:
                continue
            if x1 != 0 or x2 != width - 1:
                continue

            rect_h = y2 - y1 + 1
            expected_payload = rect_h * line_length
            if payload_size != expected_payload:
                continue

            payload = read_exact(ser, payload_size)
            if cache_meta != (width, height, bpp, line_length):
                fb_cache = bytearray(height * line_length)
                cache_meta = (width, height, bpp, line_length)

            for row in range(rect_h):
                src_off = row * line_length
                dst_off = (y1 + row) * line_length
                fb_cache[dst_off : dst_off + line_length] = payload[src_off : src_off + line_length]

            frame = decode_frame(width, height, bpp, line_length, bytes(fb_cache))
            cv2.imshow("DeferredFB Serial", frame)
            if cv2.waitKey(1) & 0xFF == ord("q"):
                break

    cv2.destroyAllWindows()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
