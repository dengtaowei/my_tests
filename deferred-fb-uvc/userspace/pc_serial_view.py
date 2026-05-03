#!/usr/bin/env python3
import struct
import sys

import cv2
import numpy as np
import serial

MAGIC = 0x31424644  # DFB1
HDR_FMT = "<10I"
HDR_SIZE = struct.calcsize(HDR_FMT)


def read_exact(ser: serial.Serial, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = ser.read(n - len(out))
        if not chunk:
            continue
        out.extend(chunk)
    return bytes(out)


def decode_frame(width: int, height: int, bpp: int, payload: bytes) -> np.ndarray:
    if bpp == 16:
        arr = np.frombuffer(payload, dtype=np.uint16).reshape((height, width))
        r = ((arr >> 11) & 0x1F).astype(np.uint8) << 3
        g = ((arr >> 5) & 0x3F).astype(np.uint8) << 2
        b = (arr & 0x1F).astype(np.uint8) << 3
        return np.dstack((b, g, r))
    if bpp == 32:
        arr = np.frombuffer(payload, dtype=np.uint8).reshape((height, width, 4))
        return arr[:, :, :3].copy()
    raise ValueError(f"unsupported bpp={bpp}")


def main() -> int:
    port = sys.argv[1] if len(sys.argv) > 1 else "COM5"
    baud = int(sys.argv[2]) if len(sys.argv) > 2 else 2000000

    with serial.Serial(port=port, baudrate=baud, timeout=0.2) as ser:
        print(f"listening on {port} ...")
        while True:
            hdr_raw = read_exact(ser, HDR_SIZE)
            hdr = struct.unpack(HDR_FMT, hdr_raw)
            magic, seq, width, height, bpp, x1, y1, x2, y2, payload_size = hdr
            if magic != MAGIC:
                continue

            payload = read_exact(ser, payload_size)
            frame = decode_frame(width, height, bpp, payload)
            cv2.imshow("DeferredFB Serial", frame)
            if cv2.waitKey(1) & 0xFF == ord("q"):
                break

    cv2.destroyAllWindows()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
