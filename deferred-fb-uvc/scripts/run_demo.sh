#!/bin/sh
set -e

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root"
    exit 1
fi

cd "$ROOT/kernel"
make
insmod deferred_fb.ko width=640 height=480 bpp=16 tx_tty=/dev/ttyGS0 || true

"$ROOT/scripts/setup_serial.sh" up

cd "$ROOT/userspace"
make
echo "Kernel TX is active. Start drawing with:"
echo "  ./fb_painter /dev/fb0"
exec ./fb_painter /dev/fb0
