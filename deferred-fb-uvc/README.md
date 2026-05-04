# Deferred IO + Framebuffer + USB Serial (Kernel Push) Demo

This version follows your new requirement:

- User-space only **mmap writes** `/dev/fb0`.
- Kernel `deferred_io` detects updates.
- Driver directly pushes frame data to PC through USB gadget serial (`/dev/ttyGS0`).
- No user-space process reads framebuffer for forwarding.

## What this demo does

1. Board OTG port is connected to PC.
2. Board driver exposes `/dev/fb0` (virtual LCD-like framebuffer).
3. User app writes pixels via `mmap(/dev/fb0)`.
4. Deferred IO callback wakes kernel TX worker.
5. Driver sends frame packet to PC via USB CDC ACM serial.
6. PC tool decodes and displays frame.

## Project layout

- `kernel/deferred_fb.c`: framebuffer + deferred-io + kernel USB-serial push.
- `include/deferred_fb_uapi.h`: packet header definition for board->PC stream.
- `userspace/fb_painter.c`: mmap framebuffer writer example.
- `userspace/pc_serial_view.py`: PC serial receiver and viewer.
- `scripts/setup_serial.sh`: create/remove USB CDC ACM gadget (configfs).
- `scripts/run_demo.sh`: board quick start.

## Board kernel config requirements

- `CONFIG_USB_GADGET=y`
- `CONFIG_USB_CONFIGFS=y`
- `CONFIG_USB_LIBCOMPOSITE=y`
- `CONFIG_USB_CONFIGFS_ACM=y`
- `CONFIG_FB=y`
- `CONFIG_FB_DEFERRED_IO=y`

## Board side steps

### 1) Enable USB serial gadget

```bash
sudo ./scripts/setup_serial.sh up
```

After success you should see `/dev/ttyGS0`.

### 2) Build and insert module

```bash
cd kernel
make
sudo insmod deferred_fb.ko width=640 height=480 bpp=16 tx_enable=1 tx_tty=/dev/ttyGS0
```

If you want a different deferred-io latency, set:

```bash
sudo insmod deferred_fb.ko width=640 height=480 bpp=16 defio_delay_ms=50 tx_enable=1 tx_tty=/dev/ttyGS0
```

### 3) Build userspace tools

```bash
cd ../userspace
make
```

### 4) Write framebuffer through mmap

```bash
sudo ./fb_painter /dev/fb0
```

Or run one-shot helper:

```bash
sudo ./scripts/run_demo.sh
```

## PC side steps

### Option A: Python viewer (existing)

```bash
pip install pyserial opencv-python numpy
```

Run viewer (`COMx` on Windows, `/dev/ttyACM0` on Linux):

```bash
python3 userspace/pc_serial_view.py COM5 2000000
```

### Option B: Qt 5.14.2 C++ viewer (new)

Project file:

- `userspace/pc_serial_view_qt.pro`

Source:

- `userspace/pc_serial_view_qt.cpp`

Build with Qt 5.14.2 (qmake):

```bash
cd userspace
qmake pc_serial_view_qt.pro
make
```

Run:

```bash
./pc_serial_view_qt --port COM5 --baud 2000000
```

You can also ignore `--port` and select port from the GUI (`Serial Port` drop-down, then `Connect`).

On Windows (Qt MinGW shell), executable is usually in `release\pc_serial_view_qt.exe`.

## Packet format (board -> PC)

- Header: `struct deferred_fb_usb_frame_hdr` (`DEFERRED_FB_USB_MAGIC = 0x31424644`)
- Header fields include: `width`, `height`, `bpp`, `line_length`, dirty rect (`x1..y2`), `payload_size`.
- Payload: **dirty-rect rows only** (currently full width rows from `y1` to `y2`), not full frame.
- PC viewer keeps a local framebuffer cache and patches dirty rows before rendering.

The dirty trigger is now based on the standard deferred-io pagelist callback:
- user-space mmap write marks pages dirty
- callback runs after `defio_delay_ms`
- driver coalesces dirty page range to line range and only transmits that dirty row block

## Stop and cleanup

```bash
sudo ./scripts/setup_serial.sh down
sudo rmmod deferred_fb
```
