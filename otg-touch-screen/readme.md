# USB Gadget 触摸屏转发

板载触摸屏 → USB 主机（Windows / Linux）HID 触摸屏。

## 编译

### C 版 touch-to-hidg（推荐）

```bash
make
# 交叉编译
make CC=arm-buildroot-linux-gnueabihf-gcc
```

生成可执行文件 `touch-to-hidg`。

### Python 版

无需编译，需板子上有 `python3`。

---

## 使用

以 root 在板子上执行。USB 接主机 **Device/OTG 口**。

### 1. 启动 Gadget

```bash
chmod +x usb-gadget-touch.sh
./usb-gadget-touch.sh start
./usb-gadget-touch.sh status
```

`status` 应显示 `RUNNING`，且 `report_desc: OK`、`/dev/hidg0: present`。

### 2. 连接 USB 到电脑

插线后等几秒。Windows 设备管理器中应出现触摸屏设备。

### 3. 测试 Gadget（可选，不摸本地屏）

```bash
python3 test-hidg.py
# 或循环: python3 test-hidg.py --loop
```

Windows 可在 **画图** 中查看是否有笔画（鼠标箭头可能不动，属正常）。

### 4. 转发本地触摸屏

```bash
# C 版
./touch-to-hidg

# 或 Python 版
python3 touch-to-hidg.py
```

在板子 LCD 上触摸，主机应收到触摸输入。

### 5. 停止

```bash
# Ctrl+C 结束 touch-to-hidg / touch-to-hidg.py 后
./usb-gadget-touch.sh stop
```

完全删除配置：

```bash
./usb-gadget-touch.sh destroy
```

修改描述符或异常后重建：

```bash
./usb-gadget-touch.sh restart
```

---

## 脚本命令

| 命令 | 说明 |
|------|------|
| `start` | 启动 Gadget |
| `stop` | 停止并移除 HID 功能 |
| `restart` | 重启 Gadget |
| `destroy` | 删除整个 Gadget |
| `status` | 查看状态 |

---

## 可选环境变量

```bash
# 5 点模式（需配合 TOUCH_MODE=multi）
SINGLE_TOUCH=0 ./usb-gadget-touch.sh restart
TOUCH_MODE=multi ./touch-to-hidg
```
