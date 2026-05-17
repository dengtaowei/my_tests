#!/bin/sh
# 使用 /bin/sh 解释器运行本脚本

#
# USB Gadget: 通过 HID 把板载触摸转发给 USB 主机（单点/多点）
# 用法: usb-gadget-touch.sh {start|stop|restart|destroy|status}
#
# 须在板子上以 root 运行；内核需 CONFIG_USB_CONFIGFS、CONFIG_USB_CONFIGFS_F_HID
#

set -e
# 任一命令失败则立即退出，避免在错误状态下继续配置 gadget

GADGET_NAME="${GADGET_NAME:-touch}"
# gadget 在 configfs 中的目录名，可用环境变量覆盖，默认 touch

GADGET_ROOT="/sys/kernel/config/usb_gadget"
# USB gadget configfs 根目录

G="${GADGET_ROOT}/${GADGET_NAME}"
# 本脚本操作的 gadget 完整路径

# ---------- USB 设备描述符中的厂商/产品信息 ----------
VID="${VID:-0x1d6b}"
# USB Vendor ID，默认 Linux Foundation 示例值，可按需修改

PID="${PID:-0x0104}"
# USB Product ID，主机用其识别设备

DEVICE_VERSION="${DEVICE_VERSION:-0x0100}"
# bcdDevice 设备版本号

USB_VERSION="${USB_VERSION:-0x0200}"
# bcdUSB USB 规范版本（2.00）

MANUFACTURER="${MANUFACTURER:-100ask}"
# 厂商字符串

PRODUCT="${PRODUCT:-USB Touch Screen}"
# 产品字符串（Windows 设备管理器中可见）

SERIAL="${SERIAL:-0001}"
# 序列号字符串

HID_FUNC="hid.usb0"
# configfs 中 HID 功能实例名，对应 /dev/hidg0

CONFIG_NAME="c.1"
# 配置实例名（一个 USB 配置可包含多个 function）

STRINGS_LANG="0x409"
# 字符串描述符语言 ID（0x409 = 英语美国）

# ---------- 单点 / 多点与报告长度 ----------
SINGLE_TOUCH="${SINGLE_TOUCH:-1}"
# 1=单点（默认），0=5 点多点

if [ "$SINGLE_TOUCH" = "1" ]; then
	# 单点模式分支
	REPORT_LENGTH="${REPORT_LENGTH:-8}"
	# Win10 默认 8 字节：ReportID + Tip + ContactID + X + Y + Count
else
	# 多点模式分支
	REPORT_LENGTH="${REPORT_LENGTH:-64}"
	# 5 点 HID 报告填充到 64 字节（与 report_length 一致）
fi

REPORT_DESC_HEX_SINGLE="050d0904a10185010922a102094215002501750195018102950781030951750895018102050109300931150026ff0f751095028102c00954950175088102c0"
# Win10 单点描述符：含 Report ID(1)、Contact ID、Tip、X/Y、Contact Count

FINGER_DESC="0922a10209421500250175019501810209328102750695018103050109300931150026ff0f751095028102050d095115002505750895018102c0"
# 多点描述符中「一个手指」集合的十六进制片段（重复 5 次）

HEADER_DESC="050d0904a101"
# 多点描述符头部：Digitizer + Touch Screen + Application Collection

FOOTER_DESC="050d095495017508810209552505b102c0"
# 多点描述符尾部：Contact Count + Contact Count Maximum(Feature) + 结束

REPORT_DESC_HEX_MULTI="${HEADER_DESC}${FINGER_DESC}${FINGER_DESC}${FINGER_DESC}${FINGER_DESC}${FINGER_DESC}${FOOTER_DESC}"
# 拼接为完整 5 点触摸 HID 报告描述符（十六进制字符串）

if [ "$SINGLE_TOUCH" = "1" ]; then
	# 根据环境选择单点用哪份描述符
	# 默认 Win10 兼容 8 字节描述符
	REPORT_DESC_HEX="$REPORT_DESC_HEX_SINGLE"
else
	# 多点模式使用多点描述符
	REPORT_DESC_HEX="$REPORT_DESC_HEX_MULTI"
fi

log() { printf '%s\n' "$*"; }
# 打印普通日志行

die() { log "ERROR: $*"; exit 1; }
# 打印错误并退出脚本

need_root() {
	[ "$(id -u)" -eq 0 ] || die "must run as root"
	# 配置 configfs gadget 必须使用 root
}

hex_to_binary() {
	# 将连续十六进制字符串转为二进制写入 stdout（供 report_desc 使用）
	_hex="$1"
	# 局部变量：入参十六进制串
	_len=${#_hex}
	# 十六进制字符个数
	_i=0
	# 循环下标
	_out=""
	# 累积 printf %b 用的 \xNN 转义串
	while [ "$_i" -lt "$_len" ]; do
		# 每两个十六进制字符转为一字节
		_byte=$(printf '%s' "$_hex" | cut -c "$((_i + 1))-$((_i + 2))")
		# 取当前 1 字节（2 个 hex 字符）
		_out="${_out}\\x${_byte}"
		# 追加 \xNN（BusyBox 无 xxd -r，用 printf %b）
		_i=$((_i + 2))
		# 下标前进 2
	done
	# shellcheck disable=SC2086
	printf '%b' "$_out"
	# 输出二进制描述符内容
}

ensure_configfs() {
	if ! mountpoint -q /sys/kernel/config 2>/dev/null; then
		# 若 configfs 未挂载则尝试挂载
		mkdir -p /sys/kernel/config
		# 创建挂载点
		mount -t configfs none /sys/kernel/config 2>/dev/null || true
		# 挂载 configfs（失败不致命，可能已挂载）
	fi
	[ -d "$GADGET_ROOT" ] || die "configfs not available (CONFIG_USB_CONFIGFS?)"
	# 确认 gadget 配置根目录存在
}

load_modules() {
	if [ -d /sys/module/libcomposite ]; then
		# libcomposite 已加载则跳过
		return
	fi
	modprobe libcomposite 2>/dev/null || die "failed to modprobe libcomposite"
	# 加载复合 USB gadget 内核模块
}

get_udc() {
	if [ -n "$UDC" ]; then
		# 用户通过环境变量指定 UDC 控制器名
		printf '%s' "$UDC"
		return
	fi
	_ls=$(ls /sys/class/udc 2>/dev/null | head -n 1)
	# 取第一个可用 UDC（如 49000000.usb-otg）
	[ -n "$_ls" ] || die "no UDC in /sys/class/udc (check OTG/device mode)"
	# 无 UDC 说明未处于 USB Device 模式
	printf '%s' "$_ls"
	# 输出 UDC 名称
}

kill_hidg_users() {
	if [ -c /dev/hidg0 ]; then
		# 若 hidg 字符设备存在
		fuser -k /dev/hidg0 2>/dev/null || true
		# 结束占用 hidg0 的进程，避免 Device busy
	fi
	killall touch-to-hidg.py 2>/dev/null || true
	# 结束触摸转发脚本（若正在运行）
}

gadget_bound() {
	[ -f "$G/UDC" ] && [ -n "$(cat "$G/UDC" 2>/dev/null)" ]
	# UDC 文件非空表示 gadget 已绑定到 USB 控制器
}

write_report_desc() {
	_func="$1"
	# 参数：HID function 目录路径
	hex_to_binary "$REPORT_DESC_HEX" > "$_func/report_desc"
	# 将二进制 HID 报告描述符写入 configfs（只能写一次，错误需删 function 重建）
}

report_desc_ok() {
	_func="$1"
	# 检查已有 HID function 的描述符是否合法
	_rd="$_func/report_desc"
	[ -f "$_rd" ] || return 1
	# 描述符文件必须存在
	_first=$(hexdump -n 4 -e '4/1 "%02x"' "$_rd" 2>/dev/null) || return 1
	# 读前 4 字节，合法应以 05 0d 09 04 开头
	[ "$_first" = "050d0904" ] || return 1
	# 非二进制（如 ASCII "0x05"）则不合格
	_rlen=$(cat "$_func/report_length" 2>/dev/null) || return 1
	[ "$_rlen" = "$REPORT_LENGTH" ] || return 1
	# report_length 须与当前模式一致（8/64）
	if [ "$SINGLE_TOUCH" = "1" ]; then
		# Win10 模式额外检查是否含 Report ID 项 85 01
		_win=$(hexdump -n 8 -e '8/1 "%02x"' "$_rd" 2>/dev/null) || return 1
		case "$_win" in
			050d0904a1018501*) ;;
			# 正确：Touch Screen Application + Report ID 1
			*) return 1 ;;
			# 缺少 8501 说明描述符版本不对，需重建
		esac
	fi
	return 0
	# 描述符检查通过
}

ensure_hid_function() {
	_func="$G/functions/$HID_FUNC"
	# HID 功能目录

	if [ -d "$_func" ] && report_desc_ok "$_func"; then
		# 已存在且描述符正确则无需重建
		return 0
	fi

	log "creating or fixing HID function $HID_FUNC"
	# 需要创建或修复 HID 功能
	rm -f "$G/configs/$CONFIG_NAME/$HID_FUNC" 2>/dev/null || true
	# 先从配置中 unlink function
	if [ -d "$_func" ]; then
		rmdir "$_func" 2>/dev/null || die "cannot reset $HID_FUNC (run: $0 stop)"
		# 删除旧 function（须先解绑 UDC 且无进程占用）
	fi

	mkdir "$_func"
	# 新建 hid.usb0 目录
	write_report_desc "$_func"
	# 写入二进制 report_desc
	printf '0\n' > "$_func/protocol"
	# HID 协议：0=无 boot 协议
	printf '0\n' > "$_func/subclass"
	# HID 子类：0
	printf '%s\n' "$REPORT_LENGTH" > "$_func/report_length"
	# 每次 write(hidg) 必须写入的字节数
}

start_gadget() {
	need_root
	# 必须 root
	ensure_configfs
	# 挂载 configfs
	load_modules
	# 加载 libcomposite

	if gadget_bound; then
		log "gadget already bound to UDC: $(cat "$G/UDC")"
		# 已绑定则直接返回
		return 0
	fi

	mkdir -p "$G"
	# 创建 gadget 目录
	cd "$G"
	# 进入 gadget 目录（后续相对路径）

	mkdir -p "strings/$STRINGS_LANG"
	# 设备字符串描述符目录
	printf '%s\n' "$VID" > idVendor
	# 写 Vendor ID
	printf '%s\n' "$PID" > idProduct
	# 写 Product ID
	printf '%s\n' "$DEVICE_VERSION" > bcdDevice
	# 写设备版本
	printf '%s\n' "$USB_VERSION" > bcdUSB
	# 写 USB 版本
	printf '%s\n' "$MANUFACTURER" > "strings/$STRINGS_LANG/manufacturer"
	printf '%s\n' "$PRODUCT" > "strings/$STRINGS_LANG/product"
	printf '%s\n' "$SERIAL" > "strings/$STRINGS_LANG/serialnumber"
	# 写 USB 字符串

	mkdir -p "configs/$CONFIG_NAME"
	# 创建 USB 配置
	mkdir -p "configs/$CONFIG_NAME/strings/$STRINGS_LANG"
	printf 'HID Touch\n' > "configs/$CONFIG_NAME/strings/$STRINGS_LANG/configuration"
	# 配置描述字符串

	ensure_hid_function
	# 创建/修复 HID 功能及描述符

	if [ ! -L "configs/$CONFIG_NAME/$HID_FUNC" ]; then
		ln -s "functions/$HID_FUNC" "configs/$CONFIG_NAME/"
		# 将 HID 功能加入该 USB 配置
	fi

	_udc=$(get_udc)
	# 获取 UDC 名
	printf '%s\n' "$_udc" > UDC
	# 绑定 UDC，gadget 对主机可见，并出现 /dev/hidg0

	if [ "$SINGLE_TOUCH" = "1" ]; then
		_mode="single-touch (win10 8-byte)"
	else
		_mode="multi-touch"
	fi
	# 日志用模式名称
	log "gadget started: $GADGET_NAME on UDC $_udc (VID/PID $VID/$PID, $_mode, report_length=$REPORT_LENGTH)"
	[ -c /dev/hidg0 ] && log "device node: /dev/hidg0" || log "warn: /dev/hidg0 not found yet (replug USB or wait)"
	# 提示 hidg 节点是否已创建
}

stop_gadget() {
	need_root
	[ -d "$G" ] || {
		log "gadget $GADGET_NAME does not exist"
		return 0
	}
	# gadget 不存在则无需停止

	kill_hidg_users
	# 释放 hidg 占用

	if gadget_bound; then
		printf '\n' > "$G/UDC" || echo "" > "$G/UDC"
		# 向 UDC 写空：解绑，USB 断开
		log "UDC unbound"
	fi

	if [ -L "$G/configs/$CONFIG_NAME/$HID_FUNC" ]; then
		rm -f "$G/configs/$CONFIG_NAME/$HID_FUNC"
		# 从配置移除 HID 功能符号链接
	fi

	if [ -d "$G/functions/$HID_FUNC" ]; then
		rmdir "$G/functions/$HID_FUNC" 2>/dev/null && log "removed function $HID_FUNC" || \
			log "warn: could not rmdir functions/$HID_FUNC (still busy?)"
		# 删除 HID function，便于下次 start 重写 report_desc
	fi
}

destroy_gadget() {
	stop_gadget
	# 先执行 stop（解绑、删 function）
	[ -d "$G" ] || return 0

	rm -f "$G/configs/$CONFIG_NAME/$HID_FUNC" 2>/dev/null || true
	rmdir "$G/configs/$CONFIG_NAME/strings/$STRINGS_LANG" 2>/dev/null || true
	rmdir "$G/configs/$CONFIG_NAME" 2>/dev/null || true
	rmdir "$G/strings/$STRINGS_LANG" 2>/dev/null || true
	rmdir "$G/functions/$HID_FUNC" 2>/dev/null || true
	# 逐层删除 config、strings、function

	cd "$GADGET_ROOT" || exit 1
	rmdir "$GADGET_NAME" 2>/dev/null && log "gadget $GADGET_NAME destroyed" || \
		die "failed to destroy $G (check: lsof /dev/hidg0, cat $G/UDC)"
	# 删除整个 gadget 目录
}

status_gadget() {
	if [ ! -d "$G" ]; then
		log "status: not configured ($G missing)"
		return 1
	fi
	# gadget 目录不存在
	if gadget_bound; then
		log "status: RUNNING on UDC $(cat "$G/UDC")"
	else
		log "status: configured but UDC not bound"
	fi
	# 打印是否已绑定 UDC
	log "  idVendor=$(cat "$G/idVendor" 2>/dev/null) idProduct=$(cat "$G/idProduct" 2>/dev/null)"
	if [ -f "$G/functions/$HID_FUNC/report_desc" ]; then
		_first=$(hexdump -n 4 -e '4/1 "%02x"' "$G/functions/$HID_FUNC/report_desc" 2>/dev/null || true)
		case "$_first" in
			050d0904) log "  report_desc: OK (binary digitizer header)" ;;
			30783035) log "  report_desc: BAD (ASCII '0x05' — re-run: $0 stop && $0 start)" ;;
			*) log "  report_desc: first bytes: $_first" ;;
		esac
		# 检查描述符是否为二进制而非文本
	fi
	[ -c /dev/hidg0 ] && log "  /dev/hidg0: present" || log "  /dev/hidg0: missing"
	# 检查用户态接口节点
}

usage() {
	cat <<EOF
Usage: $0 {start|stop|restart|destroy|status}

  start    Create gadget (if needed), write HID descriptor, bind UDC
  stop     Unbind UDC, remove HID function (keeps gadget dir for quick restart)
  restart  stop + start (recreates HID function with fresh report_desc)
  destroy  stop and remove entire gadget directory
  status   Show bind state and report_desc sanity check

Environment:
  SINGLE_TOUCH=1 (default) or 0 for 5-point
  GADGET_NAME=$GADGET_NAME  VID=$VID  PID=$PID  UDC=<name>  REPORT_LENGTH=$REPORT_LENGTH

After start, run touch bridge on the board, e.g.:
  python3 touch-to-hidg.py
EOF
}

cmd="${1:-}"
# 第一个命令行参数：子命令名

case "$cmd" in
	start)
		start_gadget
		;;
	stop)
		stop_gadget
		;;
	restart)
		stop_gadget
		start_gadget
		;;
	destroy)
		destroy_gadget
		;;
	status)
		status_gadget
		;;
	""|-h|--help)
		usage
		;;
	*)
		usage
		die "unknown command: $cmd"
		;;
esac
# 根据子命令分发到对应函数
