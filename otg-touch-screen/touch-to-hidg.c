/*
 * touch-to-hidg.c - 板载触摸屏 event0 -> USB HID gadget hidg0
 *
 * Build: make  或 arm-xxx-gcc touch-to-hidg.c -o touch-to-hidg
 * Run:   ./touch-to-hidg
 * Env:   TOUCH_MODE=single|multi (默认 single)
 *
 * ============================================================================
 * 数据转换总览（event0 -> hidg0）
 * ============================================================================
 *
 *  [Goodix 触摸芯片]
 *        |
 *        v
 *  Linux input 子系统 (/dev/input/event0)
 *        |  多条 struct input_event（不能直接把 event 原样 write 到 hidg）
 *        v
 *  本程序：先“攒一帧”，再组 USB HID 输入报告
 *        |
 *        v
 *  /dev/hidg0  (长度必须 == report_length，由 usb-gadget-touch.sh 配置)
 *        |
 *        v
 *  USB 主机 (Windows/Linux) 按 report_desc 解析为触摸屏
 *
 * ----------------------------------------------------------------------------
 * 第一步：从 event0 读出什么？
 * ----------------------------------------------------------------------------
 * 每条 input_event 含: type, code, value（时间戳本程序忽略）
 *
 *   type=EV_ABS  更新坐标/多点槽位:
 *     ABS_MT_SLOT         value = 当前手指槽号 0~4
 *     ABS_MT_TRACKING_ID  value>=0 按下, -1 抬起
 *     ABS_MT_POSITION_X/Y  该槽位的本地坐标 (Goodix: X 0~1023, Y 0~599)
 *     ABS_X / ABS_Y       部分驱动额外发的单点坐标（备份到 slot[0]）
 *
 *   type=EV_KEY  BTN_TOUCH  value=1 按下 / 0 抬起（单点辅助）
 *
 *   type=EV_SYN  SYN_REPORT  表示“本帧事件结束”，此前 ABS/KEY 同属一帧
 *
 * 本程序在收到 SYN_REPORT 之前只更新内存中的 slots[]，不写 hidg。
 *
 * ----------------------------------------------------------------------------
 * 第二步：内存状态 slots[5]（本地坐标系）
 * ----------------------------------------------------------------------------
 *   slots[i].active  <- TRACKING_ID >= 0
 *   slots[i].x/y     <- POSITION_X/Y（单位：板子屏 0~1023 x 0~599）
 *
 * 单点模式：build_report 只取第一个 active 的 slot；tip 还可参考 BTN_TOUCH。
 *
 * ----------------------------------------------------------------------------
 * 第三步：坐标映射（本地 -> HID 逻辑坐标）
 * ----------------------------------------------------------------------------
 *   hx = x * HID_X_MAX / SRC_X_MAX   (默认 4095/1023)
 *   hy = y * HID_Y_MAX / SRC_Y_MAX   (默认 4095/599)
 * 可选 INVERT_Y: hy = HID_Y_MAX - hy
 *
 * ----------------------------------------------------------------------------
 * 第四步：组装 HID 报告（必须与 usb-gadget-touch.sh 里 report_desc 一致）
 * ----------------------------------------------------------------------------
 *
 * A) report_length == 8（默认单点）
 *    byte0  Report ID = 0x01
 *    byte1  Tip Switch (按下 0x01)
 *    byte2  Contact ID = 0
 *    byte3-4 X uint16 小端
 *    byte5-6 Y uint16 小端
 *    byte7  Contact Count (按下 1 / 抬起 0)
 *
 * B) report_length == 64（TOUCH_MODE=multi）
 *    每指 6 字节 x 5 + byte30=contact count，其余填 0
 *
 * ----------------------------------------------------------------------------
 * 第五步：write(hidg0)
 * ----------------------------------------------------------------------------
 *   - 每次 write 恰好 report_length 字节
 *   - 与上一帧完全相同则跳过（减压 dwc2）
 *   - 主机 UDC state 须为 configured
 *
 * 可用 evtest /dev/input/event0 对照本地事件，用 test-hidg.py 对照 USB 输出。
 * ============================================================================
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/input.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define INPUT_DEV_DEFAULT   "/dev/input/event0"
#define HIDG_DEV_DEFAULT    "/dev/hidg0"
#define GADGET_DIR          "/sys/kernel/config/usb_gadget/touch"
#define REPORT_LEN_PATH     GADGET_DIR "/functions/hid.usb0/report_length"
#define GADGET_UDC_PATH     GADGET_DIR "/UDC"

#define NUM_SLOTS           5
#define SRC_X_MAX           1023
#define SRC_Y_MAX           599
#define HID_X_MAX           4095
#define HID_Y_MAX           4095

#define HOST_WAIT_SEC       15
#define MIN_WRITE_INTERVAL_NS 8000000LL  /* 8 ms */
#define POLL_TIMEOUT_MS     1000

#ifndef INVERT_Y
#define INVERT_Y            0
#endif

#ifndef GRAB_INPUT
#define GRAB_INPUT          1
#endif

#define REPORT_MAX          64

/* linux/input-event-codes.h may be missing on old toolchain */
#ifndef ABS_MT_SLOT
#define ABS_MT_SLOT         0x2f
#endif
#ifndef ABS_MT_TRACKING_ID
#define ABS_MT_TRACKING_ID  0x39
#endif
#ifndef ABS_MT_POSITION_X
#define ABS_MT_POSITION_X   0x35
#endif
#ifndef ABS_MT_POSITION_Y
#define ABS_MT_POSITION_Y   0x36
#endif
#ifndef BTN_TOUCH
#define BTN_TOUCH           0x14a
#endif

/* 一个触摸点的中间状态（仍为板子本地坐标，尚未映射到 HID） */
struct slot {
	bool active;	/* TRACKING_ID>=0 或单点逻辑上的“有手指” */
	int x;		/* ABS_MT_POSITION_X，范围约 0~SRC_X_MAX */
	int y;		/* ABS_MT_POSITION_Y，范围约 0~SRC_Y_MAX */
};

struct app {
	int ev_fd;
	int hid_fd;
	int report_len;
	bool multi_mode;
	bool btn_touch;
	int cur_slot;
	struct slot slots[NUM_SLOTS];
	uint8_t last_report[REPORT_MAX];
	bool have_last;
	struct timespec last_write_ts;
};

/*
 * 坐标线性映射: 板子 (0..src_max) -> HID 描述符逻辑值 (0..dst_max)
 * 例: x=512, SRC_X_MAX=1023, HID_X_MAX=4095 -> hx=2048
 */
static int scale_coord(int v, int src_max, int dst_max)
{
	if (v < 0)
		v = 0;
	if (v > src_max)
		v = src_max;
	return (int)((long long)v * dst_max / src_max);
}

static int timespec_cmp_now(const struct timespec *ts, long long add_ns)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (now.tv_sec > ts->tv_sec + 1)
		return 1;
	if (now.tv_sec < ts->tv_sec)
		return 0;
	{
		long long nsec = (long long)(now.tv_sec - ts->tv_sec) * 1000000000LL
			+ (now.tv_nsec - ts->tv_nsec);
		return nsec >= add_ns;
	}
}

static int read_file_trim(const char *path, char *buf, size_t len)
{
	FILE *f;
	size_t n;

	f = fopen(path, "r");
	if (!f)
		return -1;
	if (!fgets(buf, (int)len, f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	n = strlen(buf);
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' '))
		buf[--n] = '\0';
	return 0;
}

static int read_report_len(bool multi_mode)
{
	char buf[32];

	if (read_file_trim(REPORT_LEN_PATH, buf, sizeof(buf)) == 0)
		return atoi(buf);
	return multi_mode ? 64 : 8;
}

static bool host_configured(void)
{
	char udc[128];
	char state_path[256];
	char state[32];

	if (read_file_trim(GADGET_UDC_PATH, udc, sizeof(udc)) != 0 || udc[0] == '\0')
		return false;

	snprintf(state_path, sizeof(state_path), "/sys/class/udc/%s/state", udc);
	if (read_file_trim(state_path, state, sizeof(state)) != 0)
		return false;

	return strcmp(state, "configured") == 0;
}

static long long timespec_elapsed_ns(const struct timespec *start,
				     const struct timespec *now)
{
	return (long long)(now->tv_sec - start->tv_sec) * 1000000000LL +
	       (long long)(now->tv_nsec - start->tv_nsec);
}

static bool wait_for_host(void)
{
	struct timespec start, now;
	const long long wait_ns = (long long)HOST_WAIT_SEC * 1000000000LL;

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		if (host_configured())
			return true;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (timespec_elapsed_ns(&start, &now) >= wait_ns)
			break;
		usleep(100000);
	}
	return false;
}

/*
 * 单点模式：把 (tip, 本地 x/y) 转成 report_length 字节的 HID 报告
 * tip=false 时仍写出“抬起”报告（坐标可为 0），主机才能看到松手
 */
static void build_report_single(struct app *a, uint8_t *buf, bool tip, int x, int y)
{
	int hx = 0, hy = 0;

	memset(buf, 0, (size_t)a->report_len);
	if (tip) {
		/* 仅在有触摸时做坐标映射 */
		hx = scale_coord(x, SRC_X_MAX, HID_X_MAX);
		hy = scale_coord(y, SRC_Y_MAX, HID_Y_MAX);
#if INVERT_Y
		hy = HID_Y_MAX - hy;
#endif
	}

	/* 8 字节单点报告（与 usb-gadget-touch.sh 默认描述符一致） */
	buf[0] = 0x01;				/* Report ID */
	buf[1] = tip ? 0x01 : 0x00;		/* Tip Switch */
	buf[2] = 0x00;				/* Contact Identifier */
	if (tip) {
		buf[3] = (uint8_t)(hx & 0xff);
		buf[4] = (uint8_t)(hx >> 8);
		buf[5] = (uint8_t)(hy & 0xff);
		buf[6] = (uint8_t)(hy >> 8);
	}
	buf[7] = tip ? 0x01 : 0x00;		/* Contact Count */
}

/*
 * 多点模式：5 个 slot 各映射为 6 字节，格式与单指在描述符里的一段相同
 *   [flags 0x03][X lo][X hi][Y lo][Y hi][contact_id]
 * byte30 = 当前按下手指数
 */
static void build_report_multi(struct app *a, uint8_t *buf)
{
	int i, count = 0;

	memset(buf, 0, (size_t)a->report_len);
	for (i = 0; i < NUM_SLOTS; i++) {
		int off = i * 6;
		int hx, hy;

		if (!a->slots[i].active)
			continue;
		count++;
		buf[off] = 0x03;
		hx = scale_coord(a->slots[i].x, SRC_X_MAX, HID_X_MAX);
		hy = scale_coord(a->slots[i].y, SRC_Y_MAX, HID_Y_MAX);
#if INVERT_Y
		hy = HID_Y_MAX - hy;
#endif
		buf[off + 1] = (uint8_t)(hx & 0xff);
		buf[off + 2] = (uint8_t)(hx >> 8);
		buf[off + 3] = (uint8_t)(hy & 0xff);
		buf[off + 4] = (uint8_t)(hy >> 8);
		buf[off + 5] = (uint8_t)i;	/* Contact ID = slot 号 */
	}
	if (a->report_len > 30)
		buf[30] = (uint8_t)count;
}

/*
 * 根据 slots[] 生成一整份待写入 hidg 的报告
 * 单点：合并 BTN_TOUCH + 第一个 active 手指 -> build_report_single
 */
static void build_report(struct app *a, uint8_t *buf)
{
	int i;
	bool tip = a->btn_touch;
	int x = 0, y = 0;

	if (a->multi_mode) {
		build_report_multi(a, buf);
		return;
	}

	for (i = 0; i < NUM_SLOTS; i++) {
		if (a->slots[i].active) {
			tip = true;
			x = a->slots[i].x;
			y = a->slots[i].y;
			break;	/* 单点只转发第一根手指 */
		}
	}
	build_report_single(a, buf, tip, x, y);
}

static bool report_equal(const uint8_t *a, const uint8_t *b, int len)
{
	return memcmp(a, b, (size_t)len) == 0;
}

static int hidg_open(struct app *a)
{
	if (a->hid_fd >= 0) {
		close(a->hid_fd);
		a->hid_fd = -1;
	}
	a->hid_fd = open(HIDG_DEV_DEFAULT, O_WRONLY);
	return a->hid_fd;
}

static bool hidg_write(struct app *a, const uint8_t *report)
{
	ssize_t n;

	if (!host_configured())
		return false;

	if (!timespec_cmp_now(&a->last_write_ts, MIN_WRITE_INTERVAL_NS))
		return false;

	n = write(a->hid_fd, report, (size_t)a->report_len);
	if (n != a->report_len) {
		if (n < 0 && (errno == EPIPE || errno == ESHUTDOWN ||
			      errno == ECONNRESET || errno == 108)) {
			usleep(300000);
			if (host_configured() && hidg_open(a) >= 0)
				return false;
		}
		return false;
	}

	clock_gettime(CLOCK_MONOTONIC, &a->last_write_ts);
	return true;
}

/*
 * 一帧 input 结束（SYN_REPORT）：此时 slots[] 已更新完，才组 HID 并 write
 * 这是 event0 -> hidg 转换的“输出触发点”
 */
static void handle_syn_report(struct app *a)
{
	uint8_t report[REPORT_MAX];

	if (!host_configured())
		return;

	build_report(a, report);
	/* 与上一包相同则跳过，避免空闲 SYN 刷屏导致 USB 端点错误 */
	if (a->have_last && report_equal(report, a->last_report, a->report_len))
		return;

	if (hidg_write(a, report)) {
		memcpy(a->last_report, report, (size_t)a->report_len);
		a->have_last = true;
	}
}

/*
 * 解析单条 input_event，更新 slots / btn_touch；不在此处写 hidg
 *
 * Goodix Type B 多点典型一帧顺序示例:
 *   SLOT=0 -> TRACKING_ID=0 -> POSITION_X -> POSITION_Y -> SYN_REPORT
 * 抬起: TRACKING_ID=-1 -> SYN_REPORT
 */
static void handle_input_event(struct app *a, const struct input_event *ev)
{
	if (ev->type == EV_ABS) {
		switch (ev->code) {
		case ABS_MT_SLOT:
			a->cur_slot = ev->value;
			break;
		case ABS_MT_TRACKING_ID:
			if (a->cur_slot >= 0 && a->cur_slot < NUM_SLOTS)
				a->slots[a->cur_slot].active = ev->value >= 0;
			break;
		case ABS_MT_POSITION_X:
			if (a->cur_slot >= 0 && a->cur_slot < NUM_SLOTS)
				a->slots[a->cur_slot].x = ev->value;
			break;
		case ABS_MT_POSITION_Y:
			if (a->cur_slot >= 0 && a->cur_slot < NUM_SLOTS)
				a->slots[a->cur_slot].y = ev->value;
			break;
		case ABS_X:
			a->slots[0].x = ev->value;
			break;
		case ABS_Y:
			a->slots[0].y = ev->value;
			break;
		default:
			break;
		}
	} else if (ev->type == EV_KEY && ev->code == BTN_TOUCH) {
		a->btn_touch = ev->value != 0;
	} else if (ev->type == EV_SYN && ev->code == SYN_REPORT) {
		handle_syn_report(a);
	}
}

int main(int argc, char **argv)
{
	struct app a;
	const char *mode;
	struct pollfd pfd;
	struct input_event ev;
	int ret;

	(void)argc;
	(void)argv;

	memset(&a, 0, sizeof(a));
	a.ev_fd = -1;
	a.hid_fd = -1;
	a.cur_slot = 0;

	mode = getenv("TOUCH_MODE");
	a.multi_mode = mode && strcmp(mode, "multi") == 0;

	a.report_len = read_report_len(a.multi_mode);
	printf("mode=%s report_length=%d\n",
	       a.multi_mode ? "multi" : "single", a.report_len);
	fflush(stdout);

	if (!wait_for_host())
		fprintf(stderr, "warn: USB host not configured; touch after host enumerates\n");

	a.ev_fd = open(INPUT_DEV_DEFAULT, O_RDONLY | O_CLOEXEC);
	if (a.ev_fd < 0) {
		perror("open " INPUT_DEV_DEFAULT);
		return 1;
	}

	if (hidg_open(&a) < 0) {
		perror("open " HIDG_DEV_DEFAULT);
		close(a.ev_fd);
		return 1;
	}

#if GRAB_INPUT
	if (ioctl(a.ev_fd, EVIOCGRAB, (void *)1) < 0)
		perror("EVIOCGRAB");
#endif

	memset(&a.last_write_ts, 0, sizeof(a.last_write_ts));

	pfd.fd = a.ev_fd;
	pfd.events = POLLIN;

	while (1) {
		ret = poll(&pfd, 1, POLL_TIMEOUT_MS);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			break;
		}
		if (ret == 0)
			continue;

		/* 读尽当前可读的所有 input_event，直到 SYN_REPORT 触发转换 */
		while (read(a.ev_fd, &ev, sizeof(ev)) == sizeof(ev))
			handle_input_event(&a, &ev);
	}

	close(a.hid_fd);
	close(a.ev_fd);
	return 0;
}
