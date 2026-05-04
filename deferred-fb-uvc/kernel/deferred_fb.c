#include <linux/atomic.h>
#include <linux/fb.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/vmalloc.h>

#include "../include/deferred_fb_uapi.h"

static int width = 640;
module_param(width, int, 0644);
MODULE_PARM_DESC(width, "Framebuffer width");

static int height = 480;
module_param(height, int, 0644);
MODULE_PARM_DESC(height, "Framebuffer height");

static int bpp = 16;
module_param(bpp, int, 0644);
MODULE_PARM_DESC(bpp, "Bits per pixel (16 or 32)");

static unsigned int defio_delay_ms = 50;
module_param(defio_delay_ms, uint, 0644);
MODULE_PARM_DESC(defio_delay_ms, "deferred io delay in milliseconds");

static char *tx_tty = "/dev/ttyGS0";
module_param(tx_tty, charp, 0644);
MODULE_PARM_DESC(tx_tty, "USB serial gadget device path");

struct deferred_fb_dev {
	struct fb_info *info;
	void *vmem;
	size_t vmem_size;
	struct fb_deferred_io defio;
	u32 pseudo_palette[16];
	atomic_t seq;
	u32 tx_last_seq;
	u8 *tx_buf;
};

static struct deferred_fb_dev *gdev;

static int deferred_fb_send_all(const void *buf, size_t len)
{
	struct file *filp;
	loff_t pos = 0;
	const u8 *p = buf;
	size_t left = len;

	// filp = filp_open(tx_tty, O_WRONLY | O_NONBLOCK, 0);
	filp = filp_open(tx_tty, O_WRONLY, 0);
	if (IS_ERR(filp))
		return PTR_ERR(filp);

	while (left) {
		ssize_t written = kernel_write(filp, p, left, &pos);
		if (written < 0) {
			filp_close(filp, NULL);
			return (int)written;
		}
		if (written == 0) {
			filp_close(filp, NULL);
			return -EIO;
		}
		p += written;
		left -= written;
	}

	filp_close(filp, NULL);
	return len;
}

static void update_display(struct deferred_fb_dev *dev, unsigned int start_line, 
	unsigned int end_line)
{
	struct deferred_fb_usb_frame_hdr hdr;
	u32 seq;
	u32 y1;
	u32 y2;
	u32 line_length;
	size_t payload_size;
	void *src;
	int ret;

	y1 = start_line;
	y2 = end_line;

	if (y2 < y1)
	{
		return;
	}

	seq = (u32)atomic_read(&dev->seq);

	line_length = dev->info->fix.line_length;
	payload_size = (size_t)(y2 - y1 + 1) * line_length;
	src = (u8 *)dev->vmem + ((size_t)y1 * line_length);
	memcpy(dev->tx_buf + sizeof(struct deferred_fb_usb_frame_hdr), src, payload_size);

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = DEFERRED_FB_USB_MAGIC;
	hdr.seq = seq;
	hdr.width = width;
	hdr.height = height;
	hdr.bpp = bpp;
	hdr.line_length = line_length;
	hdr.x1 = 0;
	hdr.y1 = y1;
	hdr.x2 = width - 1;
	hdr.y2 = y2;
	hdr.payload_size = (u32)payload_size;
	memcpy(dev->tx_buf, &hdr, sizeof(struct deferred_fb_usb_frame_hdr));

	// printk("dtwdebug[%s][%d] y1=%d, y2=%d, payload_size=%d, total=%d, firstb %02x\n", __func__, __LINE__, y1, y2, payload_size, payload_size + sizeof(struct deferred_fb_usb_frame_hdr), 
	// 	((char *)src)[0]);

	// ret = deferred_fb_send_all(&hdr, sizeof(hdr));
	// if (ret < 0)
	// 	return;

	ret = deferred_fb_send_all(dev->tx_buf, payload_size + sizeof(struct deferred_fb_usb_frame_hdr));
	if (ret != payload_size + sizeof(struct deferred_fb_usb_frame_hdr))
	{
		printk("dtwdebug[%s][%d] send err ret = %d\n", __func__, __LINE__, ret);
		return;
	}

	dev->tx_last_seq = seq;
}

static void deferred_fb_deferred_io(struct fb_info *info, struct list_head *pagelist)
{
	struct deferred_fb_dev *dev = info->par;
	unsigned int dirty_lines_start, dirty_lines_end;
	struct page *page;
	unsigned long index;
	unsigned int y_low = 0, y_high = 0;
	int count = 0;

	dirty_lines_start = info->var.yres - 1;
	dirty_lines_end = 0;

	/* Mark display lines as dirty */
	list_for_each_entry(page, pagelist, lru) {
		count++;
		index = page->index << PAGE_SHIFT;
		y_low = index / info->fix.line_length;
		y_high = (index + PAGE_SIZE - 1) / info->fix.line_length;
		// printk(
		// 	"page->index=%lu y_low=%d y_high=%d\n",
		// 	page->index, y_low, y_high);
		if (y_high > info->var.yres - 1)
			y_high = info->var.yres - 1;
		if (y_low < dirty_lines_start)
			dirty_lines_start = y_low;
		if (y_high > dirty_lines_end)
			dirty_lines_end = y_high;
	}

	update_display(info->par,
					dirty_lines_start, dirty_lines_end);

	atomic_inc(&dev->seq);
}

static int deferred_fb_mmap(struct fb_info *info, struct vm_area_struct *vma)
{
	return fb_deferred_io_mmap(info, vma);
}

static struct fb_ops deferred_fb_ops = {
	.owner = THIS_MODULE,
	.fb_read = fb_sys_read,
	.fb_write = fb_sys_write,
	.fb_fillrect = sys_fillrect,
	.fb_copyarea = sys_copyarea,
	.fb_imageblit = sys_imageblit,
	.fb_mmap = deferred_fb_mmap,
};

static int __init deferred_fb_init(void)
{
	struct deferred_fb_dev *dev;
	struct fb_info *info;
	int ret;
	u32 line_length;

	if (bpp != 16 && bpp != 32)
		return -EINVAL;

	line_length = width * (bpp / 8);

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->vmem_size = (size_t)line_length * height;
	dev->vmem = vzalloc(dev->vmem_size);
	if (!dev->vmem) {
		ret = -ENOMEM;
		goto err_free_dev;
	}

	dev->tx_buf = vzalloc(dev->vmem_size + sizeof(struct deferred_fb_usb_frame_hdr));
	if (!dev->tx_buf) {
		ret = -ENOMEM;
		goto err_free_vmem;
	}

	info = framebuffer_alloc(0, NULL);
	if (!info) {
		ret = -ENOMEM;
		goto err_free_buf;
	}

	atomic_set(&dev->seq, 1);
	dev->tx_last_seq = 0;

	info->screen_base = dev->vmem;
	info->screen_size = dev->vmem_size;
	info->fbops = &deferred_fb_ops;
	info->fix = (struct fb_fix_screeninfo) {
		.id = "deferred_fb",
		.type = FB_TYPE_PACKED_PIXELS,
		.visual = bpp == 16 ? FB_VISUAL_TRUECOLOR : FB_VISUAL_DIRECTCOLOR,
		.line_length = line_length,
		.accel = FB_ACCEL_NONE,
		.smem_start = 0,
		.smem_len = dev->vmem_size,
	};

	info->var = (struct fb_var_screeninfo) {
		.xres = width,
		.yres = height,
		.xres_virtual = width,
		.yres_virtual = height,
		.bits_per_pixel = bpp,
		.activate = FB_ACTIVATE_NOW,
	};

	if (bpp == 16) {
		info->var.red.offset = 11;
		info->var.red.length = 5;
		info->var.green.offset = 5;
		info->var.green.length = 6;
		info->var.blue.offset = 0;
		info->var.blue.length = 5;
	} else {
		info->var.red.offset = 16;
		info->var.red.length = 8;
		info->var.green.offset = 8;
		info->var.green.length = 8;
		info->var.blue.offset = 0;
		info->var.blue.length = 8;
	}

	info->pseudo_palette = dev->pseudo_palette;
	info->flags = FBINFO_VIRTFB;
	info->par = dev;

	dev->defio.delay = msecs_to_jiffies(defio_delay_ms);
	if (dev->defio.delay == 0)
		dev->defio.delay = 1;
	dev->defio.deferred_io = deferred_fb_deferred_io;
	info->fbdefio = &dev->defio;
	fb_deferred_io_init(info);

	ret = register_framebuffer(info);
	if (ret)
		goto err_cleanup_defio;

	dev->info = info;
	gdev = dev;

	pr_info("deferred_fb: /dev/fb%d (%dx%dx%d), defio_delay_ms=%u\n",
		info->node, width, height, bpp, defio_delay_ms);
	return 0;

err_cleanup_defio:
	fb_deferred_io_cleanup(info);
	framebuffer_release(info);
err_free_buf:
	vfree(dev->tx_buf);
err_free_vmem:
	vfree(dev->vmem);
err_free_dev:
	kfree(dev);
	return ret;
}

static void __exit deferred_fb_exit(void)
{
	struct deferred_fb_dev *dev = gdev;

	if (!dev)
		return;

	unregister_framebuffer(dev->info);
	fb_deferred_io_cleanup(dev->info);
	framebuffer_release(dev->info);
	vfree(dev->tx_buf);
	vfree(dev->vmem);
	kfree(dev);
	gdev = NULL;
}

module_init(deferred_fb_init);
module_exit(deferred_fb_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("demo");
MODULE_DESCRIPTION("Deferred IO framebuffer demo with kernel USB serial push");
