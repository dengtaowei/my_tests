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

static unsigned int defio_delay_ms = 33;
module_param(defio_delay_ms, uint, 0644);
MODULE_PARM_DESC(defio_delay_ms, "deferred io delay in milliseconds");

static bool tx_enable = true;
module_param(tx_enable, bool, 0644);
MODULE_PARM_DESC(tx_enable, "Enable kernel push to USB serial gadget");

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
	struct mutex tx_lock;
	u32 dirty_y1;
	u32 dirty_y2;
	bool dirty_pending;
	struct work_struct tx_work;
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

	filp = filp_open(tx_tty, O_WRONLY | O_NONBLOCK, 0);
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
	return 0;
}

static void deferred_fb_mark_dirty_lines(struct deferred_fb_dev *dev, u32 y1, u32 y2)
{
	mutex_lock(&dev->tx_lock);
	if (!dev->dirty_pending) {
		dev->dirty_y1 = y1;
		dev->dirty_y2 = y2;
		dev->dirty_pending = true;
	} else {
		if (y1 < dev->dirty_y1)
			dev->dirty_y1 = y1;
		if (y2 > dev->dirty_y2)
			dev->dirty_y2 = y2;
	}
	atomic_inc(&dev->seq);
	mutex_unlock(&dev->tx_lock);
	schedule_work(&dev->tx_work);
}

static void deferred_fb_tx_worker(struct work_struct *work)
{
	struct deferred_fb_dev *dev =
		container_of(work, struct deferred_fb_dev, tx_work);
	struct deferred_fb_usb_frame_hdr hdr;
	u32 seq;
	u32 y1;
	u32 y2;
	int ret;

	if (!tx_enable)
		return;

	seq = (u32)atomic_read(&dev->seq);
	if (seq == dev->tx_last_seq)
		return;

	mutex_lock(&dev->tx_lock);
	if (!dev->dirty_pending) {
		mutex_unlock(&dev->tx_lock);
		return;
	}
	y1 = dev->dirty_y1;
	y2 = dev->dirty_y2;
	dev->dirty_pending = false;
	mutex_unlock(&dev->tx_lock);

	memcpy(dev->tx_buf, dev->vmem, dev->vmem_size);

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = DEFERRED_FB_USB_MAGIC;
	hdr.seq = seq;
	hdr.width = width;
	hdr.height = height;
	hdr.bpp = bpp;
	hdr.x1 = 0;
	hdr.y1 = y1;
	hdr.x2 = width - 1;
	hdr.y2 = y2;
	hdr.payload_size = (u32)dev->vmem_size;

	ret = deferred_fb_send_all(&hdr, sizeof(hdr));
	if (ret < 0)
		return;

	ret = deferred_fb_send_all(dev->tx_buf, dev->vmem_size);
	if (ret < 0)
		return;

	dev->tx_last_seq = seq;
}

static void deferred_fb_deferred_io(struct fb_info *info, struct list_head *pagelist)
{
	struct deferred_fb_dev *dev = info->par;
	struct page *page;
	size_t min_off = dev->vmem_size;
	size_t max_off = 0;
	bool has_pages = false;
	u32 y1, y2;

	list_for_each_entry(page, pagelist, lru) {
		size_t start = ((size_t)page->index) << PAGE_SHIFT;
		size_t end = start + PAGE_SIZE;

		if (start >= dev->vmem_size)
			continue;
		if (end > dev->vmem_size)
			end = dev->vmem_size;

		if (!has_pages) {
			min_off = start;
			max_off = end;
			has_pages = true;
		} else {
			if (start < min_off)
				min_off = start;
			if (end > max_off)
				max_off = end;
		}
	}

	if (!has_pages) {
		deferred_fb_mark_dirty_lines(dev, 0, height - 1);
		return;
	}

	y1 = (u32)(min_off / info->fix.line_length);
	y2 = (u32)((max_off - 1) / info->fix.line_length);
	if (y2 >= (u32)height)
		y2 = height - 1;

	deferred_fb_mark_dirty_lines(dev, y1, y2);
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

	dev->tx_buf = vzalloc(dev->vmem_size);
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
	mutex_init(&dev->tx_lock);
	dev->dirty_y1 = 0;
	dev->dirty_y2 = height - 1;
	dev->dirty_pending = true;
	INIT_WORK(&dev->tx_work, deferred_fb_tx_worker);
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
	schedule_work(&dev->tx_work);

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

	cancel_work_sync(&dev->tx_work);
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
