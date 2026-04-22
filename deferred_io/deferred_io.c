#include <linux/module.h>

#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/tty.h>
#include <linux/kmod.h>
#include <linux/gfp.h>
#include <linux/input.h>
#include <linux/pagemap.h>
#include <asm/ptrace.h>
#include <linux/rmap.h>
#include <linux/workqueue.h>

#define BUFFER_SIZE 8192

static struct delayed_work deferred_work;

/* 1. 确定主设备号                                                                 */
static int major = 0;
// static char *kernel_buf = NULL;
static struct class *m_deferred_io_class;

/* 3. 实现对应的open/read/write等函数，填入file_operations结构体                   */
static ssize_t m_deferred_io_drv_read (struct file *file, char __user *buf, size_t size, loff_t *offset)
{
	return 0;
}

static ssize_t m_deferred_io_drv_write (struct file *file, const char __user *buf, size_t size, loff_t *offset)
{
	
	return 0;
}

static const struct address_space_operations fb_deferred_io_aops = {
	.dirty_folio	= noop_dirty_folio,
};

static int m_deferred_io_drv_open (struct inode *node, struct file *file)
{
    void *buffer;
    
    printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);
    buffer = vzalloc(BUFFER_SIZE);
    if (!buffer)
        return -ENOMEM;
    
    file->private_data = buffer;
	memset(buffer, 0, BUFFER_SIZE);
	file->f_mapping->a_ops = &fb_deferred_io_aops;
    return 0;
}

static struct page *fb_deferred_io_page(void *screen_base, unsigned long offs)
{
	// void *screen_base = (void __force *) info->screen_base;
	struct page *page;

	// if (is_vmalloc_addr(screen_base + offs))
	page = vmalloc_to_page(screen_base + offs);
	// else
	// 	page = pfn_to_page((info->fix.smem_start + offs) >> PAGE_SHIFT);

	return page;
}

static int m_deferred_io_drv_close (struct inode *node, struct file *file)
{
	struct page *page;
	int i;
	printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);

	/* clear out the mapping that we setup */
	for (i = 0 ; i < BUFFER_SIZE; i += PAGE_SIZE) {
		page = fb_deferred_io_page(file->private_data, i);
		page->mapping = NULL;
	}

    if (file->private_data)
    {
        vfree(file->private_data);
    }
	return 0;
}

static vm_fault_t fb_deferred_io_fault(struct vm_fault *vmf)
{
    printk("dtwdebug[%s][%d]\n", __func__, __LINE__);
	unsigned long offset;
	struct page *page;
	unsigned char *buffer = vmf->vma->vm_private_data;

	offset = vmf->pgoff << PAGE_SHIFT;

	page = fb_deferred_io_page(buffer, offset);
	if (!page)
		return VM_FAULT_SIGBUS;

	get_page(page);

	if (vmf->vma->vm_file)
		page->mapping = vmf->vma->vm_file->f_mapping;
	else
		printk(KERN_ERR "no mapping available\n");

	BUG_ON(!page->mapping);
	page->index = vmf->pgoff; /* for page_mkclean() */

	vmf->page = page;
	printk("dtwdebug[%s][%d]\n", __func__, __LINE__);
	return 0;
}

static struct page *cur;

static vm_fault_t fb_deferred_io_mkwrite(struct vm_fault *vmf)
{
    printk("dtwdebug[%s][%d]\n", __func__, __LINE__);
	file_update_time(vmf->vma->vm_file);
	// struct fb_info *info = vmf->vma->vm_private_data;
	dump_stack();
	lock_page(vmf->page);
	schedule_delayed_work(&deferred_work, HZ);
	// page_mkclean(vmf->page);
	// unlock_page(vmf->page);
	cur = vmf->page;
	return VM_FAULT_LOCKED;
}

static const struct vm_operations_struct fb_deferred_io_vm_ops = {
	.fault		= fb_deferred_io_fault,
	.page_mkwrite	= fb_deferred_io_mkwrite,
};

static int m_deferred_io_drv_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_page_prot = pgprot_decrypted(vma->vm_page_prot);
	// vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	vma->vm_ops = &fb_deferred_io_vm_ops;
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
	// if (!(info->flags & FBINFO_VIRTFB))
		// vm_flags_set(vma, VM_IO);
	// vm_flags_set(vma, VM_WRITE | VM_SHARED | VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_private_data = file->private_data;
	return 0;
}

/* 2. 定义自己的file_operations结构体                                              */
static struct file_operations m_deferred_io_drv = {
	.owner	 = THIS_MODULE,
	.open    = m_deferred_io_drv_open,
	.read    = m_deferred_io_drv_read,
	.write   = m_deferred_io_drv_write,
	.release = m_deferred_io_drv_close,
	.mmap = m_deferred_io_drv_mmap,
};

static void fb_deferred_io_work(struct work_struct *work)
{
	// struct fb_info *info = container_of(work, struct fb_info, deferred_work.work);
	// struct fb_deferred_io_pageref *pageref, *next;
	// struct fb_deferred_io *fbdefio = info->fbdefio;

	// /* here we mkclean the pages, then do all deferred IO */
	// mutex_lock(&fbdefio->lock);
	// list_for_each_entry(pageref, &fbdefio->pagereflist, list) {
	// 	struct page *cur = pageref->page;
		lock_page(cur);
		page_mkclean(cur);
		unlock_page(cur);
	// }

	// /* driver's callback with pagereflist */
	// fbdefio->deferred_io(info, &fbdefio->pagereflist);

	// /* clear the list */
	// list_for_each_entry_safe(pageref, next, &fbdefio->pagereflist, list)
	// 	fb_deferred_io_pageref_put(pageref, info);

	// mutex_unlock(&fbdefio->lock);
}

/* 4. 把file_operations结构体告诉内核：注册驱动程序                                */
/* 5. 谁来注册驱动程序啊？得有一个入口函数：安装驱动程序时，就会去调用这个入口函数 */
static int __init m_deferred_io_init(void)
{
	int err;
	

	INIT_DELAYED_WORK(&deferred_work, fb_deferred_io_work);

	major = register_chrdev(0, "m_deferred_io", &m_deferred_io_drv);  /* /dev/m_deferred_io */
	printk("%s %s line %d, major %d\n", __FILE__, __FUNCTION__, __LINE__, major);

	m_deferred_io_class = class_create("m_deferred_io_class");
	err = PTR_ERR(m_deferred_io_class);
	if (IS_ERR(m_deferred_io_class)) {
		printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);
		unregister_chrdev(major, "m_deferred_io");
		return -1;
	}
	
	device_create(m_deferred_io_class, NULL, MKDEV(major, 0), NULL, "m_deferred_io"); /* /dev/m_deferred_io */
	
	return 0;
}

/* 6. 有入口函数就应该有出口函数：卸载驱动程序时，就会去调用这个出口函数           */
static void __exit m_deferred_io_exit(void)
{
	printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);
	cancel_delayed_work_sync(&deferred_work);
	device_destroy(m_deferred_io_class, MKDEV(major, 0));
	class_destroy(m_deferred_io_class);
	unregister_chrdev(major, "m_deferred_io");
}


/* 7. 其他完善：提供设备信息，自动创建设备节点                                     */

module_init(m_deferred_io_init);
module_exit(m_deferred_io_exit);

MODULE_LICENSE("GPL");


