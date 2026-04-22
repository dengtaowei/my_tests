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
#include <linux/fb.h>
#include <linux/spinlock.h>
#include <linux/spi/spi.h>
#include <linux/platform_device.h>

#define BUFFER_SIZE 1024

#define WIDTH		128
#define HEIGHT		64

static struct delayed_work deferred_work;

static struct gpio_desc *dc_gpio = NULL;
static struct spi_device *g_spi = NULL;
static unsigned char *screen_buffer = NULL;

//为0 表示命令，为1表示数据
#define OLED_CMD 	0
#define OLED_DATA 	1

static void dc_pin_init(void)
{
	gpiod_direction_output(dc_gpio, 1);
}

static void oled_set_dc_pin(int val)
{
	gpiod_set_value(dc_gpio, val);
}

static void spi_write_datas(const unsigned char *buf, int len)
{
	spi_write(g_spi, buf, len);
}


/**********************************************************************
	 * 函数名称： oled_write_cmd
	 * 功能描述： oled向特定地址写入数据或者命令
	 * 输入参数：@uc_data :要写入的数据
	 			@uc_cmd:为1则表示写入数据，为0表示写入命令
	 * 输出参数：无
	 * 返 回 值： 无
	 * 修改日期 	   版本号	 修改人		  修改内容
	 * -----------------------------------------------
	 * 2020/03/04		 V1.0	  芯晓		  创建
 ***********************************************************************/
static void oled_write_cmd_data(unsigned char uc_data,unsigned char uc_cmd)
{
	if(uc_cmd==0)
	{
		oled_set_dc_pin(0);
	}
	else
	{
		oled_set_dc_pin(1);//拉高，表示写入数据
	}
	spi_write_datas(&uc_data, 1);//写入
}


/**********************************************************************
	 * 函数名称： oled_init
	 * 功能描述： oled_init的初始化，包括SPI控制器得初始化
	 * 输入参数：无
	 * 输出参数： 初始化的结果
	 * 返 回 值： 成功则返回0，否则返回-1
	 * 修改日期 	   版本号	 修改人		  修改内容
	 * -----------------------------------------------
	 * 2020/03/15		 V1.0	  芯晓		  创建
 ***********************************************************************/
static int oled_init(void)
{
	oled_write_cmd_data(0xae,OLED_CMD);//关闭显示

	oled_write_cmd_data(0x00,OLED_CMD);//设置 lower column address
	oled_write_cmd_data(0x10,OLED_CMD);//设置 higher column address

	oled_write_cmd_data(0x40,OLED_CMD);//设置 display start line

	oled_write_cmd_data(0xB0,OLED_CMD);//设置page address

	oled_write_cmd_data(0x81,OLED_CMD);// contract control
	oled_write_cmd_data(0x66,OLED_CMD);//128

	oled_write_cmd_data(0xa1,OLED_CMD);//设置 segment remap

	oled_write_cmd_data(0xa6,OLED_CMD);//normal /reverse

	oled_write_cmd_data(0xa8,OLED_CMD);//multiple ratio
	oled_write_cmd_data(0x3f,OLED_CMD);//duty = 1/64

	oled_write_cmd_data(0xc8,OLED_CMD);//com scan direction

	oled_write_cmd_data(0xd3,OLED_CMD);//set displat offset
	oled_write_cmd_data(0x00,OLED_CMD);//

	oled_write_cmd_data(0xd5,OLED_CMD);//set osc division
	oled_write_cmd_data(0x80,OLED_CMD);//

	oled_write_cmd_data(0xd9,OLED_CMD);//ser pre-charge period
	oled_write_cmd_data(0x1f,OLED_CMD);//

	oled_write_cmd_data(0xda,OLED_CMD);//set com pins
	oled_write_cmd_data(0x12,OLED_CMD);//

	oled_write_cmd_data(0xdb,OLED_CMD);//set vcomh
	oled_write_cmd_data(0x30,OLED_CMD);//

	oled_write_cmd_data(0x8d,OLED_CMD);//set charge pump disable 
	oled_write_cmd_data(0x14,OLED_CMD);//

	oled_write_cmd_data(0xaf,OLED_CMD);//set dispkay on

	return 0;
}		  			 		  						  					  				 	   		  	  	 	  

//坐标设置
/**********************************************************************
	 * 函数名称： OLED_DIsp_Set_Pos
	 * 功能描述：设置要显示的位置
	 * 输入参数：@ x ：要显示的column address
	 			@y :要显示的page address
	 * 输出参数： 无
	 * 返 回 值： 
	 * 修改日期 	   版本号	 修改人		  修改内容
	 * -----------------------------------------------
	 * 2020/03/15		 V1.0	  芯晓		  创建
 ***********************************************************************/
static void OLED_DIsp_Set_Pos(int x, int y)
{ 	oled_write_cmd_data(0xb0+y,OLED_CMD);
	oled_write_cmd_data((x&0x0f),OLED_CMD); 
	oled_write_cmd_data(((x&0xf0)>>4)|0x10,OLED_CMD);
}   

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

static int fb_deferred_io_set_page_dirty(struct page *page)
{
	if (!PageDirty(page))
		SetPageDirty(page);
	return 0;
}

static const struct address_space_operations fb_deferred_io_aops = {
	.set_page_dirty = fb_deferred_io_set_page_dirty,
};

static int m_deferred_io_drv_open (struct inode *node, struct file *file)
{   
	file->f_mapping->a_ops = &fb_deferred_io_aops;
    return 0;
}

static struct page *fb_deferred_io_page(void *screen_base, unsigned long offs)
{
	struct page *page = NULL;

	if (is_vmalloc_addr(screen_base + offs))
		page = vmalloc_to_page(screen_base + offs);

	return page;
}

static int m_deferred_io_drv_close (struct inode *node, struct file *file)
{
	struct page *page;
	int i;
	printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);

	/* clear out the mapping that we setup */
	for (i = 0 ; i < BUFFER_SIZE; i += PAGE_SIZE) {
		page = fb_deferred_io_page(screen_buffer, i);
		page->mapping = NULL;
	}
	return 0;
}

static vm_fault_t fb_deferred_io_fault(struct vm_fault *vmf)
{
	unsigned long offset;
	struct page *page;
	unsigned char *buffer = screen_buffer;

	offset = vmf->pgoff << PAGE_SHIFT;

    printk("dtwdebug[%s][%d]\n", __func__, __LINE__);

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
	dump_stack();
	lock_page(vmf->page);
	schedule_delayed_work(&deferred_work, HZ / 20);

	cur = vmf->page;
	return VM_FAULT_LOCKED;
}

static const struct vm_operations_struct fb_deferred_io_vm_ops = {
	.fault		= fb_deferred_io_fault,
	.page_mkwrite	= fb_deferred_io_mkwrite,
};

static int m_deferred_io_drv_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &fb_deferred_io_vm_ops;
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	return 0;
}

static long fb_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct fb_var_screeninfo var;
	long ret = 0;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case FBIOGET_VSCREENINFO:
		var.xres = WIDTH;
		var.yres = HEIGHT;
		var.bits_per_pixel = 1;
		ret = copy_to_user(argp, &var, sizeof(var)) ? -EFAULT : 0;
		break;
	default:
		break;
	}

	return ret;
	
}

/* 2. 定义自己的file_operations结构体                                              */
static struct file_operations m_deferred_io_drv = {
	.owner	 = THIS_MODULE,
	.open    = m_deferred_io_drv_open,
	.read    = m_deferred_io_drv_read,
	.write   = m_deferred_io_drv_write,
	.release = m_deferred_io_drv_close,
	.mmap = m_deferred_io_drv_mmap,
	.unlocked_ioctl = fb_ioctl,
};


static u8 *oled_buf = NULL;


static void fb_deferred_io_work(struct work_struct *work)
{
	unsigned char *p[8];
	unsigned char data[8];
	int i;
	int j;
	int line;
	int bit;
	unsigned char byte;
	unsigned char *fb  = screen_buffer;
	int k;

	if (!cur)
	{
		return;
	}

	lock_page(cur);
	page_mkclean(cur);
	unlock_page(cur);
	


    k = 0;
    for (i = 0; i < 8; i++)
    {
        for (line = 0; line < 8; line++)
            p[line] = &fb[i*128 + line * 16];
        
        for (j = 0; j < 16; j++)
        {
            for (line = 0; line < 8; line++)
            {
                data[line] = *p[line];
                p[line] += 1;
            }

            for (bit = 0; bit < 8; bit++)
            {
                byte =  (((data[0]>>bit) & 1) << 0) |
                        (((data[1]>>bit) & 1) << 1) |
                        (((data[2]>>bit) & 1) << 2) |
                        (((data[3]>>bit) & 1) << 3) |
                        (((data[4]>>bit) & 1) << 4) |
                        (((data[5]>>bit) & 1) << 5) |
                        (((data[6]>>bit) & 1) << 6) |
                        (((data[7]>>bit) & 1) << 7);

                oled_buf[k++] = byte;
            }
            
        }
    }
    

    /* 3. 通过SPI发送给OLED */
    for (i = 0; i < 8; i++)
    {
        OLED_DIsp_Set_Pos(0, i);
        oled_set_dc_pin(1);
        spi_write_datas(&oled_buf[i*128], 128);
    }


}

static void init_display(void)
{
	unsigned char *p[8];
	unsigned char data[8];
	int i;
	int j;
	int line;
	int bit;
	unsigned char byte;
	unsigned char *fb  = screen_buffer;
	int k;


    k = 0;
    for (i = 0; i < 8; i++)
    {
        for (line = 0; line < 8; line++)
            p[line] = &fb[i*128 + line * 16];
        
        for (j = 0; j < 16; j++)
        {
            for (line = 0; line < 8; line++)
            {
                data[line] = *p[line];
                p[line] += 1;
            }

            for (bit = 0; bit < 8; bit++)
            {
                byte =  (((data[0]>>bit) & 1) << 0) |
                        (((data[1]>>bit) & 1) << 1) |
                        (((data[2]>>bit) & 1) << 2) |
                        (((data[3]>>bit) & 1) << 3) |
                        (((data[4]>>bit) & 1) << 4) |
                        (((data[5]>>bit) & 1) << 5) |
                        (((data[6]>>bit) & 1) << 6) |
                        (((data[7]>>bit) & 1) << 7);

                oled_buf[k++] = byte;
            }
            
        }
    }
    

    /* 3. 通过SPI发送给OLED */
    for (i = 0; i < 8; i++)
    {
        OLED_DIsp_Set_Pos(0, i);
        oled_set_dc_pin(1);
        spi_write_datas(&oled_buf[i*128], 128);
    }
}

static int deferred_io_driver_probe_spi(struct spi_device *spi)			
{										
	int err;
	struct device *dev;
	dev = &spi->dev;		
	g_spi = spi;
	

	INIT_DELAYED_WORK(&deferred_work, fb_deferred_io_work);

	dc_gpio = gpiod_get(&spi->dev, "dc", 0);

	if (!dc_gpio)
	{
		printk("dtwdebug gpio request err\n");
		return -1;
	}
    
    printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);
    screen_buffer = vzalloc(BUFFER_SIZE);
	memset(screen_buffer, 0, BUFFER_SIZE);

	major = register_chrdev(0, "m_deferred_io", &m_deferred_io_drv);  /* /dev/m_deferred_io */
	printk("%s %s line %d, major %d\n", __FILE__, __FUNCTION__, __LINE__, major);

	m_deferred_io_class = class_create(THIS_MODULE, "m_deferred_io_class");
	err = PTR_ERR(m_deferred_io_class);
	if (IS_ERR(m_deferred_io_class)) {
		printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);
		unregister_chrdev(major, "m_deferred_io");
		return -1;
	}
	
	device_create(m_deferred_io_class, NULL, MKDEV(major, 0), NULL, "m_deferred_io"); /* /dev/m_deferred_io */
	
	dc_pin_init();
	oled_init();

	oled_buf = kmalloc(1024, GFP_KERNEL);

	init_display();

	return 0;
}										
										
static int deferred_io_driver_remove_spi(struct spi_device *spi)		
{								
	
	printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);
	cancel_delayed_work_sync(&deferred_work);
	device_destroy(m_deferred_io_class, MKDEV(major, 0));
	class_destroy(m_deferred_io_class);
	unregister_chrdev(major, "m_deferred_io");

	if (screen_buffer)
	{
		vfree(screen_buffer);
		screen_buffer = NULL;
	}

	gpiod_put(dc_gpio);

	kfree(oled_buf);

	return 0;
}	

static const struct of_device_id dt_ids[] = {					
	{ .compatible = "100ask,oled" },						
	{},									
};	

static struct spi_driver deferred_io_driver_spi_driver = {
	.driver = {	
		.name = "100ask,oled",							
		.of_match_table = dt_ids,					
	},														
	.probe = deferred_io_driver_probe_spi,					
	.remove = deferred_io_driver_remove_spi,					
};

/* 4. 把file_operations结构体告诉内核：注册驱动程序                                */
/* 5. 谁来注册驱动程序啊？得有一个入口函数：安装驱动程序时，就会去调用这个入口函数 */
static int __init m_deferred_io_init(void)
{
	return spi_register_driver(&deferred_io_driver_spi_driver);
	
}

/* 6. 有入口函数就应该有出口函数：卸载驱动程序时，就会去调用这个出口函数           */
static void __exit m_deferred_io_exit(void)
{
	spi_unregister_driver(&deferred_io_driver_spi_driver);
}

// /* 7. 其他完善：提供设备信息，自动创建设备节点                                     */

module_init(m_deferred_io_init);
module_exit(m_deferred_io_exit);

MODULE_LICENSE("GPL");


