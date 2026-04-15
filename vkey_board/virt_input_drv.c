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

/* 1. 确定主设备号                                                                 */
static int major = 0;
static char kernel_buf[1024];
static struct class *virt_input_class;
static struct input_dev *virt_dev;

static int init_input_device(void)
{
    int err;
    
    // 分配输入设备结构
    virt_dev = input_allocate_device();
    if (!virt_dev) {
        printk(KERN_ERR "virt_input: Failed to allocate input device\n");
        return -ENOMEM;
    }
    
    // 设置设备信息
    virt_dev->name = "Virtual Input Device";
    virt_dev->phys = "virt_input/input0";
    virt_dev->id.bustype = BUS_VIRTUAL;
    virt_dev->id.vendor = 0x0001;
    virt_dev->id.product = 0x0001;
    virt_dev->id.version = 0x0100;
    
    // 设置支持的事件类型
    __set_bit(EV_KEY, virt_dev->evbit);      // 按键事件
    __set_bit(EV_SYN, virt_dev->evbit);      // 同步事件
    
    // 设置支持的按键（支持所有标准按键）
    for (int i = 0; i < KEY_MAX; i++) {
        __set_bit(i, virt_dev->keybit);
    }
    
    // 注册输入设备
    err = input_register_device(virt_dev);
    if (err) {
        printk(KERN_ERR "virt_input: Failed to register input device: %d\n", err);
        input_free_device(virt_dev);
        return err;
    }
    
    printk(KERN_INFO "virt_input: Input device registered successfully\n");
    return 0;
}



/* 3. 实现对应的open/read/write等函数，填入file_operations结构体                   */
static ssize_t virt_input_drv_read (struct file *file, char __user *buf, size_t size, loff_t *offset)
{
	int err;
	printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);
	err = copy_to_user(buf, kernel_buf, MIN(1024, size));
	return MIN(1024, size);
}

static ssize_t virt_input_drv_write (struct file *file, const char __user *buf, size_t size, loff_t *offset)
{
	int err;
	struct input_event ev;
	printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);
	if (sizeof(struct input_event) != size)
	{
		printk("invalid param\n");
		return EINVAL;
	}
	err = copy_from_user(&ev, buf, sizeof(struct input_event));
	// printk("kernel recv type %d, code %d, value %d\n", ev.type, ev.code, ev.value);
	
	// 处理输入事件
	if (ev.type != EV_KEY)
	{
		printk("invalid param\n");
		return EINVAL;
	}

	input_report_key(virt_dev, ev.code, ev.value);
	printk(KERN_INFO "virt_input: Key event - code: %d, value: %d\n",
			ev.code, ev.value);
            
    // 发送同步事件，确保事件被处理
    input_sync(virt_dev);
	
	return sizeof(struct input_event);
}

static int virt_input_drv_open (struct inode *node, struct file *file)
{
	printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);
	return 0;
}

static int virt_input_drv_close (struct inode *node, struct file *file)
{
	printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);
	return 0;
}

/* 2. 定义自己的file_operations结构体                                              */
static struct file_operations virt_input_drv = {
	.owner	 = THIS_MODULE,
	.open    = virt_input_drv_open,
	.read    = virt_input_drv_read,
	.write   = virt_input_drv_write,
	.release = virt_input_drv_close,
	// .poll    = gpio_key_drv_poll,
};

/* 4. 把file_operations结构体告诉内核：注册驱动程序                                */
/* 5. 谁来注册驱动程序啊？得有一个入口函数：安装驱动程序时，就会去调用这个入口函数 */
static int __init virt_input_init(void)
{
	int err;
	
	printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);
	if (init_input_device())
	{
		return -1;
	}
	major = register_chrdev(0, "virt_input", &virt_input_drv);  /* /dev/virt_input */


	virt_input_class = class_create("virt_input_class");
	err = PTR_ERR(virt_input_class);
	if (IS_ERR(virt_input_class)) {
		printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);
		unregister_chrdev(major, "virt_input");
		return -1;
	}
	
	device_create(virt_input_class, NULL, MKDEV(major, 0), NULL, "virt_input"); /* /dev/virt_input */
	
	return 0;
}

/* 6. 有入口函数就应该有出口函数：卸载驱动程序时，就会去调用这个出口函数           */
static void __exit virt_input_exit(void)
{
	printk("%s %s line %d\n", __FILE__, __FUNCTION__, __LINE__);
	device_destroy(virt_input_class, MKDEV(major, 0));
	class_destroy(virt_input_class);
	unregister_chrdev(major, "virt_input");

	if (virt_dev)
	{
		input_unregister_device(virt_dev);
        input_free_device(virt_dev);
	}
}


/* 7. 其他完善：提供设备信息，自动创建设备节点                                     */

module_init(virt_input_init);
module_exit(virt_input_exit);

MODULE_LICENSE("GPL");


