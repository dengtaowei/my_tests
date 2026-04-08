#include <linux/bitfield.h>
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/sysfs.h>

struct virtual_data {
	spinlock_t buffer_lock;
	u16 buffer_idx;
	u8 idx_write_cnt;
	u8 buffer[];
};

#define ROM_SIZE 256
#define ADDRESS_MASK (ROM_SIZE - 1)

static int i2c_slave_virtual_slave_cb(struct i2c_client *client,
				     enum i2c_slave_event event, u8 *val)
{
	struct virtual_data *virtual = i2c_get_clientdata(client);
	printk("dtwdebug[%s][%d]================ %02x\n", __func__, __LINE__, *val);
	switch (event) {
	case I2C_SLAVE_WRITE_RECEIVED:
		printk("dtwdebug[%s][%d]\n", __func__, __LINE__);
		if (virtual->idx_write_cnt < 1) {
			if (virtual->idx_write_cnt == 0)
				virtual->buffer_idx = 0;
			virtual->buffer_idx = *val;
			printk("dtwdebug[%s][%d] buffer_idx=%d\n", __func__, __LINE__, virtual->buffer_idx);
			virtual->idx_write_cnt++;
		} else {
            spin_lock(&virtual->buffer_lock);
            virtual->buffer[virtual->buffer_idx++ & ADDRESS_MASK] = *val;
            spin_unlock(&virtual->buffer_lock);
            printk("dtwdebug[%s][%d] write %02x\n", __func__, __LINE__, virtual->buffer[virtual->buffer_idx - 1]);
		}
		break;

	case I2C_SLAVE_READ_PROCESSED:
		printk("dtwdebug[%s][%d]\n", __func__, __LINE__);
		virtual->buffer_idx++;
	case I2C_SLAVE_READ_REQUESTED:
		spin_lock(&virtual->buffer_lock);
		*val = virtual->buffer[virtual->buffer_idx & ADDRESS_MASK];
		spin_unlock(&virtual->buffer_lock);
		printk("dtwdebug[%s][%d] read %02x\n", __func__, __LINE__, *val);
		break;

	case I2C_SLAVE_STOP:
	case I2C_SLAVE_WRITE_REQUESTED:
		printk("dtwdebug[%s][%d]\n", __func__, __LINE__);
		virtual->idx_write_cnt = 0;
		break;

	default:
		break;
	}

	return 0;
}

static int i2c_slave_virtual_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct virtual_data *virtual;

	virtual = devm_kzalloc(&client->dev, sizeof(struct virtual_data) + ROM_SIZE, GFP_KERNEL);
	if (!virtual)
		return -ENOMEM;

	virtual->idx_write_cnt = 0;
	spin_lock_init(&virtual->buffer_lock);
	i2c_set_clientdata(client, virtual);

	i2c_slave_register(client, i2c_slave_virtual_slave_cb);

	return 0;
};

static int i2c_slave_virtual_remove(struct i2c_client *client)
{
	i2c_slave_unregister(client);

	return 0;
}

static const struct i2c_device_id i2c_slave_virtual_id[] = {
	{ "slave-virtual", (kernel_ulong_t)NULL },
	{ }
};
MODULE_DEVICE_TABLE(i2c, i2c_slave_virtual_id);

static struct i2c_driver i2c_slave_virtual_driver = {
	.driver = {
		.name = "i2c-slave-virtual",
	},
	.probe = i2c_slave_virtual_probe,
	.remove = i2c_slave_virtual_remove,
	.id_table = i2c_slave_virtual_id,
};

static int __init i2c_driver_virtual_slave_init(void)
{
	printk("%s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
	return i2c_add_driver(&i2c_slave_virtual_driver);
}
module_init(i2c_driver_virtual_slave_init);

static void __exit i2c_virtual_slave_exit(void)
{
	i2c_del_driver(&i2c_slave_virtual_driver);
}
module_exit(i2c_virtual_slave_exit);

MODULE_AUTHOR("www.dengtaowei.net");
MODULE_LICENSE("GPL");
