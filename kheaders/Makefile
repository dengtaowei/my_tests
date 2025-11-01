# 确保你已经安装了必要的内核头文件
# sudo apt install linux-headers-$(uname -r)

# 设置内核源码目录（Ubuntu 22.04通常使用这个路径）
KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# 模块名称
MODULE_NAME = struct_offset_printer
obj-m := $(MODULE_NAME).o

# 源文件
SRC := $(MODULE_NAME).c

all: modules

modules:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	rm -f *.o *.mod.c Module.symvers modules.order

install: modules
	sudo insmod $(MODULE_NAME).ko

uninstall:
	sudo rmmod $(MODULE_NAME) || true

log:
	dmesg | grep "STRUCT_" || echo "No structure offset messages found"

.PHONY: all modules clean install uninstall log