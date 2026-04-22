# export ARCH=arm
# CROSS_COMPILE=arm-linux-gnueabi-
# export CROSS_COMPILE
# CC=arm-linux-gnueabi-gcc
# export CC

obj-m := deferred_io.o
# obj-m += deferio.o
KDIR := /home/book/100ask_stm32mp157_pro-sdk/Linux-5.4
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	$(CROSS_COMPILE)gcc deferred_io_app.c -o deferred_io_app

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm deferred_io_app

