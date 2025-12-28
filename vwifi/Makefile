obj-m := simple_virt_wifi.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod simple_virt_wifi.ko

uninstall:
	sudo rmmod simple_virt_wifi