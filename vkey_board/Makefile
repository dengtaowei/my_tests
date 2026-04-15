obj-m := virt_input_drv.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	gcc virt_input_app.c -o virt_input_app

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm virt_input_app

install:
	sudo insmod simple_virt_wifi.ko

uninstall:
	sudo rmmod simple_virt_wifi