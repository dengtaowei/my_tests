KERN_DIR = your kernel dir

all:
	make -C $(KERN_DIR) M=`pwd` modules 

clean:
	make -C $(KERN_DIR) M=`pwd` modules clean
	rm -rf modules.order

obj-m	+= i2c_adapter_drv.o
obj-m   += i2c_slave.o
