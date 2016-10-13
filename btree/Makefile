#obj-m += btree-v4l2.o
#obj-m += btree-usb.o
obj-m += btree.o
#obj-m += v4l2-ioctl.o
btree-objs := btree-v4l2.o btree-usb.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

