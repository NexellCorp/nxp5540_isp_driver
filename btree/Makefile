obj-m += btree.o
#btree-objs := videobuf2-core.o videobuf2-v4l2.o videobuf2-dma-contig.o btree-v4l2.o btree-usb.o
#btree-objs := v4l2-device.o videobuf2-dma-contig.o btree-v4l2.o btree-usb.o
btree-objs := v4l2-ioctl.o videobuf2-dma-contig.o btree-v4l2.o btree-usb.o
#btree-objs := btree-v4l2.o btree-usb.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules
	#-L /usr/include/
	#make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	#make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean
