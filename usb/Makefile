obj-m += usb-btree.o
 
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules
	#make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean
	#make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

