#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/usb.h>		// linux usb 
#include <linux/mutex.h>	// mutex
#include <linux/errno.h>	// error
#include <linux/slab.h>		// malloc/free
#include <linux/kref.h>		// kref
#include <linux/uaccess.h>	// memory access??

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hyejung Kwon");
MODULE_DESCRIPTION("a specific usb module driver for btree");

/* vendor/product id */
/* cypress vendor_id = 0x04B4, product_id = 0x00F0 */
/* artik board vendor_id = 0x04E8, product_id = 0x1234 */
#define USB_BTREE_VENDOR_ID      0x04B4
#define USB_BTREE_PRODUCT_ID     0x00F0

/* table of devices that work with this driver */
static const struct usb_device_id btree_table[] = {
	{ USB_DEVICE(USB_BTREE_VENDOR_ID, USB_BTREE_PRODUCT_ID) },
	{ }                                     /* Terminating entry */
};
MODULE_DEVICE_TABLE(usb, btree_table);


/* Get a minor range for your devices from the usb maintainer */
#define USB_BTREE_MINOR_BASE     0
#define USB_BTREE_CTL_TIMEOUT 100

#define WRITES_IN_FLIGHT	8

#define USB_CMD_DEVICE_INIT 0xD0
#define USB_CMD_MCU_HOLD 0xD1
#define USB_CMD_SET_SENSOR_ID  0xB0
#define USB_CMD_I2C_READ    0xB2
#define USB_CMD_I2C_WRITE   0xB1
#define USB_CMD_CAPTURE 0xB3
#define USB_CMD_I2C_WRITE_16    0xc4
#define USB_CMD_I2C_READ_16 0xc5

/* USB Control Message */
#define BTREE_USB_RET_SIZE 8 //64

struct usb_btree {
	struct	usb_device	*udev;
	struct	usb_interface	*interface;
	struct	semaphore	limit_sem;
	struct	usb_anchor	submitted;
	struct	urb	*bulk_in_urb;
	unsigned char	*bulk_in_buffer;
	size_t	bulk_in_size;
	size_t	bulk_in_filled;
	size_t	bulk_in_copied;
	__u8 bulk_in_endpointAddr;
	__u8 bulk_out_endpointAddr;
	int	errors;
	bool	ongoing_read;
	spinlock_t	err_lock;
	struct kref	kref;
	struct mutex	io_mutex;
	wait_queue_head_t	bulk_in_wait;
};

static struct usb_driver btree_driver;

struct usb_btree_io {
	unsigned int address;
	unsigned int data;
	int result;
	unsigned char *buf;
};

static void btree_read_bulk_callback(struct urb *urb)
{
	struct usb_btree * dev;

	dev = urb->context;

	spin_lock(&dev->err_lock);
	if(urb->status) {
		if (!(urb->status == -ENOENT ||
			urb->status == -ECONNRESET ||
			urb->status == -ESHUTDOWN))
				dev_err(&dev->interface->dev,
						"%s - nonzero write bulk status received: %d\n",
						__func__, urb->status);
		dev->errors = urb->status;
	} else {
		dev->bulk_in_filled = urb->actual_length;
	}
	dev->ongoing_read = 0;
	spin_unlock(&dev->err_lock);
	wake_up_interruptible(&dev->bulk_in_wait);

}


static int btree_recv_frame
	(struct usb_btree *dev, int count)
{
	int rv;

	usb_fill_bulk_urb(dev->bulk_in_urb,
					dev->udev,
					usb_rcvbulkpipe(dev->udev,
							dev->bulk_in_endpointAddr),
					dev->bulk_in_buffer,
					min(dev->bulk_in_size, count),
					btree_read_bulk_callback,
					dev);

	spin_lock_irq(&dev->err_lock);
	dev->ongoing_read = 1;
	spin_unlock_irq(&dev->err_lock);

	dev->bulk_in_filled = 0;
	dev->bulk_in_copied = 0;

	rv = usb_submit_urb(dev->bulk_in_urb, GFP_KERNEL);
	if (rv < 0) {
		dev_err(&dev->interface->dev,
				"%s - failed submitting read urb, error %d \n",
				__func__, rv);
		rv = (rv == -ENOMEM) ? rv : -EIO;
		spin_lock_irq(&dev->err_lock);
		dev->ongoing_read = 0;
		spin_unlock_irq(&dev->err_lock);
	}
	return rv;
}

static int btree_ctrl_msg
	(struct usb_btree *dev, int request, int dir,
	 int value, void *buf, int len)
{
	int retval = -1;

	retval = usb_control_msg(dev->udev,
			dir ? usb_rcvctrlpipe(dev->udev, 0) : usb_sndctrlpipe(dev->udev, 0),
			request, USB_TYPE_VENDOR | dir | USB_RECIP_DEVICE, value, 0x0, buf, len, USB_BTREE_CTL_TIMEOUT*5);

	dev_info(&dev->interface->dev,
			"[%s] : rq : 0x%02x dir : 0x%x value : 0x%x, len : %d result : %d \n",
			__func__, request, dir, value, len, retval);
	
	return retval = len ? 0 : retval;
}

static int btree_i2c_read
	(struct usb_btree *dev, int request,
	 int index, void *buf, int len)
{
	int retval = -1;
	retval = usb_control_msg(dev->udev, usb_rcvctrlpipe(dev->udev, 0),
			request, USB_TYPE_VENDOR | USB_DIR_IN | USB_RECIP_DEVICE,
			0, index, buf, len, USB_BTREE_CTL_TIMEOUT*10);
	
	dev_info(&dev->interface->dev,
			"[%s] : rq : 0x%02x address : 0x%4x result : %d \n",
			__func__, request, index, retval);
	
	return retval < 0 ? retval : 0;
}

static int btree_i2c_write
	(struct usb_btree *dev, int request, int value,
	 int index, void *buf, int len)
{
	int retval = -1;

	retval = usb_control_msg(dev->udev, usb_rcvctrlpipe(dev->udev, 0),
			request, USB_TYPE_VENDOR | USB_DIR_IN | USB_RECIP_DEVICE, 
			value, index, buf, len, USB_BTREE_CTL_TIMEOUT*10);
	
	dev_info(&dev->interface->dev,
			"[%s] : rq : 0x%02x address : 0x%4x value : 0x%x len : %d result : %d \n",
			__func__, request, index, value, len, retval);
	
	return retval < 0 ? retval : 0;
}

static void btree_delete(struct kref *kref)
{
	struct usb_btree *dev = container_of(kref, struct usb_btree, kref);

	usb_free_urb(dev->bulk_in_urb);
	usb_put_dev(dev->udev);
	kfree(dev->bulk_in_buffer);
	kfree(dev);
}

static ssize_t btree_read(struct file *file, char *buffer, size_t count,
						loff_t *ppos)
{
	struct usb_btree *dev;
	int rv;
	bool ongoing_io;

	dev = file->private_data;

	dev_info(&dev->interface->dev, "[%s]buffer:0x%x,count:%d \n",__func__,buffer,count);

	if (!dev->bulk_in_urb || !count)
		return 0;

	rv = mutex_lock_interruptible(&dev->io_mutex);
	if (rv < 0)
		return rv;
	if (!dev->interface) {
		rv = -ENODEV;
		goto exit;
	}

retry: 
	spin_lock_irq(&dev->err_lock);
	ongoing_io = dev->ongoing_read;
	spin_unlock_irq(&dev->err_lock);

	if (ongoing_io) {
		if (file->f_flags & O_NONBLOCK) {
			rv = -EAGAIN;
			goto exit;
		}

		rv = wait_event_interruptible(dev->bulk_in_wait, (!dev->ongoing_read));
		if (rv < 0)
			goto exit;
	}
	rv = dev->errors;
	if (rv < 0) {
		dev->errors = 0;
		rv = (rv == -EPIPE) ? rv : -EIO;
		goto exit;
	}

	if (dev->bulk_in_filled) {
		size_t available = dev->bulk_in_filled - dev->bulk_in_copied;
		size_t chunk = min(available, count);

		if (!available) {
			rv = btree_recv_frame(dev, count);
			if ( rv < 0)
				goto exit;
			else
				goto retry;
		}
		if (copy_to_user(buffer,
						dev->bulk_in_buffer + dev->bulk_in_copied,
						chunk))
			rv = -EFAULT;
		else
			rv = chunk;

		dev->bulk_in_copied += chunk;

		if (available < count)
			btree_recv_frame(dev, count - chunk);
	} else {
		rv = btree_recv_frame(dev, count);
		if (rv < 0)
			goto exit;
		else
			goto retry;
	}

exit:
	mutex_unlock(&dev->io_mutex);
	return rv;
}

static ssize_t btree_write(struct file *file, const char *user_buffer,
						size_t count, loff_t *ppos)
{
	struct usb_btree *dev;

	dev = file->private_data;

	dev_info(&dev->interface->dev, " %s \n",__func__);
	return 1;
}
/* control transfer */
/* direction - 0: host->device, 1: device -> host */
/* request type - 0x2[vendor request] */
/* receptionist - 0[device] */
static int btree_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct usb_btree *dev = file->private_data;
	int retval = 0;
	unsigned char buf[BTREE_USB_RET_SIZE];
	struct usb_btree_io io_data;

	dev_info(&dev->interface->dev,
			"ioctl : cmd = 0x%x, arg = 0x%x \n",
			cmd, arg);

	switch (cmd) {
		case USB_CMD_DEVICE_INIT:
			dev_info(&dev->interface->dev, "USB_CMD_DEVICE_INIT\n");
			memcpy(&io_data, (void *) arg, sizeof(struct usb_btree_io));
			dev_info(&dev->interface->dev, "address = 0x%x, data = 0x%x, buf = 0x%x \n",
					io_data.address, io_data.data, io_data.buf);
			retval = btree_ctrl_msg(dev, cmd, USB_DIR_IN, 0, buf, BTREE_USB_RET_SIZE);
			if (!retval) {
				dev_info(&dev->interface->dev,
						"device vendor string is %s \n",
						buf);
				memset(io_data.buf, 0x0, sizeof(io_data.buf));
				memcpy(io_data.buf, buf, sizeof(io_data.buf));
				if (copy_to_user((void __user *) arg,
								&io_data,
								sizeof(struct usb_btree_io))) {
					retval = -EFAULT;
				}
			}
			break;
		case USB_CMD_SET_SENSOR_ID:
			memcpy(&io_data, (void *) arg, sizeof(struct usb_btree_io));
			dev_info(&dev->interface->dev,
					"USB_CMD_SET_SENSOR_ID : 0x%x, address : 0x%x \n", io_data.data, io_data.address);
			retval = btree_ctrl_msg(dev, cmd, USB_DIR_IN, io_data.data, buf, BTREE_USB_RET_SIZE);
			if (!retval) { // success
				memset(&io_data, 0x0, sizeof(struct usb_btree_io));
				io_data.data = (uint8_t)(buf[0] & 0x00FF);
				dev_info(&dev->interface->dev,
					"USB_CMD_SET_SENSOR_ID : 0x%x \n", io_data.data);
				if (copy_to_user((void __user *) arg,
								&io_data,
								sizeof(struct usb_btree_io))) {
					retval = -EFAULT;
				}
			}
			break;
		case USB_CMD_MCU_HOLD: 
			memcpy(&io_data, (void *) arg, sizeof(struct usb_btree_io));
			dev_info(&dev->interface->dev,
					"USB_CMD_MCU_HOLD : 0x%x\n", io_data.data);
			retval = btree_ctrl_msg(dev, cmd, USB_DIR_IN, io_data.data, buf, BTREE_USB_RET_SIZE);
			if (!retval) { // success
				memset(&io_data, 0x0, sizeof(struct usb_btree_io));
				io_data.result = buf[0];
				dev_info(&dev->interface->dev,
					"USB_CMD_MCU_HOlD : %s \n", io_data.result ? "Success" : "Fail");
				if (copy_to_user((void __user *) arg,
								&io_data,
								sizeof(struct usb_btree_io))) {
					retval = -EFAULT;
				}
			}
			break;
		//case USB_CMD_I2C_READ:
		case USB_CMD_I2C_READ_16:
			dev_info(&dev->interface->dev, "USB_CMD_I2C_READ\n");
			memcpy(&io_data, (void *) arg, sizeof(struct usb_btree_io));
			dev_info(&dev->interface->dev, "address = 0x%x, data = 0x%4x, buf = 0x%x \n",
					io_data.address, io_data.data, io_data.buf);
			retval = btree_i2c_read(dev, cmd, io_data.address, buf, BTREE_USB_RET_SIZE);
			if (!retval) {
				dev_info(&dev->interface->dev, "result = %d, data = 0x%4x \n", buf[4], ((buf[0]<<8)+buf[1]));
				io_data.result = buf[4];
				io_data.data = ((buf[0]<<8)+buf[1]);
				if (copy_to_user((void __user *) arg,
								&io_data,
								sizeof(struct usb_btree_io))) {
					retval = -EFAULT;
				}
			}
			break;
		//case USB_CMD_I2C_WRITE:
		case USB_CMD_I2C_WRITE_16:
			printk("USB_CMD_I2C_WRITE \n");
			dev_info(&dev->interface->dev, "USB_CMD_I2C_WRITE\n");
			memcpy(&io_data, (void *) arg, sizeof(struct usb_btree_io));
			dev_info(&dev->interface->dev, "address = 0x%x, data = 0x%2x, buf = 0x%x \n",
					io_data.address, io_data.data, io_data.buf);
			retval = btree_i2c_write(dev, cmd, io_data.data, io_data.address, buf, BTREE_USB_RET_SIZE);
			if (!retval) {
				dev_info(&dev->interface->dev, "result = %d \n", buf[0]);
				io_data.result = buf[0];
				if (copy_to_user((void __user *) arg,
								&io_data,
								sizeof(struct usb_btree_io))) {
					retval = -EFAULT;
				}
			}
			break;
		case USB_CMD_CAPTURE:
			dev_info(&dev->interface->dev, "USB_CMD_CAPTURE\n");
			memcpy(&io_data, (void *) arg, sizeof(struct usb_btree_io));
			dev_info(&dev->interface->dev, "address = 0x%x, data = 0x%x, buf = 0x%x \n",
					io_data.address, io_data.data, io_data.buf);
			retval = btree_ctrl_msg(dev, cmd, USB_DIR_IN, io_data.data, buf, BTREE_USB_RET_SIZE);
			if (!retval) {
				io_data.result = buf[0];
				if (copy_to_user((void __user *) arg,
								&io_data,
								sizeof(struct usb_btree_io))) {
					retval = -EFAULT;
				}
			}
			break;
		default:
			printk(" not supported : 0x%x \n",cmd);
			break;
	}
	return retval;
}

static int btree_open(struct inode *inode, struct file *file)
{
	struct usb_btree *dev;
	struct usb_interface *interface;
	int subminor;
	int retval = 0;

	printk("[%s]\n",__func__);
	
	subminor = iminor(inode);
	printk("[%s] subminor - %d \n",
			__func__, subminor);
	
	interface = usb_find_interface(&btree_driver, subminor);
	if(!interface) {
		dev_err(&interface->dev, "%s - error, can't find device for minor %d \n",
				__func__, subminor);
		retval = -ENODEV;
		goto exit;
	}
	dev_info(&interface->dev, "%s - find device for minor %d \n",
			__func__, subminor);

	dev = usb_get_intfdata(interface);
	if( !dev) {
		retval = -ENODEV;
		goto exit;
	}
	
#if 0
	retval = usb_autopm_get_interface(interface);
	if(retval < 0) {
		dev_err(&interface->dev, "%s - error, can't get interface  %d \n",
				__func__, subminor);
		retval = -ENODEV;
		goto exit;
	}
#endif
	kref_get(&dev->kref);
	file->private_data = dev;

exit:
	return retval;
}

static int btree_release(struct inode *inode, struct file *file)
{
	struct usb_btree *dev;

	printk("%s",__func__);
	
	dev = file->private_data;
	if (dev == NULL)
		return -ENODEV;

	dev_info(&dev->interface->dev, "%s - close %d device \n",
			__func__, iminor(inode));
#if 0
	mutex_lock(&dev->io_mutex);
	if (dev->interface)
		usb_autopm_put_interface(dev->interface);
	mutex_unlock(&dev->io_mutex);
#endif	
	kref_put(&dev->kref, btree_delete);

	return 0;
}

static const struct file_operations btree_fops = {
	.owner = THIS_MODULE,
	.read = btree_read,
	.write = btree_write,
	.unlocked_ioctl = btree_ioctl,
	.open = btree_open,
	.release = btree_release,
};

/*
 * usb class driver info in order to get a minor number from the usb core,
 * and to have the device registered with the driver core
*/
static struct usb_class_driver btree_class = {
	        .name =         "btree%d",
			.fops =         &btree_fops,
			.minor_base =   USB_BTREE_MINOR_BASE,
};

static int btree_probe (struct usb_interface *interface,
						const struct usb_device_id *id)
{
	struct usb_host_interface *iface_desc;
	struct usb_endpoint_descriptor *endpoint;
	struct usb_btree *dev;
	size_t buffer_size;
	int i;
	int retval = -ENOMEM;

	dev_info(&interface->dev, "btree_probe \n");
	dev = kzalloc(sizeof(struct usb_btree), GFP_KERNEL);
	if (!dev) {
		dev_err(&interface->dev, "Out of memory \n");
		retval = - ENOMEM;
		goto error;
	}
	kref_init(&dev->kref);
	sema_init(&dev->limit_sem, WRITES_IN_FLIGHT);
	mutex_init(&dev->io_mutex);
	spin_lock_init(&dev->err_lock);
	init_usb_anchor(&dev->submitted);
	init_waitqueue_head(&dev->bulk_in_wait);

	dev->udev = usb_get_dev(interface_to_usbdev(interface));
	dev->interface = interface;

	dev_info(&interface->dev,
			" Device Information \n");
	dev_info(&interface->dev,
			" Vendor ID = 0x%x \n",
			dev->udev->descriptor.idVendor);
	dev_info(&interface->dev,
			" Product ID = 0x%x \n",
			dev->udev->descriptor.idProduct);
	dev_info(&interface->dev,
			" Manufacturer = 0x%x \n",
			dev->udev->descriptor.iManufacturer);
	dev_info(&interface->dev,
			" Class = 0x%x \n",
			dev->udev->descriptor.bDeviceClass);
	dev_info(&interface->dev,
			" SubClass = 0x%x \n",
			dev->udev->descriptor.bDeviceSubClass);
	dev_info(&interface->dev,
			" Protocol = 0x%x \n",
			dev->udev->descriptor.bDeviceProtocol);

	iface_desc = interface->cur_altsetting;
	for (i=0; i < iface_desc->desc.bNumEndpoints; ++i) {
		endpoint = &iface_desc->endpoint[i].desc;

		if (!dev->bulk_in_endpointAddr &&
			usb_endpoint_is_bulk_in(endpoint)) {
				buffer_size = usb_endpoint_maxp(endpoint);
				dev->bulk_in_size = buffer_size;
				dev->bulk_in_endpointAddr = endpoint->bEndpointAddress;
				dev_info(&interface->dev,
						" [BulkInEndpoint:0x%x] max size = %d \n",
						dev->bulk_in_endpointAddr,
						dev->bulk_in_size);
				dev->bulk_in_buffer = kmalloc(buffer_size, GFP_KERNEL);
				if (!dev->bulk_in_buffer) {
					dev_err(&interface->dev,
							"Could not allocate bulk_in_buffer \n");
					goto error;
				}
				dev->bulk_in_urb = usb_alloc_urb(0, GFP_KERNEL);
				if (!dev->bulk_in_urb) {
					dev_err(&interface->dev,
							"Could not allocate bulk_in_urb \n");
					goto error;
				}
		}

		if (!dev->bulk_out_endpointAddr &&
			usb_endpoint_is_bulk_out(endpoint)) {
			dev->bulk_out_endpointAddr = endpoint->bEndpointAddress;
			dev_info(&interface->dev,
					" [BulkOutEndpoint:0x%x] max size = %d \n",
					dev->bulk_out_endpointAddr,
					usb_endpoint_maxp(endpoint));
		}
	}

	usb_set_intfdata(interface, dev);

	retval = usb_register_dev(interface, &btree_class);
	if (retval) {
		dev_err(&interface->dev,
				"Not able to get a minor for this device \n");
		usb_set_intfdata(interface, NULL);
		goto error;
	}

	dev_info(&interface->dev,
			"USB btree device is now attached to busb%d",
			interface->minor);

	return 0;

error:
	dev_err(&interface->dev, "error\n");
	if (dev)
		kref_put(&dev->kref, btree_delete);

	return retval;
}

static void btree_disconnect(struct usb_interface *interface)
{
	struct usb_btree *dev;

	dev_info(&interface->dev, "USB device is ditached %d \n", interface->minor);
	
	dev = usb_get_intfdata(interface);
	usb_set_intfdata(interface, NULL);

	usb_deregister_dev(interface, &btree_class);

	mutex_lock(&dev->io_mutex);
	dev->interface = NULL;
	mutex_unlock(&dev->io_mutex);

	usb_kill_anchored_urbs(&dev->submitted);

	kref_put(&dev->kref, btree_delete);
}

static struct usb_driver btree_driver = {
		.name = "btree",
		.probe =	btree_probe,
		.disconnect = btree_disconnect,
		.id_table = btree_table,
};

#if 1
module_usb_driver(btree_driver);
#else
static int __init btree_driver_init(void)
{
	int result;

	printk(KERN_INFO "btree driver module init\n");
	/* register this driver with the USB subsystem */
	result = usb_register(&btree_driver);
	if (result < 0) {
		printk("usb_register failed. Error number %d \n", result);
		return -1;
	}
	return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit btree_driver_exit(void)
{
	printk(KERN_INFO "Cleaning up btree driver module.\n");
	usb_deregister(&btree_driver);
}
module_init(btree_driver_init);
module_exit(btree_driver_exit);
#endif

