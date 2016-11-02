/*
 * Copyright (C) 2016  Nexell Co., Ltd.
 * Author: Hyejung Kwon <cjscld15@nexell.co.kr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>    /* included for all kernel modules */
#include <linux/kernel.h>    /* included for KERN_INFO */
#include <linux/init.h>      /* included for __init and __exit macros */
#include <linux/usb.h>		/* linux usb */

/* temporary for usb_hcd_submit_urb */
#include <linux/usb/hcd.h>

#include <linux/mutex.h>	/* mutex */
#include <linux/errno.h>	/* error */
#include <linux/slab.h>		/* malloc/free */
#include <linux/kref.h>		/* kref */
#include <linux/uaccess.h>	/* memory access?? */

/* v4l2 */
#include <linux/videodev2.h>
#include <media/v4l2-device.h>
#include <media/videobuf2-dma-contig.h>
#include "btree-v4l2.h"

#include "btree-usb.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hyejung Kwon");
MODULE_DESCRIPTION("a specific usb module driver for btree");

/* vendor/product id */
/* cypress vendor_id = 0x04B4, product_id = 0x00F0 */
/* artik board vendor_id = 0x04E8, product_id = 0x1234 */
#define BTREE_USB_VENDOR_ID      0x04B4
#define BTREE_USB_PRODUCT_ID     0x00F0

/* table of devices that work with this driver */
static const struct usb_device_id btree_table[] = {
	{ USB_DEVICE(BTREE_USB_VENDOR_ID, BTREE_USB_PRODUCT_ID) },
	{ }                                     /* Terminating entry */
};
MODULE_DEVICE_TABLE(usb, btree_table);


#define BTREE_V4L2_DEV_NAME	"btree-v4l2"
#define BTREE_V4L2_VIDEO_NAME "btree-video"
#define BTREE_USB_MINOR_BASE     0
#define BTREE_USB_CTL_TIMEOUT 100

#define WRITES_IN_FLIGHT	8

#define USB_CMD_DEVICE_INIT 0xD0
#define USB_CMD_MCU_HOLD 0xD1
#define USB_CMD_SET_SENSOR_ID  0xB0
#define USB_CMD_I2C_READ    0xB2
#define USB_CMD_I2C_WRITE   0xB1
#define USB_CMD_CAPTURE 0xB3
#define USB_CMD_I2C_WRITE_16    0xc4
#define USB_CMD_I2C_READ_16 0xc5

#define BTREE_USB_RET_SIZE 8 //64
#define BTREE_SENSOR_ID 0x82

#define BTREE_MAX_PAGE_NUM 4
/* structures */
struct btree_usb {
	struct  usb_device  *udev;
	struct  v4l2_device v4l2_dev;
	struct  btree_video *vdev;
	void *alloc_ctx;
	struct  usb_interface   *interface;
	struct  usb_anchor  submitted;
	struct  urb *bulk_in_urb;
	unsigned char   *bulk_in_buffer;
	size_t  bulk_in_size;
	size_t  bulk_in_filled;
	size_t  bulk_in_copied;
	__u8 bulk_in_endpointAddr;
	__u8 bulk_out_endpointAddr;
	int errors;
	bool    ongoing_read;
	spinlock_t  err_lock;
	struct kref kref;
	wait_queue_head_t   bulk_in_wait;
};

struct btree_usb_io {
	unsigned int address;
	unsigned int data;
	int result;
	unsigned char *buf;
};

/* function definition */
static int btree_recv_frame(struct btree_usb *dev, bool dma_flag,
							dma_addr_t buffer, int count);

/* functions related to v4l2 registraion */
static int register_v4l2(struct btree_usb *dev)
{
	struct btree_video *vdev = NULL;
	struct v4l2_device *v4l2_dev = NULL;
	int ret = -1;

	dev->alloc_ctx = vb2_dma_contig_init_ctx(&dev->udev->dev);
	if (!dev->alloc_ctx ) {
		dev_err(&dev->udev->dev, "failed to get memory for ctx \n");
		return ret;
	}

	v4l2_dev = &dev->v4l2_dev;
	snprintf(v4l2_dev->name, sizeof(v4l2_dev->name), "%s",
			BTREE_V4L2_DEV_NAME/*dev_name(&dev->udev->dev)*/);
	ret = btree_v4l2_register_device(&dev->udev->dev, &dev->v4l2_dev);
	if (ret < 0) {
		dev_err(&dev->udev->dev, "failed to register btree device as v4l2 device");
		return ret;
	}

	vdev = btree_video_create(BTREE_V4L2_VIDEO_NAME/*v4l2_dev->name*/,
							BTREE_VIDEO_TYPE_CAPTURE, &dev->v4l2_dev, dev->alloc_ctx);
	if (!vdev) {
		dev_err(&dev->udev->dev, "failed to create btree video \n");
		return -1;
	}
	vdev->priv = dev;
	dev->vdev = vdev;
	return 0;
}

static void unregister_v4l2(struct btree_usb *dev)
{
	pr_debug("%s", __func__);
	if (dev->vdev) {
		dev->vdev->priv = NULL;
		btree_video_cleanup(dev->vdev);
		dev->vdev = NULL;
	}
	btree_v4l2_unregister_device(&dev->v4l2_dev);
	if (dev->alloc_ctx) {
		vb2_dma_contig_cleanup_ctx(dev->alloc_ctx);
		dev->alloc_ctx = NULL;
	}
}

static void btree_read_bulk_callback(struct urb *urb)
{
	struct btree_usb * dev = NULL;

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
		dev->bulk_in_filled += urb->actual_length;
	}
	dev->ongoing_read = 0;
	spin_unlock(&dev->err_lock);
	wake_up_interruptible(&dev->bulk_in_wait);
}

/*
 * dma_flag
 * - 1 : use dma transfer
 * - 0 : normal transfer
 */
static int btree_recv_frame
	(struct btree_usb *dev, bool dma_flag,
	 dma_addr_t buffer, int count)
{
	int rv;
	struct urb *urb = dev->bulk_in_urb;
	urb->dev = dev->udev;
	urb->pipe = usb_rcvbulkpipe(dev->udev,
					dev->bulk_in_endpointAddr);
	if (dma_flag) {
		urb->transfer_dma = buffer;
		urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
	} else {
		urb->transfer_flags &= ~(URB_NO_TRANSFER_DMA_MAP);
		urb->transfer_buffer = dev->bulk_in_buffer;
	}
	urb->transfer_buffer_length = min(dev->bulk_in_size, count);
	urb->complete = btree_read_bulk_callback;
	urb->context = dev;
	spin_lock_irq(&dev->err_lock);
	dev->ongoing_read = 1;
	spin_unlock_irq(&dev->err_lock);
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
	(struct btree_usb *dev, int request, int dir,
	 int value, void *buf, int len)
{
	int retval = -1;

	retval = usb_control_msg(dev->udev,
			dir ? usb_rcvctrlpipe(dev->udev, 0) : usb_sndctrlpipe(dev->udev, 0),
			request, USB_TYPE_VENDOR | dir | USB_RECIP_DEVICE,
			value, 0x0, buf, len, BTREE_USB_CTL_TIMEOUT*5);

	dev_info(&dev->interface->dev,
			"[%s] : rq : 0x%02x dir : 0x%x value : 0x%x, len : %d result : %d \n",
			__func__, request, dir, value, len, retval);
	return retval = len ? 0 : retval;
}

static int btree_i2c_read
	(struct btree_usb *dev, int request,
	 unsigned int index, void *buf, int len)
{
	int retval = -1;
	retval = usb_control_msg(dev->udev, usb_rcvctrlpipe(dev->udev, 0),
			request, USB_TYPE_VENDOR | USB_DIR_IN | USB_RECIP_DEVICE,
			0, index, buf, len, BTREE_USB_CTL_TIMEOUT*10);
	dev_info(&dev->interface->dev,
			"[%s] : rq : 0x%02x address : 0x%4x result : %d \n",
			__func__, request, index, retval);
	return retval < 0 ? retval : 0;
}

static int btree_i2c_write
	(struct btree_usb *dev, int request, unsigned int value,
	 unsigned int index, void *buf, int len)
{
	int retval = -1;

	retval = usb_control_msg(dev->udev, usb_rcvctrlpipe(dev->udev, 0),
			request, USB_TYPE_VENDOR | USB_DIR_IN | USB_RECIP_DEVICE,
			value, index, buf, len, BTREE_USB_CTL_TIMEOUT*10);
	dev_info(&dev->interface->dev,
			"[%s] : rq : 0x%02x address : 0x%4x value : 0x%x len : %d result : %d \n",
			__func__, request, index, value, len, retval);
	return retval < 0 ? retval : 0;
}

/* ioctls function for v4l2 */
unsigned int btree_read_reg(
void *priv, unsigned int address)
{
	int ret = -ENODEV;
	unsigned char buf[BTREE_USB_RET_SIZE] = {0, };
	unsigned int addr_h = 0, addr_l = 0;
	unsigned int data_h =0, data_l = 0, data = 0;
	struct btree_usb *udev = priv;

	dev_info(&udev->interface->dev,
			"[%s] \n", __func__);

	addr_h = ((address >> 7) & 0x01FE);
	addr_l = ((address << 1) & 0x01FE) | 0x0200;
	dev_info(&udev->interface->dev,
			"addr = 0x%4x, addr_l = 0x%2x, addr_h = 0x%2x\n",
			address, addr_l, addr_h);
	ret = btree_ctrl_msg(udev, USB_CMD_MCU_HOLD,
						USB_DIR_IN, 1,
						buf, BTREE_USB_RET_SIZE);
	if (ret) {
		dev_err(&udev->interface->dev,
				" failed to hold mcu \n");
		return ret;
	}

	ret = btree_i2c_read(udev, USB_CMD_I2C_READ_16,
						addr_h, buf,
						BTREE_USB_RET_SIZE);
	if (ret) {
		dev_err(&udev->interface->dev,
				" failed to read register\n");
		return ret;
	}
	printk("result = %d, data = 0x%4x \n",
			buf[4], ((buf[0]<<8)+buf[1]));
	ret = btree_i2c_read(udev, USB_CMD_I2C_READ_16,
						addr_l, buf,
						BTREE_USB_RET_SIZE);
	if (ret) {
		dev_err(&udev->interface->dev,
				"failed to read register\n");
		return ret;
	}
	data_h = ((buf[0]<<8)+buf[1]);
	dev_info(&udev->interface->dev,
			"result = %d, data = 0x%4x \n",
			buf[4], data_h);
	ret = btree_i2c_read(udev, USB_CMD_I2C_READ_16,
						addr_l, buf,
						BTREE_USB_RET_SIZE);
	if (ret) {
		dev_err(&udev->interface->dev,
				" failed to read register\n");
		return ret;
	}
	data_l = ((buf[0]<<8)+buf[1]);
	dev_info(&udev->interface->dev,
			"result = %d, data = 0x%4x \n",
			buf[4], data_l);

	data = ((data_h << 16) | data_l);
	dev_info(&udev->interface->dev,
			" data = 0x%x \n", data);

	ret = btree_ctrl_msg(udev, USB_CMD_MCU_HOLD,
						USB_DIR_IN, 0,
						buf, BTREE_USB_RET_SIZE);
	if (ret) {
		dev_err(&udev->interface->dev,
				" failed to release mcu \n");
		return ret;
	}

	return data;
}

int btree_write_reg(void *priv,
unsigned int address, unsigned int data)
{
	int ret = -ENODEV;
	unsigned char buf[BTREE_USB_RET_SIZE] = {0, };
	unsigned int addr_h = 0, addr_l = 0;
	unsigned int data_h =0, data_l = 0;
	struct btree_usb *udev = priv;
	unsigned int page_num = (address >> 12) & 0xF;

	dev_info(&udev->interface->dev,
			"[%s] page num = %d \n",
			__func__, page_num);
	if (page_num > BTREE_MAX_PAGE_NUM) {
		data_h = data;
		addr_h = (address & 0x0FFF);
	} else {
		data_h = (( data >> 16) & 0xFFFF );
		data_l = (data&0xFFFF);

		addr_h = ((address >> 7) & 0x01FE);
		addr_l = ((address << 1) & 0x01FE) | 0x0200;
	}
	ret = btree_ctrl_msg(udev, USB_CMD_MCU_HOLD,
						USB_DIR_IN, 1,
						buf, BTREE_USB_RET_SIZE);
	if (ret) {
		dev_err(&udev->interface->dev, "failed to hold mcu \n");
		return ret;
	}
	ret = btree_i2c_write(udev, USB_CMD_I2C_WRITE_16,
						data_h, addr_h,
						buf, BTREE_USB_RET_SIZE);
	if (ret) {
		dev_err(&udev->interface->dev, "failed to read register\n");
		goto done;
	}
	if (page_num > BTREE_MAX_PAGE_NUM)
		goto done;
	ret = btree_i2c_write(udev, USB_CMD_I2C_WRITE_16,
						data_l, addr_l,
						buf, BTREE_USB_RET_SIZE);
	if (ret) {
		dev_err(&udev->interface->dev, "failed to read register\n");
		goto done;
	}
done:
	ret = btree_ctrl_msg(udev, USB_CMD_MCU_HOLD,
						USB_DIR_IN, 0,
						buf, BTREE_USB_RET_SIZE);
	if (ret) {
		dev_err(&udev->interface->dev, "failed to release mcu \n");
		return ret;
	}

	return ret;
}

int btree_check_device(void *priv)
{
	int ret = -ENODEV;
	unsigned char buf[BTREE_USB_RET_SIZE] = {0, };
	struct btree_usb *dev = priv;
	dev_info(&dev->interface->dev, "[%s] \n", __func__);

	ret = btree_ctrl_msg(dev, USB_CMD_DEVICE_INIT,
						USB_DIR_IN, 0,
						buf, BTREE_USB_RET_SIZE);
	if (ret) {
		dev_err(&dev->interface->dev, "failed to btree usb device init \n");
		return ret;
	}
	printk(" vendor string is %s \n", buf);
	ret = btree_ctrl_msg(dev, USB_CMD_SET_SENSOR_ID,
						USB_DIR_IN, BTREE_SENSOR_ID,
						buf, BTREE_USB_RET_SIZE);
	if (ret) {
		dev_err(&dev->interface->dev, " failed to set sensor ID \n");
		return ret;
	}
	dev_info(&dev->interface->dev,
			" sensor id is 0x%x \n", (buf[0] & 0x00FF) );
	return ret;
}

int btree_capture_enable(
void *priv, int enable)
{
	struct btree_usb *dev = priv;
	int ret = -EFAULT;
	unsigned char buf[BTREE_USB_RET_SIZE] = {0, };
	dev_info(&dev->interface->dev, " %s - %s \n", __func__,
			(enable)?"enable":"disable");

	ret = btree_ctrl_msg(dev, USB_CMD_CAPTURE,
						USB_DIR_IN, enable,
						buf, BTREE_USB_RET_SIZE);
	if (ret) {
		dev_err(&dev->interface->dev,
				" failed to change capture status to %d \n", enable);
		return ret;
	}
	dev_info(&dev->interface->dev,
			"changing capture status is %s \n", (buf[0])?"succeed":"failed");
	if (!buf[0])
		ret = -EFAULT;

	return ret;
}
/* end of ioctls for v4l2 */

static void btree_delete(struct kref *kref)
{
	struct btree_usb *dev = container_of(kref, struct btree_usb, kref);

	pr_debug("[%s] \n", __func__);
	usb_free_urb(dev->bulk_in_urb);
	usb_put_dev(dev->udev);
	kfree(dev->bulk_in_buffer);
	kfree(dev);
}

ssize_t btree_read_frame
(void *priv, dma_addr_t buffer, size_t count)
{
	struct btree_usb *dev = priv;
	int rv = 0;
	bool ongoing_io = 0;
	size_t available = 0;

	if (!dev->bulk_in_urb || !count)
		return 0;

	if (!dev->interface) {
		rv = -ENODEV;
		goto exit;
	}
	dev->bulk_in_copied = 0;
	dev->bulk_in_filled = 0;
retry:
	spin_lock_irq(&dev->err_lock);
	ongoing_io = dev->ongoing_read;
	spin_unlock_irq(&dev->err_lock);

	if(ongoing_io) {
		rv = wait_event_interruptible(dev->bulk_in_wait,
									(!dev->ongoing_read));
		if (rv < 0) {
			dev_err(&dev->interface->dev, "wait interrupt fail %d \n",
					ongoing_io);
			goto exit;
		}
	}
	rv = dev->errors;
	if (rv < 0) {
		dev->errors = 0;
		rv = (rv == -EPIPE) ? rv : -EIO;
		goto exit;
	}
	if (dev->bulk_in_filled) {
		available = dev->bulk_in_filled - dev->bulk_in_copied;
		/*
		   dev_info(&dev->interface->dev,
				"filled:%d, copied:%d,bufsize:%d \n",
				dev->bulk_in_filled, dev->bulk_in_copied, count);
		*/
		if (!available) {
			rv = btree_recv_frame(dev, 1,
								buffer + dev->bulk_in_copied,
								count - dev->bulk_in_copied);
			if ( rv < 0)
				goto exit;
			else
				goto retry;
		}
		dev->bulk_in_copied += available;

		if (dev->bulk_in_copied < count) {
			rv = btree_recv_frame(dev, 1,
								buffer + dev->bulk_in_copied,
								count - dev->bulk_in_copied);
			if (rv < 0)
				goto exit;
			else
				goto retry;
		}
	} else {
		rv = btree_recv_frame(dev, 1, buffer, count);
		if (rv < 0)
			goto exit;
		else
			goto retry;
	}
exit:
	if (rv < 0)
		dev_info(&dev->interface->dev,
			"ret:%d, filled:%d, copied:%d,bufsize:%d \n",
			rv, dev->bulk_in_filled, dev->bulk_in_copied, count);

	return rv;
}

static ssize_t btree_read(struct file *file, char *buffer, size_t count,
						loff_t *ppos)
{
	struct btree_usb *dev = NULL;
	int rv = 0;
	bool ongoing_io = 0;
	size_t available = 0;
	dev = file->private_data;

	dev_info(&dev->interface->dev,
			"[%s]buffer:0x%x,count:%d \n",
			__func__, buffer, count);

	if (!dev->bulk_in_urb || !count)
		return 0;

	if (!dev->interface) {
		rv = -ENODEV;
		goto exit;
	}

	dev->bulk_in_copied = 0;
	dev->bulk_in_filled = 0;
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
		available = dev->bulk_in_filled - dev->bulk_in_copied;

		if (!available) {
			rv = btree_recv_frame(dev, 0, 0, count);
			if ( rv < 0)
				goto exit;
			else
				goto retry;
		}
		if (copy_to_user(buffer + dev->bulk_in_copied,
						dev->bulk_in_buffer,
						available))
			rv = -EFAULT;
		else
			rv = available;

		dev->bulk_in_copied += available;

		if (dev->bulk_in_copied < count) {
			rv = btree_recv_frame(dev, 0, 0,
								count - dev->bulk_in_copied);
			if (rv < 0)
				goto exit;
			else
				goto retry;
		}
	} else {
		rv = btree_recv_frame(dev, 0, 0, count);
		if (rv < 0)
			goto exit;
		else
			goto retry;
	}

exit:
	return rv;
}

static ssize_t btree_write(struct file *file, const char *user_buffer,
						size_t count, loff_t *ppos)
{
	struct btree_usb *dev;

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
	struct btree_usb *dev = file->private_data;
	int retval = 0;
	unsigned char buf[BTREE_USB_RET_SIZE];
	struct btree_usb_io io_data;

	dev_info(&dev->interface->dev,
			"ioctl : cmd = 0x%x, arg = 0x%x \n",
			cmd, arg);

	switch (cmd) {
		case USB_CMD_DEVICE_INIT:
			dev_info(&dev->interface->dev, "USB_CMD_DEVICE_INIT\n");
			memcpy(&io_data, (void *) arg, sizeof(struct btree_usb_io));
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
								sizeof(struct btree_usb_io))) {
					retval = -EFAULT;
				}
			}
			break;
		case USB_CMD_SET_SENSOR_ID:
			memcpy(&io_data, (void *) arg, sizeof(struct btree_usb_io));
			dev_info(&dev->interface->dev,
					"USB_CMD_SET_SENSOR_ID : 0x%x, address : 0x%x \n", io_data.data, io_data.address);
			retval = btree_ctrl_msg(dev, cmd, USB_DIR_IN, io_data.data, buf, BTREE_USB_RET_SIZE);
			if (!retval) {
				memset(&io_data, 0x0, sizeof(struct btree_usb_io));
				io_data.data = (uint8_t)(buf[0] & 0x00FF);
				dev_info(&dev->interface->dev,
					"USB_CMD_SET_SENSOR_ID : 0x%x \n", io_data.data);
				if (copy_to_user((void __user *) arg,
								&io_data,
								sizeof(struct btree_usb_io))) {
					retval = -EFAULT;
				}
			}
			break;
		case USB_CMD_MCU_HOLD:
			memcpy(&io_data, (void *) arg, sizeof(struct btree_usb_io));
			dev_info(&dev->interface->dev,
					"USB_CMD_MCU_HOLD : 0x%x\n", io_data.data);
			retval = btree_ctrl_msg(dev, cmd, USB_DIR_IN, io_data.data, buf, BTREE_USB_RET_SIZE);
			if (!retval) {
				memset(&io_data, 0x0, sizeof(struct btree_usb_io));
				io_data.result = buf[0];
				dev_info(&dev->interface->dev,
					"USB_CMD_MCU_HOlD : %s \n", io_data.result ? "Success" : "Fail");
				if (copy_to_user((void __user *) arg,
								&io_data,
								sizeof(struct btree_usb_io))) {
					retval = -EFAULT;
				}
			}
			break;
		case USB_CMD_I2C_READ_16:
			dev_info(&dev->interface->dev, "USB_CMD_I2C_READ\n");
			memcpy(&io_data, (void *) arg, sizeof(struct btree_usb_io));
			dev_info(&dev->interface->dev, "address = 0x%x, data = 0x%4x, buf = 0x%x \n",
					io_data.address, io_data.data, io_data.buf);
			retval = btree_i2c_read(dev, cmd, io_data.address, buf, BTREE_USB_RET_SIZE);
			if (!retval) {
				dev_info(&dev->interface->dev, "result = %d, data = 0x%4x \n", buf[4], ((buf[0]<<8)+buf[1]));
				io_data.result = buf[4];
				io_data.data = ((buf[0]<<8)+buf[1]);
				if (copy_to_user((void __user *) arg,
								&io_data,
								sizeof(struct btree_usb_io))) {
					retval = -EFAULT;
				}
			}
			break;
		case USB_CMD_I2C_WRITE_16:
			dev_info(&dev->interface->dev, "USB_CMD_I2C_WRITE\n");
			memcpy(&io_data, (void *) arg, sizeof(struct btree_usb_io));
			dev_info(&dev->interface->dev, "address = 0x%x, data = 0x%2x, buf = 0x%x \n",
					io_data.address, io_data.data, io_data.buf);
			retval = btree_i2c_write(dev, cmd, io_data.data, io_data.address, buf, BTREE_USB_RET_SIZE);
			if (!retval) {
				dev_info(&dev->interface->dev, "result = %d \n", buf[0]);
				io_data.result = buf[0];
				if (copy_to_user((void __user *) arg,
								&io_data,
								sizeof(struct btree_usb_io))) {
					retval = -EFAULT;
				}
			}
			break;
		case USB_CMD_CAPTURE:
			dev_info(&dev->interface->dev, "USB_CMD_CAPTURE\n");
			memcpy(&io_data, (void *) arg, sizeof(struct btree_usb_io));
			dev_info(&dev->interface->dev, "address = 0x%x, data = 0x%x, buf = 0x%x \n",
					io_data.address, io_data.data, io_data.buf);
			retval = btree_ctrl_msg(dev, cmd, USB_DIR_IN, io_data.data, buf, BTREE_USB_RET_SIZE);
			if (!retval) {
				io_data.result = buf[0];
				if (copy_to_user((void __user *) arg,
								&io_data,
								sizeof(struct btree_usb_io))) {
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

static struct usb_driver btree_driver;

static int btree_open(struct inode *inode, struct file *file)
{
	struct btree_usb *dev;
	struct usb_interface *interface;
	int subminor;
	int retval = 0;

	printk("[%s]\n",__func__);
	subminor = iminor(inode);
	printk("[%s] subminor - %d \n",
			__func__, subminor);
	interface = usb_find_interface(&btree_driver, subminor);
	if (!interface) {
		dev_err(&interface->dev, "%s - error, can't find device for minor %d \n",
				__func__, subminor);
		retval = -ENODEV;
		goto exit;
	}
	dev_info(&interface->dev, "%s - find device for minor %d \n",
			__func__, subminor);

	dev = usb_get_intfdata(interface);
	if (!dev) {
		retval = -ENODEV;
		goto exit;
	}
	kref_get(&dev->kref);
	file->private_data = dev;

exit:
	return retval;
}

static int btree_release(struct inode *inode, struct file *file)
{
	struct btree_usb *dev;

	pr_debug("%s",__func__);
	dev = file->private_data;
	if (dev == NULL)
		return -ENODEV;

	pr_debug( "%s - close %d device \n",
			__func__, iminor(inode));

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
			.minor_base =   BTREE_USB_MINOR_BASE,
};

static int btree_probe (struct usb_interface *interface,
						const struct usb_device_id *id)
{
	struct usb_host_interface *iface_desc;
	struct usb_endpoint_descriptor *endpoint;
	struct btree_usb *dev;
	size_t buffer_size;
	int i;
	int retval = -ENOMEM;

	dev_info(&interface->dev, "btree_probe \n");
	dev = kzalloc(sizeof(struct btree_usb), GFP_KERNEL);
	if (!dev) {
		dev_err(&interface->dev, "Out of memory \n");
		retval = - ENOMEM;
		return retval;
	}
	kref_init(&dev->kref);
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
				dev->bulk_in_urb = usb_alloc_urb(0, GFP_KERNEL);
				if (!dev->bulk_in_urb) {
					dev_err(&interface->dev,
							"Could not allocate bulk_in_urb \n");
					goto error;
				}
				dev->bulk_in_buffer = kmalloc(buffer_size, GFP_KERNEL);
				if (!dev->bulk_in_buffer) {
					dev_err(&interface->dev,
							"Could not allocate bulk_in_buffer \n");
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

	dev->bulk_in_copied = 0;
	dev->bulk_in_filled = 0;
	dev->ongoing_read = 0;

	usb_set_intfdata(interface, dev);

	retval = usb_register_dev(interface, &btree_class);
	if (retval) {
		dev_err(&interface->dev,
				"Not able to get a minor for this device \n");
		usb_set_intfdata(interface, NULL);
		return retval;
	}

	dev_info(&interface->dev,
			"USB btree device is now attached to btree%d",
			interface->minor);
	retval = register_v4l2(dev);
	if (retval < 0) {
		dev_err(&interface->dev,
				"failed to register btree v4l2_device \n");
		goto error;
	}
	dev_info(&interface->dev,
			"btree%d is registered as a v4l2 device",
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
	struct btree_usb *dev;

	dev_info(&interface->dev, "USB device is ditached %d \n",
			interface->minor);
	dev = usb_get_intfdata(interface);
	usb_set_intfdata(interface, NULL);

	unregister_v4l2(dev);

	usb_deregister_dev(interface, &btree_class);

	dev->interface = NULL;

	usb_kill_anchored_urbs(&dev->submitted);

	kref_put(&dev->kref, btree_delete);
}

static struct usb_driver btree_driver = {
		.name = "btree",
		.probe =	btree_probe,
		.disconnect = btree_disconnect,
		.id_table = btree_table,
};

module_usb_driver(btree_driver);
