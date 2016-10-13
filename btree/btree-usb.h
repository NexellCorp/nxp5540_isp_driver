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

#ifndef __BTREE_USB_H
#define __BTREE_USB_H

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

struct btree_usb {
	struct  usb_device  *udev;
	// v4l2
	struct  v4l2_device v4l2_dev;
	struct  btree_video *vdev;
	void *alloc_ctx;
	struct  usb_interface   *interface;
	struct  semaphore   limit_sem;
	struct  usb_anchor  submitted;
	struct  urb *bulk_in_urb;
	unsigned char   *bulk_in_buffer;
	size_t	bulk_in_bufsize;
	size_t  bulk_in_size;
	size_t  bulk_in_filled;
	size_t  bulk_in_copied;
	__u8 bulk_in_endpointAddr;
	__u8 bulk_out_endpointAddr;
	int errors;
	bool    ongoing_read;
	spinlock_t  err_lock;
	struct kref kref;
	struct mutex    io_mutex;
	wait_queue_head_t   bulk_in_wait;
};


int getMaxPacketSize(struct btree_usb *dev);

int btree_ctrl_msg (struct btree_usb *dev, int request, int dir,
					int value, void *buf, int len);

int btree_i2c_read (struct btree_usb *dev, int request,
					unsigned int index, void *buf, int len);

int btree_i2c_write (struct btree_usb *dev, int request, unsigned int value,
					unsigned int index, void *buf, int len);

int btree_recv_frame (struct btree_usb *dev, int count);

ssize_t btree_read_frame(struct btree_usb *udev,
					dma_addr_t buffer, size_t count);


#endif
