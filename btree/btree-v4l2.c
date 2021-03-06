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
#include <linux/mutex.h>	/* mutex */
#include <linux/errno.h>	/* error */
#include <linux/slab.h>		/* malloc/free */
#include <linux/kref.h>		/* kref */
#include <linux/uaccess.h>	/* memory access?? */
#include <linux/platform_device.h> /* platform device */
#include <linux/of.h> /* of */
#include <linux/usb.h> /* usb */
/* work queue */
#include <linux/workqueue.h>
/* v4l2 */
#include <linux/videodev2.h>
/* temp for vb2_dc_buf structure */
#include <media/videobuf2-memops.h>

/* v4l2 device */
#include <media/v4l2-device.h>
#include <media/v4l2-ioctl.h>
/* video device */
#include <media/v4l2-dev.h>
/* vb2_mem_ops */
#include <media/videobuf2-core.h>
/* vb2, queue */
#include <media/videobuf2-dma-contig.h>

#include <linux/time.h>

#include "btree-usb.h"
#include "btree-v4l2.h"

//#define USE_TIME_INFO

#define to_btree_video_buffer(buf) container_of(buf, struct btree_video_buffer, vb)

extern int vb2_debug;
static struct vb2_dc_buf {
	struct device           *dev;
	void                *vaddr;
	unsigned long           size;
	dma_addr_t          dma_addr;
	enum dma_data_direction     dma_dir;
	struct sg_table         *dma_sgt;
	struct frame_vector             *vec;

	/* MMAP related */
	struct vb2_vmarea_handler   handler;
	atomic_t            refcount;
	struct sg_table         *sgt_base;
	/* DMABUF related */
	struct dma_buf_attachment   *db_attach;
};

static struct btree_video_buffer *btree_video_update_buffer
(struct btree_video *me, bool remove);

static void btree_video_done_buffer
(struct btree_video *me, struct btree_video_buffer *buf);

static int set_stream_onoff(void *priv, int onoff)
{
	int ret = -EINVAL;

	ret = btree_capture_enable(priv, onoff);
	return ret;
}

static int read_frame(void *priv,
		dma_addr_t addr, unsigned int size)
{
	int ret = -EINVAL;
	ret = btree_read_frame(priv, addr, size);
	if (ret)
		pr_err("failed to read frame \n");
	return ret;
}

static int btree_video_read_frame(struct btree_video *me,
				  struct btree_video_buffer *cur_buf)
{
	int ret = -EINVAL;
	unsigned int i = 0;
	struct vb2_buffer *vb = NULL;
	struct vb2_dc_buf *dc_buf = NULL;
	struct sg_table *sgt = NULL;
	struct scatterlist *s = NULL;
#ifdef	USE_TIME_INFO
	struct timespec curr_tm;
	unsigned int file_s, file_n, chunk_s, chunk_n;
#endif
	printk("[%s] \n", __func__);

#ifdef	USE_TIME_INFO
	getnstimeofday(&curr_tm);
	file_s = curr_tm.tv_sec;
	file_n = curr_tm.tv_nsec;
#endif
	if (!cur_buf)
		return -ENOMEM;
	printk(" call stream on function \n");
	ret = set_stream_onoff(me->priv, 1);
	if (ret) {
		pr_err(" failed to stream on \n");
		return ret;
	}
	vb = cur_buf->vb.vb2_buf;
	dc_buf = vb->planes[0].mem_priv;
	sgt = dc_buf->dma_sgt;
	for_each_sg(sgt->sgl, s, sgt->nents, i) {
		if (sg_dma_len(s) > INT_MAX) {
			pr_err("buf size is too big to be transferred at once \n");
			return -ENOMEM;
		}
#ifdef	USE_TIME_INFO
		if ((i > 50) && (i < 60)) {
			getnstimeofday(&curr_tm);
			chunk_s = curr_tm.tv_sec;
			chunk_n = curr_tm.tv_nsec;
		}
#endif
		ret = read_frame(me->priv, sg_dma_address(s), sg_dma_len(s));
#ifdef	USE_TIME_INFO
		if ((i > 50) && (i < 60)) {
			getnstimeofday(&curr_tm);
			chunk_s = curr_tm.tv_sec - chunk_s;
			chunk_n = curr_tm.tv_nsec - chunk_n;
			printk("TIME[%d]: sec[%d],milisec[%d] \n",
				i,
				chunk_s % 60,
				chunk_n / 1000000);
			}
#endif
	}
	printk(" call stream off function \n");
	ret = set_stream_onoff(me->priv, 0);
	if (ret) {
		pr_err(" failed to stream off \n");
		return ret;
	}
#ifdef	USE_TIME_INFO
	getnstimeofday(&curr_tm);
	file_s = curr_tm.tv_sec - file_s;
	file_n = curr_tm.tv_nsec - file_n;
	printk(">>>>>End TIME: sec-%d, milisec%d \r\n",
		file_s % 60,
		file_n / 1000000);
#endif
	return ret;
}

/* functions related to work queue */
static void btree_video_read_handler(struct work_struct *work)
{
	int rv = -1;
	struct btree_video_buffer *buf = NULL;
	struct btree_video *me =
		container_of(work, struct btree_video, read_work);

#ifdef	USE_TIME_INFO
	struct timespec curr_tm;
	unsigned int file_s, file_n;
#endif
	pr_err("[%s] \n", __func__);
#ifdef	USE_TIME_INFO
	getnstimeofday(&curr_tm);
	file_s = curr_tm.tv_sec;
	file_n = curr_tm.tv_nsec;
#endif
	buf = btree_video_update_buffer(me, false);
	if (!buf) {
		pr_err("failed to update buffer \n");
		schedule_delayed_work(&me->read_work, 50);
	} else {
		rv =  btree_video_read_frame(me, buf);
		if ( rv < 0)
			pr_err("failed to read frame \n");
		else {
			btree_video_done_buffer(me, buf);
			btree_video_update_buffer(me, true);
#ifdef	USE_TIME_INFO
			getnstimeofday(&curr_tm);
			file_s = curr_tm.tv_sec - file_s;
			file_n = curr_tm.tv_nsec - file_n;
			printk("sec[%d],millisec[%d] \n",
			file_s % 60,
			file_n / 1000000);
#endif
			schedule_delayed_work(&me->read_work, 1);
		}
	}
}


/*
 * callback functions
 */

static int set_plane_size(struct btree_video_frame *frame, unsigned int sizes[])
{
	uint32_t y_stride = ALIGN(frame->width, 32);
	uint32_t y_size = y_stride * frame->height;

	switch (frame->format.pixelformat) {
	case V4L2_PIX_FMT_UYVY:
		printk("V4L2_PIX_FMT_UYVY \n");
		frame->size[0] = sizes[0] = (y_stride*2)*frame->height;
		frame->stride[0] = y_stride << 1;
		sizes[0] = frame->size[0];
		printk("size = %d \n", sizes[0]);
		break;
	case V4L2_PIX_FMT_YUYV:
		printk("V4L2_PIX_FMT_YUYV\n");
		frame->size[0] = sizes[0] = y_size << 1;
		frame->stride[0] = y_stride << 1;
		sizes[0] = frame->size[0];
		break;
	case V4L2_PIX_FMT_YUV422P:
		frame->size[0] = y_size;
		frame->size[1] = frame->size[2] = y_size>>1;
		frame->stride[0] = y_stride;
		frame->stride[1] = frame->stride[2] = ALIGN(y_stride >> 1, 16);

		sizes[0] = frame->size[0];
		sizes[0] += frame->size[1] *2;

		break;
	default:
		pr_err("[btree video] unknown format(%d)\n", frame->format.pixelformat);
		return -EINVAL;
	}
	return 0;
}

/*
 * queue_setup() called from vb2_reqbufs()
 * setup plane number, plane size
 */
static int btree_vb2_queue_setup(struct vb2_queue *q,
								const struct v4l2_format *fmt,
								unsigned int *num_buffers,
								unsigned int *num_planes,
								unsigned int sizes[], void *alloc_ctxs[])
{
	int ret;
	int i;
	struct btree_video *me = vb2_get_drv_priv(q);
	struct btree_video_frame *frame = NULL;

	printk("[%s]\n",__func__);

	if (q->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE ||
		q->type == V4L2_BUF_TYPE_VIDEO_CAPTURE)
		frame = &me.frame;
	if (!frame) {
		pr_err("[btree video] can't find frame for q type(0x%x)\n",
				q->type);
		return -EINVAL;
	}
	ret = set_plane_size(frame, sizes);
	if (ret < 0) {
		pr_err("[btree video] failed to set_plane_size()\n");
		return ret;
	}

	*num_planes = (unsigned int)(frame->format.num_planes);
	for (i = 0; i < *num_planes; ++i)
		alloc_ctxs[i] = me->vb2_alloc_ctx;

	return 0;
}

static int btree_vb2_buf_init(struct vb2_buffer *vb)
{
	printk("[%s] \n", __func__);
	return 0;
}


static void btree_vb2_buf_cleanup(struct vb2_buffer *vb)
{
	printk("[%s] \n", __func__);
	return 0;
}

/* real queue */
static struct btree_video_buffer *btree_video_update_buffer
(struct btree_video *me, bool remove)
{
	unsigned long flags;
	struct btree_video_buffer *buf;

	pr_err("[%s] \n", __func__);
	spin_lock_irqsave(&me->slock, flags);
	if (list_empty(&me->buffer_list)) {
		pr_err("list is empty \n");
		spin_unlock_irqrestore(&me->slock, flags);
		return -ENOENT;
	}
	buf = list_first_entry(&me->buffer_list, struct btree_video_buffer, list);
	if (remove)
		list_del_init(&buf->list);
	spin_unlock_irqrestore(&me->slock, flags);
	return buf;
}

static void btree_video_done_buffer
(struct btree_video *me, struct btree_video_buffer *buf)
{
	unsigned long flags;

	prinktk("[%s]\n",__func__);

	if (!buf) {
		pr_err(" buf is null \n");
		return;
	}
	vb2_buffer_done(buf->vb.vb2_buf, VB2_BUF_STATE_DONE);
}

static void btree_video_clear_buffer(struct btree_video *me)
{
	unsigned long flags;
	struct btree_video_buffer *buf = NULL;

	spin_lock_irqsave(&me->slock, flags);

	while (!list_empty(&me->buffer_list)) {
		buf = list_entry(me->buffer_list.next,
				 struct btree_video_buffer, list);
		if (buf) {
			struct vb2_buffer *vb = buf->priv;
			vb2_buffer_done(&buf->vb.vb2_buf, VB2_BUF_STATE_ERROR);
			list_del_init(&buf->list);
		} else
			break;
	}
	INIT_LIST_HEAD(&me->buffer_list);
	spin_unlock_irqrestore(&me->slock, flags);
}

void btree_vb2_buf_queue(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);
	struct btree_video *me = vb2_get_drv_priv(vb->vb2_queue);
	struct btree_video_buffer *buf = to_btree_video_buffer(vbuf);

	printk("[%s] \n",__func__);
	printk(" buf = 0x%x, index = %d \n", buf, vb->index);

	spin_lock_irqsave(&me->slock, flags);
	list_add_tail(&buf->list, &me->buffer_list);
	spin_unlock_irqrestore(&me->slock, flags);
}

static int btree_vb2_buf_finish(struct vb2_buffer *vb)
{
	printk("[%s] state = %d \n", __func__, vb->state);
	return 0;
}

static int btree_vb2_buf_prepare(struct vb2_buffer *vb)
{
	int i;
	btree_video *me = vb2_get_drv_priv(vb->vb2_queue);

	printk("[%s]\n", __func__);
	for (i = 0; i < vb->num_planes; i++)
		vb2_set_palne_payload(vb, i, me->frame.sizes[i]);
	return 0;
}

static struct vb2_ops btree_vb2_ops = {
	.queue_setup    = btree_vb2_queue_setup,
	.buf_prepare	= btree_vb2_buf_prepare,
	.buf_init   	= btree_vb2_buf_init,
	.buf_cleanup    = btree_vb2_buf_cleanup,
	.buf_queue  	= btree_vb2_buf_queue,
	.buf_finish 	= btree_vb2_buf_finish
};


/*
 * v4l2_ioctl_ops
 */

static int btree_video_querycap(struct file *file, void *fh,
							struct v4l2_capability	*cap)
{
	struct btree_video *me = video_drvdata(file);

	printk("[%s] \n",__func__);
	strlcpy(cap->driver, me->name, sizeof(cap->driver));
	strlcpy(cap->card, me->vdev.name, sizeof(cap->card));
	strlcpy(cap->bus_info, "media", sizeof(cap->bus_info));

	cap->version = KERNEL_VERSION(1, 0, 0);
	switch (me->type) {
	case BTREE_VIDEO_TYPE_CAPTURE:
		cap->device_caps = V4L2_CAP_VIDEO_CAPTURE |
			V4L2_CAP_VIDEO_CAPTURE_MPLANE | V4L2_CAP_STREAMING;
		break;
	case BTREE_VIDEO_TYPE_OUT:
		cap->device_caps =
			V4L2_CAP_VIDEO_OUTPUT_MPLANE | V4L2_CAP_STREAMING;
		break;
	case BTREE_VIDEO_TYPE_M2M:
		cap->device_caps = V4L2_CAP_VIDEO_CAPTURE_MPLANE |
			V4L2_CAP_VIDEO_OUTPUT_MPLANE | V4L2_CAP_STREAMING;
		break;
	default:
		pr_err("[btree video] querycap: invalid type(%d)\n", me->type);
		break;
	}
	cap->capabilities = cap->device_caps | V4L2_CAP_DEVICE_CAPS;

	return 0;
}

static int btree_video_get_format(struct file *file, void *fh,
							   struct v4l2_format *f)
{
	printk("%s \n", __func__);
	return 0;
}

static void set_sensor_output_size(
		void *priv, int width, int height)
{
	int device_w = 0, device_h = 0;
	unsigned int data = 0x064004B0; /* 1600*1200 */
	if (!btree_write_reg(priv, BTREE_REG_TYPE_ISP, BTREE_REG_SENSOR_SIZE, data)) {
		data = btree_read_reg(priv, 0x0000);
		if(data > 0) {
			device_w = ((data >> 16) & 0xFFFF);
			device_h = data & 0xFFFF;
			printk(" width[%d], height[%d] \n", device_w, device_h);
		} else
			pr_err("failed to set width and height \n");
	} else
		pr_err("failed to set width and height \n");
}

static int btree_video_set_format(struct file *file, void *fh,
							struct v4l2_format *f)
{
	struct btree_video *me = video_drvdata(file);
	struct btree_video_frame *frame;
	uint32_t width, height, pixelformat, colorspace, field;

	printk("[%s]\n",__func__);

	if ( (!me) || (!me->vbq)) {
		pr_err(" invalid handle \n");
		return -ENOMEM;
	}
	me->vbq->type = f->type;
	if (f->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE ||
		f->type == V4L2_BUF_TYPE_VIDEO_CAPTURE) {
		frame = &me.frame;
	} else {
		pr_err("[btree video] set format: invalid type(0x%x)\n", f->type);
		return -EINVAL;
	}
	if (f->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		width = f->fmt.pix_mp.width;
		height = f->fmt.pix_mp.height;
		pixelformat = f->fmt.pix_mp.pixelformat;
		colorspace = f->fmt.pix_mp.colorspace;
		field = f->fmt.pix_mp.field;
	} else {
		width = f->fmt.pix.width;
		height = f->fmt.pix.height;
		pixelformat = f->fmt.pix.pixelformat;
		colorspace = f->fmt.pix.colorspace;
		field = f->fmt.pix.field;
	}

	frame->format.name = "YUV 4:2:2 packed, YCbYCr";
	frame->format.pixelformat = pixelformat;
	frame->format.num_planes  = 1;
	frame->format.num_sw_planes  = 1;
	frame->format.is_separated  = 0;
	frame->width  = width;
	frame->height = height;

	// TODO : call usb driver??

	set_plane_size(frame, &f->fmt.pix.sizeimage);

	printk("width = %d, height = %d,pixelformat = 0x%x, colorspace = %d, field = %d\n",
			frame->width, frame->height, frame->format.pixelformat, colorspace, field);
	set_sensor_output_size(me->priv, frame->width, frame->height);

	return 0;
}

static int btree_video_reqbufs(struct file *file, void *fh,
							struct v4l2_requestbuffers *b)
{
	struct btree_video *me = video_drvdata(file);

	printk("[%s]\n",__func__);

	if (me->vbq)
		return vb2_reqbufs(me->vbq, b);
	return -EINVAL;
}

static int btree_video_querybuf(struct file *file, void *fh,
							struct v4l2_buffer *b)
{
	struct btree_video *me = video_drvdata(file);
	printk("[%s]\n",__func__);
	if (me->vbq)
		return vb2_querybuf(me->vbq, b);
	return -EINVAL;
}

static int btree_video_qbuf(struct file *file, void *fh,
						struct v4l2_buffer *b)
{
	struct btree_video *me = video_drvdata(file);
	int ret = -EINVAL;

	printk("[%s]\n",__func__);
	if (me->vbq) {
		ret = vb2_qbuf(me->vbq, b);
	}
	printk("ret = %d \n");
	return ret;
}

static int btree_video_dqbuf(struct file *file, void *fh,
						struct v4l2_buffer *b)
{
	struct btree_video *me = video_drvdata(file);
	int ret = -EINVAL;

	printk("[%s]\n",__func__);

	if (me->vbq) {
		ret = vb2_dqbuf(me->vbq, b, file->f_flags & O_NONBLOCK);
	}
	printk("ret = %d \n",ret);
	return ret;
}

static int btree_video_streamon(struct file *file, void *fh, enum v4l2_buf_type i)
{
	int ret = -EINVAL;
	struct btree_video *me = video_drvdata(file);

	printk("[%s]\n",__func__);
	if (me->vbq) {
		ret = vb2_streamon(me->vbq, i);
		if (ret < 0) {
			pr_err("[btree video] failed to vb2_streamon() for %s\n",
					me->name);
			return ret;
		}
		schedule_delayed_work(&me->read_work, 1);
	}
   return ret;
}

static int btree_video_streamoff(struct file *file, void *fh, enum v4l2_buf_type i)
{
	struct btree_video *me = video_drvdata(file);
	int ret;

	printk("[%s]\n",__func__);
	if (me->vbq) {
		// TODO : call stream off
		cancel_delayed_work(&me->read_work);
		ret = set_stream_onoff(me->priv, 0);
		if (ret) {
			pr_err("[btree video] failed to subdev s_stream for %s\n",
					me->name);
			return ret;
		}
		btree_video_clear_buffer(me);
		return vb2_streamoff(me->vbq, i);
	}
   return -EINVAL;
}

static int btree_video_get_crop(struct file *file, void *fh, struct v4l2_crop *a)
{
	printk("[%s] \n", __func__);
}

static int btree_video_set_crop(struct file *file, void *fh,
				const struct v4l2_crop *a)
{
	struct btree_video *me = video_drvdata(file);
	int data_h = 0, data_l = 0;
	unsigned int data = 0;
	unsigned int addr = 0;

	printk("[%s] crop x-%d, y-%d, w-%d, h-%d \n",
		__func__, a->c.left, a->c.top,
		a->c.width, a->c.height);
	addr = BTREE_REG_CROP_X_Y; /* crop start point x, y for ISP Input*/
	data = (((a->c.left + 0x10) << 16) | (a->c.top + 0x10));
	if (!btree_write_reg(me->priv, BTREE_REG_TYPE_ISP, addr, data)) {
		data = btree_read_reg(me->priv, addr);
		if(data > 0) {
			data_h = ((data >> 16) & 0xFFFF);
			data_l = data & 0xFFFF;
			printk(" start_x[%d], start_y[%d] \n", data_h, data_l);
		} else
			pr_err("failed to set crop position x and y \n");
	} else
		pr_err("failed to set 0x%x register \n", addr);
	addr = BTREE_REG_CROP_SIZE; /* crop size  for ISP Input */
	data = ((a->c.width << 16) | a->c.height);
	if (!btree_write_reg(me->priv, BTREE_REG_TYPE_ISP, addr, data)) {
		data = btree_read_reg(me->priv, addr);
		if(data > 0) {
			data_h = ((data >> 16) & 0xFFFF);
			data_l = data & 0xFFFF;
			printk(" crop width[%d], crop height[%d] \n", data_h, data_l);
		} else
			pr_err("failed to set crop width and height \n");
	} else
		pr_err("failed to set 0x%x register \n", addr);
	addr = BTREE_REG_USB_SIZE;
	data = a->c.width;
	if (btree_write_reg(me->priv, BTREE_REG_TYPE_SENSOR, addr, data))
		pr_err("failed to set 0x%x register \n", (addr&0x0FFF));
}

static int btree_video_get_register(struct file *file, void *fh, struct v4l2_dbg_register *a)
{
	struct btree_video *me = video_drvdata(file);
	int ret = -1;
	unsigned int data = 0;

	printk("[%s] \n", __func__);
	printk("addr:0x%4x, val:0x%8x, type:%d \n",
		a->reg, a->val, a->match.type);
	data = btree_read_reg(me->priv, a->reg);
	if (data < 0)
		pr_err("failed to get register:0x%4x \n", a->reg);
	else {
		a->val = data;
		ret = 0;
	}
	return ret;
}

static int btree_video_set_register(struct file *file, void *fh, struct v4l2_dbg_register *a)
{
	struct btree_video *me = video_drvdata(file);
	int ret = -1, type;

	printk("[%s] \n", __func__);
	printk("addr:0x%4x, val:0x%8x, type:%d \n",
		a->reg, a->val, a->match.addr);
	if (!a->match.addr)
		type = BTREE_REG_TYPE_ISP;
	else
		type = BTREE_REG_TYPE_SENSOR;

	if (btree_write_reg(me->priv, type, a->reg, a->val))
		pr_err("failed to set register:0x%4x \n", a->reg);
	else {
		ret = 0;
	}
	return ret;
}

static int btree_video_get_chip_info
(struct file *file, void *fh, struct v4l2_dbg_chip_info *a)
{
	printk("[%s] \n", __func__);
}

static int btree_video_prepare_buf
(struct file *file, void *fh, struct v4l2_buffer *b)
{
	struct btree_video *me = video_drvdata(file);
	int ret;
	mutex_lock(&me->slock);
	vb2_prepare_buf(&me->vbq, b);
	mutex_unlock(&me->slock);
	return ret;
}

static struct v4l2_ioctl_ops btree_video_ioctl_ops = {
	.vidioc_querycap		= btree_video_querycap,
	.vidioc_g_fmt_vid_cap		= btree_video_get_format,
	.vidioc_s_fmt_vid_cap		= btree_video_set_format,
	.vidioc_g_fmt_vid_cap_mplane	= btree_video_get_format,
	.vidioc_s_fmt_vid_cap_mplane	= btree_video_set_format,
	.vidioc_reqbufs                 = btree_video_reqbufs,
	.vidioc_querybuf                = btree_video_querybuf,
	.vidioc_qbuf                    = btree_video_qbuf,
	.vidioc_dqbuf                   = btree_video_dqbuf,
	.vidioc_streamon                = btree_video_streamon,
	.vidioc_streamoff               = btree_video_streamoff,
	.vidioc_g_crop			= btree_video_get_crop,
	.vidioc_s_crop			= btree_video_set_crop,
	.vidioc_s_register		= btree_video_set_register,
	.vidioc_g_register		= btree_video_get_register,
	.vidioc_g_chip_info		= btree_video_get_chip_info,
	.vidioc_prepare_buf		= btree_video_prepare_buf,
};

/*
 * v4l2_file_operations
 */

static int check_device(void *priv)
{
	return btree_check_device(priv);
}

static int btree_video_open(struct file *file)
{
	struct btree_video *me = video_drvdata(file);
	int ret = 0;

	printk("[%s]\n",__func__);
	spin_lock_init(&me->slock);
	INIT_LIST_HEAD(&me->buffer_list);
	if (me->open_count == 0) {
		memset(me->frame, 0, sizeof(struct btree_video_frame)*2);
	}
	me->open_count++;
	file->private_data = me;

	ret = check_device(me->priv);
	if (ret)
		pr_err(" btree usb device is not ready \n");

	pr_err("init work queue \n");
	INIT_DELAYED_WORK(&me->read_work, btree_video_read_handler);
	return ret;
}

static int btree_video_release(struct file *file)
{
	struct btree_video *me = video_drvdata(file);
	int ret = 0;
	printk("[%s]\n",__func__);
	cancel_delayed_work(&me->read_work);
	me->open_count--;
	if (me->open_count == 0) {
		// TODO : call usb close??
		if (me->vbq)
			vb2_queue_release(me->vbq);
	}
	file->private_data = 0;
	return ret;
}

static struct v4l2_file_operations btree_video_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = video_ioctl2,
	.open           = btree_video_open,
	.release        = btree_video_release,
};

struct btree_video *btree_video_create(char *name, uint32_t type,
									struct v4l2_device *v4l2_dev,
									void *vb2_alloc_ctx)
{
	int ret = -1;
	struct vb2_queue *vbq = NULL;
	struct btree_video *me = kzalloc(sizeof(*me), GFP_KERNEL);

	vb2_debug = 1;

	printk("%s \n", __func__);
	if (!me) {
		pr_err("failed to get memory for btree video\n");
		return NULL;
	}
	snprintf(me->name, sizeof(me->name), "%s", name);
	snprintf(me->vdev.name, sizeof(me->vdev.name), "%s", name);

	me->type	= type;
	me->v4l2_dev = v4l2_dev;
	me->vb2_alloc_ctx = vb2_alloc_ctx;
	me->open_count = 0;
	mutex_init(&me->lock);

	me->vdev.fops	= &btree_video_fops;
	me->vdev.ioctl_ops	= &btree_video_ioctl_ops;
	me->vdev.v4l2_dev	= v4l2_dev;
	me->vdev.minor	= -1;
	me->vdev.vfl_type	= VFL_TYPE_GRABBER;
	me->vdev.release	= video_device_release;
	me->vdev.lock	= &me->lock;

	vbq = kzalloc(sizeof(*vbq), GFP_KERNEL);
	if (!vbq) {
		pr_err("failed to get memory for vbq \n");
		if(me)
			kfree(me);
		return NULL;
	}

	vbq->type	= V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	vbq->io_modes = VB2_DMABUF;
	vbq->drv_priv = me;
	vbq->ops = &btree_vb2_ops;
	vbq->mem_ops = &vb2_dma_contig_memops;
	vbq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;

	ret = vb2_queue_init(vbq);
	if (ret < 0) {
		pr_err("failed to vb2_queue_init() : %d \n", ret);
		if(vbq)
			kfree(vbq);
		if(me)
			kfree(me);
		return NULL;
	}
	me->vbq = vbq;
	me->vdev.v4l2_dev = me->v4l2_dev;
	video_set_drvdata(&me->vdev, me);
	ret = video_register_device(&me->vdev, VFL_TYPE_GRABBER,
								7/*video_device_number*/);
	if (ret < 0 ) {
		pr_err("failed to video_register_device() \n");
		if(vbq)
			kfree(vbq);
		if(me)
			kfree(me);
		return NULL;
	}

	printk(" success to register video device %s \n",
			me->vdev.name);
	return me;
}
EXPORT_SYMBOL_GPL(btree_video_create);

void btree_video_cleanup(struct btree_video *me)
{
	printk("[%s] %s \n", __func__, me->vdev.name);
	video_unregister_device(&me->vdev);
	mutex_destroy(&me->lock);

	if (me->vbq) {
		vb2_queue_release(me->vbq);
		kfree(me->vbq);
		me->vbq = NULL;
	}
	kfree(me);
	me = NULL;
}
EXPORT_SYMBOL_GPL(btree_video_cleanup);

int btree_v4l2_register_device(struct device *dev,
		struct v4l2_device *v4l2_dev)
{
	int retval = -1;

	printk("[%s]", __func__);
	retval = v4l2_device_register(dev, v4l2_dev);
	if (retval < 0) {
		pr_err("failed to register btree v4l2_device \n");
		return retval;
	}
	printk("success to register [%s] as v4l2 device \n", v4l2_dev->name);
	return 0;
}
EXPORT_SYMBOL_GPL(btree_v4l2_register_device);

int btree_v4l2_unregister_device
(struct v4l2_device *v4l2_dev)
{
	printk("[%s] %s \n", __func__, v4l2_dev->name);
	v4l2_device_unregister(v4l2_dev);
	return 0;
}
EXPORT_SYMBOL_GPL(btree_v4l2_unregister_device);

