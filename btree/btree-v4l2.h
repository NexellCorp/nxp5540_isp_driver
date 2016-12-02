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

#ifndef __BTREE_V4L2_H
#define __BTREE_V4L2_h

#define BTREE_VIDEO_MAX_NAME_SIZE	32
#define BTREE_VIDEO_MAX_BUFFERS		16
#define	BTREE_VIDEO_MAX_PLANES	3

#include <linux/spinlock.h>

struct btree_video_format {
	char *name;
	uint32_t	pixelformat;
	uint32_t	mbus_code;
	uint32_t	num_planes;
	uint32_t	num_sw_planes;
	bool		is_separated;
};

struct btree_video_frame {
	uint16_t	width;
	uint16_t	height;
	uint16_t	stride[BTREE_VIDEO_MAX_PLANES];
	uint32_t	size[BTREE_VIDEO_MAX_PLANES];
	struct btree_video_format	format;
};

struct btree_video_buffer;

struct btree_video_buffer {
	struct vb2_v4l2_buffer vb;
	struct list_head	 list;
};

enum btree_video_type {
	BTREE_VIDEO_TYPE_CAPTURE = 0,
	BTREE_VIDEO_TYPE_OUT,
	BTREE_VIDEO_TYPE_M2M,
	BTREE_VIDEO_TYPE_MAX,
};

struct btree_video {
	char name[BTREE_VIDEO_MAX_NAME_SIZE];
	uint32_t type; /* btree video type */

	struct btree_video_buffer *bufs[BTREE_VIDEO_MAX_BUFFERS];

	struct v4l2_device *v4l2_dev;
	struct vb2_queue *vbq;
	void *vb2_alloc_ctx;

	/*queue */
	spinlock_t slock;
	struct list_head buffer_list;
	struct delayed_work read_work;

	struct mutex lock; /* for video_device */
	struct video_device vdev;

	struct btree_video_frame frame;
	uint32_t open_count;

	/* for saving btree_usb pointer */
	void *priv;
};

/* macros */
/* public functions */

struct btree_video *btree_video_create
(char *, uint32_t, struct v4l2_device *, void *);
void btree_video_cleanup(struct btree_video *);
int btree_v4l2_register_device
(struct device *dev, struct v4l2_device *v4l2_dev);
int btree_v4l2_unregister_device(struct v4l2_device *v4l2_dev);
#endif
