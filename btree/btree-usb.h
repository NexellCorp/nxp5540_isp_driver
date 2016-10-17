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

unsigned int btree_read_reg(void *priv,
							unsigned int address);

int btree_write_reg(void *priv,
					unsigned int address, unsigned int data);

int btree_check_device(void *priv);

int btree_capture_enable(void *priv,
						int enable);

ssize_t btree_read_frame(void *priv,
						dma_addr_t buffer, size_t count);


#endif
