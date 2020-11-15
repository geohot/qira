/******************************************************************************
 * Copyright (c) 2011 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef _LIBVIRTIO_H
#define _LIBVIRTIO_H

#include <stdint.h>

/* Device status bits */
#define VIRTIO_STAT_ACKNOWLEDGE		1
#define VIRTIO_STAT_DRIVER		2
#define VIRTIO_STAT_DRIVER_OK		4
#define VIRTIO_STAT_FAILED		128

#define VIRTIO_TIMEOUT		        5000 /* 5 sec timeout */

/* Definitions for vring_desc.flags */
#define VRING_DESC_F_NEXT	1	/* buffer continues via the next field */
#define VRING_DESC_F_WRITE	2	/* buffer is write-only (otherwise read-only) */
#define VRING_DESC_F_INDIRECT	4	/* buffer contains a list of buffer descriptors */

/* Descriptor table entry - see Virtio Spec chapter 2.3.2 */
struct vring_desc {
	uint64_t addr;		/* Address (guest-physical) */
	uint32_t len;		/* Length */
	uint16_t flags;		/* The flags as indicated above */
	uint16_t next;		/* Next field if flags & NEXT */
}; 

/* Definitions for vring_avail.flags */
#define VRING_AVAIL_F_NO_INTERRUPT	1

/* Available ring - see Virtio Spec chapter 2.3.4 */
struct vring_avail {
	uint16_t flags;
	uint16_t idx;
	uint16_t ring[];
}; 


/* Definitions for vring_used.flags */
#define VRING_USED_F_NO_NOTIFY		1

struct vring_used_elem {
	uint32_t id;		/* Index of start of used descriptor chain */
	uint32_t len;		/* Total length of the descriptor chain which was used */
};

struct vring_used {
	uint16_t flags;
	uint16_t idx;
	struct vring_used_elem ring[];
};

#define VIRTIO_TYPE_PCI 0	/* For virtio-pci interface */
struct virtio_device {
	void *base;		/* base address */
	int type;		/* VIRTIO_TYPE_PCI or VIRTIO_TYPE_VIO */
};

/* Parts of the virtqueue are aligned on a 4096 byte page boundary */
#define VQ_ALIGN(addr)	(((addr) + 0xfff) & ~0xfff)

extern unsigned long virtio_vring_size(unsigned int qsize);
extern int virtio_get_qsize(struct virtio_device *dev, int queue);
extern struct vring_desc *virtio_get_vring_desc(struct virtio_device *dev, int queue);
extern struct vring_avail *virtio_get_vring_avail(struct virtio_device *dev, int queue);
extern struct vring_used *virtio_get_vring_used(struct virtio_device *dev, int queue);

extern void virtio_reset_device(struct virtio_device *dev);
extern void virtio_queue_notify(struct virtio_device *dev, int queue);
extern void virtio_set_status(struct virtio_device *dev, int status);
extern void virtio_set_qaddr(struct virtio_device *dev, int queue, unsigned int qaddr);
extern void virtio_set_guest_features(struct virtio_device *dev, int features);
extern void virtio_get_host_features(struct virtio_device *dev, int *features);
extern uint64_t virtio_get_config(struct virtio_device *dev, int offset, int size);
extern int __virtio_read_config(struct virtio_device *dev, void *dst,
				int offset, int len);


#endif /* _LIBVIRTIO_H */
