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

/*
 * Virtio block device definitions.
 * See Virtio Spec, Appendix D, for details
 */

#ifndef _VIRTIO_BLK_H
#define _VIRTIO_BLK_H

#include <stdint.h>


struct virtio_blk_cfg {
	uint64_t	capacity;
	uint32_t	size_max;
	uint32_t	seg_max;
	struct	virtio_blk_geometry {
		uint16_t	cylinders;
		uint8_t 	heads;
		uint8_t 	sectors;
	} geometry;
	uint32_t	blk_size;
	uint32_t	sectors_max;
} __attribute__ ((packed)) ;

/* Block request */
struct virtio_blk_req {
	uint32_t  type ;
	uint32_t  ioprio ;
	uint64_t  sector ;
};

/* Block request types */
#define VIRTIO_BLK_T_IN			0
#define VIRTIO_BLK_T_OUT		1
#define VIRTIO_BLK_T_SCSI_CMD		2
#define VIRTIO_BLK_T_SCSI_CMD_OUT	3
#define VIRTIO_BLK_T_FLUSH		4
#define VIRTIO_BLK_T_FLUSH_OUT		5
#define VIRTIO_BLK_T_BARRIER		0x80000000

/* VIRTIO_BLK Feature bits */
#define VIRTIO_BLK_F_BLK_SIZE       (1 << 6)

extern int virtioblk_init(struct virtio_device *dev);
extern void virtioblk_shutdown(struct virtio_device *dev);
extern int virtioblk_read(struct virtio_device *dev, char *buf, long blocknum, long cnt);

#endif  /* _VIRTIO_BLK_H */
