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

#include <stdio.h>
#include <cpu.h>
#include <helpers.h>
#include "virtio.h"
#include "virtio-blk.h"

#define DEFAULT_SECTOR_SIZE 512

/**
 * Initialize virtio-block device.
 * @param  dev  pointer to virtio device information
 */
int
virtioblk_init(struct virtio_device *dev)
{
	struct vring_avail *vq_avail;
	int blk_size = DEFAULT_SECTOR_SIZE;
	int features;

	/* Reset device */
	// XXX That will clear the virtq base. We need to move
	//     initializing it to here anyway
	//
	//	 virtio_reset_device(dev);

	/* Acknowledge device. */
	virtio_set_status(dev, VIRTIO_STAT_ACKNOWLEDGE);

	/* Tell HV that we know how to drive the device. */
	virtio_set_status(dev, VIRTIO_STAT_ACKNOWLEDGE|VIRTIO_STAT_DRIVER);

	/* Device specific setup - we support F_BLK_SIZE */
	virtio_set_guest_features(dev,  VIRTIO_BLK_F_BLK_SIZE);

	vq_avail = virtio_get_vring_avail(dev, 0);
	vq_avail->flags = VRING_AVAIL_F_NO_INTERRUPT;
	vq_avail->idx = 0;

	/* Tell HV that setup succeeded */
	virtio_set_status(dev, VIRTIO_STAT_ACKNOWLEDGE|VIRTIO_STAT_DRIVER
				|VIRTIO_STAT_DRIVER_OK);

	virtio_get_host_features(dev, &features);
	if (features & VIRTIO_BLK_F_BLK_SIZE) {
		blk_size = virtio_get_config(dev,
				offset_of(struct virtio_blk_cfg, blk_size),
				sizeof(blk_size));
	}

	return blk_size;
}


/**
 * Shutdown the virtio-block device.
 * @param  dev  pointer to virtio device information
 */
void
virtioblk_shutdown(struct virtio_device *dev)
{
	/* Quiesce device */
	virtio_set_status(dev, VIRTIO_STAT_FAILED);

	/* Reset device */
	virtio_reset_device(dev);
}


/**
 * Read blocks
 * @param  reg  pointer to "reg" property
 * @param  buf  pointer to destination buffer
 * @param  blocknum  block number of the first block that should be read
 * @param  cnt  amount of blocks that should be read
 * @return number of blocks that have been read successfully
 */
int
virtioblk_read(struct virtio_device *dev, char *buf, long blocknum, long cnt)
{
	struct vring_desc *desc;
	int id;
	static struct virtio_blk_req blkhdr;
	//struct virtio_blk_config *blkconf;
	uint64_t capacity;
	uint32_t vq_size, time;
	struct vring_desc *vq_desc;		/* Descriptor vring */
	struct vring_avail *vq_avail;		/* "Available" vring */
	struct vring_used *vq_used;		/* "Used" vring */
	volatile uint8_t status = -1;
	volatile uint16_t *current_used_idx;
	uint16_t last_used_idx;
	int blk_size = DEFAULT_SECTOR_SIZE;

	//printf("virtioblk_read: dev=%p buf=%p blocknum=%li count=%li\n",
	//	dev, buf, blocknum, cnt);

	/* Check whether request is within disk capacity */
	capacity = virtio_get_config(dev,
			offset_of(struct virtio_blk_cfg, capacity),
			sizeof(capacity));
	if (blocknum + cnt - 1 > capacity) {
		puts("virtioblk_read: Access beyond end of device!");
		return 0;
	}

	blk_size = virtio_get_config(dev,
			offset_of(struct virtio_blk_cfg, blk_size),
			sizeof(blk_size));
	if (blk_size % DEFAULT_SECTOR_SIZE) {
		fprintf(stderr, "virtio-blk: Unaligned sector read %d\n", blk_size);
		return 0;
	}

	vq_size = virtio_get_qsize(dev, 0);
	vq_desc = virtio_get_vring_desc(dev, 0);
	vq_avail = virtio_get_vring_avail(dev, 0);
	vq_used = virtio_get_vring_used(dev, 0);

	last_used_idx = vq_used->idx;
	current_used_idx = &vq_used->idx;

	/* Set up header */
	blkhdr.type = VIRTIO_BLK_T_IN | VIRTIO_BLK_T_BARRIER;
	blkhdr.ioprio = 1;
	blkhdr.sector = blocknum * blk_size / DEFAULT_SECTOR_SIZE;

	/* Determine descriptor index */
	id = (vq_avail->idx * 3) % vq_size;

	/* Set up virtqueue descriptor for header */
	desc = &vq_desc[id];
	desc->addr = (uint64_t)&blkhdr;
	desc->len = sizeof(struct virtio_blk_req);
	desc->flags = VRING_DESC_F_NEXT;
	desc->next = (id + 1) % vq_size;

	/* Set up virtqueue descriptor for data */
	desc = &vq_desc[(id + 1) % vq_size];
	desc->addr = (uint64_t)buf;
	desc->len = cnt * blk_size;
	desc->flags = VRING_DESC_F_NEXT | VRING_DESC_F_WRITE;
	desc->next = (id + 2) % vq_size;

	/* Set up virtqueue descriptor for status */
	desc = &vq_desc[(id + 2) % vq_size];
	desc->addr = (uint64_t)&status;
	desc->len = 1;
	desc->flags = VRING_DESC_F_WRITE;
	desc->next = 0;

	vq_avail->ring[vq_avail->idx % vq_size] = id;
	mb();
	vq_avail->idx += 1;

	/* Tell HV that the queue is ready */
	virtio_queue_notify(dev, 0);

	/* Wait for host to consume the descriptor */
	time = SLOF_GetTimer() + VIRTIO_TIMEOUT;
	while (*current_used_idx == last_used_idx) {
		// do something better
		mb();
		if (time < SLOF_GetTimer())
			break;
	}

	if (status == 0)
		return cnt;

	printf("virtioblk_read failed! status = %i\n", status);

	return 0;
}
