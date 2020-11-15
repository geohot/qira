/******************************************************************************
 * Copyright (c) 2012 IBM Corporation
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
#include <string.h>
#include <cpu.h>
#include <helpers.h>
#include "virtio.h"
#include "virtio-scsi.h"

int virtioscsi_send(struct virtio_device *dev,
		    struct virtio_scsi_req_cmd *req,
		    struct virtio_scsi_resp_cmd *resp,
		    int is_read, void *buf, uint64_t buf_len)
{
        struct vring_desc *desc;
        struct vring_desc *vq_desc;		/* Descriptor vring */
        struct vring_avail *vq_avail;		/* "Available" vring */
        struct vring_used *vq_used;		/* "Used" vring */

        volatile uint16_t *current_used_idx;
        uint16_t last_used_idx;
        int id;
        uint32_t vq_size, time;

        int vq = VIRTIO_SCSI_REQUEST_VQ;

        vq_size = virtio_get_qsize(dev, vq);
        vq_desc = virtio_get_vring_desc(dev, vq);
        vq_avail = virtio_get_vring_avail(dev, vq);
        vq_used = virtio_get_vring_used(dev, vq);

        last_used_idx = vq_used->idx;
        current_used_idx = &vq_used->idx;

        /* Determine descriptor index */
        id = (vq_avail->idx * 3) % vq_size;

        desc = &vq_desc[id];
        desc->addr = (uint64_t)req;
        desc->len = sizeof(*req);
        desc->flags = VRING_DESC_F_NEXT;
        desc->next = (id + 1) % vq_size;

        /* Set up virtqueue descriptor for data */
        desc = &vq_desc[(id + 1) % vq_size];
        desc->addr = (uint64_t)resp;
        desc->len = sizeof(*resp);
        desc->flags = VRING_DESC_F_NEXT | VRING_DESC_F_WRITE;
        desc->next = (id + 2) % vq_size;

        if (buf && buf_len) {
                /* Set up virtqueue descriptor for status */
                desc = &vq_desc[(id + 2) % vq_size];
                desc->addr = (uint64_t)buf;
                desc->len = buf_len;
                desc->flags = is_read ? VRING_DESC_F_WRITE : 0;
                desc->next = 0;
        } else
                desc->flags &= ~VRING_DESC_F_NEXT;

        vq_avail->ring[vq_avail->idx % vq_size] = id;
        mb();
        vq_avail->idx += 1;

        /* Tell HV that the vq is ready */
        virtio_queue_notify(dev, vq);

	/* Wait for host to consume the descriptor */
	time = SLOF_GetTimer() + VIRTIO_TIMEOUT;
	while (*current_used_idx == last_used_idx) {
		// do something better
		mb();
		if (time < SLOF_GetTimer())
			break;
	}

        return 0;
}

/**
 * Initialize virtio-block device.
 * @param  dev  pointer to virtio device information
 */
int virtioscsi_init(struct virtio_device *dev)
{
        struct vring_avail *vq_avail;
        unsigned int idx = 0;
        int qsize = 0;

        /* Reset device */
        // XXX That will clear the virtq base. We need to move
        //     initializing it to here anyway
        //
        //     virtio_reset_device(dev);

        /* Acknowledge device. */
        virtio_set_status(dev, VIRTIO_STAT_ACKNOWLEDGE);

        /* Tell HV that we know how to drive the device. */
        virtio_set_status(dev, VIRTIO_STAT_ACKNOWLEDGE|VIRTIO_STAT_DRIVER);

        /* Device specific setup - we do not support special features right now */
        virtio_set_guest_features(dev,  0);

        while(1) {
                qsize = virtio_get_qsize(dev, idx);
                if (!qsize)
                        break;
                virtio_vring_size(qsize);

                vq_avail = virtio_get_vring_avail(dev, 0);
                vq_avail->flags = VRING_AVAIL_F_NO_INTERRUPT;
                vq_avail->idx = 0;
                idx++;
        }

	/* Tell HV that setup succeeded */
 	virtio_set_status(dev, VIRTIO_STAT_ACKNOWLEDGE|VIRTIO_STAT_DRIVER
                          |VIRTIO_STAT_DRIVER_OK);

	return 0;
}

/**
 * Shutdown the virtio-block device.
 * @param  dev  pointer to virtio device information
 */
void virtioscsi_shutdown(struct virtio_device *dev)
{
	/* Quiesce device */
	virtio_set_status(dev, VIRTIO_STAT_FAILED);

	/* Reset device */
	virtio_reset_device(dev);
}
