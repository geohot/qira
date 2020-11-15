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

/*
 * Virtio SCSI Host device definitions.
 * See Virtio Spec, Appendix I, for details
 */

#ifndef _VIRTIO_SCSI_H
#define _VIRTIO_SCSI_H

#define VIRTIO_SCSI_CDB_SIZE      32
#define VIRTIO_SCSI_SENSE_SIZE    96

#define VIRTIO_SCSI_CONTROL_VQ     0
#define VIRTIO_SCSI_EVENT_VQ       1
#define VIRTIO_SCSI_REQUEST_VQ     2

struct virtio_scsi_config
{
    uint32_t num_queues;
    uint32_t seg_max;
    uint32_t max_sectors;
    uint32_t cmd_per_lun;
    uint32_t event_info_size;
    uint32_t sense_size;
    uint32_t cdb_size;
    uint16_t max_channel;
    uint16_t max_target;
    uint32_t max_lun;
} __attribute__((packed));

/* This is the first element of the "out" scatter-gather list. */
struct virtio_scsi_req_cmd {
    uint8_t lun[8];
    uint64_t tag;
    uint8_t task_attr;
    uint8_t prio;
    uint8_t crn;
    char cdb[VIRTIO_SCSI_CDB_SIZE];
};

/* This is the first element of the "in" scatter-gather list. */
struct virtio_scsi_resp_cmd {
    uint32_t sense_len;
    uint32_t residual;
    uint16_t status_qualifier;
    uint8_t status;
    uint8_t response;
    uint8_t sense[VIRTIO_SCSI_SENSE_SIZE];
};

extern int virtioscsi_init(struct virtio_device *dev);
extern void virtioscsi_shutdown(struct virtio_device *dev);
extern int virtioscsi_send(struct virtio_device *dev,
			   struct virtio_scsi_req_cmd *req,
			   struct virtio_scsi_resp_cmd *resp,
			   int is_read, void *buf, uint64_t buf_len);

#endif /*  _VIRTIO_SCSI_H */
