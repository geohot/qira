#ifndef _VIRTIO_SCSI_H
#define _VIRTIO_SCSI_H

#define VIRTIO_SCSI_CDB_SIZE      32
#define VIRTIO_SCSI_SENSE_SIZE    96

struct virtio_scsi_config
{
    u32 num_queues;
    u32 seg_max;
    u32 max_sectors;
    u32 cmd_per_lun;
    u32 event_info_size;
    u32 sense_size;
    u32 cdb_size;
    u16 max_channel;
    u16 max_target;
    u32 max_lun;
} __attribute__((packed));

/* This is the first element of the "out" scatter-gather list. */
struct virtio_scsi_req_cmd {
    u8 lun[8];
    u64 id;
    u8 task_attr;
    u8 prio;
    u8 crn;
    char cdb[VIRTIO_SCSI_CDB_SIZE];
} __attribute__((packed));

/* This is the first element of the "in" scatter-gather list. */
struct virtio_scsi_resp_cmd {
    u32 sense_len;
    u32 residual;
    u16 status_qualifier;
    u8 status;
    u8 response;
    u8 sense[VIRTIO_SCSI_SENSE_SIZE];
} __attribute__((packed));

#define VIRTIO_SCSI_S_OK            0

struct disk_op_s;
int virtio_scsi_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize);
void virtio_scsi_setup(void);

#endif /* _VIRTIO_SCSI_H */
