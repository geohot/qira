#ifndef _VIRTIO_BLK_H
#define _VIRTIO_BLK_H

struct virtio_blk_config
{
    u64 capacity;
    u32 size_max;
    u32 seg_max;
    u16 cylinders;
    u8 heads;
    u8 sectors;
    u32 blk_size;
    u8 physical_block_exp;
    u8 alignment_offset;
    u16 min_io_size;
    u32 opt_io_size;
} __attribute__((packed));

#define VIRTIO_BLK_F_BLK_SIZE 6

/* These two define direction. */
#define VIRTIO_BLK_T_IN         0
#define VIRTIO_BLK_T_OUT        1

/* This is the first element of the read scatter-gather list. */
struct virtio_blk_outhdr {
    /* VIRTIO_BLK_T* */
    u32 type;
    /* io priority. */
    u32 ioprio;
    /* Sector (ie. 512 byte offset) */
    u64 sector;
};

#define VIRTIO_BLK_S_OK         0
#define VIRTIO_BLK_S_IOERR      1
#define VIRTIO_BLK_S_UNSUPP     2

struct disk_op_s;
int process_virtio_blk_op(struct disk_op_s *op);
void virtio_blk_setup(void);

#endif /* _VIRTIO_BLK_H */
