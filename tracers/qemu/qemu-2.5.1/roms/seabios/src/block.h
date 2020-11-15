#ifndef __BLOCK_H
#define __BLOCK_H

#include "types.h" // u32


/****************************************************************
 * Disk command request
 ****************************************************************/

struct disk_op_s {
    u64 lba;
    void *buf_fl;
    struct drive_s *drive_gf;
    u16 count;
    u8 command;
};

#define CMD_RESET   0x00
#define CMD_READ    0x02
#define CMD_WRITE   0x03
#define CMD_VERIFY  0x04
#define CMD_FORMAT  0x05
#define CMD_SEEK    0x07
#define CMD_ISREADY 0x10


/****************************************************************
 * Global storage
 ****************************************************************/

struct chs_s {
    u16 head;
    u16 cylinder;
    u16 sector;
    u16 pad;
};

struct drive_s {
    u8 type;            // Driver type (DTYPE_*)
    u8 floppy_type;     // Type of floppy (only for floppy drives).
    struct chs_s lchs;  // Logical CHS
    u64 sectors;        // Total sectors count
    u32 cntl_id;        // Unique id for a given driver type.
    u8 removable;       // Is media removable (currently unused)

    // Info for EDD calls
    u8 translation;     // type of translation
    u16 blksize;        // block size
    struct chs_s pchs;  // Physical CHS
};

#define DISK_SECTOR_SIZE  512
#define CDROM_SECTOR_SIZE 2048

#define DTYPE_NONE         0x00
#define DTYPE_FLOPPY       0x10
#define DTYPE_ATA          0x20
#define DTYPE_ATA_ATAPI    0x21
#define DTYPE_RAMDISK      0x30
#define DTYPE_CDEMU        0x40
#define DTYPE_AHCI         0x50
#define DTYPE_AHCI_ATAPI   0x51
#define DTYPE_VIRTIO_SCSI  0x60
#define DTYPE_VIRTIO_BLK   0x61
#define DTYPE_USB          0x70
#define DTYPE_USB_32       0x71
#define DTYPE_UAS          0x72
#define DTYPE_UAS_32       0x73
#define DTYPE_LSI_SCSI     0x80
#define DTYPE_ESP_SCSI     0x81
#define DTYPE_MEGASAS      0x82
#define DTYPE_PVSCSI       0x83
#define DTYPE_SDCARD       0x90

#define MAXDESCSIZE 80

#define TRANSLATION_NONE  0
#define TRANSLATION_LBA   1
#define TRANSLATION_LARGE 2
#define TRANSLATION_RECHS 3

#define EXTTYPE_FLOPPY 0
#define EXTTYPE_HD 1
#define EXTTYPE_CD 2

#define EXTSTART_HD 0x80
#define EXTSTART_CD 0xE0


/****************************************************************
 * Function defs
 ****************************************************************/

// block.c
extern u8 FloppyCount, CDCount;
extern u8 *bounce_buf_fl;
struct drive_s *getDrive(u8 exttype, u8 extdriveoffset);
int getDriveId(u8 exttype, struct drive_s *drive);
void map_floppy_drive(struct drive_s *drive);
void map_hd_drive(struct drive_s *drive);
void map_cd_drive(struct drive_s *drive);
struct int13dpt_s;
int fill_edd(u16 seg, struct int13dpt_s *param_far, struct drive_s *drive_gf);
int process_op(struct disk_op_s *op);
int send_disk_op(struct disk_op_s *op);
int create_bounce_buf(void);

#endif // block.h
