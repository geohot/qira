// Standard disk BIOS definitions.
#ifndef __DISK_H
#define __DISK_H

#include "types.h" // u8

#define DISK_RET_SUCCESS       0x00
#define DISK_RET_EPARAM        0x01
#define DISK_RET_EADDRNOTFOUND 0x02
#define DISK_RET_EWRITEPROTECT 0x03
#define DISK_RET_ECHANGED      0x06
#define DISK_RET_EBOUNDARY     0x09
#define DISK_RET_EBADTRACK     0x0c
#define DISK_RET_ECONTROLLER   0x20
#define DISK_RET_ETIMEOUT      0x80
#define DISK_RET_ENOTLOCKED    0xb0
#define DISK_RET_ELOCKED       0xb1
#define DISK_RET_ENOTREMOVABLE 0xb2
#define DISK_RET_ETOOMANYLOCKS 0xb4
#define DISK_RET_EMEDIA        0xC0
#define DISK_RET_ENOTREADY     0xAA


/****************************************************************
 * Interface structs
 ****************************************************************/

// Bios disk structures.
struct int13ext_s {
    u8  size;
    u8  reserved;
    u16 count;
    struct segoff_s data;
    u64 lba;
} PACKED;

// DPTE definition
struct dpte_s {
    u16 iobase1;
    u16 iobase2;
    u8  prefix;
    u8  unused;
    u8  irq;
    u8  blkcount;
    u8  dma;
    u8  pio;
    u16 options;
    u16 reserved;
    u8  revision;
    u8  checksum;
};

// Disk Physical Table definition
struct int13dpt_s {
    u16 size;
    u16 infos;
    u32 cylinders;
    u32 heads;
    u32 spt;
    u64 sector_count;
    u16 blksize;
    struct segoff_s dpte;
    u16 key;
    u8  dpi_length;
    u8  reserved1;
    u16 reserved2;
    u8  host_bus[4];
    u8  iface_type[8];
    u64 iface_path;
    union {
        struct {
            u64 device_path;
            u8  reserved3;
            u8  checksum;
        } phoenix;
        struct {
            u64 device_path[2];
            u8  reserved3;
            u8  checksum;
        } t13;
    };
} PACKED;

// Floppy info
struct fdpt_s {
    u16 cylinders;
    u8 heads;
    u8 a0h_signature;
    u8 phys_sectors;
    u16 precompensation;
    u8 reserved;
    u8 drive_control_byte;
    u16 phys_cylinders;
    u8 phys_heads;
    u16 landing_zone;
    u8 sectors;
    u8 checksum;
} PACKED;

// Floppy "Disk Base Table"
struct floppy_dbt_s {
    u8 specify1;
    u8 specify2;
    u8 shutoff_ticks;
    u8 bps_code;
    u8 sectors;
    u8 interblock_len;
    u8 data_len;
    u8 gap_len;
    u8 fill_byte;
    u8 settle_time;
    u8 startup_time;
} PACKED;

struct floppy_ext_dbt_s {
    struct floppy_dbt_s dbt;
    // Extra fields
    u8 max_track;
    u8 data_rate;
    u8 drive_type;
} PACKED;


/****************************************************************
 * Master boot record
 ****************************************************************/

struct packed_chs_s {
    u8 heads;
    u8 sptcyl;
    u8 cyllow;
} PACKED;

struct partition_s {
    u8 status;
    struct packed_chs_s first;
    u8 type;
    struct packed_chs_s last;
    u32 lba;
    u32 count;
} PACKED;

struct mbr_s {
    u8 code[440];
    // 0x01b8
    u32 diskseg;
    // 0x01bc
    u16 null;
    // 0x01be
    struct partition_s partitions[4];
    // 0x01fe
    u16 signature;
} PACKED;

#define MBR_SIGNATURE 0xaa55


/****************************************************************
 * ElTorito CDROM interface
 ****************************************************************/

struct eltorito_s {
    u8 size;
    u8 media;
    u8 emulated_drive;
    u8 controller_index;
    u32 ilba;
    u16 device_spec;
    u16 buffer_segment;
    u16 load_segment;
    u16 sector_count;
    struct packed_chs_s chs;
} PACKED;

#endif // disk.h
