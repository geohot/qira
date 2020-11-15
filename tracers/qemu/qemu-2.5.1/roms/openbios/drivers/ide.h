#ifndef IDE_H
#define IDE_H

#include "hdreg.h"

/*
 * legacy ide ports
 */
#define IDEREG_DATA	0x00
#define IDEREG_ERROR	0x01
#define IDEREG_FEATURE	IDEREG_ERROR
#define IDEREG_NSECTOR	0x02
#define IDEREG_SECTOR	0x03
#define IDEREG_LCYL	0x04
#define IDEREG_HCYL	0x05
#define IDEREG_CURRENT	0x06
#define IDEREG_STATUS	0x07
#define IDEREG_COMMAND	IDEREG_STATUS
#define IDEREG_CONTROL	0x08
#define IDEREG_ASTATUS	IDEREG_CONTROL

/*
 * device control bits
 */
#define IDECON_NIEN	0x02
#define IDECON_SRST	0x04

/*
 * device head bits
 */
#define IDEHEAD_LBA	0x40
#define IDEHEAD_DEV0	0x00
#define IDEHEAD_DEV1	0x10

/*
 * status bytes
 */
#define ERR_STAT	0x01
#define DRQ_STAT	0x08
#define SEEK_STAT	0x10
#define WRERR_STAT	0x20
#define READY_STAT	0x40
#define BUSY_STAT	0x80

#define IREASON_CD	0x01
#define IREASON_IO	0x02

/*
 * ATA opcodes
 */
#define WIN_READ		0x20
#define WIN_READ_EXT		0x24
#define WIN_IDENTIFY		0xEC
#define WIN_PACKET		0xA0
#define WIN_IDENTIFY_PACKET	0xA1

/*
 * ATAPI opcodes
 */
#define ATAPI_TUR		0x00
#define ATAPI_READ_10		0x28
#define ATAPI_REQ_SENSE		0x03
#define ATAPI_START_STOP_UNIT	0x1b
#define ATAPI_READ_CAPACITY	0x25

/*
 * atapi sense keys
 */
#define ATAPI_SENSE_NOT_READY	0x02

/*
 * supported device types
 */
enum {
	ide_type_unknown,
	ide_type_ata,
	ide_type_atapi,
};

enum {
	ide_media_floppy = 0x00,
	ide_media_cdrom = 0x05,
	ide_media_optical = 0x07,
	ide_media_disk = 0x20,
};

/*
 * drive addressing
 */
enum {
	ide_chs = 1,
	ide_lba28,
	ide_lba48,
};

/*
 * simple ata command that works for everything (except 48-bit lba commands)
 */
struct ata_command {
        unsigned char *buffer;
	unsigned int buflen;

	/*
	 * data register
	 */
	unsigned char data;
	unsigned char feature;
	unsigned char nsector;
	unsigned char sector;
	unsigned char lcyl;
	unsigned char hcyl;
	unsigned char device_head;
	unsigned char command;
	unsigned char control;

	/*
	 * or tasklet, just for lba48 for now (above could be scrapped)
	 */
	unsigned char task[10];

	/*
	 * output
	 */
	unsigned char stat;
	unsigned int bytes;
};

struct atapi_command {
	unsigned char cdb[12];
	unsigned char *buffer;
	unsigned int buflen;
	unsigned char data_direction;

	unsigned char stat;
	unsigned char sense_valid;
	struct request_sense sense;
	unsigned char old_cdb;
};

struct ide_channel;

struct ide_drive {
	char		unit;		/* 0: master, 1: slave */
	char		present;	/* there or not */
	char		type;		/* ata or atapi */
	char		media;		/* disk, cdrom, etc */
	char		addressing;	/* chs/lba28/lba48 */

	char		model[41];	/* name */
	int		nr;

	unsigned long	sectors;

	unsigned int	max_sectors;

	/*
	 * for legacy chs crap
	 */
	unsigned int	cyl;
	unsigned int	head;
	unsigned int	sect;

	unsigned int bs;		/* block size */

	struct ide_channel *channel;
};

struct ide_channel {

	char name[32];
	struct ide_channel *next;

	/*
	 * either mmio or io_regs is set to indicate mmio or not
	 */
	unsigned long mmio;
	int io_regs[10];

	/*
	 * can be set to a mmio hook, default it legacy outb/inb
	 */
	void (*obide_outb)(struct ide_channel *chan,
			   unsigned char addr, unsigned int port);
	unsigned char (*obide_inb)(struct ide_channel *chan,
				   unsigned int port);
	void (*obide_insw)(struct ide_channel *chan,
			   unsigned int port, unsigned char *addr,
			   unsigned int count);
	void (*obide_outsw)(struct ide_channel *chan,
			    unsigned int port, unsigned char *addr,
			    unsigned int count);

	struct ide_drive drives[2];
	char selected;
	char present;

	/*
	 * only one can be busy per channel
	 */
	struct ata_command ata_cmd;
	struct atapi_command atapi_cmd;

};

enum {
	atapi_ddir_none,
	atapi_ddir_read,
	atapi_ddir_write,
};

static int ob_ide_atapi_request_sense(struct ide_drive *drive);

#endif
