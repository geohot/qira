#ifndef BIOS_DISKS_H
#define BIOS_DISKS_H

#include "dev.h"

/*
 * Constants
 *
 */

#define	BIOS_DISK_MAX_NAME_LEN	6

struct bios_disk_sector {
	char data[512];
};

/*
 * The location of a BIOS disk
 *
 */
struct bios_disk_loc {
	uint8_t drive;
};

/*
 * A physical BIOS disk device
 *
 */
struct bios_disk_device {
	char name[BIOS_DISK_MAX_NAME_LEN];
	uint8_t drive;
	uint8_t type;
};

/*
 * A BIOS disk driver, with a valid device ID range and naming
 * function.
 *
 */
struct bios_disk_driver {
	void ( *fill_drive_name ) ( char *buf, uint8_t drive );
	uint8_t min_drive;
	uint8_t max_drive;
};

/*
 * Define a BIOS disk driver
 *
 */
#define BIOS_DISK_DRIVER( _name, _fill_drive_name, _min_drive, _max_drive )   \
	static struct bios_disk_driver _name = {			      \
		.fill_drive_name = _fill_drive_name,			      \
		.min_drive = _min_drive,				      \
		.max_drive = _max_drive,				      \
	}

/*
 * Functions in bios_disks.c
 *
 */


/*
 * bios_disk bus global definition
 *
 */
extern struct bus_driver bios_disk_driver;

#endif /* BIOS_DISKS_H */
