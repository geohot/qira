#ifndef _IPXE_ISO9660_H
#define _IPXE_ISO9660_H

/**
 * @file
 *
 * ISO9660 CD-ROM specification
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

/** ISO9660 block size */
#define ISO9660_BLKSIZE 2048

/** An ISO9660 Primary Volume Descriptor (fixed portion) */
struct iso9660_primary_descriptor_fixed {
	/** Descriptor type */
	uint8_t type;
	/** Identifier ("CD001") */
	uint8_t id[5];
} __attribute__ (( packed ));

/** An ISO9660 Primary Volume Descriptor */
struct iso9660_primary_descriptor {
	/** Fixed portion */
	struct iso9660_primary_descriptor_fixed fixed;
} __attribute__ (( packed ));

/** ISO9660 Primary Volume Descriptor type */
#define ISO9660_TYPE_PRIMARY 0x01

/** ISO9660 Primary Volume Descriptor block address */
#define ISO9660_PRIMARY_LBA 16

/** ISO9660 Boot Volume Descriptor type */
#define ISO9660_TYPE_BOOT 0x00

/** ISO9660 identifier */
#define ISO9660_ID "CD001"

#endif /* _IPXE_ISO9660_H */
