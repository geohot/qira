#ifndef _IPXE_ELTORITO_H
#define _IPXE_ELTORITO_H

/**
 * @file
 *
 * El Torito bootable CD-ROM specification
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/iso9660.h>

/** An El Torito Boot Record Volume Descriptor (fixed portion) */
struct eltorito_descriptor_fixed {
	/** Descriptor type */
	uint8_t type;
	/** Identifier ("CD001") */
	uint8_t id[5];
	/** Version, must be 1 */
	uint8_t version;
	/** Boot system indicator; must be "EL TORITO SPECIFICATION" */
	uint8_t system_id[32];
} __attribute__ (( packed ));

/** An El Torito Boot Record Volume Descriptor */
struct eltorito_descriptor {
	/** Fixed portion */
	struct eltorito_descriptor_fixed fixed;
	/** Unused */
	uint8_t unused[32];
	/** Boot catalog sector */
	uint32_t sector;
} __attribute__ (( packed ));

/** El Torito Boot Record Volume Descriptor block address */
#define ELTORITO_LBA 17

/** An El Torito Boot Catalog Validation Entry */
struct eltorito_validation_entry {
	/** Header ID; must be 1 */
	uint8_t header_id;
	/** Platform ID
	 *
	 * 0 = 80x86
	 * 1 = PowerPC
	 * 2 = Mac
	 */
	uint8_t platform_id;
	/** Reserved */
	uint16_t reserved;
	/** ID string */
	uint8_t id_string[24];
	/** Checksum word */
	uint16_t checksum;
	/** Signature; must be 0xaa55 */
	uint16_t signature;
} __attribute__ (( packed ));

/** El Torito platform IDs */
enum eltorito_platform_id {
	ELTORITO_PLATFORM_X86 = 0x00,
	ELTORITO_PLATFORM_POWERPC = 0x01,
	ELTORITO_PLATFORM_MAC = 0x02,
};

/** A bootable entry in the El Torito Boot Catalog */
struct eltorito_boot_entry {
	/** Boot indicator
	 *
	 * Must be @c ELTORITO_BOOTABLE for a bootable ISO image
	 */
	uint8_t indicator;
	/** Media type
	 *
	 */
	uint8_t media_type;
	/** Load segment */
	uint16_t load_segment;
	/** System type */
	uint8_t filesystem;
	/** Unused */
	uint8_t reserved_a;
	/** Sector count */
	uint16_t length;
	/** Starting sector */
	uint32_t start;
	/** Unused */
	uint8_t reserved_b[20];
} __attribute__ (( packed ));

/** Boot indicator for a bootable ISO image */
#define ELTORITO_BOOTABLE 0x88

/** El Torito media types */
enum eltorito_media_type {
	/** No emulation */
	ELTORITO_NO_EMULATION = 0,
};

#endif /* _IPXE_ELTORITO_H */
