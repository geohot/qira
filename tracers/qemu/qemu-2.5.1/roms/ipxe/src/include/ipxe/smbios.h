#ifndef _IPXE_SMBIOS_H
#define _IPXE_SMBIOS_H

/** @file
 *
 * System Management BIOS
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/api.h>
#include <config/general.h>
#include <ipxe/uaccess.h>

/**
 * Provide an SMBIOS API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @v _func		Implementing function
 */
#define PROVIDE_SMBIOS( _subsys, _api_func, _func ) \
	PROVIDE_SINGLE_API ( SMBIOS_PREFIX_ ## _subsys, _api_func, _func )

/* Include all architecture-independent SMBIOS API headers */
#include <ipxe/efi/efi_smbios.h>
#include <ipxe/linux/linux_smbios.h>

/* Include all architecture-dependent SMBIOS API headers */
#include <bits/smbios.h>

/** Signature for SMBIOS entry point */
#define SMBIOS_SIGNATURE \
        ( ( '_' << 0 ) + ( 'S' << 8 ) + ( 'M' << 16 ) + ( '_' << 24 ) )

/**
 * SMBIOS entry point
 *
 * This is the single table which describes the list of SMBIOS
 * structures.  It is located by scanning through the BIOS segment.
 */
struct smbios_entry {
	/** Signature
	 *
	 * Must be equal to SMBIOS_SIGNATURE
	 */
	uint32_t signature;
	/** Checksum */
	uint8_t checksum;
	/** Length */
	uint8_t len;
	/** Major version */
	uint8_t major;
	/** Minor version */
	uint8_t minor;
	/** Maximum structure size */
	uint16_t max;
	/** Entry point revision */
	uint8_t revision;
	/** Formatted area */
	uint8_t formatted[5];
	/** DMI Signature */
	uint8_t dmi_signature[5];
	/** DMI checksum */
	uint8_t dmi_checksum;
	/** Structure table length */
	uint16_t smbios_len;
	/** Structure table address */
	uint32_t smbios_address;
	/** Number of SMBIOS structures */
	uint16_t smbios_count;
	/** BCD revision */
	uint8_t bcd_revision;
} __attribute__ (( packed ));

/** An SMBIOS structure header */
struct smbios_header {
	/** Type */
	uint8_t type;
	/** Length */
	uint8_t len;
	/** Handle */
	uint16_t handle;
} __attribute__ (( packed ));

/** SMBIOS structure descriptor */
struct smbios_structure {
	/** Copy of SMBIOS structure header */
	struct smbios_header header;
	/** Offset of structure within SMBIOS */
	size_t offset;
	/** Length of strings section */
	size_t strings_len;
};

/** SMBIOS system information structure */
struct smbios_system_information {
	/** SMBIOS structure header */
	struct smbios_header header;
	/** Manufacturer string */
	uint8_t manufacturer;
	/** Product string */
	uint8_t product;
	/** Version string */
	uint8_t version;
	/** Serial number string */
	uint8_t serial;
	/** UUID */
	uint8_t uuid[16];
	/** Wake-up type */
	uint8_t wakeup;
} __attribute__ (( packed ));

/** SMBIOS system information structure type */
#define SMBIOS_TYPE_SYSTEM_INFORMATION 1

/** SMBIOS base board information structure */
struct smbios_base_board_information {
	/** SMBIOS structure header */
	struct smbios_header header;
	/** Manufacturer string */
	uint8_t manufacturer;
	/** Product string */
	uint8_t product;
	/** Version string */
	uint8_t version;
	/** Serial number string */
	uint8_t serial;
} __attribute__ (( packed ));

/** SMBIOS base board information structure type */
#define SMBIOS_TYPE_BASE_BOARD_INFORMATION 2

/** SMBIOS enclosure information structure */
struct smbios_enclosure_information {
	/** SMBIOS structure header */
	struct smbios_header header;
	/** Manufacturer string */
	uint8_t manufacturer;
	/** Type string */
	uint8_t type;
	/** Version string */
	uint8_t version;
	/** Serial number string */
	uint8_t serial;
	/** Asset tag */
	uint8_t asset_tag;
} __attribute__ (( packed ));

/** SMBIOS enclosure information structure type */
#define SMBIOS_TYPE_ENCLOSURE_INFORMATION 3

/**
 * SMBIOS entry point descriptor
 *
 * This contains the information from the SMBIOS entry point that we
 * care about.
 */
struct smbios {
	/** Start of SMBIOS structures */
	userptr_t address;
	/** Length of SMBIOS structures */
	size_t len;
	/** Number of SMBIOS structures */
	unsigned int count;
	/** SMBIOS version */
	uint16_t version;
};

/**
 * Calculate SMBIOS version
 *
 * @v major		Major version
 * @v minor		Minor version
 * @ret version		SMBIOS version
 */
#define SMBIOS_VERSION( major, minor ) ( ( (major) << 8 ) | (minor) )

extern int find_smbios ( struct smbios *smbios );
extern int find_smbios_entry ( userptr_t start, size_t len,
			       struct smbios_entry *entry );
extern int find_smbios_structure ( unsigned int type, unsigned int instance,
				   struct smbios_structure *structure );
extern int read_smbios_structure ( struct smbios_structure *structure,
				   void *data, size_t len );
extern int read_smbios_string ( struct smbios_structure *structure,
				unsigned int index,
				void *data, size_t len );
extern int smbios_version ( void );

#endif /* _IPXE_SMBIOS_H */
