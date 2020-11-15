#ifndef _IPXE_ACPI_H
#define _IPXE_ACPI_H

/** @file
 *
 * ACPI data structures
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/interface.h>

/**
 * An ACPI description header
 *
 * This is the structure common to the start of all ACPI system
 * description tables.
 */
struct acpi_description_header {
	/** ACPI signature (4 ASCII characters) */
	uint32_t signature;
	/** Length of table, in bytes, including header */
	uint32_t length;
	/** ACPI Specification minor version number */
	uint8_t revision;
	/** To make sum of entire table == 0 */
	uint8_t checksum;
	/** OEM identification */
	char oem_id[6];
	/** OEM table identification */
	char oem_table_id[8];
	/** OEM revision number */
	uint32_t oem_revision;
	/** ASL compiler vendor ID */
	char asl_compiler_id[4];
	/** ASL compiler revision number */
	uint32_t asl_compiler_revision;
} __attribute__ (( packed ));

/**
 * Build ACPI signature
 *
 * @v a			First character of ACPI signature
 * @v b			Second character of ACPI signature
 * @v c			Third character of ACPI signature
 * @v d			Fourth character of ACPI signature
 * @ret signature	ACPI signature
 */
#define ACPI_SIGNATURE( a, b, c, d ) \
	( ( (a) << 0 ) | ( (b) << 8 ) | ( (c) << 16 ) | ( (d) << 24 ) )

extern int acpi_describe ( struct interface *interface,
			   struct acpi_description_header *acpi, size_t len );
#define acpi_describe_TYPE( object_type )				\
	typeof ( int ( object_type,					\
		       struct acpi_description_header *acpi,		\
		       size_t len ) )

extern void acpi_fix_checksum ( struct acpi_description_header *acpi );

#endif /* _IPXE_ACPI_H */
