#ifndef _IPXE_UUID_H
#define _IPXE_UUID_H

/** @file
 *
 * Universally unique IDs
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <byteswap.h>

/** A universally unique ID */
union uuid {
	/** Canonical form (00000000-0000-0000-0000-000000000000) */
	struct {
		/** 8 hex digits, big-endian */
		uint32_t a;
		/** 2 hex digits, big-endian */
		uint16_t b;
		/** 2 hex digits, big-endian */
		uint16_t c;
		/** 2 hex digits, big-endian */
		uint16_t d;
		/** 12 hex digits, big-endian */
		uint8_t e[6];
	} canonical;
	uint8_t raw[16];
};

/**
 * Change UUID endianness
 *
 * @v uuid		UUID
 *
 * RFC4122 defines UUIDs as being encoded in network byte order, but
 * leaves some wriggle room for "explicit application or presentation
 * protocol specification to the contrary".  PXE, EFI and SMBIOS
 * (versions 2.6 and above) treat the first three fields as being
 * little-endian.
 */
static inline void uuid_mangle ( union uuid *uuid ) {

	__bswap_32s ( &uuid->canonical.a );
	__bswap_16s ( &uuid->canonical.b );
	__bswap_16s ( &uuid->canonical.c );
}

extern char * uuid_ntoa ( const union uuid *uuid );

#endif /* _IPXE_UUID_H */
