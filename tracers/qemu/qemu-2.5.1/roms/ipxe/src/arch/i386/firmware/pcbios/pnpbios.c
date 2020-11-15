/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <realmode.h>
#include <pnpbios.h>

/** @file
 *
 * PnP BIOS
 *
 */

/** PnP BIOS structure */
struct pnp_bios {
	/** Signature
	 *
	 * Must be equal to @c PNP_BIOS_SIGNATURE
	 */
	uint32_t signature;
	/** Version as BCD (e.g. 1.0 is 0x10) */
	uint8_t version;
	/** Length of this structure */
	uint8_t length;
	/** System capabilities */
	uint16_t control;
	/** Checksum */
	uint8_t checksum;
} __attribute__ (( packed ));

/** Signature for a PnP BIOS structure */
#define PNP_BIOS_SIGNATURE \
	( ( '$' << 0 ) + ( 'P' << 8 ) + ( 'n' << 16 ) + ( 'P' << 24 ) )

/**
 * Test address for PnP BIOS structure
 *
 * @v offset		Offset within BIOS segment to test
 * @ret rc		Return status code
 */
static int is_pnp_bios ( unsigned int offset ) {
	union {
		struct pnp_bios pnp_bios;
		uint8_t bytes[256]; /* 256 is maximum length possible */
	} u;
	size_t len;
	unsigned int i;
	uint8_t sum = 0;

	/* Read start of header and verify signature */
	copy_from_real ( &u.pnp_bios, BIOS_SEG, offset, sizeof ( u.pnp_bios ));
	if ( u.pnp_bios.signature != PNP_BIOS_SIGNATURE )
		return -EINVAL;

	/* Read whole header and verify checksum */
	len = u.pnp_bios.length;
	copy_from_real ( &u.bytes, BIOS_SEG, offset, len );
	for ( i = 0 ; i < len ; i++ ) {
		sum += u.bytes[i];
	}
	if ( sum != 0 )
		return -EINVAL;

	DBG ( "Found PnP BIOS at %04x:%04x\n", BIOS_SEG, offset );

	return 0;
}

/**
 * Locate Plug-and-Play BIOS
 *
 * @ret pnp_offset	Offset of PnP BIOS structure within BIOS segment
 *
 * The PnP BIOS structure will be at BIOS_SEG:pnp_offset.  If no PnP
 * BIOS is found, -1 is returned.
 */
int find_pnp_bios ( void ) {
	static int pnp_offset = 0;

	if ( pnp_offset )
		return pnp_offset;

	for ( pnp_offset = 0 ; pnp_offset < 0x10000 ; pnp_offset += 0x10 ) {
		if ( is_pnp_bios ( pnp_offset ) == 0 )
			return pnp_offset;
	}

	pnp_offset = -1;
	return pnp_offset;
}
