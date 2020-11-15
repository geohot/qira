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
#include <stdio.h>
#include <byteswap.h>
#include <ipxe/uuid.h>

/** @file
 *
 * Universally unique IDs
 *
 */

/**
 * Convert UUID to printable string
 *
 * @v uuid		UUID
 * @ret string		UUID in canonical form
 */
char * uuid_ntoa ( const union uuid *uuid ) {
	static char buf[37]; /* "00000000-0000-0000-0000-000000000000" */

	sprintf ( buf, "%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
		  be32_to_cpu ( uuid->canonical.a ),
		  be16_to_cpu ( uuid->canonical.b ),
		  be16_to_cpu ( uuid->canonical.c ),
		  be16_to_cpu ( uuid->canonical.d ),
		  uuid->canonical.e[0], uuid->canonical.e[1],
		  uuid->canonical.e[2], uuid->canonical.e[3],
		  uuid->canonical.e[4], uuid->canonical.e[5] );
	return buf;
}
