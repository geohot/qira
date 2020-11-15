/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdio.h>
#include <stdint.h>
#include <ipxe/crypto.h>
#include <ipxe/md5.h>

/**
 * Print an MD5 checksum with specified display address
 *
 * @v dispaddr		Display address
 * @v data		Data to checksum
 * @v len		Length of data
 */
void dbg_md5_da ( unsigned long dispaddr, const void *data,
		  unsigned long len ) {
	struct digest_algorithm *digest = &md5_algorithm;
	uint8_t digest_ctx[digest->ctxsize];
	uint8_t digest_out[digest->digestsize];
	unsigned int i;

	printf ( "md5sum ( %#08lx, %#lx ) = ", dispaddr, len );
	digest_init ( digest, digest_ctx );
	digest_update ( digest, digest_ctx, data, len );
	digest_final ( digest, digest_ctx, digest_out );
	for ( i = 0 ; i < sizeof ( digest_out ) ; i++ )
		printf ( "%02x", digest_out[i] );
	printf ( "\n" );
}
