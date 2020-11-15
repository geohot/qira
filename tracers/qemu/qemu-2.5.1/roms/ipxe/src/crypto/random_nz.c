/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
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

/** @file
 *
 * Random non-zero bytes
 *
 * The RSA algorithm requires the generation of random non-zero bytes,
 * i.e. bytes in the range [0x01,0xff].
 *
 * This algorithm is designed to comply with ANS X9.82 Part 1-2006
 * Section 9.2.1.  This standard is not freely available, but most of
 * the text appears to be shared with NIST SP 800-90, which can be
 * downloaded from
 *
 *     http://csrc.nist.gov/publications/nistpubs/800-90/SP800-90revised_March2007.pdf
 *
 * Where possible, references are given to both documents.  In the
 * case of any disagreement, ANS X9.82 takes priority over NIST SP
 * 800-90.  (In particular, note that some algorithms that are
 * Approved by NIST SP 800-90 are not Approved by ANS X9.82.)
 */

#include <stddef.h>
#include <stdint.h>
#include <ipxe/rbg.h>
#include <ipxe/random_nz.h>

/**
 * Get random non-zero bytes
 *
 * @v data		Output buffer
 * @v len		Length of output buffer
 * @ret rc		Return status code
 *
 * This algorithm is designed to be isomorphic to the Simple Discard
 * Method described in ANS X9.82 Part 1-2006 Section 9.2.1 (NIST SP
 * 800-90 Section B.5.1.1).
 */
int get_random_nz ( void *data, size_t len ) {
	uint8_t *bytes = data;
	int rc;

	while ( len ) {

		/* Generate random byte */
		if ( ( rc = rbg_generate ( NULL, 0, 0, bytes, 1 ) ) != 0 )
			return rc;

		/* Move to next byte if this byte is acceptable */
		if ( *bytes != 0 ) {
			bytes++;
			len--;
		}
	}

	return 0;
}
