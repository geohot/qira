/*
 * Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <errno.h>
#include <assert.h>
#include <ipxe/string.h>
#include <ipxe/vsprintf.h>
#include <ipxe/base16.h>

/** @file
 *
 * Base16 encoding
 *
 */

/**
 * Encode hexadecimal string (with optional byte separator character)
 *
 * @v separator		Byte separator character, or 0 for no separator
 * @v raw		Raw data
 * @v raw_len		Length of raw data
 * @v data		Buffer
 * @v len		Length of buffer
 * @ret len		Encoded length
 */
size_t hex_encode ( char separator, const void *raw, size_t raw_len,
		    char *data, size_t len ) {
	const uint8_t *bytes = raw;
	const char delimiter[2] = { separator, '\0' };
	size_t used = 0;
	unsigned int i;

	if ( len )
		data[0] = 0; /* Ensure that a terminating NUL exists */
	for ( i = 0 ; i < raw_len ; i++ ) {
		used += ssnprintf ( ( data + used ), ( len - used ),
				    "%s%02x", ( used ? delimiter : "" ),
				    bytes[i] );
	}
	return used;
}

/**
 * Decode hexadecimal string (with optional byte separator character)
 *
 * @v separator		Byte separator character, or 0 for no separator
 * @v encoded		Encoded string
 * @v data		Buffer
 * @v len		Length of buffer
 * @ret len		Length of data, or negative error
 */
int hex_decode ( char separator, const char *encoded, void *data, size_t len ) {
	uint8_t *out = data;
	unsigned int count = 0;
	unsigned int sixteens;
	unsigned int units;

	while ( *encoded ) {

		/* Check separator, if applicable */
		if ( count && separator && ( ( *(encoded++) != separator ) ) )
			return -EINVAL;

		/* Extract digits.  Note that either digit may be NUL,
		 * which would be interpreted as an invalid value by
		 * digit_value(); there is therefore no need for an
		 * explicit end-of-string check.
		 */
		sixteens = digit_value ( *(encoded++) );
		if ( sixteens >= 16 )
			return -EINVAL;
		units = digit_value ( *(encoded++) );
		if ( units >= 16 )
			return -EINVAL;

		/* Store result */
		if ( count < len )
			out[count] = ( ( sixteens << 4 ) | units );
		count++;

	}
	return count;
}
