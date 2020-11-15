/*
 * Copyright (C) 2009 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/base64.h>

/** @file
 *
 * Base64 encoding
 *
 */

static const char base64[64] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Base64-encode data
 *
 * @v raw		Raw data
 * @v raw_len		Length of raw data
 * @v data		Buffer
 * @v len		Length of buffer
 * @ret len		Encoded length
 */
size_t base64_encode ( const void *raw, size_t raw_len, char *data,
		       size_t len ) {
	const uint8_t *raw_bytes = ( ( const uint8_t * ) raw );
	size_t raw_bit_len = ( 8 * raw_len );
	size_t used = 0;
	unsigned int bit;
	unsigned int byte;
	unsigned int shift;
	unsigned int tmp;

	for ( bit = 0 ; bit < raw_bit_len ; bit += 6, used++ ) {
		byte = ( bit / 8 );
		shift = ( bit % 8 );
		tmp = ( raw_bytes[byte] << shift );
		if ( ( byte + 1 ) < raw_len )
			tmp |= ( raw_bytes[ byte + 1 ] >> ( 8 - shift ) );
		tmp = ( ( tmp >> 2 ) & 0x3f );
		if ( used < len )
			data[used] = base64[tmp];
	}
	for ( ; ( bit % 8 ) != 0 ; bit += 6, used++ ) {
		if ( used < len )
			data[used] = '=';
	}
	if ( used < len )
		data[used] = '\0';
	if ( len )
		data[ len - 1 ] = '\0'; /* Ensure terminator exists */

	return used;
}

/**
 * Base64-decode string
 *
 * @v encoded		Encoded string
 * @v data		Buffer
 * @v len		Length of buffer
 * @ret len		Length of data, or negative error
 */
int base64_decode ( const char *encoded, void *data, size_t len ) {
	const char *in = encoded;
	uint8_t *out = data;
	uint8_t in_char;
	char *match;
	int in_bits;
	unsigned int bit = 0;
	unsigned int pad_count = 0;
	size_t offset;

	/* Zero the output buffer */
	memset ( data, 0, len );

	/* Decode string */
	while ( ( in_char = *(in++) ) ) {

		/* Ignore whitespace characters */
		if ( isspace ( in_char ) )
			continue;

		/* Process pad characters */
		if ( in_char == '=' ) {
			if ( pad_count >= 2 ) {
				DBG ( "Base64-encoded string \"%s\" has too "
				      "many pad characters\n", encoded );
				return -EINVAL;
			}
			pad_count++;
			bit -= 2; /* unused_bits = ( 2 * pad_count ) */
			continue;
		}
		if ( pad_count ) {
			DBG ( "Base64-encoded string \"%s\" has invalid pad "
			      "sequence\n", encoded );
			return -EINVAL;
		}

		/* Process normal characters */
		match = strchr ( base64, in_char );
		if ( ! match ) {
			DBG ( "Base64-encoded string \"%s\" contains invalid "
			      "character '%c'\n", encoded, in_char );
			return -EINVAL;
		}
		in_bits = ( match - base64 );

		/* Add to raw data */
		in_bits <<= 2;
		offset = ( bit / 8 );
		if ( offset < len )
			out[offset] |= ( in_bits >> ( bit % 8 ) );
		offset++;
		if ( offset < len )
			out[offset] |= ( in_bits << ( 8 - ( bit % 8 ) ) );
		bit += 6;
	}

	/* Check that we decoded a whole number of bytes */
	if ( ( bit % 8 ) != 0 ) {
		DBG ( "Base64-encoded string \"%s\" has invalid bit length "
		      "%d\n", encoded, bit );
		return -EINVAL;
	}

	/* Return length in bytes */
	return ( bit / 8 );
}
