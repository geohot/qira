/*
 * Little-endian CRC32 implementation.
 *
 * Copyright (c) 2009 Joshua Oreman <oremanj@rwcr.net>.
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
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/crc32.h>

#define CRCPOLY		0xedb88320

/**
 * Calculate 32-bit little-endian CRC checksum
 *
 * @v seed	Initial value
 * @v data	Data to checksum
 * @v len	Length of data
 *
 * Usually @a seed is initially zero or all one bits, depending on the
 * protocol. To continue a CRC checksum over multiple calls, pass the
 * return value from one call as the @a seed parameter to the next.
 */
u32 crc32_le ( u32 seed, const void *data, size_t len )
{
	u32 crc = seed;
	const u8 *src = data;
	u32 mult;
	int i;

	while ( len-- ) {
		crc ^= *src++;
		for ( i = 0; i < 8; i++ ) {
			mult = ( crc & 1 ) ? CRCPOLY : 0;
			crc = ( crc >> 1 ) ^ mult;
		}
	}

	return crc;
}
