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

#include <ipxe/bitbash.h>

/** @file
 *
 * Bit-bashing interfaces
 *
 */

/**
 * Set/clear output bit
 *
 * @v basher		Bit-bashing interface
 * @v bit_id		Bit number
 * @v data		Value to write
 * 
 * If @c data is 0, a logic 0 will be written.  If @c data is
 * non-zero, a logic 1 will be written.
 */
void write_bit ( struct bit_basher *basher, unsigned int bit_id,
		 unsigned long data ) {
	basher->op->write ( basher, bit_id, ( data ? -1UL : 0 ) );
}

/**
 * Read input bit
 *
 * @v basher		Bit-bashing interface
 * @v bit_id		Bit number
 * @ret data		Value read
 *
 * @c data will always be either 0 or -1UL.  The idea is that the
 * caller can simply binary-AND the returned value with whatever mask
 * it needs to apply.
 */
int read_bit ( struct bit_basher *basher, unsigned int bit_id ) {
	return ( basher->op->read ( basher, bit_id ) ? -1UL : 0 );
}
