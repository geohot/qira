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

#include <errno.h>
#include <ipxe/bitmap.h>

/** @file
 *
 * Bitmaps for multicast downloads
 *
 */

/**
 * Resize bitmap
 *
 * @v bitmap		Bitmap
 * @v new_length	New length of bitmap, in bits
 * @ret rc		Return status code
 */
int bitmap_resize ( struct bitmap *bitmap, unsigned int new_length ) {
	unsigned int old_num_blocks;
	unsigned int new_num_blocks;
	size_t new_size;
	bitmap_block_t *new_blocks;

	old_num_blocks = BITMAP_INDEX ( bitmap->length + BITMAP_BLKSIZE - 1 );
	new_num_blocks = BITMAP_INDEX ( new_length + BITMAP_BLKSIZE - 1 );

	if ( old_num_blocks != new_num_blocks ) {
		new_size = ( new_num_blocks * sizeof ( bitmap->blocks[0] ) );
		new_blocks = realloc ( bitmap->blocks, new_size );
		if ( ! new_blocks ) {
			DBGC ( bitmap, "Bitmap %p could not resize to %d "
			       "bits\n", bitmap, new_length );
			return -ENOMEM;
		}
		bitmap->blocks = new_blocks;
	}
	bitmap->length = new_length;

	while ( old_num_blocks < new_num_blocks ) {
		bitmap->blocks[old_num_blocks++] = 0;
	}

	DBGC ( bitmap, "Bitmap %p resized to %d bits\n", bitmap, new_length );
	return 0;
}

/**
 * Test bit in bitmap
 *
 * @v bitmap		Bitmap
 * @v bit		Bit index
 * @ret is_set		Bit is set
 */
int bitmap_test ( struct bitmap *bitmap, unsigned int bit ) {
	unsigned int index = BITMAP_INDEX ( bit );
        bitmap_block_t mask = BITMAP_MASK ( bit );

	if ( bit >= bitmap->length )
		return 0;
	return ( ( bitmap->blocks[index] & mask ) != 0 );
}

/**
 * Set bit in bitmap
 *
 * @v bitmap		Bitmap
 * @v bit		Bit index
 */
void bitmap_set ( struct bitmap *bitmap, unsigned int bit ) {
	unsigned int index = BITMAP_INDEX ( bit );
        bitmap_block_t mask = BITMAP_MASK ( bit );

	DBGC ( bitmap, "Bitmap %p setting bit %d\n", bitmap, bit );

	/* Update bitmap */
	bitmap->blocks[index] |= mask;

	/* Update first gap counter */
	while ( bitmap_test ( bitmap, bitmap->first_gap ) ) {
		bitmap->first_gap++;
	}
}
