#ifndef _IPXE_BITMAP_H
#define _IPXE_BITMAP_H

/** @file
 *
 * Bitmaps for multicast downloads
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

/** A single block of bits within a bitmap */
typedef unsigned long bitmap_block_t;

/** Size of a block of bits (in bits) */
#define BITMAP_BLKSIZE ( sizeof ( bitmap_block_t ) * 8 )

/**
 * Block index within bitmap
 *
 * @v bit		Bit index
 * @ret index		Block index
 */
#define BITMAP_INDEX( bit ) ( (bit) / BITMAP_BLKSIZE )

/**
 * Block mask within bitmap
 *
 * @v bit		Bit index
 * @ret mask		Block mask
 */
#define BITMAP_MASK( bit ) ( 1UL << ( (bit) % BITMAP_BLKSIZE ) )

/** A bitmap */
struct bitmap {
	/** Bitmap data */
	bitmap_block_t *blocks;
	/** Length of the bitmap, in bits */
	unsigned int length;
	/** Index of first gap in the bitmap */
	unsigned int first_gap;
};

extern int bitmap_resize ( struct bitmap *bitmap, unsigned int new_length );
extern int bitmap_test ( struct bitmap *bitmap, unsigned int bit );
extern void bitmap_set ( struct bitmap *bitmap, unsigned int bit );

/**
 * Free bitmap resources
 *
 * @v bitmap		Bitmap
 */
static inline void bitmap_free ( struct bitmap *bitmap ) {
	free ( bitmap->blocks );
}

/**
 * Get first gap within bitmap
 *
 * @v bitmap		Bitmap
 * @ret first_gap	First gap
 *
 * The first gap is the first unset bit within the bitmap.
 */
static inline unsigned int bitmap_first_gap ( struct bitmap *bitmap ) {
	return bitmap->first_gap;
}

/**
 * Check to see if bitmap is full
 *
 * @v bitmap		Bitmap
 * @ret is_full		Bitmap is full
 *
 * The bitmap is full if it has no gaps (i.e. no unset bits).
 */
static inline int bitmap_full ( struct bitmap *bitmap ) {
	return ( bitmap->first_gap == bitmap->length );
}

#endif /* _IPXE_BITMAP_H */
