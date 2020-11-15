/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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
#include <initrd.h>
#include <ipxe/image.h>
#include <ipxe/uaccess.h>
#include <ipxe/init.h>
#include <ipxe/memblock.h>

/** @file
 *
 * Initial ramdisk (initrd) reshuffling
 *
 */

/** Maximum address available for initrd */
userptr_t initrd_top;

/** Minimum address available for initrd */
userptr_t initrd_bottom;

/**
 * Squash initrds as high as possible in memory
 *
 * @v top		Highest possible address
 * @ret used		Lowest address used by initrds
 */
static userptr_t initrd_squash_high ( userptr_t top ) {
	userptr_t current = top;
	struct image *initrd;
	struct image *highest;
	size_t len;

	/* Squash up any initrds already within or below the region */
	while ( 1 ) {

		/* Find the highest image not yet in its final position */
		highest = NULL;
		for_each_image ( initrd ) {
			if ( ( userptr_sub ( initrd->data, current ) < 0 ) &&
			     ( ( highest == NULL ) ||
			       ( userptr_sub ( initrd->data,
					       highest->data ) > 0 ) ) ) {
				highest = initrd;
			}
		}
		if ( ! highest )
			break;

		/* Move this image to its final position */
		len = ( ( highest->len + INITRD_ALIGN - 1 ) &
			~( INITRD_ALIGN - 1 ) );
		current = userptr_sub ( current, len );
		DBGC ( &images, "INITRD squashing %s [%#08lx,%#08lx)->"
		       "[%#08lx,%#08lx)\n", highest->name,
		       user_to_phys ( highest->data, 0 ),
		       user_to_phys ( highest->data, highest->len ),
		       user_to_phys ( current, 0 ),
		       user_to_phys ( current, highest->len ) );
		memmove_user ( current, 0, highest->data, 0, highest->len );
		highest->data = current;
	}

	/* Copy any remaining initrds (e.g. embedded images) to the region */
	for_each_image ( initrd ) {
		if ( userptr_sub ( initrd->data, top ) >= 0 ) {
			len = ( ( initrd->len + INITRD_ALIGN - 1 ) &
				~( INITRD_ALIGN - 1 ) );
			current = userptr_sub ( current, len );
			DBGC ( &images, "INITRD copying %s [%#08lx,%#08lx)->"
			       "[%#08lx,%#08lx)\n", initrd->name,
			       user_to_phys ( initrd->data, 0 ),
			       user_to_phys ( initrd->data, initrd->len ),
			       user_to_phys ( current, 0 ),
			       user_to_phys ( current, initrd->len ) );
			memcpy_user ( current, 0, initrd->data, 0,
				      initrd->len );
			initrd->data = current;
		}
	}

	return current;
}

/**
 * Swap position of two adjacent initrds
 *
 * @v low		Lower initrd
 * @v high		Higher initrd
 * @v free		Free space
 * @v free_len		Length of free space
 */
static void initrd_swap ( struct image *low, struct image *high,
			  userptr_t free, size_t free_len ) {
	size_t len = 0;
	size_t frag_len;
	size_t new_len;

	DBGC ( &images, "INITRD swapping %s [%#08lx,%#08lx)<->[%#08lx,%#08lx) "
	       "%s\n", low->name, user_to_phys ( low->data, 0 ),
	       user_to_phys ( low->data, low->len ),
	       user_to_phys ( high->data, 0 ),
	       user_to_phys ( high->data, high->len ), high->name );

	/* Round down length of free space */
	free_len &= ~( INITRD_ALIGN - 1 );
	assert ( free_len > 0 );

	/* Swap image data */
	while ( len < high->len ) {

		/* Calculate maximum fragment length */
		frag_len = ( high->len - len );
		if ( frag_len > free_len )
			frag_len = free_len;
		new_len = ( ( len + frag_len + INITRD_ALIGN - 1 ) &
			    ~( INITRD_ALIGN - 1 ) );

		/* Swap fragments */
		memcpy_user ( free, 0, high->data, len, frag_len );
		memmove_user ( low->data, new_len, low->data, len, low->len );
		memcpy_user ( low->data, len, free, 0, frag_len );
		len = new_len;
	}

	/* Adjust data pointers */
	high->data = low->data;
	low->data = userptr_add ( low->data, len );
}

/**
 * Swap position of any two adjacent initrds not currently in the correct order
 *
 * @v free		Free space
 * @v free_len		Length of free space
 * @ret swapped		A pair of initrds was swapped
 */
static int initrd_swap_any ( userptr_t free, size_t free_len ) {
	struct image *low;
	struct image *high;
	size_t padded_len;
	userptr_t adjacent;

	/* Find any pair of initrds that can be swapped */
	for_each_image ( low ) {

		/* Calculate location of adjacent image (if any) */
		padded_len = ( ( low->len + INITRD_ALIGN - 1 ) &
			       ~( INITRD_ALIGN - 1 ) );
		adjacent = userptr_add ( low->data, padded_len );

		/* Search for adjacent image */
		for_each_image ( high ) {

			/* If we have found the adjacent image, swap and exit */
			if ( high->data == adjacent ) {
				initrd_swap ( low, high, free, free_len );
				return 1;
			}

			/* Stop search if all remaining potential
			 * adjacent images are already in the correct
			 * order.
			 */
			if ( high == low )
				break;
		}
	}

	/* Nothing swapped */
	return 0;
}

/**
 * Dump initrd locations (for debug)
 *
 */
static void initrd_dump ( void ) {
	struct image *initrd;

	/* Do nothing unless debugging is enabled */
	if ( ! DBG_LOG )
		return;

	/* Dump initrd locations */
	for_each_image ( initrd ) {
		DBGC ( &images, "INITRD %s at [%#08lx,%#08lx)\n",
		       initrd->name, user_to_phys ( initrd->data, 0 ),
		       user_to_phys ( initrd->data, initrd->len ) );
		DBGC2_MD5A ( &images, user_to_phys ( initrd->data, 0 ),
			     user_to_virt ( initrd->data, 0 ), initrd->len );
	}
}

/**
 * Reshuffle initrds into desired order at top of memory
 *
 * @v bottom		Lowest address available for initrds
 *
 * After this function returns, the initrds have been rearranged in
 * memory and the external heap structures will have been corrupted.
 * Reshuffling must therefore take place immediately prior to jumping
 * to the loaded OS kernel; no further execution within iPXE is
 * permitted.
 */
void initrd_reshuffle ( userptr_t bottom ) {
	userptr_t top;
	userptr_t used;
	userptr_t free;
	size_t free_len;

	/* Calculate limits of available space for initrds */
	top = initrd_top;
	if ( userptr_sub ( initrd_bottom, bottom ) > 0 )
		bottom = initrd_bottom;

	/* Debug */
	DBGC ( &images, "INITRD region [%#08lx,%#08lx)\n",
	       user_to_phys ( bottom, 0 ), user_to_phys ( top, 0 ) );
	initrd_dump();

	/* Squash initrds as high as possible in memory */
	used = initrd_squash_high ( top );

	/* Calculate available free space */
	free = bottom;
	free_len = userptr_sub ( used, free );

	/* Bubble-sort initrds into desired order */
	while ( initrd_swap_any ( free, free_len ) ) {}

	/* Debug */
	initrd_dump();
}

/**
 * Check that there is enough space to reshuffle initrds
 *
 * @v len		Total length of initrds (including padding)
 * @v bottom		Lowest address available for initrds
 * @ret rc		Return status code
 */
int initrd_reshuffle_check ( size_t len, userptr_t bottom ) {
	userptr_t top;
	size_t available;

	/* Calculate limits of available space for initrds */
	top = initrd_top;
	if ( userptr_sub ( initrd_bottom, bottom ) > 0 )
		bottom = initrd_bottom;
	available = userptr_sub ( top, bottom );

	/* Allow for a sensible minimum amount of free space */
	len += INITRD_MIN_FREE_LEN;

	/* Check for available space */
	return ( ( len < available ) ? 0 : -ENOBUFS );
}

/**
 * initrd startup function
 *
 */
static void initrd_startup ( void ) {
	size_t len;

	/* Record largest memory block available.  Do this after any
	 * allocations made during driver startup (e.g. large host
	 * memory blocks for Infiniband devices, which may still be in
	 * use at the time of rearranging if a SAN device is hooked)
	 * but before any allocations for downloaded images (which we
	 * can safely reuse when rearranging).
	 */
	len = largest_memblock ( &initrd_bottom );
	initrd_top = userptr_add ( initrd_bottom, len );
}

/** initrd startup function */
struct startup_fn startup_initrd __startup_fn ( STARTUP_LATE ) = {
	.startup = initrd_startup,
};
