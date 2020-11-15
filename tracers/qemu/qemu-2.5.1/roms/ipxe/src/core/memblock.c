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

/** @file
 *
 * Largest memory block
 *
 */

#include <stdint.h>
#include <ipxe/uaccess.h>
#include <ipxe/io.h>
#include <ipxe/memblock.h>

/**
 * Find largest usable memory region
 *
 * @ret start		Start of region
 * @ret len		Length of region
 */
size_t largest_memblock ( userptr_t *start ) {
	struct memory_map memmap;
	struct memory_region *region;
	physaddr_t max = ~( ( physaddr_t ) 0 );
	physaddr_t region_start;
	physaddr_t region_end;
	size_t region_len;
	unsigned int i;
	size_t len = 0;

	/* Avoid returning uninitialised data on error */
	*start = UNULL;

	/* Scan through all memory regions */
	get_memmap ( &memmap );
	for ( i = 0 ; i < memmap.count ; i++ ) {
		region = &memmap.regions[i];
		DBG ( "Considering [%llx,%llx)\n", region->start, region->end );

		/* Truncate block to maximum physical address */
		if ( region->start > max ) {
			DBG ( "...starts after maximum address %lx\n", max );
			continue;
		}
		region_start = region->start;
		if ( region->end > max ) {
			DBG ( "...end truncated to maximum address %lx\n", max);
			region_end = 0; /* =max, given the wraparound */
		} else {
			region_end = region->end;
		}
		region_len = ( region_end - region_start );

		/* Use largest block */
		if ( region_len > len ) {
			DBG ( "...new best block found\n" );
			*start = phys_to_user ( region_start );
			len = region_len;
		}
	}

	return len;
}
