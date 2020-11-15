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

/**
 * @file
 *
 * Executable image segments
 *
 */

#include <errno.h>
#include <ipxe/uaccess.h>
#include <ipxe/io.h>
#include <ipxe/errortab.h>
#include <ipxe/segment.h>

/**
 * Segment-specific error messages
 *
 * This error happens sufficiently often to merit a user-friendly
 * description.
 */
#define ERANGE_SEGMENT __einfo_error ( EINFO_ERANGE_SEGMENT )
#define EINFO_ERANGE_SEGMENT \
	__einfo_uniqify ( EINFO_ERANGE, 0x01, "Requested memory not available" )
struct errortab segment_errors[] __errortab = {
	__einfo_errortab ( EINFO_ERANGE_SEGMENT ),
};

/**
 * Prepare segment for loading
 *
 * @v segment		Segment start
 * @v filesz		Size of the "allocated bytes" portion of the segment
 * @v memsz		Size of the segment
 * @ret rc		Return status code
 */
int prep_segment ( userptr_t segment, size_t filesz, size_t memsz ) {
	struct memory_map memmap;
	physaddr_t start = user_to_phys ( segment, 0 );
	physaddr_t mid = user_to_phys ( segment, filesz );
	physaddr_t end = user_to_phys ( segment, memsz );
	unsigned int i;

	DBG ( "Preparing segment [%lx,%lx,%lx)\n", start, mid, end );

	/* Sanity check */
	if ( filesz > memsz ) {
		DBG ( "Insane segment [%lx,%lx,%lx)\n", start, mid, end );
		return -EINVAL;
	}

	/* Get a fresh memory map.  This allows us to automatically
	 * avoid treading on any regions that Etherboot is currently
	 * editing out of the memory map.
	 */
	get_memmap ( &memmap );

	/* Look for a suitable memory region */
	for ( i = 0 ; i < memmap.count ; i++ ) {
		if ( ( start >= memmap.regions[i].start ) &&
		     ( end <= memmap.regions[i].end ) ) {
			/* Found valid region: zero bss and return */
			memset_user ( segment, filesz, 0, ( memsz - filesz ) );
			return 0;
		}
	}

	/* No suitable memory region found */
	DBG ( "Segment [%lx,%lx,%lx) does not fit into available memory\n",
	      start, mid, end );
	return -ERANGE_SEGMENT;
}
