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
 * External memory allocation
 *
 */

#include <limits.h>
#include <errno.h>
#include <ipxe/uaccess.h>
#include <ipxe/hidemem.h>
#include <ipxe/io.h>
#include <ipxe/memblock.h>
#include <ipxe/umalloc.h>

/** Alignment of external allocated memory */
#define EM_ALIGN ( 4 * 1024 )

/** Equivalent of NOWHERE for user pointers */
#define UNOWHERE ( ~UNULL )

/** An external memory block */
struct external_memory {
	/** Size of this memory block (excluding this header) */
	size_t size;
	/** Block is currently in use */
	int used;
};

/** Top of heap */
static userptr_t top = UNULL;

/** Bottom of heap (current lowest allocated block) */
static userptr_t bottom = UNULL;

/** Remaining space on heap */
static size_t heap_size;

/**
 * Initialise external heap
 *
 */
static void init_eheap ( void ) {
	userptr_t base;

	heap_size = largest_memblock ( &base );
	bottom = top = userptr_add ( base, heap_size );
	DBG ( "External heap grows downwards from %lx (size %zx)\n",
	      user_to_phys ( top, 0 ), heap_size );
}

/**
 * Collect free blocks
 *
 */
static void ecollect_free ( void ) {
	struct external_memory extmem;
	size_t len;

	/* Walk the free list and collect empty blocks */
	while ( bottom != top ) {
		copy_from_user ( &extmem, bottom, -sizeof ( extmem ),
				 sizeof ( extmem ) );
		if ( extmem.used )
			break;
		DBG ( "EXTMEM freeing [%lx,%lx)\n", user_to_phys ( bottom, 0 ),
		      user_to_phys ( bottom, extmem.size ) );
		len = ( extmem.size + sizeof ( extmem ) );
		bottom = userptr_add ( bottom, len );
		heap_size += len;
	}
}

/**
 * Reallocate external memory
 *
 * @v old_ptr		Memory previously allocated by umalloc(), or UNULL
 * @v new_size		Requested size
 * @ret new_ptr		Allocated memory, or UNULL
 *
 * Calling realloc() with a new size of zero is a valid way to free a
 * memory block.
 */
static userptr_t memtop_urealloc ( userptr_t ptr, size_t new_size ) {
	struct external_memory extmem;
	userptr_t new = ptr;
	size_t align;

	/* (Re)initialise external memory allocator if necessary */
	if ( bottom == top )
		init_eheap();

	/* Get block properties into extmem */
	if ( ptr && ( ptr != UNOWHERE ) ) {
		/* Determine old size */
		copy_from_user ( &extmem, ptr, -sizeof ( extmem ),
				 sizeof ( extmem ) );
	} else {
		/* Create a zero-length block */
		if ( heap_size < sizeof ( extmem ) ) {
			DBG ( "EXTMEM out of space\n" );
			return UNULL;
		}
		ptr = bottom = userptr_add ( bottom, -sizeof ( extmem ) );
		heap_size -= sizeof ( extmem );
		DBG ( "EXTMEM allocating [%lx,%lx)\n",
		      user_to_phys ( ptr, 0 ), user_to_phys ( ptr, 0 ) );
		extmem.size = 0;
	}
	extmem.used = ( new_size > 0 );

	/* Expand/shrink block if possible */
	if ( ptr == bottom ) {
		/* Update block */
		if ( new_size > ( heap_size - extmem.size ) ) {
			DBG ( "EXTMEM out of space\n" );
			return UNULL;
		}
		new = userptr_add ( ptr, - ( new_size - extmem.size ) );
		align = ( user_to_phys ( new, 0 ) & ( EM_ALIGN - 1 ) );
		new_size += align;
		new = userptr_add ( new, -align );
		DBG ( "EXTMEM expanding [%lx,%lx) to [%lx,%lx)\n",
		      user_to_phys ( ptr, 0 ),
		      user_to_phys ( ptr, extmem.size ),
		      user_to_phys ( new, 0 ),
		      user_to_phys ( new, new_size ));
		memmove_user ( new, 0, ptr, 0, ( ( extmem.size < new_size ) ?
						 extmem.size : new_size ) );
		bottom = new;
		heap_size -= ( new_size - extmem.size );
		extmem.size = new_size;
	} else {
		/* Cannot expand; can only pretend to shrink */
		if ( new_size > extmem.size ) {
			/* Refuse to expand */
			DBG ( "EXTMEM cannot expand [%lx,%lx)\n",
			      user_to_phys ( ptr, 0 ),
			      user_to_phys ( ptr, extmem.size ) );
			return UNULL;
		}
	}

	/* Write back block properties */
	copy_to_user ( new, -sizeof ( extmem ), &extmem,
		       sizeof ( extmem ) );

	/* Collect any free blocks and update hidden memory region */
	ecollect_free();
	hide_umalloc ( user_to_phys ( bottom, ( ( bottom == top ) ?
						0 : -sizeof ( extmem ) ) ),
		       user_to_phys ( top, 0 ) );

	return ( new_size ? new : UNOWHERE );
}

PROVIDE_UMALLOC ( memtop, urealloc, memtop_urealloc );
