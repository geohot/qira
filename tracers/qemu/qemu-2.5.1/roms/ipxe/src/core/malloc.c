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

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <ipxe/io.h>
#include <ipxe/list.h>
#include <ipxe/init.h>
#include <ipxe/refcnt.h>
#include <ipxe/malloc.h>
#include <valgrind/memcheck.h>

/** @file
 *
 * Dynamic memory allocation
 *
 */

/** A free block of memory */
struct memory_block {
	/** Size of this block */
	size_t size;
	/** Padding
	 *
	 * This padding exists to cover the "count" field of a
	 * reference counter, in the common case where a reference
	 * counter is the first element of a dynamically-allocated
	 * object.  It avoids clobbering the "count" field as soon as
	 * the memory is freed, and so allows for the possibility of
	 * detecting reference counting errors.
	 */
	char pad[ offsetof ( struct refcnt, count ) +
		  sizeof ( ( ( struct refcnt * ) NULL )->count ) ];
	/** List of free blocks */
	struct list_head list;
};

#define MIN_MEMBLOCK_SIZE \
	( ( size_t ) ( 1 << ( fls ( sizeof ( struct memory_block ) - 1 ) ) ) )

/** A block of allocated memory complete with size information */
struct autosized_block {
	/** Size of this block */
	size_t size;
	/** Remaining data */
	char data[0];
};

/**
 * Address for zero-length memory blocks
 *
 * @c malloc(0) or @c realloc(ptr,0) will return the special value @c
 * NOWHERE.  Calling @c free(NOWHERE) will have no effect.
 *
 * This is consistent with the ANSI C standards, which state that
 * "either NULL or a pointer suitable to be passed to free()" must be
 * returned in these cases.  Using a special non-NULL value means that
 * the caller can take a NULL return value to indicate failure,
 * without first having to check for a requested size of zero.
 *
 * Code outside of malloc.c do not ever need to refer to the actual
 * value of @c NOWHERE; this is an internal definition.
 */
#define NOWHERE ( ( void * ) ~( ( intptr_t ) 0 ) )

/** List of free memory blocks */
static LIST_HEAD ( free_blocks );

/** Total amount of free memory */
size_t freemem;

/**
 * Heap size
 *
 * Currently fixed at 512kB.
 */
#define HEAP_SIZE ( 512 * 1024 )

/** The heap itself */
static char heap[HEAP_SIZE] __attribute__ (( aligned ( __alignof__(void *) )));

/**
 * Mark all blocks in free list as defined
 *
 */
static inline void valgrind_make_blocks_defined ( void ) {
	struct memory_block *block;

	/* Do nothing unless running under Valgrind */
	if ( RUNNING_ON_VALGRIND <= 0 )
		return;

	/* Traverse free block list, marking each block structure as
	 * defined.  Some contortions are necessary to avoid errors
	 * from list_check().
	 */

	/* Mark block list itself as defined */
	VALGRIND_MAKE_MEM_DEFINED ( &free_blocks, sizeof ( free_blocks ) );

	/* Mark areas accessed by list_check() as defined */
	VALGRIND_MAKE_MEM_DEFINED ( &free_blocks.prev->next,
				    sizeof ( free_blocks.prev->next ) );
	VALGRIND_MAKE_MEM_DEFINED ( free_blocks.next,
				    sizeof ( *free_blocks.next ) );
	VALGRIND_MAKE_MEM_DEFINED ( &free_blocks.next->next->prev,
				    sizeof ( free_blocks.next->next->prev ) );

	/* Mark each block in list as defined */
	list_for_each_entry ( block, &free_blocks, list ) {

		/* Mark block as defined */
		VALGRIND_MAKE_MEM_DEFINED ( block, sizeof ( *block ) );

		/* Mark areas accessed by list_check() as defined */
		VALGRIND_MAKE_MEM_DEFINED ( block->list.next,
					    sizeof ( *block->list.next ) );
		VALGRIND_MAKE_MEM_DEFINED ( &block->list.next->next->prev,
				      sizeof ( block->list.next->next->prev ) );
	}
}

/**
 * Mark all blocks in free list as inaccessible
 *
 */
static inline void valgrind_make_blocks_noaccess ( void ) {
	struct memory_block *block;
	struct memory_block *prev = NULL;

	/* Do nothing unless running under Valgrind */
	if ( RUNNING_ON_VALGRIND <= 0 )
		return;

	/* Traverse free block list, marking each block structure as
	 * inaccessible.  Some contortions are necessary to avoid
	 * errors from list_check().
	 */

	/* Mark each block in list as inaccessible */
	list_for_each_entry ( block, &free_blocks, list ) {

		/* Mark previous block (if any) as inaccessible. (Current
		 * block will be accessed by list_check().)
		 */
		if ( prev )
			VALGRIND_MAKE_MEM_NOACCESS ( prev, sizeof ( *prev ) );
		prev = block;

		/* At the end of the list, list_check() will end up
		 * accessing the first list item.  Temporarily mark
		 * this area as defined.
		 */
		VALGRIND_MAKE_MEM_DEFINED ( &free_blocks.next->prev,
					    sizeof ( free_blocks.next->prev ) );
	}
	/* Mark last block (if any) as inaccessible */
	if ( prev )
		VALGRIND_MAKE_MEM_NOACCESS ( prev, sizeof ( *prev ) );

	/* Mark as inaccessible the area that was temporarily marked
	 * as defined to avoid errors from list_check().
	 */
	VALGRIND_MAKE_MEM_NOACCESS ( &free_blocks.next->prev,
				     sizeof ( free_blocks.next->prev ) );

	/* Mark block list itself as inaccessible */
	VALGRIND_MAKE_MEM_NOACCESS ( &free_blocks, sizeof ( free_blocks ) );
}

/**
 * Check integrity of the blocks in the free list
 *
 */
static inline void check_blocks ( void ) {
	struct memory_block *block;
	struct memory_block *prev = NULL;

	if ( ! ASSERTING )
		return;

	list_for_each_entry ( block, &free_blocks, list ) {

		/* Check that list structure is intact */
		list_check ( &block->list );

		/* Check that block size is not too small */
		assert ( block->size >= sizeof ( *block ) );
		assert ( block->size >= MIN_MEMBLOCK_SIZE );

		/* Check that block does not wrap beyond end of address space */
		assert ( ( ( void * ) block + block->size ) >
			 ( ( void * ) block ) );

		/* Check that blocks remain in ascending order, and
		 * that adjacent blocks have been merged.
		 */
		if ( prev ) {
			assert ( ( ( void * ) block ) > ( ( void * ) prev ) );
			assert ( ( ( void * ) block ) >
				 ( ( ( void * ) prev ) + prev->size ) );
		}
		prev = block;
	}
}

/**
 * Discard some cached data
 *
 * @ret discarded	Number of cached items discarded
 */
static unsigned int discard_cache ( void ) {
	struct cache_discarder *discarder;
	unsigned int discarded;

	for_each_table_entry ( discarder, CACHE_DISCARDERS ) {
		discarded = discarder->discard();
		if ( discarded )
			return discarded;
	}
	return 0;
}

/**
 * Discard all cached data
 *
 */
static void discard_all_cache ( void ) {
	unsigned int discarded;

	do {
		discarded = discard_cache();
	} while ( discarded );
}

/**
 * Allocate a memory block
 *
 * @v size		Requested size
 * @v align		Physical alignment
 * @v offset		Offset from physical alignment
 * @ret ptr		Memory block, or NULL
 *
 * Allocates a memory block @b physically aligned as requested.  No
 * guarantees are provided for the alignment of the virtual address.
 *
 * @c align must be a power of two.  @c size may not be zero.
 */
void * alloc_memblock ( size_t size, size_t align, size_t offset ) {
	struct memory_block *block;
	size_t align_mask;
	size_t actual_size;
	size_t pre_size;
	ssize_t post_size;
	struct memory_block *pre;
	struct memory_block *post;
	void *ptr;

	/* Sanity checks */
	assert ( size != 0 );
	assert ( ( align == 0 ) || ( ( align & ( align - 1 ) ) == 0 ) );
	valgrind_make_blocks_defined();
	check_blocks();

	/* Round up size to multiple of MIN_MEMBLOCK_SIZE and
	 * calculate alignment mask.
	 */
	actual_size = ( ( size + MIN_MEMBLOCK_SIZE - 1 ) &
			~( MIN_MEMBLOCK_SIZE - 1 ) );
	align_mask = ( ( align - 1 ) | ( MIN_MEMBLOCK_SIZE - 1 ) );

	DBGC2 ( &heap, "Allocating %#zx (aligned %#zx+%zx)\n",
		size, align, offset );
	while ( 1 ) {
		/* Search through blocks for the first one with enough space */
		list_for_each_entry ( block, &free_blocks, list ) {
			pre_size = ( ( offset - virt_to_phys ( block ) )
				     & align_mask );
			post_size = ( block->size - pre_size - actual_size );
			if ( post_size >= 0 ) {
				/* Split block into pre-block, block, and
				 * post-block.  After this split, the "pre"
				 * block is the one currently linked into the
				 * free list.
				 */
				pre   = block;
				block = ( ( ( void * ) pre   ) + pre_size );
				post  = ( ( ( void * ) block ) + actual_size );
				DBGC2 ( &heap, "[%p,%p) -> [%p,%p) + [%p,%p)\n",
					pre, ( ( ( void * ) pre ) + pre->size ),
					pre, block, post,
					( ( ( void * ) pre ) + pre->size ) );
				/* If there is a "post" block, add it in to
				 * the free list.  Leak it if it is too small
				 * (which can happen only at the very end of
				 * the heap).
				 */
				if ( (size_t) post_size >= MIN_MEMBLOCK_SIZE ) {
					VALGRIND_MAKE_MEM_UNDEFINED
						( post, sizeof ( *post ) );
					post->size = post_size;
					list_add ( &post->list, &pre->list );
				}
				/* Shrink "pre" block, leaving the main block
				 * isolated and no longer part of the free
				 * list.
				 */
				pre->size = pre_size;
				/* If there is no "pre" block, remove it from
				 * the list.  Also remove it (i.e. leak it) if
				 * it is too small, which can happen only at
				 * the very start of the heap.
				 */
				if ( pre_size < MIN_MEMBLOCK_SIZE ) {
					list_del ( &pre->list );
					VALGRIND_MAKE_MEM_NOACCESS
						( pre, sizeof ( *pre ) );
				}
				/* Update total free memory */
				freemem -= actual_size;
				/* Return allocated block */
				DBGC2 ( &heap, "Allocated [%p,%p)\n", block,
					( ( ( void * ) block ) + size ) );
				ptr = block;
				VALGRIND_MAKE_MEM_UNDEFINED ( ptr, size );
				goto done;
			}
		}

		/* Try discarding some cached data to free up memory */
		if ( ! discard_cache() ) {
			/* Nothing available to discard */
			DBGC ( &heap, "Failed to allocate %#zx (aligned "
			       "%#zx)\n", size, align );
			ptr = NULL;
			goto done;
		}
	}

 done:
	check_blocks();
	valgrind_make_blocks_noaccess();
	return ptr;
}

/**
 * Free a memory block
 *
 * @v ptr		Memory allocated by alloc_memblock(), or NULL
 * @v size		Size of the memory
 *
 * If @c ptr is NULL, no action is taken.
 */
void free_memblock ( void *ptr, size_t size ) {
	struct memory_block *freeing;
	struct memory_block *block;
	struct memory_block *tmp;
	size_t actual_size;
	ssize_t gap_before;
	ssize_t gap_after = -1;

	/* Allow for ptr==NULL */
	if ( ! ptr )
		return;
	VALGRIND_MAKE_MEM_NOACCESS ( ptr, size );

	/* Sanity checks */
	valgrind_make_blocks_defined();
	check_blocks();

	/* Round up size to match actual size that alloc_memblock()
	 * would have used.
	 */
	assert ( size != 0 );
	actual_size = ( ( size + MIN_MEMBLOCK_SIZE - 1 ) &
			~( MIN_MEMBLOCK_SIZE - 1 ) );
	freeing = ptr;
	VALGRIND_MAKE_MEM_UNDEFINED ( freeing, sizeof ( *freeing ) );
	DBGC2 ( &heap, "Freeing [%p,%p)\n",
		freeing, ( ( ( void * ) freeing ) + size ) );

	/* Check that this block does not overlap the free list */
	if ( ASSERTING ) {
		list_for_each_entry ( block, &free_blocks, list ) {
			if ( ( ( ( void * ) block ) <
			       ( ( void * ) freeing + actual_size ) ) &&
			     ( ( void * ) freeing <
			       ( ( void * ) block + block->size ) ) ) {
				assert ( 0 );
				DBGC ( &heap, "Double free of [%p,%p) "
				       "overlapping [%p,%p) detected from %p\n",
				       freeing,
				       ( ( ( void * ) freeing ) + size ), block,
				       ( ( void * ) block + block->size ),
				       __builtin_return_address ( 0 ) );
			}
		}
	}

	/* Insert/merge into free list */
	freeing->size = actual_size;
	list_for_each_entry_safe ( block, tmp, &free_blocks, list ) {
		/* Calculate gaps before and after the "freeing" block */
		gap_before = ( ( ( void * ) freeing ) - 
			       ( ( ( void * ) block ) + block->size ) );
		gap_after = ( ( ( void * ) block ) - 
			      ( ( ( void * ) freeing ) + freeing->size ) );
		/* Merge with immediately preceding block, if possible */
		if ( gap_before == 0 ) {
			DBGC2 ( &heap, "[%p,%p) + [%p,%p) -> [%p,%p)\n", block,
				( ( ( void * ) block ) + block->size ), freeing,
				( ( ( void * ) freeing ) + freeing->size ),
				block,
				( ( ( void * ) freeing ) + freeing->size ) );
			block->size += actual_size;
			list_del ( &block->list );
			VALGRIND_MAKE_MEM_NOACCESS ( freeing,
						     sizeof ( *freeing ) );
			freeing = block;
		}
		/* Stop processing as soon as we reach a following block */
		if ( gap_after >= 0 )
			break;
	}

	/* Insert before the immediately following block.  If
	 * possible, merge the following block into the "freeing"
	 * block.
	 */
	DBGC2 ( &heap, "[%p,%p)\n",
		freeing, ( ( ( void * ) freeing ) + freeing->size ) );
	list_add_tail ( &freeing->list, &block->list );
	if ( gap_after == 0 ) {
		DBGC2 ( &heap, "[%p,%p) + [%p,%p) -> [%p,%p)\n", freeing,
			( ( ( void * ) freeing ) + freeing->size ), block,
			( ( ( void * ) block ) + block->size ), freeing,
			( ( ( void * ) block ) + block->size ) );
		freeing->size += block->size;
		list_del ( &block->list );
		VALGRIND_MAKE_MEM_NOACCESS ( block, sizeof ( *block ) );
	}

	/* Update free memory counter */
	freemem += actual_size;

	check_blocks();
	valgrind_make_blocks_noaccess();
}

/**
 * Reallocate memory
 *
 * @v old_ptr		Memory previously allocated by malloc(), or NULL
 * @v new_size		Requested size
 * @ret new_ptr		Allocated memory, or NULL
 *
 * Allocates memory with no particular alignment requirement.  @c
 * new_ptr will be aligned to at least a multiple of sizeof(void*).
 * If @c old_ptr is non-NULL, then the contents of the newly allocated
 * memory will be the same as the contents of the previously allocated
 * memory, up to the minimum of the old and new sizes.  The old memory
 * will be freed.
 *
 * If allocation fails the previously allocated block is left
 * untouched and NULL is returned.
 *
 * Calling realloc() with a new size of zero is a valid way to free a
 * memory block.
 */
void * realloc ( void *old_ptr, size_t new_size ) {
	struct autosized_block *old_block;
	struct autosized_block *new_block;
	size_t old_total_size;
	size_t new_total_size;
	size_t old_size;
	void *new_ptr = NOWHERE;

	/* Allocate new memory if necessary.  If allocation fails,
	 * return without touching the old block.
	 */
	if ( new_size ) {
		new_total_size = ( new_size +
				   offsetof ( struct autosized_block, data ) );
		new_block = alloc_memblock ( new_total_size, 1, 0 );
		if ( ! new_block )
			return NULL;
		new_block->size = new_total_size;
		VALGRIND_MAKE_MEM_NOACCESS ( &new_block->size,
					     sizeof ( new_block->size ) );
		new_ptr = &new_block->data;
		VALGRIND_MALLOCLIKE_BLOCK ( new_ptr, new_size, 0, 0 );
	}
	
	/* Copy across relevant part of the old data region (if any),
	 * then free it.  Note that at this point either (a) new_ptr
	 * is valid, or (b) new_size is 0; either way, the memcpy() is
	 * valid.
	 */
	if ( old_ptr && ( old_ptr != NOWHERE ) ) {
		old_block = container_of ( old_ptr, struct autosized_block,
					   data );
		VALGRIND_MAKE_MEM_DEFINED ( &old_block->size,
					    sizeof ( old_block->size ) );
		old_total_size = old_block->size;
		assert ( old_total_size != 0 );
		old_size = ( old_total_size -
			     offsetof ( struct autosized_block, data ) );
		memcpy ( new_ptr, old_ptr,
			 ( ( old_size < new_size ) ? old_size : new_size ) );
		VALGRIND_FREELIKE_BLOCK ( old_ptr, 0 );
		free_memblock ( old_block, old_total_size );
	}

	if ( ASSERTED ) {
		DBGC ( &heap, "Possible memory corruption detected from %p\n",
		       __builtin_return_address ( 0 ) );
	}
	return new_ptr;
}

/**
 * Allocate memory
 *
 * @v size		Requested size
 * @ret ptr		Memory, or NULL
 *
 * Allocates memory with no particular alignment requirement.  @c ptr
 * will be aligned to at least a multiple of sizeof(void*).
 */
void * malloc ( size_t size ) {
	void *ptr;

	ptr = realloc ( NULL, size );
	if ( ASSERTED ) {
		DBGC ( &heap, "Possible memory corruption detected from %p\n",
		       __builtin_return_address ( 0 ) );
	}
	return ptr;
}

/**
 * Free memory
 *
 * @v ptr		Memory allocated by malloc(), or NULL
 *
 * Memory allocated with malloc_dma() cannot be freed with free(); it
 * must be freed with free_dma() instead.
 *
 * If @c ptr is NULL, no action is taken.
 */
void free ( void *ptr ) {

	realloc ( ptr, 0 );
	if ( ASSERTED ) {
		DBGC ( &heap, "Possible memory corruption detected from %p\n",
		       __builtin_return_address ( 0 ) );
	}
}

/**
 * Allocate cleared memory
 *
 * @v size		Requested size
 * @ret ptr		Allocated memory
 *
 * Allocate memory as per malloc(), and zero it.
 *
 * This function name is non-standard, but pretty intuitive.
 * zalloc(size) is always equivalent to calloc(1,size)
 */
void * zalloc ( size_t size ) {
	void *data;

	data = malloc ( size );
	if ( data )
		memset ( data, 0, size );
	if ( ASSERTED ) {
		DBGC ( &heap, "Possible memory corruption detected from %p\n",
		       __builtin_return_address ( 0 ) );
	}
	return data;
}

/**
 * Add memory to allocation pool
 *
 * @v start		Start address
 * @v end		End address
 *
 * Adds a block of memory [start,end) to the allocation pool.  This is
 * a one-way operation; there is no way to reclaim this memory.
 *
 * @c start must be aligned to at least a multiple of sizeof(void*).
 */
void mpopulate ( void *start, size_t len ) {
	/* Prevent free_memblock() from rounding up len beyond the end
	 * of what we were actually given...
	 */
	free_memblock ( start, ( len & ~( MIN_MEMBLOCK_SIZE - 1 ) ) );
}

/**
 * Initialise the heap
 *
 */
static void init_heap ( void ) {
	VALGRIND_MAKE_MEM_NOACCESS ( heap, sizeof ( heap ) );
	VALGRIND_MAKE_MEM_NOACCESS ( &free_blocks, sizeof ( free_blocks ) );
	mpopulate ( heap, sizeof ( heap ) );
}

/** Memory allocator initialisation function */
struct init_fn heap_init_fn __init_fn ( INIT_EARLY ) = {
	.initialise = init_heap,
};

/**
 * Discard all cached data on shutdown
 *
 */
static void shutdown_cache ( int booting __unused ) {
	discard_all_cache();
}

/** Memory allocator shutdown function */
struct startup_fn heap_startup_fn __startup_fn ( STARTUP_EARLY ) = {
	.shutdown = shutdown_cache,
};

#if 0
#include <stdio.h>
/**
 * Dump free block list
 *
 */
void mdumpfree ( void ) {
	struct memory_block *block;

	printf ( "Free block list:\n" );
	list_for_each_entry ( block, &free_blocks, list ) {
		printf ( "[%p,%p] (size %#zx)\n", block,
			 ( ( ( void * ) block ) + block->size ), block->size );
	}
}
#endif
