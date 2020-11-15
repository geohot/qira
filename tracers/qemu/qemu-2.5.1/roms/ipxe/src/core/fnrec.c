/*
 * Copyright (C) 2010 Stefan Hajnoczi <stefanha@gmail.com>.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ipxe/init.h>
#include <ipxe/uaccess.h>
#include <ipxe/io.h>

/** @file
 *
 * Function trace recorder for crash and hang debugging
 *
 */

/** Constant for identifying valid trace buffers */
#define FNREC_MAGIC ( 'f' << 24 | 'n' << 16 | 'r' << 8 | 'e' )

/** Number of trace buffer entries */
#define FNREC_NUM_ENTRIES 4096

/** Trace buffer physical address
 *
 * Fixed at 17MB
 */
#define FNREC_PHYS_ADDRESS ( 17 * 1024 * 1024 )

/** A trace buffer entry */
struct fnrec_entry {
	/** Called function address */
	void *called_fn;
	/** Call site */
	void *call_site;
	/** Entry count */
	uint16_t entry_count;
	/** Exit count */
	uint16_t exit_count;
	/** Checksum */
	unsigned long checksum;
};

/** A trace buffer */
struct fnrec_buffer {
	/** Constant for identifying valid trace buffers */
	uint32_t magic;

	/** Next trace buffer entry to fill */
	unsigned int idx;

	/** Trace buffer */
	struct fnrec_entry data[FNREC_NUM_ENTRIES]
		__attribute__ (( aligned ( 64 ) ));
};

/** The trace buffer */
static struct fnrec_buffer *fnrec_buffer;

/**
 * Test whether the trace buffer is valid
 *
 * @ret is_valid	Buffer is valid
 */
static int fnrec_is_valid ( void ) {
	return ( fnrec_buffer && ( fnrec_buffer->magic == FNREC_MAGIC ) );
}

/**
 * Invalidate the trace buffer
 *
 */
static void fnrec_invalidate ( void ) {
	fnrec_buffer->magic = 0;
}

/**
 * Reset the trace buffer and clear entries
 */
static void fnrec_reset ( void ) {
	memset ( fnrec_buffer, 0, sizeof ( *fnrec_buffer ) );
	fnrec_buffer->magic = FNREC_MAGIC;
}

/**
 * Append an entry to the trace buffer
 *
 * @v called_fn		Called function
 * @v call_site		Call site
 * @ret entry		Trace buffer entry
 */
static struct fnrec_entry * fnrec_append ( void *called_fn, void *call_site ) {
	struct fnrec_entry *entry;

	/* Re-use existing entry, if possible */
	entry = &fnrec_buffer->data[ fnrec_buffer->idx ];
	if ( ( entry->called_fn == called_fn ) &&
	     ( entry->call_site == call_site ) &&
	     ( entry->entry_count >= entry->exit_count ) ) {
		return entry;
	}

	/* Otherwise, create a new entry */
	fnrec_buffer->idx = ( ( fnrec_buffer->idx + 1 ) % FNREC_NUM_ENTRIES );
	entry = &fnrec_buffer->data[ fnrec_buffer->idx ];
	entry->called_fn = called_fn;
	entry->call_site = call_site;
	entry->entry_count = 0;
	entry->exit_count = 0;
	entry->checksum = ( ( ( unsigned long ) called_fn ) ^
			    ( ( unsigned long ) call_site ) );
	return entry;
}

/**
 * Print the contents of the trace buffer in chronological order
 */
static void fnrec_dump ( void ) {
	struct fnrec_entry *entry;
	unsigned int i;
	unsigned int idx;
	unsigned long checksum;

	printf ( "fnrec buffer dump:\n" );
	for ( i = 1 ; i <= FNREC_NUM_ENTRIES ; i++ ) {
		idx = ( ( fnrec_buffer->idx + i ) % FNREC_NUM_ENTRIES );
		entry = &fnrec_buffer->data[idx];
		if ( ( entry->entry_count == 0 ) && ( entry->exit_count == 0 ) )
			continue;
		checksum = ( ( ( ( unsigned long ) entry->called_fn ) ^
			       ( ( unsigned long ) entry->call_site ) ) +
			     entry->entry_count + entry->exit_count );
		printf ( "%p %p %d %d", entry->called_fn, entry->call_site,
			 entry->entry_count, entry->exit_count );
		if ( entry->checksum != checksum ) {
			printf ( " (checksum wrong at phys %08lx)",
				 virt_to_phys ( entry ) );
		}
		printf ( "\n");
	}
}

/**
 * Function tracer initialisation function
 */
static void fnrec_init ( void ) {

	fnrec_buffer = phys_to_virt ( FNREC_PHYS_ADDRESS );
	if ( fnrec_is_valid() ) {
		fnrec_invalidate();
		fnrec_dump();
	} else {
		printf ( "fnrec buffer not found\n" );
	}
	fnrec_reset();
}

struct init_fn fnrec_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = fnrec_init,
};

/*
 * These functions are called from every C function.  The compiler inserts
 * these calls when -finstrument-functions is used.
 */
void __cyg_profile_func_enter ( void *called_fn, void *call_site ) {
	struct fnrec_entry *entry;

	if ( fnrec_is_valid() ) {
		entry = fnrec_append ( called_fn, call_site );
		entry->entry_count++;
		entry->checksum++;
		mb();
	}
}

void __cyg_profile_func_exit ( void *called_fn, void *call_site ) {
	struct fnrec_entry *entry;

	if ( fnrec_is_valid() ) {
		entry = fnrec_append ( called_fn, call_site );
		entry->exit_count++;
		entry->checksum++;
		mb();
	}
}
