/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ipxe/retry.h>
#include <ipxe/timer.h>
#include <ipxe/ipstat.h>
#include <ipxe/fragment.h>

/** @file
 *
 * Fragment reassembly
 *
 */

/**
 * Expire fragment reassembly buffer
 *
 * @v timer		Retry timer
 * @v fail		Failure indicator
 */
static void fragment_expired ( struct retry_timer *timer, int fail __unused ) {
	struct fragment *fragment =
		container_of ( timer, struct fragment, timer );

	DBGC ( fragment, "FRAG %p expired\n", fragment );
	free_iob ( fragment->iobuf );
	list_del ( &fragment->list );
	fragment->fragments->stats->reasm_fails++;
	free ( fragment );
}

/**
 * Find fragment reassembly buffer
 *
 * @v fragments		Fragment reassembler
 * @v iobuf		I/O buffer
 * @v hdrlen		Length of non-fragmentable potion of I/O buffer
 * @ret fragment	Fragment reassembly buffer, or NULL if not found
 */
static struct fragment * fragment_find ( struct fragment_reassembler *fragments,
					 struct io_buffer *iobuf,
					 size_t hdrlen ) {
	struct fragment *fragment;

	list_for_each_entry ( fragment, &fragments->list, list ) {
		if ( fragments->is_fragment ( fragment, iobuf, hdrlen ) )
			return fragment;
	}
	return NULL;
}

/**
 * Reassemble packet
 *
 * @v fragments		Fragment reassembler
 * @v iobuf		I/O buffer
 * @v hdrlen		Length of non-fragmentable potion of I/O buffer
 * @ret iobuf		Reassembled packet, or NULL
 *
 * This function takes ownership of the I/O buffer.  Note that the
 * length of the non-fragmentable portion may be modified.
 */
struct io_buffer * fragment_reassemble ( struct fragment_reassembler *fragments,
					 struct io_buffer *iobuf,
					 size_t *hdrlen ) {
	struct fragment *fragment;
	struct io_buffer *new_iobuf;
	size_t new_len;
	size_t offset;
	size_t expected_offset;
	int more_frags;

	/* Update statistics */
	fragments->stats->reasm_reqds++;

	/* Find matching fragment reassembly buffer, if any */
	fragment = fragment_find ( fragments, iobuf, *hdrlen );

	/* Drop out-of-order fragments */
	offset = fragments->fragment_offset ( iobuf, *hdrlen );
	expected_offset = ( fragment ? ( iob_len ( fragment->iobuf ) -
					 fragment->hdrlen ) : 0 );
	if ( offset != expected_offset ) {
		DBGC ( fragment, "FRAG %p dropping out-of-sequence fragment "
		       "[%zd,%zd), expected [%zd,...)\n", fragment, offset,
		       ( offset + iob_len ( iobuf ) - *hdrlen ),
		       expected_offset );
		goto drop;
	}

	/* Create or extend fragment reassembly buffer as applicable */
	if ( ! fragment ) {

		/* Create new fragment reassembly buffer */
		fragment = zalloc ( sizeof ( *fragment ) );
		if ( ! fragment )
			goto drop;
		list_add ( &fragment->list, &fragments->list );
		fragment->iobuf = iobuf;
		fragment->hdrlen = *hdrlen;
		timer_init ( &fragment->timer, fragment_expired, NULL );
		fragment->fragments = fragments;
		DBGC ( fragment, "FRAG %p [0,%zd)\n", fragment,
		       ( iob_len ( iobuf ) - *hdrlen ) );

	} else {

		/* Check if this is the final fragment */
		more_frags = fragments->more_fragments ( iobuf, *hdrlen );
		DBGC ( fragment, "FRAG %p [%zd,%zd)%s\n", fragment,
		       offset, ( offset + iob_len ( iobuf ) - *hdrlen ),
		       ( more_frags ? "" : " complete" ) );

		/* Extend fragment reassembly buffer.  Preserve I/O
		 * buffer headroom to allow for code which modifies
		 * and resends the buffer (e.g. ICMP echo responses).
		 */
		iob_pull ( iobuf, *hdrlen );
		new_len = ( iob_headroom ( fragment->iobuf ) +
			    iob_len ( fragment->iobuf ) + iob_len ( iobuf ) );
		new_iobuf = alloc_iob ( new_len );
		if ( ! new_iobuf ) {
			DBGC ( fragment, "FRAG %p could not extend reassembly "
			       "buffer to %zd bytes\n", fragment, new_len );
			goto drop;
		}
		iob_reserve ( new_iobuf, iob_headroom ( fragment->iobuf ) );
		memcpy ( iob_put ( new_iobuf, iob_len ( fragment->iobuf ) ),
			 fragment->iobuf->data, iob_len ( fragment->iobuf ) );
		memcpy ( iob_put ( new_iobuf, iob_len ( iobuf ) ),
			 iobuf->data, iob_len ( iobuf ) );
		free_iob ( fragment->iobuf );
		fragment->iobuf = new_iobuf;
		free_iob ( iobuf );

		/* Stop fragment reassembly timer */
		stop_timer ( &fragment->timer );

		/* If this is the final fragment, return it */
		if ( ! more_frags ) {
			iobuf = fragment->iobuf;
			*hdrlen = fragment->hdrlen;
			list_del ( &fragment->list );
			free ( fragment );
			fragments->stats->reasm_oks++;
			return iobuf;
		}
	}

	/* (Re)start fragment reassembly timer */
	start_timer_fixed ( &fragment->timer, FRAGMENT_TIMEOUT );

	return NULL;

 drop:
	fragments->stats->reasm_fails++;
	free_iob ( iobuf );
	return NULL;
}
