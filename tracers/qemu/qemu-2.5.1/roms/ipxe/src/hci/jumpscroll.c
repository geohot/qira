/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
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

/**
 * Jump scrolling
 *
 */

#include <assert.h>
#include <ipxe/keys.h>
#include <ipxe/jumpscroll.h>

/**
 * Handle keypress
 *
 * @v scroll		Jump scroller
 * @v key		Key pressed by user
 * @ret move		Scroller movement, or zero
 */
int jump_scroll_key ( struct jump_scroller *scroll, int key ) {

	/* Sanity checks */
	assert ( scroll->rows != 0 );
	assert ( scroll->count != 0 );
	assert ( scroll->current < scroll->count );
	assert ( scroll->first < scroll->count );
	assert ( scroll->first <= scroll->current );
	assert ( scroll->current < ( scroll->first + scroll->rows ) );

	/* Handle key, if applicable */
	switch ( key ) {
	case KEY_UP:
		return -1;
	case KEY_DOWN:
		return +1;
	case KEY_PPAGE:
		return ( scroll->first - scroll->current - 1 );
	case KEY_NPAGE:
		return ( scroll->first - scroll->current + scroll->rows );
	case KEY_HOME:
		return -( scroll->count );
	case KEY_END:
		return +( scroll->count );
	default:
		return 0;
	}
}

/**
 * Move scroller
 *
 * @v scroll		Jump scroller
 * @v move		Scroller movement
 * @ret move		Continuing scroller movement (if applicable)
 */
int jump_scroll_move ( struct jump_scroller *scroll, int move ) {
	int current = scroll->current;
	int last = ( scroll->count - 1 );

	/* Sanity checks */
	assert ( move != 0 );
	assert ( scroll->count != 0 );

	/* Move to the new current item */
	current += move;

	/* Check for start/end of list */
	if ( current < 0 ) {
		/* We have attempted to move before the start of the
		 * list.  Move to the start of the list and continue
		 * moving forwards (if applicable).
		 */
		scroll->current = 0;
		return +1;
	} else if ( current > last ) {
		/* We have attempted to move after the end of the
		 * list.  Move to the end of the list and continue
		 * moving backwards (if applicable).
		 */
		scroll->current = last;
		return -1;
	} else {
		/* Update the current item and continue moving in the
		 * same direction (if applicable).
		 */
		scroll->current = current;
		return ( ( move > 0 ) ? +1 : -1 );
	}
}

/**
 * Jump scroll to new page (if applicable)
 *
 * @v scroll		Jump scroller
 * @ret jumped		Jumped to a new page
 */
int jump_scroll ( struct jump_scroller *scroll ) {
	unsigned int index;

	/* Sanity checks */
	assert ( scroll->rows != 0 );
	assert ( scroll->count != 0 );
	assert ( scroll->current < scroll->count );
	assert ( scroll->first < scroll->count );

	/* Do nothing if we are already on the correct page */
	index = ( scroll->current - scroll->first );
	if ( index < scroll->rows )
		return 0;

	/* Move to required page */
	while ( scroll->first < scroll->current )
		scroll->first += scroll->rows;
	while ( scroll->first > scroll->current )
		scroll->first -= scroll->rows;

	return 1;
}
