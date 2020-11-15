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

#include <string.h>
#include <assert.h>
#include <ipxe/editbox.h>

/** @file
 *
 * Editable text box widget
 *
 */

#define EDITBOX_MIN_CHARS 3

/**
 * Initialise text box widget
 *
 * @v box		Editable text box widget
 * @v buf		Text buffer
 * @v len		Size of text buffer
 * @v win		Containing window
 * @v row		Row
 * @v col		Starting column
 * @v width		Width
 * @v flags		Flags
 */
void init_editbox ( struct edit_box *box, char *buf, size_t len,
		    WINDOW *win, unsigned int row, unsigned int col,
		    unsigned int width, unsigned int flags ) {
	memset ( box, 0, sizeof ( *box ) );
	init_editstring ( &box->string, buf, len );
	box->string.cursor = strlen ( buf );
	box->win = ( win ? win : stdscr );
	box->row = row;
	box->col = col;
	box->width = width;
	box->flags = flags;
}

/**
 * Draw text box widget
 *
 * @v box		Editable text box widget
 *
 */
void draw_editbox ( struct edit_box *box ) {
	size_t width = box->width;
	char buf[ width + 1 ];
	signed int cursor_offset, underflow, overflow, first;
	size_t len;

	/* Adjust starting offset so that cursor remains within box */
	cursor_offset = ( box->string.cursor - box->first );
	underflow = ( EDITBOX_MIN_CHARS - cursor_offset );
	overflow = ( cursor_offset - ( width - 1 ) );
	first = box->first;
	if ( underflow > 0 ) {
		first -= underflow;
		if ( first < 0 )
			first = 0;
	} else if ( overflow > 0 ) {
		first += overflow;
	}
	box->first = first;
	cursor_offset = ( box->string.cursor - first );

	/* Construct underscore-padded string portion */
	memset ( buf, '_', width );
	buf[width] = '\0';
	len = ( strlen ( box->string.buf ) - first );
	if ( len > width )
		len = width;
	if ( box->flags & EDITBOX_STARS ) {
		memset ( buf, '*', len );
	} else {
		memcpy ( buf, ( box->string.buf + first ), len );
	}

	/* Print box content and move cursor */
	if ( ! box->win )
		box->win = stdscr;
	mvwprintw ( box->win, box->row, box->col, "%s", buf );
	wmove ( box->win, box->row, ( box->col + cursor_offset ) );
}
