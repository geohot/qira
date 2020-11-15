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
 * Line buffering
 *
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ipxe/linebuf.h>

/**
 * Retrieve buffered-up line
 *
 * @v linebuf		Line buffer
 * @ret line		Buffered line, or NULL if no line ready to read
 */
char * buffered_line ( struct line_buffer *linebuf ) {
	char *line = &linebuf->data[ linebuf->len ];

	/* Fail unless we have a newly completed line to retrieve */
	if ( ( linebuf->len == 0 ) || ( linebuf->consumed == 0 ) ||
	     ( *(--line) != '\0' ) )
		return NULL;

	/* Identify start of line */
	while ( ( line > linebuf->data ) && ( line[-1] != '\0' ) )
		line--;

	return line;
}

/**
 * Discard line buffer contents
 *
 * @v linebuf		Line buffer
 */
void empty_line_buffer ( struct line_buffer *linebuf ) {

	free ( linebuf->data );
	linebuf->data = NULL;
	linebuf->len = 0;
	linebuf->consumed = 0;
}

/**
 * Buffer up received data by lines
 *
 * @v linebuf			Line buffer
 * @v data			New data to add
 * @v len			Length of new data to add
 * @ret len			Consumed length, or negative error number
 *
 * After calling line_buffer(), use buffered_line() to determine
 * whether or not a complete line is available.  Carriage returns and
 * newlines will have been stripped, and the line will be
 * NUL-terminated.  This buffered line is valid only until the next
 * call to line_buffer() (or to empty_line_buffer()).
 *
 * Note that line buffers use dynamically allocated storage; you
 * should call empty_line_buffer() before freeing a @c struct @c
 * line_buffer.
 */
int line_buffer ( struct line_buffer *linebuf, const char *data, size_t len ) {
	const char *eol;
	size_t consume;
	size_t new_len;
	char *new_data;
	char *lf;
	char *cr;

	/* Search for line terminator */
	if ( ( eol = memchr ( data, '\n', len ) ) ) {
		consume = ( eol - data + 1 );
	} else {
		consume = len;
	}

	/* Reject any embedded NULs within the data to be consumed */
	if ( memchr ( data, '\0', consume ) )
		return -EINVAL;

	/* Reallocate data buffer and copy in new data */
	new_len = ( linebuf->len + consume );
	new_data = realloc ( linebuf->data, ( new_len + 1 ) );
	if ( ! new_data )
		return -ENOMEM;
	memcpy ( ( new_data + linebuf->len ), data, consume );
	new_data[new_len] = '\0';
	linebuf->data = new_data;
	linebuf->len = new_len;

	/* If we have reached end of line, terminate the line */
	if ( eol ) {

		/* Overwrite trailing LF (which must exist at this point) */
		assert ( linebuf->len > 0 );
		lf = &linebuf->data[ linebuf->len - 1 ];
		assert ( *lf == '\n' );
		*lf = '\0';

		/* Trim (and overwrite) trailing CR, if present */
		if ( linebuf->len > 1 ) {
			cr = ( lf - 1 );
			if ( *cr == '\r' ) {
				linebuf->len--;
				*cr = '\0';
			}
		}
	}

	/* Record consumed length */
	linebuf->consumed = consume;

	return consume;
}
