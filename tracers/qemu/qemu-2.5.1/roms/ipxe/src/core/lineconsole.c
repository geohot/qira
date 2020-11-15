/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
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

/** @file
 *
 * Line-based console
 *
 */

#include <stdint.h>
#include <stddef.h>
#include <ipxe/ansiesc.h>
#include <ipxe/lineconsole.h>

/**
 * Print a character to a line-based console
 *
 * @v character		Character to be printed
 * @ret print		Print line
 */
size_t line_putchar ( struct line_console *line, int character ) {

	/* Strip ANSI escape sequences */
	character = ansiesc_process ( &line->ctx, character );
	if ( character < 0 )
		return 0;

	/* Ignore carriage return */
	if ( character == '\r' )
		return 0;

	/* Treat newline as a terminator */
	if ( character == '\n' )
		character = 0;

	/* Add character to buffer */
	line->buffer[line->index++] = character;

	/* Do nothing more unless we reach end-of-line (or end-of-buffer) */
	if ( ( character != 0 ) &&
	     ( line->index < ( line->len - 1 /* NUL */ ) ) ) {
		return 0;
	}

	/* Reset to start of buffer */
	line->index = 0;

	return 1;
}
