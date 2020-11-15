/*
 * Copyright (C) 2011 Michael Brown <mbrown@fensystems.co.uk>.
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
 * Prompt for keypress
 *
 */

#include <errno.h>
#include <stdio.h>
#include <ipxe/console.h>
#include <usr/prompt.h>

/**
 * Prompt for keypress
 *
 * @v text		Prompt string
 * @v timeout		Timeout period, in ticks (0=indefinite)
 * @v key		Key to wait for (0=any key)
 * @ret rc		Return status code
 *
 * Returns success if the specified key was pressed within the
 * specified timeout period.
 */
int prompt ( const char *text, unsigned long timeout, int key ) {
	int key_pressed;

	/* Display prompt */
	printf ( "%s", text );

	/* Wait for key */
	key_pressed = getkey ( timeout );

	/* Clear the prompt line */
	while ( *(text++) )
		printf ( "\b \b" );

	/* Check for timeout */
	if ( key_pressed < 0 )
		return -ETIMEDOUT;

	/* Check for correct key pressed */
	if ( key && ( key_pressed != key ) )
		return -ECANCELED;

	return 0;
}
