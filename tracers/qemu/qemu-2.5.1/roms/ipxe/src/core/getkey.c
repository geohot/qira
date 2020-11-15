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

#include <ctype.h>
#include <ipxe/console.h>
#include <ipxe/process.h>
#include <ipxe/keys.h>
#include <ipxe/timer.h>
#include <ipxe/nap.h>

/** @file
 *
 * Special key interpretation
 *
 */

#define GETKEY_TIMEOUT ( TICKS_PER_SEC / 4 )

/**
 * Read character from console if available within timeout period
 *
 * @v timeout		Timeout period, in ticks (0=indefinite)
 * @ret character	Character read from console
 */
static int getchar_timeout ( unsigned long timeout ) {
	unsigned long start = currticks();

	while ( ( timeout == 0 ) || ( ( currticks() - start ) < timeout ) ) {
		step();
		if ( iskey() )
			return getchar();
		cpu_nap();
	}

	return -1;
}

/**
 * Get single keypress
 *
 * @v timeout		Timeout period, in ticks (0=indefinite)
 * @ret key		Key pressed
 *
 * The returned key will be an ASCII value or a KEY_XXX special
 * constant.  This function differs from getchar() in that getchar()
 * will return "special" keys (e.g. cursor keys) as a series of
 * characters forming an ANSI escape sequence.
 */
int getkey ( unsigned long timeout ) {
	int character;
	unsigned int n = 0;

	character = getchar_timeout ( timeout );
	if ( character != ESC )
		return character;

	while ( ( character = getchar_timeout ( GETKEY_TIMEOUT ) ) >= 0 ) {
		if ( character == '[' )
			continue;
		if ( isdigit ( character ) ) {
			n = ( ( n * 10 ) + ( character - '0' ) );
			continue;
		}
		if ( character >= 0x40 )
			return KEY_ANSI ( n, character );
	}

	return ESC;
}
