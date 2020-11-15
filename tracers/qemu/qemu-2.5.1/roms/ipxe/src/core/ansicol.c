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

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/ansiesc.h>
#include <ipxe/ansicol.h>
#include <config/colour.h>

/** @file
 *
 * ANSI colours
 *
 */

/** ANSI colour pair definitions */
static struct ansicol_pair ansicol_pairs[] = {
	[CPAIR_DEFAULT] = { COLOR_DEFAULT, COLOR_DEFAULT },
	[CPAIR_NORMAL] = { COLOR_NORMAL_FG, COLOR_NORMAL_BG },
	[CPAIR_SELECT] = { COLOR_SELECT_FG, COLOR_SELECT_BG },
	[CPAIR_SEPARATOR] = { COLOR_SEPARATOR_FG, COLOR_SEPARATOR_BG },
	[CPAIR_EDIT] = { COLOR_EDIT_FG, COLOR_EDIT_BG },
	[CPAIR_ALERT] = { COLOR_ALERT_FG, COLOR_ALERT_BG },
	[CPAIR_URL] = { COLOR_URL_FG, COLOR_URL_BG },
	[CPAIR_PXE] = { COLOR_PXE_FG, COLOR_PXE_BG },
};

/**
 * Set ANSI colour (when no colour definition support is present)
 *
 * @v colour		Colour index
 * @v which		Foreground/background selector
 */
__weak void ansicol_set ( unsigned int colour, unsigned int which ) {

	/* Colour indices are hardcoded and should never be out of range */
	assert ( colour < 10 );

	/* Set basic colour */
	printf ( CSI "%c%dm", which, colour );
}

/**
 * Set ANSI foreground colour
 *
 * @v colour		Colour index
 */
static void ansicol_foreground ( unsigned int colour ) {
	ansicol_set ( colour, '3' );
}

/**
 * Set ANSI background colour
 *
 * @v colour		Colour index
 */
static void ansicol_background ( unsigned int colour ) {
	ansicol_set ( colour, '4' );
}

/**
 * Set ANSI foreground and background colour
 *
 * @v cpair		Colour pair index
 */
void ansicol_set_pair ( unsigned int cpair ) {
	struct ansicol_pair *pair;

	/* Colour pair indices are hardcoded and should never be out of range */
	assert ( cpair < ( sizeof ( ansicol_pairs ) /
			   sizeof ( ansicol_pairs[0] ) ) );

	/* Set both foreground and background colours */
	pair = &ansicol_pairs[cpair];
	ansicol_foreground ( pair->foreground );
	ansicol_background ( pair->background );
}

/**
 * Define ANSI colour pair
 *
 * @v cpair		Colour pair index
 * @v foreground	Foreground colour index
 * @v background	Background colour index
 * @ret rc		Return status code
 */
int ansicol_define_pair ( unsigned int cpair, unsigned int foreground,
			  unsigned int background ) {
	struct ansicol_pair *pair;

	/* Fail if colour index is out of range */
	if ( cpair >= ( sizeof ( ansicol_pairs ) / sizeof ( ansicol_pairs[0] )))
		return -EINVAL;

	/* Update colour pair definition */
	pair = &ansicol_pairs[cpair];
	pair->foreground = foreground;
	pair->background = background;
	DBGC ( &ansicol_pairs[0], "ANSICOL redefined colour pair %d as "
	       "foreground %d background %d\n", cpair, foreground, background );

	return 0;
}
