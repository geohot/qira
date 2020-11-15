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
#include <ipxe/ansiesc.h>
#include <ipxe/ansicol.h>
#include <config/colour.h>

/** @file
 *
 * ANSI colour definitions
 *
 */

/**
 * Construct ANSI colour definition
 *
 * @v basic		Basic colour
 * @v rgb		24-bit RGB value (or ANSICOL_NO_RGB)
 * @ret ansicol		ANSI colour definition
 */
#define ANSICOL_DEFINE( basic, rgb ) ( ( (basic) << 28 ) | (rgb) )

/**
 * Extract basic colour from ANSI colour definition
 *
 * @v ansicol		ANSI colour definition
 * @ret basic		Basic colour
 */
#define ANSICOL_BASIC( ansicol ) ( (ansicol) >> 28 )

/**
 * Extract 24-bit RGB value from ANSI colour definition
 *
 * @v ansicol		ANSI colour definition
 * @ret rgb		24-bit RGB value
 */
#define ANSICOL_RGB( ansicol ) ( ( (ansicol) >> 0 ) & 0xffffffUL )

/**
 * Extract 24-bit RGB value red component from ANSI colour definition
 *
 * @v ansicol		ANSI colour definition
 * @ret red		Red component
 */
#define ANSICOL_RED( ansicol ) ( ( (ansicol) >> 16 ) & 0xff )

/**
 * Extract 24-bit RGB value green component from ANSI colour definition
 *
 * @v ansicol		ANSI colour definition
 * @ret green		Green component
 */
#define ANSICOL_GREEN( ansicol ) ( ( (ansicol) >> 8 ) & 0xff )

/**
 * Extract 24-bit RGB value blue component from ANSI colour definition
 *
 * @v ansicol		ANSI colour definition
 * @ret blue		Blue component
 */
#define ANSICOL_BLUE( ansicol ) ( ( (ansicol) >> 0 ) & 0xff )

/**
 * Construct default ANSI colour definition
 *
 * @v basic		Basic colour
 * @ret ansicol		ANSI colour definition
 *
 * Colours default to being just a basic colour.  If the colour
 * matches the normal UI text background colour, then its basic colour
 * value is set to @c ANSICOL_MAGIC.
 */
#define ANSICOL_DEFAULT( basic )					\
	ANSICOL_DEFINE ( ( ( (basic) == COLOR_NORMAL_BG ) ?		\
			   ANSICOL_MAGIC : (basic) ),			\
			 ANSICOL_NO_RGB )

/** ANSI colour definitions */
static uint32_t ansicols[] = {
	[COLOR_BLACK]	= ANSICOL_DEFAULT ( COLOR_BLACK ),
	[COLOR_RED]	= ANSICOL_DEFAULT ( COLOR_RED ),
	[COLOR_GREEN]	= ANSICOL_DEFAULT ( COLOR_GREEN ),
	[COLOR_YELLOW]	= ANSICOL_DEFAULT ( COLOR_YELLOW ),
	[COLOR_BLUE]	= ANSICOL_DEFAULT ( COLOR_BLUE ),
	[COLOR_MAGENTA]	= ANSICOL_DEFAULT ( COLOR_MAGENTA ),
	[COLOR_CYAN]	= ANSICOL_DEFAULT ( COLOR_CYAN ),
	[COLOR_WHITE]	= ANSICOL_DEFAULT ( COLOR_WHITE ),
};

/** Magic basic colour */
static uint8_t ansicol_magic = COLOR_NORMAL_BG;

/**
 * Define ANSI colour
 *
 * @v colour		Colour index
 * @v basic		Basic colour
 * @v rgb		24-bit RGB value (or ANSICOL_NO_RGB)
 * @ret rc		Return status code
 */
int ansicol_define ( unsigned int colour, unsigned int basic, uint32_t rgb ) {
	uint32_t ansicol;

	/* Fail if colour index is out of range */
	if ( colour >= ( sizeof ( ansicols ) / sizeof ( ansicols[0] ) ) )
		return -EINVAL;

	/* Update colour definition */
	ansicol = ANSICOL_DEFINE ( basic, rgb );
	ansicols[colour] = ansicol;
	DBGC ( &ansicols[0], "ANSICOL redefined colour %d as basic %d RGB "
	       "%#06lx%s\n", colour, ANSICOL_BASIC ( ansicol ),
	       ANSICOL_RGB ( ansicol ),
	       ( ( ansicol & ANSICOL_NO_RGB ) ? " [norgb]" : "" ) );

	return 0;
}

/**
 * Set ANSI colour (using colour definitions)
 *
 * @v colour		Colour index
 * @v which		Foreground/background selector
 */
void ansicol_set ( unsigned int colour, unsigned int which ) {
	uint32_t ansicol;
	unsigned int basic;

	/* Use default colour if colour index is out of range */
	if ( colour < ( sizeof ( ansicols ) / sizeof ( ansicols[0] ) ) ) {
		ansicol = ansicols[colour];
	} else {
		ansicol = ANSICOL_DEFINE ( COLOUR_DEFAULT, ANSICOL_NO_RGB );
	}

	/* If basic colour is out of range, use the magic colour */
	basic = ANSICOL_BASIC ( ansicol );
	if ( basic >= 10 )
		basic = ansicol_magic;

	/* Set basic colour first */
	printf ( CSI "%c%dm", which, basic );

	/* Set 24-bit RGB colour, if applicable */
	if ( ! ( ansicol & ANSICOL_NO_RGB ) ) {
		printf ( CSI "%c8;2;%d;%d;%dm", which, ANSICOL_RED ( ansicol ),
			 ANSICOL_GREEN ( ansicol ), ANSICOL_BLUE ( ansicol ) );
	}
}

/**
 * Reset magic colour
 *
 */
void ansicol_reset_magic ( void ) {

	/* Set to the compile-time default background colour */
	ansicol_magic = COLOR_NORMAL_BG;
}

/**
 * Set magic colour to transparent
 *
 */
void ansicol_set_magic_transparent ( void ) {

	/* Set to the console default colour (which will give a
	 * transparent background on the framebuffer console).
	 */
	ansicol_magic = COLOR_DEFAULT;
}
