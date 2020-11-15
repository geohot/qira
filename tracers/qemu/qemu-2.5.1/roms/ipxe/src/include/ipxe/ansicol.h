#ifndef _IPXE_ANSICOL_H
#define _IPXE_ANSICOL_H

/** @file
 *
 * ANSI colours
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <curses.h> /* For COLOR_RED etc. */

/** Default colour (usually white foreground, black background) */
#define COLOUR_DEFAULT 9
#define COLOR_DEFAULT COLOUR_DEFAULT

/** Magic colour
 *
 * The magic basic colour is automatically remapped to the colour
 * stored in @c ansicol_magic.  This is used to allow the UI
 * background to automatically become transparent when a background
 * picture is used.
 */
#define ANSICOL_MAGIC 15

/** RGB value for "not defined" */
#define ANSICOL_NO_RGB 0x01000000

/**
 * @defgroup ansicolpairs ANSI colour pairs
 * @{
 */

/** Default colour pair */
#define CPAIR_DEFAULT 0

/** Normal text */
#define CPAIR_NORMAL 1

/** Highlighted text */
#define CPAIR_SELECT 2

/** Unselectable text (e.g. continuation ellipses, menu separators) */
#define CPAIR_SEPARATOR 3

/** Editable text */
#define CPAIR_EDIT 4

/** Error text */
#define CPAIR_ALERT 5

/** URL text */
#define CPAIR_URL 6

/** PXE selected menu entry */
#define CPAIR_PXE 7

/** @} */

/** An ANSI colour pair definition */
struct ansicol_pair {
	/** Foreground colour index */
	uint8_t foreground;
	/** Background colour index */
	uint8_t background;
} __attribute__ (( packed ));

/* ansicol.c */
extern void ansicol_set_pair ( unsigned int cpair );
extern int ansicol_define_pair ( unsigned int cpair, unsigned int foreground,
				 unsigned int background );

/* ansicoldef.c */
extern int ansicol_define ( unsigned int colour, unsigned int ansi,
			    uint32_t rgb );
extern void ansicol_reset_magic ( void );
extern void ansicol_set_magic_transparent ( void );

/* Function provided by ansicol.c but overridden by ansicoldef.c, if present */
extern void ansicol_set ( unsigned int colour, unsigned int which );

#endif /* _IPXE_ANSICOL_H */
