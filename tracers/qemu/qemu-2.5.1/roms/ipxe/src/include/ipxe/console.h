#ifndef _IPXE_CONSOLE_H
#define _IPXE_CONSOLE_H

#include <stddef.h>
#include <stdio.h>
#include <ipxe/tables.h>

/** @file
 *
 * User interaction.
 *
 * Various console devices can be selected via the build options
 * CONSOLE_FIRMWARE, CONSOLE_SERIAL etc.  The console functions
 * putchar(), getchar() and iskey() delegate to the individual console
 * drivers.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

struct pixel_buffer;

/** A console configuration */
struct console_configuration {
	/** Width */
	unsigned int width;
	/** Height */
	unsigned int height;
	/** Colour depth */
	unsigned int depth;
	/** Left margin */
	unsigned int left;
	/** Right margin */
	unsigned int right;
	/** Top margin */
	unsigned int top;
	/** Bottom margin */
	unsigned int bottom;
	/** Background picture, if any */
	struct pixel_buffer *pixbuf;
};

/**
 * A console driver
 *
 * Defines the functions that implement a particular console type.
 * Must be made part of the console drivers table by using
 * #__console_driver.
 *
 * @note Consoles that cannot be used before their initialisation
 * function has completed should set #disabled initially.  This allows
 * other console devices to still be used to print out early debugging
 * messages.
 */
struct console_driver {
	/**
	 * Console disabled flags
	 *
	 * This is the bitwise OR of zero or more console disabled
	 * flags.
	 */
	int disabled;
	/**
	 * Write a character to the console
	 *
	 * @v character		Character to be written
	 */
	void ( * putchar ) ( int character );
	/**
	 * Read a character from the console
	 *
	 * @ret character	Character read
	 *
	 * If no character is available to be read, this method will
	 * block.  The character read should not be echoed back to the
	 * console.
	 */
	int ( * getchar ) ( void );
	/**
	 * Check for available input
	 *
	 * @ret is_available	Input is available
	 *
	 * This should return true if a subsequent call to getchar()
	 * will not block.
	 */
	int ( * iskey ) ( void );
	/**
	 * Configure console
	 *
	 * @v config		Console configuration, or NULL to reset
	 * @ret rc		Return status code
	 */
	int ( * configure ) ( struct console_configuration *config );
	/**
	 * Console usage bitmask
	 *
	 * This is the bitwise OR of zero or more @c CONSOLE_USAGE_XXX
	 * values.
	 */
	int usage;
};

/** Console is disabled for input */
#define CONSOLE_DISABLED_INPUT 0x0001

/** Console is disabled for output */
#define CONSOLE_DISABLED_OUTPUT 0x0002

/** Console is disabled for all uses */
#define CONSOLE_DISABLED ( CONSOLE_DISABLED_INPUT | CONSOLE_DISABLED_OUTPUT )

/** Console driver table */
#define CONSOLES __table ( struct console_driver, "consoles" )

/**
 * Mark a <tt> struct console_driver </tt> as being part of the
 * console drivers table.
 *
 * Use as e.g.
 *
 * @code
 *
 *   struct console_driver my_console __console_driver = {
 *      .putchar = my_putchar,
 *	.getchar = my_getchar,
 *	.iskey = my_iskey,
 *   };
 *
 * @endcode
 *
 */
#define __console_driver __table_entry ( CONSOLES, 01 )

/**
 * @defgroup consoleusage Console usages
 * @{
 */

/** Standard output */
#define CONSOLE_USAGE_STDOUT 0x0001

/** Debug messages */
#define CONSOLE_USAGE_DEBUG 0x0002

/** Text-based user interface */
#define CONSOLE_USAGE_TUI 0x0004

/** Log messages */
#define CONSOLE_USAGE_LOG 0x0008

/** All console usages */
#define CONSOLE_USAGE_ALL ( CONSOLE_USAGE_STDOUT | CONSOLE_USAGE_DEBUG | \
			    CONSOLE_USAGE_TUI | CONSOLE_USAGE_LOG )

/** @} */

/**
 * Test to see if console has an explicit usage
 *
 * @v console		Console definition (e.g. CONSOLE_PCBIOS)
 * @ret explicit	Console has an explicit usage
 *
 * This relies upon the trick that the expression ( 2 * N + 1 ) will
 * be valid even if N is defined to be empty, since it will then
 * evaluate to give ( 2 * + 1 ) == ( 2 * +1 ) == 2.
 */
#define CONSOLE_EXPLICIT( console ) ( ( 2 * console + 1 ) != 2 )

/** Default console width */
#define CONSOLE_DEFAULT_WIDTH 80

/** Default console height */
#define CONSOLE_DEFAULT_HEIGHT 25

extern int console_usage;
extern unsigned int console_width;
extern unsigned int console_height;

/**
 * Set console usage
 *
 * @v usage		New console usage
 * @ret old_usage	Previous console usage
 */
static inline __attribute__ (( always_inline )) int
console_set_usage ( int usage ) {
	int old_usage = console_usage;

	console_usage = usage;
	return old_usage;
}

/**
 * Set console size
 *
 * @v width		Width, in characters
 * @v height		Height, in characters
 */
static inline __attribute__ (( always_inline )) void
console_set_size ( unsigned int width, unsigned int height ) {
	console_width = width;
	console_height = height;
}

extern int iskey ( void );
extern int getkey ( unsigned long timeout );
extern int console_configure ( struct console_configuration *config );

/**
 * Reset console
 *
 */
static inline __attribute__ (( always_inline )) void console_reset ( void ) {

	console_configure ( NULL );
}

#endif /* _IPXE_CONSOLE_H */
