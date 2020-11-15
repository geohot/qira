#include "stddef.h"
#include <ipxe/console.h>
#include <ipxe/process.h>
#include <ipxe/nap.h>

/** @file */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** Current console usage */
int console_usage = CONSOLE_USAGE_STDOUT;

/** Console width */
unsigned int console_width = CONSOLE_DEFAULT_WIDTH;

/** Console height */
unsigned int console_height = CONSOLE_DEFAULT_HEIGHT;

/**
 * Write a single character to each console device
 *
 * @v character		Character to be written
 *
 * The character is written out to all enabled console devices, using
 * each device's console_driver::putchar() method.
 */
void putchar ( int character ) {
	struct console_driver *console;

	/* Automatic LF -> CR,LF translation */
	if ( character == '\n' )
		putchar ( '\r' );

	for_each_table_entry ( console, CONSOLES ) {
		if ( ( ! ( console->disabled & CONSOLE_DISABLED_OUTPUT ) ) &&
		     ( console_usage & console->usage ) &&
		     console->putchar )
			console->putchar ( character );
	}
}

/**
 * Check to see if any input is available on any console
 *
 * @ret console		Console device that has input available, or NULL
 *
 * All enabled console devices are checked once for available input
 * using each device's console_driver::iskey() method.  The first
 * console device that has available input will be returned, if any.
 */
static struct console_driver * has_input ( void ) {
	struct console_driver *console;

	for_each_table_entry ( console, CONSOLES ) {
		if ( ( ! ( console->disabled & CONSOLE_DISABLED_INPUT ) ) &&
		     console->iskey ) {
			if ( console->iskey () )
				return console;
		}
	}
	return NULL;
}

/**
 * Read a single character from any console
 *
 * @ret character	Character read from a console.
 *
 * A character will be read from the first enabled console device that
 * has input available using that console's console_driver::getchar()
 * method.  If no console has input available to be read, this method
 * will block.  To perform a non-blocking read, use something like
 *
 * @code
 *
 *   int key = iskey() ? getchar() : -1;
 *
 * @endcode
 *
 * The character read will not be echoed back to any console.
 */
int getchar ( void ) {
	struct console_driver *console;
	int character;

	while ( 1 ) {
		console = has_input();
		if ( console && console->getchar ) {
			character = console->getchar ();
			break;
		}

		/* Doze for a while (until the next interrupt).  This works
		 * fine, because the keyboard is interrupt-driven, and the
		 * timer interrupt (approx. every 50msec) takes care of the
		 * serial port, which is read by polling.  This reduces the
		 * power dissipation of a modern CPU considerably, and also
		 * makes Etherboot waiting for user interaction waste a lot
		 * less CPU time in a VMware session.
		 */
		cpu_nap();

		/* Keep processing background tasks while we wait for
		 * input.
		 */
		step();
	}

	/* CR -> LF translation */
	if ( character == '\r' )
		character = '\n';

	return character;
}

/**
 * Check for available input on any console
 *
 * @ret is_available	Input is available on a console
 *
 * All enabled console devices are checked once for available input
 * using each device's console_driver::iskey() method.  If any console
 * device has input available, this call will return true.  If this
 * call returns true, you can then safely call getchar() without
 * blocking.
 */
int iskey ( void ) {
	return has_input() ? 1 : 0;
}

/**
 * Configure console
 *
 * @v config		Console configuration
 * @ret rc		Return status code
 *
 * The configuration is passed to all configurable consoles, including
 * those which are currently disabled.  Consoles may choose to enable
 * or disable themselves depending upon the configuration.
 *
 * If configuration fails, then all consoles will be reset.
 */
int console_configure ( struct console_configuration *config ) {
	struct console_driver *console;
	int rc;

	/* Reset console width and height */
	console_set_size ( CONSOLE_DEFAULT_WIDTH, CONSOLE_DEFAULT_HEIGHT );

	/* Try to configure each console */
	for_each_table_entry ( console, CONSOLES ) {
		if ( ( console->configure ) &&
		     ( ( rc = console->configure ( config ) ) != 0 ) )
				goto err;
	}

	return 0;

 err:
	/* Reset all consoles, avoiding a potential infinite loop */
	if ( config )
		console_reset();
	return rc;
}
