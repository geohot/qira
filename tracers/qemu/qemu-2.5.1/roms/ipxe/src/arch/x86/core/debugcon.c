/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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
 * Debug port console
 *
 * The debug port is supported by bochs (via the "port_e9_hack"
 * configuration file directive) and by qemu (via the "-debugcon"
 * command-line option).
 */

#include <stdint.h>
#include <ipxe/io.h>
#include <ipxe/console.h>
#include <ipxe/init.h>
#include <config/console.h>

/** Debug port */
#define DEBUG_PORT 0xe9

/** Debug port installation check magic value */
#define DEBUG_PORT_CHECK 0xe9

/* Set default console usage if applicable */
#if ! ( defined ( CONSOLE_DEBUGCON ) && CONSOLE_EXPLICIT ( CONSOLE_DEBUGCON ) )
#undef CONSOLE_DEBUGCON
#define CONSOLE_DEBUGCON ( CONSOLE_USAGE_ALL & ~CONSOLE_USAGE_TUI )
#endif

/**
 * Print a character to debug port console
 *
 * @v character		Character to be printed
 */
static void debugcon_putchar ( int character ) {

	/* Write character to debug port */
	outb ( character, DEBUG_PORT );
}

/** Debug port console driver */
struct console_driver debugcon_console __console_driver = {
	.putchar = debugcon_putchar,
	.usage = CONSOLE_DEBUGCON,
};

/**
 * Initialise debug port console
 *
 */
static void debugcon_init ( void ) {
	uint8_t check;

	/* Check if console is present */
	check = inb ( DEBUG_PORT );
	if ( check != DEBUG_PORT_CHECK ) {
		DBG ( "Debug port not present; disabling console\n" );
		debugcon_console.disabled = CONSOLE_DISABLED;
	}
}

/**
 * Debug port console initialisation function
 */
struct init_fn debugcon_init_fn __init_fn ( INIT_EARLY ) = {
	.initialise = debugcon_init,
};
