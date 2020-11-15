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
 * VMware logfile console
 *
 */

#include <string.h>
#include <ipxe/console.h>
#include <ipxe/lineconsole.h>
#include <ipxe/init.h>
#include <ipxe/guestrpc.h>
#include <config/console.h>

/** VMware logfile console buffer size */
#define VMCONSOLE_BUFSIZE 128

/* Set default console usage if applicable */
#if ! ( defined ( CONSOLE_VMWARE ) && CONSOLE_EXPLICIT ( CONSOLE_VMWARE ) )
#undef CONSOLE_VMWARE
#define CONSOLE_VMWARE ( CONSOLE_USAGE_ALL & ~CONSOLE_USAGE_TUI )
#endif

/** VMware logfile console GuestRPC channel */
static int vmconsole_channel;

/** VMware logfile console line buffer */
static struct {
	char prefix[4];
	char message[VMCONSOLE_BUFSIZE];
} vmconsole_buffer = {
	.prefix = "log ",
};

/** VMware logfile console ANSI escape sequence handlers */
static struct ansiesc_handler vmconsole_handlers[] = {
	{ 0, NULL }
};

/** VMware logfile line console */
static struct line_console vmconsole_line = {
	.buffer = vmconsole_buffer.message,
	.len = sizeof ( vmconsole_buffer.message ),
	.ctx = {
		.handlers = vmconsole_handlers,
	},
};

/** VMware logfile console recursion marker */
static int vmconsole_entered;

/**
 * Print a character to VMware logfile console
 *
 * @v character		Character to be printed
 */
static void vmconsole_putchar ( int character ) {
	int rc;

	/* Ignore if we are already mid-logging */
	if ( vmconsole_entered )
		return;

	/* Fill line buffer */
	if ( line_putchar ( &vmconsole_line, character ) == 0 )
		return;

	/* Guard against re-entry */
	vmconsole_entered = 1;

	/* Send log message */
	if ( ( rc = guestrpc_command ( vmconsole_channel,
				       vmconsole_buffer.prefix, NULL, 0 ) ) <0){
		DBG ( "VMware console could not send log message: %s\n",
		      strerror ( rc ) );
	}

	/* Clear re-entry flag */
	vmconsole_entered = 0;
}

/** VMware logfile console driver */
struct console_driver vmconsole __console_driver = {
	.putchar = vmconsole_putchar,
	.disabled = CONSOLE_DISABLED,
	.usage = CONSOLE_VMWARE,
};

/**
 * Initialise VMware logfile console
 *
 */
static void vmconsole_init ( void ) {
	int rc;

	/* Attempt to open console */
	vmconsole_channel = guestrpc_open();
	if ( vmconsole_channel < 0 ) {
		rc = vmconsole_channel;
		DBG ( "VMware console could not be initialised: %s\n",
		      strerror ( rc ) );
		return;
	}

	/* Mark console as available */
	vmconsole.disabled = 0;
}

/**
 * VMware logfile console initialisation function
 */
struct init_fn vmconsole_init_fn __init_fn ( INIT_CONSOLE ) = {
	.initialise = vmconsole_init,
};
