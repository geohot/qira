/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <ipxe/device.h>
#include <ipxe/console.h>
#include <ipxe/init.h>

/** @file
 *
 * Initialisation, startup and shutdown routines
 *
 */

/** "startup() has been called" flag */
static int started = 0;

/**
 * Initialise iPXE
 *
 * This function performs the one-time-only and irreversible
 * initialisation steps, such as initialising the heap.  It must be
 * called before (almost) any other function.
 *
 * There is, by definition, no counterpart to this function on the
 * shutdown path.
 */
void initialise ( void ) {
	struct init_fn *init_fn;

	/* Call registered initialisation functions */
	for_each_table_entry ( init_fn, INIT_FNS )
		init_fn->initialise ();
}

/**
 * Start up iPXE
 *
 * This function performs the repeatable initialisation steps, such as
 * probing devices.  You may call startup() and shutdown() multiple
 * times (as is done via the PXE API when PXENV_START_UNDI is used).
 */
void startup ( void ) {
	struct startup_fn *startup_fn;

	if ( started )
		return;

	/* Call registered startup functions */
	for_each_table_entry ( startup_fn, STARTUP_FNS ) {
		if ( startup_fn->startup )
			startup_fn->startup();
	}

	started = 1;
}

/**
 * Shut down iPXE
 *
 * @v flags		Shutdown behaviour flags
 *
 * This function reverses the actions of startup(), and leaves iPXE in
 * a state ready to be removed from memory.  You may call startup()
 * again after calling shutdown().
 *
 * Call this function only once, before either exiting main() or
 * starting up a non-returnable image.
 */
void shutdown ( int flags ) {
	struct startup_fn *startup_fn;

	if ( ! started )
		return;

	/* Call registered shutdown functions (in reverse order) */
	for_each_table_entry_reverse ( startup_fn, STARTUP_FNS ) {
		if ( startup_fn->shutdown )
			startup_fn->shutdown ( flags );
	}

	/* Reset console */
	console_reset();

	started = 0;
}
