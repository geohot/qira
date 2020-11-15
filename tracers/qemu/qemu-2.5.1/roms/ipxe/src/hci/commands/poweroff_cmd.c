/*
 * Copyright (C) 2013 Marin Hannache <ipxe@mareo.fr>.
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

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/reboot.h>

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * Power off command
 *
 */

/** "poweroff" options */
struct poweroff_options {};

/** "poweroff" option list */
static struct option_descriptor poweroff_opts[] = {};

/** "poweroff" command descriptor */
static struct command_descriptor poweroff_cmd =
	COMMAND_DESC ( struct poweroff_options, poweroff_opts, 0, 0, NULL );

/**
 * The "poweroff" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int poweroff_exec ( int argc, char **argv ) {
	struct poweroff_options opts;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &poweroff_cmd, &opts ) ) != 0 )
		return rc;

	/* Power off system */
	rc = poweroff();
	if ( rc != 0 )
		printf ( "Could not power off: %s\n", strerror ( rc ) );

	return rc;
}

/** "poweroff" command */
struct command poweroff_command __command = {
	.name = "poweroff",
	.exec = poweroff_exec,
};
