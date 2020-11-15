/*
 * Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <string.h>
#include <stdio.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/login_ui.h>

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * Login commands
 *
 */

/** "login" options */
struct login_options {};

/** "login" option list */
static struct option_descriptor login_opts[] = {};

/** "login" command descriptor */
static struct command_descriptor login_cmd =
	COMMAND_DESC ( struct login_options, login_opts, 0, 0, NULL );

/**
 * "login" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int login_exec ( int argc, char **argv ) {
	struct login_options opts;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &login_cmd, &opts ) ) != 0 )
		return rc;

	/* Show login UI */
	if ( ( rc = login_ui() ) != 0 ) {
		printf ( "Could not set credentials: %s\n",
			 strerror ( rc ) );
		return rc;
	}

	return 0;
}

/** Login commands */
struct command login_command __command = {
	.name = "login",
	.exec = login_exec,
};
