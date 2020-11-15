/*
 * Copyright (C) 2008 Stefan Hajnoczi <stefanha@gmail.com>.
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
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/gdbstub.h>

/** @file
 *
 * GDB stub command
 *
 */

/**
 * Parse GDB transport name
 *
 * @v text		Text
 * @ret trans		GDB transport
 * @ret rc		Return status code
 */
static int parse_gdb_transport ( const char *text,
				 struct gdb_transport **trans ) {

	/* Sanity check */
	assert ( text != NULL );

	/* Find transport */
	*trans = find_gdb_transport ( text );
	if ( ! *trans ) {
		printf ( "\"%s\": no such transport (is it compiled in?)\n",
			 text );
		return -ENOTSUP;
	}

	return 0;
}

/** "gdbstub" options */
struct gdbstub_options {};

/** "gdbstub" option list */
static struct option_descriptor gdbstub_opts[] = {};

/** "gdbstub" command descriptor */
static struct command_descriptor gdbstub_cmd =
	COMMAND_DESC ( struct gdbstub_options, gdbstub_opts, 1, MAX_ARGUMENTS,
		       "<transport> [<options>...]" );

/**
 * The "gdbstub" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int gdbstub_exec ( int argc, char **argv ) {
	struct gdbstub_options opts;
	struct gdb_transport *trans;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &gdbstub_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse transport name */
	if ( ( rc = parse_gdb_transport ( argv[optind++], &trans ) ) != 0 )
		return rc;

	/* Initialise transport */
	if ( trans->init ) {
		if ( ( rc = trans->init ( argc - optind,
					  &argv[optind] ) ) != 0 ) {
			return rc;
		}
	}

	/* Enter GDB stub */
	gdbstub_start ( trans );

	return 0;
}

/** GDB stub commands */
struct command gdbstub_commands[] __command = {
	{
		.name = "gdbstub",
		.exec = gdbstub_exec,
	},
};
