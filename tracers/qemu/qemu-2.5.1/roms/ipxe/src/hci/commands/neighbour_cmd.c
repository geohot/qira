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

/** @file
 *
 * Neighbour management commands
 *
 */

#include <getopt.h>
#include <ipxe/parseopt.h>
#include <ipxe/command.h>
#include <usr/neighmgmt.h>

/** "nstat" options */
struct nstat_options {};

/** "nstat" option list */
static struct option_descriptor nstat_opts[] = {};

/** "nstat" command descriptor */
static struct command_descriptor nstat_cmd =
	COMMAND_DESC ( struct nstat_options, nstat_opts, 0, 0, NULL );

/**
 * The "nstat" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int nstat_exec ( int argc, char **argv ) {
	struct nstat_options opts;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &nstat_cmd, &opts ) ) != 0)
		return rc;

	nstat();

	return 0;
}

/** Neighbour management commands */
struct command neighbour_commands[] __command = {
	{
		.name = "nstat",
		.exec = nstat_exec,
	},
};
