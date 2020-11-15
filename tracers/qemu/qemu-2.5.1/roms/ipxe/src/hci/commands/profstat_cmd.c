/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <usr/profstat.h>

/** @file
 *
 * Profiling commands
 *
 */

/** "profstat" options */
struct profstat_options {};

/** "profstat" option list */
static struct option_descriptor profstat_opts[] = {};

/** "profstat" command descriptor */
static struct command_descriptor profstat_cmd =
	COMMAND_DESC ( struct profstat_options, profstat_opts, 0, 0, NULL );

/**
 * The "profstat" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int profstat_exec ( int argc, char **argv ) {
	struct profstat_options opts;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &profstat_cmd, &opts ) ) != 0 )
		return rc;

	profstat();

	return 0;
}

/** Profiling commands */
struct command profstat_commands[] __command = {
	{
		.name = "profstat",
		.exec = profstat_exec,
	},
};
