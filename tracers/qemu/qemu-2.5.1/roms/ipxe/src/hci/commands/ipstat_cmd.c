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
#include <usr/ipstat.h>

/** @file
 *
 * IP statistics commands
 *
 */

/** "ipstat" options */
struct ipstat_options {};

/** "ipstat" option list */
static struct option_descriptor ipstat_opts[] = {};

/** "ipstat" command descriptor */
static struct command_descriptor ipstat_cmd =
	COMMAND_DESC ( struct ipstat_options, ipstat_opts, 0, 0, NULL );

/**
 * The "ipstat" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int ipstat_exec ( int argc, char **argv ) {
	struct ipstat_options opts;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &ipstat_cmd, &opts ) ) != 0 )
		return rc;

	ipstat();

	return 0;
}

/** Routing table management commands */
struct command ipstat_commands[] __command = {
	{
		.name = "ipstat",
		.exec = ipstat_exec,
	},
};
