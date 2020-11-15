/*
 * Copyright (C) 2012 Patrick Plenefisch <phplenefisch@wpi.edu>.
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
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdio.h>
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <usr/nslookup.h>

/** @file
 *
 * nslookup command
 *
 */

/** "nslookup" options */
struct nslookup_options {};

/** "nslookup" option list */
static struct option_descriptor nslookup_opts[] = {};

/** "nslookup" command descriptor */
static struct command_descriptor nslookup_cmd =
	COMMAND_DESC ( struct nslookup_options, nslookup_opts, 2, 2,
		       "<setting> <name>" );

/**
 * The "nslookup" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int nslookup_exec ( int argc, char **argv ) {
	struct nslookup_options opts;
	const char *name;
	const char *setting_name;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &nslookup_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse setting name */
	setting_name = argv[optind];

	/* Parse name to be resolved */
	name = argv[ optind + 1 ];

	/* Look up name */
	if ( ( rc = nslookup ( name, setting_name ) ) != 0 )
		return rc;

	return 0;
}

/** The "nslookup" command */
struct command nslookup_command __command = {
	.name = "nslookup",
	.exec = nslookup_exec,
};
