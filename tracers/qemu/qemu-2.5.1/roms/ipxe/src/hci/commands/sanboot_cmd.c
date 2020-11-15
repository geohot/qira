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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/uri.h>
#include <ipxe/sanboot.h>
#include <usr/autoboot.h>

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * SAN commands
 *
 */

/** "sanboot" options */
struct sanboot_options {
	/** Drive number */
	unsigned int drive;
	/** Do not describe SAN device */
	int no_describe;
	/** Keep SAN device */
	int keep;
};

/** "sanboot" option list */
static union {
	/* "sanboot" takes all three options */
	struct option_descriptor sanboot[3];
	/* "sanhook" takes only --drive and --no-describe */
	struct option_descriptor sanhook[2];
	/* "sanunhook" takes only --drive */
	struct option_descriptor sanunhook[1];
} opts = {
	.sanboot = {
		OPTION_DESC ( "drive", 'd', required_argument,
			      struct sanboot_options, drive, parse_integer ),
		OPTION_DESC ( "no-describe", 'n', no_argument,
			      struct sanboot_options, no_describe, parse_flag ),
		OPTION_DESC ( "keep", 'k', no_argument,
			      struct sanboot_options, keep, parse_flag ),
	},
};


/** "sanhook" command descriptor */
static struct command_descriptor sanhook_cmd =
	COMMAND_DESC ( struct sanboot_options, opts.sanhook, 1, 1,
		       "<root-path>" );

/** "sanboot" command descriptor */
static struct command_descriptor sanboot_cmd =
	COMMAND_DESC ( struct sanboot_options, opts.sanboot, 0, 1,
		       "[<root-path>]" );

/** "sanunhook" command descriptor */
static struct command_descriptor sanunhook_cmd =
	COMMAND_DESC ( struct sanboot_options, opts.sanunhook, 0, 0, NULL );

/**
 * The "sanboot", "sanhook" and "sanunhook" commands
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v default_flags	Default set of flags for uriboot()
 * @v no_root_path_flags Additional flags to apply if no root path is present
 * @ret rc		Return status code
 */
static int sanboot_core_exec ( int argc, char **argv,
			       struct command_descriptor *cmd,
			       int default_flags, int no_root_path_flags ) {
	struct sanboot_options opts;
	const char *root_path;
	struct uri *uri;
	int flags;
	int rc;

	/* Initialise options */
	memset ( &opts, 0, sizeof ( opts ) );
	opts.drive = san_default_drive();

	/* Parse options */
	if ( ( rc = reparse_options ( argc, argv, cmd, &opts ) ) != 0 )
		goto err_parse_options;

	/* Parse root path, if present */
	if ( argc > optind ) {
		root_path = argv[optind];
		uri = parse_uri ( root_path );
		if ( ! uri ) {
			rc = -ENOMEM;
			goto err_parse_uri;
		}
	} else {
		root_path = NULL;
		uri = NULL;
	}

	/* Construct flags */
	flags = default_flags;
	if ( opts.no_describe )
		flags |= URIBOOT_NO_SAN_DESCRIBE;
	if ( opts.keep )
		flags |= URIBOOT_NO_SAN_UNHOOK;
	if ( ! root_path )
		flags |= no_root_path_flags;

	/* Boot from root path */
	if ( ( rc = uriboot ( NULL, uri, opts.drive, flags ) ) != 0 )
		goto err_uriboot;

 err_uriboot:
	uri_put ( uri );
 err_parse_uri:
 err_parse_options:
	return rc;
}

/**
 * The "sanhook" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int sanhook_exec ( int argc, char **argv ) {
	return sanboot_core_exec ( argc, argv, &sanhook_cmd,
				   ( URIBOOT_NO_SAN_BOOT |
				     URIBOOT_NO_SAN_UNHOOK ), 0 );
}

/**
 * The "sanboot" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int sanboot_exec ( int argc, char **argv ) {
	return sanboot_core_exec ( argc, argv, &sanboot_cmd,
				   0, URIBOOT_NO_SAN_UNHOOK );
}

/**
 * The "sanunhook" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int sanunhook_exec ( int argc, char **argv ) {
	return sanboot_core_exec ( argc, argv, &sanunhook_cmd,
				   ( URIBOOT_NO_SAN_DESCRIBE |
				     URIBOOT_NO_SAN_BOOT ), 0 );
}

/** SAN commands */
struct command sanboot_commands[] __command = {
	{
		.name = "sanhook",
		.exec = sanhook_exec,
	},
	{
		.name = "sanboot",
		.exec = sanboot_exec,
	},
	{
		.name = "sanunhook",
		.exec = sanunhook_exec,
	},
};
