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

#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/reboot.h>

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * Reboot command
 *
 */

/** "reboot" options */
struct reboot_options {
	/** Perform a warm reboot */
	int warm;
};

/** "reboot" option list */
static struct option_descriptor reboot_opts[] = {
	OPTION_DESC ( "warm", 'w', no_argument,
		      struct reboot_options, warm, parse_flag ),
};

/** "reboot" command descriptor */
static struct command_descriptor reboot_cmd =
	COMMAND_DESC ( struct reboot_options, reboot_opts, 0, 0, NULL );

/**
 * The "reboot" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int reboot_exec ( int argc, char **argv ) {
	struct reboot_options opts;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &reboot_cmd, &opts ) ) != 0 )
		return rc;

	/* Reboot system */
	reboot ( opts.warm );

	return 0;
}

/** "reboot" command */
struct command reboot_command __command = {
	.name = "reboot",
	.exec = reboot_exec,
};
