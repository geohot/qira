/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <readline/readline.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/shell.h>
#include <config/branding.h>

/** @file
 *
 * Minimal command shell
 *
 */

/** The shell prompt string */
static const char shell_prompt[] = PRODUCT_SHORT_NAME "> ";

/**
 * "help" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int help_exec ( int argc __unused, char **argv __unused ) {
	struct command *command;
	unsigned int hpos = 0;

	printf ( "\nAvailable commands:\n\n" );
	for_each_table_entry ( command, COMMANDS ) {
		hpos += printf ( "  %s", command->name );
		if ( hpos > ( 16 * 4 ) ) {
			printf ( "\n" );
			hpos = 0;
		} else {
			while ( hpos % 16 ) {
				printf ( " " );
				hpos++;
			}
		}
	}
	printf ( "\n\nType \"<command> --help\" for further information\n\n" );
	return 0;
}

/** "help" command */
struct command help_command __command = {
	.name = "help",
	.exec = help_exec,
};

/**
 * Start command shell
 *
 */
int shell ( void ) {
	struct readline_history history;
	char *line;
	int rc = 0;

	/* Initialise shell history */
	memset ( &history, 0, sizeof ( history ) );

	/* Read and execute commands */
	do {
		readline_history ( shell_prompt, NULL, &history, &line );
		if ( line ) {
			rc = system ( line );
			free ( line );
		}
	} while ( ! shell_stopped ( SHELL_STOP_COMMAND_SEQUENCE ) );

	/* Discard shell history */
	history_free ( &history );

	return rc;
}

/** "shell" options */
struct shell_options {};

/** "shell" option list */
static struct option_descriptor shell_opts[] = {};

/** "shell" command descriptor */
static struct command_descriptor shell_cmd =
	COMMAND_DESC ( struct shell_options, shell_opts, 0, 0, NULL );

/**
 * "shell" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int shell_exec ( int argc, char **argv ) {
	struct shell_options opts;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &shell_cmd, &opts ) ) != 0 )
		return rc;

	/* Start shell */
	if ( ( rc = shell() ) != 0 )
		return rc;

	return 0;
}

/** "shell" command */
struct command shell_command __command = {
	.name = "shell",
	.exec = shell_exec,
};
