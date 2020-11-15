/*
 * Copyright (C) 2009 Daniel Verkamp <daniel@drv.nu>.
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
 * March-19-2009 @ 02:44: Added sleep command.
 * Shao Miller <shao.miller@yrdsb.edu.on.ca>.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/timer.h>

/** @file
 *
 * Time commands
 *
 */

/** "time" options */
struct time_options {};

/** "time" option list */
static struct option_descriptor time_opts[] = {};

/** "time" command descriptor */
static struct command_descriptor time_cmd =
	COMMAND_DESC ( struct time_options, time_opts, 1, MAX_ARGUMENTS,
		       "<command>" );

/**
 * "time" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int time_exec ( int argc, char **argv ) {
	struct time_options opts;
	unsigned long start;
	unsigned long elapsed;
	int decisecs;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &time_cmd, &opts ) ) != 0 )
		return rc;

	start = currticks();
	rc = execv ( argv[1], argv + 1 );
	elapsed = ( currticks() - start );
	decisecs = ( 10 * elapsed / ticks_per_sec() );

	printf ( "%s: %d.%ds\n", argv[0],
		 ( decisecs / 10 ), ( decisecs % 10 ) );

	return rc;
}

/** "time" command */
struct command time_command __command = {
	.name = "time",
	.exec = time_exec,
};
