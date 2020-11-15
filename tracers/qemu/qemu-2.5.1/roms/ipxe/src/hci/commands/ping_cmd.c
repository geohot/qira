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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/timer.h>
#include <usr/pingmgmt.h>

/** @file
 *
 * Ping command
 *
 */

/** Default payload length */
#define PING_DEFAULT_SIZE 64

/** Default timeout */
#define PING_DEFAULT_TIMEOUT TICKS_PER_SEC

/** "ping" options */
struct ping_options {
	/** Payload length */
	unsigned int size;
	/** Timeout (in ms) */
	unsigned long timeout;
	/** Number of packets to send (or zero for no limit) */
	unsigned int count;
	/** Inhibit output */
	int quiet;
};

/** "ping" option list */
static struct option_descriptor ping_opts[] = {
	OPTION_DESC ( "size", 's', required_argument,
		      struct ping_options, size, parse_integer ),
	OPTION_DESC ( "timeout", 't', required_argument,
		      struct ping_options, timeout, parse_timeout ),
	OPTION_DESC ( "count", 'c', required_argument,
		      struct ping_options, count, parse_integer ),
	OPTION_DESC ( "quiet", 'q', no_argument,
		      struct ping_options, quiet, parse_flag ),
};

/** "ping" command descriptor */
static struct command_descriptor ping_cmd =
	COMMAND_DESC ( struct ping_options, ping_opts, 1, 1, "<host>" );

/**
 * The "ping" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int ping_exec ( int argc, char **argv ) {
	struct ping_options opts;
	const char *hostname;
	int rc;

	/* Initialise options */
	memset ( &opts, 0, sizeof ( opts ) );
	opts.size = PING_DEFAULT_SIZE;
	opts.timeout = PING_DEFAULT_TIMEOUT;

	/* Parse options */
	if ( ( rc = reparse_options ( argc, argv, &ping_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse hostname */
	hostname = argv[optind];

	/* Ping */
	if ( ( rc = ping ( hostname, opts.timeout, opts.size,
			   opts.count, opts.quiet ) ) != 0 )
		return rc;

	return 0;
}

/** Ping command */
struct command ping_command __command = {
	.name = "ping",
	.exec = ping_exec,
};
