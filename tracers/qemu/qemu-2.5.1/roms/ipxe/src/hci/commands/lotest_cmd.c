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

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <ipxe/netdevice.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/if_ether.h>
#include <usr/lotest.h>

/** @file
 *
 * Loopback testing commands
 *
 */

/** "lotest" options */
struct lotest_options {
	/** MTU */
	unsigned int mtu;
};

/** "lotest" option list */
static struct option_descriptor lotest_opts[] = {
	OPTION_DESC ( "mtu", 'm', required_argument,
		      struct lotest_options, mtu, parse_integer ),
};

/** "lotest" command descriptor */
static struct command_descriptor lotest_cmd =
	COMMAND_DESC ( struct lotest_options, lotest_opts, 2, 2,
		       "<sending interface> <receiving interface>" );

/**
 * "lotest" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int lotest_exec ( int argc, char **argv ) {
	struct lotest_options opts;
	struct net_device *sender;
	struct net_device *receiver;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &lotest_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse sending interface name */
	if ( ( rc = parse_netdev ( argv[optind], &sender ) ) != 0 )
		return rc;

	/* Parse receiving interface name */
	if ( ( rc = parse_netdev ( argv[ optind + 1 ], &receiver ) ) != 0 )
		return rc;

	/* Use default MTU if none specified */
	if ( ! opts.mtu )
		opts.mtu = ETH_MAX_MTU;

	/* Perform loopback test */
	if ( ( rc = loopback_test ( sender, receiver, opts.mtu ) ) != 0 ) {
		printf ( "Test failed: %s\n", strerror ( rc ) );
		return rc;
	}

	return 0;
}

/** Loopback testing commands */
struct command lotest_command __command = {
	.name = "lotest",
	.exec = lotest_exec,
};
