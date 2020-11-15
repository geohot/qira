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

#include <ipxe/netdevice.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <hci/ifmgmt_cmd.h>
#include <pxe_call.h>

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * PXE commands
 *
 */

/** "startpxe" options */
struct startpxe_options {};

/** "startpxe" option list */
static struct option_descriptor startpxe_opts[] = {};

/**
 * "startpxe" payload
 *
 * @v netdev		Network device
 * @v opts		Command options
 * @ret rc		Return status code
 */
static int startpxe_payload ( struct net_device *netdev,
			      struct startpxe_options *opts __unused ) {

	if ( netdev_is_open ( netdev ) )
		pxe_activate ( netdev );

	return 0;
}

/** "startpxe" command descriptor */
static struct ifcommon_command_descriptor startpxe_cmd =
	IFCOMMON_COMMAND_DESC ( struct startpxe_options, startpxe_opts,
				0, MAX_ARGUMENTS, "[<interface>]",
				startpxe_payload, 0 );

/**
 * The "startpxe" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int startpxe_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &startpxe_cmd );
}

/** "stoppxe" options */
struct stoppxe_options {};

/** "stoppxe" option list */
static struct option_descriptor stoppxe_opts[] = {};

/** "stoppxe" command descriptor */
static struct command_descriptor stoppxe_cmd =
	COMMAND_DESC ( struct stoppxe_options, stoppxe_opts, 0, 0, NULL );

/**
 * The "stoppxe" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int stoppxe_exec ( int argc __unused, char **argv __unused ) {
	struct stoppxe_options opts;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &stoppxe_cmd, &opts ) ) != 0 )
		return rc;

	pxe_deactivate();

	return 0;
}

/** PXE commands */
struct command pxe_commands[] __command = {
	{
		.name = "startpxe",
		.exec = startpxe_exec,
	},
	{
		.name = "stoppxe",
		.exec = stoppxe_exec,
	},
};
