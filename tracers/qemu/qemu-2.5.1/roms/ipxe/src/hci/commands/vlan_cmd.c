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
#include <ipxe/vlan.h>

/** @file
 *
 * VLAN commands
 *
 */

/** "vcreate" options */
struct vcreate_options {
	/** VLAN tag */
	unsigned int tag;
	/** VLAN default priority */
	unsigned int priority;
};

/** "vcreate" option list */
static struct option_descriptor vcreate_opts[] = {
	OPTION_DESC ( "tag", 't', required_argument,
		      struct vcreate_options, tag, parse_integer ),
	OPTION_DESC ( "priority", 'p', required_argument,
		      struct vcreate_options, priority, parse_integer ),
};

/** "vcreate" command descriptor */
static struct command_descriptor vcreate_cmd =
	COMMAND_DESC ( struct vcreate_options, vcreate_opts, 1, 1,
		       "<trunk interface>" );

/**
 * "vcreate" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int vcreate_exec ( int argc, char **argv ) {
	struct vcreate_options opts;
	struct net_device *trunk;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &vcreate_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse trunk interface */
	if ( ( rc = parse_netdev ( argv[optind], &trunk ) ) != 0 )
		return rc;

	/* Create VLAN device */
	if ( ( rc = vlan_create ( trunk, opts.tag, opts.priority ) ) != 0 ) {
		printf ( "Could not create VLAN device: %s\n",
			 strerror ( rc ) );
		return rc;
	}

	return 0;
}

/** "vdestroy" options */
struct vdestroy_options {};

/** "vdestroy" option list */
static struct option_descriptor vdestroy_opts[] = {};

/** "vdestroy" command descriptor */
static struct command_descriptor vdestroy_cmd =
	COMMAND_DESC ( struct vdestroy_options, vdestroy_opts, 1, 1,
		       "<VLAN interface>" );

/**
 * "vdestroy" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int vdestroy_exec ( int argc, char **argv ) {
	struct vdestroy_options opts;
	struct net_device *netdev;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &vdestroy_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse trunk interface */
	if ( ( rc = parse_netdev ( argv[optind], &netdev ) ) != 0 )
		return rc;

	/* Destroy VLAN device */
	if ( ( rc = vlan_destroy ( netdev ) ) != 0 ) {
		printf ( "Could not destroy VLAN device: %s\n",
			 strerror ( rc ) );
		return rc;
	}

	return 0;
}

/** VLAN commands */
struct command vlan_commands[] __command = {
	{
		.name = "vcreate",
		.exec = vcreate_exec,
	},
	{
		.name = "vdestroy",
		.exec = vdestroy_exec,
	},
};
