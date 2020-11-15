/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <errno.h>
#include <getopt.h>
#include <ipxe/netdevice.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <usr/ifmgmt.h>
#include <hci/ifmgmt_cmd.h>

/** @file
 *
 * Network interface management commands
 *
 */

/**
 * Execute if<xxx> command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @v cmd		Command descriptor
 * @v payload		Command to execute
 * @v verb		Verb describing the action of the command
 * @ret rc		Return status code
 */
int ifcommon_exec ( int argc, char **argv,
		    struct ifcommon_command_descriptor *ifcmd ) {
	struct command_descriptor *cmd = &ifcmd->cmd;
	uint8_t opts[cmd->len];
	struct net_device *netdev;
	int i;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, cmd, opts ) ) != 0 )
		return rc;

	if ( optind != argc ) {
		/* Treat arguments as a list of interfaces to try */
		for ( i = optind ; i < argc ; i++ ) {
			if ( ( rc = parse_netdev ( argv[i], &netdev ) ) != 0 )
				continue;
			if ( ( ( rc = ifcmd->payload ( netdev, opts ) ) == 0 )
			     && ifcmd->stop_on_first_success ) {
				return 0;
			}
		}
	} else {
		/* Try all interfaces */
		rc = -ENODEV;
		for_each_netdev ( netdev ) {
			if ( ( ( rc = ifcmd->payload ( netdev, opts ) ) == 0 )
			     && ifcmd->stop_on_first_success ) {
				return 0;
			}
		}
	}

	return rc;
}

/** "ifopen" options */
struct ifopen_options {};

/** "ifopen" option list */
static struct option_descriptor ifopen_opts[] = {};

/**
 * "ifopen" payload
 *
 * @v netdev		Network device
 * @v opts		Command options
 * @ret rc		Return status code
 */
static int ifopen_payload ( struct net_device *netdev,
			    struct ifopen_options *opts __unused ) {
	return ifopen ( netdev );
}

/** "ifopen" command descriptor */
static struct ifcommon_command_descriptor ifopen_cmd =
	IFCOMMON_COMMAND_DESC ( struct ifopen_options, ifopen_opts,
				0, MAX_ARGUMENTS, "[<interface>...]",
				ifopen_payload, 0 );

/**
 * The "ifopen" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int ifopen_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &ifopen_cmd );
}

/** "ifclose" options */
struct ifclose_options {};

/** "ifclose" option list */
static struct option_descriptor ifclose_opts[] = {};

/**
 * "ifclose" payload
 *
 * @v netdev		Network device
 * @v opts		Command options
 * @ret rc		Return status code
 */
static int ifclose_payload ( struct net_device *netdev,
			     struct ifclose_options *opts __unused ) {
	ifclose ( netdev );
	return 0;
}

/** "ifclose" command descriptor */
static struct ifcommon_command_descriptor ifclose_cmd =
	IFCOMMON_COMMAND_DESC ( struct ifclose_options, ifclose_opts,
				0, MAX_ARGUMENTS, "[<interface>...]",
				ifclose_payload, 0 );

/**
 * The "ifclose" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int ifclose_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &ifclose_cmd );
}

/** "ifstat" options */
struct ifstat_options {};

/** "ifstat" option list */
static struct option_descriptor ifstat_opts[] = {};

/**
 * "ifstat" payload
 *
 * @v netdev		Network device
 * @v opts		Command options
 * @ret rc		Return status code
 */
static int ifstat_payload ( struct net_device *netdev,
			    struct ifstat_options *opts __unused ) {
	ifstat ( netdev );
	return 0;
}

/** "ifstat" command descriptor */
static struct ifcommon_command_descriptor ifstat_cmd =
	IFCOMMON_COMMAND_DESC ( struct ifstat_options, ifstat_opts,
				0, MAX_ARGUMENTS, "[<interface>...]",
				ifstat_payload, 0 );

/**
 * The "ifstat" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int ifstat_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &ifstat_cmd );
}

/** "ifconf" options */
struct ifconf_options {
	/** Configurator */
	struct net_device_configurator *configurator;
};

/** "ifconf" option list */
static struct option_descriptor ifconf_opts[] = {
	OPTION_DESC ( "configurator", 'c', required_argument,
		      struct ifconf_options, configurator,
		      parse_netdev_configurator ),
};

/**
 * "ifconf" payload
 *
 * @v netdev		Network device
 * @v opts		Command options
 * @ret rc		Return status code
 */
static int ifconf_payload ( struct net_device *netdev,
			    struct ifconf_options *opts ) {
	int rc;

	/* Attempt configuration */
	if ( ( rc = ifconf ( netdev, opts->configurator ) ) != 0 ) {

		/* Close device on failure, to avoid memory exhaustion */
		netdev_close ( netdev );

		return rc;
	}

	return 0;
}

/** "ifconf" command descriptor */
static struct ifcommon_command_descriptor ifconf_cmd =
	IFCOMMON_COMMAND_DESC ( struct ifconf_options, ifconf_opts,
				0, MAX_ARGUMENTS, "[<interface>...]",
				ifconf_payload, 1 );

/**
 * The "ifconf" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
int ifconf_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &ifconf_cmd );
}

/** Interface management commands */
struct command ifmgmt_commands[] __command = {
	{
		.name = "ifopen",
		.exec = ifopen_exec,
	},
	{
		.name = "ifclose",
		.exec = ifclose_exec,
	},
	{
		.name = "ifstat",
		.exec = ifstat_exec,
	},
	{
		.name = "ifconf",
		.exec = ifconf_exec,
	},
};
