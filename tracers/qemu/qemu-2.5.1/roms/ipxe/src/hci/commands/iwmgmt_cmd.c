/*
 * Copyright (C) 2009 Joshua Oreman <oremanj@rwcr.net>.
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

#include <ipxe/netdevice.h>
#include <ipxe/net80211.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <usr/iwmgmt.h>
#include <hci/ifmgmt_cmd.h>

/** @file
 *
 * Wireless interface management commands
 *
 */

/** "iwstat" options */
struct iwstat_options {};

/** "iwstat" option list */
static struct option_descriptor iwstat_opts[] = {};

/**
 * "iwstat" payload
 *
 * @v netdev		Network device
 * @v opts		Command options
 * @ret rc		Return status code
 */
static int iwstat_payload ( struct net_device *netdev,
			    struct iwstat_options *opts __unused ) {
	struct net80211_device *dev = net80211_get ( netdev );

	if ( dev )
		iwstat ( dev );

	return 0;
}

/** "iwstat" command descriptor */
static struct ifcommon_command_descriptor iwstat_cmd =
	IFCOMMON_COMMAND_DESC ( struct iwstat_options, iwstat_opts,
				0, MAX_ARGUMENTS, "[<interface>...]",
				iwstat_payload, 0 );

/**
 * The "iwstat" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int iwstat_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &iwstat_cmd );
}

/** "iwlist" options */
struct iwlist_options {};

/** "iwlist" option list */
static struct option_descriptor iwlist_opts[] = {};

/**
 * "iwlist" payload
 *
 * @v netdev		Network device
 * @v opts		Command options
 * @ret rc		Return status code
 */
static int iwlist_payload ( struct net_device *netdev,
			    struct iwlist_options *opts __unused ) {
	struct net80211_device *dev = net80211_get ( netdev );

	if ( dev )
		return iwlist ( dev );

	return 0;
}

/** "iwlist" command descriptor */
static struct ifcommon_command_descriptor iwlist_cmd =
	IFCOMMON_COMMAND_DESC ( struct iwlist_options, iwlist_opts,
				0, MAX_ARGUMENTS, "[<interface>...]",
				iwlist_payload, 0 );

/**
 * The "iwlist" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int iwlist_exec ( int argc, char **argv ) {
	return ifcommon_exec ( argc, argv, &iwlist_cmd );
}

/** Wireless interface management commands */
struct command iwmgmt_commands[] __command = {
	{
		.name = "iwstat",
		.exec = iwstat_exec,
	},
	{
		.name = "iwlist",
		.exec = iwlist_exec,
	},
};
