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
#include <errno.h>
#include <getopt.h>
#include <strings.h>
#include <ipxe/fc.h>
#include <ipxe/fcels.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/tables.h>
#include <usr/fcmgmt.h>

/** @file
 *
 * Fibre Channel management commands
 *
 */

/**
 * Parse Fibre Channel port name
 *
 * @v text		Text
 * @ret port		Fibre Channel port
 * @ret rc		Return status code
 */
static int parse_fc_port ( char *text, struct fc_port **port ) {

	/* Sanity check */
	assert ( text != NULL );

	/* Find Fibre Channel port */
	*port = fc_port_find ( text );
	if ( ! *port ) {
		printf ( "\"%s\": no such port\n", text );
		return -ENODEV;
	}

	return 0;
}

/**
 * Parse Fibre Channel port ID
 *
 * @v text		Text
 * @ret port_id		Fibre Channel port ID
 * @ret rc		Return status code
 */
static int parse_fc_port_id ( char *text, struct fc_port_id *port_id ) {
	int rc;

	/* Sanity check */
	assert ( text != NULL );

	/* Parse port ID */
	if ( ( rc = fc_id_aton ( text, port_id ) ) != 0 ) {
		printf ( "\"%s\": invalid port ID\n", text );
		return -EINVAL;
	}

	return 0;
}

/**
 * Parse Fibre Channel ELS handler name
 *
 * @v text		Text
 * @ret handler		Fibre Channel ELS handler
 * @ret rc		Return status code
 */
static int parse_fc_els_handler ( char *text, struct fc_els_handler **handler ){

	for_each_table_entry ( (*handler), FC_ELS_HANDLERS ) {
		if ( strcasecmp ( (*handler)->name, text ) == 0 )
			return 0;
	}

	printf ( "\"%s\": unrecognised ELS\n", text );
	return -ENOENT;
}

/** "fcstat" options */
struct fcstat_options {};

/** "fcstat" option list */
static struct option_descriptor fcstat_opts[] = {};

/** "fcstat" command descriptor */
static struct command_descriptor fcstat_cmd =
	COMMAND_DESC ( struct fcstat_options, fcstat_opts, 0, 0, NULL );

/**
 * The "fcstat" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int fcstat_exec ( int argc, char **argv ) {
	struct fcstat_options opts;
	struct fc_port *port;
	struct fc_peer *peer;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &fcstat_cmd, &opts ) ) != 0 )
		return rc;

	list_for_each_entry ( port, &fc_ports, list )
		fcportstat ( port );
	list_for_each_entry ( peer, &fc_peers, list )
		fcpeerstat ( peer );

	return 0;
}

/** "fcels" options */
struct fcels_options {
	/** Fibre Channel port */
	struct fc_port *port;
	/** Fibre Channel peer port ID */
	struct fc_port_id peer_port_id;
};

/** "fcels" option list */
static struct option_descriptor fcels_opts[] = {
	OPTION_DESC ( "port", 'p', required_argument,
		      struct fcels_options, port, parse_fc_port ),
	OPTION_DESC ( "id", 'i', required_argument,
		      struct fcels_options, peer_port_id, parse_fc_port_id ),
};

/** "fcels" command descriptor */
static struct command_descriptor fcels_cmd =
	COMMAND_DESC ( struct fcels_options, fcels_opts, 1, 1, "<request>" );

/**
 * The "fcels" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int fcels_exec ( int argc, char **argv ) {
	struct fcels_options opts;
	struct fc_els_handler *handler;
	struct fc_port_id *id;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &fcels_cmd, &opts ) ) != 0 )
		return rc;

	/* Parse ELS handler */
	if ( ( rc = parse_fc_els_handler ( argv[optind], &handler ) ) != 0 )
		return rc;

	/* Use first port if no port specified */
	if ( ! opts.port ) {
		opts.port = list_first_entry ( &fc_ports, struct fc_port,
					       list );
		if ( ! opts.port ) {
			printf ( "No ports\n" );
			return -ENODEV;
		}
	}

	/* Use link peer port ID if no peer port ID specified */
	id = &opts.peer_port_id;
	if ( memcmp ( id, &fc_empty_port_id, sizeof ( *id ) ) == 0 ) {
		if ( fc_link_ok ( &opts.port->link ) &&
		     ! ( opts.port->flags & FC_PORT_HAS_FABRIC ) ) {
			id = &opts.port->ptp_link_port_id;
		} else {
			id = &fc_f_port_id;
		}
	}

	/** Issue ELS */
	if ( ( rc = fcels ( opts.port, id, handler ) ) != 0 )
		return rc;

	return 0;
}

/** Fibre Channel management commands */
struct command fcmgmt_commands[] __command = {
	{
		.name = "fcstat",
		.exec = fcstat_exec,
	},
	{
		.name = "fcels",
		.exec = fcels_exec,
	},
};
