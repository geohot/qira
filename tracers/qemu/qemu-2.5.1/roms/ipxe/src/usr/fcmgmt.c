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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ipxe/fc.h>
#include <ipxe/fcels.h>
#include <ipxe/monojob.h>
#include <usr/fcmgmt.h>

/** @file
 *
 * Fibre Channel management
 *
 */

/**
 * Print status of Fibre Channel port
 *
 * @v port		Fibre Channel port
 */
void fcportstat ( struct fc_port *port ) {
	printf ( "%s: %s id %s", port->name, fc_ntoa ( &port->port_wwn ),
		 fc_id_ntoa ( &port->port_id ) );
	printf ( " node %s\n  [Link:", fc_ntoa ( &port->node_wwn ) );
	if ( fc_link_ok ( &port->link ) ) {
		printf ( " up, %s", fc_ntoa ( &port->link_port_wwn ) );
		if ( ( port->flags & FC_PORT_HAS_FABRIC ) ) {
			printf ( " fabric" );
		} else {
			printf ( " id %s",
				 fc_id_ntoa ( &port->ptp_link_port_id ) );
		}
		printf ( " node %s]\n", fc_ntoa ( &port->link_node_wwn ) );
	} else {
		printf ( " down: %s]\n", strerror ( port->link.rc ) );
	}
}

/**
 * Print status of Fibre Channel peer
 *
 * @v peer		Fibre Channel peer
 */
void fcpeerstat ( struct fc_peer *peer ) {
	struct fc_ulp *ulp;
	uint8_t *param;
	unsigned int i;

	printf ( "%s:\n  [Link:", fc_ntoa ( &peer->port_wwn ) );
	if ( fc_link_ok ( &peer->link ) ) {
		printf ( " up, port %s id %s]\n", peer->port->name,
			 fc_id_ntoa ( &peer->port_id ) );
	} else {
		printf ( " down: %s]\n", strerror ( peer->link.rc ) );
	}

	list_for_each_entry ( ulp, &peer->ulps, list ) {
		printf ( "  [Type %02x link:", ulp->type );
		if ( fc_link_ok ( &ulp->link ) ) {
			printf ( " up, params" );
			param = ulp->param;
			for ( i = 0 ; i < ulp->param_len ; i++ ) {
				printf ( "%c%02x", ( ( i == 0 ) ? ' ' : ':' ),
					 param[i] );
			}
		} else {
			printf ( " down: %s", strerror ( ulp->link.rc ) );
		}
		printf ( "]\n" );
	}
}

/**
 * Issue Fibre Channel ELS
 *
 * @v port		Fibre Channel port
 * @v peer_port_id	Peer port ID
 * @v handler		ELS handler
 * @ret rc		Return status code
 */
int fcels ( struct fc_port *port, struct fc_port_id *peer_port_id,
	    struct fc_els_handler *handler ) {
	int rc;

	/* Initiate ELS */
	printf ( "%s %s to %s...",
		 port->name, handler->name, fc_id_ntoa ( peer_port_id ) );
	if ( ( rc = fc_els_request ( &monojob, port, peer_port_id,
				     handler ) ) != 0 ) {
		printf ( "%s\n", strerror ( rc ) );
		return rc;
	}

	/* Wait for ELS to complete */
	return monojob_wait ( "", 0 );
}
