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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/interface.h>
#include <ipxe/iobuf.h>
#include <ipxe/process.h>
#include <ipxe/xfer.h>
#include <ipxe/fc.h>
#include <ipxe/fcns.h>

/** @file
 *
 * Fibre Channel name server lookups
 *
 */

/** A Fibre Channel name server query */
struct fc_ns_query {
	/** Reference count */
	struct refcnt refcnt;
	/** Fibre Channel exchange */
	struct interface xchg;

	/** Fibre Channel peer */
	struct fc_peer *peer;
	/** Fibre Channel port */
	struct fc_port *port;

	/** Process */
	struct process process;
	/** Success handler
	 *
	 * @v peer		Fibre Channel peer
	 * @v port		Fibre Channel port
	 * @v peer_port_id	Peer port ID
	 * @ret rc		Return status code
	 */
	int ( * done ) ( struct fc_peer *peer, struct fc_port *port,
			 struct fc_port_id *peer_port_id );
};

/**
 * Free name server query
 *
 * @v refcnt		Reference count
 */
static void fc_ns_query_free ( struct refcnt *refcnt ) {
	struct fc_ns_query *query =
		container_of ( refcnt, struct fc_ns_query, refcnt );

	fc_peer_put ( query->peer );
	fc_port_put ( query->port );
	free ( query );
}

/**
 * Close name server query
 *
 * @v query		Name server query
 * @v rc		Reason for close
 */
static void fc_ns_query_close ( struct fc_ns_query *query, int rc ) {

	/* Stop process */
	process_del ( &query->process );

	/* Shut down interfaces */
	intf_shutdown ( &query->xchg, rc );
}

/**
 * Receive name server query response
 *
 * @v query		Name server query
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int fc_ns_query_deliver ( struct fc_ns_query *query,
				 struct io_buffer *iobuf,
				 struct xfer_metadata *meta __unused ) {
	union fc_ns_response *resp = iobuf->data;
	struct fc_port_id *peer_port_id;
	int rc;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( resp->ct ) ) {
		DBGC ( query, "FCNS %p received underlength response (%zd "
		       "bytes)\n", query, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto done;
	}

	/* Handle response */
	switch ( ntohs ( resp->ct.code ) ) {
	case FC_GS_ACCEPT:
		if ( iob_len ( iobuf ) < sizeof ( resp->gid_pn ) ) {
			DBGC ( query, "FCNS %p received underlength accept "
			       "response (%zd bytes)\n",
			       query, iob_len ( iobuf ) );
			rc = -EINVAL;
			goto done;
		}
		peer_port_id = &resp->gid_pn.port_id.port_id;
		DBGC ( query, "FCNS %p resolved %s to %s via %s\n",
		       query, fc_ntoa ( &query->peer->port_wwn ),
		       fc_id_ntoa ( peer_port_id ), query->port->name );
		if ( ( rc = query->done ( query->peer, query->port,
					  peer_port_id ) ) != 0 )
			goto done;
		break;
	case FC_GS_REJECT:
		DBGC ( query, "FCNS %p rejected (reason %02x explanation "
		       "%02x)\n", query, resp->reject.ct.reason,
		       resp->reject.ct.explanation );
		break;
	default:
		DBGC ( query, "FCNS %p received invalid response code %04x\n",
		       query, ntohs ( resp->ct.code ) );
		rc = -ENOTSUP;
		goto done;
	}

	rc = 0;
 done:
	free_iob ( iobuf );
	fc_ns_query_close ( query, rc );
	return rc;
}

/**
 * Name server query process
 *
 * @v query		Name server query
 */
static void fc_ns_query_step ( struct fc_ns_query *query ) {
	struct xfer_metadata meta;
	struct fc_ns_gid_pn_request gid_pn;
	int xchg_id;
	int rc;

	/* Create exchange */
	if ( ( xchg_id = fc_xchg_originate ( &query->xchg, query->port,
					     &fc_gs_port_id,
					     FC_TYPE_CT ) ) < 0 ) {
		rc = xchg_id;
		DBGC ( query, "FCNS %p could not create exchange: %s\n",
		       query, strerror ( rc ) );
		fc_ns_query_close ( query, rc );
		return;
	}

	/* Construct query request */
	memset ( &gid_pn, 0, sizeof ( gid_pn ) );
	gid_pn.ct.revision = FC_CT_REVISION;
	gid_pn.ct.type = FC_GS_TYPE_DS;
	gid_pn.ct.subtype = FC_DS_SUBTYPE_NAME;
	gid_pn.ct.code = htons ( FC_NS_GET ( FC_NS_PORT_NAME, FC_NS_PORT_ID ));
	memcpy ( &gid_pn.port_wwn, &query->peer->port_wwn,
		 sizeof ( gid_pn.port_wwn ) );
	memset ( &meta, 0, sizeof ( meta ) );
	meta.flags = XFER_FL_OVER;

	/* Send query */
	if ( ( rc = xfer_deliver_raw_meta ( &query->xchg, &gid_pn,
					    sizeof ( gid_pn ), &meta ) ) != 0){
		DBGC ( query, "FCNS %p could not deliver query: %s\n",
		       query, strerror ( rc ) );
		fc_ns_query_close ( query, rc );
		return;
	}
}

/** Name server exchange interface operations */
static struct interface_operation fc_ns_query_xchg_op[] = {
	INTF_OP ( xfer_deliver, struct fc_ns_query *, fc_ns_query_deliver ),
	INTF_OP ( intf_close, struct fc_ns_query *, fc_ns_query_close ),
};

/** Name server exchange interface descriptor */
static struct interface_descriptor fc_ns_query_xchg_desc =
	INTF_DESC ( struct fc_ns_query, xchg, fc_ns_query_xchg_op );

/** Name server process descriptor */
static struct process_descriptor fc_ns_query_process_desc =
	PROC_DESC_ONCE ( struct fc_ns_query, process, fc_ns_query_step );

/**
 * Issue Fibre Channel name server query
 *
 * @v peer		Fibre Channel peer
 * @v port		Fibre Channel port
 * @ret rc		Return status code
 */
int fc_ns_query ( struct fc_peer *peer, struct fc_port *port,
		  int ( * done ) ( struct fc_peer *peer, struct fc_port *port,
				   struct fc_port_id *peer_port_id ) ) {
	struct fc_ns_query *query;

	/* Allocate and initialise structure */
	query = zalloc ( sizeof ( *query ) );
	if ( ! query )
		return -ENOMEM;
	ref_init ( &query->refcnt, fc_ns_query_free );
	intf_init ( &query->xchg, &fc_ns_query_xchg_desc, &query->refcnt );
	process_init ( &query->process, &fc_ns_query_process_desc,
		       &query->refcnt );
	query->peer = fc_peer_get ( peer );
	query->port = fc_port_get ( port );
	query->done = done;

	DBGC ( query, "FCNS %p querying %s via %s\n",
	       query, fc_ntoa ( &query->peer->port_wwn ), port->name );

	/* Mortalise self and return */
	ref_put ( &query->refcnt );
	return 0;
}
