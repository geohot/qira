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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/interface.h>
#include <ipxe/xfer.h>
#include <ipxe/iobuf.h>
#include <ipxe/process.h>
#include <ipxe/fc.h>
#include <ipxe/fcels.h>

/** @file
 *
 * Fibre Channel Extended Link Services
 *
 */

/** Fibre Channel ELS transaction debug message format */
#define FCELS_FMT "FCELS %s %s %s %s"

/** Fibre Channel ELS transaction debug message arguments */
#define FCELS_ARGS( els )						\
	(els)->port->name,						\
	( (els)->handler ? (els)->handler->name : "unknown ELS" ),	\
	( fc_els_is_request ( els ) ? "to" : "from" ),			\
	fc_id_ntoa ( &(els)->peer_port_id )

struct fc_els_handler fc_els_unknown_handler __fc_els_handler;

/**
 * Free Fibre Channel ELS transaction
 *
 * @v refcnt		Reference count
 */
static void fc_els_free ( struct refcnt *refcnt ) {
	struct fc_els *els = container_of ( refcnt, struct fc_els, refcnt );

	assert ( ! process_running ( &els->process ) );
	fc_port_put ( els->port );
	free ( els );
}

/**
 * Close Fibre Channel ELS transaction
 *
 * @v els		Fibre Channel ELS transaction
 * @v rc		Reason for close
 */
static void fc_els_close ( struct fc_els *els, int rc ) {

	if ( rc != 0 ) {
		DBGC ( els, FCELS_FMT " complete (%s)\n",
		       FCELS_ARGS ( els ), strerror ( rc ) );
	}

	/* Stop process */
	process_del ( &els->process );

	/* Shut down interfaces */
	intf_shutdown ( &els->xchg, rc );
	intf_shutdown ( &els->job, rc );
}

/**
 * Detect Fibre Channel ELS frame handler
 *
 * @v els		Fibre Channel ELS transaction
 * @v command		ELS command code
 * @ret handler		ELS handler, or NULL
 */
static struct fc_els_handler * fc_els_detect ( struct fc_els *els,
					       const void *data,
					       size_t len ) {
	const struct fc_els_frame_common *frame = data;
	struct fc_els_handler *handler;
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *frame ) )
		return NULL;

	/* Try each handler in turn */
	for_each_table_entry ( handler, FC_ELS_HANDLERS ) {
		if ( ( rc = handler->detect ( els, data, len ) ) == 0 )
			return handler;
	}

	return NULL;
}

/**
 * Transmit Fibre Channel ELS frame
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		Data to transmit
 * @v len		Length of data
 * @ret rc		Return status code
 */
int fc_els_tx ( struct fc_els *els, const void *data, size_t len ) {
	struct xfer_metadata meta;
	struct sockaddr_fc dest;
	int rc;

	DBGC2 ( els, FCELS_FMT " transmitting:\n", FCELS_ARGS ( els ) );
	DBGC2_HDA ( els, 0, data, len );

	/* Construct metadata */
	memset ( &meta, 0, sizeof ( meta ) );
	meta.flags = ( fc_els_is_request ( els ) ?
		       XFER_FL_OVER : ( XFER_FL_RESPONSE | XFER_FL_OUT ) );
	meta.dest = fc_fill_sockaddr ( &dest, &els->peer_port_id );

	/* Transmit frame */
	if ( ( rc = xfer_deliver_raw_meta ( &els->xchg, data, len,
					    &meta ) ) != 0 ) {
		DBGC ( els, FCELS_FMT " could not deliver frame: %s\n",
		       FCELS_ARGS ( els ), strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Receive Fibre Channel ELS frame
 *
 * @v els		Fibre Channel ELS transaction
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int fc_els_rx ( struct fc_els *els,
		       struct io_buffer *iobuf,
		       struct xfer_metadata *meta ) {
	struct fc_els_frame_common *frame = iobuf->data;
	struct sockaddr_fc *src = ( ( struct sockaddr_fc * ) meta->src );
	struct sockaddr_fc *dest = ( ( struct sockaddr_fc * ) meta->dest );
	size_t len = iob_len ( iobuf );
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *frame ) ) {
		DBGC ( els, FCELS_FMT " received underlength frame:\n",
		       FCELS_ARGS ( els ) );
		DBGC_HDA ( els, 0, frame, len );
		rc = -EINVAL;
		goto done;
	}
	if ( ! src ) {
		DBGC ( els, FCELS_FMT " received frame missing source "
		       "address:\n", FCELS_ARGS ( els ) );
		rc = -EINVAL;
		goto done;
	}
	if ( ! dest ) {
		DBGC ( els, FCELS_FMT " received frame missing destination "
		       "address:\n", FCELS_ARGS ( els ) );
		rc = -EINVAL;
		goto done;
	}

	/* Check for rejection responses */
	if ( fc_els_is_request ( els ) &&
	     ( frame->command != FC_ELS_LS_ACC ) ) {
		DBGC ( els, FCELS_FMT " rejected:\n", FCELS_ARGS ( els ) );
		DBGC_HDA ( els, 0, frame, len );
		rc = -EACCES;
		goto done;
	}

	/* Update port IDs */
	memcpy ( &els->port_id, &dest->sfc_port_id, sizeof ( els->port_id ) );
	memcpy ( &els->peer_port_id, &src->sfc_port_id,
		 sizeof ( els->peer_port_id ) );

	/* Determine handler, if necessary */
	if ( ! els->handler )
		els->handler = fc_els_detect ( els, frame, len );
	if ( ! els->handler )
		els->handler = &fc_els_unknown_handler;

	DBGC2 ( els, FCELS_FMT " received:\n", FCELS_ARGS ( els ) );
	DBGC2_HDA ( els, 0, frame, len );

	/* Handle received frame */
	if ( ( rc = els->handler->rx ( els, frame, len ) ) != 0 ) {
		DBGC ( els, FCELS_FMT " could not handle received frame: "
		       "%s\n", FCELS_ARGS ( els ), strerror ( rc ) );
		DBGC_HDA ( els, 0, frame, len );
		goto done;
	}

 done:
	/* Free I/O buffer */
	free_iob ( iobuf );

	/* Close transaction */
	fc_els_close ( els, rc );

	return rc;
}

/** Fibre Channel ELS exchange interface operations */
static struct interface_operation fc_els_xchg_op[] = {
	INTF_OP ( xfer_deliver, struct fc_els *, fc_els_rx ),
	INTF_OP ( intf_close, struct fc_els *, fc_els_close ),
};

/** Fibre Channel ELS exchange interface descriptor */
static struct interface_descriptor fc_els_xchg_desc =
	INTF_DESC ( struct fc_els, xchg, fc_els_xchg_op );

/** Fibre Channel ELS job control interface operations */
static struct interface_operation fc_els_job_op[] = {
	INTF_OP ( intf_close, struct fc_els *, fc_els_close ),
};

/** Fibre Channel ELS job control interface descriptor */
static struct interface_descriptor fc_els_job_desc =
	INTF_DESC ( struct fc_els, job, fc_els_job_op );

/**
 * Fibre Channel ELS process
 *
 * @v els		Fibre Channel ELS transaction
 */
static void fc_els_step ( struct fc_els *els ) {
	int xchg_id;
	int rc;

	/* Sanity check */
	assert ( fc_els_is_request ( els ) );

	/* Create exchange */
	if ( ( xchg_id = fc_xchg_originate ( &els->xchg, els->port,
					     &els->peer_port_id,
					     FC_TYPE_ELS ) ) < 0 ) {
		rc = xchg_id;
		DBGC ( els, FCELS_FMT " could not create exchange: %s\n",
		       FCELS_ARGS ( els ), strerror ( rc ) );
		fc_els_close ( els, rc );
		return;
	}

	/* Transmit request */
	if ( ( rc = els->handler->tx ( els ) ) != 0 ) {
		DBGC ( els, FCELS_FMT " could not transmit request: %s\n",
		       FCELS_ARGS ( els ), strerror ( rc ) );
		fc_els_close ( els, rc );
		return;
	}
}

/** Fibre Channel ELS process descriptor */
static struct process_descriptor fc_els_process_desc =
	PROC_DESC_ONCE ( struct fc_els, process, fc_els_step );

/**
 * Create ELS transaction
 *
 * @v port		Fibre Channel port
 * @v port_id		Local port ID
 * @v peer_port_id	Peer port ID
 * @ret els		Fibre Channel ELS transaction, or NULL
 */
static struct fc_els * fc_els_create ( struct fc_port *port,
				       struct fc_port_id *port_id,
				       struct fc_port_id *peer_port_id ) {
	struct fc_els *els;

	/* Allocate and initialise structure */
	els = zalloc ( sizeof ( *els ) );
	if ( ! els )
		return NULL;
	ref_init ( &els->refcnt, fc_els_free );
	intf_init ( &els->job, &fc_els_job_desc, &els->refcnt );
	intf_init ( &els->xchg, &fc_els_xchg_desc, &els->refcnt );
	process_init_stopped ( &els->process, &fc_els_process_desc,
			       &els->refcnt );
	els->port = fc_port_get ( port );
	memcpy ( &els->port_id, port_id, sizeof ( els->port_id ) );
	memcpy ( &els->peer_port_id, peer_port_id,
		 sizeof ( els->peer_port_id ) );
	return els;
}

/**
 * Create ELS request
 *
 * @v job		Parent job-control interface
 * @v port		Fibre Channel port
 * @v peer_port_id	Peer port ID
 * @v handler		ELS handler
 * @ret rc		Return status code
 */
int fc_els_request ( struct interface *job, struct fc_port *port,
		     struct fc_port_id *peer_port_id,
		     struct fc_els_handler *handler ) {
	struct fc_els *els;

	/* Allocate and initialise structure */
	els = fc_els_create ( port, &port->port_id, peer_port_id );
	if ( ! els )
		return -ENOMEM;
	els->handler = handler;
	els->flags = FC_ELS_REQUEST;
	process_add ( &els->process );

	/* Attach to parent job interface, mortalise self, and return */
	intf_plug_plug ( &els->job, job );
	ref_put ( &els->refcnt );
	return 0;
}

/**
 * Create ELS response
 *
 * @v xchg		Exchange interface
 * @v port		Fibre Channel port
 * @v port_id		Local port ID
 * @v peer_port_id	Peer port ID
 * @ret rc		Return status code
 */
static int fc_els_respond ( struct interface *xchg, struct fc_port *port,
			    struct fc_port_id *port_id,
			    struct fc_port_id *peer_port_id ) {
	struct fc_els *els;

	/* Allocate and initialise structure */
	els = fc_els_create ( port, port_id, peer_port_id );
	if ( ! els )
		return -ENOMEM;

	/* Attach to exchange interface, mortalise self, and return */
	intf_plug_plug ( &els->xchg, xchg );
	ref_put ( &els->refcnt );
	return 0;
}

/** Fibre Channel ELS responder */
struct fc_responder fc_els_responder __fc_responder = {
	.type = FC_TYPE_ELS,
	.respond = fc_els_respond,
};

/******************************************************************************
 *
 * Unknown ELS handler
 *
 ******************************************************************************
 */

/**
 * Transmit unknown ELS request
 *
 * @v els		Fibre Channel ELS transaction
 * @ret rc		Return status code
 */
static int fc_els_unknown_tx ( struct fc_els *els __unused ) {
	return -ENOTSUP;
}

/**
 * Transmit unknown ELS response
 *
 * @v els		Fibre Channel ELS transaction
 * @ret rc		Return status code
 */
static int fc_els_unknown_tx_response ( struct fc_els *els ) {
	struct fc_ls_rjt_frame ls_rjt;

	/* Construct LS_RJT */
	memset ( &ls_rjt, 0, sizeof ( ls_rjt ) );
	ls_rjt.command = FC_ELS_LS_RJT;
	ls_rjt.reason = FC_ELS_RJT_UNSUPPORTED;

	/* Transmit LS_RJT */
	return fc_els_tx ( els, &ls_rjt, sizeof ( ls_rjt ) );
}

/**
 * Receive unknown ELS
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_unknown_rx ( struct fc_els *els, void *data, size_t len ) {
	int rc;

	DBGC ( els, FCELS_FMT ":\n", FCELS_ARGS ( els ) );
	DBGC_HDA ( els, 0, data, len );

	/* Transmit response, if applicable */
	if ( ! fc_els_is_request ( els ) ) {
		if ( ( rc = fc_els_unknown_tx_response ( els ) ) != 0 )
			return rc;
	}

	return 0;
}

/**
 * Detect unknown ELS
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_unknown_detect ( struct fc_els *els __unused,
				   const void *data __unused,
				   size_t len __unused ) {
	return -ENOTSUP;
}

/** Unknown ELS handler */
struct fc_els_handler fc_els_unknown_handler __fc_els_handler = {
	.name		= "UNKNOWN",
	.tx		= fc_els_unknown_tx,
	.rx		= fc_els_unknown_rx,
	.detect		= fc_els_unknown_detect,
};

/******************************************************************************
 *
 * FLOGI
 *
 ******************************************************************************
 */

/**
 * Transmit FLOGI
 *
 * @v els		Fibre Channel ELS transaction
 * @ret rc		Return status code
 */
static int fc_els_flogi_tx ( struct fc_els *els ) {
	struct fc_login_frame flogi;

	/* Construct FLOGI */
	memset ( &flogi, 0, sizeof ( flogi ) );
	flogi.command = fc_els_tx_command ( els, FC_ELS_FLOGI );
	flogi.common.version = htons ( FC_LOGIN_VERSION );
	flogi.common.credit = htons ( FC_LOGIN_DEFAULT_B2B );
	flogi.common.flags = htons ( FC_LOGIN_CONTINUOUS_OFFSET );
	flogi.common.mtu = htons ( FC_LOGIN_DEFAULT_MTU );
	memcpy ( &flogi.port_wwn, &els->port->port_wwn,
		 sizeof ( flogi.port_wwn ) );
	memcpy ( &flogi.node_wwn, &els->port->node_wwn,
		 sizeof ( flogi.node_wwn ) );
	flogi.class3.flags = htons ( FC_LOGIN_CLASS_VALID |
				     FC_LOGIN_CLASS_SEQUENTIAL );

	/* Transmit FLOGI */
	return fc_els_tx ( els, &flogi, sizeof ( flogi ) );
}

/**
 * Receive FLOGI
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_flogi_rx ( struct fc_els *els, void *data, size_t len ) {
	struct fc_login_frame *flogi = data;
	int has_fabric;
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *flogi ) ) {
		DBGC ( els, FCELS_FMT " received underlength frame:\n",
		       FCELS_ARGS ( els ) );
		DBGC_HDA ( els, 0, data, len );
		return -EINVAL;
	}

	/* Extract parameters */
	has_fabric = ( flogi->common.flags & htons ( FC_LOGIN_F_PORT ) );
	DBGC ( els, FCELS_FMT " has node %s\n", FCELS_ARGS ( els ),
	       fc_ntoa ( &flogi->node_wwn ) );
	DBGC ( els, FCELS_FMT " has port %s\n", FCELS_ARGS ( els ),
	       fc_ntoa ( &flogi->port_wwn ) );
	if ( has_fabric ) {
		DBGC ( els, FCELS_FMT " has fabric with", FCELS_ARGS ( els ) );
		DBGC ( els, " local ID %s\n", fc_id_ntoa ( &els->port_id ) );
	} else {
		DBGC ( els, FCELS_FMT " has point-to-point link\n",
		       FCELS_ARGS ( els ) );
	}

	/* Log in port */
	if ( ( rc = fc_port_login ( els->port, &els->port_id, &flogi->node_wwn,
				    &flogi->port_wwn, has_fabric ) ) != 0 ) {
		DBGC ( els, FCELS_FMT " could not log in port: %s\n",
		       FCELS_ARGS ( els ), strerror ( rc ) );
		return rc;
	}

	/* Send any responses to the newly-assigned peer port ID, if
	 * applicable.
	 */
	if ( ! has_fabric ) {
		memcpy ( &els->peer_port_id, &els->port->ptp_link_port_id,
			 sizeof ( els->peer_port_id ) );
	}

	/* Transmit response, if applicable */
	if ( ! fc_els_is_request ( els ) ) {
		if ( ( rc = fc_els_flogi_tx ( els ) ) != 0 )
			return rc;
	}

	return 0;
}

/**
 * Detect FLOGI
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_flogi_detect ( struct fc_els *els __unused, const void *data,
				 size_t len __unused ) {
	const struct fc_login_frame *flogi = data;

	/* Check for FLOGI */
	if ( flogi->command != FC_ELS_FLOGI )
		return -EINVAL;

	return 0;
}

/** FLOGI ELS handler */
struct fc_els_handler fc_els_flogi_handler __fc_els_handler = {
	.name		= "FLOGI",
	.tx		= fc_els_flogi_tx,
	.rx		= fc_els_flogi_rx,
	.detect		= fc_els_flogi_detect,
};

/**
 * Create FLOGI request
 *
 * @v parent		Parent interface
 * @v port		Fibre Channel port
 * @ret rc		Return status code
 */
int fc_els_flogi ( struct interface *parent, struct fc_port *port ) {

	return fc_els_request ( parent, port, &fc_f_port_id,
				&fc_els_flogi_handler );
}

/******************************************************************************
 *
 * PLOGI
 *
 ******************************************************************************
 */

/**
 * Transmit PLOGI
 *
 * @v els		Fibre Channel ELS transaction
 * @ret rc		Return status code
 */
static int fc_els_plogi_tx ( struct fc_els *els ) {
	struct fc_login_frame plogi;

	/* Construct PLOGI */
	memset ( &plogi, 0, sizeof ( plogi ) );
	plogi.command = fc_els_tx_command ( els, FC_ELS_PLOGI );
	plogi.common.version = htons ( FC_LOGIN_VERSION );
	plogi.common.credit = htons ( FC_LOGIN_DEFAULT_B2B );
	plogi.common.flags = htons ( FC_LOGIN_CONTINUOUS_OFFSET );
	plogi.common.mtu = htons ( FC_LOGIN_DEFAULT_MTU );
	plogi.common.u.plogi.max_seq = htons ( FC_LOGIN_DEFAULT_MAX_SEQ );
	plogi.common.u.plogi.rel_offs = htons ( FC_LOGIN_DEFAULT_REL_OFFS );
	plogi.common.e_d_tov = htonl ( FC_LOGIN_DEFAULT_E_D_TOV );
	memcpy ( &plogi.port_wwn, &els->port->port_wwn,
		 sizeof ( plogi.port_wwn ) );
	memcpy ( &plogi.node_wwn, &els->port->node_wwn,
		 sizeof ( plogi.node_wwn ) );
	plogi.class3.flags = htons ( FC_LOGIN_CLASS_VALID |
				     FC_LOGIN_CLASS_SEQUENTIAL );
	plogi.class3.mtu = htons ( FC_LOGIN_DEFAULT_MTU );
	plogi.class3.max_seq = htons ( FC_LOGIN_DEFAULT_MAX_SEQ );
	plogi.class3.max_seq_per_xchg = 1;

	/* Transmit PLOGI */
	return fc_els_tx ( els, &plogi, sizeof ( plogi ) );
}

/**
 * Receive PLOGI
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_plogi_rx ( struct fc_els *els, void *data, size_t len ) {
	struct fc_login_frame *plogi = data;
	struct fc_peer *peer;
	int rc;

	/* Sanity checks */
	if ( len < sizeof ( *plogi ) ) {
		DBGC ( els, FCELS_FMT " received underlength frame:\n",
		       FCELS_ARGS ( els ) );
		DBGC_HDA ( els, 0, data, len );
		rc = -EINVAL;
		goto err_sanity;
	}
	if ( ! fc_link_ok ( &els->port->link ) ) {
		DBGC ( els, FCELS_FMT " received while port link is down\n",
		       FCELS_ARGS ( els ) );
		rc = -EINVAL;
		goto err_sanity;
	}

	/* Extract parameters */
	DBGC ( els, FCELS_FMT " has node %s\n", FCELS_ARGS ( els ),
	       fc_ntoa ( &plogi->node_wwn ) );
	DBGC ( els, FCELS_FMT " has port %s as %s\n",
	       FCELS_ARGS ( els ), fc_ntoa ( &plogi->port_wwn ),
	       fc_id_ntoa ( &els->peer_port_id ) );

	/* Get peer */
	peer = fc_peer_get_wwn ( &plogi->port_wwn );
	if ( ! peer ) {
		DBGC ( els, FCELS_FMT " could not create peer\n",
		       FCELS_ARGS ( els ) );
		rc = -ENOMEM;
		goto err_peer_get_wwn;
	}

	/* Record login */
	if ( ( rc = fc_peer_login ( peer, els->port,
				    &els->peer_port_id ) ) != 0 ) {
		DBGC ( els, FCELS_FMT " could not log in peer: %s\n",
		       FCELS_ARGS ( els ), strerror ( rc ) );
		goto err_login;
	}

	/* Transmit response, if applicable */
	if ( ! fc_els_is_request ( els ) ) {
		if ( ( rc = fc_els_plogi_tx ( els ) ) != 0 )
			goto err_plogi_tx;
	}

	/* Drop temporary reference to peer */
	fc_peer_put ( peer );

	return 0;

 err_plogi_tx:
 err_login:
	fc_peer_put ( peer );
 err_peer_get_wwn:
 err_sanity:
	return rc;
}

/**
 * Detect PLOGI
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_plogi_detect ( struct fc_els *els __unused, const void *data,
				 size_t len __unused ) {
	const struct fc_login_frame *plogi = data;

	/* Check for PLOGI */
	if ( plogi->command != FC_ELS_PLOGI )
		return -EINVAL;

	return 0;
}

/** PLOGI ELS handler */
struct fc_els_handler fc_els_plogi_handler __fc_els_handler = {
	.name		= "PLOGI",
	.tx		= fc_els_plogi_tx,
	.rx		= fc_els_plogi_rx,
	.detect		= fc_els_plogi_detect,
};

/**
 * Create PLOGI request
 *
 * @v parent		Parent interface
 * @v port		Fibre Channel port
 * @v peer_port_id	Peer port ID
 * @ret rc		Return status code
 */
int fc_els_plogi ( struct interface *parent, struct fc_port *port,
		   struct fc_port_id *peer_port_id ) {

	return fc_els_request ( parent, port, peer_port_id,
				&fc_els_plogi_handler );
}

/******************************************************************************
 *
 * LOGO
 *
 ******************************************************************************
 */

/**
 * Transmit LOGO request
 *
 * @v els		Fibre Channel ELS transaction
 * @ret rc		Return status code
 */
static int fc_els_logo_tx ( struct fc_els *els ) {
	struct fc_logout_request_frame logo;

	/* Construct LOGO */
	memset ( &logo, 0, sizeof ( logo ) );
	logo.command = FC_ELS_LOGO;
	memcpy ( &logo.port_id, &els->port->port_id, sizeof ( logo.port_id ) );
	memcpy ( &logo.port_wwn, &els->port->port_wwn,
		 sizeof ( logo.port_wwn ) );

	/* Transmit LOGO */
	return fc_els_tx ( els, &logo, sizeof ( logo ) );
}

/**
 * Transmit LOGO response
 *
 * @v els		Fibre Channel ELS transaction
 * @ret rc		Return status code
 */
static int fc_els_logo_tx_response ( struct fc_els *els ) {
	struct fc_logout_response_frame logo;

	/* Construct LOGO */
	memset ( &logo, 0, sizeof ( logo ) );
	logo.command = FC_ELS_LS_ACC;

	/* Transmit LOGO */
	return fc_els_tx ( els, &logo, sizeof ( logo ) );
}

/**
 * Log out individual peer or whole port as applicable
 *
 * @v els		Fibre Channel ELS transaction
 * @v port_id		Peer port ID
 */
static void fc_els_logo_logout ( struct fc_els *els,
				 struct fc_port_id *peer_port_id ) {
	struct fc_peer *peer;

	if ( ( memcmp ( peer_port_id, &fc_f_port_id,
			sizeof ( *peer_port_id ) ) == 0 ) ||
	     ( memcmp ( peer_port_id, &els->port->port_id,
			sizeof ( *peer_port_id ) ) == 0 ) ) {
		fc_port_logout ( els->port, 0 );
	} else {
		peer = fc_peer_get_port_id ( els->port, peer_port_id );
		if ( peer ) {
			fc_peer_logout ( peer, 0 );
			fc_peer_put ( peer );
		}
	}
}

/**
 * Receive LOGO request
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_logo_rx_request ( struct fc_els *els, void *data,
				    size_t len ) {
	struct fc_logout_request_frame *logo = data;
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *logo ) ) {
		DBGC ( els, FCELS_FMT " received underlength frame:\n",
		       FCELS_ARGS ( els ) );
		DBGC_HDA ( els, 0, data, len );
		return -EINVAL;
	}

	DBGC ( els, FCELS_FMT " has port %s as %s\n", FCELS_ARGS ( els ),
	       fc_ntoa ( &logo->port_wwn ), fc_id_ntoa ( &logo->port_id ) );

	/* Log out individual peer or whole port as applicable */
	fc_els_logo_logout ( els, &logo->port_id );

	/* Transmit repsonse */
	if ( ( rc = fc_els_logo_tx_response ( els ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Receive LOGO response
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_logo_rx_response ( struct fc_els *els, void *data __unused,
				     size_t len __unused ) {

	/* Log out individual peer or whole port as applicable */
	fc_els_logo_logout ( els, &els->peer_port_id );

	return 0;
}

/**
 * Receive LOGO
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_logo_rx ( struct fc_els *els, void *data, size_t len ) {

	if ( fc_els_is_request ( els ) ) {
		return fc_els_logo_rx_response ( els, data, len );
	} else {
		return fc_els_logo_rx_request ( els, data, len );
	}
}

/**
 * Detect LOGO
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_logo_detect ( struct fc_els *els __unused, const void *data,
				size_t len __unused ) {
	const struct fc_logout_request_frame *logo = data;

	/* Check for LOGO */
	if ( logo->command != FC_ELS_LOGO )
		return -EINVAL;

	return 0;
}

/** LOGO ELS handler */
struct fc_els_handler fc_els_logo_handler __fc_els_handler = {
	.name		= "LOGO",
	.tx		= fc_els_logo_tx,
	.rx		= fc_els_logo_rx,
	.detect		= fc_els_logo_detect,
};

/**
 * Create LOGO request
 *
 * @v parent		Parent interface
 * @v port		Fibre Channel port
 * @v peer_port_id	Peer port ID
 * @ret rc		Return status code
 */
int fc_els_logo ( struct interface *parent, struct fc_port *port,
		  struct fc_port_id *peer_port_id ) {

	return fc_els_request ( parent, port, peer_port_id,
				&fc_els_logo_handler );
}

/******************************************************************************
 *
 * PRLI
 *
 ******************************************************************************
 */

/**
 * Find PRLI descriptor
 *
 * @v type		Upper-layer protocol type
 * @ret descriptor	PRLI descriptor, or NULL
 */
static struct fc_els_prli_descriptor *
fc_els_prli_descriptor ( unsigned int type ) {
	struct fc_els_prli_descriptor *descriptor;

	for_each_table_entry ( descriptor, FC_ELS_PRLI_DESCRIPTORS ) {
		if ( descriptor->type == type )
			return descriptor;
	}
	return NULL;
}

/**
 * Transmit PRLI
 *
 * @v els		Fibre Channel ELS transaction
 * @v descriptor	ELS PRLI descriptor
 * @v param		Service parameters
 * @ret rc		Return status code
 */
int fc_els_prli_tx ( struct fc_els *els,
		     struct fc_els_prli_descriptor *descriptor, void *param ) {
	struct {
		struct fc_prli_frame frame;
		uint8_t param[descriptor->param_len];
	} __attribute__ (( packed )) prli;
	struct fc_ulp *ulp;
	int rc;

	/* Get ULP */
	ulp = fc_ulp_get_port_id_type ( els->port, &els->peer_port_id,
					descriptor->type );
	if ( ! ulp ) {
		rc = -ENOMEM;
		goto err_get_port_id_type;
	}

	/* Build frame for transmission */
	memset ( &prli, 0, sizeof ( prli ) );
	prli.frame.command = fc_els_tx_command ( els, FC_ELS_PRLI );
	prli.frame.page_len =
		( sizeof ( prli.frame.page ) + sizeof ( prli.param ) );
	prli.frame.len = htons ( sizeof ( prli ) );
	prli.frame.page.type = descriptor->type;
	if ( fc_els_is_request ( els ) ) {
		prli.frame.page.flags |= htons ( FC_PRLI_ESTABLISH );
	} else if ( fc_link_ok ( &ulp->link ) ) {
		prli.frame.page.flags |= htons ( FC_PRLI_ESTABLISH |
						    FC_PRLI_RESPONSE_SUCCESS );
	}
	memcpy ( &prli.param, param, sizeof ( prli.param ) );

	/* Transmit frame */
	if ( ( rc = fc_els_tx ( els, &prli, sizeof ( prli ) ) ) != 0 )
		goto err_tx;

	/* Drop temporary reference to ULP */
	fc_ulp_put ( ulp );

	return 0;

 err_tx:
	fc_ulp_put ( ulp );
 err_get_port_id_type:
	return rc;
}

/**
 * Receive PRLI
 *
 * @v els		Fibre Channel ELS transaction
 * @v descriptor	ELS PRLI descriptor
 * @v frame		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
int fc_els_prli_rx ( struct fc_els *els,
		     struct fc_els_prli_descriptor *descriptor,
		     void *data, size_t len ) {
	struct {
		struct fc_prli_frame frame;
		uint8_t param[descriptor->param_len];
	} __attribute__ (( packed )) *prli = data;
	struct fc_ulp *ulp;
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *prli ) ) {
		DBGC ( els, FCELS_FMT " received underlength frame:\n",
		       FCELS_ARGS ( els ) );
		DBGC_HDA ( els, 0, data, len );
		rc = -EINVAL;
		goto err_sanity;
	}

	DBGC ( els, FCELS_FMT " has parameters:\n", FCELS_ARGS ( els ) );
	DBGC_HDA ( els, 0, prli->param, sizeof ( prli->param ) );

	/* Get ULP */
	ulp = fc_ulp_get_port_id_type ( els->port, &els->peer_port_id,
					descriptor->type );
	if ( ! ulp ) {
		rc = -ENOMEM;
		goto err_get_port_id_type;
	}

	/* Sanity check */
	if ( ! fc_link_ok ( &ulp->peer->link ) ) {
		DBGC ( els, FCELS_FMT " received while peer link is down\n",
		       FCELS_ARGS ( els ) );
		rc = -EINVAL;
		goto err_link;
	}

	/* Log in ULP, if applicable */
	if ( prli->frame.page.flags & htons ( FC_PRLI_ESTABLISH ) ) {
		if ( ( rc = fc_ulp_login ( ulp, prli->param,
					   sizeof ( prli->param ),
					   fc_els_is_request ( els ) ) ) != 0 ){
			DBGC ( els, FCELS_FMT " could not log in ULP: %s\n",
			       FCELS_ARGS ( els ), strerror ( rc ) );
			goto err_login;
		}
	} else {
		if ( fc_els_is_request ( els ) ) {
			fc_ulp_logout ( ulp, -EACCES );
		} else {
			/* This is just an information-gathering PRLI; do not
			 * log in or out
			 */
		}
	}

	/* Transmit response, if applicable */
	if ( ! fc_els_is_request ( els ) ) {
		if ( ( rc = els->handler->tx ( els ) ) != 0 )
			goto err_tx;
	}

	/* Drop temporary reference to ULP */
	fc_ulp_put ( ulp );

	return 0;

 err_tx:
 err_login:
 err_link:
	fc_ulp_put ( ulp );
 err_get_port_id_type:
 err_sanity:
	return rc;
}

/**
 * Detect PRLI
 *
 * @v els		Fibre Channel ELS transaction
 * @v descriptor	ELS PRLI descriptor
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
int fc_els_prli_detect ( struct fc_els *els __unused,
			 struct fc_els_prli_descriptor *descriptor,
			 const void *data, size_t len ) {
	const struct {
		struct fc_prli_frame frame;
		uint8_t param[descriptor->param_len];
	} __attribute__ (( packed )) *prli = data;

	/* Check for PRLI */
	if ( prli->frame.command != FC_ELS_PRLI )
		return -EINVAL;

	/* Check for sufficient length to contain service parameter page */
	if ( len < sizeof ( *prli ) )
		return -EINVAL;

	/* Check for upper-layer protocol type */
	if ( prli->frame.page.type != descriptor->type )
		return -EINVAL;

	return 0;
}

/**
 * Create PRLI request
 *
 * @v parent		Parent interface
 * @v port		Fibre Channel port
 * @v peer_port_id	Peer port ID
 * @v type		Upper-layer protocol type
 * @ret rc		Return status code
 */
int fc_els_prli ( struct interface *parent, struct fc_port *port,
		  struct fc_port_id *peer_port_id, unsigned int type ) {
	struct fc_els_prli_descriptor *descriptor;

	/* Find a PRLI descriptor */
	descriptor = fc_els_prli_descriptor ( type );
	if ( ! descriptor )
		return -ENOTSUP;

	return fc_els_request ( parent, port, peer_port_id,
				descriptor->handler );
}

/******************************************************************************
 *
 * RTV
 *
 ******************************************************************************
 */

/**
 * Transmit RTV response
 *
 * @v els		Fibre Channel ELS transaction
 * @ret rc		Return status code
 */
static int fc_els_rtv_tx_response ( struct fc_els *els ) {
	struct fc_rtv_response_frame rtv;

	/* Construct RTV */
	memset ( &rtv, 0, sizeof ( rtv ) );
	rtv.command = FC_ELS_LS_ACC;
	rtv.e_d_tov = htonl ( FC_LOGIN_DEFAULT_E_D_TOV );

	/* Transmit RTV */
	return fc_els_tx ( els, &rtv, sizeof ( rtv ) );
}

/**
 * Receive RTV
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_rtv_rx ( struct fc_els *els, void *data __unused,
			   size_t len __unused ) {
	int rc;

	DBGC ( els, FCELS_FMT "\n", FCELS_ARGS ( els ) );

	/* Transmit response */
	if ( ! fc_els_is_request ( els ) ) {
		if ( ( rc = fc_els_rtv_tx_response ( els ) ) != 0 )
			return rc;
	}

	return 0;
}

/**
 * Detect RTV
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_rtv_detect ( struct fc_els *els __unused, const void *data,
			       size_t len __unused ) {
	const struct fc_rtv_request_frame *rtv = data;

	/* Check for RTV */
	if ( rtv->command != FC_ELS_RTV )
		return -EINVAL;

	return 0;
}

/** RTV ELS handler */
struct fc_els_handler fc_els_rtv_handler __fc_els_handler = {
	.name		= "RTV",
	.tx		= fc_els_unknown_tx,
	.rx		= fc_els_rtv_rx,
	.detect		= fc_els_rtv_detect,
};

/******************************************************************************
 *
 * ECHO
 *
 ******************************************************************************
 */

/** ECHO request data */
struct fc_echo_request_frame {
	/** ECHO frame header */
	struct fc_echo_frame_header echo;
	/** Magic marker */
	uint32_t magic;
} __attribute__ (( packed ));

/** ECHO magic marker */
#define FC_ECHO_MAGIC 0x69505845

/**
 * Transmit ECHO
 *
 * @v els		Fibre Channel ELS transaction
 * @ret rc		Return status code
 */
static int fc_els_echo_tx ( struct fc_els *els ) {
	struct fc_echo_request_frame echo;

	/* Construct ECHO */
	memset ( &echo, 0, sizeof ( echo ) );
	echo.echo.command = FC_ELS_ECHO;
	echo.magic = htonl ( FC_ECHO_MAGIC );

	/* Transmit ECHO */
	return fc_els_tx ( els, &echo, sizeof ( echo ) );
}

/**
 * Receive ECHO request
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_echo_rx_request ( struct fc_els *els, void *data,
				    size_t len ) {
	struct {
		struct fc_echo_frame_header echo;
		char payload[ len - sizeof ( struct fc_echo_frame_header ) ];
	} *echo = data;
	int rc;

	DBGC ( els, FCELS_FMT "\n", FCELS_ARGS ( els ) );

	/* Transmit response */
	echo->echo.command = FC_ELS_LS_ACC;
	if ( ( rc = fc_els_tx ( els, echo, sizeof ( *echo ) ) ) != 0 )
		return rc;

	/* Nothing to do */
	return 0;
}

/**
 * Receive ECHO response
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_echo_rx_response ( struct fc_els *els, void *data,
				     size_t len ) {
	struct fc_echo_request_frame *echo = data;

	DBGC ( els, FCELS_FMT "\n", FCELS_ARGS ( els ) );

	/* Check response is correct */
	if ( ( len != sizeof ( *echo ) ) ||
	     ( echo->magic != htonl ( FC_ECHO_MAGIC ) ) ) {
		DBGC ( els, FCELS_FMT " received bad echo response\n",
		       FCELS_ARGS ( els ) );
		DBGC_HDA ( els, 0, data, len );
		return -EIO;
	}

	return 0;
}

/**
 * Receive ECHO
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_echo_rx ( struct fc_els *els, void *data, size_t len ) {

	if ( fc_els_is_request ( els ) ) {
		return fc_els_echo_rx_response ( els, data, len );
	} else {
		return fc_els_echo_rx_request ( els, data, len );
	}
}

/**
 * Detect ECHO
 *
 * @v els		Fibre Channel ELS transaction
 * @v data		ELS frame
 * @v len		Length of ELS frame
 * @ret rc		Return status code
 */
static int fc_els_echo_detect ( struct fc_els *els __unused, const void *data,
				size_t len __unused ) {
	const struct fc_echo_frame_header *echo = data;

	/* Check for ECHO */
	if ( echo->command != FC_ELS_ECHO )
		return -EINVAL;

	return 0;
}

/** ECHO ELS handler */
struct fc_els_handler fc_els_echo_handler __fc_els_handler = {
	.name		= "ECHO",
	.tx		= fc_els_echo_tx,
	.rx		= fc_els_echo_rx,
	.detect		= fc_els_echo_detect,
};
