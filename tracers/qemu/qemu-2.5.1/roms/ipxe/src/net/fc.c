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
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/refcnt.h>
#include <ipxe/list.h>
#include <ipxe/tables.h>
#include <ipxe/timer.h>
#include <ipxe/retry.h>
#include <ipxe/interface.h>
#include <ipxe/xfer.h>
#include <ipxe/iobuf.h>
#include <ipxe/fc.h>
#include <ipxe/fcels.h>
#include <ipxe/fcns.h>

/** @file
 *
 * Fibre Channel
 *
 */

/** List of Fibre Channel ports */
LIST_HEAD ( fc_ports );

/** List of Fibre Channel peers */
LIST_HEAD ( fc_peers );

/******************************************************************************
 *
 * Well-known addresses
 *
 ******************************************************************************
 */

/** Unassigned port ID */
struct fc_port_id fc_empty_port_id = { .bytes = { 0x00, 0x00, 0x00 } };

/** F_Port contoller port ID */
struct fc_port_id fc_f_port_id = { .bytes = { 0xff, 0xff, 0xfe } };

/** Generic services port ID */
struct fc_port_id fc_gs_port_id = { .bytes = { 0xff, 0xff, 0xfc } };

/** Point-to-point low port ID */
struct fc_port_id fc_ptp_low_port_id = { .bytes = { 0x01, 0x01, 0x01 } };

/** Point-to-point high port ID */
struct fc_port_id fc_ptp_high_port_id = { .bytes = { 0x01, 0x01, 0x02 } };

/******************************************************************************
 *
 * Utility functions
 *
 ******************************************************************************
 */

/**
 * Format Fibre Channel port ID
 *
 * @v id		Fibre Channel port ID
 * @ret id_text		Port ID text
 */
const char * fc_id_ntoa ( const struct fc_port_id *id ) {
	static char id_text[ FC_PORT_ID_STRLEN + 1 /* NUL */ ];

	snprintf ( id_text, sizeof ( id_text ), "%02x.%02x.%02x",
		   id->bytes[0], id->bytes[1], id->bytes[2] );
	return id_text;
}

/**
 * Parse Fibre Channel port ID
 *
 * @v id_text		Port ID text
 * @ret id		Fibre Channel port ID
 * @ret rc		Return status code
 */
int fc_id_aton ( const char *id_text, struct fc_port_id *id ) {
	char *ptr = ( ( char * ) id_text );
	unsigned int i = 0;

	while ( 1 ) {
		id->bytes[i++] = strtoul ( ptr, &ptr, 16 );
		if ( i == sizeof ( id->bytes ) )
			return ( ( *ptr == '\0' ) ? 0 : -EINVAL );
		if ( *ptr != '.' )
			return -EINVAL;
		ptr++;
	}
}

/**
 * Format Fibre Channel WWN
 *
 * @v wwn		Fibre Channel WWN
 * @ret wwn_text	WWN text
 */
const char * fc_ntoa ( const struct fc_name *wwn ) {
	static char wwn_text[ FC_NAME_STRLEN + 1 /* NUL */ ];

	snprintf ( wwn_text, sizeof ( wwn_text ),
		   "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		   wwn->bytes[0], wwn->bytes[1], wwn->bytes[2], wwn->bytes[3],
		   wwn->bytes[4], wwn->bytes[5], wwn->bytes[6], wwn->bytes[7] );
	return wwn_text;
}

/**
 * Parse Fibre Channel WWN
 *
 * @v wwn_text		WWN text
 * @ret wwn		Fibre Channel WWN
 * @ret rc		Return status code
 */
int fc_aton ( const char *wwn_text, struct fc_name *wwn ) {
	char *ptr = ( ( char * ) wwn_text );
	unsigned int i = 0;

	while ( 1 ) {
		wwn->bytes[i++] = strtoul ( ptr, &ptr, 16 );
		if ( i == sizeof ( wwn->bytes ) )
			return ( ( *ptr == '\0' ) ? 0 : -EINVAL );
		if ( *ptr != ':' )
			return -EINVAL;
		ptr++;
	}
}

/**
 * Fill Fibre Channel socket address
 *
 * @v sa_fc		Fibre Channel socket address to fill in
 * @v id		Fibre Channel port ID
 * @ret sa		Socket address
 */
struct sockaddr * fc_fill_sockaddr ( struct sockaddr_fc *sa_fc,
				     struct fc_port_id *id ) {
	union {
		struct sockaddr sa;
		struct sockaddr_fc fc;
	} *u = container_of ( sa_fc, typeof ( *u ), fc );

	memset ( sa_fc, 0, sizeof ( *sa_fc ) );
	sa_fc->sfc_family = AF_FC;
	memcpy ( &sa_fc->sfc_port_id, id, sizeof ( sa_fc->sfc_port_id ) );
	return &u->sa;
}

/******************************************************************************
 *
 * Fibre Channel link state
 *
 ******************************************************************************
 */

/** Default link status code */
#define EUNKNOWN_LINK_STATUS __einfo_error ( EINFO_EUNKNOWN_LINK_STATUS )
#define EINFO_EUNKNOWN_LINK_STATUS \
	__einfo_uniqify ( EINFO_EINPROGRESS, 0x01, "Unknown" )

/**
 * Mark Fibre Channel link as up
 *
 * @v link		Fibre Channel link state monitor
 */
static void fc_link_up ( struct fc_link_state *link ) {

	/* Stop retry timer */
	stop_timer ( &link->timer );

	/* Record link state */
	link->rc = 0;
}

/**
 * Mark Fibre Channel link as down
 *
 * @v link		Fibre Channel link state monitor
 * @v rc		Link state
 */
static void fc_link_err ( struct fc_link_state *link, int rc ) {

	/* Record link state */
	if ( rc == 0 )
		rc = -EUNKNOWN_LINK_STATUS;
	link->rc = rc;

	/* Schedule another link examination */
	start_timer_fixed ( &link->timer, FC_LINK_RETRY_DELAY );
}

/**
 * Examine Fibre Channel link state
 *
 * @v link		Fibre Channel link state monitor
 */
static void fc_link_examine ( struct fc_link_state *link ) {

	link->examine ( link );
}

/**
 * Handle Fibre Channel link retry timer expiry
 */
static void fc_link_expired ( struct retry_timer *timer, int over __unused ) {
	struct fc_link_state *link =
		container_of ( timer, struct fc_link_state, timer );

	/* Schedule another link examination */
	start_timer_fixed ( &link->timer, FC_LINK_RETRY_DELAY );

	/* Examine link */
	fc_link_examine ( link );
}

/**
 * Initialise Fibre Channel link state monitor
 *
 * @v link		Fibre Channel link state monitor
 * @v examine		Examine link state method
 * @v refcnt		Reference counter
 */
static void fc_link_init ( struct fc_link_state *link,
			   void ( * examine ) ( struct fc_link_state *link ),
			   struct refcnt *refcnt ) {

	link->rc = -EUNKNOWN_LINK_STATUS;
	timer_init ( &link->timer, fc_link_expired, refcnt );
	link->examine = examine;
}

/**
 * Start monitoring Fibre Channel link state
 *
 * @v link		Fibre Channel link state monitor
 */
static void fc_link_start ( struct fc_link_state *link ) {
	start_timer_nodelay ( &link->timer );
}

/**
 * Stop monitoring Fibre Channel link state
 *
 * @v link		Fibre Channel link state monitor
 */
static void fc_link_stop ( struct fc_link_state *link ) {
	stop_timer ( &link->timer );
}

/******************************************************************************
 *
 * Fibre Channel exchanges
 *
 ******************************************************************************
 */

/** A Fibre Channel exchange */
struct fc_exchange {
	/** Reference count */
	struct refcnt refcnt;
	/** Fibre Channel port */
	struct fc_port *port;
	/** List of active exchanges within this port */
	struct list_head list;

	/** Peer port ID */
	struct fc_port_id peer_port_id;
	/** Data structure type */
	unsigned int type;
	/** Flags */
	unsigned int flags;
	/** Local exchange ID */
	uint16_t xchg_id;
	/** Peer exchange ID */
	uint16_t peer_xchg_id;
	/** Active sequence ID */
	uint8_t seq_id;
	/** Active sequence count */
	uint16_t seq_cnt;

	/** Timeout timer */
	struct retry_timer timer;

	/** Upper-layer protocol interface */
	struct interface ulp;
};

/** Fibre Channel exchange flags */
enum fc_exchange_flags {
	/** We are the exchange originator */
	FC_XCHG_ORIGINATOR = 0x0001,
	/** We have the sequence initiative */
	FC_XCHG_SEQ_INITIATIVE = 0x0002,
	/** This is the first sequence of the exchange */
	FC_XCHG_SEQ_FIRST = 0x0004,
};

/** Fibre Channel timeout */
#define FC_TIMEOUT ( 1 * TICKS_PER_SEC )

/**
 * Create local Fibre Channel exchange identifier
 *
 * @ret xchg_id		Local exchange ID
 */
static unsigned int fc_new_xchg_id ( void ) {
	static uint16_t next_id = 0x0000;

	/* We must avoid using FC_RX_ID_UNKNOWN (0xffff) */
	next_id += 2;
	return next_id;
}

/**
 * Create local Fibre Channel sequence identifier
 *
 * @ret seq_id		Local sequence identifier
 */
static unsigned int fc_new_seq_id ( void ) {
	static uint8_t seq_id = 0x00;

	return (++seq_id);
}

/**
 * Free Fibre Channel exchange
 *
 * @v refcnt		Reference count
 */
static void fc_xchg_free ( struct refcnt *refcnt ) {
	struct fc_exchange *xchg =
		container_of ( refcnt, struct fc_exchange, refcnt );

	assert ( ! timer_running ( &xchg->timer ) );
	assert ( list_empty ( &xchg->list ) );

	fc_port_put ( xchg->port );
	free ( xchg );
}

/**
 * Close Fibre Channel exchange
 *
 * @v xchg		Fibre Channel exchange
 * @v rc		Reason for close
 */
static void fc_xchg_close ( struct fc_exchange *xchg, int rc ) {
	struct fc_port *port = xchg->port;

	if ( rc != 0 ) {
		DBGC2 ( port, "FCXCHG %s/%04x closed: %s\n",
			port->name, xchg->xchg_id, strerror ( rc ) );
	}

	/* Stop timer */
	stop_timer ( &xchg->timer );

	/* If list still holds a reference, remove from list of open
	 * exchanges and drop list's reference.
	 */
	if ( ! list_empty ( &xchg->list ) ) {
		list_del ( &xchg->list );
		INIT_LIST_HEAD ( &xchg->list );
		ref_put ( &xchg->refcnt );
	}

	/* Shutdown interfaces */
	intf_shutdown ( &xchg->ulp, rc );
}

/**
 * Handle exchange timeout
 *
 * @v timer		Timeout timer
 * @v over		Failure indicator
 */
static void fc_xchg_expired ( struct retry_timer *timer, int over __unused ) {
	struct fc_exchange *xchg =
		container_of ( timer, struct fc_exchange, timer );
	struct fc_port *port = xchg->port;

	DBGC ( port, "FCXCHG %s/%04x timed out\n", port->name, xchg->xchg_id );

	/* Terminate the exchange */
	fc_xchg_close ( xchg, -ETIMEDOUT );
}

/**
 * Check Fibre Channel exchange window
 *
 * @v xchg		Fibre Channel exchange
 * @ret len		Length opf window
 */
static size_t fc_xchg_window ( struct fc_exchange *xchg __unused ) {

	/* We don't currently store the path MTU */
	return FC_LOGIN_DEFAULT_MTU;
}

/**
 * Allocate Fibre Channel I/O buffer
 *
 * @v xchg		Fibre Channel exchange
 * @v len		Payload length
 * @ret iobuf		I/O buffer, or NULL
 */
static struct io_buffer * fc_xchg_alloc_iob ( struct fc_exchange *xchg,
					      size_t len ) {
	struct fc_port *port = xchg->port;
	struct io_buffer *iobuf;

	iobuf = xfer_alloc_iob ( &port->transport,
				 ( sizeof ( struct fc_frame_header ) + len ) );
	if ( iobuf ) {
		iob_reserve ( iobuf, sizeof ( struct fc_frame_header ) );
	}
	return iobuf;
}

/**
 * Transmit data as part of a Fibre Channel exchange
 *
 * @v xchg		Fibre Channel exchange
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int fc_xchg_tx ( struct fc_exchange *xchg, struct io_buffer *iobuf,
			struct xfer_metadata *meta ) {
	struct fc_port *port = xchg->port;
	struct sockaddr_fc *dest = ( ( struct sockaddr_fc * ) meta->dest );
	struct fc_frame_header *fchdr;
	unsigned int r_ctl;
	unsigned int f_ctl_es;
	int rc;

	/* Sanity checks */
	if ( ! ( xchg->flags & FC_XCHG_SEQ_INITIATIVE ) ) {
		DBGC ( port, "FCXCHG %s/%04x cannot transmit while not "
		       "holding sequence initiative\n",
		       port->name, xchg->xchg_id );
		rc = -EBUSY;
		goto done;
	}

	/* Calculate routing control */
	switch ( xchg->type ) {
	case FC_TYPE_ELS:
		r_ctl = FC_R_CTL_ELS;
		if ( meta->flags & XFER_FL_RESPONSE ) {
			r_ctl |= FC_R_CTL_SOL_CTRL;
		} else {
			r_ctl |= FC_R_CTL_UNSOL_CTRL;
		}
		break;
	case FC_TYPE_CT:
		r_ctl = FC_R_CTL_DATA;
		if ( meta->flags & XFER_FL_RESPONSE ) {
			r_ctl |= FC_R_CTL_SOL_CTRL;
		} else {
			r_ctl |= FC_R_CTL_UNSOL_CTRL;
		}
		break;
	default:
		r_ctl = FC_R_CTL_DATA;
		switch ( meta->flags &
			 ( XFER_FL_CMD_STAT | XFER_FL_RESPONSE ) ) {
		case ( XFER_FL_CMD_STAT | XFER_FL_RESPONSE ):
			r_ctl |= FC_R_CTL_CMD_STAT;
			break;
		case ( XFER_FL_CMD_STAT ):
			r_ctl |= FC_R_CTL_UNSOL_CMD;
			break;
		case ( XFER_FL_RESPONSE ):
			r_ctl |= FC_R_CTL_SOL_DATA;
			break;
		default:
			r_ctl |= FC_R_CTL_UNSOL_DATA;
			break;
		}
		break;
	}

	/* Calculate exchange and sequence control */
	f_ctl_es = 0;
	if ( ! ( xchg->flags & FC_XCHG_ORIGINATOR ) )
		f_ctl_es |= FC_F_CTL_ES_RESPONDER;
	if ( xchg->flags & FC_XCHG_SEQ_FIRST )
		f_ctl_es |= FC_F_CTL_ES_FIRST;
	if ( meta->flags & XFER_FL_OUT )
		f_ctl_es |= ( FC_F_CTL_ES_END | FC_F_CTL_ES_LAST );
	if ( meta->flags & XFER_FL_OVER )
		f_ctl_es |= ( FC_F_CTL_ES_END | FC_F_CTL_ES_TRANSFER );

	/* Create frame header */
	fchdr = iob_push ( iobuf, sizeof ( *fchdr ) );
	memset ( fchdr, 0, sizeof ( *fchdr ) );
	fchdr->r_ctl = r_ctl;
	memcpy ( &fchdr->d_id,
		 ( dest ? &dest->sfc_port_id : &xchg->peer_port_id ),
		 sizeof ( fchdr->d_id ) );
	memcpy ( &fchdr->s_id, &port->port_id, sizeof ( fchdr->s_id ) );
	fchdr->type = xchg->type;
	fchdr->f_ctl_es = f_ctl_es;
	fchdr->seq_id = xchg->seq_id;
	fchdr->seq_cnt = htons ( xchg->seq_cnt++ );
	fchdr->ox_id = htons ( ( xchg->flags & FC_XCHG_ORIGINATOR ) ?
			       xchg->xchg_id : xchg->peer_xchg_id );
	fchdr->rx_id = htons ( ( xchg->flags & FC_XCHG_ORIGINATOR ) ?
			       xchg->peer_xchg_id : xchg->xchg_id );
	if ( meta->flags & XFER_FL_ABS_OFFSET ) {
		fchdr->f_ctl_misc |= FC_F_CTL_MISC_REL_OFF;
		fchdr->parameter = htonl ( meta->offset );
	}

	/* Relinquish sequence initiative if applicable */
	if ( meta->flags & XFER_FL_OVER ) {
		xchg->flags &= ~( FC_XCHG_SEQ_INITIATIVE | FC_XCHG_SEQ_FIRST );
		xchg->seq_cnt = 0;
	}

	/* Reset timeout */
	start_timer_fixed ( &xchg->timer, FC_TIMEOUT );

	/* Deliver frame */
	if ( ( rc = xfer_deliver_iob ( &port->transport,
				       iob_disown ( iobuf ) ) ) != 0 ) {
		DBGC ( port, "FCXCHG %s/%04x cannot transmit: %s\n",
		       port->name, xchg->xchg_id, strerror ( rc ) );
		goto done;
	}

 done:
	free_iob ( iobuf );
	return rc;
}

/** Mapping from Fibre Channel routing control information to xfer metadata */
static const uint8_t fc_r_ctl_info_meta_flags[ FC_R_CTL_INFO_MASK + 1 ] = {
	[FC_R_CTL_UNCAT]	= ( 0 ),
	[FC_R_CTL_SOL_DATA]	= ( XFER_FL_RESPONSE ),
	[FC_R_CTL_UNSOL_CTRL]	= ( XFER_FL_CMD_STAT ),
	[FC_R_CTL_SOL_CTRL]	= ( XFER_FL_CMD_STAT ),
	[FC_R_CTL_UNSOL_DATA]	= ( 0 ),
	[FC_R_CTL_DATA_DESC]	= ( XFER_FL_CMD_STAT ),
	[FC_R_CTL_UNSOL_CMD]	= ( XFER_FL_CMD_STAT ),
	[FC_R_CTL_CMD_STAT]	= ( XFER_FL_CMD_STAT | XFER_FL_RESPONSE ),
};

/**
 * Receive data as part of a Fibre Channel exchange
 *
 * @v xchg		Fibre Channel exchange
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int fc_xchg_rx ( struct fc_exchange *xchg, struct io_buffer *iobuf,
			struct xfer_metadata *meta __unused ) {
	struct fc_port *port = xchg->port;
	struct fc_frame_header *fchdr = iobuf->data;
	struct xfer_metadata fc_meta;
	struct sockaddr_fc src;
	struct sockaddr_fc dest;
	int rc;

	/* Record peer exchange ID */
	xchg->peer_xchg_id =
		ntohs ( ( fchdr->f_ctl_es & FC_F_CTL_ES_RESPONDER ) ?
			fchdr->rx_id : fchdr->ox_id );

	/* Sequence checks */
	if ( xchg->flags & FC_XCHG_SEQ_INITIATIVE ) {
		DBGC ( port, "FCXCHG %s/%04x received frame while holding "
		       "sequence initiative\n", port->name, xchg->xchg_id );
		rc = -EBUSY;
		goto done;
	}
	if ( ntohs ( fchdr->seq_cnt ) != xchg->seq_cnt ) {
		DBGC ( port, "FCXCHG %s/%04x received out-of-order frame %d "
		       "(expected %d)\n", port->name, xchg->xchg_id,
		       ntohs ( fchdr->seq_cnt ), xchg->seq_cnt );
		rc = -EPIPE;
		goto done;
	}
	if ( xchg->seq_cnt == 0 )
		xchg->seq_id = fchdr->seq_id;
	xchg->seq_cnt++;
	if ( fchdr->seq_id != xchg->seq_id ) {
		DBGC ( port, "FCXCHG %s/%04x received frame for incorrect "
		       "sequence %02x (expected %02x)\n", port->name,
		       xchg->xchg_id, fchdr->seq_id, xchg->seq_id );
		rc = -EPIPE;
		goto done;
	}

	/* Check for end of sequence and transfer of sequence initiative */
	if ( fchdr->f_ctl_es & FC_F_CTL_ES_END ) {
		xchg->seq_cnt = 0;
		if ( fchdr->f_ctl_es & FC_F_CTL_ES_TRANSFER ) {
			xchg->flags |= FC_XCHG_SEQ_INITIATIVE;
			xchg->seq_id = fc_new_seq_id();
		}
	}

	/* Construct metadata */
	memset ( &fc_meta, 0, sizeof ( fc_meta ) );
	fc_meta.flags =
		fc_r_ctl_info_meta_flags[ fchdr->r_ctl & FC_R_CTL_INFO_MASK ];
	if ( fchdr->f_ctl_es & FC_F_CTL_ES_TRANSFER ) {
		fc_meta.flags |= XFER_FL_OVER;
	}
	if ( ( fchdr->f_ctl_es & FC_F_CTL_ES_LAST ) &&
	     ( fchdr->f_ctl_es & FC_F_CTL_ES_END ) ) {
		fc_meta.flags |= XFER_FL_OUT;
	}
	if ( fchdr->f_ctl_misc & FC_F_CTL_MISC_REL_OFF ) {
		fc_meta.flags |= XFER_FL_ABS_OFFSET;
		fc_meta.offset = ntohl ( fchdr->parameter );
	}
	fc_meta.src = fc_fill_sockaddr ( &src, &fchdr->s_id );
	fc_meta.dest = fc_fill_sockaddr ( &dest, &fchdr->d_id );

	/* Reset timeout */
	start_timer_fixed ( &xchg->timer, FC_TIMEOUT );

	/* Deliver via exchange's ULP interface */
	iob_pull ( iobuf, sizeof ( *fchdr ) );
	if ( ( rc = xfer_deliver ( &xchg->ulp, iob_disown ( iobuf ),
				   &fc_meta ) ) != 0 ) {
		DBGC ( port, "FCXCHG %s/%04x cannot deliver frame: %s\n",
		       port->name, xchg->xchg_id, strerror ( rc ) );
		goto done;
	}

	/* Close exchange if applicable */
	if ( ( fchdr->f_ctl_es & FC_F_CTL_ES_LAST ) &&
	     ( fchdr->f_ctl_es & FC_F_CTL_ES_END ) ) {
		fc_xchg_close ( xchg, 0 );
	}

 done:
	free_iob ( iobuf );
	return rc;
}

/** Fibre Channel exchange ULP interface operations */
static struct interface_operation fc_xchg_ulp_op[] = {
	INTF_OP ( xfer_deliver, struct fc_exchange *, fc_xchg_tx ),
	INTF_OP ( xfer_alloc_iob, struct fc_exchange *, fc_xchg_alloc_iob ),
	INTF_OP ( xfer_window, struct fc_exchange *, fc_xchg_window ),
	INTF_OP ( intf_close, struct fc_exchange *, fc_xchg_close ),
};

/** Fibre Channel exchange ULP interface descriptor */
static struct interface_descriptor fc_xchg_ulp_desc =
	INTF_DESC ( struct fc_exchange, ulp, fc_xchg_ulp_op );

/**
 * Create new Fibre Channel exchange
 *
 * @v port		Fibre Channel port
 * @v peer_port_id	Peer port ID
 * @ret xchg		Exchange, or NULL
 */
static struct fc_exchange * fc_xchg_create ( struct fc_port *port,
					     struct fc_port_id *peer_port_id,
					     unsigned int type ) {
	struct fc_exchange *xchg;

	/* Allocate and initialise structure */
	xchg = zalloc ( sizeof ( *xchg ) );
	if ( ! xchg )
		return NULL;
	ref_init ( &xchg->refcnt, fc_xchg_free );
	intf_init ( &xchg->ulp, &fc_xchg_ulp_desc, &xchg->refcnt );
	timer_init ( &xchg->timer, fc_xchg_expired, &xchg->refcnt );
	xchg->port = fc_port_get ( port );
	memcpy ( &xchg->peer_port_id, peer_port_id,
		 sizeof ( xchg->peer_port_id ) );
	xchg->type = type;
	xchg->xchg_id = fc_new_xchg_id();
	xchg->peer_xchg_id = FC_RX_ID_UNKNOWN;
	xchg->seq_id = fc_new_seq_id();

	/* Transfer reference to list of exchanges and return */
	list_add ( &xchg->list, &port->xchgs );
	return xchg;
}

/**
 * Originate a new Fibre Channel exchange
 *
 * @v parent		Interface to which to attach
 * @v port		Fibre Channel port
 * @v peer_port_id	Peer port ID
 * @ret xchg_id		Exchange ID, or negative error
 */
int fc_xchg_originate ( struct interface *parent, struct fc_port *port,
			struct fc_port_id *peer_port_id, unsigned int type ) {
	struct fc_exchange *xchg;

	/* Allocate and initialise structure */
	xchg = fc_xchg_create ( port, peer_port_id, type );
	if ( ! xchg )
		return -ENOMEM;
	xchg->flags = ( FC_XCHG_ORIGINATOR | FC_XCHG_SEQ_INITIATIVE |
			FC_XCHG_SEQ_FIRST );

	DBGC2 ( port, "FCXCHG %s/%04x originating to %s (type %02x)\n",
		port->name, xchg->xchg_id, fc_id_ntoa ( &xchg->peer_port_id ),
		xchg->type );

	/* Attach to parent interface and return */
	intf_plug_plug ( &xchg->ulp, parent );
	return xchg->xchg_id;
}

/**
 * Open a new responder Fibre Channel exchange
 *
 * @v port		Fibre Channel port
 * @v fchdr		Fibre Channel frame header
 * @ret xchg		Fibre Channel exchange, or NULL
 */
static struct fc_exchange * fc_xchg_respond ( struct fc_port *port,
					      struct fc_frame_header *fchdr ) {
	struct fc_exchange *xchg;
	struct fc_responder *responder;
	unsigned int type = fchdr->type;
	int rc;

	/* Allocate and initialise structure */
	xchg = fc_xchg_create ( port, &fchdr->s_id, type );
	if ( ! xchg )
		return NULL;
	xchg->seq_id = fchdr->seq_id;

	DBGC2 ( port, "FCXCHG %s/%04x responding to %s xchg %04x (type "
		"%02x)\n", port->name, xchg->xchg_id,
		fc_id_ntoa ( &xchg->peer_port_id ),
		ntohs ( fchdr->ox_id ), xchg->type );

	/* Find a responder, if any */
	for_each_table_entry ( responder, FC_RESPONDERS ) {
		if ( responder->type == type ) {
			if ( ( rc = responder->respond ( &xchg->ulp, port,
							 &fchdr->d_id,
							 &fchdr->s_id ) ) !=0 ){
				DBGC ( port, "FCXCHG %s/%04x could not "
				       "respond: %s\n", port->name,
				       xchg->xchg_id, strerror ( rc ) );
			}
		}
		break;
	}

	/* We may or may not have a ULP attached at this point, but
	 * the exchange does exist.
	 */
	return xchg;
}

/******************************************************************************
 *
 * Fibre Channel ports
 *
 ******************************************************************************
 */

/**
 * Close Fibre Channel port
 *
 * @v port		Fibre Channel port
 * @v rc		Reason for close
 */
static void fc_port_close ( struct fc_port *port, int rc ) {
	struct fc_exchange *xchg;
	struct fc_exchange *tmp;

	DBGC ( port, "FCPORT %s closed\n", port->name );

	/* Log out port, if necessary */
	if ( fc_link_ok ( &port->link ) )
		fc_port_logout ( port, rc );

	/* Stop link monitor */
	fc_link_stop ( &port->link );

	/* Shut down interfaces */
	intf_shutdown ( &port->transport, rc );
	intf_shutdown ( &port->flogi, rc );
	intf_shutdown ( &port->ns_plogi, rc );

	/* Shut down any remaining exchanges */
	list_for_each_entry_safe ( xchg, tmp, &port->xchgs, list )
		fc_xchg_close ( xchg, rc );

	/* Remove from list of ports */
	list_del ( &port->list );
	INIT_LIST_HEAD ( &port->list );
}

/**
 * Identify Fibre Channel exchange by local exchange ID
 *
 * @v port		Fibre Channel port
 * @v xchg_id		Local exchange ID
 * @ret xchg		Fibre Channel exchange, or NULL
 */
static struct fc_exchange * fc_port_demux ( struct fc_port *port,
					    unsigned int xchg_id ) {
	struct fc_exchange *xchg;

	list_for_each_entry ( xchg, &port->xchgs, list ) {
		if ( xchg->xchg_id == xchg_id )
			return xchg;
	}
	return NULL;
}

/**
 * Handle received frame from Fibre Channel port
 *
 * @v port		Fibre Channel port
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int fc_port_deliver ( struct fc_port *port, struct io_buffer *iobuf,
			     struct xfer_metadata *meta ) {
	struct fc_frame_header *fchdr = iobuf->data;
	unsigned int xchg_id;
	struct fc_exchange *xchg;
	int rc;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *fchdr ) ) {
		DBGC ( port, "FCPORT %s received underlength frame (%zd "
		       "bytes)\n", port->name, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto err_sanity;
	}

	/* Verify local port ID */
	if ( ( memcmp ( &fchdr->d_id, &port->port_id,
			sizeof ( fchdr->d_id ) ) != 0 ) &&
	     ( memcmp ( &fchdr->d_id, &fc_f_port_id,
			sizeof ( fchdr->d_id ) ) != 0 ) &&
	     ( memcmp ( &port->port_id, &fc_empty_port_id,
			sizeof ( port->port_id ) ) != 0 ) ) {
		DBGC ( port, "FCPORT %s received frame for incorrect port ID "
		       "%s\n", port->name, fc_id_ntoa ( &fchdr->d_id ) );
		rc = -ENOTCONN;
		goto err_port_id;
	}

	/* Demultiplex amongst active exchanges */
	xchg_id = ntohs ( ( fchdr->f_ctl_es & FC_F_CTL_ES_RESPONDER ) ?
			  fchdr->ox_id : fchdr->rx_id );
	xchg = fc_port_demux ( port, xchg_id );

	/* If we have no active exchange and this frame starts a new
	 * exchange, try to create a new responder exchange
	 */
	if ( ( fchdr->f_ctl_es & FC_F_CTL_ES_FIRST ) &&
	     ( fchdr->seq_cnt == 0 ) ) {

		/* Create new exchange */
		xchg = fc_xchg_respond ( port, fchdr );
		if ( ! xchg ) {
			DBGC ( port, "FCPORT %s cannot create new exchange\n",
			       port->name );
			rc = -ENOMEM;
			goto err_respond;
		}
	}

	/* Fail if no exchange exists */
	if ( ! xchg ) {
		DBGC ( port, "FCPORT %s xchg %04x unknown\n",
		       port->name, xchg_id );
		rc = -ENOTCONN;
		goto err_no_xchg;
	}

	/* Pass received frame to exchange */
	ref_get ( &xchg->refcnt );
	if ( ( rc = fc_xchg_rx ( xchg, iob_disown ( iobuf ), meta ) ) != 0 )
		goto err_xchg_rx;

 err_xchg_rx:
	ref_put ( &xchg->refcnt );
 err_no_xchg:
 err_respond:
 err_port_id:
 err_sanity:
	free_iob ( iobuf );
	return rc;
}

/**
 * Log in Fibre Channel port
 *
 * @v port		Fibre Channel port
 * @v port_id		Local port ID
 * @v link_node_wwn	Link node name
 * @v link_port_wwn	Link port name
 * @v has_fabric	Link is to a fabric
 * @ret rc		Return status code
 */
int fc_port_login ( struct fc_port *port, struct fc_port_id *port_id,
		    const struct fc_name *link_node_wwn,
		    const struct fc_name *link_port_wwn, int has_fabric ) {
	struct fc_peer *peer;
	struct fc_peer *tmp;
	int rc;

	/* Perform implicit logout if logged in and details differ */
	if ( fc_link_ok ( &port->link ) &&
	     ( ( ( !! ( port->flags & FC_PORT_HAS_FABRIC ) ) !=
		 ( !! has_fabric ) ) ||
	       ( memcmp ( &port->link_node_wwn, link_node_wwn,
			  sizeof ( port->link_node_wwn ) ) != 0 ) ||
	       ( memcmp ( &port->link_port_wwn, link_port_wwn,
			  sizeof ( port->link_port_wwn ) ) != 0 ) ||
	       ( has_fabric &&
		 ( memcmp ( &port->port_id, port_id,
			    sizeof ( port->port_id ) ) != 0 ) ) ) ) {
		fc_port_logout ( port, 0 );
	}

	/* Log in, if applicable */
	if ( ! fc_link_ok ( &port->link ) ) {

		/* Record link port name */
		memcpy ( &port->link_node_wwn, link_node_wwn,
			 sizeof ( port->link_node_wwn ) );
		memcpy ( &port->link_port_wwn, link_port_wwn,
			 sizeof ( port->link_port_wwn ) );
		DBGC ( port, "FCPORT %s logged in to %s",
		       port->name, fc_ntoa ( &port->link_node_wwn ) );
		DBGC ( port, " port %s\n", fc_ntoa ( &port->link_port_wwn ) );

		/* Calculate local (and possibly remote) port IDs */
		if ( has_fabric ) {
			port->flags |= FC_PORT_HAS_FABRIC;
			memcpy ( &port->port_id, port_id,
				 sizeof ( port->port_id ) );
		} else {
			port->flags &= ~FC_PORT_HAS_FABRIC;
			if ( memcmp ( &port->port_wwn, link_port_wwn,
				      sizeof ( port->port_wwn ) ) > 0 ) {
				memcpy ( &port->port_id, &fc_ptp_high_port_id,
					 sizeof ( port->port_id ) );
				memcpy ( &port->ptp_link_port_id,
					 &fc_ptp_low_port_id,
					 sizeof ( port->ptp_link_port_id ) );
			} else {
				memcpy ( &port->port_id, &fc_ptp_low_port_id,
					 sizeof ( port->port_id ) );
				memcpy ( &port->ptp_link_port_id,
					 &fc_ptp_high_port_id,
					 sizeof ( port->ptp_link_port_id ) );
			}
		}
		DBGC ( port, "FCPORT %s logged in via a %s, with local ID "
		       "%s\n", port->name,
		       ( ( port->flags & FC_PORT_HAS_FABRIC ) ?
			 "fabric" : "point-to-point link" ),
		       fc_id_ntoa ( &port->port_id ) );
	}

	/* Log in to name server, if attached to a fabric */
	if ( has_fabric && ! ( port->flags & FC_PORT_HAS_NS ) ) {

		DBGC ( port, "FCPORT %s attempting login to name server\n",
		       port->name );

		intf_restart ( &port->ns_plogi, -ECANCELED );
		if ( ( rc = fc_els_plogi ( &port->ns_plogi, port,
					   &fc_gs_port_id ) ) != 0 ) {
			DBGC ( port, "FCPORT %s could not initiate name "
			       "server PLOGI: %s\n",
			       port->name, strerror ( rc ) );
			fc_port_logout ( port, rc );
			return rc;
		}
	}

	/* Record login */
	fc_link_up ( &port->link );

	/* Notify peers of link state change */
	list_for_each_entry_safe ( peer, tmp, &fc_peers, list ) {
		fc_peer_get ( peer );
		fc_link_examine ( &peer->link );
		fc_peer_put ( peer );
	}

	return 0;
}

/**
 * Log out Fibre Channel port
 *
 * @v port		Fibre Channel port
 * @v rc		Reason for logout
 */
void fc_port_logout ( struct fc_port *port, int rc ) {
	struct fc_peer *peer;
	struct fc_peer *tmp;

	DBGC ( port, "FCPORT %s logged out: %s\n",
	       port->name, strerror ( rc ) );

	/* Erase port details */
	memset ( &port->port_id, 0, sizeof ( port->port_id ) );
	port->flags = 0;

	/* Record logout */
	fc_link_err ( &port->link, rc );

	/* Notify peers of link state change */
	list_for_each_entry_safe ( peer, tmp, &fc_peers, list ) {
		fc_peer_get ( peer );
		fc_link_examine ( &peer->link );
		fc_peer_put ( peer );
	}
}

/**
 * Handle FLOGI completion
 *
 * @v port		Fibre Channel port
 * @v rc		Reason for completion
 */
static void fc_port_flogi_done ( struct fc_port *port, int rc ) {

	intf_restart ( &port->flogi, rc );

	if ( rc != 0 )
		fc_port_logout ( port, rc );
}

/**
 * Handle name server PLOGI completion
 *
 * @v port		Fibre Channel port
 * @v rc		Reason for completion
 */
static void fc_port_ns_plogi_done ( struct fc_port *port, int rc ) {

	intf_restart ( &port->ns_plogi, rc );

	if ( rc == 0 ) {
		port->flags |= FC_PORT_HAS_NS;
		DBGC ( port, "FCPORT %s logged in to name server\n",
		       port->name );
	} else {
		DBGC ( port, "FCPORT %s could not log in to name server: %s\n",
		       port->name, strerror ( rc ) );
		/* Absence of a name server is not a fatal error */
	}
}

/**
 * Examine Fibre Channel port link state
 *
 * @ link		Fibre Channel link state monitor
 */
static void fc_port_examine ( struct fc_link_state *link ) {
	struct fc_port *port = container_of ( link, struct fc_port, link );
	int rc;

	/* Do nothing if already logged in */
	if ( fc_link_ok ( &port->link ) )
		return;

	DBGC ( port, "FCPORT %s attempting login\n", port->name );

	/* Try to create FLOGI ELS */
	intf_restart ( &port->flogi, -ECANCELED );
	if ( ( rc = fc_els_flogi ( &port->flogi, port ) ) != 0 ) {
		DBGC ( port, "FCPORT %s could not initiate FLOGI: %s\n",
		       port->name, strerror ( rc ) );
		fc_port_logout ( port, rc );
		return;
	}
}

/**
 * Handle change of flow control window
 *
 * @v port		Fibre Channel port
 */
static void fc_port_window_changed ( struct fc_port *port ) {
	size_t window;

	/* Check if transport layer is ready */
	window = xfer_window ( &port->transport );
	if ( window > 0 ) {

		/* Transport layer is ready.  Start login if the link
		 * is not already up.
		 */
		if ( ! fc_link_ok ( &port->link ) )
			fc_link_start ( &port->link );

	} else {

		/* Transport layer is not ready.  Log out port and
		 * wait for transport layer before attempting log in
		 * again.
		 */
		fc_port_logout ( port, -ENOTCONN );
		fc_link_stop ( &port->link );
	}
}

/** Fibre Channel port transport interface operations */
static struct interface_operation fc_port_transport_op[] = {
	INTF_OP ( xfer_deliver, struct fc_port *, fc_port_deliver ),
	INTF_OP ( xfer_window_changed, struct fc_port *,
		  fc_port_window_changed ),
	INTF_OP ( intf_close, struct fc_port *, fc_port_close ),
};

/** Fibre Channel port transport interface descriptor */
static struct interface_descriptor fc_port_transport_desc =
	INTF_DESC ( struct fc_port, transport, fc_port_transport_op );

/** Fibre Channel port FLOGI interface operations */
static struct interface_operation fc_port_flogi_op[] = {
	INTF_OP ( intf_close, struct fc_port *, fc_port_flogi_done ),
};

/** Fibre Channel port FLOGI interface descriptor */
static struct interface_descriptor fc_port_flogi_desc =
	INTF_DESC ( struct fc_port, flogi, fc_port_flogi_op );

/** Fibre Channel port name server PLOGI interface operations */
static struct interface_operation fc_port_ns_plogi_op[] = {
	INTF_OP ( intf_close, struct fc_port *, fc_port_ns_plogi_done ),
};

/** Fibre Channel port name server PLOGI interface descriptor */
static struct interface_descriptor fc_port_ns_plogi_desc =
	INTF_DESC ( struct fc_port, ns_plogi, fc_port_ns_plogi_op );

/**
 * Create Fibre Channel port
 *
 * @v transport		Transport interface
 * @v node		Fibre Channel node name
 * @v port		Fibre Channel port name
 * @v name		Symbolic port name
 * @ret rc		Return status code
 */
int fc_port_open ( struct interface *transport, const struct fc_name *node_wwn,
		   const struct fc_name *port_wwn, const char *name ) {
	struct fc_port *port;

	/* Allocate and initialise structure */
	port = zalloc ( sizeof ( *port ) );
	if ( ! port )
		return -ENOMEM;
	ref_init ( &port->refcnt, NULL );
	intf_init ( &port->transport, &fc_port_transport_desc, &port->refcnt );
	fc_link_init ( &port->link, fc_port_examine, &port->refcnt );
	intf_init ( &port->flogi, &fc_port_flogi_desc, &port->refcnt );
	intf_init ( &port->ns_plogi, &fc_port_ns_plogi_desc, &port->refcnt );
	list_add_tail ( &port->list, &fc_ports );
	INIT_LIST_HEAD ( &port->xchgs );
	memcpy ( &port->node_wwn, node_wwn, sizeof ( port->node_wwn ) );
	memcpy ( &port->port_wwn, port_wwn, sizeof ( port->port_wwn ) );
	snprintf ( port->name, sizeof ( port->name ), "%s", name );

	DBGC ( port, "FCPORT %s opened as %s",
	       port->name, fc_ntoa ( &port->node_wwn ) );
	DBGC ( port, " port %s\n", fc_ntoa ( &port->port_wwn ) );

	/* Attach to transport layer, mortalise self, and return */
	intf_plug_plug ( &port->transport, transport );
	ref_put ( &port->refcnt );
	return 0;
}

/**
 * Find Fibre Channel port by name
 *
 * @v name		Fibre Channel port name
 * @ret port		Fibre Channel port, or NULL
 */
struct fc_port * fc_port_find ( const char *name ) {
	struct fc_port *port;

	list_for_each_entry ( port, &fc_ports, list ) {
		if ( strcmp ( name, port->name ) == 0 )
			return port;
	}
	return NULL;
}

/******************************************************************************
 *
 * Fibre Channel peers
 *
 ******************************************************************************
 */

/**
 * Close Fibre Channel peer
 *
 * @v peer		Fibre Channel peer
 * @v rc		Reason for close
 */
static void fc_peer_close ( struct fc_peer *peer, int rc ) {

	DBGC ( peer, "FCPEER %s closed: %s\n",
	       fc_ntoa ( &peer->port_wwn ) , strerror ( rc ) );

	/* Sanity check */
	assert ( list_empty ( &peer->ulps ) );

	/* Stop link timer */
	fc_link_stop ( &peer->link );

	/* Shut down interfaces */
	intf_shutdown ( &peer->plogi, rc );

	/* Remove from list of peers */
	list_del ( &peer->list );
	INIT_LIST_HEAD ( &peer->list );
}

/**
 * Increment Fibre Channel peer active usage count
 *
 * @v peer		Fibre Channel peer
 */
static void fc_peer_increment ( struct fc_peer *peer ) {

	/* Increment our usage count */
	peer->usage++;
}

/**
 * Decrement Fibre Channel peer active usage count
 *
 * @v peer		Fibre Channel peer
 */
static void fc_peer_decrement ( struct fc_peer *peer ) {

	/* Sanity check */
	assert ( peer->usage > 0 );

	/* Decrement our usage count and log out if we reach zero */
	if ( --(peer->usage) == 0 )
		fc_peer_logout ( peer, 0 );
}

/**
 * Log in Fibre Channel peer
 *
 * @v peer		Fibre Channel peer
 * @v port		Fibre Channel port
 * @v port_id		Port ID
 * @ret rc		Return status code
 */
int fc_peer_login ( struct fc_peer *peer, struct fc_port *port,
		    struct fc_port_id *port_id ) {
	struct fc_ulp *ulp;
	struct fc_ulp *tmp;

	/* Perform implicit logout if logged in and details differ */
	if ( fc_link_ok ( &peer->link ) &&
	     ( ( peer->port != port ) ||
	       ( memcmp ( &peer->port_id, port_id,
			  sizeof ( peer->port_id ) ) !=0 ) ) ) {
		fc_peer_logout ( peer, 0 );
	}

	/* Log in, if applicable */
	if ( ! fc_link_ok ( &peer->link ) ) {

		/* Record peer details */
		assert ( peer->port == NULL );
		peer->port = fc_port_get ( port );
		memcpy ( &peer->port_id, port_id, sizeof ( peer->port_id ) );
		DBGC ( peer, "FCPEER %s logged in via %s as %s\n",
		       fc_ntoa ( &peer->port_wwn ), peer->port->name,
		       fc_id_ntoa ( &peer->port_id ) );

		/* Add login reference */
		fc_peer_get ( peer );
	}

	/* Record login */
	fc_link_up ( &peer->link );

	/* Notify ULPs of link state change */
	list_for_each_entry_safe ( ulp, tmp, &peer->ulps, list ) {
		fc_ulp_get ( ulp );
		fc_link_examine ( &ulp->link );
		fc_ulp_put ( ulp );
	}

	return 0;
}

/**
 * Log out Fibre Channel peer
 *
 * @v peer		Fibre Channel peer
 * @v rc		Reason for logout
 */
void fc_peer_logout ( struct fc_peer *peer, int rc ) {
	struct fc_ulp *ulp;
	struct fc_ulp *tmp;

	DBGC ( peer, "FCPEER %s logged out: %s\n",
	       fc_ntoa ( &peer->port_wwn ), strerror ( rc ) );

	/* Drop login reference, if applicable */
	if ( fc_link_ok ( &peer->link ) )
		fc_peer_put ( peer );

	/* Erase peer details */
	fc_port_put ( peer->port );
	peer->port = NULL;

	/* Record logout */
	fc_link_err ( &peer->link, rc );

	/* Notify ULPs of link state change */
	list_for_each_entry_safe ( ulp, tmp, &peer->ulps, list ) {
		fc_ulp_get ( ulp );
		fc_link_examine ( &ulp->link );
		fc_ulp_put ( ulp );
	}

	/* Close peer if there are no active users */
	if ( peer->usage == 0 )
		fc_peer_close ( peer, rc );
}

/**
 * Handle PLOGI completion
 *
 * @v peer		Fibre Channel peer
 * @v rc		Reason for completion
 */
static void fc_peer_plogi_done ( struct fc_peer *peer, int rc ) {

	intf_restart ( &peer->plogi, rc );

	if ( rc != 0 )
		fc_peer_logout ( peer, rc );
}

/**
 * Initiate PLOGI
 *
 * @v peer		Fibre Channel peer
 * @v port		Fibre Channel port
 * @v peer_port_id	Peer port ID
 * @ret rc		Return status code
 */
static int fc_peer_plogi ( struct fc_peer *peer, struct fc_port *port,
			   struct fc_port_id *peer_port_id ) {
	int rc;

	/* Try to create PLOGI ELS */
	intf_restart ( &peer->plogi, -ECANCELED );
	if ( ( rc = fc_els_plogi ( &peer->plogi, port, peer_port_id ) ) != 0 ) {
		DBGC ( peer, "FCPEER %s could not initiate PLOGI: %s\n",
		       fc_ntoa ( &peer->port_wwn ), strerror ( rc ) );
		fc_peer_logout ( peer, rc );
		return rc;
	}

	return 0;
}

/**
 * Examine Fibre Channel peer link state
 *
 * @ link		Fibre Channel link state monitor
 */
static void fc_peer_examine ( struct fc_link_state *link ) {
	struct fc_peer *peer = container_of ( link, struct fc_peer, link );
	struct fc_port *port;
	int rc;

	/* Check to see if underlying port link has gone down */
	if ( peer->port && ( ! fc_link_ok ( &peer->port->link ) ) ) {
		fc_peer_logout ( peer, -ENOTCONN );
		return;
	}

	/* Do nothing if already logged in */
	if ( fc_link_ok ( &peer->link ) )
		return;

	DBGC ( peer, "FCPEER %s attempting login\n",
	       fc_ntoa ( &peer->port_wwn ) );

	/* Sanity check */
	assert ( peer->port == NULL );

	/* First, look for a port with the peer attached via a
	 * point-to-point link.
	 */
	list_for_each_entry ( port, &fc_ports, list ) {
		if ( fc_link_ok ( &port->link ) &&
		     ( ! ( port->flags & FC_PORT_HAS_FABRIC ) ) &&
		     ( memcmp ( &peer->port_wwn, &port->link_port_wwn,
				sizeof ( peer->port_wwn ) ) == 0 ) ) {
			/* Use this peer port ID, and stop looking */
			fc_peer_plogi ( peer, port, &port->ptp_link_port_id );
			return;
		}
	}

	/* If the peer is not directly attached, try initiating a name
	 * server lookup on any suitable ports.
	 */
	list_for_each_entry ( port, &fc_ports, list ) {
		if ( fc_link_ok ( &port->link ) &&
		     ( port->flags & FC_PORT_HAS_FABRIC ) &&
		     ( port->flags & FC_PORT_HAS_NS ) ) {
			if ( ( rc = fc_ns_query ( peer, port,
						  fc_peer_plogi ) ) != 0 ) {
				DBGC ( peer, "FCPEER %s could not attempt "
				       "name server lookup on %s: %s\n",
				       fc_ntoa ( &peer->port_wwn ), port->name,
				       strerror ( rc ) );
				/* Non-fatal */
			}
		}
	}
}

/** Fibre Channel peer PLOGI interface operations */
static struct interface_operation fc_peer_plogi_op[] = {
	INTF_OP ( intf_close, struct fc_peer *, fc_peer_plogi_done ),
};

/** Fibre Channel peer PLOGI interface descriptor */
static struct interface_descriptor fc_peer_plogi_desc =
	INTF_DESC ( struct fc_peer, plogi, fc_peer_plogi_op );

/**
 * Create Fibre Channel peer
 *
 * @v port_wwn		Node name
 * @ret peer		Fibre Channel peer, or NULL
 */
static struct fc_peer * fc_peer_create ( const struct fc_name *port_wwn ) {
	struct fc_peer *peer;

	/* Allocate and initialise structure */
	peer = zalloc ( sizeof ( *peer ) );
	if ( ! peer )
		return NULL;
	ref_init ( &peer->refcnt, NULL );
	fc_link_init ( &peer->link, fc_peer_examine, &peer->refcnt );
	intf_init ( &peer->plogi, &fc_peer_plogi_desc, &peer->refcnt );
	list_add_tail ( &peer->list, &fc_peers );
	memcpy ( &peer->port_wwn, port_wwn, sizeof ( peer->port_wwn ) );
	INIT_LIST_HEAD ( &peer->ulps );

	/* Start link monitor */
	fc_link_start ( &peer->link );

	DBGC ( peer, "FCPEER %s created\n", fc_ntoa ( &peer->port_wwn ) );
	return peer;
}

/**
 * Get Fibre Channel peer by node name
 *
 * @v port_wwn		Node name
 * @ret peer		Fibre Channel peer, or NULL
 */
struct fc_peer * fc_peer_get_wwn ( const struct fc_name *port_wwn ) {
	struct fc_peer *peer;

	/* Look for an existing peer */
	list_for_each_entry ( peer, &fc_peers, list ) {
		if ( memcmp ( &peer->port_wwn, port_wwn,
			      sizeof ( peer->port_wwn ) ) == 0 )
			return fc_peer_get ( peer );
	}

	/* Create a new peer */
	peer = fc_peer_create ( port_wwn );
	if ( ! peer )
		return NULL;

	return peer;
}

/**
 * Get Fibre Channel peer by port ID
 *
 * @v port		Fibre Channel port
 * @v peer_port_id	Peer port ID
 * @ret peer		Fibre Channel peer, or NULL
 */
struct fc_peer * fc_peer_get_port_id ( struct fc_port *port,
				       const struct fc_port_id *peer_port_id ){
	struct fc_peer *peer;

	/* Look for an existing peer */
	list_for_each_entry ( peer, &fc_peers, list ) {
		if ( ( peer->port == port ) &&
		     ( memcmp ( &peer->port_id, peer_port_id,
				sizeof ( peer->port_id ) ) == 0 ) )
			return fc_peer_get ( peer );
	}

	/* Cannot create a new peer, since we have no port name to use */
	return NULL;
}

/******************************************************************************
 *
 * Fibre Channel upper-layer protocols
 *
 ******************************************************************************
 */

/**
 * Free Fibre Channel upper-layer protocol
 *
 * @v refcnt		Reference count
 */
static void fc_ulp_free ( struct refcnt *refcnt ) {
	struct fc_ulp *ulp = container_of ( refcnt, struct fc_ulp, refcnt );

	fc_peer_put ( ulp->peer );
	free ( ulp );
}

/**
 * Close Fibre Channel upper-layer protocol
 *
 * @v ulp		Fibre Channel upper-layer protocol
 * @v rc		Reason for close
 */
static void fc_ulp_close ( struct fc_ulp *ulp, int rc ) {

	DBGC ( ulp, "FCULP %s/%02x closed: %s\n",
	       fc_ntoa ( &ulp->peer->port_wwn ), ulp->type, strerror ( rc ) );

	/* Sanity check */
	assert ( list_empty ( &ulp->users ) );

	/* Stop link monitor */
	fc_link_stop ( &ulp->link );

	/* Shut down interfaces */
	intf_shutdown ( &ulp->prli, rc );

	/* Remove from list of ULPs */
	list_del ( &ulp->list );
	INIT_LIST_HEAD ( &ulp->list );
}

/**
 * Attach Fibre Channel upper-layer protocol user
 *
 * @v ulp		Fibre Channel upper-layer protocol
 * @v user		Fibre Channel upper-layer protocol user
 */
void fc_ulp_attach ( struct fc_ulp *ulp, struct fc_ulp_user *user ) {

	/* Sanity check */
	assert ( user->ulp == NULL );

	/* Increment peer's usage count */
	fc_peer_increment ( ulp->peer );

	/* Attach user */
	user->ulp = fc_ulp_get ( ulp );
	list_add ( &user->list, &ulp->users );
}

/**
 * Detach Fibre Channel upper-layer protocol user
 *
 * @v user		Fibre Channel upper-layer protocol user
 */
void fc_ulp_detach ( struct fc_ulp_user *user ) {
	struct fc_ulp *ulp = user->ulp;

	/* Do nothing if not attached */
	if ( ! ulp )
		return;

	/* Sanity checks */
	list_check_contains_entry ( user, &ulp->users, list );

	/* Detach user and log out if no users remain */
	list_del ( &user->list );
	if ( list_empty ( &ulp->users ) )
		fc_ulp_logout ( ulp, 0 );

	/* Decrement our peer's usage count */
	fc_peer_decrement ( ulp->peer );

	/* Drop reference */
	user->ulp = NULL;
	fc_ulp_put ( ulp );
}

/**
 * Log in Fibre Channel upper-layer protocol
 *
 * @v ulp		Fibre Channel upper-layer protocol
 * @v param		Service parameters
 * @v param_len		Length of service parameters
 * @v originated	Login was originated by us
 * @ret rc		Return status code
 */
int fc_ulp_login ( struct fc_ulp *ulp, const void *param, size_t param_len,
		   int originated ) {
	struct fc_ulp_user *user;
	struct fc_ulp_user *tmp;

	/* Perform implicit logout if logged in and service parameters differ */
	if ( fc_link_ok ( &ulp->link ) &&
	     ( ( ulp->param_len != param_len ) ||
	       ( memcmp ( ulp->param, param, ulp->param_len ) != 0 ) ) ) {
		fc_ulp_logout ( ulp, 0 );
	}

	/* Work around a bug in some versions of the Linux Fibre
	 * Channel stack, which fail to fully initialise image pairs
	 * established via a PRLI originated by the Linux stack
	 * itself.
	 */
	if ( originated )
		ulp->flags |= FC_ULP_ORIGINATED_LOGIN_OK;
	if ( ! ( ulp->flags & FC_ULP_ORIGINATED_LOGIN_OK ) ) {
		DBGC ( ulp, "FCULP %s/%02x sending extra PRLI to work around "
		       "Linux bug\n",
		       fc_ntoa ( &ulp->peer->port_wwn ), ulp->type );
		fc_link_stop ( &ulp->link );
		fc_link_start ( &ulp->link );
		return 0;
	}

	/* Log in, if applicable */
	if ( ! fc_link_ok ( &ulp->link ) ) {

		/* Record service parameters */
		assert ( ulp->param == NULL );
		assert ( ulp->param_len == 0 );
		ulp->param = malloc ( param_len );
		if ( ! ulp->param ) {
			DBGC ( ulp, "FCULP %s/%02x could not record "
			       "parameters\n",
			       fc_ntoa ( &ulp->peer->port_wwn ), ulp->type );
			return -ENOMEM;
		}
		memcpy ( ulp->param, param, param_len );
		ulp->param_len = param_len;
		DBGC ( ulp, "FCULP %s/%02x logged in with parameters:\n",
		       fc_ntoa ( &ulp->peer->port_wwn ), ulp->type );
		DBGC_HDA ( ulp, 0, ulp->param, ulp->param_len );

		/* Add login reference */
		fc_ulp_get ( ulp );
	}

	/* Record login */
	fc_link_up ( &ulp->link );

	/* Notify users of link state change */
	list_for_each_entry_safe ( user, tmp, &ulp->users, list ) {
		fc_ulp_user_get ( user );
		user->examine ( user );
		fc_ulp_user_put ( user );
	}

	return 0;
}

/**
 * Log out Fibre Channel upper-layer protocol
 *
 * @v ulp		Fibre Channel upper-layer protocol
 * @v rc		Reason for logout
 */
void fc_ulp_logout ( struct fc_ulp *ulp, int rc ) {
	struct fc_ulp_user *user;
	struct fc_ulp_user *tmp;

	DBGC ( ulp, "FCULP %s/%02x logged out: %s\n",
	       fc_ntoa ( &ulp->peer->port_wwn ), ulp->type, strerror ( rc ) );

	/* Drop login reference, if applicable */
	if ( fc_link_ok ( &ulp->link ) )
		fc_ulp_put ( ulp );

	/* Discard service parameters */
	free ( ulp->param );
	ulp->param = NULL;
	ulp->param_len = 0;
	ulp->flags = 0;

	/* Record logout */
	fc_link_err ( &ulp->link, rc );

	/* Notify users of link state change */
	list_for_each_entry_safe ( user, tmp, &ulp->users, list ) {
		fc_ulp_user_get ( user );
		user->examine ( user );
		fc_ulp_user_put ( user );
	}

	/* Close ULP if there are no clients attached */
	if ( list_empty ( &ulp->users ) )
		fc_ulp_close ( ulp, rc );
}

/**
 * Handle PRLI completion
 *
 * @v ulp		Fibre Channel upper-layer protocol
 * @v rc		Reason for completion
 */
static void fc_ulp_prli_done ( struct fc_ulp *ulp, int rc ) {

	intf_restart ( &ulp->prli, rc );

	if ( rc != 0 )
		fc_ulp_logout ( ulp, rc );
}

/**
 * Examine Fibre Channel upper-layer protocol link state
 *
 * @ link		Fibre Channel link state monitor
 */
static void fc_ulp_examine ( struct fc_link_state *link ) {
	struct fc_ulp *ulp = container_of ( link, struct fc_ulp, link );
	int rc;

	/* Check to see if underlying peer link has gone down */
	if ( ! fc_link_ok ( &ulp->peer->link ) ) {
		fc_ulp_logout ( ulp, -ENOTCONN );
		return;
	}

	/* Do nothing if already logged in */
	if ( fc_link_ok ( &ulp->link ) &&
	     ( ulp->flags & FC_ULP_ORIGINATED_LOGIN_OK ) )
		return;

	DBGC ( ulp, "FCULP %s/%02x attempting login\n",
	       fc_ntoa ( &ulp->peer->port_wwn ), ulp->type );

	/* Try to create PRLI ELS */
	intf_restart ( &ulp->prli, -ECANCELED );
	if ( ( rc = fc_els_prli ( &ulp->prli, ulp->peer->port,
				  &ulp->peer->port_id, ulp->type ) ) != 0 ) {
		DBGC ( ulp, "FCULP %s/%02x could not initiate PRLI: %s\n",
		       fc_ntoa ( &ulp->peer->port_wwn ), ulp->type,
		       strerror ( rc ) );
		fc_ulp_logout ( ulp, rc );
		return;
	}
}

/** Fibre Channel upper-layer protocol PRLI interface operations */
static struct interface_operation fc_ulp_prli_op[] = {
	INTF_OP ( intf_close, struct fc_ulp *, fc_ulp_prli_done ),
};

/** Fibre Channel upper-layer protocol PRLI interface descriptor */
static struct interface_descriptor fc_ulp_prli_desc =
	INTF_DESC ( struct fc_ulp, prli, fc_ulp_prli_op );

/**
 * Create Fibre Channel upper-layer protocl
 *
 * @v peer		Fibre Channel peer
 * @v type		Type
 * @ret ulp		Fibre Channel upper-layer protocol, or NULL
 */
static struct fc_ulp * fc_ulp_create ( struct fc_peer *peer,
				       unsigned int type ) {
	struct fc_ulp *ulp;

	/* Allocate and initialise structure */
	ulp = zalloc ( sizeof ( *ulp ) );
	if ( ! ulp )
		return NULL;
	ref_init ( &ulp->refcnt, fc_ulp_free );
	fc_link_init ( &ulp->link, fc_ulp_examine, &ulp->refcnt );
	intf_init ( &ulp->prli, &fc_ulp_prli_desc, &ulp->refcnt );
	ulp->peer = fc_peer_get ( peer );
	list_add_tail ( &ulp->list, &peer->ulps );
	ulp->type = type;
	INIT_LIST_HEAD ( &ulp->users );

	/* Start link state monitor */
	fc_link_start ( &ulp->link );

	DBGC ( ulp, "FCULP %s/%02x created\n",
	       fc_ntoa ( &ulp->peer->port_wwn ), ulp->type );
	return ulp;
}

/**
 * Get Fibre Channel upper-layer protocol by peer and type
 *
 * @v peer		Fibre Channel peer
 * @v type		Type
 * @ret ulp		Fibre Channel upper-layer protocol, or NULL
 */
static struct fc_ulp * fc_ulp_get_type ( struct fc_peer *peer,
					 unsigned int type ) {
	struct fc_ulp *ulp;

	/* Look for an existing ULP */
	list_for_each_entry ( ulp, &peer->ulps, list ) {
		if ( ulp->type == type )
			return fc_ulp_get ( ulp );
	}

	/* Create a new ULP */
	ulp = fc_ulp_create ( peer, type );
	if ( ! ulp )
		return NULL;

	return ulp;
}

/**
 * Get Fibre Channel upper-layer protocol by port name and type
 *
 * @v port_wwn		Port name
 * @v type		Type
 * @ret ulp		Fibre Channel upper-layer protocol, or NULL
 */
struct fc_ulp * fc_ulp_get_wwn_type ( const struct fc_name *port_wwn,
				      unsigned int type ) {
	struct fc_ulp *ulp;
	struct fc_peer *peer;

	/* Get peer */
	peer = fc_peer_get_wwn ( port_wwn );
	if ( ! peer )
		goto err_peer_get_wwn;

	/* Get ULP */
	ulp = fc_ulp_get_type ( peer, type );
	if ( ! ulp )
		goto err_ulp_get_type;

	/* Drop temporary reference to peer */
	fc_peer_put ( peer );

	return ulp;

	fc_ulp_put ( ulp );
 err_ulp_get_type:
	fc_peer_put ( peer );
 err_peer_get_wwn:
	return NULL;
}

/**
 * Get Fibre Channel upper-layer protocol by port ID and type
 *
 * @v port		Fibre Channel port
 * @v peer_port_id	Peer port ID
 * @v type		Type
 * @ret ulp		Fibre Channel upper-layer protocol, or NULL
 */
struct fc_ulp * fc_ulp_get_port_id_type ( struct fc_port *port,
					  const struct fc_port_id *peer_port_id,
					  unsigned int type ) {
	struct fc_ulp *ulp;
	struct fc_peer *peer;

	/* Get peer */
	peer = fc_peer_get_port_id ( port, peer_port_id );
	if ( ! peer )
		goto err_peer_get_wwn;

	/* Get ULP */
	ulp = fc_ulp_get_type ( peer, type );
	if ( ! ulp )
		goto err_ulp_get_type;

	/* Drop temporary reference to peer */
	fc_peer_put ( peer );

	return ulp;

	fc_ulp_put ( ulp );
 err_ulp_get_type:
	fc_peer_put ( peer );
 err_peer_get_wwn:
	return NULL;
}

/* Drag in objects via fc_ports */
REQUIRING_SYMBOL ( fc_ports );

/* Drag in Fibre Channel configuration */
REQUIRE_OBJECT ( config_fc );
