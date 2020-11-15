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
#include <errno.h>
#include <byteswap.h>
#include <ipxe/if_ether.h>
#include <ipxe/if_arp.h>
#include <ipxe/iobuf.h>
#include <ipxe/interface.h>
#include <ipxe/xfer.h>
#include <ipxe/netdevice.h>
#include <ipxe/ethernet.h>
#include <ipxe/vlan.h>
#include <ipxe/features.h>
#include <ipxe/errortab.h>
#include <ipxe/device.h>
#include <ipxe/crc32.h>
#include <ipxe/retry.h>
#include <ipxe/timer.h>
#include <ipxe/fc.h>
#include <ipxe/fip.h>
#include <ipxe/fcoe.h>

/** @file
 *
 * FCoE protocol
 *
 */

FEATURE ( FEATURE_PROTOCOL, "FCoE", DHCP_EB_FEATURE_FCOE, 1 );

/* Disambiguate the various error causes */
#define EINVAL_UNDERLENGTH __einfo_error ( EINFO_EINVAL_UNDERLENGTH )
#define EINFO_EINVAL_UNDERLENGTH \
	__einfo_uniqify ( EINFO_EINVAL, 0x01, "Underlength packet" )
#define EINVAL_SOF __einfo_error ( EINFO_EINVAL_SOF )
#define EINFO_EINVAL_SOF \
	__einfo_uniqify ( EINFO_EINVAL, 0x02, "Invalid SoF delimiter" )
#define EINVAL_CRC __einfo_error ( EINFO_EINVAL_CRC )
#define EINFO_EINVAL_CRC \
	__einfo_uniqify ( EINFO_EINVAL, 0x03, "Invalid CRC (not stripped?)" )
#define EINVAL_EOF __einfo_error ( EINFO_EINVAL_EOF )
#define EINFO_EINVAL_EOF \
	__einfo_uniqify ( EINFO_EINVAL, 0x04, "Invalid EoF delimiter" )

/** An FCoE port */
struct fcoe_port {
	/** Reference count */
	struct refcnt refcnt;
	/** List of FCoE ports */
	struct list_head list;
	/** Transport interface */
	struct interface transport;
	/** Network device */
	struct net_device *netdev;

	/** Node WWN */
	union fcoe_name node_wwn;
	/** Port WWN */
	union fcoe_name port_wwn;

	/** FIP retransmission timer */
	struct retry_timer timer;
	/** FIP timeout counter */
	unsigned int timeouts;
	/** Flags */
	unsigned int flags;
	/** FCoE forwarder priority */
	unsigned int priority;
	/** Keepalive delay (in ms) */
	unsigned int keepalive;
	/** FCoE forwarder MAC address */
	uint8_t fcf_mac[ETH_ALEN];
	/** Local MAC address */
	uint8_t local_mac[ETH_ALEN];
};

/** FCoE flags */
enum fcoe_flags {
	/** Underlying network device is available */
	FCOE_HAVE_NETWORK = 0x0001,
	/** We have selected an FCoE forwarder to use */
	FCOE_HAVE_FCF = 0x0002,
	/** We have a FIP-capable FCoE forwarder available to be used */
	FCOE_HAVE_FIP_FCF = 0x0004,
	/** FCoE forwarder supports server-provided MAC addresses */
	FCOE_FCF_ALLOWS_SPMA = 0x0008,
	/** An alternative VLAN has been found */
	FCOE_VLAN_FOUND = 0x0010,
	/** VLAN discovery has timed out */
	FCOE_VLAN_TIMED_OUT = 0x0020,
};

struct net_protocol fcoe_protocol __net_protocol;
struct net_protocol fip_protocol __net_protocol;

/** FCoE All-FCoE-MACs address */
static uint8_t all_fcoe_macs[ETH_ALEN] =
	{ 0x01, 0x10, 0x18, 0x01, 0x00, 0x00 };

/** FCoE All-ENode-MACs address */
static uint8_t all_enode_macs[ETH_ALEN] =
	{ 0x01, 0x10, 0x18, 0x01, 0x00, 0x01 };

/** FCoE All-FCF-MACs address */
static uint8_t all_fcf_macs[ETH_ALEN] =
	{ 0x01, 0x10, 0x18, 0x01, 0x00, 0x02 };

/** Default FCoE forwarded MAC address */
static uint8_t default_fcf_mac[ETH_ALEN] =
	{ 0x0e, 0xfc, 0x00, 0xff, 0xff, 0xfe };

/** Maximum number of VLAN requests before giving up on VLAN discovery */
#define FCOE_MAX_VLAN_REQUESTS 2

/** Delay between retrying VLAN requests */
#define FCOE_VLAN_RETRY_DELAY ( TICKS_PER_SEC )

/** Delay between retrying polling VLAN requests */
#define FCOE_VLAN_POLL_DELAY ( 30 * TICKS_PER_SEC )

/** Maximum number of FIP solicitations before giving up on FIP */
#define FCOE_MAX_FIP_SOLICITATIONS 2

/** Delay between retrying FIP solicitations */
#define FCOE_FIP_RETRY_DELAY ( TICKS_PER_SEC )

/** Maximum number of missing discovery advertisements */
#define FCOE_MAX_FIP_MISSING_KEEPALIVES 4

/** List of FCoE ports */
static LIST_HEAD ( fcoe_ports );

/******************************************************************************
 *
 * FCoE protocol
 *
 ******************************************************************************
 */

/**
 * Identify FCoE port by network device
 *
 * @v netdev		Network device
 * @ret fcoe		FCoE port, or NULL
 */
static struct fcoe_port * fcoe_demux ( struct net_device *netdev ) {
	struct fcoe_port *fcoe;

	list_for_each_entry ( fcoe, &fcoe_ports, list ) {
		if ( fcoe->netdev == netdev )
			return fcoe;
	}
	return NULL;
}

/**
 * Reset FCoE port
 *
 * @v fcoe		FCoE port
 */
static void fcoe_reset ( struct fcoe_port *fcoe ) {

	/* Detach FC port, if any */
	intf_restart ( &fcoe->transport, -ECANCELED );

	/* Reset any FIP state */
	stop_timer ( &fcoe->timer );
	fcoe->timeouts = 0;
	fcoe->flags = 0;
	fcoe->priority = ( FIP_LOWEST_PRIORITY + 1 );
	fcoe->keepalive = 0;
	memcpy ( fcoe->fcf_mac, default_fcf_mac,
		 sizeof ( fcoe->fcf_mac ) );
	memcpy ( fcoe->local_mac, fcoe->netdev->ll_addr,
		 sizeof ( fcoe->local_mac ) );

	/* Start FIP solicitation if network is available */
	if ( netdev_is_open ( fcoe->netdev ) &&
	     netdev_link_ok ( fcoe->netdev ) ) {
		fcoe->flags |= FCOE_HAVE_NETWORK;
		start_timer_nodelay ( &fcoe->timer );
		DBGC ( fcoe, "FCoE %s starting %s\n", fcoe->netdev->name,
		       ( vlan_can_be_trunk ( fcoe->netdev ) ?
			 "VLAN discovery" : "FIP solicitation" ) );
	}

	/* Send notification of window change */
	xfer_window_changed ( &fcoe->transport );
}

/**
 * Transmit FCoE packet
 *
 * @v fcoe		FCoE port
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int fcoe_deliver ( struct fcoe_port *fcoe,
			  struct io_buffer *iobuf,
			  struct xfer_metadata *meta __unused ) {
	struct fc_frame_header *fchdr = iobuf->data;
	struct fc_els_frame_common *els = ( iobuf->data + sizeof ( *fchdr ) );
	struct fcoe_header *fcoehdr;
	struct fcoe_footer *fcoeftr;
	struct fip_header *fiphdr;
	struct fip_login *fipflogi;
	struct fip_mac_address *fipmac;
	uint32_t crc;
	struct net_protocol *net_protocol;
	void *ll_source;
	int rc;

	/* Send as FIP or FCoE as appropriate */
	if ( ( fchdr->r_ctl == ( FC_R_CTL_ELS | FC_R_CTL_UNSOL_CTRL ) ) &&
	     ( els->command == FC_ELS_FLOGI ) &&
	     ( fcoe->flags & FCOE_HAVE_FIP_FCF ) ) {

		/* Create FIP FLOGI descriptor */
		fipflogi = iob_push ( iobuf,
				      offsetof ( typeof ( *fipflogi ), fc ) );
		memset ( fipflogi, 0, offsetof ( typeof ( *fipflogi ), fc ) );
		fipflogi->type = FIP_FLOGI;
		fipflogi->len = ( iob_len ( iobuf ) / 4 );

		/* Create FIP MAC address descriptor */
		fipmac = iob_put ( iobuf, sizeof ( *fipmac ) );
		memset ( fipmac, 0, sizeof ( *fipmac ) );
		fipmac->type = FIP_MAC_ADDRESS;
		fipmac->len = ( sizeof ( *fipmac ) / 4 );
		if ( fcoe->flags & FCOE_FCF_ALLOWS_SPMA ) {
			memcpy ( fipmac->mac, fcoe->netdev->ll_addr,
				 sizeof ( fipmac->mac ) );
		}

		/* Create FIP header */
		fiphdr = iob_push ( iobuf, sizeof ( *fiphdr ) );
		memset ( fiphdr, 0, sizeof ( *fiphdr ) );
		fiphdr->version = FIP_VERSION;
		fiphdr->code = htons ( FIP_CODE_ELS );
		fiphdr->subcode = FIP_ELS_REQUEST;
		fiphdr->len =
			htons ( ( iob_len ( iobuf ) - sizeof ( *fiphdr ) ) / 4);
		fiphdr->flags = ( ( fcoe->flags & FCOE_FCF_ALLOWS_SPMA ) ?
				  htons ( FIP_SP ) : htons ( FIP_FP ) );

		/* Send as FIP packet from netdev's own MAC address */
		net_protocol = &fip_protocol;
		ll_source = fcoe->netdev->ll_addr;

	} else {

		/* Calculate CRC */
		crc = crc32_le ( ~((uint32_t)0), iobuf->data,
				 iob_len ( iobuf ) );

		/* Create FCoE header */
		fcoehdr = iob_push ( iobuf, sizeof ( *fcoehdr ) );
		memset ( fcoehdr, 0, sizeof ( *fcoehdr ) );
		fcoehdr->sof = ( ( fchdr->seq_cnt == ntohs ( 0 ) ) ?
				 FCOE_SOF_I3 : FCOE_SOF_N3 );

		/* Create FCoE footer */
		fcoeftr = iob_put ( iobuf, sizeof ( *fcoeftr ) );
		memset ( fcoeftr, 0, sizeof ( *fcoeftr ) );
		fcoeftr->crc = cpu_to_le32 ( crc ^ ~((uint32_t)0) );
		fcoeftr->eof = ( ( fchdr->f_ctl_es & FC_F_CTL_ES_END ) ?
				 FCOE_EOF_T : FCOE_EOF_N );

		/* Send as FCoE packet from FCoE MAC address */
		net_protocol = &fcoe_protocol;
		ll_source = fcoe->local_mac;
	}

	/* Transmit packet */
	if ( ( rc = net_tx ( iob_disown ( iobuf ), fcoe->netdev, net_protocol,
			     fcoe->fcf_mac, ll_source ) ) != 0 ) {
		DBGC ( fcoe, "FCoE %s could not transmit: %s\n",
		       fcoe->netdev->name, strerror ( rc ) );
		goto done;
	}

 done:
	free_iob ( iobuf );
	return rc;
}

/**
 * Allocate FCoE I/O buffer
 *
 * @v len		Payload length
 * @ret iobuf		I/O buffer, or NULL
 */
static struct io_buffer * fcoe_alloc_iob ( struct fcoe_port *fcoe __unused,
					   size_t len ) {
	struct io_buffer *iobuf;

	iobuf = alloc_iob ( MAX_LL_HEADER_LEN + sizeof ( struct fcoe_header ) +
			    len + sizeof ( struct fcoe_footer ) );
	if ( iobuf ) {
		iob_reserve ( iobuf, ( MAX_LL_HEADER_LEN +
				       sizeof ( struct fcoe_header ) ) );
	}
	return iobuf;
}

/**
 * Process incoming FCoE packets
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v ll_dest		Link-layer destination address
 * @v ll_source		Link-layer source address
 * @v flags		Packet flags
 * @ret rc		Return status code
 */
static int fcoe_rx ( struct io_buffer *iobuf, struct net_device *netdev,
		     const void *ll_dest, const void *ll_source,
		     unsigned int flags __unused ) {
	struct fcoe_header *fcoehdr;
	struct fcoe_footer *fcoeftr;
	struct fcoe_port *fcoe;
	int rc;

	/* Identify FCoE port */
	if ( ( fcoe = fcoe_demux ( netdev ) ) == NULL ) {
		DBG ( "FCoE received frame for net device %s missing FCoE "
		      "port\n", netdev->name );
		rc = -ENOTCONN;
		goto done;
	}

	/* Discard packets not destined for us */
	if ( ( memcmp ( fcoe->local_mac, ll_dest,
			sizeof ( fcoe->local_mac ) ) != 0 ) &&
	     ( memcmp ( default_fcf_mac, ll_dest,
			sizeof ( default_fcf_mac ) ) != 0 ) ) {
		DBGC2 ( fcoe, "FCoE %s ignoring packet for %s\n",
			fcoe->netdev->name, eth_ntoa ( ll_dest ) );
		rc = -ENOTCONN;
		goto done;
	}

	/* Sanity check */
	if ( iob_len ( iobuf ) < ( sizeof ( *fcoehdr ) + sizeof ( *fcoeftr ) )){
		DBGC ( fcoe, "FCoE %s received under-length frame (%zd "
		       "bytes)\n", fcoe->netdev->name, iob_len ( iobuf ) );
		rc = -EINVAL_UNDERLENGTH;
		goto done;
	}

	/* Strip header and footer */
	fcoehdr = iobuf->data;
	iob_pull ( iobuf, sizeof ( *fcoehdr ) );
	fcoeftr = ( iobuf->data + iob_len ( iobuf ) - sizeof ( *fcoeftr ) );
	iob_unput ( iobuf, sizeof ( *fcoeftr ) );

	/* Validity checks */
	if ( fcoehdr->version != FCOE_FRAME_VER ) {
		DBGC ( fcoe, "FCoE %s received unsupported frame version "
		       "%02x\n", fcoe->netdev->name, fcoehdr->version );
		rc = -EPROTONOSUPPORT;
		goto done;
	}
	if ( ! ( ( fcoehdr->sof == FCOE_SOF_I3 ) ||
		 ( fcoehdr->sof == FCOE_SOF_N3 ) ) ) {
		DBGC ( fcoe, "FCoE %s received unsupported start-of-frame "
		       "delimiter %02x\n", fcoe->netdev->name, fcoehdr->sof );
		rc = -EINVAL_SOF;
		goto done;
	}
	if ( ( le32_to_cpu ( fcoeftr->crc ) ^ ~((uint32_t)0) ) !=
	     crc32_le ( ~((uint32_t)0), iobuf->data, iob_len ( iobuf ) ) ) {
		DBGC ( fcoe, "FCoE %s received invalid CRC\n",
		       fcoe->netdev->name );
		rc = -EINVAL_CRC;
		goto done;
	}
	if ( ! ( ( fcoeftr->eof == FCOE_EOF_N ) ||
		 ( fcoeftr->eof == FCOE_EOF_T ) ) ) {
		DBGC ( fcoe, "FCoE %s received unsupported end-of-frame "
		       "delimiter %02x\n", fcoe->netdev->name, fcoeftr->eof );
		rc = -EINVAL_EOF;
		goto done;
	}

	/* Record FCF address if applicable */
	if ( ( fcoe->flags & FCOE_HAVE_FCF ) &&
	     ( ! ( fcoe->flags & FCOE_HAVE_FIP_FCF ) ) ) {
		memcpy ( &fcoe->fcf_mac, ll_source, sizeof ( fcoe->fcf_mac ) );
	}

	/* Hand off via transport interface */
	if ( ( rc = xfer_deliver_iob ( &fcoe->transport,
				       iob_disown ( iobuf ) ) ) != 0 ) {
		DBGC ( fcoe, "FCoE %s could not deliver frame: %s\n",
		       fcoe->netdev->name, strerror ( rc ) );
		goto done;
	}

 done:
	free_iob ( iobuf );
	return rc;
}

/**
 * Check FCoE flow control window
 *
 * @v fcoe		FCoE port
 * @ret len		Length of window
 */
static size_t fcoe_window ( struct fcoe_port *fcoe ) {
	return ( ( fcoe->flags & FCOE_HAVE_FCF ) ? ~( ( size_t ) 0 ) : 0 );
}

/**
 * Close FCoE port
 *
 * @v fcoe		FCoE port
 * @v rc		Reason for close
 */
static void fcoe_close ( struct fcoe_port *fcoe, int rc ) {

	stop_timer ( &fcoe->timer );
	intf_shutdown ( &fcoe->transport, rc );
	netdev_put ( fcoe->netdev );
	list_del ( &fcoe->list );
	ref_put ( &fcoe->refcnt );
}

/**
 * Identify device underlying FCoE port
 *
 * @v fcoe		FCoE port
 * @ret device		Underlying device
 */
static struct device * fcoe_identify_device ( struct fcoe_port *fcoe ) {
	return fcoe->netdev->dev;
}

/** FCoE transport interface operations */
static struct interface_operation fcoe_transport_op[] = {
	INTF_OP ( xfer_deliver, struct fcoe_port *, fcoe_deliver ),
	INTF_OP ( xfer_alloc_iob, struct fcoe_port *, fcoe_alloc_iob ),
	INTF_OP ( xfer_window, struct fcoe_port *, fcoe_window ),
	INTF_OP ( intf_close, struct fcoe_port *, fcoe_close ),
	INTF_OP ( identify_device, struct fcoe_port *,
		  fcoe_identify_device ),
};

/** FCoE transport interface descriptor */
static struct interface_descriptor fcoe_transport_desc =
	INTF_DESC ( struct fcoe_port, transport, fcoe_transport_op );

/******************************************************************************
 *
 * FIP protocol
 *
 ******************************************************************************
 */

/**
 * Parse FIP packet into descriptor set
 *
 * @v fcoe		FCoE port
 * @v fiphdr		FIP header
 * @v len		Length of FIP packet
 * @v descs		Descriptor set to fill in
 * @ret rc		Return status code
 */
static int fcoe_fip_parse ( struct fcoe_port *fcoe, struct fip_header *fiphdr,
			    size_t len, struct fip_descriptors *descs ) {
	union fip_descriptor *desc;
	size_t descs_len;
	size_t desc_len;
	size_t desc_offset;
	unsigned int desc_type;

	/* Check FIP version */
	if ( fiphdr->version != FIP_VERSION ) {
		DBGC ( fcoe, "FCoE %s received unsupported FIP version %02x\n",
		       fcoe->netdev->name, fiphdr->version );
		return -EINVAL;
	}

	/* Check length */
	descs_len = ( ntohs ( fiphdr->len ) * 4 );
	if ( ( sizeof ( *fiphdr ) + descs_len ) > len ) {
		DBGC ( fcoe, "FCoE %s received bad descriptor list length\n",
		       fcoe->netdev->name );
		return -EINVAL;
	}

	/* Parse descriptor list */
	memset ( descs, 0, sizeof ( *descs ) );
	for ( desc_offset = 0 ;
	      desc_offset <= ( descs_len - sizeof ( desc->common ) ) ;
	      desc_offset += desc_len ) {

		/* Find descriptor and validate length */
		desc = ( ( ( void * ) ( fiphdr + 1 ) ) + desc_offset );
		desc_type = desc->common.type;
		desc_len = ( desc->common.len * 4 );
		if ( desc_len == 0 ) {
			DBGC ( fcoe, "FCoE %s received zero-length "
			       "descriptor\n", fcoe->netdev->name );
			return -EINVAL;
		}
		if ( ( desc_offset + desc_len ) > descs_len ) {
			DBGC ( fcoe, "FCoE %s descriptor overrun\n",
			       fcoe->netdev->name );
			return -EINVAL;
		}

		/* Handle descriptors that we understand */
		if ( ( desc_type > FIP_RESERVED ) &&
		     ( desc_type < FIP_NUM_DESCRIPTOR_TYPES ) ) {
			/* Use only the first instance of a descriptor */
			if ( descs->desc[desc_type] == NULL )
				descs->desc[desc_type] = desc;
			continue;
		}

		/* Abort if we cannot understand a critical descriptor */
		if ( FIP_IS_CRITICAL ( desc_type ) ) {
			DBGC ( fcoe, "FCoE %s cannot understand critical "
			       "descriptor type %02x\n",
			       fcoe->netdev->name, desc_type );
			return -ENOTSUP;
		}

		/* Ignore non-critical descriptors that we cannot understand */
	}

	return 0;
}

/**
 * Send FIP VLAN request
 *
 * @v fcoe		FCoE port
 * @ret rc		Return status code
 */
static int fcoe_fip_tx_vlan ( struct fcoe_port *fcoe ) {
	struct io_buffer *iobuf;
	struct {
		struct fip_header hdr;
		struct fip_mac_address mac_address;
	} __attribute__ (( packed )) *request;
	int rc;

	/* Allocate I/O buffer */
	iobuf = alloc_iob ( MAX_LL_HEADER_LEN + sizeof ( *request ) );
	if ( ! iobuf )
		return -ENOMEM;
	iob_reserve ( iobuf, MAX_LL_HEADER_LEN );

	/* Construct VLAN request */
	request = iob_put ( iobuf, sizeof ( *request ) );
	memset ( request, 0, sizeof ( *request ) );
	request->hdr.version = FIP_VERSION;
	request->hdr.code = htons ( FIP_CODE_VLAN );
	request->hdr.subcode = FIP_VLAN_REQUEST;
	request->hdr.len = htons ( ( sizeof ( *request ) -
				     sizeof ( request->hdr ) ) / 4 );
	request->mac_address.type = FIP_MAC_ADDRESS;
	request->mac_address.len =
		( sizeof ( request->mac_address ) / 4 );
	memcpy ( request->mac_address.mac, fcoe->netdev->ll_addr,
		 sizeof ( request->mac_address.mac ) );

	/* Send VLAN request */
	if ( ( rc = net_tx ( iob_disown ( iobuf ), fcoe->netdev,
			     &fip_protocol, all_fcf_macs,
			     fcoe->netdev->ll_addr ) ) != 0 ) {
		DBGC ( fcoe, "FCoE %s could not send VLAN request: "
		       "%s\n", fcoe->netdev->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Handle received FIP VLAN notification
 *
 * @v fcoe		FCoE port
 * @v descs		Descriptor list
 * @v flags		Flags
 * @ret rc		Return status code
 */
static int fcoe_fip_rx_vlan ( struct fcoe_port *fcoe,
			      struct fip_descriptors *descs,
			      unsigned int flags __unused ) {
	struct fip_mac_address *mac_address = fip_mac_address ( descs );
	struct fip_vlan *vlan = fip_vlan ( descs );
	unsigned int tag;
	int rc;

	/* Sanity checks */
	if ( ! mac_address ) {
		DBGC ( fcoe, "FCoE %s received VLAN notification missing MAC "
		       "address\n", fcoe->netdev->name );
		return -EINVAL;
	}
	if ( ! vlan ) {
		DBGC ( fcoe, "FCoE %s received VLAN notification missing VLAN "
		       "tag\n", fcoe->netdev->name );
		return -EINVAL;
	}

	/* Create VLAN */
	tag = ntohs ( vlan->vlan );
	DBGC ( fcoe, "FCoE %s creating VLAN %d for FCF %s\n",
	       fcoe->netdev->name, tag, eth_ntoa ( mac_address->mac ) );
	if ( ( rc = vlan_create ( fcoe->netdev, tag,
				  FCOE_VLAN_PRIORITY ) ) != 0 ) {
		DBGC ( fcoe, "FCoE %s could not create VLAN %d: %s\n",
		       fcoe->netdev->name, tag, strerror ( rc ) );
		return rc;
	}

	/* Record that a VLAN was found.  This FCoE port will play no
	 * further active role; the real FCoE traffic will use the
	 * port automatically created for the new VLAN device.
	 */
	fcoe->flags |= FCOE_VLAN_FOUND;

	return 0;
}

/**
 * Send FIP discovery solicitation
 *
 * @v fcoe		FCoE port
 * @ret rc		Return status code
 */
static int fcoe_fip_tx_solicitation ( struct fcoe_port *fcoe ) {
	struct io_buffer *iobuf;
	struct {
		struct fip_header hdr;
		struct fip_mac_address mac_address;
		struct fip_name_id name_id;
		struct fip_max_fcoe_size max_fcoe_size;
	} __attribute__ (( packed )) *solicitation;
	int rc;

	/* Allocate I/O buffer */
	iobuf = alloc_iob ( MAX_LL_HEADER_LEN + sizeof ( *solicitation ) );
	if ( ! iobuf )
		return -ENOMEM;
	iob_reserve ( iobuf, MAX_LL_HEADER_LEN );

	/* Construct discovery solicitation */
	solicitation = iob_put ( iobuf, sizeof ( *solicitation ) );
	memset ( solicitation, 0, sizeof ( *solicitation ) );
	solicitation->hdr.version = FIP_VERSION;
	solicitation->hdr.code = htons ( FIP_CODE_DISCOVERY );
	solicitation->hdr.subcode = FIP_DISCOVERY_SOLICIT;
	solicitation->hdr.len =	htons ( ( sizeof ( *solicitation ) -
					  sizeof ( solicitation->hdr ) ) / 4 );
	solicitation->hdr.flags = htons ( FIP_FP | FIP_SP );
	solicitation->mac_address.type = FIP_MAC_ADDRESS;
	solicitation->mac_address.len =
		( sizeof ( solicitation->mac_address ) / 4 );
	memcpy ( solicitation->mac_address.mac, fcoe->netdev->ll_addr,
		 sizeof ( solicitation->mac_address.mac ) );
	solicitation->name_id.type = FIP_NAME_ID;
	solicitation->name_id.len = ( sizeof ( solicitation->name_id ) / 4 );
	memcpy ( &solicitation->name_id.name, &fcoe->node_wwn.fc,
		 sizeof ( solicitation->name_id.name ) );
	solicitation->max_fcoe_size.type = FIP_MAX_FCOE_SIZE;
	solicitation->max_fcoe_size.len =
		( sizeof ( solicitation->max_fcoe_size ) / 4 );
	solicitation->max_fcoe_size.mtu =
		htons ( ETH_MAX_MTU - sizeof ( struct fcoe_header ) -
			sizeof ( struct fcoe_footer ) );

	/* Send discovery solicitation */
	if ( ( rc = net_tx ( iob_disown ( iobuf ), fcoe->netdev,
			     &fip_protocol, all_fcf_macs,
			     fcoe->netdev->ll_addr ) ) != 0 ) {
		DBGC ( fcoe, "FCoE %s could not send discovery solicitation: "
		       "%s\n", fcoe->netdev->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Handle received FIP discovery advertisement
 *
 * @v fcoe		FCoE port
 * @v descs		Descriptor list
 * @v flags		Flags
 * @ret rc		Return status code
 */
static int fcoe_fip_rx_advertisement ( struct fcoe_port *fcoe,
				       struct fip_descriptors *descs,
				       unsigned int flags ) {
	struct fip_priority *priority = fip_priority ( descs );
	struct fip_mac_address *mac_address = fip_mac_address ( descs );
	struct fip_fka_adv_p *fka_adv_p = fip_fka_adv_p ( descs );

	/* Sanity checks */
	if ( ! priority ) {
		DBGC ( fcoe, "FCoE %s received advertisement missing "
		       "priority\n", fcoe->netdev->name );
		return -EINVAL;
	}
	if ( ! mac_address ) {
		DBGC ( fcoe, "FCoE %s received advertisement missing MAC "
		       "address\n", fcoe->netdev->name );
		return -EINVAL;
	}
	if ( ! fka_adv_p ) {
		DBGC ( fcoe, "FCoE %s received advertisement missing FKA ADV "
		       "period\n", fcoe->netdev->name );
		return -EINVAL;
	}

	if ( ! ( fcoe->flags & FCOE_HAVE_FCF ) ) {

		/* We are soliciting for an FCF.  Store the highest
		 * (i.e. lowest-valued) priority solicited
		 * advertisement that we receive.
		 */
		if ( ( ( flags & ( FIP_A | FIP_S | FIP_F ) ) ==
		       ( FIP_A | FIP_S | FIP_F ) ) &&
		     ( priority->priority < fcoe->priority ) ) {

			fcoe->flags |= FCOE_HAVE_FIP_FCF;
			fcoe->priority = priority->priority;
			if ( fka_adv_p->flags & FIP_NO_KEEPALIVE ) {
				fcoe->keepalive = 0;
			} else {
				fcoe->keepalive = ntohl ( fka_adv_p->period );
			}
			fcoe->flags &= ~FCOE_FCF_ALLOWS_SPMA;
			if ( flags & FIP_SP )
				fcoe->flags |= FCOE_FCF_ALLOWS_SPMA;
			memcpy ( fcoe->fcf_mac, mac_address->mac,
				 sizeof ( fcoe->fcf_mac ) );
			DBGC ( fcoe, "FCoE %s selected FCF %s (pri %d",
			       fcoe->netdev->name, eth_ntoa ( fcoe->fcf_mac ),
			       fcoe->priority );
			if ( fcoe->keepalive ) {
				DBGC ( fcoe, ", FKA ADV %dms",
				       fcoe->keepalive );
			}
			DBGC ( fcoe, ", %cPMA)\n",
			       ( ( fcoe->flags & FCOE_FCF_ALLOWS_SPMA ) ?
				 'S' : 'F' ) );
		}

	} else if ( fcoe->flags & FCOE_HAVE_FIP_FCF ) {

		/* We are checking that the FCF remains alive.  Reset
		 * the timeout counter if this is an advertisement
		 * from our forwarder.
		 */
		if ( memcmp ( fcoe->fcf_mac, mac_address->mac,
			      sizeof ( fcoe->fcf_mac ) ) == 0 ) {
			fcoe->timeouts = 0;
		}

	} else {

		/* We are operating in non-FIP mode and have received
		 * a FIP advertisement.  Reset the link in order to
		 * attempt FIP.
		 */
		fcoe_reset ( fcoe );

	}

	return 0;
}

/**
 * Handle received FIP ELS response
 *
 * @v fcoe		FCoE port
 * @v descs		Descriptor list
 * @v flags		Flags
 * @ret rc		Return status code
 */
static int fcoe_fip_rx_els_response ( struct fcoe_port *fcoe,
				      struct fip_descriptors *descs,
				      unsigned int flags __unused ) {
	struct fip_els *flogi = fip_flogi ( descs );
	struct fip_mac_address *mac_address = fip_mac_address ( descs );
	void *frame;
	size_t frame_len;
	int rc;

	/* Sanity checks */
	if ( ! flogi ) {
		DBGC ( fcoe, "FCoE %s received ELS response missing FLOGI\n",
		       fcoe->netdev->name );
		return -EINVAL;
	}
	if ( ! mac_address ) {
		DBGC ( fcoe, "FCoE %s received ELS response missing MAC "
		       "address\n", fcoe->netdev->name );
		return -EINVAL;
	}

	/* Record local MAC address */
	memcpy ( fcoe->local_mac, mac_address->mac, sizeof ( fcoe->local_mac ));
	DBGC ( fcoe, "FCoE %s using local MAC %s\n",
	       fcoe->netdev->name, eth_ntoa ( fcoe->local_mac ) );

	/* Hand off via transport interface */
	frame = &flogi->fc;
	frame_len = ( ( flogi->len * 4 ) - offsetof ( typeof ( *flogi ), fc ) );
	if ( ( rc = xfer_deliver_raw ( &fcoe->transport, frame,
				       frame_len ) ) != 0 ) {
		DBGC ( fcoe, "FCoE %s could not deliver FIP FLOGI frame: %s\n",
		       fcoe->netdev->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Send FIP keepalive
 *
 * @v fcoe		FCoE port
 * @ret rc		Return status code
 */
static int fcoe_fip_tx_keepalive ( struct fcoe_port *fcoe ) {
	struct io_buffer *iobuf;
	struct {
		struct fip_header hdr;
		struct fip_mac_address mac_address;
	} __attribute__ (( packed )) *keepalive;
	int rc;

	/* Allocate I/O buffer */
	iobuf = alloc_iob ( MAX_LL_HEADER_LEN + sizeof ( *keepalive ) );
	if ( ! iobuf )
		return -ENOMEM;
	iob_reserve ( iobuf, MAX_LL_HEADER_LEN );

	/* Construct keepalive */
	keepalive = iob_put ( iobuf, sizeof ( *keepalive ) );
	memset ( keepalive, 0, sizeof ( *keepalive ) );
	keepalive->hdr.version = FIP_VERSION;
	keepalive->hdr.code = htons ( FIP_CODE_MAINTAIN );
	keepalive->hdr.subcode = FIP_MAINTAIN_KEEP_ALIVE;
	keepalive->hdr.len =	htons ( ( sizeof ( *keepalive ) -
					  sizeof ( keepalive->hdr ) ) / 4 );
	keepalive->mac_address.type = FIP_MAC_ADDRESS;
	keepalive->mac_address.len =
		( sizeof ( keepalive->mac_address ) / 4 );
	memcpy ( keepalive->mac_address.mac, fcoe->netdev->ll_addr,
		 sizeof ( keepalive->mac_address.mac ) );

	/* Send keepalive */
	if ( ( rc = net_tx ( iob_disown ( iobuf ), fcoe->netdev,
			     &fip_protocol, fcoe->fcf_mac,
			     fcoe->netdev->ll_addr ) ) != 0 ) {
		DBGC ( fcoe, "FCoE %s could not send keepalive: %s\n",
		       fcoe->netdev->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/** A FIP handler */
struct fip_handler {
	/** Protocol code */
	uint16_t code;
	/** Protocol subcode */
	uint8_t subcode;
	/**
	 * Receive FIP packet
	 *
	 * @v fcoe		FCoE port
	 * @v descs		Descriptor list
	 * @v flags		Flags
	 * @ret rc		Return status code
	 */
	int ( * rx ) ( struct fcoe_port *fcoe, struct fip_descriptors *descs,
		       unsigned int flags );
};

/** FIP handlers */
static struct fip_handler fip_handlers[] = {
	{ FIP_CODE_VLAN, FIP_VLAN_NOTIFY,
	  fcoe_fip_rx_vlan },
	{ FIP_CODE_DISCOVERY, FIP_DISCOVERY_ADVERTISE,
	  fcoe_fip_rx_advertisement },
	{ FIP_CODE_ELS, FIP_ELS_RESPONSE,
	  fcoe_fip_rx_els_response },
};

/**
 * Process incoming FIP packets
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v ll_dest		Link-layer destination address
 * @v ll_source		Link-layer source address
 * @v flags		Packet flags
 * @ret rc		Return status code
 */
static int fcoe_fip_rx ( struct io_buffer *iobuf,
			 struct net_device *netdev,
			 const void *ll_dest,
			 const void *ll_source __unused,
			 unsigned int flags __unused ) {
	struct fip_header *fiphdr = iobuf->data;
	struct fip_descriptors descs;
	struct fip_handler *handler;
	struct fcoe_port *fcoe;
	unsigned int i;
	int rc;

	/* Identify FCoE port */
	if ( ( fcoe = fcoe_demux ( netdev ) ) == NULL ) {
		DBG ( "FCoE received FIP frame for net device %s missing FCoE "
		      "port\n", netdev->name );
		rc = -ENOTCONN;
		goto done;
	}

	/* Discard packets not destined for us */
	if ( ( memcmp ( fcoe->netdev->ll_addr, ll_dest, ETH_ALEN ) != 0 ) &&
	     ( memcmp ( all_fcoe_macs, ll_dest,
			sizeof ( all_fcoe_macs ) ) != 0 ) &&
	     ( memcmp ( all_enode_macs, ll_dest,
			sizeof ( all_enode_macs ) ) != 0 ) ) {
		DBGC2 ( fcoe, "FCoE %s ignoring FIP packet for %s\n",
			fcoe->netdev->name, eth_ntoa ( ll_dest ) );
		rc = -ENOTCONN;
		goto done;
	}

	/* Parse FIP packet */
	if ( ( rc = fcoe_fip_parse ( fcoe, fiphdr, iob_len ( iobuf ),
				     &descs ) ) != 0 )
		goto done;

	/* Find a suitable handler */
	for ( i = 0 ; i < ( sizeof ( fip_handlers ) /
			    sizeof ( fip_handlers[0] ) ) ; i++ ) {
		handler = &fip_handlers[i];
		if ( ( handler->code == ntohs ( fiphdr->code ) ) &&
		     ( handler->subcode == fiphdr->subcode ) ) {
			rc = handler->rx ( fcoe, &descs,
					   ntohs ( fiphdr->flags ) );
			goto done;
		}
	}
	DBGC ( fcoe, "FCoE %s received unsupported FIP code %04x.%02x\n",
	       fcoe->netdev->name, ntohs ( fiphdr->code ), fiphdr->subcode );
	rc = -ENOTSUP;

 done:
	free_iob ( iobuf );
	return rc;
}

/******************************************************************************
 *
 * FCoE ports
 *
 ******************************************************************************
 */

/**
 * Handle FCoE timer expiry
 *
 * @v timer		FIP timer
 * @v over		Timer expired
 */
static void fcoe_expired ( struct retry_timer *timer, int over __unused ) {
	struct fcoe_port *fcoe =
		container_of ( timer, struct fcoe_port, timer );
	int rc;

	/* Sanity check */
	assert ( fcoe->flags & FCOE_HAVE_NETWORK );

	/* Increment the timeout counter */
	fcoe->timeouts++;

	if ( vlan_can_be_trunk ( fcoe->netdev ) &&
	     ! ( fcoe->flags & FCOE_VLAN_TIMED_OUT ) ) {

		/* If we have already found a VLAN, send infrequent
		 * VLAN requests, in case VLAN information changes.
		 */
		if ( fcoe->flags & FCOE_VLAN_FOUND ) {
			fcoe->flags &= ~FCOE_VLAN_FOUND;
			fcoe->timeouts = 0;
			start_timer_fixed ( &fcoe->timer,
					    FCOE_VLAN_POLL_DELAY );
			fcoe_fip_tx_vlan ( fcoe );
			return;
		}

		/* If we have not yet found a VLAN, and we have not
		 * yet timed out and given up on finding one, then
		 * send a VLAN request and wait.
		 */
		if ( fcoe->timeouts <= FCOE_MAX_VLAN_REQUESTS ) {
			start_timer_fixed ( &fcoe->timer,
					    FCOE_VLAN_RETRY_DELAY );
			fcoe_fip_tx_vlan ( fcoe );
			return;
		}

		/* We have timed out waiting for a VLAN; proceed to
		 * FIP discovery.
		 */
		fcoe->flags |= FCOE_VLAN_TIMED_OUT;
		fcoe->timeouts = 0;
		DBGC ( fcoe, "FCoE %s giving up on VLAN discovery\n",
		       fcoe->netdev->name );
		start_timer_nodelay ( &fcoe->timer );

	} else if ( ! ( fcoe->flags & FCOE_HAVE_FCF ) ) {

		/* If we have not yet found a FIP-capable forwarder,
		 * and we have not yet timed out and given up on
		 * finding one, then send a FIP solicitation and wait.
		 */
		start_timer_fixed ( &fcoe->timer, FCOE_FIP_RETRY_DELAY );
		if ( ( ! ( fcoe->flags & FCOE_HAVE_FIP_FCF ) ) &&
		     ( fcoe->timeouts <= FCOE_MAX_FIP_SOLICITATIONS ) ) {
			fcoe_fip_tx_solicitation ( fcoe );
			return;
		}

		/* Attach Fibre Channel port */
		if ( ( rc = fc_port_open ( &fcoe->transport, &fcoe->node_wwn.fc,
					   &fcoe->port_wwn.fc,
					   fcoe->netdev->name ) ) != 0 ) {
			DBGC ( fcoe, "FCoE %s could not create FC port: %s\n",
			       fcoe->netdev->name, strerror ( rc ) );
			/* We will try again on the next timer expiry */
			return;
		}
		stop_timer ( &fcoe->timer );

		/* Either we have found a FIP-capable forwarder, or we
		 * have timed out and will fall back to pre-FIP mode.
		 */
		fcoe->flags |= FCOE_HAVE_FCF;
		fcoe->timeouts = 0;
		DBGC ( fcoe, "FCoE %s using %sFIP FCF %s\n", fcoe->netdev->name,
		       ( ( fcoe->flags & FCOE_HAVE_FIP_FCF ) ? "" : "non-" ),
		       eth_ntoa ( fcoe->fcf_mac ) );

		/* Start sending keepalives if applicable */
		if ( fcoe->keepalive )
			start_timer_nodelay ( &fcoe->timer );

		/* Send notification of window change */
		xfer_window_changed ( &fcoe->transport );

	} else {

		/* Send keepalive */
		start_timer_fixed ( &fcoe->timer,
			      ( ( fcoe->keepalive * TICKS_PER_SEC ) / 1000 ) );
		fcoe_fip_tx_keepalive ( fcoe );

		/* Abandon FCF if we have not seen its advertisements */
		if ( fcoe->timeouts > FCOE_MAX_FIP_MISSING_KEEPALIVES ) {
			DBGC ( fcoe, "FCoE %s abandoning FCF %s\n",
			       fcoe->netdev->name, eth_ntoa ( fcoe->fcf_mac ));
			fcoe_reset ( fcoe );
		}
	}
}

/**
 * Create FCoE port
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int fcoe_probe ( struct net_device *netdev ) {
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	struct fcoe_port *fcoe;
	int rc;

	/* Sanity check */
	if ( ll_protocol->ll_proto != htons ( ARPHRD_ETHER ) ) {
		/* Not an error; simply skip this net device */
		DBG ( "FCoE skipping non-Ethernet device %s\n", netdev->name );
		rc = 0;
		goto err_non_ethernet;
	}

	/* Allocate and initialise structure */
	fcoe = zalloc ( sizeof ( *fcoe ) );
	if ( ! fcoe ) {
		rc = -ENOMEM;
		goto err_zalloc;
	}
	ref_init ( &fcoe->refcnt, NULL );
	intf_init ( &fcoe->transport, &fcoe_transport_desc, &fcoe->refcnt );
	timer_init ( &fcoe->timer, fcoe_expired, &fcoe->refcnt );
	fcoe->netdev = netdev_get ( netdev );

	/* Construct node and port names */
	fcoe->node_wwn.fcoe.authority = htons ( FCOE_AUTHORITY_IEEE );
	memcpy ( &fcoe->node_wwn.fcoe.mac, netdev->ll_addr,
		 sizeof ( fcoe->node_wwn.fcoe.mac ) );
	fcoe->port_wwn.fcoe.authority = htons ( FCOE_AUTHORITY_IEEE_EXTENDED );
	memcpy ( &fcoe->port_wwn.fcoe.mac, netdev->ll_addr,
		 sizeof ( fcoe->port_wwn.fcoe.mac ) );

	DBGC ( fcoe, "FCoE %s is %s", fcoe->netdev->name,
	       fc_ntoa ( &fcoe->node_wwn.fc ) );
	DBGC ( fcoe, " port %s\n", fc_ntoa ( &fcoe->port_wwn.fc ) );

	/* Transfer reference to port list */
	list_add ( &fcoe->list, &fcoe_ports );
	return 0;

	netdev_put ( fcoe->netdev );
 err_zalloc:
 err_non_ethernet:
	return rc;
}

/**
 * Handle FCoE port device or link state change
 *
 * @v netdev		Network device
 */
static void fcoe_notify ( struct net_device *netdev ) {
	struct fcoe_port *fcoe;

	/* Sanity check */
	if ( ( fcoe = fcoe_demux ( netdev ) ) == NULL ) {
		DBG ( "FCoE notification for net device %s missing FCoE "
		      "port\n", netdev->name );
		return;
	}

	/* Reset the FCoE link if necessary */
	if ( ! ( netdev_is_open ( netdev ) &&
		 netdev_link_ok ( netdev ) &&
		 ( fcoe->flags & FCOE_HAVE_NETWORK ) ) ) {
		fcoe_reset ( fcoe );
	}
}

/**
 * Destroy FCoE port
 *
 * @v netdev		Network device
 */
static void fcoe_remove ( struct net_device *netdev ) {
	struct fcoe_port *fcoe;

	/* Sanity check */
	if ( ( fcoe = fcoe_demux ( netdev ) ) == NULL ) {
		DBG ( "FCoE removal of net device %s missing FCoE port\n",
		      netdev->name );
		return;
	}

	/* Close FCoE device */
	fcoe_close ( fcoe, 0 );
}

/** FCoE driver */
struct net_driver fcoe_driver __net_driver = {
	.name = "FCoE",
	.probe = fcoe_probe,
	.notify = fcoe_notify,
	.remove = fcoe_remove,
};

/** FCoE protocol */
struct net_protocol fcoe_protocol __net_protocol = {
	.name = "FCoE",
	.net_proto = htons ( ETH_P_FCOE ),
	.rx = fcoe_rx,
};

/** FIP protocol */
struct net_protocol fip_protocol __net_protocol = {
	.name = "FIP",
	.net_proto = htons ( ETH_P_FIP ),
	.rx = fcoe_fip_rx,
};

/** Human-readable message for CRC errors
 *
 * It seems as though several drivers neglect to strip the Ethernet
 * CRC, which will cause the FCoE footer to be misplaced and result
 * (coincidentally) in an "invalid CRC" error from FCoE.
 */
struct errortab fcoe_errors[] __errortab = {
	__einfo_errortab ( EINFO_EINVAL_CRC ),
};
