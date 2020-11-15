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

#include <stdlib.h>
#include <string.h>
#include <byteswap.h>
#include <errno.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/eth_slow.h>

/** @file
 *
 * Ethernet slow protocols
 *
 * We implement a very simple passive LACP entity, that pretends that
 * each port is the only port on an individual system.  We avoid the
 * need for timeout logic (and retaining local state about our
 * partner) by requesting the same timeout period (1s or 30s) as our
 * partner requests, and then simply responding to every packet the
 * partner sends us.
 */

struct net_protocol eth_slow_protocol __net_protocol;

/** Slow protocols multicast address */
static const uint8_t eth_slow_address[ETH_ALEN] =
	{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x02 };

/**
 * Name LACP TLV type
 *
 * @v type		LACP TLV type
 * @ret name		Name of LACP TLV type
 */
static inline __attribute__ (( always_inline )) const char *
eth_slow_lacp_tlv_name ( uint8_t type ) {
	switch ( type ) {
	case ETH_SLOW_TLV_TERMINATOR:		return "terminator";
	case ETH_SLOW_TLV_LACP_ACTOR:		return "actor";
	case ETH_SLOW_TLV_LACP_PARTNER:		return "partner";
	case ETH_SLOW_TLV_LACP_COLLECTOR:	return "collector";
	default:				return "<invalid>";
	}
}

/**
 * Name marker TLV type
 *
 * @v type		Marker TLV type
 * @ret name		Name of marker TLV type
 */
static inline __attribute__ (( always_inline )) const char *
eth_slow_marker_tlv_name ( uint8_t type ) {
	switch ( type ) {
	case ETH_SLOW_TLV_TERMINATOR:		return "terminator";
	case ETH_SLOW_TLV_MARKER_REQUEST:	return "request";
	case ETH_SLOW_TLV_MARKER_RESPONSE:	return "response";
	default:				return "<invalid>";
	}
}

/**
 * Name LACP state
 *
 * @v state		LACP state
 * @ret name		LACP state name
 */
static const char * eth_slow_lacp_state_name ( uint8_t state ) {
	static char state_chars[] = "AFGSRTLX";
	unsigned int i;

	for ( i = 0 ; i < 8 ; i++ ) {
		state_chars[i] |= 0x20;
		if ( state & ( 1 << i ) )
			state_chars[i] &= ~0x20;
	}
	return state_chars;
}

/**
 * Dump LACP packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v label		"RX" or "TX"
 */
static void eth_slow_lacp_dump ( struct io_buffer *iobuf,
				 struct net_device *netdev,
				 const char *label ) {
	union eth_slow_packet *eth_slow = iobuf->data;
	struct eth_slow_lacp *lacp = &eth_slow->lacp;

	DBGC ( netdev,
	       "SLOW %s %s LACP actor (%04x,%s,%04x,%02x,%04x) [%s]\n",
	       netdev->name, label, ntohs ( lacp->actor.system_priority ),
	       eth_ntoa ( lacp->actor.system ),
	       ntohs ( lacp->actor.key ),
	       ntohs ( lacp->actor.port_priority ),
	       ntohs ( lacp->actor.port ),
	       eth_slow_lacp_state_name ( lacp->actor.state ) );
	DBGC ( netdev,
	       "SLOW %s %s LACP partner (%04x,%s,%04x,%02x,%04x) [%s]\n",
	       netdev->name, label, ntohs ( lacp->partner.system_priority ),
	       eth_ntoa ( lacp->partner.system ),
	       ntohs ( lacp->partner.key ),
	       ntohs ( lacp->partner.port_priority ),
	       ntohs ( lacp->partner.port ),
	       eth_slow_lacp_state_name ( lacp->partner.state ) );
	DBGC ( netdev, "SLOW %s %s LACP collector %04x (%d us)\n",
	       netdev->name, label, ntohs ( lacp->collector.max_delay ),
	       ( ntohs ( lacp->collector.max_delay ) * 10 ) );
	DBGC2_HDA ( netdev, 0, iobuf->data, iob_len ( iobuf ) );
}

/**
 * Process incoming LACP packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int eth_slow_lacp_rx ( struct io_buffer *iobuf,
			      struct net_device *netdev ) {
	union eth_slow_packet *eth_slow = iobuf->data;
	struct eth_slow_lacp *lacp = &eth_slow->lacp;

	eth_slow_lacp_dump ( iobuf, netdev, "RX" );

	/* Build response */
	memset ( lacp->reserved, 0, sizeof ( lacp->reserved ) );
	memset ( &lacp->terminator, 0, sizeof ( lacp->terminator ) );
	memset ( &lacp->collector, 0, sizeof ( lacp->collector ) );
	lacp->collector.tlv.type = ETH_SLOW_TLV_LACP_COLLECTOR;
	lacp->collector.tlv.length = ETH_SLOW_TLV_LACP_COLLECTOR_LEN;
	memcpy ( &lacp->partner, &lacp->actor, sizeof ( lacp->partner ) );
	lacp->partner.tlv.type = ETH_SLOW_TLV_LACP_PARTNER;
	lacp->partner.tlv.length = ETH_SLOW_TLV_LACP_PARTNER_LEN;
	memset ( &lacp->partner.reserved, 0,
		 sizeof ( lacp->partner.reserved ) );
	memset ( &lacp->actor, 0, sizeof ( lacp->actor ) );
	lacp->actor.tlv.type = ETH_SLOW_TLV_LACP_ACTOR;
	lacp->actor.tlv.length = ETH_SLOW_TLV_LACP_ACTOR_LEN;
	lacp->actor.system_priority = htons ( LACP_SYSTEM_PRIORITY_MAX );
	memcpy ( lacp->actor.system, netdev->ll_addr,
		 sizeof ( lacp->actor.system ) );
	lacp->actor.key = htons ( 1 );
	lacp->actor.port_priority = htons ( LACP_PORT_PRIORITY_MAX );
	lacp->actor.port = htons ( 1 );
	lacp->actor.state = ( LACP_STATE_AGGREGATABLE |
			      LACP_STATE_IN_SYNC |
			      LACP_STATE_COLLECTING |
			      LACP_STATE_DISTRIBUTING |
			      ( lacp->partner.state & LACP_STATE_FAST ) );
	lacp->header.version = ETH_SLOW_LACP_VERSION;

	/* Send response */
	eth_slow_lacp_dump ( iobuf, netdev, "TX" );
	return net_tx ( iobuf, netdev, &eth_slow_protocol, eth_slow_address,
			netdev->ll_addr );
}

/**
 * Dump marker packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v label		"RX" or "TX"
 */
static void eth_slow_marker_dump ( struct io_buffer *iobuf,
				   struct net_device *netdev,
				   const char *label ) {
	union eth_slow_packet *eth_slow = iobuf->data;
	struct eth_slow_marker *marker = &eth_slow->marker;

	DBGC ( netdev, "SLOW %s %s marker %s port %04x system %s xact %08x\n",
	       netdev->name, label,
	       eth_slow_marker_tlv_name ( marker->marker.tlv.type ),
	       ntohs ( marker->marker.port ),
	       eth_ntoa ( marker->marker.system ),
	       ntohl ( marker->marker.xact ) );
	DBGC2_HDA ( netdev, 0, iobuf->data, iob_len ( iobuf ) );
}

/**
 * Process incoming marker packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int eth_slow_marker_rx ( struct io_buffer *iobuf,
				struct net_device *netdev ) {
	union eth_slow_packet *eth_slow = iobuf->data;
	struct eth_slow_marker *marker = &eth_slow->marker;

	eth_slow_marker_dump ( iobuf, netdev, "RX" );

	if ( marker->marker.tlv.type == ETH_SLOW_TLV_MARKER_REQUEST ) {
		/* Send marker response */
		marker->marker.tlv.type = ETH_SLOW_TLV_MARKER_RESPONSE;
		eth_slow_marker_dump ( iobuf, netdev, "TX" );
		return net_tx ( iobuf, netdev, &eth_slow_protocol,
				eth_slow_address, netdev->ll_addr );
	} else {
		/* Discard all other marker packets */
		free_iob ( iobuf );
		return -EINVAL;
	}
}

/**
 * Process incoming slow packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v ll_dest		Link-layer destination address
 * @v ll_source		Link-layer source address
 * @v flags		Packet flags
 * @ret rc		Return status code
 */
static int eth_slow_rx ( struct io_buffer *iobuf,
			 struct net_device *netdev,
			 const void *ll_dest __unused,
			 const void *ll_source __unused,
			 unsigned int flags __unused ) {
	union eth_slow_packet *eth_slow = iobuf->data;

	/* Sanity checks */
	if ( iob_len ( iobuf ) < sizeof ( *eth_slow ) ) {
		free_iob ( iobuf );
		return -EINVAL;
	}

	/* Handle according to subtype */
	switch ( eth_slow->header.subtype ) {
	case ETH_SLOW_SUBTYPE_LACP:
		return eth_slow_lacp_rx ( iobuf, netdev );
	case ETH_SLOW_SUBTYPE_MARKER:
		return eth_slow_marker_rx ( iobuf, netdev );
	default:
		DBGC ( netdev, "SLOW %s RX unknown subtype %02x\n",
		       netdev->name, eth_slow->header.subtype );
		free_iob ( iobuf );
		return -EINVAL;
	}
}

/** Slow protocol */
struct net_protocol eth_slow_protocol __net_protocol = {
	.name = "Slow",
	.net_proto = htons ( ETH_P_SLOW ),
	.rx = eth_slow_rx,
};
