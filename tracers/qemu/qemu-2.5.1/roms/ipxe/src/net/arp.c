/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <byteswap.h>
#include <errno.h>
#include <ipxe/if_ether.h>
#include <ipxe/if_arp.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/neighbour.h>
#include <ipxe/arp.h>

/** @file
 *
 * Address Resolution Protocol
 *
 * This file implements the address resolution protocol as defined in
 * RFC826.  The implementation is media-independent and
 * protocol-independent; it is not limited to Ethernet or to IPv4.
 *
 */

struct net_protocol arp_protocol __net_protocol;

/**
 * Transmit ARP request
 *
 * @v netdev		Network device
 * @v net_protocol	Network-layer protocol
 * @v net_dest		Destination network-layer address
 * @v net_source	Source network-layer address
 * @ret rc		Return status code
 */
int arp_tx_request ( struct net_device *netdev,
		     struct net_protocol *net_protocol,
		     const void *net_dest, const void *net_source ) {
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	struct io_buffer *iobuf;
	struct arphdr *arphdr;
	int rc;

	/* Allocate ARP packet */
	iobuf = alloc_iob ( MAX_LL_HEADER_LEN + sizeof ( *arphdr ) +
			    ( 2 * ( MAX_LL_ADDR_LEN + MAX_NET_ADDR_LEN ) ) );
	if ( ! iobuf )
		return -ENOMEM;
	iob_reserve ( iobuf, MAX_LL_HEADER_LEN );

	/* Build up ARP request */
	arphdr = iob_put ( iobuf, sizeof ( *arphdr ) );
	arphdr->ar_hrd = ll_protocol->ll_proto;
	arphdr->ar_hln = ll_protocol->ll_addr_len;
	arphdr->ar_pro = net_protocol->net_proto;
	arphdr->ar_pln = net_protocol->net_addr_len;
	arphdr->ar_op = htons ( ARPOP_REQUEST );
	memcpy ( iob_put ( iobuf, ll_protocol->ll_addr_len ),
		 netdev->ll_addr, ll_protocol->ll_addr_len );
	memcpy ( iob_put ( iobuf, net_protocol->net_addr_len ),
		 net_source, net_protocol->net_addr_len );
	memset ( iob_put ( iobuf, ll_protocol->ll_addr_len ),
		 0, ll_protocol->ll_addr_len );
	memcpy ( iob_put ( iobuf, net_protocol->net_addr_len ),
		 net_dest, net_protocol->net_addr_len );

	/* Transmit ARP request */
	if ( ( rc = net_tx ( iobuf, netdev, &arp_protocol,
			     netdev->ll_broadcast, netdev->ll_addr ) ) != 0 ) {
		DBGC ( netdev, "ARP %s %s %s could not transmit request: %s\n",
		       netdev->name, net_protocol->name,
		       net_protocol->ntoa ( net_dest ), strerror ( rc ) );
		return rc;
	}

	return 0;
}

/** ARP neighbour discovery protocol */
struct neighbour_discovery arp_discovery = {
	.name = "ARP",
	.tx_request = arp_tx_request,
};

/**
 * Identify ARP protocol
 *
 * @v net_proto			Network-layer protocol, in network-endian order
 * @ret arp_net_protocol	ARP protocol, or NULL
 *
 */
static struct arp_net_protocol * arp_find_protocol ( uint16_t net_proto ) {
	struct arp_net_protocol *arp_net_protocol;

	for_each_table_entry ( arp_net_protocol, ARP_NET_PROTOCOLS ) {
		if ( arp_net_protocol->net_protocol->net_proto == net_proto )
			return arp_net_protocol;
	}
	return NULL;
}

/**
 * Process incoming ARP packets
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v ll_source		Link-layer source address
 * @v flags		Packet flags
 * @ret rc		Return status code
 */
static int arp_rx ( struct io_buffer *iobuf, struct net_device *netdev,
		    const void *ll_dest __unused,
		    const void *ll_source __unused,
		    unsigned int flags __unused ) {
	struct arphdr *arphdr = iobuf->data;
	struct arp_net_protocol *arp_net_protocol;
	struct net_protocol *net_protocol;
	struct ll_protocol *ll_protocol;
	int rc;

	/* Identify network-layer and link-layer protocols */
	arp_net_protocol = arp_find_protocol ( arphdr->ar_pro );
	if ( ! arp_net_protocol ) {
		rc = -EPROTONOSUPPORT;
		goto done;
	}
	net_protocol = arp_net_protocol->net_protocol;
	ll_protocol = netdev->ll_protocol;

	/* Sanity checks */
	if ( ( arphdr->ar_hrd != ll_protocol->ll_proto ) ||
	     ( arphdr->ar_hln != ll_protocol->ll_addr_len ) ||
	     ( arphdr->ar_pln != net_protocol->net_addr_len ) ) {
		rc = -EINVAL;
		goto done;
	}

	/* Update neighbour cache entry for this sender, if any */
	neighbour_update ( netdev, net_protocol, arp_sender_pa ( arphdr ),
			   arp_sender_ha ( arphdr ) );

	/* If it's not a request, there's nothing more to do */
	if ( arphdr->ar_op != htons ( ARPOP_REQUEST ) ) {
		rc = 0;
		goto done;
	}

	/* See if we own the target protocol address */
	if ( arp_net_protocol->check ( netdev, arp_target_pa ( arphdr ) ) != 0){
		rc = 0;
		goto done;
	}

	/* Change request to a reply */
	DBGC2 ( netdev, "ARP %s %s %s reply => %s %s\n",
		netdev->name, net_protocol->name,
		net_protocol->ntoa ( arp_target_pa ( arphdr ) ),
		ll_protocol->name, ll_protocol->ntoa ( netdev->ll_addr ) );
	arphdr->ar_op = htons ( ARPOP_REPLY );
	memswap ( arp_sender_ha ( arphdr ), arp_target_ha ( arphdr ),
		 arphdr->ar_hln + arphdr->ar_pln );
	memcpy ( arp_sender_ha ( arphdr ), netdev->ll_addr, arphdr->ar_hln );

	/* Send reply */
	if ( ( rc = net_tx ( iob_disown ( iobuf ), netdev, &arp_protocol,
			     arp_target_ha ( arphdr ),
			     netdev->ll_addr ) ) != 0 ) {
		DBGC ( netdev, "ARP %s %s %s could not transmit reply: %s\n",
		       netdev->name, net_protocol->name,
		       net_protocol->ntoa ( arp_target_pa ( arphdr ) ),
		       strerror ( rc ) );
		goto done;
	}

	/* Success */
	rc = 0;

 done:
	free_iob ( iobuf );
	return rc;
}

/**
 * Transcribe ARP address
 *
 * @v net_addr	ARP address
 * @ret string	"<ARP>"
 *
 * This operation is meaningless for the ARP protocol.
 */
static const char * arp_ntoa ( const void *net_addr __unused ) {
	return "<ARP>";
}

/** ARP network protocol */
struct net_protocol arp_protocol __net_protocol = {
	.name = "ARP",
	.net_proto = htons ( ETH_P_ARP ),
	.rx = arp_rx,
	.ntoa = arp_ntoa,
};
