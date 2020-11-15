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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <byteswap.h>
#include <errno.h>
#include <ipxe/errortab.h>
#include <ipxe/malloc.h>
#include <ipxe/if_arp.h>
#include <ipxe/arp.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/ip.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/infiniband.h>
#include <ipxe/ib_pathrec.h>
#include <ipxe/ib_mcast.h>
#include <ipxe/retry.h>
#include <ipxe/ipoib.h>

/** @file
 *
 * IP over Infiniband
 */

/* Disambiguate the various error causes */
#define ENXIO_ARP_REPLY __einfo_error ( EINFO_ENXIO_ARP_REPLY )
#define EINFO_ENXIO_ARP_REPLY						\
	__einfo_uniqify ( EINFO_ENXIO, 0x01,				\
			  "Missing REMAC for ARP reply target address" )
#define ENXIO_NON_IPV4 __einfo_error ( EINFO_ENXIO_NON_IPV4 )
#define EINFO_ENXIO_NON_IPV4						\
	__einfo_uniqify ( EINFO_ENXIO, 0x02,				\
			  "Missing REMAC for non-IPv4 packet" )
#define ENXIO_ARP_SENT __einfo_error ( EINFO_ENXIO_ARP_SENT )
#define EINFO_ENXIO_ARP_SENT						\
	__einfo_uniqify ( EINFO_ENXIO, 0x03,				\
			  "Missing REMAC for IPv4 packet (ARP sent)" )

/** Number of IPoIB send work queue entries */
#define IPOIB_NUM_SEND_WQES 2

/** Number of IPoIB receive work queue entries */
#define IPOIB_NUM_RECV_WQES 4

/** Number of IPoIB completion entries */
#define IPOIB_NUM_CQES 8

/** An IPoIB device */
struct ipoib_device {
	/** Network device */
	struct net_device *netdev;
	/** Underlying Infiniband device */
	struct ib_device *ibdev;
	/** Completion queue */
	struct ib_completion_queue *cq;
	/** Queue pair */
	struct ib_queue_pair *qp;
	/** Local MAC */
	struct ipoib_mac mac;
	/** Broadcast MAC */
	struct ipoib_mac broadcast;
	/** Joined to IPv4 broadcast multicast group
	 *
	 * This flag indicates whether or not we have initiated the
	 * join to the IPv4 broadcast multicast group.
	 */
	int broadcast_joined;
	/** IPv4 broadcast multicast group membership */
	struct ib_mc_membership broadcast_membership;
	/** REMAC cache */
	struct list_head peers;
};

/** Broadcast IPoIB address */
static struct ipoib_mac ipoib_broadcast = {
	.flags__qpn = htonl ( IB_QPN_BROADCAST ),
	.gid.bytes = { 0xff, 0x12, 0x40, 0x1b, 0x00, 0x00, 0x00, 0x00,
		       0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff },
};

/** Link status for "broadcast join in progress" */
#define EINPROGRESS_JOINING __einfo_error ( EINFO_EINPROGRESS_JOINING )
#define EINFO_EINPROGRESS_JOINING __einfo_uniqify \
	( EINFO_EINPROGRESS, 0x01, "Joining" )

/** Human-readable message for the link status */
struct errortab ipoib_errors[] __errortab = {
	__einfo_errortab ( EINFO_EINPROGRESS_JOINING ),
};

static struct net_device_operations ipoib_operations;

/****************************************************************************
 *
 * IPoIB REMAC cache
 *
 ****************************************************************************
 */

/** An IPoIB REMAC cache entry */
struct ipoib_peer {
	/** List of REMAC cache entries */
	struct list_head list;
	/** Remote Ethermet MAC */
	struct ipoib_remac remac;
	/** MAC address */
	struct ipoib_mac mac;
};

/**
 * Find IPoIB MAC from REMAC
 *
 * @v ipoib		IPoIB device
 * @v remac		Remote Ethernet MAC
 * @ret mac		IPoIB MAC (or NULL if not found)
 */
static struct ipoib_mac * ipoib_find_remac ( struct ipoib_device *ipoib,
					     const struct ipoib_remac *remac ) {
	struct ipoib_peer *peer;

	/* Check for broadcast or multicast REMAC.  We transmit
	 * multicasts as broadcasts for simplicity.
	 */
	if ( is_multicast_ether_addr ( remac ) )
		return &ipoib->broadcast;

	/* Try to find via REMAC cache */
	list_for_each_entry ( peer, &ipoib->peers, list ) {
		if ( memcmp ( remac, &peer->remac,
			      sizeof ( peer->remac ) ) == 0 ) {
			/* Move peer to start of list */
			list_del ( &peer->list );
			list_add ( &peer->list, &ipoib->peers );
			return &peer->mac;
		}
	}

	DBGC ( ipoib, "IPoIB %p unknown REMAC %s\n",
	       ipoib, eth_ntoa ( remac ) );
	return NULL;
}

/**
 * Add IPoIB MAC to REMAC cache
 *
 * @v ipoib		IPoIB device
 * @v remac		Remote Ethernet MAC
 * @v mac		IPoIB MAC
 * @ret rc		Return status code
 */
static int ipoib_map_remac ( struct ipoib_device *ipoib,
			     const struct ipoib_remac *remac,
			     const struct ipoib_mac *mac ) {
	struct ipoib_peer *peer;

	/* Check for existing entry in REMAC cache */
	list_for_each_entry ( peer, &ipoib->peers, list ) {
		if ( memcmp ( remac, &peer->remac,
			      sizeof ( peer->remac ) ) == 0 ) {
			/* Move peer to start of list */
			list_del ( &peer->list );
			list_add ( &peer->list, &ipoib->peers );
			/* Update MAC */
			memcpy ( &peer->mac, mac, sizeof ( peer->mac ) );
			return 0;
		}
	}

	/* Create new entry */
	peer = malloc ( sizeof ( *peer ) );
	if ( ! peer )
		return -ENOMEM;
	memcpy ( &peer->remac, remac, sizeof ( peer->remac ) );
	memcpy ( &peer->mac, mac, sizeof ( peer->mac ) );
	list_add ( &peer->list, &ipoib->peers );

	return 0;
}

/**
 * Flush REMAC cache
 *
 * @v ipoib		IPoIB device
 */
static void ipoib_flush_remac ( struct ipoib_device *ipoib ) {
	struct ipoib_peer *peer;
	struct ipoib_peer *tmp;

	list_for_each_entry_safe ( peer, tmp, &ipoib->peers, list ) {
		list_del ( &peer->list );
		free ( peer );
	}
}

/**
 * Discard some entries from the REMAC cache
 *
 * @ret discarded	Number of cached items discarded
 */
static unsigned int ipoib_discard_remac ( void ) {
	struct net_device *netdev;
	struct ipoib_device *ipoib;
	struct ipoib_peer *peer;
	unsigned int discarded = 0;

	/* Try to discard one cache entry for each IPoIB device */
	for_each_netdev ( netdev ) {

		/* Skip non-IPoIB devices */
		if ( netdev->op != &ipoib_operations )
			continue;
		ipoib = netdev->priv;

		/* Discard least recently used cache entry (if any) */
		list_for_each_entry_reverse ( peer, &ipoib->peers, list ) {
			list_del ( &peer->list );
			free ( peer );
			discarded++;
			break;
		}
	}

	return discarded;
}

/** IPoIB cache discarder */
struct cache_discarder ipoib_discarder __cache_discarder ( CACHE_EXPENSIVE ) = {
	.discard = ipoib_discard_remac,
};

/****************************************************************************
 *
 * IPoIB link layer
 *
 ****************************************************************************
 */

/**
 * Initialise IPoIB link-layer address
 *
 * @v hw_addr		Hardware address
 * @v ll_addr		Link-layer address
 */
static void ipoib_init_addr ( const void *hw_addr, void *ll_addr ) {
	const uint8_t *guid = hw_addr;
	uint8_t *eth_addr = ll_addr;
	uint8_t guid_mask = IPOIB_GUID_MASK;
	unsigned int i;

	/* Extract bytes from GUID according to mask */
	for ( i = 0 ; i < 8 ; i++, guid++, guid_mask <<= 1 ) {
		if ( guid_mask & 0x80 )
			*(eth_addr++) = *guid;
	}
}

/** IPoIB protocol */
struct ll_protocol ipoib_protocol __ll_protocol = {
	.name		= "IPoIB",
	.ll_proto	= htons ( ARPHRD_ETHER ),
	.hw_addr_len	= sizeof ( union ib_guid ),
	.ll_addr_len	= ETH_ALEN,
	.ll_header_len	= ETH_HLEN,
	.push		= eth_push,
	.pull		= eth_pull,
	.init_addr	= ipoib_init_addr,
	.ntoa		= eth_ntoa,
	.mc_hash	= eth_mc_hash,
	.eth_addr	= eth_eth_addr,
	.eui64		= eth_eui64,
	.flags		= LL_NAME_ONLY,
};

/**
 * Allocate IPoIB device
 *
 * @v priv_size		Size of driver private data
 * @ret netdev		Network device, or NULL
 */
struct net_device * alloc_ipoibdev ( size_t priv_size ) {
	struct net_device *netdev;

	netdev = alloc_netdev ( priv_size );
	if ( netdev ) {
		netdev->ll_protocol = &ipoib_protocol;
		netdev->ll_broadcast = eth_broadcast;
		netdev->max_pkt_len = IB_MAX_PAYLOAD_SIZE;
	}
	return netdev;
}

/****************************************************************************
 *
 * IPoIB translation layer
 *
 ****************************************************************************
 */

/**
 * Translate transmitted ARP packet
 *
 * @v netdev		Network device
 * @v iobuf		Packet to be transmitted (with no link-layer headers)
 * @ret rc		Return status code
 */
static int ipoib_translate_tx_arp ( struct net_device *netdev,
				    struct io_buffer *iobuf ) {
	struct ipoib_device *ipoib = netdev->priv;
	struct arphdr *arphdr = iobuf->data;
	struct ipoib_mac *target_ha = NULL;
	void *sender_pa;
	void *target_pa;

	/* Do nothing unless ARP contains eIPoIB link-layer addresses */
	if ( arphdr->ar_hln != ETH_ALEN )
		return 0;

	/* Fail unless we have room to expand packet */
	if ( iob_tailroom ( iobuf ) < ( 2 * ( sizeof ( ipoib->mac ) -
					      ETH_ALEN ) ) ) {
		DBGC ( ipoib, "IPoIB %p insufficient space in TX ARP\n",
		       ipoib );
		return -ENOBUFS;
	}

	/* Look up REMAC, if applicable */
	if ( arphdr->ar_op == ARPOP_REPLY ) {
		target_ha = ipoib_find_remac ( ipoib, arp_target_pa ( arphdr ));
		if ( ! target_ha ) {
			DBGC ( ipoib, "IPoIB %p no REMAC for %s ARP reply\n",
			       ipoib, eth_ntoa ( arp_target_pa ( arphdr ) ) );
			return -ENXIO_ARP_REPLY;
		}
	}

	/* Construct new packet */
	iob_put ( iobuf, ( 2 * ( sizeof ( ipoib->mac ) - ETH_ALEN ) ) );
	sender_pa = arp_sender_pa ( arphdr );
	target_pa = arp_target_pa ( arphdr );
	arphdr->ar_hrd = htons ( ARPHRD_INFINIBAND );
	arphdr->ar_hln = sizeof ( ipoib->mac );
	memcpy ( arp_target_pa ( arphdr ), target_pa, arphdr->ar_pln );
	memcpy ( arp_sender_pa ( arphdr ), sender_pa, arphdr->ar_pln );
	memcpy ( arp_sender_ha ( arphdr ), &ipoib->mac, sizeof ( ipoib->mac ) );
	memset ( arp_target_ha ( arphdr ), 0, sizeof ( ipoib->mac ) );
	if ( target_ha ) {
		memcpy ( arp_target_ha ( arphdr ), target_ha,
			 sizeof ( *target_ha ) );
	}

	return 0;
}

/**
 * Translate transmitted packet
 *
 * @v netdev		Network device
 * @v iobuf		Packet to be transmitted (with no link-layer headers)
 * @v net_proto		Network-layer protocol (in network byte order)
 * @ret rc		Return status code
 */
static int ipoib_translate_tx ( struct net_device *netdev,
				struct io_buffer *iobuf, uint16_t net_proto ) {

	switch ( net_proto ) {
	case htons ( ETH_P_ARP ) :
		return ipoib_translate_tx_arp ( netdev, iobuf );
	case htons ( ETH_P_IP ) :
		/* No translation needed */
		return 0;
	default:
		/* Cannot handle other traffic via eIPoIB */
		return -ENOTSUP;
	}
}

/**
 * Translate received ARP packet
 *
 * @v netdev		Network device
 * @v iobuf		Received packet (with no link-layer headers)
 * @v remac		Constructed Remote Ethernet MAC
 * @ret rc		Return status code
 */
static int ipoib_translate_rx_arp ( struct net_device *netdev,
				    struct io_buffer *iobuf,
				    struct ipoib_remac *remac ) {
	struct ipoib_device *ipoib = netdev->priv;
	struct arphdr *arphdr = iobuf->data;
	void *sender_pa;
	void *target_pa;
	int rc;

	/* Do nothing unless ARP contains IPoIB link-layer addresses */
	if ( arphdr->ar_hln != sizeof ( ipoib->mac ) )
		return 0;

	/* Create REMAC cache entry */
	if ( ( rc = ipoib_map_remac ( ipoib, remac,
				      arp_sender_ha ( arphdr ) ) ) != 0 ) {
		DBGC ( ipoib, "IPoIB %p could not map REMAC: %s\n",
		       ipoib, strerror ( rc ) );
		return rc;
	}

	/* Construct new packet */
	sender_pa = arp_sender_pa ( arphdr );
	target_pa = arp_target_pa ( arphdr );
	arphdr->ar_hrd = htons ( ARPHRD_ETHER );
	arphdr->ar_hln = ETH_ALEN;
	memcpy ( arp_sender_pa ( arphdr ), sender_pa, arphdr->ar_pln );
	memcpy ( arp_target_pa ( arphdr ), target_pa, arphdr->ar_pln );
	memcpy ( arp_sender_ha ( arphdr ), remac, ETH_ALEN );
	memset ( arp_target_ha ( arphdr ), 0, ETH_ALEN );
	if ( arphdr->ar_op == ARPOP_REPLY ) {
		/* Assume received replies were directed to us */
		memcpy ( arp_target_ha ( arphdr ), netdev->ll_addr, ETH_ALEN );
	}
	iob_unput ( iobuf, ( 2 * ( sizeof ( ipoib->mac ) - ETH_ALEN ) ) );

	return 0;
}

/**
 * Translate received packet
 *
 * @v netdev		Network device
 * @v iobuf		Received packet (with no link-layer headers)
 * @v remac		Constructed Remote Ethernet MAC
 * @v net_proto		Network-layer protocol (in network byte order)
 * @ret rc		Return status code
 */
static int ipoib_translate_rx ( struct net_device *netdev,
				struct io_buffer *iobuf,
				struct ipoib_remac *remac,
				uint16_t net_proto ) {

	switch ( net_proto ) {
	case htons ( ETH_P_ARP ) :
		return ipoib_translate_rx_arp ( netdev, iobuf, remac );
	case htons ( ETH_P_IP ) :
		/* No translation needed */
		return 0;
	default:
		/* Cannot handle other traffic via eIPoIB */
		return -ENOTSUP;
	}
}

/****************************************************************************
 *
 * IPoIB network device
 *
 ****************************************************************************
 */

/**
 * Transmit packet via IPoIB network device
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int ipoib_transmit ( struct net_device *netdev,
			    struct io_buffer *iobuf ) {
	struct ipoib_device *ipoib = netdev->priv;
	struct ib_device *ibdev = ipoib->ibdev;
	struct ethhdr *ethhdr;
	struct iphdr *iphdr;
	struct ipoib_hdr *ipoib_hdr;
	struct ipoib_mac *mac;
	struct ib_address_vector dest;
	uint16_t net_proto;
	int rc;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *ethhdr ) ) {
		DBGC ( ipoib, "IPoIB %p buffer too short\n", ipoib );
		return -EINVAL;
	}

	/* Attempting transmission while link is down will put the
	 * queue pair into an error state, so don't try it.
	 */
	if ( ! ib_link_ok ( ibdev ) )
		return -ENETUNREACH;

	/* Strip eIPoIB header */
	ethhdr = iobuf->data;
	net_proto = ethhdr->h_protocol;
	iob_pull ( iobuf, sizeof ( *ethhdr ) );

	/* Identify destination address */
	mac = ipoib_find_remac ( ipoib, ( ( void * ) ethhdr->h_dest ) );
	if ( ! mac ) {
		/* Generate a new ARP request (if possible) to trigger
		 * population of the REMAC cache entry.
		 */
		if ( ( net_proto != htons ( ETH_P_IP ) ) ||
		     ( iob_len ( iobuf ) < sizeof ( *iphdr ) ) ) {
			DBGC ( ipoib, "IPoIB %p no REMAC for %s non-IPv4 "
			       "packet type %04x\n", ipoib,
			       eth_ntoa ( ethhdr->h_dest ),
			       ntohs ( net_proto ) );
			return -ENXIO_NON_IPV4;
		}
		iphdr = iobuf->data;
		if ( ( rc = arp_tx_request ( netdev, &ipv4_protocol,
					     &iphdr->dest, &iphdr->src ) ) !=0){
			DBGC ( ipoib, "IPoIB %p could not ARP for %s/%s/",
			       ipoib, eth_ntoa ( ethhdr->h_dest ),
			       inet_ntoa ( iphdr->dest ) );
			DBGC ( ipoib, "%s: %s\n", inet_ntoa ( iphdr->src ),
			       strerror ( rc ) );
			return rc;
		}
		DBGC ( ipoib, "IPoIB %p no REMAC for %s/%s/", ipoib,
		       eth_ntoa ( ethhdr->h_dest ), inet_ntoa ( iphdr->dest ) );
		DBGC  ( ipoib, "%s\n", inet_ntoa ( iphdr->src ) );
		return -ENXIO_ARP_SENT;
	}

	/* Translate packet if applicable */
	if ( ( rc = ipoib_translate_tx ( netdev, iobuf, net_proto ) ) != 0 )
		return rc;

	/* Prepend real IPoIB header */
	ipoib_hdr = iob_push ( iobuf, sizeof ( *ipoib_hdr ) );
	ipoib_hdr->proto = net_proto;
	ipoib_hdr->reserved = 0;

	/* Construct address vector */
	memset ( &dest, 0, sizeof ( dest ) );
	dest.qpn = ( ntohl ( mac->flags__qpn ) & IB_QPN_MASK );
	dest.gid_present = 1;
	memcpy ( &dest.gid, &mac->gid, sizeof ( dest.gid ) );
	if ( ( rc = ib_resolve_path ( ibdev, &dest ) ) != 0 ) {
		/* Path not resolved yet */
		return rc;
	}

	return ib_post_send ( ibdev, ipoib->qp, &dest, iobuf );
}

/**
 * Handle IPoIB send completion
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void ipoib_complete_send ( struct ib_device *ibdev __unused,
				  struct ib_queue_pair *qp,
				  struct io_buffer *iobuf, int rc ) {
	struct ipoib_device *ipoib = ib_qp_get_ownerdata ( qp );

	netdev_tx_complete_err ( ipoib->netdev, iobuf, rc );
}

/**
 * Handle IPoIB receive completion
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v dest		Destination address vector, or NULL
 * @v source		Source address vector, or NULL
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void ipoib_complete_recv ( struct ib_device *ibdev __unused,
				  struct ib_queue_pair *qp,
				  struct ib_address_vector *dest,
				  struct ib_address_vector *source,
				  struct io_buffer *iobuf, int rc ) {
	struct ipoib_device *ipoib = ib_qp_get_ownerdata ( qp );
	struct net_device *netdev = ipoib->netdev;
	struct ipoib_hdr *ipoib_hdr;
	struct ethhdr *ethhdr;
	struct ipoib_remac remac;
	uint16_t net_proto;

	/* Record errors */
	if ( rc != 0 ) {
		netdev_rx_err ( netdev, iobuf, rc );
		return;
	}

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( struct ipoib_hdr ) ) {
		DBGC ( ipoib, "IPoIB %p received packet too short to "
		       "contain IPoIB header\n", ipoib );
		DBGC_HD ( ipoib, iobuf->data, iob_len ( iobuf ) );
		netdev_rx_err ( netdev, iobuf, -EIO );
		return;
	}
	if ( ! source ) {
		DBGC ( ipoib, "IPoIB %p received packet without address "
		       "vector\n", ipoib );
		netdev_rx_err ( netdev, iobuf, -ENOTTY );
		return;
	}

	/* Strip real IPoIB header */
	ipoib_hdr = iobuf->data;
	net_proto = ipoib_hdr->proto;
	iob_pull ( iobuf, sizeof ( *ipoib_hdr ) );

	/* Construct source address from remote QPN and LID */
	remac.qpn = htonl ( source->qpn | EIPOIB_QPN_LA );
	remac.lid = htons ( source->lid );

	/* Translate packet if applicable */
	if ( ( rc = ipoib_translate_rx ( netdev, iobuf, &remac,
					 net_proto ) ) != 0 ) {
		netdev_rx_err ( netdev, iobuf, rc );
		return;
	}

	/* Prepend eIPoIB header */
	ethhdr = iob_push ( iobuf, sizeof ( *ethhdr ) );
	memcpy ( &ethhdr->h_source, &remac, sizeof ( ethhdr->h_source ) );
	ethhdr->h_protocol = net_proto;

	/* Construct destination address */
	if ( dest->gid_present && ( memcmp ( &dest->gid, &ipoib->broadcast.gid,
					     sizeof ( dest->gid ) ) == 0 ) ) {
		/* Broadcast GID; use the Ethernet broadcast address */
		memcpy ( &ethhdr->h_dest, eth_broadcast,
			 sizeof ( ethhdr->h_dest ) );
	} else {
		/* Assume destination address is local Ethernet MAC */
		memcpy ( &ethhdr->h_dest, netdev->ll_addr,
			 sizeof ( ethhdr->h_dest ) );
	}

	/* Hand off to network layer */
	netdev_rx ( netdev, iobuf );
}

/** IPoIB completion operations */
static struct ib_completion_queue_operations ipoib_cq_op = {
	.complete_send = ipoib_complete_send,
	.complete_recv = ipoib_complete_recv,
};

/**
 * Allocate IPoIB receive I/O buffer
 *
 * @v len		Length of buffer
 * @ret iobuf		I/O buffer, or NULL
 *
 * Some Infiniband hardware requires 2kB alignment of receive buffers
 * and provides no way to disable header separation.  The result is
 * that there are only four bytes of link-layer header (the real IPoIB
 * header) before the payload.  This is not sufficient space to insert
 * an eIPoIB link-layer pseudo-header.
 *
 * We therefore allocate I/O buffers offset to start slightly before
 * the natural alignment boundary, in order to allow sufficient space.
 */
static struct io_buffer * ipoib_alloc_iob ( size_t len ) {
	struct io_buffer *iobuf;
	size_t reserve_len;

	/* Calculate additional length required at start of buffer */
	reserve_len = ( sizeof ( struct ethhdr ) -
			sizeof ( struct ipoib_hdr ) );

	/* Allocate buffer */
	iobuf = alloc_iob_raw ( ( len + reserve_len ), len, -reserve_len );
	if ( iobuf ) {
		iob_reserve ( iobuf, reserve_len );
	}
	return iobuf;
}

/** IPoIB queue pair operations */
static struct ib_queue_pair_operations ipoib_qp_op = {
	.alloc_iob = ipoib_alloc_iob,
};

/**
 * Poll IPoIB network device
 *
 * @v netdev		Network device
 */
static void ipoib_poll ( struct net_device *netdev ) {
	struct ipoib_device *ipoib = netdev->priv;
	struct ib_device *ibdev = ipoib->ibdev;

	/* Poll Infiniband device */
	ib_poll_eq ( ibdev );

	/* Poll the retry timers (required for IPoIB multicast join) */
	retry_poll();
}

/**
 * Handle IPv4 broadcast multicast group join completion
 *
 * @v ibdev		Infiniband device
 * @v qp		Queue pair
 * @v membership	Multicast group membership
 * @v rc		Status code
 * @v mad		Response MAD (or NULL on error)
 */
void ipoib_join_complete ( struct ib_device *ibdev __unused,
			   struct ib_queue_pair *qp __unused,
			   struct ib_mc_membership *membership, int rc,
			   union ib_mad *mad __unused ) {
	struct ipoib_device *ipoib = container_of ( membership,
				   struct ipoib_device, broadcast_membership );

	/* Record join status as link status */
	netdev_link_err ( ipoib->netdev, rc );
}

/**
 * Join IPv4 broadcast multicast group
 *
 * @v ipoib		IPoIB device
 * @ret rc		Return status code
 */
static int ipoib_join_broadcast_group ( struct ipoib_device *ipoib ) {
	int rc;

	if ( ( rc = ib_mcast_join ( ipoib->ibdev, ipoib->qp,
				    &ipoib->broadcast_membership,
				    &ipoib->broadcast.gid,
				    ipoib_join_complete ) ) != 0 ) {
		DBGC ( ipoib, "IPoIB %p could not join broadcast group: %s\n",
		       ipoib, strerror ( rc ) );
		return rc;
	}
	ipoib->broadcast_joined = 1;

	return 0;
}

/**
 * Leave IPv4 broadcast multicast group
 *
 * @v ipoib		IPoIB device
 */
static void ipoib_leave_broadcast_group ( struct ipoib_device *ipoib ) {

	if ( ipoib->broadcast_joined ) {
		ib_mcast_leave ( ipoib->ibdev, ipoib->qp,
				 &ipoib->broadcast_membership );
		ipoib->broadcast_joined = 0;
	}
}

/**
 * Handle link status change
 *
 * @v ibdev		Infiniband device
 */
static void ipoib_link_state_changed ( struct ib_device *ibdev ) {
	struct net_device *netdev = ib_get_ownerdata ( ibdev );
	struct ipoib_device *ipoib = netdev->priv;
	int rc;

	/* Leave existing broadcast group */
	if ( ipoib->qp )
		ipoib_leave_broadcast_group ( ipoib );

	/* Update MAC address based on potentially-new GID prefix */
	memcpy ( &ipoib->mac.gid.s.prefix, &ibdev->gid.s.prefix,
		 sizeof ( ipoib->mac.gid.s.prefix ) );

	/* Update broadcast GID based on potentially-new partition key */
	ipoib->broadcast.gid.words[2] =
		htons ( ibdev->pkey | IB_PKEY_FULL );

	/* Set net device link state to reflect Infiniband link state */
	rc = ib_link_rc ( ibdev );
	netdev_link_err ( netdev, ( rc ? rc : -EINPROGRESS_JOINING ) );

	/* Join new broadcast group */
	if ( ib_is_open ( ibdev ) && ib_link_ok ( ibdev ) && ipoib->qp &&
	     ( ( rc = ipoib_join_broadcast_group ( ipoib ) ) != 0 ) ) {
		DBGC ( ipoib, "IPoIB %p could not rejoin broadcast group: "
		       "%s\n", ipoib, strerror ( rc ) );
		netdev_link_err ( netdev, rc );
		return;
	}
}

/**
 * Open IPoIB network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int ipoib_open ( struct net_device *netdev ) {
	struct ipoib_device *ipoib = netdev->priv;
	struct ib_device *ibdev = ipoib->ibdev;
	int rc;

	/* Open IB device */
	if ( ( rc = ib_open ( ibdev ) ) != 0 ) {
		DBGC ( ipoib, "IPoIB %p could not open device: %s\n",
		       ipoib, strerror ( rc ) );
		goto err_ib_open;
	}

	/* Allocate completion queue */
	ipoib->cq = ib_create_cq ( ibdev, IPOIB_NUM_CQES, &ipoib_cq_op );
	if ( ! ipoib->cq ) {
		DBGC ( ipoib, "IPoIB %p could not allocate completion queue\n",
		       ipoib );
		rc = -ENOMEM;
		goto err_create_cq;
	}

	/* Allocate queue pair */
	ipoib->qp = ib_create_qp ( ibdev, IB_QPT_UD, IPOIB_NUM_SEND_WQES,
				   ipoib->cq, IPOIB_NUM_RECV_WQES, ipoib->cq,
				   &ipoib_qp_op );
	if ( ! ipoib->qp ) {
		DBGC ( ipoib, "IPoIB %p could not allocate queue pair\n",
		       ipoib );
		rc = -ENOMEM;
		goto err_create_qp;
	}
	ib_qp_set_ownerdata ( ipoib->qp, ipoib );

	/* Update MAC address with QPN */
	ipoib->mac.flags__qpn = htonl ( ipoib->qp->qpn );

	/* Fill receive rings */
	ib_refill_recv ( ibdev, ipoib->qp );

	/* Fake a link status change to join the broadcast group */
	ipoib_link_state_changed ( ibdev );

	return 0;

	ib_destroy_qp ( ibdev, ipoib->qp );
 err_create_qp:
	ib_destroy_cq ( ibdev, ipoib->cq );
 err_create_cq:
	ib_close ( ibdev );
 err_ib_open:
	return rc;
}

/**
 * Close IPoIB network device
 *
 * @v netdev		Network device
 */
static void ipoib_close ( struct net_device *netdev ) {
	struct ipoib_device *ipoib = netdev->priv;
	struct ib_device *ibdev = ipoib->ibdev;

	/* Flush REMAC cache */
	ipoib_flush_remac ( ipoib );

	/* Leave broadcast group */
	ipoib_leave_broadcast_group ( ipoib );

	/* Remove QPN from MAC address */
	ipoib->mac.flags__qpn = 0;

	/* Tear down the queues */
	ib_destroy_qp ( ibdev, ipoib->qp );
	ipoib->qp = NULL;
	ib_destroy_cq ( ibdev, ipoib->cq );
	ipoib->cq = NULL;

	/* Close IB device */
	ib_close ( ibdev );
}

/** IPoIB network device operations */
static struct net_device_operations ipoib_operations = {
	.open		= ipoib_open,
	.close		= ipoib_close,
	.transmit	= ipoib_transmit,
	.poll		= ipoib_poll,
};

/**
 * Probe IPoIB device
 *
 * @v ibdev		Infiniband device
 * @ret rc		Return status code
 */
static int ipoib_probe ( struct ib_device *ibdev ) {
	struct net_device *netdev;
	struct ipoib_device *ipoib;
	int rc;

	/* Allocate network device */
	netdev = alloc_ipoibdev ( sizeof ( *ipoib ) );
	if ( ! netdev )
		return -ENOMEM;
	netdev_init ( netdev, &ipoib_operations );
	ipoib = netdev->priv;
	ib_set_ownerdata ( ibdev, netdev );
	netdev->dev = ibdev->dev;
	memset ( ipoib, 0, sizeof ( *ipoib ) );
	ipoib->netdev = netdev;
	ipoib->ibdev = ibdev;
	INIT_LIST_HEAD ( &ipoib->peers );

	/* Extract hardware address */
	memcpy ( netdev->hw_addr, &ibdev->gid.s.guid,
		 sizeof ( ibdev->gid.s.guid ) );

	/* Set local MAC address */
	memcpy ( &ipoib->mac.gid.s.guid, &ibdev->gid.s.guid,
		 sizeof ( ipoib->mac.gid.s.guid ) );

	/* Set default broadcast MAC address */
	memcpy ( &ipoib->broadcast, &ipoib_broadcast,
		 sizeof ( ipoib->broadcast ) );

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register_netdev;

	return 0;

 err_register_netdev:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
	return rc;
}

/**
 * Remove IPoIB device
 *
 * @v ibdev		Infiniband device
 */
static void ipoib_remove ( struct ib_device *ibdev ) {
	struct net_device *netdev = ib_get_ownerdata ( ibdev );

	unregister_netdev ( netdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/** IPoIB driver */
struct ib_driver ipoib_driver __ib_driver = {
	.name = "IPoIB",
	.probe = ipoib_probe,
	.notify = ipoib_link_state_changed,
	.remove = ipoib_remove,
};
