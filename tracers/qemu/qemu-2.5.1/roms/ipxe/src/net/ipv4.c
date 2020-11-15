/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
 * Copyright (C) 2006 Nikhil Chandru Rao
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/list.h>
#include <ipxe/in.h>
#include <ipxe/arp.h>
#include <ipxe/if_ether.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/ip.h>
#include <ipxe/tcpip.h>
#include <ipxe/dhcp.h>
#include <ipxe/settings.h>
#include <ipxe/fragment.h>
#include <ipxe/ipstat.h>
#include <ipxe/profile.h>

/** @file
 *
 * IPv4 protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/* Unique IP datagram identification number (high byte) */
static uint8_t next_ident_high = 0;

/** List of IPv4 miniroutes */
struct list_head ipv4_miniroutes = LIST_HEAD_INIT ( ipv4_miniroutes );

/** IPv4 statistics */
static struct ip_statistics ipv4_stats;

/** IPv4 statistics family */
struct ip_statistics_family
ipv4_stats_family __ip_statistics_family ( IP_STATISTICS_IPV4 ) = {
	.version = 4,
	.stats = &ipv4_stats,
};

/** Transmit profiler */
static struct profiler ipv4_tx_profiler __profiler = { .name = "ipv4.tx" };

/** Receive profiler */
static struct profiler ipv4_rx_profiler __profiler = { .name = "ipv4.rx" };

/**
 * Add IPv4 minirouting table entry
 *
 * @v netdev		Network device
 * @v address		IPv4 address
 * @v netmask		Subnet mask
 * @v gateway		Gateway address (if any)
 * @ret miniroute	Routing table entry, or NULL
 */
static struct ipv4_miniroute * __malloc
add_ipv4_miniroute ( struct net_device *netdev, struct in_addr address,
		     struct in_addr netmask, struct in_addr gateway ) {
	struct ipv4_miniroute *miniroute;

	DBGC ( netdev, "IPv4 add %s", inet_ntoa ( address ) );
	DBGC ( netdev, "/%s ", inet_ntoa ( netmask ) );
	if ( gateway.s_addr )
		DBGC ( netdev, "gw %s ", inet_ntoa ( gateway ) );
	DBGC ( netdev, "via %s\n", netdev->name );

	/* Allocate and populate miniroute structure */
	miniroute = malloc ( sizeof ( *miniroute ) );
	if ( ! miniroute ) {
		DBGC ( netdev, "IPv4 could not add miniroute\n" );
		return NULL;
	}

	/* Record routing information */
	miniroute->netdev = netdev_get ( netdev );
	miniroute->address = address;
	miniroute->netmask = netmask;
	miniroute->gateway = gateway;
		
	/* Add to end of list if we have a gateway, otherwise
	 * to start of list.
	 */
	if ( gateway.s_addr ) {
		list_add_tail ( &miniroute->list, &ipv4_miniroutes );
	} else {
		list_add ( &miniroute->list, &ipv4_miniroutes );
	}

	return miniroute;
}

/**
 * Delete IPv4 minirouting table entry
 *
 * @v miniroute		Routing table entry
 */
static void del_ipv4_miniroute ( struct ipv4_miniroute *miniroute ) {
	struct net_device *netdev = miniroute->netdev;

	DBGC ( netdev, "IPv4 del %s", inet_ntoa ( miniroute->address ) );
	DBGC ( netdev, "/%s ", inet_ntoa ( miniroute->netmask ) );
	if ( miniroute->gateway.s_addr )
		DBGC ( netdev, "gw %s ", inet_ntoa ( miniroute->gateway ) );
	DBGC ( netdev, "via %s\n", miniroute->netdev->name );

	netdev_put ( miniroute->netdev );
	list_del ( &miniroute->list );
	free ( miniroute );
}

/**
 * Perform IPv4 routing
 *
 * @v scope_id		Destination address scope ID
 * @v dest		Final destination address
 * @ret dest		Next hop destination address
 * @ret miniroute	Routing table entry to use, or NULL if no route
 *
 * If the route requires use of a gateway, the next hop destination
 * address will be overwritten with the gateway address.
 */
static struct ipv4_miniroute * ipv4_route ( unsigned int scope_id,
					    struct in_addr *dest ) {
	struct ipv4_miniroute *miniroute;

	/* Find first usable route in routing table */
	list_for_each_entry ( miniroute, &ipv4_miniroutes, list ) {

		/* Skip closed network devices */
		if ( ! netdev_is_open ( miniroute->netdev ) )
			continue;

		if ( IN_IS_MULTICAST ( dest->s_addr ) ) {

			/* If destination is non-global, and the scope ID
			 * matches this network device, then use this route.
			 */
			if ( miniroute->netdev->index == scope_id )
				return miniroute;

		} else {

			/* If destination is an on-link global
			 * address, then use this route.
			 */
			if ( ( ( dest->s_addr ^ miniroute->address.s_addr )
			       & miniroute->netmask.s_addr ) == 0 )
				return miniroute;

			/* If destination is an off-link global
			 * address, and we have a default gateway,
			 * then use this route.
			 */
			if ( miniroute->gateway.s_addr ) {
				*dest = miniroute->gateway;
				return miniroute;
			}
		}
	}

	return NULL;
}

/**
 * Determine transmitting network device
 *
 * @v st_dest		Destination network-layer address
 * @ret netdev		Transmitting network device, or NULL
 */
static struct net_device * ipv4_netdev ( struct sockaddr_tcpip *st_dest ) {
	struct sockaddr_in *sin_dest = ( ( struct sockaddr_in * ) st_dest );
	struct in_addr dest = sin_dest->sin_addr;
	struct ipv4_miniroute *miniroute;

	/* Find routing table entry */
	miniroute = ipv4_route ( sin_dest->sin_scope_id, &dest );
	if ( ! miniroute )
		return NULL;

	return miniroute->netdev;
}

/**
 * Check if IPv4 fragment matches fragment reassembly buffer
 *
 * @v fragment		Fragment reassembly buffer
 * @v iobuf		I/O buffer
 * @v hdrlen		Length of non-fragmentable potion of I/O buffer
 * @ret is_fragment	Fragment matches this reassembly buffer
 */
static int ipv4_is_fragment ( struct fragment *fragment,
			      struct io_buffer *iobuf,
			      size_t hdrlen __unused ) {
	struct iphdr *frag_iphdr = fragment->iobuf->data;
	struct iphdr *iphdr = iobuf->data;

	return ( ( iphdr->src.s_addr == frag_iphdr->src.s_addr ) &&
		 ( iphdr->ident == frag_iphdr->ident ) );
}

/**
 * Get IPv4 fragment offset
 *
 * @v iobuf		I/O buffer
 * @v hdrlen		Length of non-fragmentable potion of I/O buffer
 * @ret offset		Offset
 */
static size_t ipv4_fragment_offset ( struct io_buffer *iobuf,
				     size_t hdrlen __unused ) {
	struct iphdr *iphdr = iobuf->data;

	return ( ( ntohs ( iphdr->frags ) & IP_MASK_OFFSET ) << 3 );
}

/**
 * Check if more fragments exist
 *
 * @v iobuf		I/O buffer
 * @v hdrlen		Length of non-fragmentable potion of I/O buffer
 * @ret more_frags	More fragments exist
 */
static int ipv4_more_fragments ( struct io_buffer *iobuf,
				 size_t hdrlen __unused ) {
	struct iphdr *iphdr = iobuf->data;

	return ( iphdr->frags & htons ( IP_MASK_MOREFRAGS ) );
}

/** IPv4 fragment reassembler */
static struct fragment_reassembler ipv4_reassembler = {
	.list = LIST_HEAD_INIT ( ipv4_reassembler.list ),
	.is_fragment = ipv4_is_fragment,
	.fragment_offset = ipv4_fragment_offset,
	.more_fragments = ipv4_more_fragments,
	.stats = &ipv4_stats,
};

/**
 * Add IPv4 pseudo-header checksum to existing checksum
 *
 * @v iobuf		I/O buffer
 * @v csum		Existing checksum
 * @ret csum		Updated checksum
 */
static uint16_t ipv4_pshdr_chksum ( struct io_buffer *iobuf, uint16_t csum ) {
	struct ipv4_pseudo_header pshdr;
	struct iphdr *iphdr = iobuf->data;
	size_t hdrlen = ( ( iphdr->verhdrlen & IP_MASK_HLEN ) * 4 );

	/* Build pseudo-header */
	pshdr.src = iphdr->src;
	pshdr.dest = iphdr->dest;
	pshdr.zero_padding = 0x00;
	pshdr.protocol = iphdr->protocol;
	pshdr.len = htons ( iob_len ( iobuf ) - hdrlen );

	/* Update the checksum value */
	return tcpip_continue_chksum ( csum, &pshdr, sizeof ( pshdr ) );
}

/**
 * Transmit IP packet
 *
 * @v iobuf		I/O buffer
 * @v tcpip		Transport-layer protocol
 * @v st_src		Source network-layer address
 * @v st_dest		Destination network-layer address
 * @v netdev		Network device to use if no route found, or NULL
 * @v trans_csum	Transport-layer checksum to complete, or NULL
 * @ret rc		Status
 *
 * This function expects a transport-layer segment and prepends the IP header
 */
static int ipv4_tx ( struct io_buffer *iobuf,
		     struct tcpip_protocol *tcpip_protocol,
		     struct sockaddr_tcpip *st_src,
		     struct sockaddr_tcpip *st_dest,
		     struct net_device *netdev,
		     uint16_t *trans_csum ) {
	struct iphdr *iphdr = iob_push ( iobuf, sizeof ( *iphdr ) );
	struct sockaddr_in *sin_src = ( ( struct sockaddr_in * ) st_src );
	struct sockaddr_in *sin_dest = ( ( struct sockaddr_in * ) st_dest );
	struct ipv4_miniroute *miniroute;
	struct in_addr next_hop;
	struct in_addr netmask = { .s_addr = 0 };
	uint8_t ll_dest_buf[MAX_LL_ADDR_LEN];
	const void *ll_dest;
	int rc;

	/* Start profiling */
	profile_start ( &ipv4_tx_profiler );

	/* Update statistics */
	ipv4_stats.out_requests++;

	/* Fill up the IP header, except source address */
	memset ( iphdr, 0, sizeof ( *iphdr ) );
	iphdr->verhdrlen = ( IP_VER | ( sizeof ( *iphdr ) / 4 ) );
	iphdr->service = IP_TOS;
	iphdr->len = htons ( iob_len ( iobuf ) );	
	iphdr->ttl = IP_TTL;
	iphdr->protocol = tcpip_protocol->tcpip_proto;
	iphdr->dest = sin_dest->sin_addr;

	/* Use routing table to identify next hop and transmitting netdev */
	next_hop = iphdr->dest;
	if ( sin_src )
		iphdr->src = sin_src->sin_addr;
	if ( ( next_hop.s_addr != INADDR_BROADCAST ) &&
	     ( ( miniroute = ipv4_route ( sin_dest->sin_scope_id,
					  &next_hop ) ) != NULL ) ) {
		iphdr->src = miniroute->address;
		netmask = miniroute->netmask;
		netdev = miniroute->netdev;
	}
	if ( ! netdev ) {
		DBGC ( sin_dest->sin_addr, "IPv4 has no route to %s\n",
		       inet_ntoa ( iphdr->dest ) );
		ipv4_stats.out_no_routes++;
		rc = -ENETUNREACH;
		goto err;
	}

	/* (Ab)use the "ident" field to convey metadata about the
	 * network device statistics into packet traces.  Useful for
	 * extracting debug information from non-debug builds.
	 */
	iphdr->ident = htons ( ( (++next_ident_high) << 8 ) |
			       ( ( netdev->rx_stats.bad & 0xf ) << 4 ) |
			       ( ( netdev->rx_stats.good & 0xf ) << 0 ) );

	/* Fix up checksums */
	if ( trans_csum )
		*trans_csum = ipv4_pshdr_chksum ( iobuf, *trans_csum );
	iphdr->chksum = tcpip_chksum ( iphdr, sizeof ( *iphdr ) );

	/* Print IP4 header for debugging */
	DBGC2 ( sin_dest->sin_addr, "IPv4 TX %s->", inet_ntoa ( iphdr->src ) );
	DBGC2 ( sin_dest->sin_addr, "%s len %d proto %d id %04x csum %04x\n",
		inet_ntoa ( iphdr->dest ), ntohs ( iphdr->len ),
		iphdr->protocol, ntohs ( iphdr->ident ),
		ntohs ( iphdr->chksum ) );

	/* Calculate link-layer destination address, if possible */
	if ( ( ( next_hop.s_addr ^ INADDR_BROADCAST ) & ~netmask.s_addr ) == 0){
		/* Broadcast address */
		ipv4_stats.out_bcast_pkts++;
		ll_dest = netdev->ll_broadcast;
	} else if ( IN_IS_MULTICAST ( next_hop.s_addr ) ) {
		/* Multicast address */
		ipv4_stats.out_mcast_pkts++;
		if ( ( rc = netdev->ll_protocol->mc_hash ( AF_INET, &next_hop,
							   ll_dest_buf ) ) !=0){
			DBGC ( sin_dest->sin_addr, "IPv4 could not hash "
			       "multicast %s: %s\n",
			       inet_ntoa ( next_hop ), strerror ( rc ) );
			goto err;
		}
		ll_dest = ll_dest_buf;
	} else {
		/* Unicast address */
		ll_dest = NULL;
	}

	/* Update statistics */
	ipv4_stats.out_transmits++;
	ipv4_stats.out_octets += iob_len ( iobuf );

	/* Hand off to link layer (via ARP if applicable) */
	if ( ll_dest ) {
		if ( ( rc = net_tx ( iobuf, netdev, &ipv4_protocol, ll_dest,
				     netdev->ll_addr ) ) != 0 ) {
			DBGC ( sin_dest->sin_addr, "IPv4 could not transmit "
			       "packet via %s: %s\n",
			       netdev->name, strerror ( rc ) );
			return rc;
		}
	} else {
		if ( ( rc = arp_tx ( iobuf, netdev, &ipv4_protocol, &next_hop,
				     &iphdr->src, netdev->ll_addr ) ) != 0 ) {
			DBGC ( sin_dest->sin_addr, "IPv4 could not transmit "
			       "packet via %s: %s\n",
			       netdev->name, strerror ( rc ) );
			return rc;
		}
	}

	profile_stop ( &ipv4_tx_profiler );
	return 0;

 err:
	free_iob ( iobuf );
	return rc;
}

/**
 * Check if network device has any IPv4 address
 *
 * @v netdev		Network device
 * @ret has_any_addr	Network device has any IPv4 address
 */
int ipv4_has_any_addr ( struct net_device *netdev ) {
	struct ipv4_miniroute *miniroute;

	list_for_each_entry ( miniroute, &ipv4_miniroutes, list ) {
		if ( miniroute->netdev == netdev )
			return 1;
	}
	return 0;
}

/**
 * Check if network device has a specific IPv4 address
 *
 * @v netdev		Network device
 * @v addr		IPv4 address
 * @ret has_addr	Network device has this IPv4 address
 */
static int ipv4_has_addr ( struct net_device *netdev, struct in_addr addr ) {
	struct ipv4_miniroute *miniroute;

	list_for_each_entry ( miniroute, &ipv4_miniroutes, list ) {
		if ( ( miniroute->netdev == netdev ) &&
		     ( miniroute->address.s_addr == addr.s_addr ) ) {
			/* Found matching address */
			return 1;
		}
	}
	return 0;
}

/**
 * Process incoming packets
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v ll_dest		Link-layer destination address
 * @v ll_source		Link-layer destination source
 * @v flags		Packet flags
 * @ret rc		Return status code
 *
 * This function expects an IP4 network datagram. It processes the headers 
 * and sends it to the transport layer.
 */
static int ipv4_rx ( struct io_buffer *iobuf,
		     struct net_device *netdev,
		     const void *ll_dest __unused,
		     const void *ll_source __unused,
		     unsigned int flags ) {
	struct iphdr *iphdr = iobuf->data;
	size_t hdrlen;
	size_t len;
	union {
		struct sockaddr_in sin;
		struct sockaddr_tcpip st;
	} src, dest;
	uint16_t csum;
	uint16_t pshdr_csum;
	int rc;

	/* Start profiling */
	profile_start ( &ipv4_rx_profiler );

	/* Update statistics */
	ipv4_stats.in_receives++;
	ipv4_stats.in_octets += iob_len ( iobuf );
	if ( flags & LL_BROADCAST ) {
		ipv4_stats.in_bcast_pkts++;
	} else if ( flags & LL_MULTICAST ) {
		ipv4_stats.in_mcast_pkts++;
	}

	/* Sanity check the IPv4 header */
	if ( iob_len ( iobuf ) < sizeof ( *iphdr ) ) {
		DBGC ( iphdr->src, "IPv4 packet too short at %zd bytes (min "
		       "%zd bytes)\n", iob_len ( iobuf ), sizeof ( *iphdr ) );
		goto err_header;
	}
	if ( ( iphdr->verhdrlen & IP_MASK_VER ) != IP_VER ) {
		DBGC ( iphdr->src, "IPv4 version %#02x not supported\n",
		       iphdr->verhdrlen );
		goto err_header;
	}
	hdrlen = ( ( iphdr->verhdrlen & IP_MASK_HLEN ) * 4 );
	if ( hdrlen < sizeof ( *iphdr ) ) {
		DBGC ( iphdr->src, "IPv4 header too short at %zd bytes (min "
		       "%zd bytes)\n", hdrlen, sizeof ( *iphdr ) );
		goto err_header;
	}
	if ( hdrlen > iob_len ( iobuf ) ) {
		DBGC ( iphdr->src, "IPv4 header too long at %zd bytes "
		       "(packet is %zd bytes)\n", hdrlen, iob_len ( iobuf ) );
		goto err_header;
	}
	if ( ( csum = tcpip_chksum ( iphdr, hdrlen ) ) != 0 ) {
		DBGC ( iphdr->src, "IPv4 checksum incorrect (is %04x "
		       "including checksum field, should be 0000)\n", csum );
		goto err_header;
	}
	len = ntohs ( iphdr->len );
	if ( len < hdrlen ) {
		DBGC ( iphdr->src, "IPv4 length too short at %zd bytes "
		       "(header is %zd bytes)\n", len, hdrlen );
		goto err_header;
	}
	if ( len > iob_len ( iobuf ) ) {
		DBGC ( iphdr->src, "IPv4 length too long at %zd bytes "
		       "(packet is %zd bytes)\n", len, iob_len ( iobuf ) );
		ipv4_stats.in_truncated_pkts++;
		goto err_other;
	}

	/* Truncate packet to correct length */
	iob_unput ( iobuf, ( iob_len ( iobuf ) - len ) );

	/* Print IPv4 header for debugging */
	DBGC2 ( iphdr->src, "IPv4 RX %s<-", inet_ntoa ( iphdr->dest ) );
	DBGC2 ( iphdr->src, "%s len %d proto %d id %04x csum %04x\n",
		inet_ntoa ( iphdr->src ), ntohs ( iphdr->len ), iphdr->protocol,
		ntohs ( iphdr->ident ), ntohs ( iphdr->chksum ) );

	/* Discard unicast packets not destined for us */
	if ( ( ! ( flags & LL_MULTICAST ) ) &&
	     ipv4_has_any_addr ( netdev ) &&
	     ( ! ipv4_has_addr ( netdev, iphdr->dest ) ) ) {
		DBGC ( iphdr->src, "IPv4 discarding non-local unicast packet "
		       "for %s\n", inet_ntoa ( iphdr->dest ) );
		ipv4_stats.in_addr_errors++;
		goto err_other;
	}

	/* Perform fragment reassembly if applicable */
	if ( iphdr->frags & htons ( IP_MASK_OFFSET | IP_MASK_MOREFRAGS ) ) {
		/* Pass the fragment to fragment_reassemble() which returns
		 * either a fully reassembled I/O buffer or NULL.
		 */
		iobuf = fragment_reassemble ( &ipv4_reassembler, iobuf,
					      &hdrlen );
		if ( ! iobuf )
			return 0;
		iphdr = iobuf->data;
	}

	/* Construct socket addresses, calculate pseudo-header
	 * checksum, and hand off to transport layer
	 */
	memset ( &src, 0, sizeof ( src ) );
	src.sin.sin_family = AF_INET;
	src.sin.sin_addr = iphdr->src;
	memset ( &dest, 0, sizeof ( dest ) );
	dest.sin.sin_family = AF_INET;
	dest.sin.sin_addr = iphdr->dest;
	pshdr_csum = ipv4_pshdr_chksum ( iobuf, TCPIP_EMPTY_CSUM );
	iob_pull ( iobuf, hdrlen );
	if ( ( rc = tcpip_rx ( iobuf, netdev, iphdr->protocol, &src.st,
			       &dest.st, pshdr_csum, &ipv4_stats ) ) != 0 ) {
		DBGC ( src.sin.sin_addr, "IPv4 received packet rejected by "
		       "stack: %s\n", strerror ( rc ) );
		return rc;
	}

	profile_stop ( &ipv4_rx_profiler );
	return 0;

 err_header:
	ipv4_stats.in_hdr_errors++;
 err_other:
	free_iob ( iobuf );
	return -EINVAL;
}

/** 
 * Check existence of IPv4 address for ARP
 *
 * @v netdev		Network device
 * @v net_addr		Network-layer address
 * @ret rc		Return status code
 */
static int ipv4_arp_check ( struct net_device *netdev, const void *net_addr ) {
	const struct in_addr *address = net_addr;

	if ( ipv4_has_addr ( netdev, *address ) )
		return 0;

	return -ENOENT;
}

/**
 * Parse IPv4 address
 *
 * @v string		IPv4 address string
 * @ret in		IPv4 address to fill in
 * @ret ok		IPv4 address is valid
 *
 * Note that this function returns nonzero iff the address is valid,
 * to match the standard BSD API function of the same name.  Unlike
 * most other iPXE functions, a zero therefore indicates failure.
 */
int inet_aton ( const char *string, struct in_addr *in ) {
	const char *separator = "...";
	uint8_t *byte = ( ( uint8_t * ) in );
	char *endp;
	unsigned long value;

	while ( 1 ) {
		value = strtoul ( string, &endp, 0 );
		if ( string == endp )
			return 0;
		if ( value > 0xff )
			return 0;
		*(byte++) = value;
		if ( *endp != *separator )
			return 0;
		if ( ! *(separator++) )
			return 1;
		string = ( endp + 1 );
	}
}

/**
 * Convert IPv4 address to dotted-quad notation
 *
 * @v in		IPv4 address
 * @ret string		IPv4 address in dotted-quad notation
 */
char * inet_ntoa ( struct in_addr in ) {
	static char buf[16]; /* "xxx.xxx.xxx.xxx" */
	uint8_t *bytes = ( uint8_t * ) &in;
	
	sprintf ( buf, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3] );
	return buf;
}

/**
 * Transcribe IPv4 address
 *
 * @v net_addr		IPv4 address
 * @ret string		IPv4 address in dotted-quad notation
 *
 */
static const char * ipv4_ntoa ( const void *net_addr ) {
	return inet_ntoa ( * ( ( struct in_addr * ) net_addr ) );
}

/**
 * Transcribe IPv4 socket address
 *
 * @v sa		Socket address
 * @ret string		Socket address in standard notation
 */
static const char * ipv4_sock_ntoa ( struct sockaddr *sa ) {
	struct sockaddr_in *sin = ( ( struct sockaddr_in * ) sa );

	return inet_ntoa ( sin->sin_addr );
}

/**
 * Parse IPv4 socket address
 *
 * @v string		Socket address string
 * @v sa		Socket address to fill in
 * @ret rc		Return status code
 */
static int ipv4_sock_aton ( const char *string, struct sockaddr *sa ) {
	struct sockaddr_in *sin = ( ( struct sockaddr_in * ) sa );
	struct in_addr in;

	if ( inet_aton ( string, &in ) ) {
		sin->sin_addr = in;
		return 0;
	}
	return -EINVAL;
}

/** IPv4 protocol */
struct net_protocol ipv4_protocol __net_protocol = {
	.name = "IP",
	.net_proto = htons ( ETH_P_IP ),
	.net_addr_len = sizeof ( struct in_addr ),
	.rx = ipv4_rx,
	.ntoa = ipv4_ntoa,
};

/** IPv4 TCPIP net protocol */
struct tcpip_net_protocol ipv4_tcpip_protocol __tcpip_net_protocol = {
	.name = "IPv4",
	.sa_family = AF_INET,
	.header_len = sizeof ( struct iphdr ),
	.tx = ipv4_tx,
	.netdev = ipv4_netdev,
};

/** IPv4 ARP protocol */
struct arp_net_protocol ipv4_arp_protocol __arp_net_protocol = {
	.net_protocol = &ipv4_protocol,
	.check = ipv4_arp_check,
};

/** IPv4 socket address converter */
struct sockaddr_converter ipv4_sockaddr_converter __sockaddr_converter = {
	.family = AF_INET,
	.ntoa = ipv4_sock_ntoa,
	.aton = ipv4_sock_aton,
};

/******************************************************************************
 *
 * Settings
 *
 ******************************************************************************
 */

/**
 * Parse IPv4 address setting value
 *
 * @v type		Setting type
 * @v value		Formatted setting value
 * @v buf		Buffer to contain raw value
 * @v len		Length of buffer
 * @ret len		Length of raw value, or negative error
 */
int parse_ipv4_setting ( const struct setting_type *type __unused,
			 const char *value, void *buf, size_t len ) {
	struct in_addr ipv4;

	/* Parse IPv4 address */
	if ( inet_aton ( value, &ipv4 ) == 0 )
		return -EINVAL;

	/* Copy to buffer */
	if ( len > sizeof ( ipv4 ) )
		len = sizeof ( ipv4 );
	memcpy ( buf, &ipv4, len );

	return ( sizeof ( ipv4 ) );
}

/**
 * Format IPv4 address setting value
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
int format_ipv4_setting ( const struct setting_type *type __unused,
			  const void *raw, size_t raw_len, char *buf,
			  size_t len ) {
	const struct in_addr *ipv4 = raw;

	if ( raw_len < sizeof ( *ipv4 ) )
		return -EINVAL;
	return snprintf ( buf, len, "%s", inet_ntoa ( *ipv4 ) );
}

/** IPv4 address setting */
const struct setting ip_setting __setting ( SETTING_IP, ip ) = {
	.name = "ip",
	.description = "IP address",
	.tag = DHCP_EB_YIADDR,
	.type = &setting_type_ipv4,
};

/** IPv4 subnet mask setting */
const struct setting netmask_setting __setting ( SETTING_IP, netmask ) = {
	.name = "netmask",
	.description = "Subnet mask",
	.tag = DHCP_SUBNET_MASK,
	.type = &setting_type_ipv4,
};

/** Default gateway setting */
const struct setting gateway_setting __setting ( SETTING_IP, gateway ) = {
	.name = "gateway",
	.description = "Default gateway",
	.tag = DHCP_ROUTERS,
	.type = &setting_type_ipv4,
};

/**
 * Create IPv4 routing table based on configured settings
 *
 * @ret rc		Return status code
 */
static int ipv4_create_routes ( void ) {
	struct ipv4_miniroute *miniroute;
	struct ipv4_miniroute *tmp;
	struct net_device *netdev;
	struct settings *settings;
	struct in_addr address = { 0 };
	struct in_addr netmask = { 0 };
	struct in_addr gateway = { 0 };

	/* Delete all existing routes */
	list_for_each_entry_safe ( miniroute, tmp, &ipv4_miniroutes, list )
		del_ipv4_miniroute ( miniroute );

	/* Create a route for each configured network device */
	for_each_netdev ( netdev ) {
		settings = netdev_settings ( netdev );
		/* Get IPv4 address */
		address.s_addr = 0;
		fetch_ipv4_setting ( settings, &ip_setting, &address );
		if ( ! address.s_addr )
			continue;
		/* Get subnet mask */
		fetch_ipv4_setting ( settings, &netmask_setting, &netmask );
		/* Calculate default netmask, if necessary */
		if ( ! netmask.s_addr ) {
			if ( IN_IS_CLASSA ( address.s_addr ) ) {
				netmask.s_addr = INADDR_NET_CLASSA;
			} else if ( IN_IS_CLASSB ( address.s_addr ) ) {
				netmask.s_addr = INADDR_NET_CLASSB;
			} else if ( IN_IS_CLASSC ( address.s_addr ) ) {
				netmask.s_addr = INADDR_NET_CLASSC;
			}
		}
		/* Get default gateway, if present */
		fetch_ipv4_setting ( settings, &gateway_setting, &gateway );
		/* Configure route */
		miniroute = add_ipv4_miniroute ( netdev, address,
						 netmask, gateway );
		if ( ! miniroute )
			return -ENOMEM;
	}

	return 0;
}

/** IPv4 settings applicator */
struct settings_applicator ipv4_settings_applicator __settings_applicator = {
	.apply = ipv4_create_routes,
};

/* Drag in objects via ipv4_protocol */
REQUIRING_SYMBOL ( ipv4_protocol );

/* Drag in ICMPv4 */
REQUIRE_OBJECT ( icmpv4 );
