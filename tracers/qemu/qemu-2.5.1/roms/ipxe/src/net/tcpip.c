#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/iobuf.h>
#include <ipxe/tables.h>
#include <ipxe/ipstat.h>
#include <ipxe/netdevice.h>
#include <ipxe/tcpip.h>

/** @file
 *
 * Transport-network layer interface
 *
 * This file contains functions and utilities for the
 * TCP/IP transport-network layer interface
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Process a received TCP/IP packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v tcpip_proto	Transport-layer protocol number
 * @v st_src		Partially-filled source address
 * @v st_dest		Partially-filled destination address
 * @v pshdr_csum	Pseudo-header checksum
 * @v stats		IP statistics
 * @ret rc		Return status code
 *
 * This function expects a transport-layer segment from the network
 * layer.  The network layer should fill in as much as it can of the
 * source and destination addresses (i.e. it should fill in the
 * address family and the network-layer addresses, but leave the ports
 * and the rest of the structures as zero).
 */
int tcpip_rx ( struct io_buffer *iobuf, struct net_device *netdev,
	       uint8_t tcpip_proto, struct sockaddr_tcpip *st_src,
	       struct sockaddr_tcpip *st_dest, uint16_t pshdr_csum,
	       struct ip_statistics *stats ) {
	struct tcpip_protocol *tcpip;

	/* Hand off packet to the appropriate transport-layer protocol */
	for_each_table_entry ( tcpip, TCPIP_PROTOCOLS ) {
		if ( tcpip->tcpip_proto == tcpip_proto ) {
			DBG ( "TCP/IP received %s packet\n", tcpip->name );
			stats->in_delivers++;
			return tcpip->rx ( iobuf, netdev, st_src, st_dest,
					   pshdr_csum );
		}
	}

	DBG ( "Unrecognised TCP/IP protocol %d\n", tcpip_proto );
	stats->in_unknown_protos++;
	free_iob ( iobuf );
	return -EPROTONOSUPPORT;
}

/**
 * Find TCP/IP network-layer protocol
 *
 * @v st_dest		Destination address
 * @ret tcpip_net	TCP/IP network-layer protocol, or NULL if not found
 */
static struct tcpip_net_protocol *
tcpip_net_protocol ( struct sockaddr_tcpip *st_dest ) {
	struct tcpip_net_protocol *tcpip_net;

	for_each_table_entry ( tcpip_net, TCPIP_NET_PROTOCOLS ) {
		if ( tcpip_net->sa_family == st_dest->st_family )
			return tcpip_net;
	}

	DBG ( "Unrecognised TCP/IP address family %d\n", st_dest->st_family );
	return NULL;
}

/**
 * Transmit a TCP/IP packet
 *
 * @v iobuf		I/O buffer
 * @v tcpip_protocol	Transport-layer protocol
 * @v st_src		Source address, or NULL to use route default
 * @v st_dest		Destination address
 * @v netdev		Network device to use if no route found, or NULL
 * @v trans_csum	Transport-layer checksum to complete, or NULL
 * @ret rc		Return status code
 */
int tcpip_tx ( struct io_buffer *iobuf, struct tcpip_protocol *tcpip_protocol,
	       struct sockaddr_tcpip *st_src, struct sockaddr_tcpip *st_dest,
	       struct net_device *netdev, uint16_t *trans_csum ) {
	struct tcpip_net_protocol *tcpip_net;

	/* Hand off packet to the appropriate network-layer protocol */
	tcpip_net = tcpip_net_protocol ( st_dest );
	if ( tcpip_net ) {
		DBG ( "TCP/IP sending %s packet\n", tcpip_net->name );
		return tcpip_net->tx ( iobuf, tcpip_protocol, st_src, st_dest,
				       netdev, trans_csum );
	}

	free_iob ( iobuf );
	return -EAFNOSUPPORT;
}

/**
 * Determine transmitting network device
 *
 * @v st_dest		Destination address
 * @ret netdev		Network device, or NULL
 */
struct net_device * tcpip_netdev ( struct sockaddr_tcpip *st_dest ) {
	struct tcpip_net_protocol *tcpip_net;

	/* Hand off to the appropriate network-layer protocol */
	tcpip_net = tcpip_net_protocol ( st_dest );
	if ( tcpip_net )
		return tcpip_net->netdev ( st_dest );

	return NULL;
}

/**
 * Determine maximum transmission unit
 *
 * @v st_dest		Destination address
 * @ret mtu		Maximum transmission unit
 */
size_t tcpip_mtu ( struct sockaddr_tcpip *st_dest ) {
	struct tcpip_net_protocol *tcpip_net;
	struct net_device *netdev;
	size_t mtu;

	/* Find appropriate network-layer protocol */
	tcpip_net = tcpip_net_protocol ( st_dest );
	if ( ! tcpip_net )
		return 0;

	/* Find transmitting network device */
	netdev = tcpip_net->netdev ( st_dest );
	if ( ! netdev )
		return 0;

	/* Calculate MTU */
	mtu = ( netdev->max_pkt_len - netdev->ll_protocol->ll_header_len -
		tcpip_net->header_len );

	return mtu;
}

/**
 * Calculate continued TCP/IP checkum
 *
 * @v partial		Checksum of already-summed data, in network byte order
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret cksum		Updated checksum, in network byte order
 *
 * Calculates a TCP/IP-style 16-bit checksum over the data block.  The
 * checksum is returned in network byte order.
 *
 * This function may be used to add new data to an existing checksum.
 * The function assumes that both the old data and the new data start
 * on even byte offsets; if this is not the case then you will need to
 * byte-swap either the input partial checksum, the output checksum,
 * or both.  Deciding which to swap is left as an exercise for the
 * interested reader.
 */
uint16_t generic_tcpip_continue_chksum ( uint16_t partial,
					 const void *data, size_t len ) {
	unsigned int cksum = ( ( ~partial ) & 0xffff );
	unsigned int value;
	unsigned int i;
	
	for ( i = 0 ; i < len ; i++ ) {
		value = * ( ( uint8_t * ) data + i );
		if ( i & 1 ) {
			/* Odd bytes: swap on little-endian systems */
			value = be16_to_cpu ( value );
		} else {
			/* Even bytes: swap on big-endian systems */
			value = le16_to_cpu ( value );
		}
		cksum += value;
		if ( cksum > 0xffff )
			cksum -= 0xffff;
	}
	
	return ( ~cksum );
}

/**
 * Calculate TCP/IP checkum
 *
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret cksum		Checksum, in network byte order
 *
 * Calculates a TCP/IP-style 16-bit checksum over the data block.  The
 * checksum is returned in network byte order.
 */
uint16_t tcpip_chksum ( const void *data, size_t len ) {
	return tcpip_continue_chksum ( TCPIP_EMPTY_CSUM, data, len );
}

/**
 * Bind to local TCP/IP port
 *
 * @v st_local		Local TCP/IP socket address, or NULL
 * @v available		Function to check port availability
 * @ret port		Local port number, or negative error
 */
int tcpip_bind ( struct sockaddr_tcpip *st_local,
		 int ( * available ) ( int port ) ) {
	uint16_t flags = 0;
	uint16_t try_port = 0;
	uint16_t min_port;
	uint16_t max_port;
	unsigned int offset;
	unsigned int i;

	/* Extract parameters from local socket address */
	if ( st_local ) {
		flags = st_local->st_flags;
		try_port = ntohs ( st_local->st_port );
	}

	/* If an explicit port is specified, check its availability */
	if ( try_port )
		return available ( try_port );

	/* Otherwise, find an available port in the range [1,1023] or
	 * [1025,65535] as appropriate.
	 */
	min_port = ( ( ( ~flags ) & TCPIP_BIND_PRIVILEGED ) + 1 );
	max_port = ( ( flags & TCPIP_BIND_PRIVILEGED ) - 1 );
	offset = random();
	for ( i = 0 ; i <= max_port ; i++ ) {
		try_port = ( ( i + offset ) & max_port );
		if ( try_port < min_port )
			continue;
		if ( available ( try_port ) < 0 )
			continue;
		return try_port;
	}
	return -EADDRINUSE;
}
