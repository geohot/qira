#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <ipxe/tcpip.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/uri.h>
#include <ipxe/netdevice.h>
#include <ipxe/udp.h>

/** @file
 *
 * UDP protocol
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * A UDP connection
 *
 */
struct udp_connection {
	/** Reference counter */
	struct refcnt refcnt;
	/** List of UDP connections */
	struct list_head list;

	/** Data transfer interface */
	struct interface xfer;

	/** Local socket address */
	struct sockaddr_tcpip local;
	/** Remote socket address */
	struct sockaddr_tcpip peer;
};

/**
 * List of registered UDP connections
 */
static LIST_HEAD ( udp_conns );

/* Forward declatations */
static struct interface_descriptor udp_xfer_desc;
struct tcpip_protocol udp_protocol __tcpip_protocol;

/**
 * Check if local UDP port is available
 *
 * @v port		Local port number
 * @ret port		Local port number, or negative error
 */
static int udp_port_available ( int port ) {
	struct udp_connection *udp;

	list_for_each_entry ( udp, &udp_conns, list ) {
		if ( udp->local.st_port == htons ( port ) )
			return -EADDRINUSE;
	}
	return port;
}

/**
 * Open a UDP connection
 *
 * @v xfer		Data transfer interface
 * @v peer		Peer socket address, or NULL
 * @v local		Local socket address, or NULL
 * @v promisc		Socket is promiscuous
 * @ret rc		Return status code
 */
static int udp_open_common ( struct interface *xfer,
			     struct sockaddr *peer, struct sockaddr *local,
			     int promisc ) {
	struct sockaddr_tcpip *st_peer = ( struct sockaddr_tcpip * ) peer;
	struct sockaddr_tcpip *st_local = ( struct sockaddr_tcpip * ) local;
	struct udp_connection *udp;
	int port;
	int rc;

	/* Allocate and initialise structure */
	udp = zalloc ( sizeof ( *udp ) );
	if ( ! udp )
		return -ENOMEM;
	DBGC ( udp, "UDP %p allocated\n", udp );
	ref_init ( &udp->refcnt, NULL );
	intf_init ( &udp->xfer, &udp_xfer_desc, &udp->refcnt );
	if ( st_peer )
		memcpy ( &udp->peer, st_peer, sizeof ( udp->peer ) );
	if ( st_local )
		memcpy ( &udp->local, st_local, sizeof ( udp->local ) );

	/* Bind to local port */
	if ( ! promisc ) {
		port = tcpip_bind ( st_local, udp_port_available );
		if ( port < 0 ) {
			rc = port;
			DBGC ( udp, "UDP %p could not bind: %s\n",
			       udp, strerror ( rc ) );
			goto err;
		}
		udp->local.st_port = htons ( port );
		DBGC ( udp, "UDP %p bound to port %d\n",
		       udp, ntohs ( udp->local.st_port ) );
	}

	/* Attach parent interface, transfer reference to connection
	 * list and return
	 */
	intf_plug_plug ( &udp->xfer, xfer );
	list_add ( &udp->list, &udp_conns );
	return 0;

 err:
	ref_put ( &udp->refcnt );
	return rc;
}

/**
 * Open a UDP connection
 *
 * @v xfer		Data transfer interface
 * @v peer		Peer socket address
 * @v local		Local socket address, or NULL
 * @ret rc		Return status code
 */
int udp_open ( struct interface *xfer, struct sockaddr *peer,
	       struct sockaddr *local ) {
	return udp_open_common ( xfer, peer, local, 0 );
}

/**
 * Open a promiscuous UDP connection
 *
 * @v xfer		Data transfer interface
 * @ret rc		Return status code
 *
 * Promiscuous UDP connections are required in order to support the
 * PXE API.
 */
int udp_open_promisc ( struct interface *xfer ) {
	return udp_open_common ( xfer, NULL, NULL, 1 );
}

/**
 * Close a UDP connection
 *
 * @v udp		UDP connection
 * @v rc		Reason for close
 */
static void udp_close ( struct udp_connection *udp, int rc ) {

	/* Close data transfer interface */
	intf_shutdown ( &udp->xfer, rc );

	/* Remove from list of connections and drop list's reference */
	list_del ( &udp->list );
	ref_put ( &udp->refcnt );

	DBGC ( udp, "UDP %p closed\n", udp );
}

/**
 * Transmit data via a UDP connection to a specified address
 *
 * @v udp		UDP connection
 * @v iobuf		I/O buffer
 * @v src		Source address, or NULL to use default
 * @v dest		Destination address, or NULL to use default
 * @v netdev		Network device, or NULL to use default
 * @ret rc		Return status code
 */
static int udp_tx ( struct udp_connection *udp, struct io_buffer *iobuf,
		    struct sockaddr_tcpip *src, struct sockaddr_tcpip *dest,
		    struct net_device *netdev ) {
       	struct udp_header *udphdr;
	size_t len;
	int rc;

	/* Check we can accommodate the header */
	if ( ( rc = iob_ensure_headroom ( iobuf,
					  MAX_LL_NET_HEADER_LEN ) ) != 0 ) {
		free_iob ( iobuf );
		return rc;
	}

	/* Fill in default values if not explicitly provided */
	if ( ! src )
		src = &udp->local;
	if ( ! dest )
		dest = &udp->peer;

	/* Add the UDP header */
	udphdr = iob_push ( iobuf, sizeof ( *udphdr ) );
	len = iob_len ( iobuf );
	udphdr->dest = dest->st_port;
	udphdr->src = src->st_port;
	udphdr->len = htons ( len );
	udphdr->chksum = 0;
	udphdr->chksum = tcpip_chksum ( udphdr, len );

	/* Dump debugging information */
	DBGC2 ( udp, "UDP %p TX %d->%d len %d\n", udp,
		ntohs ( udphdr->src ), ntohs ( udphdr->dest ),
		ntohs ( udphdr->len ) );

	/* Send it to the next layer for processing */
	if ( ( rc = tcpip_tx ( iobuf, &udp_protocol, src, dest, netdev,
			       &udphdr->chksum ) ) != 0 ) {
		DBGC ( udp, "UDP %p could not transmit packet: %s\n",
		       udp, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Identify UDP connection by local address
 *
 * @v local		Local address
 * @ret udp		UDP connection, or NULL
 */
static struct udp_connection * udp_demux ( struct sockaddr_tcpip *local ) {
	static const struct sockaddr_tcpip empty_sockaddr = { .pad = { 0, } };
	struct udp_connection *udp;

	list_for_each_entry ( udp, &udp_conns, list ) {
		if ( ( ( udp->local.st_family == local->st_family ) ||
		       ( udp->local.st_family == 0 ) ) &&
		     ( ( udp->local.st_port == local->st_port ) ||
		       ( udp->local.st_port == 0 ) ) &&
		     ( ( memcmp ( udp->local.pad, local->pad,
				  sizeof ( udp->local.pad ) ) == 0 ) ||
		       ( memcmp ( udp->local.pad, empty_sockaddr.pad,
				  sizeof ( udp->local.pad ) ) == 0 ) ) ) {
			return udp;
		}
	}
	return NULL;
}

/**
 * Process a received packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v st_src		Partially-filled source address
 * @v st_dest		Partially-filled destination address
 * @v pshdr_csum	Pseudo-header checksum
 * @ret rc		Return status code
 */
static int udp_rx ( struct io_buffer *iobuf,
		    struct net_device *netdev __unused,
		    struct sockaddr_tcpip *st_src,
		    struct sockaddr_tcpip *st_dest, uint16_t pshdr_csum ) {
	struct udp_header *udphdr = iobuf->data;
	struct udp_connection *udp;
	struct xfer_metadata meta;
	size_t ulen;
	unsigned int csum;
	int rc = 0;

	/* Sanity check packet */
	if ( iob_len ( iobuf ) < sizeof ( *udphdr ) ) {
		DBG ( "UDP packet too short at %zd bytes (min %zd bytes)\n",
		      iob_len ( iobuf ), sizeof ( *udphdr ) );
		
		rc = -EINVAL;
		goto done;
	}
	ulen = ntohs ( udphdr->len );
	if ( ulen < sizeof ( *udphdr ) ) {
		DBG ( "UDP length too short at %zd bytes "
		      "(header is %zd bytes)\n", ulen, sizeof ( *udphdr ) );
		rc = -EINVAL;
		goto done;
	}
	if ( ulen > iob_len ( iobuf ) ) {
		DBG ( "UDP length too long at %zd bytes (packet is %zd "
		      "bytes)\n", ulen, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto done;
	}
	if ( udphdr->chksum ) {
		csum = tcpip_continue_chksum ( pshdr_csum, iobuf->data, ulen );
		if ( csum != 0 ) {
			DBG ( "UDP checksum incorrect (is %04x including "
			      "checksum field, should be 0000)\n", csum );
			rc = -EINVAL;
			goto done;
		}
	}

	/* Parse parameters from header and strip header */
	st_src->st_port = udphdr->src;
	st_dest->st_port = udphdr->dest;
	udp = udp_demux ( st_dest );
	iob_unput ( iobuf, ( iob_len ( iobuf ) - ulen ) );
	iob_pull ( iobuf, sizeof ( *udphdr ) );

	/* Dump debugging information */
	DBGC2 ( udp, "UDP %p RX %d<-%d len %zd\n", udp,
		ntohs ( udphdr->dest ), ntohs ( udphdr->src ), ulen );

	/* Ignore if no matching connection found */
	if ( ! udp ) {
		DBG ( "No UDP connection listening on port %d\n",
		      ntohs ( udphdr->dest ) );
		rc = -ENOTCONN;
		goto done;
	}

	/* Pass data to application */
	memset ( &meta, 0, sizeof ( meta ) );
	meta.src = ( struct sockaddr * ) st_src;
	meta.dest = ( struct sockaddr * ) st_dest;
	rc = xfer_deliver ( &udp->xfer, iob_disown ( iobuf ), &meta );

 done:
	free_iob ( iobuf );
	return rc;
}

struct tcpip_protocol udp_protocol __tcpip_protocol = {
	.name = "UDP",
	.rx = udp_rx,
	.tcpip_proto = IP_UDP,
};

/***************************************************************************
 *
 * Data transfer interface
 *
 ***************************************************************************
 */

/**
 * Allocate I/O buffer for UDP
 *
 * @v udp		UDP connection
 * @v len		Payload size
 * @ret iobuf		I/O buffer, or NULL
 */
static struct io_buffer * udp_xfer_alloc_iob ( struct udp_connection *udp,
					       size_t len ) {
	struct io_buffer *iobuf;

	iobuf = alloc_iob ( MAX_LL_NET_HEADER_LEN + len );
	if ( ! iobuf ) {
		DBGC ( udp, "UDP %p cannot allocate buffer of length %zd\n",
		       udp, len );
		return NULL;
	}
	iob_reserve ( iobuf, MAX_LL_NET_HEADER_LEN );
	return iobuf;
}

/**
 * Deliver datagram as I/O buffer
 *
 * @v udp		UDP connection
 * @v iobuf		Datagram I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int udp_xfer_deliver ( struct udp_connection *udp,
			      struct io_buffer *iobuf,
			      struct xfer_metadata *meta ) {

	/* Transmit data, if possible */
	return udp_tx ( udp, iobuf, ( ( struct sockaddr_tcpip * ) meta->src ),
			( ( struct sockaddr_tcpip * ) meta->dest ),
			meta->netdev );
}

/** UDP data transfer interface operations */
static struct interface_operation udp_xfer_operations[] = {
	INTF_OP ( xfer_deliver, struct udp_connection *, udp_xfer_deliver ),
	INTF_OP ( xfer_alloc_iob, struct udp_connection *, udp_xfer_alloc_iob ),
	INTF_OP ( intf_close, struct udp_connection *, udp_close ),
};

/** UDP data transfer interface descriptor */
static struct interface_descriptor udp_xfer_desc =
	INTF_DESC ( struct udp_connection, xfer, udp_xfer_operations );

/***************************************************************************
 *
 * Openers
 *
 ***************************************************************************
 */

/** UDP IPv4 socket opener */
struct socket_opener udp_ipv4_socket_opener __socket_opener = {
	.semantics	= UDP_SOCK_DGRAM,
	.family		= AF_INET,
	.open		= udp_open,
};

/** UDP IPv6 socket opener */
struct socket_opener udp_ipv6_socket_opener __socket_opener = {
	.semantics	= UDP_SOCK_DGRAM,
	.family		= AF_INET6,
	.open		= udp_open,
};

/** Linkage hack */
int udp_sock_dgram = UDP_SOCK_DGRAM;

/**
 * Open UDP URI
 *
 * @v xfer		Data transfer interface
 * @v uri		URI
 * @ret rc		Return status code
 */
static int udp_open_uri ( struct interface *xfer, struct uri *uri ) {
	struct sockaddr_tcpip peer;

	/* Sanity check */
	if ( ! uri->host )
		return -EINVAL;

	memset ( &peer, 0, sizeof ( peer ) );
	peer.st_port = htons ( uri_port ( uri, 0 ) );
	return xfer_open_named_socket ( xfer, SOCK_DGRAM,
					( struct sockaddr * ) &peer,
					uri->host, NULL );
}

/** UDP URI opener */
struct uri_opener udp_uri_opener __uri_opener = {
	.scheme		= "udp",
	.open		= udp_open_uri,
};
