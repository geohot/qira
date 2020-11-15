/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <errno.h>
#include <byteswap.h>
#include <ipxe/refcnt.h>
#include <ipxe/list.h>
#include <ipxe/iobuf.h>
#include <ipxe/tcpip.h>
#include <ipxe/icmp.h>
#include <ipxe/interface.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/netdevice.h>
#include <ipxe/ping.h>

/** @file
 *
 * ICMP ping protocol
 *
 */

/**
 * A ping connection
 *
 */
struct ping_connection {
	/** Reference counter */
	struct refcnt refcnt;
	/** List of ping connections */
	struct list_head list;

	/** Remote socket address */
	struct sockaddr_tcpip peer;
	/** Local port number */
	uint16_t port;

	/** Data transfer interface */
	struct interface xfer;
};

/** List of registered ping connections */
static LIST_HEAD ( ping_conns );

/**
 * Identify ping connection by local port number
 *
 * @v port		Local port number
 * @ret ping		Ping connection, or NULL
 */
static struct ping_connection * ping_demux ( unsigned int port ) {
	struct ping_connection *ping;

	list_for_each_entry ( ping, &ping_conns, list ) {
		if ( ping->port == port )
			return ping;
	}
	return NULL;
}

/**
 * Check if local port number is available
 *
 * @v port		Local port number
 * @ret port		Local port number, or negative error
 */
static int ping_port_available ( int port ) {

	return ( ping_demux ( port ) ? -EADDRINUSE : port );
}

/**
 * Process ICMP ping reply
 *
 * @v iobuf		I/O buffer
 * @v st_src		Source address
 * @ret rc		Return status code
 */
int ping_rx ( struct io_buffer *iobuf, struct sockaddr_tcpip *st_src ) {
	struct icmp_echo *echo = iobuf->data;
	struct ping_connection *ping;
	struct xfer_metadata meta;
	int rc;

	/* Sanity check: should already have been checked by ICMP layer */
	assert ( iob_len ( iobuf ) >= sizeof ( *echo ) );

	/* Identify connection */
	ping = ping_demux ( ntohs ( echo->ident ) );
	DBGC ( ping, "PING %p reply id %#04x seq %#04x\n",
	       ping, ntohs ( echo->ident ), ntohs ( echo->sequence ) );
	if ( ! ping ) {
		rc = -ENOTCONN;
		goto discard;
	}

	/* Strip header, construct metadata, and pass data to upper layer */
	iob_pull ( iobuf, sizeof ( *echo ) );
	memset ( &meta, 0, sizeof ( meta ) );
	meta.src = ( ( struct sockaddr * ) st_src );
	meta.flags = XFER_FL_ABS_OFFSET;
	meta.offset = ntohs ( echo->sequence );
	return xfer_deliver ( &ping->xfer, iob_disown ( iobuf ), &meta );

 discard:
	free_iob ( iobuf );
	return rc;
}

/**
 * Allocate I/O buffer for ping
 *
 * @v ping		Ping connection
 * @v len		Payload size
 * @ret iobuf		I/O buffer, or NULL
 */
static struct io_buffer *
ping_alloc_iob ( struct ping_connection *ping __unused, size_t len ) {
	size_t header_len;
	struct io_buffer *iobuf;

	header_len = ( MAX_LL_NET_HEADER_LEN + sizeof ( struct icmp_echo ) );
	iobuf = alloc_iob ( header_len + len );
	if ( iobuf )
		iob_reserve ( iobuf, header_len );
	return iobuf;
}

/**
 * Deliver datagram as I/O buffer
 *
 * @v ping		Ping connection
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int ping_deliver ( struct ping_connection *ping, struct io_buffer *iobuf,
			  struct xfer_metadata *meta ) {
	struct icmp_echo *echo = iob_push ( iobuf, sizeof ( *echo ) );
	int rc;

	/* Construct header */
	memset ( echo, 0, sizeof ( *echo ) );
	echo->ident = htons ( ping->port );
	echo->sequence = htons ( meta->offset );

	/* Transmit echo request */
	if ( ( rc = icmp_tx_echo_request ( iob_disown ( iobuf ),
					   &ping->peer ) ) != 0 ) {
		DBGC ( ping, "PING %p could not transmit: %s\n",
		       ping, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Close ping connection
 *
 * @v ping		Ping connection
 * @v rc		Reason for close
 */
static void ping_close ( struct ping_connection *ping, int rc ) {

	/* Close data transfer interface */
	intf_shutdown ( &ping->xfer, rc );

	/* Remove from list of connections and drop list's reference */
	list_del ( &ping->list );
	ref_put ( &ping->refcnt );

	DBGC ( ping, "PING %p closed\n", ping );
}

/** Ping data transfer interface operations */
static struct interface_operation ping_xfer_operations[] = {
	INTF_OP ( xfer_deliver, struct ping_connection *, ping_deliver ),
	INTF_OP ( xfer_alloc_iob, struct ping_connection *, ping_alloc_iob ),
	INTF_OP ( intf_close, struct ping_connection *, ping_close ),
};

/** Ping data transfer interface descriptor */
static struct interface_descriptor ping_xfer_desc =
	INTF_DESC ( struct ping_connection, xfer, ping_xfer_operations );

/**
 * Open a ping connection
 *
 * @v xfer		Data transfer interface
 * @v peer		Peer socket address
 * @v local		Local socket address, or NULL
 * @ret rc		Return status code
 */
static int ping_open ( struct interface *xfer, struct sockaddr *peer,
		       struct sockaddr *local ) {
	struct sockaddr_tcpip *st_peer = ( struct sockaddr_tcpip * ) peer;
	struct sockaddr_tcpip *st_local = ( struct sockaddr_tcpip * ) local;
	struct ping_connection *ping;
	int port;
	int rc;

	/* Allocate and initialise structure */
	ping = zalloc ( sizeof ( *ping ) );
	if ( ! ping ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	DBGC ( ping, "PING %p allocated\n", ping );
	ref_init ( &ping->refcnt, NULL );
	intf_init ( &ping->xfer, &ping_xfer_desc, &ping->refcnt );
	memcpy ( &ping->peer, st_peer, sizeof ( ping->peer ) );

	/* Bind to local port */
	port = tcpip_bind ( st_local, ping_port_available );
	if ( port < 0 ) {
		rc = port;
		DBGC ( ping, "PING %p could not bind: %s\n",
		       ping, strerror ( rc ) );
		goto err_bind;
	}
	ping->port = port;
	DBGC ( ping, "PING %p bound to id %#04x\n", ping, port );

	/* Attach parent interface, transfer reference to connection
	 * list, and return
	 */
	intf_plug_plug ( &ping->xfer, xfer );
	list_add ( &ping->list, &ping_conns );
	return 0;

 err_bind:
	ref_put ( &ping->refcnt );
 err_alloc:
	return rc;
}

/** Ping IPv4 socket opener */
struct socket_opener ping_ipv4_socket_opener __socket_opener = {
	.semantics	= PING_SOCK_ECHO,
	.family		= AF_INET,
	.open		= ping_open,
};

/** Ping IPv6 socket opener */
struct socket_opener ping_ipv6_socket_opener __socket_opener = {
	.semantics	= PING_SOCK_ECHO,
	.family		= AF_INET6,
	.open		= ping_open,
};

/** Linkage hack */
int ping_sock_echo = PING_SOCK_ECHO;
