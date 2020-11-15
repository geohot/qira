/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
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

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/xfer.h>
#include <ipxe/iobuf.h>
#include <ipxe/open.h>
#include <ipxe/tcpip.h>
#include <ipxe/uuid.h>
#include <ipxe/base16.h>
#include <ipxe/netdevice.h>
#include <ipxe/timer.h>
#include <ipxe/fault.h>
#include <ipxe/pccrd.h>
#include <ipxe/peerdisc.h>

/** @file
 *
 * Peer Content Caching and Retrieval (PeerDist) protocol peer discovery
 *
 */

/** List of discovery segments */
static LIST_HEAD ( peerdisc_segments );

/** Number of repeated discovery attempts */
#define PEERDISC_REPEAT_COUNT 2

/** Time between repeated discovery attempts */
#define PEERDISC_REPEAT_TIMEOUT ( 1 * TICKS_PER_SEC )

/** Default discovery timeout (in seconds) */
#define PEERDISC_DEFAULT_TIMEOUT_SECS 2

/** Recommended discovery timeout (in seconds)
 *
 * We reduce the recommended discovery timeout whenever a segment
 * fails to discover any peers, and restore the default value whenever
 * a valid discovery reply is received.  We continue to send discovery
 * requests even if the recommended timeout is reduced to zero.
 *
 * This strategy is intended to minimise discovery delays when no
 * peers are available on the network, while allowing downloads to
 * quickly switch back to using PeerDist acceleration if new peers
 * become available.
 */
unsigned int peerdisc_timeout_secs = PEERDISC_DEFAULT_TIMEOUT_SECS;

static struct peerdisc_segment * peerdisc_find ( const char *id );
static int peerdisc_discovered ( struct peerdisc_segment *segment,
				 const char *location );

/******************************************************************************
 *
 * Discovery sockets
 *
 ******************************************************************************
 */

/**
 * Open all PeerDist discovery sockets
 *
 * @ret rc		Return status code
 */
static int peerdisc_socket_open ( void ) {
	struct peerdisc_socket *socket;
	int rc;

	/* Open each socket */
	for_each_table_entry ( socket, PEERDISC_SOCKETS ) {
		if ( ( rc = xfer_open_socket ( &socket->xfer, SOCK_DGRAM,
					       &socket->address.sa,
					       NULL ) ) != 0 ) {
			DBGC ( socket, "PEERDISC %s could not open socket: "
			       "%s\n", socket->name, strerror ( rc ) );
			goto err;
		}
	}

	return 0;

 err:
	for_each_table_entry_continue_reverse ( socket, PEERDISC_SOCKETS )
		intf_restart ( &socket->xfer, rc );
	return rc;
}

/**
 * Attempt to transmit PeerDist discovery requests on all sockets
 *
 * @v uuid		Message UUID string
 * @v id		Segment identifier string
 */
static void peerdisc_socket_tx ( const char *uuid, const char *id ) {
	struct peerdisc_socket *socket;
	struct net_device *netdev;
	struct xfer_metadata meta;
	union {
		struct sockaddr sa;
		struct sockaddr_tcpip st;
	} address;
	char *request;
	size_t len;
	int rc;

	/* Construct discovery request */
	request = peerdist_discovery_request ( uuid, id );
	if ( ! request )
		goto err_request;
	len = strlen ( request );

	/* Initialise data transfer metadata */
	memset ( &meta, 0, sizeof ( meta ) );
	meta.dest = &address.sa;

	/* Send message on each socket */
	for_each_table_entry ( socket, PEERDISC_SOCKETS ) {

		/* Initialise socket address */
		memcpy ( &address.sa, &socket->address.sa,
			 sizeof ( address.sa ) );

		/* Send message on each open network device */
		for_each_netdev ( netdev ) {

			/* Skip unopened network devices */
			if ( ! netdev_is_open ( netdev ) )
				continue;
			address.st.st_scope_id = netdev->index;

			/* Discard request (for test purposes) if applicable */
			if ( inject_fault ( PEERDISC_DISCARD_RATE ) )
				continue;

			/* Transmit request */
			if ( ( rc = xfer_deliver_raw_meta ( &socket->xfer,
							    request, len,
							    &meta ) ) != 0 ) {
				DBGC ( socket, "PEERDISC %s could not transmit "
				       "via %s: %s\n", socket->name,
				       netdev->name, strerror ( rc ) );
				/* Contine to try other net devices/sockets */
				continue;
			}
		}
	}

	free ( request );
 err_request:
	return;
}

/**
 * Handle received PeerDist discovery reply
 *
 * @v socket		PeerDist discovery socket
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int peerdisc_socket_rx ( struct peerdisc_socket *socket,
				struct io_buffer *iobuf,
				struct xfer_metadata *meta __unused ) {
	struct peerdist_discovery_reply reply;
	struct peerdisc_segment *segment;
	char *id;
	char *location;
	int rc;

	/* Discard reply (for test purposes) if applicable */
	if ( ( rc = inject_fault ( PEERDISC_DISCARD_RATE ) ) != 0 )
		goto err;

	/* Parse reply */
	if ( ( rc = peerdist_discovery_reply ( iobuf->data, iob_len ( iobuf ),
					       &reply ) ) != 0 ) {
		DBGC ( socket, "PEERDISC %s could not parse reply: %s\n",
		       socket->name, strerror ( rc ) );
		DBGC_HDA ( socket, 0, iobuf->data, iob_len ( iobuf ) );
		goto err;
	}

	/* Any kind of discovery reply indicates that there are active
	 * peers on a local network, so restore the recommended
	 * discovery timeout to its default value for future requests.
	 */
	if ( peerdisc_timeout_secs != PEERDISC_DEFAULT_TIMEOUT_SECS ) {
		DBGC ( socket, "PEERDISC %s restoring timeout to %d seconds\n",
		       socket->name, PEERDISC_DEFAULT_TIMEOUT_SECS );
	}
	peerdisc_timeout_secs = PEERDISC_DEFAULT_TIMEOUT_SECS;

	/* Iterate over segment IDs */
	for ( id = reply.ids ; *id ; id += ( strlen ( id ) + 1 /* NUL */ ) ) {

		/* Find corresponding segment */
		segment = peerdisc_find ( id );
		if ( ! segment ) {
			DBGC ( socket, "PEERDISC %s ignoring reply for %s\n",
			       socket->name, id );
			continue;
		}

		/* Report all discovered peer locations */
		for ( location = reply.locations ; *location ;
		      location += ( strlen ( location ) + 1 /* NUL */ ) ) {

			/* Report discovered peer location */
			if ( ( rc = peerdisc_discovered ( segment,
							  location ) ) != 0 )
				goto err;
		}
	}

 err:
	free_iob ( iobuf );
	return rc;
}

/**
 * Close all PeerDist discovery sockets
 *
 * @v rc		Reason for close
 */
static void peerdisc_socket_close ( int rc ) {
	struct peerdisc_socket *socket;

	/* Close all sockets */
	for_each_table_entry ( socket, PEERDISC_SOCKETS )
		intf_restart ( &socket->xfer, rc );
}

/** PeerDist discovery socket interface operations */
static struct interface_operation peerdisc_socket_operations[] = {
	INTF_OP ( xfer_deliver, struct peerdisc_socket *, peerdisc_socket_rx ),
};

/** PeerDist discovery socket interface descriptor */
static struct interface_descriptor peerdisc_socket_desc =
	INTF_DESC ( struct peerdisc_socket, xfer, peerdisc_socket_operations );

/** PeerDist discovery IPv4 socket */
struct peerdisc_socket peerdisc_socket_ipv4 __peerdisc_socket = {
	.name = "IPv4",
	.address = {
		.sin = {
			.sin_family = AF_INET,
			.sin_port = htons ( PEERDIST_DISCOVERY_PORT ),
			.sin_addr.s_addr = htonl ( PEERDIST_DISCOVERY_IPV4 ),
		},
	},
	.xfer = INTF_INIT ( peerdisc_socket_desc ),
};

/** PeerDist discovery IPv6 socket */
struct peerdisc_socket peerdisc_socket_ipv6 __peerdisc_socket = {
	.name = "IPv6",
	.address = {
		.sin6 = {
			.sin6_family = AF_INET6,
			.sin6_port = htons ( PEERDIST_DISCOVERY_PORT ),
			.sin6_addr.s6_addr = PEERDIST_DISCOVERY_IPV6,
		},
	},
	.xfer = INTF_INIT ( peerdisc_socket_desc ),
};

/******************************************************************************
 *
 * Discovery segments
 *
 ******************************************************************************
 */

/**
 * Free PeerDist discovery segment
 *
 * @v refcnt		Reference count
 */
static void peerdisc_free ( struct refcnt *refcnt ) {
	struct peerdisc_segment *segment =
		container_of ( refcnt, struct peerdisc_segment, refcnt );
	struct peerdisc_peer *peer;
	struct peerdisc_peer *tmp;

	/* Free all discovered peers */
	list_for_each_entry_safe ( peer, tmp, &segment->peers, list ) {
		list_del ( &peer->list );
		free ( peer );
	}

	/* Free segment */
	free ( segment );
}

/**
 * Find PeerDist discovery segment
 *
 * @v id		Segment ID
 * @ret segment		PeerDist discovery segment, or NULL if not found
 */
static struct peerdisc_segment * peerdisc_find ( const char *id ) {
	struct peerdisc_segment *segment;

	/* Look for a matching segment */
	list_for_each_entry ( segment, &peerdisc_segments, list ) {
		if ( strcmp ( id, segment->id ) == 0 )
			return segment;
	}

	return NULL;
}

/**
 * Add discovered PeerDist peer
 *
 * @v segment		PeerDist discovery segment
 * @v location		Peer location
 * @ret rc		Return status code
 */
static int peerdisc_discovered ( struct peerdisc_segment *segment,
				 const char *location ) {
	struct peerdisc_peer *peer;
	struct peerdisc_client *peerdisc;
	struct peerdisc_client *tmp;

	/* Ignore duplicate peers */
	list_for_each_entry ( peer, &segment->peers, list ) {
		if ( strcmp ( peer->location, location ) == 0 ) {
			DBGC2 ( segment, "PEERDISC %p duplicate %s\n",
				segment, location );
			return 0;
		}
	}
	DBGC2 ( segment, "PEERDISC %p discovered %s\n", segment, location );

	/* Allocate and initialise structure */
	peer = zalloc ( sizeof ( *peer ) + strlen ( location ) + 1 /* NUL */ );
	if ( ! peer )
		return -ENOMEM;
	strcpy ( peer->location, location );

	/* Add to end of list of peers */
	list_add_tail ( &peer->list, &segment->peers );

	/* Notify all clients */
	list_for_each_entry_safe ( peerdisc, tmp, &segment->clients, list )
		peerdisc->op->discovered ( peerdisc );

	return 0;
}

/**
 * Handle discovery timer expiry
 *
 * @v timer		Discovery timer
 * @v over		Failure indicator
 */
static void peerdisc_expired ( struct retry_timer *timer, int over __unused ) {
	struct peerdisc_segment *segment =
		container_of ( timer, struct peerdisc_segment, timer );

	/* Attempt to transmit discovery requests */
	peerdisc_socket_tx ( segment->uuid, segment->id );

	/* Schedule next transmission, if applicable */
	if ( timer->count < PEERDISC_REPEAT_COUNT )
		start_timer_fixed ( &segment->timer, PEERDISC_REPEAT_TIMEOUT );
}

/**
 * Create PeerDist discovery segment
 *
 * @v id		Segment ID
 * @ret segment		PeerDist discovery segment, or NULL on error
 */
static struct peerdisc_segment * peerdisc_create ( const char *id ) {
	struct peerdisc_segment *segment;
	union {
		union uuid uuid;
		uint32_t dword[ sizeof ( union uuid ) / sizeof ( uint32_t ) ];
	} random_uuid;
	size_t uuid_len;
	size_t id_len;
	char *uuid;
	char *uuid_copy;
	char *id_copy;
	unsigned int i;

	/* Generate a random message UUID.  This does not require high
	 * quality randomness.
	 */
	for ( i = 0 ; i < ( sizeof ( random_uuid.dword ) /
			    sizeof ( random_uuid.dword[0] ) ) ; i++ )
		random_uuid.dword[i] = random();
	uuid = uuid_ntoa ( &random_uuid.uuid );

	/* Calculate string lengths */
	id_len = ( strlen ( id ) + 1 /* NUL */ );
	uuid_len = ( strlen ( uuid ) + 1 /* NUL */ );

	/* Allocate and initialise structure */
	segment = zalloc ( sizeof ( *segment ) + id_len + uuid_len );
	if ( ! segment )
		return NULL;
	id_copy = ( ( ( void * ) segment ) + sizeof ( *segment ) );
	memcpy ( id_copy, id, id_len );
	uuid_copy = ( ( ( void * ) id_copy ) + id_len );
	memcpy ( uuid_copy, uuid, uuid_len );
	ref_init ( &segment->refcnt, peerdisc_free );
	segment->id = id_copy;
	segment->uuid = uuid_copy;
	INIT_LIST_HEAD ( &segment->peers );
	INIT_LIST_HEAD ( &segment->clients );
	timer_init ( &segment->timer, peerdisc_expired, &segment->refcnt );
	DBGC2 ( segment, "PEERDISC %p discovering %s\n", segment, segment->id );

	/* Start discovery timer */
	start_timer_nodelay ( &segment->timer );

	/* Add to list of segments, transfer reference to list, and return */
	list_add_tail ( &segment->list, &peerdisc_segments );
	return segment;
}

/**
 * Destroy PeerDist discovery segment
 *
 * @v segment		PeerDist discovery segment
 */
static void peerdisc_destroy ( struct peerdisc_segment *segment ) {

	/* Sanity check */
	assert ( list_empty ( &segment->clients ) );

	/* Stop timer */
	stop_timer ( &segment->timer );

	/* Remove from list of segments and drop list's reference */
	list_del ( &segment->list );
	ref_put ( &segment->refcnt );
}

/******************************************************************************
 *
 * Discovery clients
 *
 ******************************************************************************
 */

/**
 * Open PeerDist discovery client
 *
 * @v peerdisc		PeerDist discovery client
 * @v id		Segment ID
 * @v len		Length of segment ID
 * @ret rc		Return status code
 */
int peerdisc_open ( struct peerdisc_client *peerdisc, const void *id,
		    size_t len ) {
	struct peerdisc_segment *segment;
	char id_string[ base16_encoded_len ( len ) + 1 /* NUL */ ];
	char *id_chr;
	int rc;

	/* Construct ID string */
	base16_encode ( id, len, id_string, sizeof ( id_string ) );
	for ( id_chr = id_string ; *id_chr ; id_chr++ )
		*id_chr = toupper ( *id_chr );

	/* Sanity check */
	assert ( peerdisc->segment == NULL );

	/* Open socket if this is the first segment */
	if ( list_empty ( &peerdisc_segments ) &&
	     ( ( rc = peerdisc_socket_open() ) != 0 ) )
		return rc;

	/* Find or create segment */
	if ( ! ( ( segment = peerdisc_find ( id_string ) ) ||
		 ( segment = peerdisc_create ( id_string ) ) ) )
		return -ENOMEM;

	/* Add to list of clients */
	ref_get ( &segment->refcnt );
	peerdisc->segment = segment;
	list_add_tail ( &peerdisc->list, &segment->clients );

	return 0;
}

/**
 * Close PeerDist discovery client
 *
 * @v peerdisc		PeerDist discovery client
 */
void peerdisc_close ( struct peerdisc_client *peerdisc ) {
	struct peerdisc_segment *segment = peerdisc->segment;

	/* Ignore if discovery is already closed */
	if ( ! segment )
		return;

	/* If no peers were discovered, reduce the recommended
	 * discovery timeout to minimise delays on future requests.
	 */
	if ( list_empty ( &segment->peers ) && peerdisc_timeout_secs ) {
		peerdisc_timeout_secs--;
		DBGC ( segment, "PEERDISC %p reducing timeout to %d "
		       "seconds\n", peerdisc, peerdisc_timeout_secs );
	}

	/* Remove from list of clients */
	peerdisc->segment = NULL;
	list_del ( &peerdisc->list );
	ref_put ( &segment->refcnt );

	/* If this was the last clients, destroy the segment */
	if ( list_empty ( &segment->clients ) )
		peerdisc_destroy ( segment );

	/* If there are no more segments, close the socket */
	if ( list_empty ( &peerdisc_segments ) )
		peerdisc_socket_close ( 0 );
}
