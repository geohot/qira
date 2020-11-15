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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ipxe/iobuf.h>
#include <ipxe/retry.h>
#include <ipxe/timer.h>
#include <ipxe/malloc.h>
#include <ipxe/neighbour.h>

/** @file
 *
 * Neighbour discovery
 *
 * This file implements the abstract functions of neighbour discovery,
 * independent of the underlying network protocol (e.g. ARP or NDP).
 *
 */

/** Neighbour discovery minimum timeout */
#define NEIGHBOUR_MIN_TIMEOUT ( TICKS_PER_SEC / 8 )

/** Neighbour discovery maximum timeout */
#define NEIGHBOUR_MAX_TIMEOUT ( TICKS_PER_SEC * 3 )

/** The neighbour cache */
struct list_head neighbours = LIST_HEAD_INIT ( neighbours );

static void neighbour_expired ( struct retry_timer *timer, int over );

/**
 * Free neighbour cache entry
 *
 * @v refcnt		Reference count
 */
static void neighbour_free ( struct refcnt *refcnt ) {
	struct neighbour *neighbour =
		container_of ( refcnt, struct neighbour, refcnt );

	/* Sanity check */
	assert ( list_empty ( &neighbour->tx_queue ) );

	/* Drop reference to network device */
	netdev_put ( neighbour->netdev );

	/* Free neighbour */
	free ( neighbour );
}

/**
 * Create neighbour cache entry
 *
 * @v netdev		Network device
 * @v net_protocol	Network-layer protocol
 * @v net_dest		Destination network-layer address
 * @ret neighbour	Neighbour cache entry, or NULL if allocation failed
 */
static struct neighbour * neighbour_create ( struct net_device *netdev,
					     struct net_protocol *net_protocol,
					     const void *net_dest ) {
	struct neighbour *neighbour;

	/* Allocate and initialise entry */
	neighbour = zalloc ( sizeof ( *neighbour ) );
	if ( ! neighbour )
		return NULL;
	ref_init ( &neighbour->refcnt, neighbour_free );
	neighbour->netdev = netdev_get ( netdev );
	neighbour->net_protocol = net_protocol;
	memcpy ( neighbour->net_dest, net_dest,
		 net_protocol->net_addr_len );
	timer_init ( &neighbour->timer, neighbour_expired, &neighbour->refcnt );
	set_timer_limits ( &neighbour->timer, NEIGHBOUR_MIN_TIMEOUT,
			   NEIGHBOUR_MAX_TIMEOUT );
	INIT_LIST_HEAD ( &neighbour->tx_queue );

	/* Transfer ownership to cache */
	list_add ( &neighbour->list, &neighbours );

	DBGC ( neighbour, "NEIGHBOUR %s %s %s created\n", netdev->name,
	       net_protocol->name, net_protocol->ntoa ( net_dest ) );
	return neighbour;
}

/**
 * Find neighbour cache entry
 *
 * @v netdev		Network device
 * @v net_protocol	Network-layer protocol
 * @v net_dest		Destination network-layer address
 * @ret neighbour	Neighbour cache entry, or NULL if not found
 */
static struct neighbour * neighbour_find ( struct net_device *netdev,
					   struct net_protocol *net_protocol,
					   const void *net_dest ) {
	struct neighbour *neighbour;

	list_for_each_entry ( neighbour, &neighbours, list ) {
		if ( ( neighbour->netdev == netdev ) &&
		     ( neighbour->net_protocol == net_protocol ) &&
		     ( memcmp ( neighbour->net_dest, net_dest,
				net_protocol->net_addr_len ) == 0 ) ) {

			/* Move to start of cache */
			list_del ( &neighbour->list );
			list_add ( &neighbour->list, &neighbours );

			return neighbour;
		}
	}
	return NULL;
}

/**
 * Start neighbour discovery
 *
 * @v neighbour		Neighbour cache entry
 * @v discovery		Neighbour discovery protocol
 * @v net_source	Source network-layer address
 */
static void neighbour_discover ( struct neighbour *neighbour,
				 struct neighbour_discovery *discovery,
				 const void *net_source ) {
	struct net_device *netdev = neighbour->netdev;
	struct net_protocol *net_protocol = neighbour->net_protocol;

	/* Record discovery protocol and source network-layer address */
	neighbour->discovery = discovery;
	memcpy ( neighbour->net_source, net_source,
		 net_protocol->net_addr_len );

	/* Start timer to trigger neighbour discovery */
	start_timer_nodelay ( &neighbour->timer );

	DBGC ( neighbour, "NEIGHBOUR %s %s %s discovering via %s\n",
	       netdev->name, net_protocol->name,
	       net_protocol->ntoa ( neighbour->net_dest ),
	       neighbour->discovery->name );
}

/**
 * Complete neighbour discovery
 *
 * @v neighbour		Neighbour cache entry
 * @v ll_dest		Destination link-layer address
 */
static void neighbour_discovered ( struct neighbour *neighbour,
				   const void *ll_dest ) {
	struct net_device *netdev = neighbour->netdev;
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	struct net_protocol *net_protocol = neighbour->net_protocol;
	struct io_buffer *iobuf;
	int rc;

	/* Fill in link-layer address */
	memcpy ( neighbour->ll_dest, ll_dest, ll_protocol->ll_addr_len );
	DBGC ( neighbour, "NEIGHBOUR %s %s %s is %s %s\n", netdev->name,
	       net_protocol->name, net_protocol->ntoa ( neighbour->net_dest ),
	       ll_protocol->name, ll_protocol->ntoa ( neighbour->ll_dest ) );

	/* Stop retransmission timer */
	stop_timer ( &neighbour->timer );

	/* Transmit any packets in queue.  Take out a temporary
	 * reference on the entry to prevent it from going out of
	 * scope during the call to net_tx().
	 */
	ref_get ( &neighbour->refcnt );
	while ( ( iobuf = list_first_entry ( &neighbour->tx_queue,
					     struct io_buffer, list )) != NULL){
		DBGC2 ( neighbour, "NEIGHBOUR %s %s %s transmitting deferred "
			"packet\n", netdev->name, net_protocol->name,
			net_protocol->ntoa ( neighbour->net_dest ) );
		list_del ( &iobuf->list );
		if ( ( rc = net_tx ( iobuf, netdev, net_protocol, ll_dest,
				     netdev->ll_addr ) ) != 0 ) {
			DBGC ( neighbour, "NEIGHBOUR %s %s %s could not "
			       "transmit deferred packet: %s\n",
			       netdev->name, net_protocol->name,
			       net_protocol->ntoa ( neighbour->net_dest ),
			       strerror ( rc ) );
			/* Ignore error and continue */
		}
	}
	ref_put ( &neighbour->refcnt );
}

/**
 * Destroy neighbour cache entry
 *
 * @v neighbour		Neighbour cache entry
 * @v rc		Reason for destruction
 */
static void neighbour_destroy ( struct neighbour *neighbour, int rc ) {
	struct net_device *netdev = neighbour->netdev;
	struct net_protocol *net_protocol = neighbour->net_protocol;
	struct io_buffer *iobuf;

	/* Take ownership from cache */
	list_del ( &neighbour->list );

	/* Stop timer */
	stop_timer ( &neighbour->timer );

	/* Discard any outstanding I/O buffers */
	while ( ( iobuf = list_first_entry ( &neighbour->tx_queue,
					     struct io_buffer, list )) != NULL){
		DBGC2 ( neighbour, "NEIGHBOUR %s %s %s discarding deferred "
			"packet: %s\n", netdev->name, net_protocol->name,
			net_protocol->ntoa ( neighbour->net_dest ),
			strerror ( rc ) );
		list_del ( &iobuf->list );
		netdev_tx_err ( neighbour->netdev, iobuf, rc );
	}

	DBGC ( neighbour, "NEIGHBOUR %s %s %s destroyed: %s\n", netdev->name,
	       net_protocol->name, net_protocol->ntoa ( neighbour->net_dest ),
	       strerror ( rc ) );

	/* Drop remaining reference */
	ref_put ( &neighbour->refcnt );
}

/**
 * Handle neighbour timer expiry
 *
 * @v timer		Retry timer
 * @v fail		Failure indicator
 */
static void neighbour_expired ( struct retry_timer *timer, int fail ) {
	struct neighbour *neighbour =
		container_of ( timer, struct neighbour, timer );
	struct net_device *netdev = neighbour->netdev;
	struct net_protocol *net_protocol = neighbour->net_protocol;
	struct neighbour_discovery *discovery =
		neighbour->discovery;
	const void *net_dest = neighbour->net_dest;
	const void *net_source = neighbour->net_source;
	int rc;

	/* If we have failed, destroy the cache entry */
	if ( fail ) {
		neighbour_destroy ( neighbour, -ETIMEDOUT );
		return;
	}

	/* Restart the timer */
	start_timer ( &neighbour->timer );

	/* Transmit neighbour request */
	if ( ( rc = discovery->tx_request ( netdev, net_protocol, net_dest,
					    net_source ) ) != 0 ) {
		DBGC ( neighbour, "NEIGHBOUR %s %s %s could not transmit %s "
		       "request: %s\n", netdev->name, net_protocol->name,
		       net_protocol->ntoa ( neighbour->net_dest ),
		       neighbour->discovery->name, strerror ( rc ) );
		/* Retransmit when timer expires */
		return;
	}
}

/**
 * Transmit packet, determining link-layer address via neighbour discovery
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v discovery		Neighbour discovery protocol
 * @v net_protocol	Network-layer protocol
 * @v net_dest		Destination network-layer address
 * @v net_source	Source network-layer address
 * @v ll_source		Source link-layer address
 * @ret rc		Return status code
 */
int neighbour_tx ( struct io_buffer *iobuf, struct net_device *netdev,
		   struct net_protocol *net_protocol, const void *net_dest,
		   struct neighbour_discovery *discovery,
		   const void *net_source, const void *ll_source ) {
	struct neighbour *neighbour;

	/* Find or create neighbour cache entry */
	neighbour = neighbour_find ( netdev, net_protocol, net_dest );
	if ( ! neighbour ) {
		neighbour = neighbour_create ( netdev, net_protocol, net_dest );
		if ( ! neighbour )
			return -ENOMEM;
		neighbour_discover ( neighbour, discovery, net_source );
	}

	/* If a link-layer address is available then transmit
	 * immediately, otherwise queue for later transmission.
	 */
	if ( neighbour_has_ll_dest ( neighbour ) ) {
		return net_tx ( iobuf, netdev, net_protocol, neighbour->ll_dest,
				ll_source );
	} else {
		DBGC2 ( neighbour, "NEIGHBOUR %s %s %s deferring packet\n",
			netdev->name, net_protocol->name,
			net_protocol->ntoa ( net_dest ) );
		list_add_tail ( &iobuf->list, &neighbour->tx_queue );
		return 0;
	}
}

/**
 * Update existing neighbour cache entry
 *
 * @v netdev		Network device
 * @v net_protocol	Network-layer protocol
 * @v net_dest		Destination network-layer address
 * @v ll_dest		Destination link-layer address
 * @ret rc		Return status code
 */
int neighbour_update ( struct net_device *netdev,
		       struct net_protocol *net_protocol,
		       const void *net_dest, const void *ll_dest ) {
	struct neighbour *neighbour;

	/* Find neighbour cache entry */
	neighbour = neighbour_find ( netdev, net_protocol, net_dest );
	if ( ! neighbour )
		return -ENOENT;

	/* Set destination address */
	neighbour_discovered ( neighbour, ll_dest );

	return 0;
}

/**
 * Define neighbour cache entry
 *
 * @v netdev		Network device
 * @v net_protocol	Network-layer protocol
 * @v net_dest		Destination network-layer address
 * @v ll_dest		Destination link-layer address, if known
 * @ret rc		Return status code
 */
int neighbour_define ( struct net_device *netdev,
		       struct net_protocol *net_protocol,
		       const void *net_dest, const void *ll_dest ) {
	struct neighbour *neighbour;

	/* Find or create neighbour cache entry */
	neighbour = neighbour_find ( netdev, net_protocol, net_dest );
	if ( ! neighbour ) {
		neighbour = neighbour_create ( netdev, net_protocol, net_dest );
		if ( ! neighbour )
			return -ENOMEM;
	}

	/* Set destination address */
	neighbour_discovered ( neighbour, ll_dest );

	return 0;
}

/**
 * Update neighbour cache on network device state change or removal
 *
 * @v netdev		Network device
 */
static void neighbour_flush ( struct net_device *netdev ) {
	struct neighbour *neighbour;
	struct neighbour *tmp;

	/* Remove all neighbour cache entries when a network device is closed */
	if ( ! netdev_is_open ( netdev ) ) {
		list_for_each_entry_safe ( neighbour, tmp, &neighbours, list )
			neighbour_destroy ( neighbour, -ENODEV );
	}
}

/** Neighbour driver (for net device notifications) */
struct net_driver neighbour_net_driver __net_driver = {
	.name = "Neighbour",
	.notify = neighbour_flush,
	.remove = neighbour_flush,
};

/**
 * Discard some cached neighbour entries
 *
 * @ret discarded	Number of cached items discarded
 */
static unsigned int neighbour_discard ( void ) {
	struct neighbour *neighbour;

	/* Drop oldest cache entry, if any */
	neighbour = list_last_entry ( &neighbours, struct neighbour, list );
	if ( neighbour ) {
		neighbour_destroy ( neighbour, -ENOBUFS );
		return 1;
	} else {
		return 0;
	}
}

/**
 * Neighbour cache discarder
 *
 * Neighbour cache entries are deemed to have a high replacement cost,
 * since flushing an active neighbour cache entry midway through a TCP
 * transfer will cause substantial disruption.
 */
struct cache_discarder neighbour_discarder __cache_discarder (CACHE_EXPENSIVE)={
	.discard = neighbour_discard,
};
