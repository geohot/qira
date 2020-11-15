/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <ipxe/netdevice.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/malloc.h>
#include <ipxe/base16.h>
#include <ipxe/xen.h>
#include <ipxe/xenstore.h>
#include <ipxe/xenbus.h>
#include <ipxe/xengrant.h>
#include <ipxe/xenevent.h>
#include "netfront.h"

/** @file
 *
 * Xen netfront driver
 *
 */

/* Disambiguate the various error causes */
#define EIO_NETIF_RSP_ERROR						\
	__einfo_error ( EINFO_EIO_NETIF_RSP_ERROR )
#define EINFO_EIO_NETIF_RSP_ERROR					\
	__einfo_uniqify ( EINFO_EIO, -NETIF_RSP_ERROR,			\
			  "Unspecified network error" )
#define EIO_NETIF_RSP_DROPPED						\
	__einfo_error ( EINFO_EIO_NETIF_RSP_DROPPED )
#define EINFO_EIO_NETIF_RSP_DROPPED					\
	__einfo_uniqify ( EINFO_EIO, -NETIF_RSP_DROPPED,		\
			  "Packet dropped" )
#define EIO_NETIF_RSP( status )						\
	EUNIQ ( EINFO_EIO, -(status),					\
		EIO_NETIF_RSP_ERROR, EIO_NETIF_RSP_DROPPED )

/******************************************************************************
 *
 * XenStore interface
 *
 ******************************************************************************
 */

/**
 * Reset device
 *
 * @v netfront		Netfront device
 * @ret rc		Return status code
 */
static int netfront_reset ( struct netfront_nic *netfront ) {
	struct xen_device *xendev = netfront->xendev;
	int state;
	int rc;

	/* Get current backend state */
	if ( ( state = xenbus_backend_state ( xendev ) ) < 0 ) {
		rc = state;
		DBGC ( netfront, "NETFRONT %s could not read backend state: "
		       "%s\n", xendev->key, strerror ( rc ) );
		return rc;
	}

	/* If the backend is not already in InitWait, then mark
	 * frontend as Closed to shut down the backend.
	 */
	if ( state != XenbusStateInitWait ) {

		/* Set state to Closed */
		xenbus_set_state ( xendev, XenbusStateClosed );

		/* Wait for backend to reach Closed */
		if ( ( rc = xenbus_backend_wait ( xendev,
						  XenbusStateClosed ) ) != 0 ) {
			DBGC ( netfront, "NETFRONT %s backend did not reach "
			       "Closed: %s\n", xendev->key, strerror ( rc ) );
			return rc;
		}
	}

	/* Reset state to Initialising */
	xenbus_set_state ( xendev, XenbusStateInitialising );

	/* Wait for backend to reach InitWait */
	if ( ( rc = xenbus_backend_wait ( xendev, XenbusStateInitWait ) ) != 0){
		DBGC ( netfront, "NETFRONT %s backend did not reach InitWait: "
		       "%s\n", xendev->key, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Fetch MAC address
 *
 * @v netfront		Netfront device
 * @v hw_addr		Hardware address to fill in
 * @ret rc		Return status code
 */
static int netfront_read_mac ( struct netfront_nic *netfront, void *hw_addr ) {
	struct xen_device *xendev = netfront->xendev;
	struct xen_hypervisor *xen = xendev->xen;
	char *mac;
	int len;
	int rc;

	/* Fetch MAC address */
	if ( ( rc = xenstore_read ( xen, &mac, xendev->key, "mac", NULL ) )!=0){
		DBGC ( netfront, "NETFRONT %s could not read MAC address: %s\n",
		       xendev->key, strerror ( rc ) );
		goto err_xenstore_read;
	}
	DBGC2 ( netfront, "NETFRONT %s has MAC address \"%s\"\n",
		xendev->key, mac );

	/* Decode MAC address */
	len = hex_decode ( ':', mac, hw_addr, ETH_ALEN );
	if ( len < 0 ) {
		rc = len;
		DBGC ( netfront, "NETFRONT %s could not decode MAC address "
		       "\"%s\": %s\n", xendev->key, mac, strerror ( rc ) );
		goto err_decode;
	}

	/* Success */
	rc = 0;

 err_decode:
	free ( mac );
 err_xenstore_read:
	return rc;
}

/**
 * Write XenStore numeric value
 *
 * @v netfront		Netfront device
 * @v subkey		Subkey
 * @v num		Numeric value
 * @ret rc		Return status code
 */
static int netfront_write_num ( struct netfront_nic *netfront,
				const char *subkey, unsigned long num ) {
	struct xen_device *xendev = netfront->xendev;
	struct xen_hypervisor *xen = xendev->xen;
	int rc;

	/* Write value */
	if ( ( rc = xenstore_write_num ( xen, num, xendev->key, subkey,
					 NULL ) ) != 0 ) {
		DBGC ( netfront, "NETFRONT %s could not set %s=\"%ld\": %s\n",
		       xendev->key, subkey, num, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Write XenStore flag value
 *
 * @v netfront		Netfront device
 * @v subkey		Subkey
 * @v num		Numeric value
 * @ret rc		Return status code
 */
static int netfront_write_flag ( struct netfront_nic *netfront,
				 const char *subkey ) {

	return netfront_write_num ( netfront, subkey, 1 );
}

/**
 * Delete XenStore value
 *
 * @v netfront		Netfront device
 * @v subkey		Subkey
 * @ret rc		Return status code
 */
static int netfront_rm ( struct netfront_nic *netfront, const char *subkey ) {
	struct xen_device *xendev = netfront->xendev;
	struct xen_hypervisor *xen = xendev->xen;
	int rc;

	/* Remove value */
	if ( ( rc = xenstore_rm ( xen, xendev->key, subkey, NULL ) ) != 0 ) {
		DBGC ( netfront, "NETFRONT %s could not delete %s: %s\n",
		       xendev->key, subkey, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/******************************************************************************
 *
 * Events
 *
 ******************************************************************************
 */

/**
 * Create event channel
 *
 * @v netfront		Netfront device
 * @ret rc		Return status code
 */
static int netfront_create_event ( struct netfront_nic *netfront ) {
	struct xen_device *xendev = netfront->xendev;
	struct xen_hypervisor *xen = xendev->xen;
	struct evtchn_alloc_unbound alloc_unbound;
	struct evtchn_close close;
	int xenrc;
	int rc;

	/* Allocate event */
	alloc_unbound.dom = DOMID_SELF;
	alloc_unbound.remote_dom = xendev->backend_id;
	if ( ( xenrc = xenevent_alloc_unbound ( xen, &alloc_unbound ) ) != 0 ) {
		rc = -EXEN ( xenrc );
		DBGC ( netfront, "NETFRONT %s could not allocate event: %s\n",
		       xendev->key, strerror ( rc ) );
		goto err_alloc_unbound;
	}
	netfront->event.port = alloc_unbound.port;

	/* Publish event channel */
	if ( ( rc = netfront_write_num ( netfront, "event-channel",
					 netfront->event.port ) ) != 0 )
		goto err_write_num;

	DBGC ( netfront, "NETFRONT %s event-channel=\"%d\"\n",
	       xendev->key, netfront->event.port );
	return 0;

	netfront_rm ( netfront, "event-channel" );
 err_write_num:
	close.port = netfront->event.port;
	xenevent_close ( xen, &close );
 err_alloc_unbound:
	return rc;
}

/**
 * Send event
 *
 * @v netfront		Netfront device
 * @ret rc		Return status code
 */
static inline __attribute__ (( always_inline )) int
netfront_send_event ( struct netfront_nic *netfront ) {
	struct xen_device *xendev = netfront->xendev;
	struct xen_hypervisor *xen = xendev->xen;
	int xenrc;
	int rc;

	/* Send event */
	if ( ( xenrc = xenevent_send ( xen, &netfront->event ) ) != 0 ) {
		rc = -EXEN ( xenrc );
		DBGC ( netfront, "NETFRONT %s could not send event: %s\n",
		       xendev->key, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Destroy event channel
 *
 * @v netfront		Netfront device
 */
static void netfront_destroy_event ( struct netfront_nic *netfront ) {
	struct xen_device *xendev = netfront->xendev;
	struct xen_hypervisor *xen = xendev->xen;
	struct evtchn_close close;

	/* Unpublish event channel */
	netfront_rm ( netfront, "event-channel" );

	/* Close event channel */
	close.port = netfront->event.port;
	xenevent_close ( xen, &close );
}

/******************************************************************************
 *
 * Descriptor rings
 *
 ******************************************************************************
 */

/**
 * Create descriptor ring
 *
 * @v netfront		Netfront device
 * @v ring		Descriptor ring
 * @ret rc		Return status code
 */
static int netfront_create_ring ( struct netfront_nic *netfront,
				  struct netfront_ring *ring ) {
	struct xen_device *xendev = netfront->xendev;
	struct xen_hypervisor *xen = xendev->xen;
	unsigned int i;
	int rc;

	/* Initialise buffer ID ring */
	for ( i = 0 ; i < ring->count ; i++ ) {
		ring->ids[i] = i;
		assert ( ring->iobufs[i] == NULL );
	}
	ring->id_prod = 0;
	ring->id_cons = 0;

	/* Allocate and initialise shared ring */
	ring->sring.raw = malloc_dma ( PAGE_SIZE, PAGE_SIZE );
	if ( ! ring->sring.raw ) {
		rc = -ENOMEM;
		goto err_alloc;
	}

	/* Grant access to shared ring */
	if ( ( rc = xengrant_permit_access ( xen, ring->ref, xendev->backend_id,
					     0, ring->sring.raw ) ) != 0 ) {
		DBGC ( netfront, "NETFRONT %s could not permit access to "
		       "%#08lx: %s\n", xendev->key,
		       virt_to_phys ( ring->sring.raw ), strerror ( rc ) );
		goto err_permit_access;
	}

	/* Publish shared ring reference */
	if ( ( rc = netfront_write_num ( netfront, ring->ref_key,
					 ring->ref ) ) != 0 )
		goto err_write_num;

	DBGC ( netfront, "NETFRONT %s %s=\"%d\" [%08lx,%08lx)\n",
	       xendev->key, ring->ref_key, ring->ref,
	       virt_to_phys ( ring->sring.raw ),
	       ( virt_to_phys ( ring->sring.raw ) + PAGE_SIZE ) );
	return 0;

	netfront_rm ( netfront, ring->ref_key );
 err_write_num:
	xengrant_invalidate ( xen, ring->ref );
 err_permit_access:
	free_dma ( ring->sring.raw, PAGE_SIZE );
 err_alloc:
	return rc;
}

/**
 * Add buffer to descriptor ring
 *
 * @v netfront		Netfront device
 * @v ring		Descriptor ring
 * @v iobuf		I/O buffer
 * @v id		Buffer ID to fill in
 * @v ref		Grant reference to fill in
 * @ret rc		Return status code
 *
 * The caller is responsible for ensuring that there is space in the
 * ring.
 */
static int netfront_push ( struct netfront_nic *netfront,
			   struct netfront_ring *ring, struct io_buffer *iobuf,
			   uint16_t *id, grant_ref_t *ref ) {
	struct xen_device *xendev = netfront->xendev;
	struct xen_hypervisor *xen = xendev->xen;
	unsigned int next_id;
	unsigned int next_ref;
	int rc;

	/* Sanity check */
	assert ( ! netfront_ring_is_full ( ring ) );

	/* Allocate buffer ID */
	next_id = ring->ids[ ring->id_prod & ( ring->count - 1 ) ];
	next_ref = ring->refs[next_id];

	/* Grant access to I/O buffer page.  I/O buffers are naturally
	 * aligned, so we never need to worry about crossing a page
	 * boundary.
	 */
	if ( ( rc = xengrant_permit_access ( xen, next_ref, xendev->backend_id,
					     0, iobuf->data ) ) != 0 ) {
		DBGC ( netfront, "NETFRONT %s could not permit access to "
		       "%#08lx: %s\n", xendev->key,
		       virt_to_phys ( iobuf->data ), strerror ( rc ) );
		return rc;
	}

	/* Store I/O buffer */
	assert ( ring->iobufs[next_id] == NULL );
	ring->iobufs[next_id] = iobuf;

	/* Consume buffer ID */
	ring->id_prod++;

	/* Return buffer ID and grant reference */
	*id = next_id;
	*ref = next_ref;

	return 0;
}

/**
 * Remove buffer from descriptor ring
 *
 * @v netfront		Netfront device
 * @v ring		Descriptor ring
 * @v id		Buffer ID
 * @ret iobuf		I/O buffer
 */
static struct io_buffer * netfront_pull ( struct netfront_nic *netfront,
					  struct netfront_ring *ring,
					  unsigned int id ) {
	struct xen_device *xendev = netfront->xendev;
	struct xen_hypervisor *xen = xendev->xen;
	struct io_buffer *iobuf;

	/* Sanity check */
	assert ( id < ring->count );

	/* Revoke access from I/O buffer page */
	xengrant_invalidate ( xen, ring->refs[id] );

	/* Retrieve I/O buffer */
	iobuf = ring->iobufs[id];
	assert ( iobuf != NULL );
	ring->iobufs[id] = NULL;

	/* Free buffer ID */
	ring->ids[ ( ring->id_cons++ ) & ( ring->count - 1 ) ] = id;

	return iobuf;
}

/**
 * Destroy descriptor ring
 *
 * @v netfront		Netfront device
 * @v ring		Descriptor ring
 * @v discard		Method used to discard outstanding buffer, or NULL
 */
static void netfront_destroy_ring ( struct netfront_nic *netfront,
				    struct netfront_ring *ring,
				    void ( * discard ) ( struct io_buffer * ) ){
	struct xen_device *xendev = netfront->xendev;
	struct xen_hypervisor *xen = xendev->xen;
	struct io_buffer *iobuf;
	unsigned int id;

	/* Flush any outstanding buffers */
	while ( ! netfront_ring_is_empty ( ring ) ) {
		id = ring->ids[ ring->id_cons & ( ring->count - 1 ) ];
		iobuf = netfront_pull ( netfront, ring, id );
		if ( discard )
			discard ( iobuf );
	}

	/* Unpublish shared ring reference */
	netfront_rm ( netfront, ring->ref_key );

	/* Revoke access from shared ring */
	xengrant_invalidate ( xen, ring->ref );

	/* Free page */
	free_dma ( ring->sring.raw, PAGE_SIZE );
	ring->sring.raw = NULL;
}

/******************************************************************************
 *
 * Network device interface
 *
 ******************************************************************************
 */

/**
 * Refill receive descriptor ring
 *
 * @v netdev		Network device
 */
static void netfront_refill_rx ( struct net_device *netdev ) {
	struct netfront_nic *netfront = netdev->priv;
	struct xen_device *xendev = netfront->xendev;
	struct io_buffer *iobuf;
	struct netif_rx_request *request;
	int notify;
	int rc;

	/* Do nothing if ring is already full */
	if ( netfront_ring_is_full ( &netfront->rx ) )
		return;

	/* Refill ring */
	do {

		/* Allocate I/O buffer */
		iobuf = alloc_iob ( PAGE_SIZE );
		if ( ! iobuf ) {
			/* Wait for next refill */
			break;
		}

		/* Add to descriptor ring */
		request = RING_GET_REQUEST ( &netfront->rx_fring,
					     netfront->rx_fring.req_prod_pvt );
		if ( ( rc = netfront_push ( netfront, &netfront->rx,
					    iobuf, &request->id,
					    &request->gref ) ) != 0 ) {
			netdev_rx_err ( netdev, iobuf, rc );
			break;
		}
		DBGC2 ( netfront, "NETFRONT %s RX id %d ref %d is %#08lx+%zx\n",
			xendev->key, request->id, request->gref,
			virt_to_phys ( iobuf->data ), iob_tailroom ( iobuf ) );

		/* Move to next descriptor */
		netfront->rx_fring.req_prod_pvt++;

	} while ( ! netfront_ring_is_full ( &netfront->rx ) );

	/* Push new descriptors and notify backend if applicable */
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY ( &netfront->rx_fring, notify );
	if ( notify )
		netfront_send_event ( netfront );
}

/**
 * Open network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int netfront_open ( struct net_device *netdev ) {
	struct netfront_nic *netfront = netdev->priv;
	struct xen_device *xendev = netfront->xendev;
	int rc;

	/* Ensure device is in a suitable initial state */
	if ( ( rc = netfront_reset ( netfront ) ) != 0 )
		goto err_reset;

	/* Create transmit descriptor ring */
	if ( ( rc = netfront_create_ring ( netfront, &netfront->tx ) ) != 0 )
		goto err_create_tx;
	SHARED_RING_INIT ( netfront->tx_sring );
	FRONT_RING_INIT ( &netfront->tx_fring, netfront->tx_sring, PAGE_SIZE );
	assert ( RING_SIZE ( &netfront->tx_fring ) >= netfront->tx.count );

	/* Create receive descriptor ring */
	if ( ( rc = netfront_create_ring ( netfront, &netfront->rx ) ) != 0 )
		goto err_create_rx;
	SHARED_RING_INIT ( netfront->rx_sring );
	FRONT_RING_INIT ( &netfront->rx_fring, netfront->rx_sring, PAGE_SIZE );
	assert ( RING_SIZE ( &netfront->rx_fring ) >= netfront->rx.count );

	/* Create event channel */
	if ( ( rc = netfront_create_event ( netfront ) ) != 0 )
		goto err_create_event;

	/* "Request" the rx-copy feature.  Current versions of
	 * xen_netback.ko will fail silently if this parameter is not
	 * present.
	 */
	if ( ( rc = netfront_write_flag ( netfront, "request-rx-copy" ) ) != 0 )
		goto err_request_rx_copy;

	/* Disable checksum offload, since we will always do the work anyway */
	if ( ( rc = netfront_write_flag ( netfront,
					  "feature-no-csum-offload" ) ) != 0 )
		goto err_feature_no_csum_offload;

	/* Inform backend that we will send notifications for RX requests */
	if ( ( rc = netfront_write_flag ( netfront,
					  "feature-rx-notify" ) ) != 0 )
		goto err_feature_rx_notify;

	/* Set state to Connected */
	if ( ( rc = xenbus_set_state ( xendev, XenbusStateConnected ) ) != 0 ) {
		DBGC ( netfront, "NETFRONT %s could not set state=\"%d\": %s\n",
		       xendev->key, XenbusStateConnected, strerror ( rc ) );
		goto err_set_state;
	}

	/* Wait for backend to connect */
	if ( ( rc = xenbus_backend_wait ( xendev, XenbusStateConnected ) ) !=0){
		DBGC ( netfront, "NETFRONT %s could not connect to backend: "
		       "%s\n", xendev->key, strerror ( rc ) );
		goto err_backend_wait;
	}

	/* Refill receive descriptor ring */
	netfront_refill_rx ( netdev );

	/* Set link up */
	netdev_link_up ( netdev );

	return 0;

 err_backend_wait:
	netfront_reset ( netfront );
 err_set_state:
	netfront_rm ( netfront, "feature-rx-notify" );
 err_feature_rx_notify:
	netfront_rm ( netfront, "feature-no-csum-offload" );
 err_feature_no_csum_offload:
	netfront_rm ( netfront, "request-rx-copy" );
 err_request_rx_copy:
	netfront_destroy_event ( netfront );
 err_create_event:
	netfront_destroy_ring ( netfront, &netfront->rx, NULL );
 err_create_rx:
	netfront_destroy_ring ( netfront, &netfront->tx, NULL );
 err_create_tx:
 err_reset:
	return rc;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
static void netfront_close ( struct net_device *netdev ) {
	struct netfront_nic *netfront = netdev->priv;
	struct xen_device *xendev = netfront->xendev;
	int rc;

	/* Reset devic, thereby ensuring that grant references are no
	 * longer in use, etc.
	 */
	if ( ( rc = netfront_reset ( netfront ) ) != 0 ) {
		DBGC ( netfront, "NETFRONT %s could not disconnect from "
		       "backend: %s\n", xendev->key, strerror ( rc ) );
		/* Things will probably go _very_ badly wrong if this
		 * happens, since it means the backend may still write
		 * to the outstanding RX buffers that we are about to
		 * free.  The best we can do is report the error via
		 * the link status, but there's a good chance the
		 * machine will crash soon.
		 */
		netdev_link_err ( netdev, rc );
	} else {
		netdev_link_down ( netdev );
	}

	/* Delete flags */
	netfront_rm ( netfront, "feature-rx-notify" );
	netfront_rm ( netfront, "feature-no-csum-offload" );
	netfront_rm ( netfront, "request-rx-copy" );

	/* Destroy event channel */
	netfront_destroy_event ( netfront );

	/* Destroy receive descriptor ring, freeing any outstanding
	 * I/O buffers.
	 */
	netfront_destroy_ring ( netfront, &netfront->rx, free_iob );

	/* Destroy transmit descriptor ring.  Leave any outstanding
	 * I/O buffers to be freed by netdev_tx_flush().
	 */
	netfront_destroy_ring ( netfront, &netfront->tx, NULL );
}

/**
 * Transmit packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int netfront_transmit ( struct net_device *netdev,
			       struct io_buffer *iobuf ) {
	struct netfront_nic *netfront = netdev->priv;
	struct xen_device *xendev = netfront->xendev;
	struct netif_tx_request *request;
	int notify;
	int rc;

	/* Check that we have space in the ring */
	if ( netfront_ring_is_full ( &netfront->tx ) ) {
		DBGC ( netfront, "NETFRONT %s out of transmit descriptors\n",
		       xendev->key );
		return -ENOBUFS;
	}

	/* Add to descriptor ring */
	request = RING_GET_REQUEST ( &netfront->tx_fring,
				     netfront->tx_fring.req_prod_pvt );
	if ( ( rc = netfront_push ( netfront, &netfront->tx, iobuf,
				    &request->id, &request->gref ) ) != 0 ) {
		return rc;
	}
	request->offset = ( virt_to_phys ( iobuf->data ) & ( PAGE_SIZE - 1 ) );
	request->flags = NETTXF_data_validated;
	request->size = iob_len ( iobuf );
	DBGC2 ( netfront, "NETFRONT %s TX id %d ref %d is %#08lx+%zx\n",
		xendev->key, request->id, request->gref,
		virt_to_phys ( iobuf->data ), iob_len ( iobuf ) );

	/* Consume descriptor */
	netfront->tx_fring.req_prod_pvt++;

	/* Push new descriptor and notify backend if applicable */
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY ( &netfront->tx_fring, notify );
	if ( notify )
		netfront_send_event ( netfront );

	return 0;
}

/**
 * Poll for completed packets
 *
 * @v netdev		Network device
 */
static void netfront_poll_tx ( struct net_device *netdev ) {
	struct netfront_nic *netfront = netdev->priv;
	struct xen_device *xendev = netfront->xendev;
	struct netif_tx_response *response;
	struct io_buffer *iobuf;
	unsigned int status;
	int rc;

	/* Consume any unconsumed responses */
	while ( RING_HAS_UNCONSUMED_RESPONSES ( &netfront->tx_fring ) ) {

		/* Get next response */
		response = RING_GET_RESPONSE ( &netfront->tx_fring,
					       netfront->tx_fring.rsp_cons++ );

		/* Retrieve from descriptor ring */
		iobuf = netfront_pull ( netfront, &netfront->tx, response->id );
		status = response->status;
		if ( status == NETIF_RSP_OKAY ) {
			DBGC2 ( netfront, "NETFRONT %s TX id %d complete\n",
				xendev->key, response->id );
			netdev_tx_complete ( netdev, iobuf );
		} else {
			rc = -EIO_NETIF_RSP ( status );
			DBGC2 ( netfront, "NETFRONT %s TX id %d error %d: %s\n",
				xendev->key, response->id, status,
				strerror ( rc ) );
			netdev_tx_complete_err ( netdev, iobuf, rc );
		}
	}
}

/**
 * Poll for received packets
 *
 * @v netdev		Network device
 */
static void netfront_poll_rx ( struct net_device *netdev ) {
	struct netfront_nic *netfront = netdev->priv;
	struct xen_device *xendev = netfront->xendev;
	struct netif_rx_response *response;
	struct io_buffer *iobuf;
	int status;
	size_t len;
	int rc;

	/* Consume any unconsumed responses */
	while ( RING_HAS_UNCONSUMED_RESPONSES ( &netfront->rx_fring ) ) {

		/* Get next response */
		response = RING_GET_RESPONSE ( &netfront->rx_fring,
					       netfront->rx_fring.rsp_cons++ );

		/* Retrieve from descriptor ring */
		iobuf = netfront_pull ( netfront, &netfront->rx, response->id );
		status = response->status;
		if ( status >= 0 ) {
			len = status;
			iob_reserve ( iobuf, response->offset );
			iob_put ( iobuf, len );
			DBGC2 ( netfront, "NETFRONT %s RX id %d complete "
				"%#08lx+%zx\n", xendev->key, response->id,
				virt_to_phys ( iobuf->data ), len );
			netdev_rx ( netdev, iobuf );
		} else {
			rc = -EIO_NETIF_RSP ( status );
			DBGC2 ( netfront, "NETFRONT %s RX id %d error %d: %s\n",
				xendev->key, response->id, status,
				strerror ( rc ) );
			netdev_rx_err ( netdev, iobuf, rc );
		}
	}
}

/**
 * Poll for completed and received packets
 *
 * @v netdev		Network device
 */
static void netfront_poll ( struct net_device *netdev ) {

	/* Poll for TX completions */
	netfront_poll_tx ( netdev );

	/* Poll for RX completions */
	netfront_poll_rx ( netdev );

	/* Refill RX descriptor ring */
	netfront_refill_rx ( netdev );
}

/** Network device operations */
static struct net_device_operations netfront_operations = {
	.open		= netfront_open,
	.close		= netfront_close,
	.transmit	= netfront_transmit,
	.poll		= netfront_poll,
};

/******************************************************************************
 *
 * Xen device bus interface
 *
 ******************************************************************************
 */

/**
 * Probe Xen device
 *
 * @v xendev		Xen device
 * @ret rc		Return status code
 */
static int netfront_probe ( struct xen_device *xendev ) {
	struct xen_hypervisor *xen = xendev->xen;
	struct net_device *netdev;
	struct netfront_nic *netfront;
	int rc;

	/* Allocate and initialise structure */
	netdev = alloc_etherdev ( sizeof ( *netfront ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	netdev_init ( netdev, &netfront_operations );
	netdev->dev = &xendev->dev;
	netfront = netdev->priv;
	netfront->xendev = xendev;
	DBGC ( netfront, "NETFRONT %s backend=\"%s\" in domain %ld\n",
	       xendev->key, xendev->backend, xendev->backend_id );

	/* Allocate grant references and initialise descriptor rings */
	if ( ( rc = xengrant_alloc ( xen, netfront->refs,
				     NETFRONT_REF_COUNT ) ) != 0 ) {
		DBGC ( netfront, "NETFRONT %s could not allocate grant "
		       "references: %s\n", xendev->key, strerror ( rc ) );
		goto err_grant_alloc;
	}
	netfront_init_ring ( &netfront->tx, "tx-ring-ref",
			     netfront->refs[NETFRONT_REF_TX_RING],
			     NETFRONT_NUM_TX_DESC, netfront->tx_iobufs,
			     &netfront->refs[NETFRONT_REF_TX_BASE],
			     netfront->tx_ids );
	netfront_init_ring ( &netfront->rx, "rx-ring-ref",
			     netfront->refs[NETFRONT_REF_RX_RING],
			     NETFRONT_NUM_RX_DESC, netfront->rx_iobufs,
			     &netfront->refs[NETFRONT_REF_RX_BASE],
			     netfront->rx_ids );

	/* Fetch MAC address */
	if ( ( rc = netfront_read_mac ( netfront, netdev->hw_addr ) ) != 0 )
		goto err_read_mac;

	/* Reset device.  Ignore failures; allow the device to be
	 * registered so that reset errors can be observed by the user
	 * when attempting to open the device.
	 */
	netfront_reset ( netfront );

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register_netdev;

	/* Set initial link state */
	netdev_link_down ( netdev );

	xen_set_drvdata ( xendev, netdev );
	return 0;

	unregister_netdev ( netdev );
 err_register_netdev:
 err_read_mac:
	xengrant_free ( xen, netfront->refs, NETFRONT_REF_COUNT );
 err_grant_alloc:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
 err_alloc:
	return rc;
}

/**
 * Remove Xen device
 *
 * @v xendev		Xen device
 */
static void netfront_remove ( struct xen_device *xendev ) {
	struct net_device *netdev = xen_get_drvdata ( xendev );
	struct netfront_nic *netfront = netdev->priv;
	struct xen_hypervisor *xen = xendev->xen;

	/* Unregister network device */
	unregister_netdev ( netdev );

	/* Free resources */
	xengrant_free ( xen, netfront->refs, NETFRONT_REF_COUNT );

	/* Free network device */
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/** Xen netfront driver */
struct xen_driver netfront_driver __xen_driver = {
	.name = "netfront",
	.type = "vif",
	.probe = netfront_probe,
	.remove = netfront_remove,
};
