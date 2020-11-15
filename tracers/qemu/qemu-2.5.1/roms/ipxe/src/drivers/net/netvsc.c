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

/** @file
 *
 * Hyper-V network virtual service client
 *
 * The network virtual service client (NetVSC) connects to the network
 * virtual service provider (NetVSP) via the Hyper-V virtual machine
 * bus (VMBus).  It provides a transport layer for RNDIS packets.
 */

#include <errno.h>
#include <unistd.h>
#include <byteswap.h>
#include <ipxe/umalloc.h>
#include <ipxe/rndis.h>
#include <ipxe/vmbus.h>
#include "netvsc.h"

/**
 * Send control message and wait for completion
 *
 * @v netvsc		NetVSC device
 * @v xrid		Relative transaction ID
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 */
static int netvsc_control ( struct netvsc_device *netvsc, unsigned int xrid,
			    const void *data, size_t len ) {
	uint64_t xid = ( NETVSC_BASE_XID + xrid );
	unsigned int i;
	int rc;

	/* Send control message */
	if ( ( rc = vmbus_send_control ( netvsc->vmdev, xid, data, len ) ) !=0){
		DBGC ( netvsc, "NETVSC %s could not send control message: %s\n",
		       netvsc->name, strerror ( rc ) );
		return rc;
	}

	/* Record transaction ID */
	netvsc->wait_xrid = xrid;

	/* Wait for operation to complete */
	for ( i = 0 ; i < NETVSC_MAX_WAIT_MS ; i++ ) {

		/* Check for completion */
		if ( ! netvsc->wait_xrid )
			return netvsc->wait_rc;

		/* Poll VMBus device */
		vmbus_poll ( netvsc->vmdev );

		/* Delay for 1ms */
		mdelay ( 1 );
	}

	DBGC ( netvsc, "NETVSC %s timed out waiting for XRID %d\n",
	       netvsc->name, xrid );
	vmbus_dump_channel ( netvsc->vmdev );
	return -ETIMEDOUT;
}

/**
 * Handle generic completion
 *
 * @v netvsc		NetVSC device
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 */
static int netvsc_completed ( struct netvsc_device *netvsc __unused,
			      const void *data __unused, size_t len __unused ) {
	return 0;
}

/**
 * Initialise communication
 *
 * @v netvsc		NetVSC device
 * @ret rc		Return status code
 */
static int netvsc_initialise ( struct netvsc_device *netvsc ) {
	struct netvsc_init_message msg;
	int rc;

	/* Construct message */
	memset ( &msg, 0, sizeof ( msg ) );
	msg.header.type = cpu_to_le32 ( NETVSC_INIT_MSG );
	msg.min = cpu_to_le32 ( NETVSC_VERSION_1 );
	msg.max = cpu_to_le32 ( NETVSC_VERSION_1 );

	/* Send message and wait for completion */
	if ( ( rc = netvsc_control ( netvsc, NETVSC_INIT_XRID, &msg,
				     sizeof ( msg ) ) ) != 0 ) {
		DBGC ( netvsc, "NETVSC %s could not initialise: %s\n",
		       netvsc->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Handle initialisation completion
 *
 * @v netvsc		NetVSC device
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 */
static int
netvsc_initialised ( struct netvsc_device *netvsc, const void *data,
		     size_t len ) {
	const struct netvsc_init_completion *cmplt = data;

	/* Check completion */
	if ( len < sizeof ( *cmplt ) ) {
		DBGC ( netvsc, "NETVSC %s underlength initialisation "
		       "completion (%zd bytes)\n", netvsc->name, len );
		return -EINVAL;
	}
	if ( cmplt->header.type != cpu_to_le32 ( NETVSC_INIT_CMPLT ) ) {
		DBGC ( netvsc, "NETVSC %s unexpected initialisation completion "
		       "type %d\n", netvsc->name,
		       le32_to_cpu ( cmplt->header.type ) );
		return -EPROTO;
	}
	if ( cmplt->status != cpu_to_le32 ( NETVSC_OK ) ) {
		DBGC ( netvsc, "NETVSC %s initialisation failure status %d\n",
		       netvsc->name, le32_to_cpu ( cmplt->status ) );
		return -EPROTO;
	}

	return 0;
}

/**
 * Set NDIS version
 *
 * @v netvsc		NetVSC device
 * @ret rc		Return status code
 */
static int netvsc_ndis_version ( struct netvsc_device *netvsc ) {
	struct netvsc_ndis_version_message msg;
	int rc;

	/* Construct message */
	memset ( &msg, 0, sizeof ( msg ) );
	msg.header.type = cpu_to_le32 ( NETVSC_NDIS_VERSION_MSG );
	msg.major = cpu_to_le32 ( NETVSC_NDIS_MAJOR );
	msg.minor = cpu_to_le32 ( NETVSC_NDIS_MINOR );

	/* Send message and wait for completion */
	if ( ( rc = netvsc_control ( netvsc, NETVSC_NDIS_VERSION_XRID,
				     &msg, sizeof ( msg ) ) ) != 0 ) {
		DBGC ( netvsc, "NETVSC %s could not set NDIS version: %s\n",
		       netvsc->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Establish data buffer
 *
 * @v netvsc		NetVSC device
 * @v buffer		Data buffer
 * @ret rc		Return status code
 */
static int netvsc_establish_buffer ( struct netvsc_device *netvsc,
				     struct netvsc_buffer *buffer ) {
	struct netvsc_establish_buffer_message msg;
	int rc;

	/* Construct message */
	memset ( &msg, 0, sizeof ( msg ) );
	msg.header.type = cpu_to_le32 ( buffer->establish_type );
	msg.gpadl = cpu_to_le32 ( buffer->gpadl );
	msg.pageset = buffer->pages.pageset; /* Already protocol-endian */

	/* Send message and wait for completion */
	if ( ( rc = netvsc_control ( netvsc, buffer->establish_xrid, &msg,
				     sizeof ( msg ) ) ) != 0 ) {
		DBGC ( netvsc, "NETVSC %s could not establish buffer: %s\n",
		       netvsc->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Handle establish receive data buffer completion
 *
 * @v netvsc		NetVSC device
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 */
static int netvsc_rx_established_buffer ( struct netvsc_device *netvsc,
					  const void *data, size_t len ) {
	const struct netvsc_rx_establish_buffer_completion *cmplt = data;

	/* Check completion */
	if ( len < sizeof ( *cmplt ) ) {
		DBGC ( netvsc, "NETVSC %s underlength buffer completion (%zd "
		       "bytes)\n", netvsc->name, len );
		return -EINVAL;
	}
	if ( cmplt->header.type != cpu_to_le32 ( NETVSC_RX_ESTABLISH_CMPLT ) ) {
		DBGC ( netvsc, "NETVSC %s unexpected buffer completion type "
		       "%d\n", netvsc->name, le32_to_cpu ( cmplt->header.type));
		return -EPROTO;
	}
	if ( cmplt->status != cpu_to_le32 ( NETVSC_OK ) ) {
		DBGC ( netvsc, "NETVSC %s buffer failure status %d\n",
		       netvsc->name, le32_to_cpu ( cmplt->status ) );
		return -EPROTO;
	}

	return 0;
}

/**
 * Revoke data buffer
 *
 * @v netvsc		NetVSC device
 * @v buffer		Data buffer
 * @ret rc		Return status code
 */
static int netvsc_revoke_buffer ( struct netvsc_device *netvsc,
				  struct netvsc_buffer *buffer ) {
	struct netvsc_revoke_buffer_message msg;
	int rc;

	/* Construct message */
	memset ( &msg, 0, sizeof ( msg ) );
	msg.header.type = cpu_to_le32 ( buffer->revoke_type );
	msg.pageset = buffer->pages.pageset; /* Already protocol-endian */

	/* Send message and wait for completion */
	if ( ( rc = netvsc_control ( netvsc, buffer->revoke_xrid,
				     &msg, sizeof ( msg ) ) ) != 0 ) {
		DBGC ( netvsc, "NETVSC %s could not revoke buffer: %s\n",
		       netvsc->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Handle received control packet
 *
 * @v vmdev		VMBus device
 * @v xid		Transaction ID
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 */
static int netvsc_recv_control ( struct vmbus_device *vmdev, uint64_t xid,
				 const void *data, size_t len ) {
	struct rndis_device *rndis = vmbus_get_drvdata ( vmdev );
	struct netvsc_device *netvsc = rndis->priv;

	DBGC ( netvsc, "NETVSC %s received unsupported control packet "
	       "(%08llx):\n", netvsc->name, xid );
	DBGC_HDA ( netvsc, 0, data, len );
	return -ENOTSUP;
}

/**
 * Handle received data packet
 *
 * @v vmdev		VMBus device
 * @v xid		Transaction ID
 * @v data		Data
 * @v len		Length of data
 * @v list		List of I/O buffers
 * @ret rc		Return status code
 */
static int netvsc_recv_data ( struct vmbus_device *vmdev, uint64_t xid,
			      const void *data, size_t len,
			      struct list_head *list ) {
	struct rndis_device *rndis = vmbus_get_drvdata ( vmdev );
	struct netvsc_device *netvsc = rndis->priv;
	const struct netvsc_rndis_message *msg = data;
	struct io_buffer *iobuf;
	struct io_buffer *tmp;
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *msg ) ) {
		DBGC ( netvsc, "NETVSC %s received underlength RNDIS packet "
		       "(%zd bytes)\n", netvsc->name, len );
		rc = -EINVAL;
		goto err_sanity;
	}
	if ( msg->header.type != cpu_to_le32 ( NETVSC_RNDIS_MSG ) ) {
		DBGC ( netvsc, "NETVSC %s received unexpected RNDIS packet "
		       "type %d\n", netvsc->name,
		       le32_to_cpu ( msg->header.type ) );
		rc = -EINVAL;
		goto err_sanity;
	}

	/* Send completion back to host */
	if ( ( rc = vmbus_send_completion ( vmdev, xid, NULL, 0 ) ) != 0 ) {
		DBGC ( netvsc, "NETVSC %s could not send completion: %s\n",
		       netvsc->name, strerror ( rc ) );
		goto err_completion;
	}

	/* Hand off to RNDIS */
	list_for_each_entry_safe ( iobuf, tmp, list, list ) {
		list_del ( &iobuf->list );
		rndis_rx ( rndis, iob_disown ( iobuf ) );
	}

	return 0;

 err_completion:
 err_sanity:
	list_for_each_entry_safe ( iobuf, tmp, list, list ) {
		list_del ( &iobuf->list );
		free_iob ( iobuf );
	}
	return rc;
}

/**
 * Handle received completion packet
 *
 * @v vmdev		VMBus device
 * @v xid		Transaction ID
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 */
static int netvsc_recv_completion ( struct vmbus_device *vmdev, uint64_t xid,
				    const void *data, size_t len ) {
	struct rndis_device *rndis = vmbus_get_drvdata ( vmdev );
	struct netvsc_device *netvsc = rndis->priv;
	struct io_buffer *iobuf;
	int ( * completion ) ( struct netvsc_device *netvsc,
			       const void *data, size_t len );
	unsigned int xrid = ( xid - NETVSC_BASE_XID );
	unsigned int tx_id;
	int rc;

	/* Handle transmit completion, if applicable */
	tx_id = ( xrid - NETVSC_TX_BASE_XRID );
	if ( ( tx_id < NETVSC_TX_NUM_DESC ) &&
	     ( ( iobuf = netvsc->tx.iobufs[tx_id] ) != NULL ) ) {

		/* Free buffer ID */
		netvsc->tx.iobufs[tx_id] = NULL;
		netvsc->tx.ids[ ( netvsc->tx.id_cons++ ) &
				( netvsc->tx.count - 1 ) ] = tx_id;

		/* Hand back to RNDIS */
		rndis_tx_complete ( rndis, iobuf );
		return 0;
	}

	/* Otherwise determine completion handler */
	if ( xrid == NETVSC_INIT_XRID ) {
		completion = netvsc_initialised;
	} else if ( xrid == NETVSC_RX_ESTABLISH_XRID ) {
		completion = netvsc_rx_established_buffer;
	} else if ( ( netvsc->wait_xrid != 0 ) &&
		    ( xrid == netvsc->wait_xrid ) ) {
		completion = netvsc_completed;
	} else {
		DBGC ( netvsc, "NETVSC %s received unexpected completion "
		       "(%08llx)\n", netvsc->name, xid );
		return -EPIPE;
	}

	/* Hand off to completion handler */
	rc = completion ( netvsc, data, len );

	/* Record completion handler result if applicable */
	if ( xrid == netvsc->wait_xrid ) {
		netvsc->wait_xrid = 0;
		netvsc->wait_rc = rc;
	}

	return rc;
}

/**
 * Handle received cancellation packet
 *
 * @v vmdev		VMBus device
 * @v xid		Transaction ID
 * @ret rc		Return status code
 */
static int netvsc_recv_cancellation ( struct vmbus_device *vmdev,
				      uint64_t xid ) {
	struct rndis_device *rndis = vmbus_get_drvdata ( vmdev );
	struct netvsc_device *netvsc = rndis->priv;

	DBGC ( netvsc, "NETVSC %s received unsupported cancellation packet "
	       "(%08llx):\n", netvsc->name, xid );
	return -ENOTSUP;
}

/** VMBus channel operations */
static struct vmbus_channel_operations netvsc_channel_operations = {
	.recv_control = netvsc_recv_control,
	.recv_data = netvsc_recv_data,
	.recv_completion = netvsc_recv_completion,
	.recv_cancellation = netvsc_recv_cancellation,
};

/**
 * Poll for completed and received packets
 *
 * @v rndis		RNDIS device
 */
static void netvsc_poll ( struct rndis_device *rndis ) {
	struct netvsc_device *netvsc = rndis->priv;
	struct vmbus_device *vmdev = netvsc->vmdev;

	/* Poll VMBus device */
	while ( vmbus_has_data ( vmdev ) )
		vmbus_poll ( vmdev );
}

/**
 * Transmit packet
 *
 * @v rndis		RNDIS device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 *
 * If this method returns success then the RNDIS device must
 * eventually report completion via rndis_tx_complete().
 */
static int netvsc_transmit ( struct rndis_device *rndis,
			     struct io_buffer *iobuf ) {
	struct netvsc_device *netvsc = rndis->priv;
	struct rndis_header *header = iobuf->data;
	struct netvsc_rndis_message msg;
	unsigned int tx_id;
	unsigned int xrid;
	uint64_t xid;
	int rc;

	/* Sanity check */
	assert ( iob_len ( iobuf ) >= sizeof ( *header ) );
	assert ( iob_len ( iobuf ) == le32_to_cpu ( header->len ) );

	/* Check that we have space in the transmit ring */
	if ( netvsc_ring_is_full ( &netvsc->tx ) )
		return rndis_tx_defer ( rndis, iobuf );

	/* Allocate buffer ID and calculate transaction ID */
	tx_id = netvsc->tx.ids[ netvsc->tx.id_prod & ( netvsc->tx.count - 1 ) ];
	assert ( netvsc->tx.iobufs[tx_id] == NULL );
	xrid = ( NETVSC_TX_BASE_XRID + tx_id );
	xid = ( NETVSC_BASE_XID + xrid );

	/* Construct message */
	memset ( &msg, 0, sizeof ( msg ) );
	msg.header.type = cpu_to_le32 ( NETVSC_RNDIS_MSG );
	msg.channel = ( ( header->type == cpu_to_le32 ( RNDIS_PACKET_MSG ) ) ?
			NETVSC_RNDIS_DATA : NETVSC_RNDIS_CONTROL );
	msg.buffer = cpu_to_le32 ( NETVSC_RNDIS_NO_BUFFER );

	/* Send message */
	if ( ( rc = vmbus_send_data ( netvsc->vmdev, xid, &msg, sizeof ( msg ),
				      iobuf ) ) != 0 ) {
		DBGC ( netvsc, "NETVSC %s could not send RNDIS message: %s\n",
		       netvsc->name, strerror ( rc ) );
		return rc;
	}

	/* Store I/O buffer and consume buffer ID */
	netvsc->tx.iobufs[tx_id] = iobuf;
	netvsc->tx.id_prod++;

	return 0;
}

/**
 * Cancel transmission
 *
 * @v netvsc		NetVSC device
 * @v iobuf		I/O buffer
 * @v tx_id		Transmission ID
 */
static void netvsc_cancel_transmit ( struct netvsc_device *netvsc,
				     struct io_buffer *iobuf,
				     unsigned int tx_id ) {
	unsigned int xrid;
	uint64_t xid;

	/* Send cancellation */
	xrid = ( NETVSC_TX_BASE_XRID + tx_id );
	xid = ( NETVSC_BASE_XID + xrid );
	DBGC ( netvsc, "NETVSC %s cancelling transmission %#x\n",
	       netvsc->name, tx_id );
	vmbus_send_cancellation ( netvsc->vmdev, xid );

	/* Report back to RNDIS */
	rndis_tx_complete_err ( netvsc->rndis, iobuf, -ECANCELED );
}

/**
 * Create descriptor ring
 *
 * @v netvsc		NetVSC device
 * @v ring		Descriptor ring
 * @ret rc		Return status code
 */
static int netvsc_create_ring ( struct netvsc_device *netvsc __unused,
				struct netvsc_ring *ring ) {
	unsigned int i;

	/* Initialise buffer ID ring */
	for ( i = 0 ; i < ring->count ; i++ ) {
		ring->ids[i] = i;
		assert ( ring->iobufs[i] == NULL );
	}
	ring->id_prod = 0;
	ring->id_cons = 0;

	return 0;
}

/**
 * Destroy descriptor ring
 *
 * @v netvsc		NetVSC device
 * @v ring		Descriptor ring
 * @v discard		Method used to discard outstanding buffer, or NULL
 */
static void netvsc_destroy_ring ( struct netvsc_device *netvsc,
				  struct netvsc_ring *ring,
				  void ( * discard ) ( struct netvsc_device *,
						       struct io_buffer *,
						       unsigned int ) ) {
	struct io_buffer *iobuf;
	unsigned int i;

	/* Flush any outstanding buffers */
	for ( i = 0 ; i < ring->count ; i++ ) {
		iobuf = ring->iobufs[i];
		if ( ! iobuf )
			continue;
		ring->iobufs[i] = NULL;
		ring->ids[ ( ring->id_cons++ ) & ( ring->count - 1 ) ] = i;
		if ( discard )
			discard ( netvsc, iobuf, i );
	}

	/* Sanity check */
	assert ( netvsc_ring_is_empty ( ring ) );
}

/**
 * Copy data from data buffer
 *
 * @v pages		Transfer page set
 * @v data		Data buffer
 * @v offset		Offset within page set
 * @v len		Length within page set
 * @ret rc		Return status code
 */
static int netvsc_buffer_copy ( struct vmbus_xfer_pages *pages, void *data,
				size_t offset, size_t len ) {
	struct netvsc_buffer *buffer =
		container_of ( pages, struct netvsc_buffer, pages );

	/* Sanity check */
	if ( ( offset > buffer->len ) || ( len > ( buffer->len - offset ) ) )
		return -ERANGE;

	/* Copy data from buffer */
	copy_from_user ( data, buffer->data, offset, len );

	return 0;
}

/** Transfer page set operations */
static struct vmbus_xfer_pages_operations netvsc_xfer_pages_operations = {
	.copy = netvsc_buffer_copy,
};

/**
 * Create data buffer
 *
 * @v netvsc		NetVSC device
 * @v buffer		Data buffer
 * @ret rc		Return status code
 */
static int netvsc_create_buffer ( struct netvsc_device *netvsc,
				  struct netvsc_buffer *buffer ) {
	struct vmbus_device *vmdev = netvsc->vmdev;
	int gpadl;
	int rc;

	/* Allocate receive buffer */
	buffer->data = umalloc ( buffer->len );
	if ( ! buffer->data ) {
		DBGC ( netvsc, "NETVSC %s could not allocate %zd-byte buffer\n",
		       netvsc->name, buffer->len );
		rc = -ENOMEM;
		goto err_alloc;
	}

	/* Establish GPA descriptor list */
	gpadl = vmbus_establish_gpadl ( vmdev, buffer->data, buffer->len );
	if ( gpadl < 0 ) {
		rc = gpadl;
		DBGC ( netvsc, "NETVSC %s could not establish GPADL: %s\n",
		       netvsc->name, strerror ( rc ) );
		goto err_establish_gpadl;
	}
	buffer->gpadl = gpadl;

	/* Register transfer page set */
	if ( ( rc = vmbus_register_pages ( vmdev, &buffer->pages ) ) != 0 ) {
		DBGC ( netvsc, "NETVSC %s could not register transfer pages: "
		       "%s\n", netvsc->name, strerror ( rc ) );
		goto err_register_pages;
	}

	return 0;

	vmbus_unregister_pages ( vmdev, &buffer->pages );
 err_register_pages:
	vmbus_gpadl_teardown ( vmdev, gpadl );
 err_establish_gpadl:
	ufree ( buffer->data );
 err_alloc:
	return rc;
}

/**
 * Destroy data buffer
 *
 * @v netvsc		NetVSC device
 * @v buffer		Data buffer
 */
static void netvsc_destroy_buffer ( struct netvsc_device *netvsc,
				    struct netvsc_buffer *buffer ) {
	struct vmbus_device *vmdev = netvsc->vmdev;
	int rc;

	/* Unregister transfer pages */
	vmbus_unregister_pages ( vmdev, &buffer->pages );

	/* Tear down GPA descriptor list */
	if ( ( rc = vmbus_gpadl_teardown ( vmdev, buffer->gpadl ) ) != 0 ) {
		DBGC ( netvsc, "NETVSC %s could not tear down GPADL: %s\n",
		       netvsc->name, strerror ( rc ) );
		/* Death is imminent.  The host may well continue to
		 * write to the data buffer.  The best we can do is
		 * leak memory for now and hope that the host doesn't
		 * write to this region after we load an OS.
		 */
		return;
	}

	/* Free buffer */
	ufree ( buffer->data );
}

/**
 * Open device
 *
 * @v rndis		RNDIS device
 * @ret rc		Return status code
 */
static int netvsc_open ( struct rndis_device *rndis ) {
	struct netvsc_device *netvsc = rndis->priv;
	int rc;

	/* Initialise receive buffer */
	if ( ( rc = netvsc_create_buffer ( netvsc, &netvsc->rx ) ) != 0 )
		goto err_create_rx;

	/* Open channel */
	if ( ( rc = vmbus_open ( netvsc->vmdev, &netvsc_channel_operations,
				 PAGE_SIZE, PAGE_SIZE, NETVSC_MTU ) ) != 0 ) {
		DBGC ( netvsc, "NETVSC %s could not open VMBus: %s\n",
		       netvsc->name, strerror ( rc ) );
		goto err_vmbus_open;
	}

	/* Initialise communication with NetVSP */
	if ( ( rc = netvsc_initialise ( netvsc ) ) != 0 )
		goto err_initialise;
	if ( ( rc = netvsc_ndis_version ( netvsc ) ) != 0 )
		goto err_ndis_version;

	/* Initialise transmit ring */
	if ( ( rc = netvsc_create_ring ( netvsc, &netvsc->tx ) ) != 0 )
		goto err_create_tx;

	/* Establish receive buffer */
	if ( ( rc = netvsc_establish_buffer ( netvsc, &netvsc->rx ) ) != 0 )
		goto err_establish_rx;

	return 0;

	netvsc_revoke_buffer ( netvsc, &netvsc->rx );
 err_establish_rx:
	netvsc_destroy_ring ( netvsc, &netvsc->tx, NULL );
 err_create_tx:
 err_ndis_version:
 err_initialise:
	vmbus_close ( netvsc->vmdev );
 err_vmbus_open:
	netvsc_destroy_buffer ( netvsc, &netvsc->rx );
 err_create_rx:
	return rc;
}

/**
 * Close device
 *
 * @v rndis		RNDIS device
 */
static void netvsc_close ( struct rndis_device *rndis ) {
	struct netvsc_device *netvsc = rndis->priv;

	/* Revoke receive buffer */
	netvsc_revoke_buffer ( netvsc, &netvsc->rx );

	/* Destroy transmit ring */
	netvsc_destroy_ring ( netvsc, &netvsc->tx, netvsc_cancel_transmit );

	/* Close channel */
	vmbus_close ( netvsc->vmdev );

	/* Destroy receive buffer */
	netvsc_destroy_buffer ( netvsc, &netvsc->rx );
}

/** RNDIS operations */
static struct rndis_operations netvsc_operations = {
	.open = netvsc_open,
	.close = netvsc_close,
	.transmit = netvsc_transmit,
	.poll = netvsc_poll,
};

/**
 * Probe device
 *
 * @v vmdev		VMBus device
 * @ret rc		Return status code
 */
static int netvsc_probe ( struct vmbus_device *vmdev ) {
	struct netvsc_device *netvsc;
	struct rndis_device *rndis;
	int rc;

	/* Allocate and initialise structure */
	rndis = alloc_rndis ( sizeof ( *netvsc ) );
	if ( ! rndis ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	rndis_init ( rndis, &netvsc_operations );
	rndis->netdev->dev = &vmdev->dev;
	netvsc = rndis->priv;
	netvsc->vmdev = vmdev;
	netvsc->rndis = rndis;
	netvsc->name = vmdev->dev.name;
	netvsc_init_ring ( &netvsc->tx, NETVSC_TX_NUM_DESC,
			   netvsc->tx_iobufs, netvsc->tx_ids );
	netvsc_init_buffer ( &netvsc->rx, NETVSC_RX_BUF_PAGESET,
			     &netvsc_xfer_pages_operations,
			     NETVSC_RX_ESTABLISH_MSG, NETVSC_RX_ESTABLISH_XRID,
			     NETVSC_RX_REVOKE_MSG, NETVSC_RX_REVOKE_XRID,
			     NETVSC_RX_BUF_LEN );
	vmbus_set_drvdata ( vmdev, rndis );

	/* Register RNDIS device */
	if ( ( rc = register_rndis ( rndis ) ) != 0 ) {
		DBGC ( netvsc, "NETVSC %s could not register: %s\n",
		       netvsc->name, strerror ( rc ) );
		goto err_register;
	}

	return 0;

	unregister_rndis ( rndis );
 err_register:
	free_rndis ( rndis );
 err_alloc:
	return rc;
}

/**
 * Remove device
 *
 * @v vmdev		VMBus device
 */
static void netvsc_remove ( struct vmbus_device *vmdev ) {
	struct rndis_device *rndis = vmbus_get_drvdata ( vmdev );

	/* Unregister RNDIS device */
	unregister_rndis ( rndis );

	/* Free RNDIS device */
	free_rndis ( rndis );
}

/** NetVSC driver */
struct vmbus_driver netvsc_driver __vmbus_driver = {
	.name = "netvsc",
	.type = VMBUS_TYPE ( 0xf8615163, 0xdf3e, 0x46c5, 0x913f,
			     0xf2, 0xd2, 0xf9, 0x65, 0xed, 0x0e ),
	.probe = netvsc_probe,
	.remove = netvsc_remove,
};
