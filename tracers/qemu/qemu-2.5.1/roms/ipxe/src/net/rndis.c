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
 * Remote Network Driver Interface Specification
 *
 */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/ethernet.h>
#include <ipxe/device.h>
#include <ipxe/rndis.h>

/**
 * Allocate I/O buffer
 *
 * @v len		Length
 * @ret iobuf		I/O buffer, or NULL
 */
static struct io_buffer * rndis_alloc_iob ( size_t len ) {
	struct rndis_header *header;
	struct io_buffer *iobuf;

	/* Allocate I/O buffer and reserve space */
	iobuf = alloc_iob ( sizeof ( *header ) + len );
	if ( iobuf )
		iob_reserve ( iobuf, sizeof ( *header ) );

	return iobuf;
}

/**
 * Wait for completion
 *
 * @v rndis		RNDIS device
 * @v wait_id		Request ID
 * @ret rc		Return status code
 */
static int rndis_wait ( struct rndis_device *rndis, unsigned int wait_id ) {
	unsigned int i;

	/* Record query ID */
	rndis->wait_id = wait_id;

	/* Wait for operation to complete */
	for ( i = 0 ; i < RNDIS_MAX_WAIT_MS ; i++ ) {

		/* Check for completion */
		if ( ! rndis->wait_id )
			return rndis->wait_rc;

		/* Poll RNDIS device */
		rndis->op->poll ( rndis );

		/* Delay for 1ms */
		mdelay ( 1 );
	}

	DBGC ( rndis, "RNDIS %s timed out waiting for ID %#08x\n",
	       rndis->name, wait_id );
	return -ETIMEDOUT;
}

/**
 * Transmit message
 *
 * @v rndis		RNDIS device
 * @v iobuf		I/O buffer
 * @v type		Message type
 * @ret rc		Return status code
 */
static int rndis_tx_message ( struct rndis_device *rndis,
			      struct io_buffer *iobuf, unsigned int type ) {
	struct rndis_header *header;
	int rc;

	/* Prepend RNDIS header */
	header = iob_push ( iobuf, sizeof ( *header ) );
	header->type = cpu_to_le32 ( type );
	header->len = cpu_to_le32 ( iob_len ( iobuf ) );

	/* Transmit message */
	if ( ( rc = rndis->op->transmit ( rndis, iobuf ) ) != 0 ) {
		DBGC ( rndis, "RNDIS %s could not transmit: %s\n",
		       rndis->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Complete message transmission
 *
 * @v rndis		RNDIS device
 * @v iobuf		I/O buffer
 * @v rc		Packet status code
 */
void rndis_tx_complete_err ( struct rndis_device *rndis,
			     struct io_buffer *iobuf, int rc ) {
	struct net_device *netdev = rndis->netdev;
	struct rndis_header *header;
	size_t len = iob_len ( iobuf );

	/* Sanity check */
	if ( len < sizeof ( *header ) ) {
		DBGC ( rndis, "RNDIS %s completed underlength transmission:\n",
		       rndis->name );
		DBGC_HDA ( rndis, 0, iobuf->data, len );
		netdev_tx_err ( netdev, NULL, -EINVAL );
		return;
	}
	header = iobuf->data;

	/* Complete buffer */
	if ( header->type == cpu_to_le32 ( RNDIS_PACKET_MSG ) ) {
		netdev_tx_complete_err ( netdev, iobuf, rc );
	} else {
		free_iob ( iobuf );
	}
}

/**
 * Transmit data packet
 *
 * @v rndis		RNDIS device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int rndis_tx_data ( struct rndis_device *rndis,
			   struct io_buffer *iobuf ) {
	struct rndis_packet_message *msg;
	size_t len = iob_len ( iobuf );
	int rc;

	/* Prepend packet message header */
	msg = iob_push ( iobuf, sizeof ( *msg ) );
	memset ( msg, 0, sizeof ( *msg ) );
	msg->data.offset = cpu_to_le32 ( sizeof ( *msg ) );
	msg->data.len = cpu_to_le32 ( len );

	/* Transmit message */
	if ( ( rc = rndis_tx_message ( rndis, iobuf, RNDIS_PACKET_MSG ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Defer transmitted packet
 *
 * @v rndis		RNDIS device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 *
 * As with netdev_tx_defer(), the caller must ensure that space in the
 * transmit descriptor ring is freed up before calling
 * rndis_tx_complete().
 *
 * Unlike netdev_tx_defer(), this call may fail.
 */
int rndis_tx_defer ( struct rndis_device *rndis, struct io_buffer *iobuf ) {
	struct net_device *netdev = rndis->netdev;
	struct rndis_header *header;
	struct rndis_packet_message *msg;

	/* Fail unless this was a packet message.  Only packet
	 * messages correspond to I/O buffers in the network device's
	 * TX queue; other messages cannot be deferred in this way.
	 */
	assert ( iob_len ( iobuf ) >= sizeof ( *header ) );
	header = iobuf->data;
	if ( header->type != cpu_to_le32 ( RNDIS_PACKET_MSG ) )
		return -ENOTSUP;

	/* Strip RNDIS header and packet message header, to return
	 * this packet to the state in which we received it.
	 */
	iob_pull ( iobuf, ( sizeof ( *header ) + sizeof ( *msg ) ) );

	/* Defer packet */
	netdev_tx_defer ( netdev, iobuf );

	return 0;
}

/**
 * Receive data packet
 *
 * @v rndis		RNDIS device
 * @v iobuf		I/O buffer
 */
static void rndis_rx_data ( struct rndis_device *rndis,
			    struct io_buffer *iobuf ) {
	struct net_device *netdev = rndis->netdev;
	struct rndis_packet_message *msg;
	size_t len = iob_len ( iobuf );
	size_t data_offset;
	size_t data_len;
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *msg ) ) {
		DBGC ( rndis, "RNDIS %s received underlength data packet:\n",
		       rndis->name );
		DBGC_HDA ( rndis, 0, iobuf->data, len );
		rc = -EINVAL;
		goto err_len;
	}
	msg = iobuf->data;

	/* Locate and sanity check data buffer */
	data_offset = le32_to_cpu ( msg->data.offset );
	data_len = le32_to_cpu ( msg->data.len );
	if ( ( data_offset > len ) || ( data_len > ( len - data_offset ) ) ) {
		DBGC ( rndis, "RNDIS %s data packet data exceeds packet:\n",
		       rndis->name );
		DBGC_HDA ( rndis, 0, iobuf->data, len );
		rc = -EINVAL;
		goto err_data;
	}

	/* Strip non-data portions */
	iob_pull ( iobuf, data_offset );
	iob_unput ( iobuf, ( iob_len ( iobuf ) - data_len ) );

	/* Hand off to network stack */
	netdev_rx ( netdev, iob_disown ( iobuf ) );

	return;

 err_data:
 err_len:
	/* Report error to network stack */
	netdev_rx_err ( netdev, iob_disown ( iobuf ), rc );
}

/**
 * Transmit initialisation message
 *
 * @v rndis		RNDIS device
 * @v id		Request ID
 * @ret rc		Return status code
 */
static int rndis_tx_initialise ( struct rndis_device *rndis, unsigned int id ) {
	struct io_buffer *iobuf;
	struct rndis_initialise_message *msg;
	int rc;

	/* Allocate I/O buffer */
	iobuf = rndis_alloc_iob ( sizeof ( *msg ) );
	if ( ! iobuf ) {
		rc = -ENOMEM;
		goto err_alloc;
	}

	/* Construct message */
	msg = iob_put ( iobuf, sizeof ( *msg ) );
	memset ( msg, 0, sizeof ( *msg ) );
	msg->id = id; /* Non-endian */
	msg->major = cpu_to_le32 ( RNDIS_VERSION_MAJOR );
	msg->minor = cpu_to_le32 ( RNDIS_VERSION_MINOR );
	msg->mtu = cpu_to_le32 ( RNDIS_MTU );

	/* Transmit message */
	if ( ( rc = rndis_tx_message ( rndis, iobuf,
				       RNDIS_INITIALISE_MSG ) ) != 0 )
		goto err_tx;

	return 0;

 err_tx:
	free_iob ( iobuf );
 err_alloc:
	return rc;
}

/**
 * Receive initialisation completion
 *
 * @v rndis		RNDIS device
 * @v iobuf		I/O buffer
 */
static void rndis_rx_initialise ( struct rndis_device *rndis,
				  struct io_buffer *iobuf ) {
	struct rndis_initialise_completion *cmplt;
	size_t len = iob_len ( iobuf );
	unsigned int id;
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *cmplt ) ) {
		DBGC ( rndis, "RNDIS %s received underlength initialisation "
		       "completion:\n", rndis->name );
		DBGC_HDA ( rndis, 0, iobuf->data, len );
		rc = -EINVAL;
		goto err_len;
	}
	cmplt = iobuf->data;

	/* Extract request ID */
	id = cmplt->id; /* Non-endian */

	/* Check status */
	if ( cmplt->status ) {
		DBGC ( rndis, "RNDIS %s received initialisation completion "
		       "failure %#08x\n", rndis->name,
		       le32_to_cpu ( cmplt->status ) );
		rc = -EIO;
		goto err_status;
	}

	/* Success */
	rc = 0;

 err_status:
	/* Record completion result if applicable */
	if ( id == rndis->wait_id ) {
		rndis->wait_id = 0;
		rndis->wait_rc = rc;
	}
 err_len:
	free_iob ( iobuf );
}

/**
 * Initialise RNDIS
 *
 * @v rndis		RNDIS device
 * @ret rc		Return status code
 */
static int rndis_initialise ( struct rndis_device *rndis ) {
	int rc;

	/* Transmit initialisation message */
	if ( ( rc = rndis_tx_initialise ( rndis, RNDIS_INIT_ID ) ) != 0 )
		return rc;

	/* Wait for response */
	if ( ( rc = rndis_wait ( rndis, RNDIS_INIT_ID ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Transmit halt message
 *
 * @v rndis		RNDIS device
 * @ret rc		Return status code
 */
static int rndis_tx_halt ( struct rndis_device *rndis ) {
	struct io_buffer *iobuf;
	struct rndis_halt_message *msg;
	int rc;

	/* Allocate I/O buffer */
	iobuf = rndis_alloc_iob ( sizeof ( *msg ) );
	if ( ! iobuf ) {
		rc = -ENOMEM;
		goto err_alloc;
	}

	/* Construct message */
	msg = iob_put ( iobuf, sizeof ( *msg ) );
	memset ( msg, 0, sizeof ( *msg ) );

	/* Transmit message */
	if ( ( rc = rndis_tx_message ( rndis, iobuf, RNDIS_HALT_MSG ) ) != 0 )
		goto err_tx;

	return 0;

 err_tx:
	free_iob ( iobuf );
 err_alloc:
	return rc;
}

/**
 * Halt RNDIS
 *
 * @v rndis		RNDIS device
 * @ret rc		Return status code
 */
static int rndis_halt ( struct rndis_device *rndis ) {
	int rc;

	/* Transmit halt message */
	if ( ( rc = rndis_tx_halt ( rndis ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Transmit OID message
 *
 * @v rndis		RNDIS device
 * @v oid		Object ID
 * @v data		New OID value (or NULL to query current value)
 * @v len		Length of new OID value
 * @ret rc		Return status code
 */
static int rndis_tx_oid ( struct rndis_device *rndis, unsigned int oid,
			  const void *data, size_t len ) {
	struct io_buffer *iobuf;
	struct rndis_oid_message *msg;
	unsigned int type;
	int rc;

	/* Allocate I/O buffer */
	iobuf = rndis_alloc_iob ( sizeof ( *msg ) + len );
	if ( ! iobuf ) {
		rc = -ENOMEM;
		goto err_alloc;
	}

	/* Construct message.  We use the OID as the request ID. */
	msg = iob_put ( iobuf, sizeof ( *msg ) );
	memset ( msg, 0, sizeof ( *msg ) );
	msg->id = oid; /* Non-endian */
	msg->oid = cpu_to_le32 ( oid );
	msg->offset = cpu_to_le32 ( sizeof ( *msg ) );
	msg->len = cpu_to_le32 ( len );
	memcpy ( iob_put ( iobuf, len ), data, len );

	/* Transmit message */
	type = ( data ? RNDIS_SET_MSG : RNDIS_QUERY_MSG );
	if ( ( rc = rndis_tx_message ( rndis, iobuf, type ) ) != 0 )
		goto err_tx;

	return 0;

 err_tx:
	free_iob ( iobuf );
 err_alloc:
	return rc;
}

/**
 * Receive query OID completion
 *
 * @v rndis		RNDIS device
 * @v iobuf		I/O buffer
 */
static void rndis_rx_query_oid ( struct rndis_device *rndis,
				 struct io_buffer *iobuf ) {
	struct net_device *netdev = rndis->netdev;
	struct rndis_query_completion *cmplt;
	size_t len = iob_len ( iobuf );
	size_t info_offset;
	size_t info_len;
	unsigned int id;
	void *info;
	uint32_t *link_status;
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *cmplt ) ) {
		DBGC ( rndis, "RNDIS %s received underlength query "
		       "completion:\n", rndis->name );
		DBGC_HDA ( rndis, 0, iobuf->data, len );
		rc = -EINVAL;
		goto err_len;
	}
	cmplt = iobuf->data;

	/* Extract request ID */
	id = cmplt->id; /* Non-endian */

	/* Check status */
	if ( cmplt->status ) {
		DBGC ( rndis, "RNDIS %s received query completion failure "
		       "%#08x\n", rndis->name, le32_to_cpu ( cmplt->status ) );
		DBGC_HDA ( rndis, 0, iobuf->data, len );
		rc = -EIO;
		goto err_status;
	}

	/* Locate and sanity check information buffer */
	info_offset = le32_to_cpu ( cmplt->offset );
	info_len = le32_to_cpu ( cmplt->len );
	if ( ( info_offset > len ) || ( info_len > ( len - info_offset ) ) ) {
		DBGC ( rndis, "RNDIS %s query completion information exceeds "
		       "packet:\n", rndis->name );
		DBGC_HDA ( rndis, 0, iobuf->data, len );
		rc = -EINVAL;
		goto err_info;
	}
	info = ( ( ( void * ) cmplt ) + info_offset );

	/* Handle OID */
	switch ( id ) {

	case RNDIS_OID_802_3_PERMANENT_ADDRESS:
		if ( info_len > sizeof ( netdev->hw_addr ) )
			info_len = sizeof ( netdev->hw_addr );
		memcpy ( netdev->hw_addr, info, info_len );
		break;

	case RNDIS_OID_802_3_CURRENT_ADDRESS:
		if ( info_len > sizeof ( netdev->ll_addr ) )
			info_len = sizeof ( netdev->ll_addr );
		memcpy ( netdev->ll_addr, info, info_len );
		break;

	case RNDIS_OID_GEN_MEDIA_CONNECT_STATUS:
		if ( info_len != sizeof ( *link_status ) ) {
			DBGC ( rndis, "RNDIS %s invalid link status:\n",
			       rndis->name );
			DBGC_HDA ( rndis, 0, iobuf->data, len );
			rc = -EPROTO;
			goto err_link_status;
		}
		link_status = info;
		if ( *link_status == 0 ) {
			DBGC ( rndis, "RNDIS %s link is up\n", rndis->name );
			netdev_link_up ( netdev );
		} else {
			DBGC ( rndis, "RNDIS %s link is down: %#08x\n",
			       rndis->name, le32_to_cpu ( *link_status ) );
			netdev_link_down ( netdev );
		}
		break;

	default:
		DBGC ( rndis, "RNDIS %s unexpected query completion ID %#08x\n",
		       rndis->name, id );
		DBGC_HDA ( rndis, 0, iobuf->data, len );
		rc = -EPROTO;
		goto err_id;
	}

	/* Success */
	rc = 0;

 err_id:
 err_link_status:
 err_info:
 err_status:
	/* Record completion result if applicable */
	if ( id == rndis->wait_id ) {
		rndis->wait_id = 0;
		rndis->wait_rc = rc;
	}
 err_len:
	/* Free I/O buffer */
	free_iob ( iobuf );
}

/**
 * Receive set OID completion
 *
 * @v rndis		RNDIS device
 * @v iobuf		I/O buffer
 */
static void rndis_rx_set_oid ( struct rndis_device *rndis,
			       struct io_buffer *iobuf ) {
	struct rndis_set_completion *cmplt;
	size_t len = iob_len ( iobuf );
	unsigned int id;
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *cmplt ) ) {
		DBGC ( rndis, "RNDIS %s received underlength set completion:\n",
		       rndis->name );
		DBGC_HDA ( rndis, 0, iobuf->data, len );
		rc = -EINVAL;
		goto err_len;
	}
	cmplt = iobuf->data;

	/* Extract request ID */
	id = cmplt->id; /* Non-endian */

	/* Check status */
	if ( cmplt->status ) {
		DBGC ( rndis, "RNDIS %s received set completion failure "
		       "%#08x\n", rndis->name, le32_to_cpu ( cmplt->status ) );
		DBGC_HDA ( rndis, 0, iobuf->data, len );
		rc = -EIO;
		goto err_status;
	}

	/* Success */
	rc = 0;

 err_status:
	/* Record completion result if applicable */
	if ( id == rndis->wait_id ) {
		rndis->wait_id = 0;
		rndis->wait_rc = rc;
	}
 err_len:
	/* Free I/O buffer */
	free_iob ( iobuf );
}

/**
 * Query or set OID
 *
 * @v rndis		RNDIS device
 * @v oid		Object ID
 * @v data		New OID value (or NULL to query current value)
 * @v len		Length of new OID value
 * @ret rc		Return status code
 */
static int rndis_oid ( struct rndis_device *rndis, unsigned int oid,
		       const void *data, size_t len ) {
	int rc;

	/* Transmit query */
	if ( ( rc = rndis_tx_oid ( rndis, oid, data, len ) ) != 0 )
		return rc;

	/* Wait for response */
	if ( ( rc = rndis_wait ( rndis, oid ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Receive indicate status message
 *
 * @v rndis		RNDIS device
 * @v iobuf		I/O buffer
 */
static void rndis_rx_status ( struct rndis_device *rndis,
			      struct io_buffer *iobuf ) {
	struct net_device *netdev = rndis->netdev;
	struct rndis_indicate_status_message *msg;
	size_t len = iob_len ( iobuf );
	unsigned int status;
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *msg ) ) {
		DBGC ( rndis, "RNDIS %s received underlength status message:\n",
		       rndis->name );
		DBGC_HDA ( rndis, 0, iobuf->data, len );
		rc = -EINVAL;
		goto err_len;
	}
	msg = iobuf->data;

	/* Extract status */
	status = le32_to_cpu ( msg->status );

	/* Handle status */
	switch ( msg->status ) {

	case RNDIS_STATUS_MEDIA_CONNECT:
		DBGC ( rndis, "RNDIS %s link is up\n", rndis->name );
		netdev_link_up ( netdev );
		break;

	case RNDIS_STATUS_MEDIA_DISCONNECT:
		DBGC ( rndis, "RNDIS %s link is down\n", rndis->name );
		netdev_link_down ( netdev );
		break;

	case RNDIS_STATUS_WTF_WORLD:
		/* Ignore */
		break;

	default:
		DBGC ( rndis, "RNDIS %s unexpected status %#08x:\n",
		       rndis->name, status );
		DBGC_HDA ( rndis, 0, iobuf->data, len );
		rc = -ENOTSUP;
		goto err_status;
	}

	/* Free I/O buffer */
	free_iob ( iobuf );

	return;

 err_status:
 err_len:
	/* Report error via network device statistics */
	netdev_rx_err ( netdev, iobuf, rc );
}

/**
 * Receive RNDIS message
 *
 * @v rndis		RNDIS device
 * @v iobuf		I/O buffer
 * @v type		Message type
 */
static void rndis_rx_message ( struct rndis_device *rndis,
			       struct io_buffer *iobuf, unsigned int type ) {
	struct net_device *netdev = rndis->netdev;
	int rc;

	/* Handle packet */
	switch ( type ) {

	case RNDIS_PACKET_MSG:
		rndis_rx_data ( rndis, iob_disown ( iobuf ) );
		break;

	case RNDIS_INITIALISE_CMPLT:
		rndis_rx_initialise ( rndis, iob_disown ( iobuf ) );
		break;

	case RNDIS_QUERY_CMPLT:
		rndis_rx_query_oid ( rndis, iob_disown ( iobuf ) );
		break;

	case RNDIS_SET_CMPLT:
		rndis_rx_set_oid ( rndis, iob_disown ( iobuf ) );
		break;

	case RNDIS_INDICATE_STATUS_MSG:
		rndis_rx_status ( rndis, iob_disown ( iobuf ) );
		break;

	default:
		DBGC ( rndis, "RNDIS %s received unexpected type %#08x\n",
		       rndis->name, type );
		DBGC_HDA ( rndis, 0, iobuf->data, iob_len ( iobuf ) );
		rc = -EPROTO;
		goto err_type;
	}

	return;

 err_type:
	/* Report error via network device statistics */
	netdev_rx_err ( netdev, iobuf, rc );
}

/**
 * Receive packet from underlying transport layer
 *
 * @v rndis		RNDIS device
 * @v iobuf		I/O buffer
 */
void rndis_rx ( struct rndis_device *rndis, struct io_buffer *iobuf ) {
	struct net_device *netdev = rndis->netdev;
	struct rndis_header *header;
	unsigned int type;
	int rc;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *header ) ) {
		DBGC ( rndis, "RNDIS %s received underlength packet:\n",
		       rndis->name );
		DBGC_HDA ( rndis, 0, iobuf->data, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto drop;
	}
	header = iobuf->data;

	/* Parse and strip header */
	type = le32_to_cpu ( header->type );
	iob_pull ( iobuf, sizeof ( *header ) );

	/* Handle message */
	rndis_rx_message ( rndis, iob_disown ( iobuf ), type );

	return;

 drop:
	/* Record error */
	netdev_rx_err ( netdev, iob_disown ( iobuf ), rc );
}

/**
 * Discard packet from underlying transport layer
 *
 * @v rndis		RNDIS device
 * @v iobuf		I/O buffer
 * @v rc		Packet status code
 */
void rndis_rx_err ( struct rndis_device *rndis, struct io_buffer *iobuf,
		    int rc ) {
	struct net_device *netdev = rndis->netdev;

	/* Record error */
	netdev_rx_err ( netdev, iob_disown ( iobuf ), rc );
}

/**
 * Set receive filter
 *
 * @v rndis		RNDIS device
 * @v filter		Receive filter
 * @ret rc		Return status code
 */
static int rndis_filter ( struct rndis_device *rndis, unsigned int filter ) {
	uint32_t value = cpu_to_le32 ( filter );
	int rc;

	/* Set receive filter */
	if ( ( rc = rndis_oid ( rndis, RNDIS_OID_GEN_CURRENT_PACKET_FILTER,
				&value, sizeof ( value ) ) ) != 0 ) {
		DBGC ( rndis, "RNDIS %s could not set receive filter to %#08x: "
		       "%s\n", rndis->name, filter, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Open network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int rndis_open ( struct net_device *netdev ) {
	struct rndis_device *rndis = netdev->priv;
	int rc;

	/* Open RNDIS device */
	if ( ( rc = rndis->op->open ( rndis ) ) != 0 ) {
		DBGC ( rndis, "RNDIS %s could not open: %s\n",
		       rndis->name, strerror ( rc ) );
		goto err_open;
	}

	/* Initialise RNDIS */
	if ( ( rc = rndis_initialise ( rndis ) ) != 0 )
		goto err_initialise;

	/* Set receive filter */
	if ( ( rc = rndis_filter ( rndis, ( RNDIS_FILTER_UNICAST |
					    RNDIS_FILTER_MULTICAST |
					    RNDIS_FILTER_ALL_MULTICAST |
					    RNDIS_FILTER_BROADCAST |
					    RNDIS_FILTER_PROMISCUOUS ) ) ) != 0)
		goto err_set_filter;

	/* Update link status */
	if ( ( rc = rndis_oid ( rndis, RNDIS_OID_GEN_MEDIA_CONNECT_STATUS,
				NULL, 0 ) ) != 0 )
		goto err_query_link;

	return 0;

 err_query_link:
 err_set_filter:
	rndis_halt ( rndis );
 err_initialise:
	rndis->op->close ( rndis );
 err_open:
	return rc;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
static void rndis_close ( struct net_device *netdev ) {
	struct rndis_device *rndis = netdev->priv;

	/* Clear receive filter */
	rndis_filter ( rndis, 0 );

	/* Halt RNDIS device */
	rndis_halt ( rndis );

	/* Close RNDIS device */
	rndis->op->close ( rndis );
}

/**
 * Transmit packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int rndis_transmit ( struct net_device *netdev,
			    struct io_buffer *iobuf ) {
	struct rndis_device *rndis = netdev->priv;

	/* Transmit data packet */
	return rndis_tx_data ( rndis, iobuf );
}

/**
 * Poll for completed and received packets
 *
 * @v netdev		Network device
 */
static void rndis_poll ( struct net_device *netdev ) {
	struct rndis_device *rndis = netdev->priv;

	/* Poll RNDIS device */
	rndis->op->poll ( rndis );
}

/** Network device operations */
static struct net_device_operations rndis_operations = {
	.open		= rndis_open,
	.close		= rndis_close,
	.transmit	= rndis_transmit,
	.poll		= rndis_poll,
};

/**
 * Allocate RNDIS device
 *
 * @v priv_len		Length of private data
 * @ret rndis		RNDIS device, or NULL on allocation failure
 */
struct rndis_device * alloc_rndis ( size_t priv_len ) {
	struct net_device *netdev;
	struct rndis_device *rndis;

	/* Allocate and initialise structure */
	netdev = alloc_etherdev ( sizeof ( *rndis ) + priv_len );
	if ( ! netdev )
		return NULL;
	netdev_init ( netdev, &rndis_operations );
	rndis = netdev->priv;
	rndis->netdev = netdev;
	rndis->priv = ( ( ( void * ) rndis ) + sizeof ( *rndis ) );

	return rndis;
}

/**
 * Register RNDIS device
 *
 * @v rndis		RNDIS device
 * @ret rc		Return status code
 *
 * Note that this routine will open and use the RNDIS device in order
 * to query the MAC address.  The device must be immediately ready for
 * use prior to registration.
 */
int register_rndis ( struct rndis_device *rndis ) {
	struct net_device *netdev = rndis->netdev;
	int rc;

	/* Assign device name (for debugging) */
	rndis->name = netdev->dev->name;

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 ) {
		DBGC ( rndis, "RNDIS %s could not register: %s\n",
		       rndis->name, strerror ( rc ) );
		goto err_register;
	}

	/* Open RNDIS device to read MAC addresses */
	if ( ( rc = rndis->op->open ( rndis ) ) != 0 ) {
		DBGC ( rndis, "RNDIS %s could not open: %s\n",
		       rndis->name, strerror ( rc ) );
		goto err_open;
	}

	/* Initialise RNDIS */
	if ( ( rc = rndis_initialise ( rndis ) ) != 0 )
		goto err_initialise;

	/* Query permanent MAC address */
	if ( ( rc = rndis_oid ( rndis, RNDIS_OID_802_3_PERMANENT_ADDRESS,
				NULL, 0 ) ) != 0 )
		goto err_query_permanent;

	/* Query current MAC address */
	if ( ( rc = rndis_oid ( rndis, RNDIS_OID_802_3_CURRENT_ADDRESS,
				NULL, 0 ) ) != 0 )
		goto err_query_current;

	/* Get link status */
	if ( ( rc = rndis_oid ( rndis, RNDIS_OID_GEN_MEDIA_CONNECT_STATUS,
				NULL, 0 ) ) != 0 )
		goto err_query_link;

	/* Halt RNDIS device */
	rndis_halt ( rndis );

	/* Close RNDIS device */
	rndis->op->close ( rndis );

	return 0;

 err_query_link:
 err_query_current:
 err_query_permanent:
	rndis_halt ( rndis );
 err_initialise:
	rndis->op->close ( rndis );
 err_open:
	unregister_netdev ( netdev );
 err_register:
	return rc;
}

/**
 * Unregister RNDIS device
 *
 * @v rndis		RNDIS device
 */
void unregister_rndis ( struct rndis_device *rndis ) {
	struct net_device *netdev = rndis->netdev;

	/* Unregister network device */
	unregister_netdev ( netdev );
}

/**
 * Free RNDIS device
 *
 * @v rndis		RNDIS device
 */
void free_rndis ( struct rndis_device *rndis ) {
	struct net_device *netdev = rndis->netdev;

	/* Free network device */
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}
