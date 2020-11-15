/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <strings.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/features.h>
#include <ipxe/iobuf.h>
#include <ipxe/bitmap.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/uri.h>
#include <ipxe/tcpip.h>
#include <ipxe/timer.h>
#include <ipxe/retry.h>

/** @file
 *
 * Scalable Local Area Multicast protocol
 *
 * The SLAM protocol is supported only by Etherboot; it was designed
 * and implemented by Eric Biederman.  A server implementation is
 * available in contrib/mini-slamd.  There does not appear to be any
 * documentation beyond a few sparse comments in Etherboot's
 * proto_slam.c.
 *
 * SLAM packets use three types of data field:
 *
 *  Nul : A single NUL (0) byte, used as a list terminator
 *
 *  Raw : A block of raw data
 *
 *  Int : A variable-length integer, in big-endian order.  The length
 *        of the integer is encoded in the most significant three bits.
 *
 * Packets received by the client have the following layout:
 *
 *  Int : Transaction identifier.  This is an opaque value.
 *
 *  Int : Total number of bytes in the transfer.
 *
 *  Int : Block size, in bytes.
 *
 *  Int : Packet sequence number within the transfer (if this packet
 *        contains data).
 *
 *  Raw : Packet data (if this packet contains data).
 *
 * Packets transmitted by the client consist of a run-length-encoded
 * representation of the received-blocks bitmap, looking something
 * like:
 *
 *  Int : Number of consecutive successfully-received packets
 *  Int : Number of consecutive missing packets
 *  Int : Number of consecutive successfully-received packets
 *  Int : Number of consecutive missing packets
 *  ....
 *  Nul
 *
 */

FEATURE ( FEATURE_PROTOCOL, "SLAM", DHCP_EB_FEATURE_SLAM, 1 );

/** Default SLAM server port */
#define SLAM_DEFAULT_PORT 10000

/** Default SLAM multicast IP address */
#define SLAM_DEFAULT_MULTICAST_IP \
	( ( 239 << 24 ) | ( 255 << 16 ) | ( 1 << 8 ) | ( 1 << 0 ) )

/** Default SLAM multicast port */
#define SLAM_DEFAULT_MULTICAST_PORT 10000

/** Maximum SLAM header length */
#define SLAM_MAX_HEADER_LEN ( 7 /* transaction id */ + 7 /* total_bytes */ + \
			      7 /* block_size */ )

/** Maximum number of blocks to request per NACK
 *
 * This is a policy decision equivalent to selecting a TCP window
 * size.
 */
#define SLAM_MAX_BLOCKS_PER_NACK 4

/** Maximum SLAM NACK length
 *
 * We only ever send a NACK for a single range of up to @c
 * SLAM_MAX_BLOCKS_PER_NACK blocks.
 */
#define SLAM_MAX_NACK_LEN ( 7 /* block */ + 7 /* #blocks */ + 1 /* NUL */ )

/** SLAM slave timeout */
#define SLAM_SLAVE_TIMEOUT ( 1 * TICKS_PER_SEC )

/** A SLAM request */
struct slam_request {
	/** Reference counter */
	struct refcnt refcnt;

	/** Data transfer interface */
	struct interface xfer;
	/** Unicast socket */
	struct interface socket;
	/** Multicast socket */
	struct interface mc_socket;

	/** Master client retry timer */
	struct retry_timer master_timer;
	/** Slave client retry timer */
	struct retry_timer slave_timer;

	/** Cached header */
	uint8_t header[SLAM_MAX_HEADER_LEN];
	/** Size of cached header */
	size_t header_len;
	/** Total number of bytes in transfer */
	unsigned long total_bytes;
	/** Transfer block size */
	unsigned long block_size;
	/** Number of blocks in transfer */
	unsigned long num_blocks;
	/** Block bitmap */
	struct bitmap bitmap;
	/** NACK sent flag */
	int nack_sent;
};

/**
 * Free a SLAM request
 *
 * @v refcnt		Reference counter
 */
static void slam_free ( struct refcnt *refcnt ) {
	struct slam_request *slam =
		container_of ( refcnt, struct slam_request, refcnt );

	bitmap_free ( &slam->bitmap );
	free ( slam );
}

/**
 * Mark SLAM request as complete
 *
 * @v slam		SLAM request
 * @v rc		Return status code
 */
static void slam_finished ( struct slam_request *slam, int rc ) {
	static const uint8_t slam_disconnect[] = { 0 };

	DBGC ( slam, "SLAM %p finished with status code %d (%s)\n",
	       slam, rc, strerror ( rc ) );

	/* Send a disconnect message if we ever sent anything to the
	 * server.
	 */
	if ( slam->nack_sent ) {
		xfer_deliver_raw ( &slam->socket, slam_disconnect,
				   sizeof ( slam_disconnect ) );
	}

	/* Stop the retry timers */
	stop_timer ( &slam->master_timer );
	stop_timer ( &slam->slave_timer );

	/* Close all data transfer interfaces */
	intf_shutdown ( &slam->socket, rc );
	intf_shutdown ( &slam->mc_socket, rc );
	intf_shutdown ( &slam->xfer, rc );
}

/****************************************************************************
 *
 * TX datapath
 *
 */

/**
 * Add a variable-length value to a SLAM packet
 *
 * @v slam		SLAM request
 * @v iobuf		I/O buffer
 * @v value		Value to add
 * @ret rc		Return status code
 *
 * Adds a variable-length value to the end of an I/O buffer.  Will
 * always leave at least one byte of tailroom in the I/O buffer (to
 * allow space for the terminating NUL).
 */
static int slam_put_value ( struct slam_request *slam,
			    struct io_buffer *iobuf, unsigned long value ) {
	uint8_t *data;
	size_t len;
	unsigned int i;

	/* Calculate variable length required to store value.  Always
	 * leave at least one byte in the I/O buffer.
	 */
	len = ( ( flsl ( value ) + 10 ) / 8 );
	if ( len >= iob_tailroom ( iobuf ) ) {
		DBGC2 ( slam, "SLAM %p cannot add %zd-byte value\n",
			slam, len );
		return -ENOBUFS;
	}
	/* There is no valid way within the protocol that we can end
	 * up trying to push a full-sized long (i.e. without space for
	 * the length encoding).
	 */
	assert ( len <= sizeof ( value ) );

	/* Add value */
	data = iob_put ( iobuf, len );
	for ( i = len ; i-- ; ) {
		data[i] = value;
		value >>= 8;
	}
	*data |= ( len << 5 );
	assert ( value == 0 );

	return 0;
}

/**
 * Send SLAM NACK packet
 *
 * @v slam		SLAM request
 * @ret rc		Return status code
 */
static int slam_tx_nack ( struct slam_request *slam ) {
	struct io_buffer *iobuf;
	unsigned long first_block;
	unsigned long num_blocks;
	uint8_t *nul;
	int rc;

	/* Mark NACK as sent, so that we know we have to disconnect later */
	slam->nack_sent = 1;

	/* Allocate I/O buffer */
	iobuf = xfer_alloc_iob ( &slam->socket,	SLAM_MAX_NACK_LEN );
	if ( ! iobuf ) {
		DBGC ( slam, "SLAM %p could not allocate I/O buffer\n",
		       slam );
		return -ENOMEM;
	}

	/* Construct NACK.  We always request only a single packet;
	 * this allows us to force multicast-TFTP-style flow control
	 * on the SLAM server, which will otherwise just blast the
	 * data out as fast as it can.  On a gigabit network, without
	 * RX checksumming, this would inevitably cause packet drops.
	 */
	first_block = bitmap_first_gap ( &slam->bitmap );
	for ( num_blocks = 1 ; ; num_blocks++ ) {
		if ( num_blocks >= SLAM_MAX_BLOCKS_PER_NACK )
			break;
		if ( ( first_block + num_blocks ) >= slam->num_blocks )
			break;
		if ( bitmap_test ( &slam->bitmap,
				   ( first_block + num_blocks ) ) )
			break;
	}
	if ( first_block ) {
		DBGCP ( slam, "SLAM %p transmitting NACK for blocks "
			"%ld-%ld\n", slam, first_block,
			( first_block + num_blocks - 1 ) );
	} else {
		DBGC ( slam, "SLAM %p transmitting initial NACK for blocks "
		       "0-%ld\n", slam, ( num_blocks - 1 ) );
	}
	if ( ( rc = slam_put_value ( slam, iobuf, first_block ) ) != 0 )
		return rc;
	if ( ( rc = slam_put_value ( slam, iobuf, num_blocks ) ) != 0 )
		return rc;
	nul = iob_put ( iobuf, 1 );
	*nul = 0;

	/* Transmit packet */
	return xfer_deliver_iob ( &slam->socket, iobuf );
}

/**
 * Handle SLAM master client retry timer expiry
 *
 * @v timer		Master retry timer
 * @v fail		Failure indicator
 */
static void slam_master_timer_expired ( struct retry_timer *timer,
					int fail ) {
	struct slam_request *slam =
		container_of ( timer, struct slam_request, master_timer );

	if ( fail ) {
		/* Allow timer to stop running.  We will terminate the
		 * connection only if the slave timer times out.
		 */
		DBGC ( slam, "SLAM %p giving up acting as master client\n",
		       slam );
	} else {
		/* Retransmit NACK */
		start_timer ( timer );
		slam_tx_nack ( slam );
	}
}

/**
 * Handle SLAM slave client retry timer expiry
 *
 * @v timer		Master retry timer
 * @v fail		Failure indicator
 */
static void slam_slave_timer_expired ( struct retry_timer *timer,
					int fail ) {
	struct slam_request *slam =
		container_of ( timer, struct slam_request, slave_timer );

	if ( fail ) {
		/* Terminate connection */
		slam_finished ( slam, -ETIMEDOUT );
	} else {
		/* Try sending a NACK */
		DBGC ( slam, "SLAM %p trying to become master client\n",
		       slam );
		start_timer ( timer );
		slam_tx_nack ( slam );
	}
}

/****************************************************************************
 *
 * RX datapath
 *
 */

/**
 * Read and strip a variable-length value from a SLAM packet
 *
 * @v slam		SLAM request
 * @v iobuf		I/O buffer
 * @v value		Value to fill in, or NULL to ignore value
 * @ret rc		Return status code
 *
 * Reads a variable-length value from the start of the I/O buffer.  
 */
static int slam_pull_value ( struct slam_request *slam,
			     struct io_buffer *iobuf,
			     unsigned long *value ) {
	uint8_t *data;
	size_t len;

	/* Sanity check */
	if ( iob_len ( iobuf ) == 0 ) {
		DBGC ( slam, "SLAM %p empty value\n", slam );
		return -EINVAL;
	}

	/* Read and verify length of value */
	data = iobuf->data;
	len = ( *data >> 5 );
	if ( ( len == 0 ) ||
	     ( value && ( len > sizeof ( *value ) ) ) ) {
		DBGC ( slam, "SLAM %p invalid value length %zd bytes\n",
		       slam, len );
		return -EINVAL;
	}
	if ( len > iob_len ( iobuf ) ) {
		DBGC ( slam, "SLAM %p value extends beyond I/O buffer\n",
		       slam );
		return -EINVAL;
	}

	/* Read value */
	iob_pull ( iobuf, len );
	*value = ( *data & 0x1f );
	while ( --len ) {
		*value <<= 8;
		*value |= *(++data);
	}

	return 0;
}

/**
 * Read and strip SLAM header
 *
 * @v slam		SLAM request
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int slam_pull_header ( struct slam_request *slam,
			      struct io_buffer *iobuf ) {
	void *header = iobuf->data;
	int rc;

	/* If header matches cached header, just pull it and return */
	if ( ( slam->header_len <= iob_len ( iobuf ) ) &&
	     ( memcmp ( slam->header, iobuf->data, slam->header_len ) == 0 )){
		iob_pull ( iobuf, slam->header_len );
		return 0;
	}

	DBGC ( slam, "SLAM %p detected changed header; resetting\n", slam );

	/* Read and strip transaction ID, total number of bytes, and
	 * block size.
	 */
	if ( ( rc = slam_pull_value ( slam, iobuf, NULL ) ) != 0 )
		return rc;
	if ( ( rc = slam_pull_value ( slam, iobuf,
				      &slam->total_bytes ) ) != 0 )
		return rc;
	if ( ( rc = slam_pull_value ( slam, iobuf,
				      &slam->block_size ) ) != 0 )
		return rc;

	/* Update the cached header */
	slam->header_len = ( iobuf->data - header );
	assert ( slam->header_len <= sizeof ( slam->header ) );
	memcpy ( slam->header, header, slam->header_len );

	/* Calculate number of blocks */
	slam->num_blocks = ( ( slam->total_bytes + slam->block_size - 1 ) /
			     slam->block_size );

	DBGC ( slam, "SLAM %p has total bytes %ld, block size %ld, num "
	       "blocks %ld\n", slam, slam->total_bytes, slam->block_size,
	       slam->num_blocks );

	/* Discard and reset the bitmap */
	bitmap_free ( &slam->bitmap );
	memset ( &slam->bitmap, 0, sizeof ( slam->bitmap ) );

	/* Allocate a new bitmap */
	if ( ( rc = bitmap_resize ( &slam->bitmap,
				    slam->num_blocks ) ) != 0 ) {
		/* Failure to allocate a bitmap is fatal */
		DBGC ( slam, "SLAM %p could not allocate bitmap for %ld "
		       "blocks: %s\n", slam, slam->num_blocks,
		       strerror ( rc ) );
		slam_finished ( slam, rc );
		return rc;
	}

	/* Notify recipient of file size */
	xfer_seek ( &slam->xfer, slam->total_bytes );

	return 0;
}

/**
 * Receive SLAM data packet
 *
 * @v slam		SLAM request
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int slam_mc_socket_deliver ( struct slam_request *slam,
				    struct io_buffer *iobuf,
				    struct xfer_metadata *rx_meta __unused ) {
	struct xfer_metadata meta;
	unsigned long packet;
	size_t len;
	int rc;

	/* Stop the master client timer.  Restart the slave client timer. */
	stop_timer ( &slam->master_timer );
	stop_timer ( &slam->slave_timer );
	start_timer_fixed ( &slam->slave_timer, SLAM_SLAVE_TIMEOUT );

	/* Read and strip packet header */
	if ( ( rc = slam_pull_header ( slam, iobuf ) ) != 0 )
		goto err_discard;

	/* Read and strip packet number */
	if ( ( rc = slam_pull_value ( slam, iobuf, &packet ) ) != 0 )
		goto err_discard;

	/* Sanity check packet number */
	if ( packet >= slam->num_blocks ) {
		DBGC ( slam, "SLAM %p received out-of-range packet %ld "
		       "(num_blocks=%ld)\n", slam, packet, slam->num_blocks );
		rc = -EINVAL;
		goto err_discard;
	}

	/* Sanity check length */
	len = iob_len ( iobuf );
	if ( len > slam->block_size ) {
		DBGC ( slam, "SLAM %p received oversize packet of %zd bytes "
		       "(block_size=%ld)\n", slam, len, slam->block_size );
		rc = -EINVAL;
		goto err_discard;
	}
	if ( ( packet != ( slam->num_blocks - 1 ) ) &&
	     ( len < slam->block_size ) ) {
		DBGC ( slam, "SLAM %p received short packet of %zd bytes "
		       "(block_size=%ld)\n", slam, len, slam->block_size );
		rc = -EINVAL;
		goto err_discard;
	}

	/* If we have already seen this packet, discard it */
	if ( bitmap_test ( &slam->bitmap, packet ) ) {
		goto discard;
	}

	/* Pass to recipient */
	memset ( &meta, 0, sizeof ( meta ) );
	meta.flags = XFER_FL_ABS_OFFSET;
	meta.offset = ( packet * slam->block_size );
	if ( ( rc = xfer_deliver ( &slam->xfer, iobuf, &meta ) ) != 0 )
		goto err;

	/* Mark block as received */
	bitmap_set ( &slam->bitmap, packet );

	/* If we have received all blocks, terminate */
	if ( bitmap_full ( &slam->bitmap ) )
		slam_finished ( slam, 0 );

	return 0;

 err_discard:
 discard:
	free_iob ( iobuf );
 err:
	return rc;
}

/**
 * Receive SLAM non-data packet
 *
 * @v slam		SLAM request
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int slam_socket_deliver ( struct slam_request *slam,
				 struct io_buffer *iobuf,
				 struct xfer_metadata *rx_meta __unused ) {
	int rc;

	/* Restart the master client timer */
	stop_timer ( &slam->master_timer );
	start_timer ( &slam->master_timer );

	/* Read and strip packet header */
	if ( ( rc = slam_pull_header ( slam, iobuf ) ) != 0 )
		goto discard;

	/* Sanity check */
	if ( iob_len ( iobuf ) != 0 ) {
		DBGC ( slam, "SLAM %p received trailing garbage:\n", slam );
		DBGC_HD ( slam, iobuf->data, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto discard;
	}

	/* Discard packet */
	free_iob ( iobuf );

	/* Send NACK in reply */
	slam_tx_nack ( slam );

	return 0;

 discard:
	free_iob ( iobuf );
	return rc;

}

/** SLAM unicast socket interface operations */
static struct interface_operation slam_socket_operations[] = {
	INTF_OP ( xfer_deliver, struct slam_request *, slam_socket_deliver ),
	INTF_OP ( intf_close, struct slam_request *, slam_finished ),
};

/** SLAM unicast socket interface descriptor */
static struct interface_descriptor slam_socket_desc =
	INTF_DESC ( struct slam_request, socket, slam_socket_operations );

/** SLAM multicast socket interface operations */
static struct interface_operation slam_mc_socket_operations[] = {
	INTF_OP ( xfer_deliver, struct slam_request *, slam_mc_socket_deliver ),
	INTF_OP ( intf_close, struct slam_request *, slam_finished ),
};

/** SLAM multicast socket interface descriptor */
static struct interface_descriptor slam_mc_socket_desc =
	INTF_DESC ( struct slam_request, mc_socket, slam_mc_socket_operations );

/****************************************************************************
 *
 * Data transfer interface
 *
 */

/** SLAM data transfer interface operations */
static struct interface_operation slam_xfer_operations[] = {
	INTF_OP ( intf_close, struct slam_request *, slam_finished ),
};

/** SLAM data transfer interface descriptor */
static struct interface_descriptor slam_xfer_desc =
	INTF_DESC ( struct slam_request, xfer, slam_xfer_operations );

/**
 * Parse SLAM URI multicast address
 *
 * @v slam		SLAM request
 * @v path		Path portion of x-slam:// URI
 * @v address		Socket address to fill in
 * @ret rc		Return status code
 */
static int slam_parse_multicast_address ( struct slam_request *slam,
					  const char *path,
					  struct sockaddr_in *address ) {
	char path_dup[ strlen ( path ) /* no +1 */ ];
	char *sep;
	char *end;

	/* Create temporary copy of path, minus the leading '/' */
	assert ( *path == '/' );
	memcpy ( path_dup, ( path + 1 ) , sizeof ( path_dup ) );

	/* Parse port, if present */
	sep = strchr ( path_dup, ':' );
	if ( sep ) {
		*(sep++) = '\0';
		address->sin_port = htons ( strtoul ( sep, &end, 0 ) );
		if ( *end != '\0' ) {
			DBGC ( slam, "SLAM %p invalid multicast port "
			       "\"%s\"\n", slam, sep );
			return -EINVAL;
		}
	}

	/* Parse address */
	if ( inet_aton ( path_dup, &address->sin_addr ) == 0 ) {
		DBGC ( slam, "SLAM %p invalid multicast address \"%s\"\n",
		       slam, path_dup );
		return -EINVAL;
	}

	return 0;
}

/**
 * Initiate a SLAM request
 *
 * @v xfer		Data transfer interface
 * @v uri		Uniform Resource Identifier
 * @ret rc		Return status code
 */
static int slam_open ( struct interface *xfer, struct uri *uri ) {
	static const struct sockaddr_in default_multicast = {
		.sin_family = AF_INET,
		.sin_port = htons ( SLAM_DEFAULT_MULTICAST_PORT ),
		.sin_addr = { htonl ( SLAM_DEFAULT_MULTICAST_IP ) },
	};
	struct slam_request *slam;
	struct sockaddr_tcpip server;
	struct sockaddr_in multicast;
	int rc;

	/* Sanity checks */
	if ( ! uri->host )
		return -EINVAL;

	/* Allocate and populate structure */
	slam = zalloc ( sizeof ( *slam ) );
	if ( ! slam )
		return -ENOMEM;
	ref_init ( &slam->refcnt, slam_free );
	intf_init ( &slam->xfer, &slam_xfer_desc, &slam->refcnt );
	intf_init ( &slam->socket, &slam_socket_desc, &slam->refcnt );
	intf_init ( &slam->mc_socket, &slam_mc_socket_desc, &slam->refcnt );
	timer_init ( &slam->master_timer, slam_master_timer_expired,
		     &slam->refcnt );
	timer_init ( &slam->slave_timer, slam_slave_timer_expired,
		     &slam->refcnt );
	/* Fake an invalid cached header of { 0x00, ... } */
	slam->header_len = 1;
	/* Fake parameters for initial NACK */
	slam->num_blocks = 1;
	if ( ( rc = bitmap_resize ( &slam->bitmap, 1 ) ) != 0 ) {
		DBGC ( slam, "SLAM %p could not allocate initial bitmap: "
		       "%s\n", slam, strerror ( rc ) );
		goto err;
	}

	/* Open unicast socket */
	memset ( &server, 0, sizeof ( server ) );
	server.st_port = htons ( uri_port ( uri, SLAM_DEFAULT_PORT ) );
	if ( ( rc = xfer_open_named_socket ( &slam->socket, SOCK_DGRAM,
					     ( struct sockaddr * ) &server,
					     uri->host, NULL ) ) != 0 ) {
		DBGC ( slam, "SLAM %p could not open unicast socket: %s\n",
		       slam, strerror ( rc ) );
		goto err;
	}

	/* Open multicast socket */
	memcpy ( &multicast, &default_multicast, sizeof ( multicast ) );
	if ( uri->path &&
	     ( ( rc = slam_parse_multicast_address ( slam, uri->path,
						     &multicast ) ) != 0 ) ) {
		goto err;
	}
	if ( ( rc = xfer_open_socket ( &slam->mc_socket, SOCK_DGRAM,
				 ( struct sockaddr * ) &multicast,
				 ( struct sockaddr * ) &multicast ) ) != 0 ) {
		DBGC ( slam, "SLAM %p could not open multicast socket: %s\n",
		       slam, strerror ( rc ) );
		goto err;
	}

	/* Start slave retry timer */
	start_timer_fixed ( &slam->slave_timer, SLAM_SLAVE_TIMEOUT );

	/* Attach to parent interface, mortalise self, and return */
	intf_plug_plug ( &slam->xfer, xfer );
	ref_put ( &slam->refcnt );
	return 0;

 err:
	slam_finished ( slam, rc );
	ref_put ( &slam->refcnt );
	return rc;
}

/** SLAM URI opener */
struct uri_opener slam_uri_opener __uri_opener = {
	.scheme	= "x-slam",
	.open	= slam_open,
};
