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
#include <stdio.h>
#include <errno.h>
#include <ipxe/http.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/uri.h>
#include <ipxe/timer.h>
#include <ipxe/profile.h>
#include <ipxe/fault.h>
#include <ipxe/pccrr.h>
#include <ipxe/peerblk.h>

/** @file
 *
 * Peer Content Caching and Retrieval (PeerDist) protocol block downloads
 *
 */

/** PeerDist decryption chunksize
 *
 * This is a policy decision.
 */
#define PEERBLK_DECRYPT_CHUNKSIZE 2048

/** PeerDist raw block download attempt initial progress timeout
 *
 * This is a policy decision.
 */
#define PEERBLK_RAW_OPEN_TIMEOUT ( 10 * TICKS_PER_SEC )

/** PeerDist raw block download attempt ongoing progress timeout
 *
 * This is a policy decision.
 */
#define PEERBLK_RAW_RX_TIMEOUT ( 15 * TICKS_PER_SEC )

/** PeerDist retrieval protocol block download attempt initial progress timeout
 *
 * This is a policy decision.
 */
#define PEERBLK_RETRIEVAL_OPEN_TIMEOUT ( 3 * TICKS_PER_SEC )

/** PeerDist retrieval protocol block download attempt ongoing progress timeout
 *
 * This is a policy decision.
 */
#define PEERBLK_RETRIEVAL_RX_TIMEOUT ( 5 * TICKS_PER_SEC )

/** PeerDist maximum number of full download attempt cycles
 *
 * This is the maximum number of times that we will try a full cycle
 * of download attempts (i.e. a retrieval protocol download attempt
 * from each discovered peer plus a raw download attempt from the
 * origin server).
 *
 * This is a policy decision.
 */
#define PEERBLK_MAX_ATTEMPT_CYCLES 4

/** PeerDist block download profiler */
static struct profiler peerblk_download_profiler __profiler =
	{ .name = "peerblk.download" };

/** PeerDist block download attempt success profiler */
static struct profiler peerblk_attempt_success_profiler __profiler =
	{ .name = "peerblk.attempt.success" };

/** PeerDist block download attempt failure profiler */
static struct profiler peerblk_attempt_failure_profiler __profiler =
	{ .name = "peerblk.attempt.failure" };

/** PeerDist block download attempt timeout profiler */
static struct profiler peerblk_attempt_timeout_profiler __profiler =
	{ .name = "peerblk.attempt.timeout" };

/** PeerDist block download discovery success profiler */
static struct profiler peerblk_discovery_success_profiler __profiler =
	{ .name = "peerblk.discovery.success" };

/** PeerDist block download discovery timeout profiler */
static struct profiler peerblk_discovery_timeout_profiler __profiler =
	{ .name = "peerblk.discovery.timeout" };

/**
 * Get profiling timestamp
 *
 * @ret timestamp	Timestamp
 */
static inline __attribute__ (( always_inline )) unsigned long
peerblk_timestamp ( void ) {

	if ( PROFILING ) {
		return currticks();
	} else {
		return 0;
	}
}

/**
 * Free PeerDist block download
 *
 * @v refcnt		Reference count
 */
static void peerblk_free ( struct refcnt *refcnt ) {
	struct peerdist_block *peerblk =
		container_of ( refcnt, struct peerdist_block, refcnt );

	uri_put ( peerblk->uri );
	free ( peerblk->cipherctx );
	free ( peerblk );
}

/**
 * Reset PeerDist block download attempt
 *
 * @v peerblk		PeerDist block download
 * @v rc		Reason for reset
 */
static void peerblk_reset ( struct peerdist_block *peerblk, int rc ) {

	/* Stop decryption process */
	process_del ( &peerblk->process );

	/* Stop timer */
	stop_timer ( &peerblk->timer );

	/* Abort any current download attempt */
	intf_restart ( &peerblk->raw, rc );
	intf_restart ( &peerblk->retrieval, rc );

	/* Empty received data buffer */
	xferbuf_free ( &peerblk->buffer );
	peerblk->pos = 0;

	/* Reset digest and free cipher context */
	digest_init ( peerblk->digest, peerblk->digestctx );
	free ( peerblk->cipherctx );
	peerblk->cipherctx = NULL;
	peerblk->cipher = NULL;

	/* Reset trim thresholds */
	peerblk->start = ( peerblk->trim.start - peerblk->range.start );
	peerblk->end = ( peerblk->trim.end - peerblk->range.start );
	assert ( peerblk->start <= peerblk->end );
}

/**
 * Close PeerDist block download
 *
 * @v peerblk		PeerDist block download
 * @v rc		Reason for close
 */
static void peerblk_close ( struct peerdist_block *peerblk, int rc ) {
	unsigned long now = peerblk_timestamp();

	/* Profile overall block download */
	profile_custom ( &peerblk_download_profiler,
			 ( now - peerblk->started ) );

	/* Reset download attempt */
	peerblk_reset ( peerblk, rc );

	/* Close discovery */
	peerdisc_close ( &peerblk->discovery );

	/* Shut down all interfaces */
	intf_shutdown ( &peerblk->retrieval, rc );
	intf_shutdown ( &peerblk->raw, rc );
	intf_shutdown ( &peerblk->xfer, rc );
}

/**
 * Calculate offset within overall download
 *
 * @v peerblk		PeerDist block download
 * @v pos		Position within incoming data stream
 * @ret offset		Offset within overall download
 */
static inline __attribute__ (( always_inline )) size_t
peerblk_offset ( struct peerdist_block *peerblk, size_t pos ) {

	return ( ( pos - peerblk->start ) + peerblk->offset );
}

/**
 * Deliver download attempt data block
 *
 * @v peerblk		PeerDist block download
 * @v iobuf		I/O buffer
 * @v meta		Original data transfer metadata
 * @v pos		Position within incoming data stream
 * @ret rc		Return status code
 */
static int peerblk_deliver ( struct peerdist_block *peerblk,
			     struct io_buffer *iobuf,
			     struct xfer_metadata *meta, size_t pos ) {
	struct xfer_metadata xfer_meta;
	size_t len = iob_len ( iobuf );
	size_t start = pos;
	size_t end = ( pos + len );
	int rc;

	/* Discard zero-length packets and packets which lie entirely
	 * outside the trimmed range.
	 */
	if ( ( start >= peerblk->end ) || ( end <= peerblk->start ) ||
	     ( len == 0 ) ) {
		free_iob ( iobuf );
		return 0;
	}

	/* Truncate data to within trimmed range */
	if ( start < peerblk->start ) {
		iob_pull ( iobuf, ( peerblk->start - start ) );
		start = peerblk->start;
	}
	if ( end > peerblk->end ) {
		iob_unput ( iobuf, ( end - peerblk->end ) );
		end = peerblk->end;
	}

	/* Construct metadata */
	memcpy ( &xfer_meta, meta, sizeof ( xfer_meta ) );
	xfer_meta.flags |= XFER_FL_ABS_OFFSET;
	xfer_meta.offset = peerblk_offset ( peerblk, start );

	/* Deliver data */
	if ( ( rc = xfer_deliver ( &peerblk->xfer, iob_disown ( iobuf ),
				   &xfer_meta ) ) != 0 ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d could not deliver data: %s\n",
		       peerblk, peerblk->segment, peerblk->block,
		       strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Finish PeerDist block download attempt
 *
 * @v peerblk		PeerDist block download
 * @v rc		Reason for close
 */
static void peerblk_done ( struct peerdist_block *peerblk, int rc ) {
	struct digest_algorithm *digest = peerblk->digest;
	uint8_t hash[digest->digestsize];
	unsigned long now = peerblk_timestamp();

	/* Check for errors on completion */
	if ( rc != 0 ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d attempt failed: %s\n",
		       peerblk, peerblk->segment, peerblk->block,
		       strerror ( rc ) );
		goto err;
	}

	/* Check digest */
	digest_final ( digest, peerblk->digestctx, hash );
	if ( memcmp ( hash, peerblk->hash, peerblk->digestsize ) != 0 ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d digest mismatch:\n",
		       peerblk, peerblk->segment, peerblk->block );
		DBGC_HDA ( peerblk, 0, hash, peerblk->digestsize );
		DBGC_HDA ( peerblk, 0, peerblk->hash, peerblk->digestsize );
		rc = -EIO;
		goto err;
	}

	/* Profile successful attempt */
	profile_custom ( &peerblk_attempt_success_profiler,
			 ( now - peerblk->attempted ) );

	/* Close download */
	peerblk_close ( peerblk, 0 );
	return;

 err:
	/* Record failure reason and schedule a retry attempt */
	profile_custom ( &peerblk_attempt_failure_profiler,
			 ( now - peerblk->attempted ) );
	peerblk_reset ( peerblk, rc );
	peerblk->rc = rc;
	start_timer_nodelay ( &peerblk->timer );
}

/******************************************************************************
 *
 * Raw block download attempts (using an HTTP range request)
 *
 ******************************************************************************
 */

/**
 * Open PeerDist raw block download attempt
 *
 * @v peerblk		PeerDist block download
 * @ret rc		Return status code
 */
static int peerblk_raw_open ( struct peerdist_block *peerblk ) {
	struct http_request_range range;
	int rc;

	DBGC2 ( peerblk, "PEERBLK %p %d.%d attempting raw range request\n",
		peerblk, peerblk->segment, peerblk->block );

	/* Construct HTTP range */
	memset ( &range, 0, sizeof ( range ) );
	range.start = peerblk->range.start;
	range.len = ( peerblk->range.end - peerblk->range.start );

	/* Initiate range request to retrieve block */
	if ( ( rc = http_open ( &peerblk->raw, &http_get, peerblk->uri,
				&range, NULL ) ) != 0 ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d could not create range "
		       "request: %s\n", peerblk, peerblk->segment,
		       peerblk->block, strerror ( rc ) );
		return rc;
	}

	/* Annul HTTP connection (for testing) if applicable.  Do not
	 * report as an immediate error, in order to test our ability
	 * to recover from a totally unresponsive HTTP server.
	 */
	if ( inject_fault ( PEERBLK_ANNUL_RATE ) )
		intf_restart ( &peerblk->raw, 0 );

	return 0;
}

/**
 * Receive PeerDist raw data
 *
 * @v peerblk		PeerDist block download
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int peerblk_raw_rx ( struct peerdist_block *peerblk,
			    struct io_buffer *iobuf,
			    struct xfer_metadata *meta ) {
	size_t len = iob_len ( iobuf );
	size_t pos = peerblk->pos;
	size_t mid = ( ( peerblk->range.end - peerblk->range.start ) / 2 );
	int rc;

	/* Corrupt received data (for testing) if applicable */
	inject_corruption ( PEERBLK_CORRUPT_RATE, iobuf->data, len );

	/* Fail if data is delivered out of order, since the streaming
	 * digest requires strict ordering.
	 */
	if ( ( rc = xfer_check_order ( meta, &peerblk->pos, len ) ) != 0 )
		goto err;

	/* Add data to digest */
	digest_update ( peerblk->digest, peerblk->digestctx, iobuf->data, len );

	/* Deliver data */
	if ( ( rc = peerblk_deliver ( peerblk, iob_disown ( iobuf ), meta,
				      pos ) ) != 0 )
		goto err;

	/* Extend download attempt timer */
	start_timer_fixed ( &peerblk->timer, PEERBLK_RAW_RX_TIMEOUT );

	/* Stall download attempt (for testing) if applicable */
	if ( ( pos < mid ) && ( ( pos + len ) >= mid ) &&
	     ( ( rc = inject_fault ( PEERBLK_STALL_RATE ) ) != 0 ) ) {
		intf_restart ( &peerblk->raw, rc );
	}

	return 0;

 err:
	free_iob ( iobuf );
	peerblk_done ( peerblk, rc );
	return rc;
}

/**
 * Close PeerDist raw block download attempt
 *
 * @v peerblk		PeerDist block download
 * @v rc		Reason for close
 */
static void peerblk_raw_close ( struct peerdist_block *peerblk, int rc ) {

	/* Restart interface */
	intf_restart ( &peerblk->raw, rc );

	/* Fail immediately if we have an error */
	if ( rc != 0 )
		goto done;

	/* Abort download attempt (for testing) if applicable */
	if ( ( rc = inject_fault ( PEERBLK_ABORT_RATE ) ) != 0 )
		goto done;

 done:
	/* Complete download attempt */
	peerblk_done ( peerblk, rc );
}

/******************************************************************************
 *
 * Retrieval protocol block download attempts (using HTTP POST)
 *
 ******************************************************************************
 */

/**
 * Construct PeerDist retrieval protocol URI
 *
 * @v location		Peer location
 * @ret uri		Retrieval URI, or NULL on error
 */
static struct uri * peerblk_retrieval_uri ( const char *location ) {
	char uri_string[ 7 /* "http://" */ + strlen ( location ) +
			 sizeof ( PEERDIST_MAGIC_PATH /* includes NUL */ ) ];

	/* Construct URI string */
	snprintf ( uri_string, sizeof ( uri_string ),
		   ( "http://%s" PEERDIST_MAGIC_PATH ), location );

	/* Parse URI string */
	return parse_uri ( uri_string );
}

/**
 * Open PeerDist retrieval protocol block download attempt
 *
 * @v peerblk		PeerDist block download
 * @v location		Peer location
 * @ret rc		Return status code
 */
static int peerblk_retrieval_open ( struct peerdist_block *peerblk,
				    const char *location ) {
	size_t digestsize = peerblk->digestsize;
	peerdist_msg_getblks_t ( digestsize, 1, 0 ) req;
	peerblk_msg_blk_t ( digestsize, 0, 0, 0 ) *rsp;
	struct http_request_content content;
	struct uri *uri;
	int rc;

	DBGC2 ( peerblk, "PEERBLK %p %d.%d attempting retrieval from %s\n",
		peerblk, peerblk->segment, peerblk->block, location );

	/* Construct block fetch request */
	memset ( &req, 0, sizeof ( req ) );
	req.getblks.hdr.version.raw = htonl ( PEERDIST_MSG_GETBLKS_VERSION );
	req.getblks.hdr.type = htonl ( PEERDIST_MSG_GETBLKS_TYPE );
	req.getblks.hdr.len = htonl ( sizeof ( req ) );
	req.getblks.hdr.algorithm = htonl ( PEERDIST_MSG_AES_128_CBC );
	req.segment.segment.digestsize = htonl ( digestsize );
	memcpy ( req.segment.id, peerblk->id, digestsize );
	req.ranges.ranges.count = htonl ( 1 );
	req.ranges.range[0].first = htonl ( peerblk->block );
	req.ranges.range[0].count = htonl ( 1 );

	/* Construct POST request content */
	memset ( &content, 0, sizeof ( content ) );
	content.data = &req;
	content.len = sizeof ( req );

	/* Construct URI */
	if ( ( uri = peerblk_retrieval_uri ( location ) ) == NULL ) {
		rc = -ENOMEM;
		goto err_uri;
	}

	/* Update trim thresholds */
	peerblk->start += offsetof ( typeof ( *rsp ), msg.vrf );
	peerblk->end += offsetof ( typeof ( *rsp ), msg.vrf );

	/* Initiate HTTP POST to retrieve block */
	if ( ( rc = http_open ( &peerblk->retrieval, &http_post, uri,
				NULL, &content ) ) != 0 ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d could not create retrieval "
		       "request: %s\n", peerblk, peerblk->segment,
		       peerblk->block, strerror ( rc ) );
		goto err_open;
	}

	/* Annul HTTP connection (for testing) if applicable.  Do not
	 * report as an immediate error, in order to test our ability
	 * to recover from a totally unresponsive HTTP server.
	 */
	if ( inject_fault ( PEERBLK_ANNUL_RATE ) )
		intf_restart ( &peerblk->retrieval, 0 );

 err_open:
	uri_put ( uri );
 err_uri:
	return rc;
}

/**
 * Receive PeerDist retrieval protocol data
 *
 * @v peerblk		PeerDist block download
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int peerblk_retrieval_rx ( struct peerdist_block *peerblk,
				  struct io_buffer *iobuf,
				  struct xfer_metadata *meta ) {
	size_t len = iob_len ( iobuf );
	size_t start;
	size_t end;
	size_t before;
	size_t after;
	size_t cut;
	int rc;

	/* Some genius at Microsoft thought it would be a great idea
	 * to place the AES-CBC initialisation vector *after* the
	 * encrypted data, thereby making it logically impossible to
	 * decrypt each packet as it arrives.
	 *
	 * To work around this mindless stupidity, we deliver the
	 * ciphertext as-is and later use xfer_buffer() to obtain
	 * access to the underlying data transfer buffer in order to
	 * perform the decryption.
	 *
	 * There will be some data both before and after the bytes
	 * corresponding to the trimmed plaintext: a MSG_BLK
	 * header/footer, some block padding for the AES-CBC cipher,
	 * and a possibly large quantity of unwanted ciphertext which
	 * is excluded from the trimmed content range.  We store this
	 * data in a local data transfer buffer.  If the amount of
	 * data to be stored is too large, we will fail allocation and
	 * so eventually fall back to using a range request (which
	 * does not require this kind of temporary storage
	 * allocation).
	 */

	/* Corrupt received data (for testing) if applicable */
	inject_corruption ( PEERBLK_CORRUPT_RATE, iobuf->data, len );

	/* Calculate start and end positions of this buffer */
	start = peerblk->pos;
	if ( meta->flags & XFER_FL_ABS_OFFSET )
		start = 0;
	start += meta->offset;
	end = ( start + len );

	/* Buffer any data before the trimmed content */
	if ( ( start < peerblk->start ) && ( len > 0 ) ) {

		/* Calculate length of data before the trimmed content */
		before = ( peerblk->start - start );
		if ( before > len )
			before = len;

		/* Buffer data before the trimmed content */
		if ( ( rc = xferbuf_write ( &peerblk->buffer, start,
					    iobuf->data, before ) ) != 0 ) {
			DBGC ( peerblk, "PEERBLK %p %d.%d could not buffer "
			       "data: %s\n", peerblk, peerblk->segment,
			       peerblk->block, strerror ( rc ) );
			goto err;
		}
	}

	/* Buffer any data after the trimmed content */
	if ( ( end > peerblk->end ) && ( len > 0 ) ) {

		/* Calculate length of data after the trimmed content */
		after = ( end - peerblk->end );
		if ( after > len )
			after = len;

		/* Buffer data after the trimmed content */
		cut = ( peerblk->end - peerblk->start );
		if ( ( rc = xferbuf_write ( &peerblk->buffer,
					    ( end - after - cut ),
					    ( iobuf->data + len - after ),
					    after ) ) != 0 ) {
			DBGC ( peerblk, "PEERBLK %p %d.%d could not buffer "
			       "data: %s\n", peerblk, peerblk->segment,
			       peerblk->block, strerror ( rc ) );
			goto err;
		}
	}

	/* Deliver any remaining data */
	if ( ( rc = peerblk_deliver ( peerblk, iob_disown ( iobuf ), meta,
				      start ) ) != 0 )
		goto err;

	/* Update position */
	peerblk->pos = end;

	/* Extend download attempt timer */
	start_timer_fixed ( &peerblk->timer, PEERBLK_RETRIEVAL_RX_TIMEOUT );

	/* Stall download attempt (for testing) if applicable */
	if ( ( start < peerblk->end ) && ( end >= peerblk->end ) &&
	     ( ( rc = inject_fault ( PEERBLK_STALL_RATE ) ) != 0 ) ) {
		intf_restart ( &peerblk->retrieval, rc );
	}

	return 0;

 err:
	free_iob ( iobuf );
	peerblk_done ( peerblk, rc );
	return rc;
}

/**
 * Parse retrieval protocol message header
 *
 * @v peerblk		PeerDist block download
 * @ret rc		Return status code
 */
static int peerblk_parse_header ( struct peerdist_block *peerblk ) {
	struct {
		struct peerdist_msg_transport_header hdr;
		struct peerdist_msg_header msg;
	} __attribute__ (( packed )) *msg = peerblk->buffer.data;
	struct cipher_algorithm *cipher;
	size_t len = peerblk->buffer.len;
	size_t keylen = 0;
	int rc;

	/* Check message length */
	if ( len < sizeof ( *msg ) ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d message too short for header "
		       "(%zd bytes)\n", peerblk, peerblk->segment,
		       peerblk->block, len );
		return -ERANGE;
	}

	/* Check message type */
	if ( msg->msg.type != htonl ( PEERDIST_MSG_BLK_TYPE ) ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d unexpected message type "
		       "%#08x\n", peerblk, peerblk->segment, peerblk->block,
		       ntohl ( msg->msg.type ) );
		return -EPROTO;
	}

	/* Determine cipher algorithm and key length */
	cipher = &aes_cbc_algorithm;
	switch ( msg->msg.algorithm ) {
	case htonl ( PEERDIST_MSG_PLAINTEXT ) :
		cipher = NULL;
		break;
	case htonl ( PEERDIST_MSG_AES_128_CBC ) :
		keylen = ( 128 / 8 );
		break;
	case htonl ( PEERDIST_MSG_AES_192_CBC ) :
		keylen = ( 192 / 8 );
		break;
	case htonl ( PEERDIST_MSG_AES_256_CBC ) :
		keylen = ( 256 / 8 );
		break;
	default:
		DBGC ( peerblk, "PEERBLK %p %d.%d unrecognised algorithm "
		       "%#08x\n", peerblk, peerblk->segment, peerblk->block,
		       ntohl ( msg->msg.algorithm ) );
		return -ENOTSUP;
	}
	DBGC2 ( peerblk, "PEERBLK %p %d.%d using %s with %zd-bit key\n",
		peerblk, peerblk->segment, peerblk->block,
		( cipher ? cipher->name : "plaintext" ), ( 8 * keylen ) );

	/* Sanity check key length against maximum secret length */
	if ( keylen > peerblk->digestsize ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d %zd-byte secret too short "
		       "for %zd-bit key\n", peerblk, peerblk->segment,
		       peerblk->block, peerblk->digestsize, ( 8 * keylen ) );
		return -EPROTO;
	}

	/* Allocate cipher context.  Freeing the cipher context (on
	 * error or otherwise) is handled by peerblk_reset().
	 */
	peerblk->cipher = cipher;
	assert ( peerblk->cipherctx == NULL );
	peerblk->cipherctx = malloc ( cipher->ctxsize );
	if ( ! peerblk->cipherctx )
		return -ENOMEM;

	/* Initialise cipher */
	if ( ( rc = cipher_setkey ( cipher, peerblk->cipherctx, peerblk->secret,
				    keylen ) ) != 0 ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d could not set key: %s\n",
		       peerblk, peerblk->segment, peerblk->block,
		       strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Parse retrieval protocol message segment and block details
 *
 * @v peerblk		PeerDist block download
 * @v buf_len		Length of buffered data to fill in
 * @ret rc		Return status code
 */
static int peerblk_parse_block ( struct peerdist_block *peerblk,
				 size_t *buf_len ) {
	size_t digestsize = peerblk->digestsize;
	peerblk_msg_blk_t ( digestsize, 0, 0, 0 ) *msg = peerblk->buffer.data;
	size_t len = peerblk->buffer.len;
	size_t data_len;
	size_t total;

	/* Check message length */
	if ( len < offsetof ( typeof ( *msg ), msg.block.data ) ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d message too short for "
		       "zero-length data (%zd bytes)\n", peerblk,
		       peerblk->segment, peerblk->block, len );
		return -ERANGE;
	}

	/* Check digest size */
	if ( ntohl ( msg->msg.segment.segment.digestsize ) != digestsize ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d incorrect digest size %d\n",
		       peerblk, peerblk->segment, peerblk->block,
		       ntohl ( msg->msg.segment.segment.digestsize ) );
		return -EPROTO;
	}

	/* Check segment ID */
	if ( memcmp ( msg->msg.segment.id, peerblk->id, digestsize ) != 0 ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d segment ID mismatch\n",
		       peerblk, peerblk->segment, peerblk->block );
		return -EPROTO;
	}

	/* Check block ID */
	if ( ntohl ( msg->msg.index ) != peerblk->block ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d block ID mismatch (got %d)\n",
		       peerblk, peerblk->segment, peerblk->block,
		       ntohl ( msg->msg.index ) );
		return -EPROTO;
	}

	/* Check for missing blocks */
	data_len = be32_to_cpu ( msg->msg.block.block.len );
	if ( ! data_len ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d block not found\n",
		       peerblk, peerblk->segment, peerblk->block );
		return -ENOENT;
	}

	/* Check for underlength blocks */
	if ( data_len < ( peerblk->range.end - peerblk->range.start ) ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d underlength block (%zd "
		       "bytes)\n", peerblk, peerblk->segment, peerblk->block,
		       data_len );
		return -ERANGE;
	}

	/* Calculate buffered data length (i.e. excluding data which
	 * was delivered to the final data transfer buffer).
	 */
	*buf_len = ( data_len - ( peerblk->end - peerblk->start ) );

	/* Describe data before the trimmed content */
	peerblk->decrypt[PEERBLK_BEFORE].xferbuf = &peerblk->buffer;
	peerblk->decrypt[PEERBLK_BEFORE].offset =
		offsetof ( typeof ( *msg ), msg.block.data );
	peerblk->decrypt[PEERBLK_BEFORE].len =
		( peerblk->start -
		  offsetof ( typeof ( *msg ), msg.block.data ) );
	total = peerblk->decrypt[PEERBLK_BEFORE].len;

	/* Describe data within the trimmed content */
	peerblk->decrypt[PEERBLK_DURING].offset =
		peerblk_offset ( peerblk, peerblk->start );
	peerblk->decrypt[PEERBLK_DURING].len =
		( peerblk->end - peerblk->start );
	total += peerblk->decrypt[PEERBLK_DURING].len;

	/* Describe data after the trimmed content */
	peerblk->decrypt[PEERBLK_AFTER].xferbuf = &peerblk->buffer;
	peerblk->decrypt[PEERBLK_AFTER].offset = peerblk->start;
	peerblk->decrypt[PEERBLK_AFTER].len =
		( offsetof ( typeof ( *msg ), msg.block.data )
		  + *buf_len - peerblk->start );
	total += peerblk->decrypt[PEERBLK_AFTER].len;

	/* Sanity check */
	assert ( total == be32_to_cpu ( msg->msg.block.block.len ) );

	/* Initialise cipher and digest lengths */
	peerblk->cipher_remaining = total;
	peerblk->digest_remaining =
		( peerblk->range.end - peerblk->range.start );
	assert ( peerblk->cipher_remaining >= peerblk->digest_remaining );

	return 0;
}

/**
 * Parse retrieval protocol message useless details
 *
 * @v peerblk		PeerDist block download
 * @v buf_len		Length of buffered data
 * @v vrf_len		Length of uselessness to fill in
 * @ret rc		Return status code
 */
static int peerblk_parse_useless ( struct peerdist_block *peerblk,
				   size_t buf_len, size_t *vrf_len ) {
	size_t digestsize = peerblk->digestsize;
	peerblk_msg_blk_t ( digestsize, buf_len, 0, 0 ) *msg =
		peerblk->buffer.data;
	size_t len = peerblk->buffer.len;

	/* Check message length */
	if ( len < offsetof ( typeof ( *msg ), msg.vrf.data ) ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d message too short for "
		       "zero-length uselessness (%zd bytes)\n", peerblk,
		       peerblk->segment, peerblk->block, len );
		return -ERANGE;
	}

	/* Extract length of uselessness */
	*vrf_len = be32_to_cpu ( msg->msg.vrf.vrf.len );

	return 0;
}

/**
 * Parse retrieval protocol message initialisation vector details
 *
 * @v peerblk		PeerDist block download
 * @v buf_len		Length of buffered data
 * @v vrf_len		Length of uselessness
 * @ret rc		Return status code
 */
static int peerblk_parse_iv ( struct peerdist_block *peerblk, size_t buf_len,
			      size_t vrf_len ) {
	size_t digestsize = peerblk->digestsize;
	size_t blksize = peerblk->cipher->blocksize;
	peerblk_msg_blk_t ( digestsize, buf_len, vrf_len, blksize ) *msg =
		peerblk->buffer.data;
	size_t len = peerblk->buffer.len;

	/* Check message length */
	if ( len < sizeof ( *msg ) ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d message too short for "
		       "initialisation vector (%zd bytes)\n", peerblk,
		       peerblk->segment, peerblk->block, len );
		return -ERANGE;
	}

	/* Check initialisation vector size */
	if ( ntohl ( msg->msg.iv.iv.blksize ) != blksize ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d incorrect IV size %d\n",
		       peerblk, peerblk->segment, peerblk->block,
		       ntohl ( msg->msg.iv.iv.blksize ) );
		return -EPROTO;
	}

	/* Set initialisation vector */
	cipher_setiv ( peerblk->cipher, peerblk->cipherctx, msg->msg.iv.data );

	return 0;
}

/**
 * Read from decryption buffers
 *
 * @v peerblk		PeerDist block download
 * @v data		Data buffer
 * @v len		Length to read
 * @ret rc		Return status code
 */
static int peerblk_decrypt_read ( struct peerdist_block *peerblk,
				  void *data, size_t len ) {
	struct peerdist_block_decrypt *decrypt = peerblk->decrypt;
	size_t frag_len;
	int rc;

	/* Read from each decryption buffer in turn */
	for ( ; len ; decrypt++, data += frag_len, len -= frag_len ) {

		/* Calculate length to use from this buffer */
		frag_len = decrypt->len;
		if ( frag_len > len )
			frag_len = len;
		if ( ! frag_len )
			continue;

		/* Read from this buffer */
		if ( ( rc = xferbuf_read ( decrypt->xferbuf, decrypt->offset,
					   data, frag_len ) ) != 0 )
			return rc;
	}

	return 0;
}

/**
 * Write to decryption buffers and update offsets and lengths
 *
 * @v peerblk		PeerDist block download
 * @v data		Data buffer
 * @v len		Length to read
 * @ret rc		Return status code
 */
static int peerblk_decrypt_write ( struct peerdist_block *peerblk,
				   const void *data, size_t len ) {
	struct peerdist_block_decrypt *decrypt = peerblk->decrypt;
	size_t frag_len;
	int rc;

	/* Write to each decryption buffer in turn */
	for ( ; len ; decrypt++, data += frag_len, len -= frag_len ) {

		/* Calculate length to use from this buffer */
		frag_len = decrypt->len;
		if ( frag_len > len )
			frag_len = len;
		if ( ! frag_len )
			continue;

		/* Write to this buffer */
		if ( ( rc = xferbuf_write ( decrypt->xferbuf, decrypt->offset,
					    data, frag_len ) ) != 0 )
			return rc;

		/* Update offset and length */
		decrypt->offset += frag_len;
		decrypt->len -= frag_len;
	}

	return 0;
}

/**
 * Decrypt one chunk of PeerDist retrieval protocol data
 *
 * @v peerblk		PeerDist block download
 */
static void peerblk_decrypt ( struct peerdist_block *peerblk ) {
	struct cipher_algorithm *cipher = peerblk->cipher;
	struct digest_algorithm *digest = peerblk->digest;
	struct xfer_buffer *xferbuf;
	size_t cipher_len;
	size_t digest_len;
	void *data;
	int rc;

	/* Sanity check */
	assert ( ( PEERBLK_DECRYPT_CHUNKSIZE % cipher->blocksize ) == 0 );

	/* Get the underlying data transfer buffer */
	xferbuf = xfer_buffer ( &peerblk->xfer );
	if ( ! xferbuf ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d has no underlying data "
		       "transfer buffer\n", peerblk, peerblk->segment,
		       peerblk->block );
		rc = -ENOTSUP;
		goto err_xfer_buffer;
	}
	peerblk->decrypt[PEERBLK_DURING].xferbuf = xferbuf;

	/* Calculate cipher and digest lengths */
	cipher_len = PEERBLK_DECRYPT_CHUNKSIZE;
	if ( cipher_len > peerblk->cipher_remaining )
		cipher_len = peerblk->cipher_remaining;
	digest_len = cipher_len;
	if ( digest_len > peerblk->digest_remaining )
		digest_len = peerblk->digest_remaining;
	assert ( ( cipher_len & ( cipher->blocksize - 1 ) ) == 0 );

	/* Allocate temporary data buffer */
	data = malloc ( cipher_len );
	if ( ! data ) {
		rc = -ENOMEM;
		goto err_alloc_data;
	}

	/* Read ciphertext */
	if ( ( rc = peerblk_decrypt_read ( peerblk, data, cipher_len ) ) != 0 ){
		DBGC ( peerblk, "PEERBLK %p %d.%d could not read ciphertext: "
		       "%s\n", peerblk, peerblk->segment, peerblk->block,
		       strerror ( rc ) );
		goto err_read;
	}

	/* Decrypt data */
	cipher_decrypt ( cipher, peerblk->cipherctx, data, data, cipher_len );

	/* Add data to digest */
	digest_update ( digest, peerblk->digestctx, data, digest_len );

	/* Write plaintext */
	if ( ( rc = peerblk_decrypt_write ( peerblk, data, cipher_len ) ) != 0){
		DBGC ( peerblk, "PEERBLK %p %d.%d could not write plaintext: "
		       "%s\n", peerblk, peerblk->segment, peerblk->block,
		       strerror ( rc ) );
		goto err_write;
	}

	/* Consume input */
	peerblk->cipher_remaining -= cipher_len;
	peerblk->digest_remaining -= digest_len;

	/* Free temporary data buffer */
	free ( data );

	/* Continue processing until all input is consumed */
	if ( peerblk->cipher_remaining )
		return;

	/* Complete download attempt */
	peerblk_done ( peerblk, 0 );
	return;

 err_write:
 err_read:
	free ( data );
 err_alloc_data:
 err_xfer_buffer:
	peerblk_done ( peerblk, rc );
}

/**
 * Close PeerDist retrieval protocol block download attempt
 *
 * @v peerblk		PeerDist block download
 * @v rc		Reason for close
 */
static void peerblk_retrieval_close ( struct peerdist_block *peerblk, int rc ) {
	size_t buf_len;
	size_t vrf_len;

	/* Restart interface */
	intf_restart ( &peerblk->retrieval, rc );

	/* Fail immediately if we have an error */
	if ( rc != 0 )
		goto done;

	/* Abort download attempt (for testing) if applicable */
	if ( ( rc = inject_fault ( PEERBLK_ABORT_RATE ) ) != 0 )
		goto done;

	/* Parse message header */
	if ( ( rc = peerblk_parse_header ( peerblk ) ) != 0 )
		goto done;

	/* Parse message segment and block details */
	if ( ( rc = peerblk_parse_block ( peerblk, &buf_len ) ) != 0 )
		goto done;

	/* If the block was plaintext, then there is nothing more to do */
	if ( ! peerblk->cipher )
		goto done;

	/* Parse message useless details */
	if ( ( rc = peerblk_parse_useless ( peerblk, buf_len, &vrf_len ) ) != 0)
		goto done;

	/* Parse message initialisation vector details */
	if ( ( rc = peerblk_parse_iv ( peerblk, buf_len, vrf_len ) ) != 0 )
		goto done;

	/* Fail if decryption length is not aligned to the cipher block size */
	if ( peerblk->cipher_remaining & ( peerblk->cipher->blocksize - 1 ) ) {
		DBGC ( peerblk, "PEERBLK %p %d.%d unaligned data length %zd\n",
		       peerblk, peerblk->segment, peerblk->block,
		       peerblk->cipher_remaining );
		rc = -EPROTO;
		goto done;
	}

	/* Stop the download attempt timer: there is no point in
	 * timing out while decrypting.
	 */
	stop_timer ( &peerblk->timer );

	/* Start decryption process */
	process_add ( &peerblk->process );
	return;

 done:
	/* Complete download attempt */
	peerblk_done ( peerblk, rc );
}

/******************************************************************************
 *
 * Retry policy
 *
 ******************************************************************************
 */

/**
 * Handle PeerDist retry timer expiry
 *
 * @v timer		Retry timer
 * @v over		Failure indicator
 */
static void peerblk_expired ( struct retry_timer *timer, int over __unused ) {
	struct peerdist_block *peerblk =
		container_of ( timer, struct peerdist_block, timer );
	struct peerdisc_segment *segment = peerblk->discovery.segment;
	struct peerdisc_peer *head;
	unsigned long now = peerblk_timestamp();
	const char *location;
	int rc;

	/* Profile discovery timeout, if applicable */
	if ( ( peerblk->peer == NULL ) && ( timer->timeout != 0 ) ) {
		profile_custom ( &peerblk_discovery_timeout_profiler,
				 ( now - peerblk->started ) );
		DBGC ( peerblk, "PEERBLK %p %d.%d discovery timed out after "
		       "%ld ticks\n", peerblk, peerblk->segment,
		       peerblk->block, timer->timeout );
	}

	/* Profile download timeout, if applicable */
	if ( ( peerblk->peer != NULL ) && ( timer->timeout != 0 ) ) {
		profile_custom ( &peerblk_attempt_timeout_profiler,
				 ( now - peerblk->attempted ) );
		DBGC ( peerblk, "PEERBLK %p %d.%d timed out after %ld ticks\n",
		       peerblk, peerblk->segment, peerblk->block,
		       timer->timeout );
	}

	/* Abort any current download attempt */
	peerblk_reset ( peerblk, -ETIMEDOUT );

	/* Record attempt start time */
	peerblk->attempted = now;

	/* If we have exceeded our maximum number of attempt cycles
	 * (each cycle comprising a retrieval protocol download from
	 * each peer in the list followed by a raw download from the
	 * origin server), then abort the overall download.
	 */
	head = list_entry ( &segment->peers, struct peerdisc_peer, list );
	if ( ( peerblk->peer == head ) &&
	     ( ++peerblk->cycles >= PEERBLK_MAX_ATTEMPT_CYCLES ) ) {
		rc = peerblk->rc;
		assert ( rc != 0 );
		goto err;
	}

	/* If we have not yet made any download attempts, then move to
	 * the start of the peer list.
	 */
	if ( peerblk->peer == NULL )
		peerblk->peer = head;

	/* Attempt retrieval protocol download from next usable peer */
	list_for_each_entry_continue ( peerblk->peer, &segment->peers, list ) {

		/* Attempt retrieval protocol download from this peer */
		location = peerblk->peer->location;
		if ( ( rc = peerblk_retrieval_open ( peerblk,
						     location ) ) != 0 ) {
			/* Non-fatal: continue to try next peer */
			continue;
		}

		/* Start download attempt timer */
		peerblk->rc = -ETIMEDOUT;
		start_timer_fixed ( &peerblk->timer,
				    PEERBLK_RETRIEVAL_OPEN_TIMEOUT );
		return;
	}

	/* Attempt raw download */
	if ( ( rc = peerblk_raw_open ( peerblk ) ) != 0 )
		goto err;

	/* Start download attempt timer */
	peerblk->rc = -ETIMEDOUT;
	start_timer_fixed ( &peerblk->timer, PEERBLK_RAW_OPEN_TIMEOUT );
	return;

 err:
	peerblk_close ( peerblk, rc );
}

/**
 * Handle PeerDist peer discovery
 *
 * @v discovery		PeerDist discovery client
 */
static void peerblk_discovered ( struct peerdisc_client *discovery ) {
	struct peerdist_block *peerblk =
		container_of ( discovery, struct peerdist_block, discovery );
	unsigned long now = peerblk_timestamp();

	/* Do nothing unless we are still waiting for the initial
	 * discovery timeout.
	 */
	if ( ( peerblk->peer != NULL ) || ( peerblk->timer.timeout == 0 ) )
		return;

	/* Schedule an immediate retry */
	start_timer_nodelay ( &peerblk->timer );

	/* Profile discovery success */
	profile_custom ( &peerblk_discovery_success_profiler,
			 ( now - peerblk->started ) );
}

/******************************************************************************
 *
 * Opener
 *
 ******************************************************************************
 */

/** PeerDist block download data transfer interface operations */
static struct interface_operation peerblk_xfer_operations[] = {
	INTF_OP ( intf_close, struct peerdist_block *, peerblk_close ),
};

/** PeerDist block download data transfer interface descriptor */
static struct interface_descriptor peerblk_xfer_desc =
	INTF_DESC ( struct peerdist_block, xfer, peerblk_xfer_operations );

/** PeerDist block download raw data interface operations */
static struct interface_operation peerblk_raw_operations[] = {
	INTF_OP ( xfer_deliver, struct peerdist_block *, peerblk_raw_rx ),
	INTF_OP ( intf_close, struct peerdist_block *, peerblk_raw_close ),
};

/** PeerDist block download raw data interface descriptor */
static struct interface_descriptor peerblk_raw_desc =
	INTF_DESC ( struct peerdist_block, raw, peerblk_raw_operations );

/** PeerDist block download retrieval protocol interface operations */
static struct interface_operation peerblk_retrieval_operations[] = {
	INTF_OP ( xfer_deliver, struct peerdist_block *, peerblk_retrieval_rx ),
	INTF_OP ( intf_close, struct peerdist_block *, peerblk_retrieval_close),
};

/** PeerDist block download retrieval protocol interface descriptor */
static struct interface_descriptor peerblk_retrieval_desc =
	INTF_DESC ( struct peerdist_block, retrieval,
		    peerblk_retrieval_operations );

/** PeerDist block download decryption process descriptor */
static struct process_descriptor peerblk_process_desc =
	PROC_DESC ( struct peerdist_block, process, peerblk_decrypt );

/** PeerDist block download discovery operations */
static struct peerdisc_client_operations peerblk_discovery_operations = {
	.discovered = peerblk_discovered,
};

/**
 * Open PeerDist block download
 *
 * @v xfer		Data transfer interface
 * @v uri		Original URI
 * @v info		Content information block
 * @ret rc		Return status code
 */
int peerblk_open ( struct interface *xfer, struct uri *uri,
		   struct peerdist_info_block *block ) {
	const struct peerdist_info_segment *segment = block->segment;
	const struct peerdist_info *info = segment->info;
	struct digest_algorithm *digest = info->digest;
	struct peerdist_block *peerblk;
	unsigned long timeout;
	size_t digestsize;
	int rc;

	/* Allocate and initialise structure */
	peerblk = zalloc ( sizeof ( *peerblk ) + digest->ctxsize );
	if ( ! peerblk ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	ref_init ( &peerblk->refcnt, peerblk_free );
	intf_init ( &peerblk->xfer, &peerblk_xfer_desc, &peerblk->refcnt );
	intf_init ( &peerblk->raw, &peerblk_raw_desc, &peerblk->refcnt );
	intf_init ( &peerblk->retrieval, &peerblk_retrieval_desc,
		    &peerblk->refcnt );
	peerblk->uri = uri_get ( uri );
	memcpy ( &peerblk->range, &block->range, sizeof ( peerblk->range ) );
	memcpy ( &peerblk->trim, &block->trim, sizeof ( peerblk->trim ) );
	peerblk->offset = ( block->trim.start - info->trim.start );
	peerblk->digest = info->digest;
	peerblk->digestsize = digestsize = info->digestsize;
	peerblk->digestctx = ( ( ( void * ) peerblk ) + sizeof ( *peerblk ) );
	peerblk->segment = segment->index;
	memcpy ( peerblk->id, segment->id, sizeof ( peerblk->id ) );
	memcpy ( peerblk->secret, segment->secret, sizeof ( peerblk->secret ) );
	peerblk->block = block->index;
	memcpy ( peerblk->hash, block->hash, sizeof ( peerblk->hash ) );
	xferbuf_malloc_init ( &peerblk->buffer );
	process_init_stopped ( &peerblk->process, &peerblk_process_desc,
			       &peerblk->refcnt );
	peerdisc_init ( &peerblk->discovery, &peerblk_discovery_operations );
	timer_init ( &peerblk->timer, peerblk_expired, &peerblk->refcnt );
	DBGC2 ( peerblk, "PEERBLK %p %d.%d id %02x%02x%02x%02x%02x..."
		"%02x%02x%02x [%08zx,%08zx)", peerblk, peerblk->segment,
		peerblk->block, peerblk->id[0], peerblk->id[1], peerblk->id[2],
		peerblk->id[3], peerblk->id[4], peerblk->id[ digestsize - 3 ],
		peerblk->id[ digestsize - 2 ], peerblk->id[ digestsize - 1 ],
		peerblk->range.start, peerblk->range.end );
	if ( ( peerblk->trim.start != peerblk->range.start ) ||
	     ( peerblk->trim.end != peerblk->range.end ) ) {
		DBGC2 ( peerblk, " covers [%08zx,%08zx)",
			peerblk->trim.start, peerblk->trim.end );
	}
	DBGC2 ( peerblk, "\n" );

	/* Open discovery */
	if ( ( rc = peerdisc_open ( &peerblk->discovery, peerblk->id,
				    peerblk->digestsize ) ) != 0 )
		goto err_open_discovery;

	/* Schedule a retry attempt either immediately (if we already
	 * have some peers) or after the discovery timeout.
	 */
	timeout = ( list_empty ( &peerblk->discovery.segment->peers ) ?
		    ( peerdisc_timeout_secs * TICKS_PER_SEC ) : 0 );
	start_timer_fixed ( &peerblk->timer, timeout );

	/* Record start time */
	peerblk->started = peerblk_timestamp();

	/* Attach to parent interface, mortalise self, and return */
	intf_plug_plug ( xfer, &peerblk->xfer );
	ref_put ( &peerblk->refcnt );
	return 0;

 err_open_discovery:
	peerblk_close ( peerblk, rc );
 err_alloc:
	return rc;
}
