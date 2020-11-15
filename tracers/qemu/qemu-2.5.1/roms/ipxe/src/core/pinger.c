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
#include <ipxe/refcnt.h>
#include <ipxe/interface.h>
#include <ipxe/job.h>
#include <ipxe/xfer.h>
#include <ipxe/iobuf.h>
#include <ipxe/open.h>
#include <ipxe/socket.h>
#include <ipxe/retry.h>
#include <ipxe/pinger.h>

/** @file
 *
 * ICMP ping sender
 *
 */

/* Disambiguate the various error causes */
#define EPROTO_LEN __einfo_error ( EINFO_EPROTO_LEN )
#define EINFO_EPROTO_LEN __einfo_uniqify ( EINFO_EPROTO, 0x01, \
					   "Incorrect reply length" )
#define EPROTO_DATA __einfo_error ( EINFO_EPROTO_DATA )
#define EINFO_EPROTO_DATA __einfo_uniqify ( EINFO_EPROTO, 0x02, \
					    "Incorrect reply data" )
#define EPROTO_SEQ __einfo_error ( EINFO_EPROTO_SEQ )
#define EINFO_EPROTO_SEQ __einfo_uniqify ( EINFO_EPROTO, 0x03, \
					   "Delayed or out-of-sequence reply" )

/** A pinger */
struct pinger {
	/** Reference count */
	struct refcnt refcnt;

	/** Job control interface */
	struct interface job;
	/** Data transfer interface */
	struct interface xfer;

	/** Timer */
	struct retry_timer timer;
	/** Timeout */
	unsigned long timeout;

	/** Payload length */
	size_t len;
	/** Current sequence number */
	uint16_t sequence;
	/** Response for current sequence number is still pending */
	int pending;
	/** Number of remaining expiry events (zero to continue indefinitely) */
	unsigned int remaining;
	/** Return status */
	int rc;

	/** Callback function
	 *
	 * @v src		Source socket address, or NULL
	 * @v sequence		Sequence number
	 * @v len		Payload length
	 * @v rc		Status code
	 */
	void ( * callback ) ( struct sockaddr *src, unsigned int sequence,
			      size_t len, int rc );
};

/**
 * Generate payload
 *
 * @v pinger		Pinger
 * @v data		Data buffer
 */
static void pinger_generate ( struct pinger *pinger, void *data ) {
	uint8_t *bytes = data;
	unsigned int i;

	/* Generate byte sequence */
	for ( i = 0 ; i < pinger->len ; i++ )
		bytes[i] = ( i & 0xff );
}

/**
 * Verify payload
 *
 * @v pinger		Pinger
 * @v data		Data buffer
 * @ret rc		Return status code
 */
static int pinger_verify ( struct pinger *pinger, const void *data ) {
	const uint8_t *bytes = data;
	unsigned int i;

	/* Check byte sequence */
	for ( i = 0 ; i < pinger->len ; i++ ) {
		if ( bytes[i] != ( i & 0xff ) )
			return -EPROTO_DATA;
	}

	return 0;
}

/**
 * Close pinger
 *
 * @v pinger		Pinger
 * @v rc		Reason for close
 */
static void pinger_close ( struct pinger *pinger, int rc ) {

	/* Stop timer */
	stop_timer ( &pinger->timer );

	/* Shut down interfaces */
	intf_shutdown ( &pinger->xfer, rc );
	intf_shutdown ( &pinger->job, rc );
}

/**
 * Handle data transfer window change
 *
 * @v pinger		Pinger
 */
static void pinger_window_changed ( struct pinger *pinger ) {

	/* Do nothing if timer is already running */
	if ( timer_running ( &pinger->timer ) )
		return;

	/* Start timer when window opens for the first time */
	if ( xfer_window ( &pinger->xfer ) )
		start_timer_nodelay ( &pinger->timer );
}

/**
 * Handle timer expiry
 *
 * @v timer		Timer
 * @v over		Failure indicator
 */
static void pinger_expired ( struct retry_timer *timer, int over __unused ) {
	struct pinger *pinger = container_of ( timer, struct pinger, timer );
	struct xfer_metadata meta;
	struct io_buffer *iobuf;
	int rc;

	/* If no response has been received, notify the callback function */
	if ( pinger->pending && pinger->callback )
		pinger->callback ( NULL, pinger->sequence, 0, -ETIMEDOUT );

	/* Check for termination */
	if ( pinger->remaining && ( --pinger->remaining == 0 ) ) {
		pinger_close ( pinger, pinger->rc );
		return;
	}

	/* Increase sequence number */
	pinger->sequence++;

	/* Restart timer.  Do this before attempting to transmit, in
	 * case the transmission attempt fails.
	 */
	start_timer_fixed ( &pinger->timer, pinger->timeout );
	pinger->pending = 1;

	/* Allocate I/O buffer */
	iobuf = xfer_alloc_iob ( &pinger->xfer, pinger->len );
	if ( ! iobuf ) {
		DBGC ( pinger, "PINGER %p could not allocate I/O buffer\n",
		       pinger );
		return;
	}

	/* Generate payload */
	pinger_generate ( pinger, iob_put ( iobuf, pinger->len ) );

	/* Generate metadata */
	memset ( &meta, 0, sizeof ( meta ) );
	meta.flags = XFER_FL_ABS_OFFSET;
	meta.offset = pinger->sequence;

	/* Transmit packet */
	if ( ( rc = xfer_deliver ( &pinger->xfer, iobuf, &meta ) ) != 0 ) {
		DBGC ( pinger, "PINGER %p could not transmit: %s\n",
		       pinger, strerror ( rc ) );
		return;
	}
}

/**
 * Handle received data
 *
 * @v pinger		Pinger
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int pinger_deliver ( struct pinger *pinger, struct io_buffer *iobuf,
			    struct xfer_metadata *meta ) {
	size_t len = iob_len ( iobuf );
	uint16_t sequence = meta->offset;
	int terminate = 0;
	int rc;

	/* Clear response pending flag, if applicable */
	if ( sequence == pinger->sequence )
		pinger->pending = 0;

	/* Check for errors */
	if ( len != pinger->len ) {
		/* Incorrect length: terminate immediately if we are
		 * not pinging indefinitely.
		 */
		DBGC ( pinger, "PINGER %p received incorrect length %zd "
		       "(expected %zd)\n", pinger, len, pinger->len );
		rc = -EPROTO_LEN;
		terminate = ( pinger->remaining != 0 );
	} else if ( ( rc = pinger_verify ( pinger, iobuf->data ) ) != 0 ) {
		/* Incorrect data: terminate immediately if we are not
		 * pinging indefinitely.
		 */
		DBGC ( pinger, "PINGER %p received incorrect data:\n", pinger );
		DBGC_HDA ( pinger, 0, iobuf->data, iob_len ( iobuf ) );
		terminate = ( pinger->remaining != 0 );
	} else if ( sequence != pinger->sequence ) {
		/* Incorrect sequence number (probably a delayed response):
		 * report via callback but otherwise ignore.
		 */
		DBGC ( pinger, "PINGER %p received sequence %d (expected %d)\n",
		       pinger, sequence, pinger->sequence );
		rc = -EPROTO_SEQ;
		terminate = 0;
	} else {
		/* Success: record that a packet was successfully received,
		 * and terminate if we expect to send no further packets.
		 */
		rc = 0;
		pinger->rc = 0;
		terminate = ( pinger->remaining == 1 );
	}

	/* Discard I/O buffer */
	free_iob ( iobuf );

	/* Notify callback function, if applicable */
	if ( pinger->callback )
		pinger->callback ( meta->src, sequence, len, rc );

	/* Terminate if applicable */
	if ( terminate )
		pinger_close ( pinger, rc );

	return rc;
}

/** Pinger data transfer interface operations */
static struct interface_operation pinger_xfer_op[] = {
	INTF_OP ( xfer_deliver, struct pinger *, pinger_deliver ),
	INTF_OP ( xfer_window_changed, struct pinger *, pinger_window_changed ),
	INTF_OP ( intf_close, struct pinger *, pinger_close ),
};

/** Pinger data transfer interface descriptor */
static struct interface_descriptor pinger_xfer_desc =
	INTF_DESC ( struct pinger, xfer, pinger_xfer_op );

/** Pinger job control interface operations */
static struct interface_operation pinger_job_op[] = {
	INTF_OP ( intf_close, struct pinger *, pinger_close ),
};

/** Pinger job control interface descriptor */
static struct interface_descriptor pinger_job_desc =
	INTF_DESC ( struct pinger, job, pinger_job_op );

/**
 * Create pinger
 *
 * @v job		Job control interface
 * @v hostname		Hostname to ping
 * @v timeout		Timeout (in ticks)
 * @v len		Payload length
 * @v count		Number of packets to send (or zero for no limit)
 * @v callback		Callback function (or NULL)
 * @ret rc		Return status code
 */
int create_pinger ( struct interface *job, const char *hostname,
		    unsigned long timeout, size_t len, unsigned int count,
		    void ( * callback ) ( struct sockaddr *src,
					  unsigned int sequence, size_t len,
					  int rc ) ) {
	struct pinger *pinger;
	int rc;

	/* Sanity check */
	if ( ! timeout )
		return -EINVAL;

	/* Allocate and initialise structure */
	pinger = zalloc ( sizeof ( *pinger ) );
	if ( ! pinger )
		return -ENOMEM;
	ref_init ( &pinger->refcnt, NULL );
	intf_init ( &pinger->job, &pinger_job_desc, &pinger->refcnt );
	intf_init ( &pinger->xfer, &pinger_xfer_desc, &pinger->refcnt );
	timer_init ( &pinger->timer, pinger_expired, &pinger->refcnt );
	pinger->timeout = timeout;
	pinger->len = len;
	pinger->remaining = ( count ? ( count + 1 /* Initial packet */ ) : 0 );
	pinger->callback = callback;
	pinger->rc = -ETIMEDOUT;

	/* Open socket */
	if ( ( rc = xfer_open_named_socket ( &pinger->xfer, SOCK_ECHO, NULL,
					     hostname, NULL ) ) != 0 ) {
		DBGC ( pinger, "PINGER %p could not open socket: %s\n",
		       pinger, strerror ( rc ) );
		goto err;
	}

	/* Attach parent interface, mortalise self, and return */
	intf_plug_plug ( &pinger->job, job );
	ref_put ( &pinger->refcnt );
	return 0;

 err:
	pinger_close ( pinger, rc );
	ref_put ( &pinger->refcnt );
	return rc;
}
