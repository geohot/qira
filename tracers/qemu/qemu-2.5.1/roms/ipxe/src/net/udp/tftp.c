/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <byteswap.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/refcnt.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/uri.h>
#include <ipxe/tcpip.h>
#include <ipxe/retry.h>
#include <ipxe/features.h>
#include <ipxe/bitmap.h>
#include <ipxe/settings.h>
#include <ipxe/dhcp.h>
#include <ipxe/uri.h>
#include <ipxe/tftp.h>

/** @file
 *
 * TFTP protocol
 *
 */

FEATURE ( FEATURE_PROTOCOL, "TFTP", DHCP_EB_FEATURE_TFTP, 1 );

/* TFTP-specific error codes */
#define EINVAL_BLKSIZE 	__einfo_error ( EINFO_EINVAL_BLKSIZE )
#define EINFO_EINVAL_BLKSIZE __einfo_uniqify \
	( EINFO_EINVAL, 0x01, "Invalid blksize" )
#define EINVAL_TSIZE __einfo_error ( EINFO_EINVAL_TSIZE )
#define EINFO_EINVAL_TSIZE __einfo_uniqify \
	( EINFO_EINVAL, 0x02, "Invalid tsize" )
#define EINVAL_MC_NO_PORT __einfo_error ( EINFO_EINVAL_MC_NO_PORT )
#define EINFO_EINVAL_MC_NO_PORT __einfo_uniqify \
	( EINFO_EINVAL, 0x03, "Missing multicast port" )
#define EINVAL_MC_NO_MC __einfo_error ( EINFO_EINVAL_MC_NO_MC )
#define EINFO_EINVAL_MC_NO_MC __einfo_uniqify \
	( EINFO_EINVAL, 0x04, "Missing multicast mc" )
#define EINVAL_MC_INVALID_MC __einfo_error ( EINFO_EINVAL_MC_INVALID_MC )
#define EINFO_EINVAL_MC_INVALID_MC __einfo_uniqify \
	( EINFO_EINVAL, 0x05, "Missing multicast IP" )
#define EINVAL_MC_INVALID_IP __einfo_error ( EINFO_EINVAL_MC_INVALID_IP )
#define EINFO_EINVAL_MC_INVALID_IP __einfo_uniqify \
	( EINFO_EINVAL, 0x06, "Invalid multicast IP" )
#define EINVAL_MC_INVALID_PORT __einfo_error ( EINFO_EINVAL_MC_INVALID_PORT )
#define EINFO_EINVAL_MC_INVALID_PORT __einfo_uniqify \
	( EINFO_EINVAL, 0x07, "Invalid multicast port" )

/**
 * A TFTP request
 *
 * This data structure holds the state for an ongoing TFTP transfer.
 */
struct tftp_request {
	/** Reference count */
	struct refcnt refcnt;
	/** Data transfer interface */
	struct interface xfer;

	/** URI being fetched */
	struct uri *uri;
	/** Transport layer interface */
	struct interface socket;
	/** Multicast transport layer interface */
	struct interface mc_socket;

	/** Data block size
	 *
	 * This is the "blksize" option negotiated with the TFTP
	 * server.  (If the TFTP server does not support TFTP options,
	 * this will default to 512).
	 */
	unsigned int blksize;
	/** File size
	 *
	 * This is the value returned in the "tsize" option from the
	 * TFTP server.  If the TFTP server does not support the
	 * "tsize" option, this value will be zero.
	 */
	unsigned long tsize;
	
	/** Server port
	 *
	 * This is the port to which RRQ packets are sent.
	 */
	unsigned int port;
	/** Peer address
	 *
	 * The peer address is determined by the first response
	 * received to the TFTP RRQ.
	 */
	struct sockaddr_tcpip peer;
	/** Request flags */
	unsigned int flags;
	/** MTFTP timeout count */
	unsigned int mtftp_timeouts;

	/** Block bitmap */
	struct bitmap bitmap;
	/** Maximum known length
	 *
	 * We don't always know the file length in advance.  In
	 * particular, if the TFTP server doesn't support the tsize
	 * option, or we are using MTFTP, then we don't know the file
	 * length until we see the end-of-file block (which, in the
	 * case of MTFTP, may not be the last block we see).
	 *
	 * This value is updated whenever we obtain information about
	 * the file length.
	 */
	size_t filesize;
	/** Retransmission timer */
	struct retry_timer timer;
};

/** TFTP request flags */
enum {
	/** Send ACK packets */
	TFTP_FL_SEND_ACK = 0x0001,
	/** Request blksize and tsize options */
	TFTP_FL_RRQ_SIZES = 0x0002,
	/** Request multicast option */
	TFTP_FL_RRQ_MULTICAST = 0x0004,
	/** Perform MTFTP recovery on timeout */
	TFTP_FL_MTFTP_RECOVERY = 0x0008,
};

/** Maximum number of MTFTP open requests before falling back to TFTP */
#define MTFTP_MAX_TIMEOUTS 3

/**
 * Free TFTP request
 *
 * @v refcnt		Reference counter
 */
static void tftp_free ( struct refcnt *refcnt ) {
	struct tftp_request *tftp =
		container_of ( refcnt, struct tftp_request, refcnt );

	uri_put ( tftp->uri );
	bitmap_free ( &tftp->bitmap );
	free ( tftp );
}

/**
 * Mark TFTP request as complete
 *
 * @v tftp		TFTP connection
 * @v rc		Return status code
 */
static void tftp_done ( struct tftp_request *tftp, int rc ) {

	DBGC ( tftp, "TFTP %p finished with status %d (%s)\n",
	       tftp, rc, strerror ( rc ) );

	/* Stop the retry timer */
	stop_timer ( &tftp->timer );

	/* Close all data transfer interfaces */
	intf_shutdown ( &tftp->socket, rc );
	intf_shutdown ( &tftp->mc_socket, rc );
	intf_shutdown ( &tftp->xfer, rc );
}

/**
 * Reopen TFTP socket
 *
 * @v tftp		TFTP connection
 * @ret rc		Return status code
 */
static int tftp_reopen ( struct tftp_request *tftp ) {
	struct sockaddr_tcpip server;
	int rc;

	/* Close socket */
	intf_restart ( &tftp->socket, 0 );

	/* Disable ACK sending. */
	tftp->flags &= ~TFTP_FL_SEND_ACK;

	/* Reset peer address */
	memset ( &tftp->peer, 0, sizeof ( tftp->peer ) );

	/* Open socket */
	memset ( &server, 0, sizeof ( server ) );
	server.st_port = htons ( tftp->port );
	if ( ( rc = xfer_open_named_socket ( &tftp->socket, SOCK_DGRAM,
					     ( struct sockaddr * ) &server,
					     tftp->uri->host, NULL ) ) != 0 ) {
		DBGC ( tftp, "TFTP %p could not open socket: %s\n",
		       tftp, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Reopen TFTP multicast socket
 *
 * @v tftp		TFTP connection
 * @v local		Local socket address
 * @ret rc		Return status code
 */
static int tftp_reopen_mc ( struct tftp_request *tftp,
			    struct sockaddr *local ) {
	int rc;

	/* Close multicast socket */
	intf_restart ( &tftp->mc_socket, 0 );

	/* Open multicast socket.  We never send via this socket, so
	 * use the local address as the peer address (since the peer
	 * address cannot be NULL).
	 */
	if ( ( rc = xfer_open_socket ( &tftp->mc_socket, SOCK_DGRAM,
				       local, local ) ) != 0 ) {
		DBGC ( tftp, "TFTP %p could not open multicast "
		       "socket: %s\n", tftp, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Presize TFTP receive buffers and block bitmap
 *
 * @v tftp		TFTP connection
 * @v filesize		Known minimum file size
 * @ret rc		Return status code
 */
static int tftp_presize ( struct tftp_request *tftp, size_t filesize ) {
	unsigned int num_blocks;
	int rc;

	/* Do nothing if we are already large enough */
	if ( filesize <= tftp->filesize )
		return 0;

	/* Record filesize */
	tftp->filesize = filesize;

	/* Notify recipient of file size */
	xfer_seek ( &tftp->xfer, filesize );
	xfer_seek ( &tftp->xfer, 0 );

	/* Calculate expected number of blocks.  Note that files whose
	 * length is an exact multiple of the blocksize will have a
	 * trailing zero-length block, which must be included.
	 */
	num_blocks = ( ( filesize / tftp->blksize ) + 1 );
	if ( ( rc = bitmap_resize ( &tftp->bitmap, num_blocks ) ) != 0 ) {
		DBGC ( tftp, "TFTP %p could not resize bitmap to %d blocks: "
		       "%s\n", tftp, num_blocks, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * MTFTP multicast receive address
 *
 * This is treated as a global configuration parameter.
 */
static struct sockaddr_in tftp_mtftp_socket = {
	.sin_family = AF_INET,
	.sin_addr.s_addr = htonl ( 0xefff0101 ),
	.sin_port = htons ( 3001 ),
};

/**
 * Set MTFTP multicast address
 *
 * @v address		Multicast IPv4 address
 */
void tftp_set_mtftp_address ( struct in_addr address ) {
	tftp_mtftp_socket.sin_addr = address;
}

/**
 * Set MTFTP multicast port
 *
 * @v port		Multicast port
 */
void tftp_set_mtftp_port ( unsigned int port ) {
	tftp_mtftp_socket.sin_port = htons ( port );
}

/**
 * Transmit RRQ
 *
 * @v tftp		TFTP connection
 * @ret rc		Return status code
 */
static int tftp_send_rrq ( struct tftp_request *tftp ) {
	const char *path = tftp->uri->path;
	struct tftp_rrq *rrq;
	size_t len;
	struct io_buffer *iobuf;
	size_t blksize;

	DBGC ( tftp, "TFTP %p requesting \"%s\"\n", tftp, path );

	/* Allocate buffer */
	len = ( sizeof ( *rrq ) + strlen ( path ) + 1 /* NUL */
		+ 5 + 1 /* "octet" + NUL */
		+ 7 + 1 + 5 + 1 /* "blksize" + NUL + ddddd + NUL */
		+ 5 + 1 + 1 + 1 /* "tsize" + NUL + "0" + NUL */ 
		+ 9 + 1 + 1 /* "multicast" + NUL + NUL */ );
	iobuf = xfer_alloc_iob ( &tftp->socket, len );
	if ( ! iobuf )
		return -ENOMEM;

	/* Determine block size */
	blksize = xfer_window ( &tftp->xfer );
	if ( blksize > TFTP_MAX_BLKSIZE )
		blksize = TFTP_MAX_BLKSIZE;

	/* Build request */
	rrq = iob_put ( iobuf, sizeof ( *rrq ) );
	rrq->opcode = htons ( TFTP_RRQ );
	iob_put ( iobuf, snprintf ( iobuf->tail, iob_tailroom ( iobuf ),
				    "%s%coctet", path, 0 ) + 1 );
	if ( tftp->flags & TFTP_FL_RRQ_SIZES ) {
		iob_put ( iobuf, snprintf ( iobuf->tail,
					    iob_tailroom ( iobuf ),
					    "blksize%c%zd%ctsize%c0",
					    0, blksize, 0, 0 ) + 1 );
	}
	if ( tftp->flags & TFTP_FL_RRQ_MULTICAST ) {
		iob_put ( iobuf, snprintf ( iobuf->tail,
					    iob_tailroom ( iobuf ),
					    "multicast%c", 0 ) + 1 );
	}

	/* RRQ always goes to the address specified in the initial
	 * xfer_open() call
	 */
	return xfer_deliver_iob ( &tftp->socket, iobuf );
}

/**
 * Transmit ACK
 *
 * @v tftp		TFTP connection
 * @ret rc		Return status code
 */
static int tftp_send_ack ( struct tftp_request *tftp ) {
	struct tftp_ack *ack;
	struct io_buffer *iobuf;
	struct xfer_metadata meta = {
		.dest = ( struct sockaddr * ) &tftp->peer,
	};
	unsigned int block;

	/* Determine next required block number */
	block = bitmap_first_gap ( &tftp->bitmap );
	DBGC2 ( tftp, "TFTP %p sending ACK for block %d\n", tftp, block );

	/* Allocate buffer */
	iobuf = xfer_alloc_iob ( &tftp->socket, sizeof ( *ack ) );
	if ( ! iobuf )
		return -ENOMEM;

	/* Build ACK */
	ack = iob_put ( iobuf, sizeof ( *ack ) );
	ack->opcode = htons ( TFTP_ACK );
	ack->block = htons ( block );

	/* ACK always goes to the peer recorded from the RRQ response */
	return xfer_deliver ( &tftp->socket, iobuf, &meta );
}

/**
 * Transmit ERROR (Abort)
 *
 * @v tftp		TFTP connection
 * @v errcode		TFTP error code
 * @v errmsg		Error message string
 * @ret rc		Return status code
 */
static int tftp_send_error ( struct tftp_request *tftp, int errcode,
			     const char *errmsg ) {
	struct tftp_error *err;
	struct io_buffer *iobuf;
	struct xfer_metadata meta = {
		.dest = ( struct sockaddr * ) &tftp->peer,
	};
	size_t msglen;

	DBGC2 ( tftp, "TFTP %p sending ERROR %d: %s\n", tftp, errcode,
		errmsg );

	/* Allocate buffer */
	msglen = sizeof ( *err ) + strlen ( errmsg ) + 1 /* NUL */;
	iobuf = xfer_alloc_iob ( &tftp->socket, msglen );
	if ( ! iobuf )
		return -ENOMEM;

	/* Build ERROR */
	err = iob_put ( iobuf, msglen );
	err->opcode = htons ( TFTP_ERROR );
	err->errcode = htons ( errcode );
	strcpy ( err->errmsg, errmsg );

	/* ERR always goes to the peer recorded from the RRQ response */
	return xfer_deliver ( &tftp->socket, iobuf, &meta );
}

/**
 * Transmit next relevant packet
 *
 * @v tftp		TFTP connection
 * @ret rc		Return status code
 */
static int tftp_send_packet ( struct tftp_request *tftp ) {

	/* Update retransmission timer.  While name resolution takes place the
	 * window is zero.  Avoid unnecessary delay after name resolution
	 * completes by retrying immediately.
	 */
	stop_timer ( &tftp->timer );
	if ( xfer_window ( &tftp->socket ) ) {
		start_timer ( &tftp->timer );
	} else {
		start_timer_nodelay ( &tftp->timer );
	}

	/* Send RRQ or ACK as appropriate */
	if ( ! tftp->peer.st_family ) {
		return tftp_send_rrq ( tftp );
	} else {
		if ( tftp->flags & TFTP_FL_SEND_ACK ) {
			return tftp_send_ack ( tftp );
		} else {
			return 0;
		}
	}
}

/**
 * Handle TFTP retransmission timer expiry
 *
 * @v timer		Retry timer
 * @v fail		Failure indicator
 */
static void tftp_timer_expired ( struct retry_timer *timer, int fail ) {
	struct tftp_request *tftp =
		container_of ( timer, struct tftp_request, timer );
	int rc;

	/* If we are doing MTFTP, attempt the various recovery strategies */
	if ( tftp->flags & TFTP_FL_MTFTP_RECOVERY ) {
		if ( tftp->peer.st_family ) {
			/* If we have received any response from the server,
			 * try resending the RRQ to restart the download.
			 */
			DBGC ( tftp, "TFTP %p attempting reopen\n", tftp );
			if ( ( rc = tftp_reopen ( tftp ) ) != 0 )
				goto err;
		} else {
			/* Fall back to plain TFTP after several attempts */
			tftp->mtftp_timeouts++;
			DBGC ( tftp, "TFTP %p timeout %d waiting for MTFTP "
			       "open\n", tftp, tftp->mtftp_timeouts );

			if ( tftp->mtftp_timeouts > MTFTP_MAX_TIMEOUTS ) {
				DBGC ( tftp, "TFTP %p falling back to plain "
				       "TFTP\n", tftp );
				tftp->flags = TFTP_FL_RRQ_SIZES;

				/* Close multicast socket */
				intf_restart ( &tftp->mc_socket, 0 );

				/* Reset retry timer */
				start_timer_nodelay ( &tftp->timer );

				/* The blocksize may change: discard
				 * the block bitmap
				 */
				bitmap_free ( &tftp->bitmap );
				memset ( &tftp->bitmap, 0,
					 sizeof ( tftp->bitmap ) );

				/* Reopen on standard TFTP port */
				tftp->port = TFTP_PORT;
				if ( ( rc = tftp_reopen ( tftp ) ) != 0 )
					goto err;
			}
		}
	} else {
		/* Not doing MTFTP (or have fallen back to plain
		 * TFTP); fail as per normal.
		 */
		if ( fail ) {
			rc = -ETIMEDOUT;
			goto err;
		}
	}
	tftp_send_packet ( tftp );
	return;

 err:
	tftp_done ( tftp, rc );
}

/**
 * Process TFTP "blksize" option
 *
 * @v tftp		TFTP connection
 * @v value		Option value
 * @ret rc		Return status code
 */
static int tftp_process_blksize ( struct tftp_request *tftp,
				  const char *value ) {
	char *end;

	tftp->blksize = strtoul ( value, &end, 10 );
	if ( *end ) {
		DBGC ( tftp, "TFTP %p got invalid blksize \"%s\"\n",
		       tftp, value );
		return -EINVAL_BLKSIZE;
	}
	DBGC ( tftp, "TFTP %p blksize=%d\n", tftp, tftp->blksize );

	return 0;
}

/**
 * Process TFTP "tsize" option
 *
 * @v tftp		TFTP connection
 * @v value		Option value
 * @ret rc		Return status code
 */
static int tftp_process_tsize ( struct tftp_request *tftp,
				const char *value ) {
	char *end;

	tftp->tsize = strtoul ( value, &end, 10 );
	if ( *end ) {
		DBGC ( tftp, "TFTP %p got invalid tsize \"%s\"\n",
		       tftp, value );
		return -EINVAL_TSIZE;
	}
	DBGC ( tftp, "TFTP %p tsize=%ld\n", tftp, tftp->tsize );

	return 0;
}

/**
 * Process TFTP "multicast" option
 *
 * @v tftp		TFTP connection
 * @v value		Option value
 * @ret rc		Return status code
 */
static int tftp_process_multicast ( struct tftp_request *tftp,
				    const char *value ) {
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
	} socket;
	char buf[ strlen ( value ) + 1 ];
	char *addr;
	char *port;
	char *port_end;
	char *mc;
	char *mc_end;
	int rc;

	/* Split value into "addr,port,mc" fields */
	memcpy ( buf, value, sizeof ( buf ) );
	addr = buf;
	port = strchr ( addr, ',' );
	if ( ! port ) {
		DBGC ( tftp, "TFTP %p multicast missing port,mc\n", tftp );
		return -EINVAL_MC_NO_PORT;
	}
	*(port++) = '\0';
	mc = strchr ( port, ',' );
	if ( ! mc ) {
		DBGC ( tftp, "TFTP %p multicast missing mc\n", tftp );
		return -EINVAL_MC_NO_MC;
	}
	*(mc++) = '\0';

	/* Parse parameters */
	if ( strtoul ( mc, &mc_end, 0 ) == 0 )
		tftp->flags &= ~TFTP_FL_SEND_ACK;
	if ( *mc_end ) {
		DBGC ( tftp, "TFTP %p multicast invalid mc %s\n", tftp, mc );
		return -EINVAL_MC_INVALID_MC;
	}
	DBGC ( tftp, "TFTP %p is%s the master client\n",
	       tftp, ( ( tftp->flags & TFTP_FL_SEND_ACK ) ? "" : " not" ) );
	if ( *addr && *port ) {
		socket.sin.sin_family = AF_INET;
		if ( inet_aton ( addr, &socket.sin.sin_addr ) == 0 ) {
			DBGC ( tftp, "TFTP %p multicast invalid IP address "
			       "%s\n", tftp, addr );
			return -EINVAL_MC_INVALID_IP;
		}
		DBGC ( tftp, "TFTP %p multicast IP address %s\n",
		       tftp, inet_ntoa ( socket.sin.sin_addr ) );
		socket.sin.sin_port = htons ( strtoul ( port, &port_end, 0 ) );
		if ( *port_end ) {
			DBGC ( tftp, "TFTP %p multicast invalid port %s\n",
			       tftp, port );
			return -EINVAL_MC_INVALID_PORT;
		}
		DBGC ( tftp, "TFTP %p multicast port %d\n",
		       tftp, ntohs ( socket.sin.sin_port ) );
		if ( ( rc = tftp_reopen_mc ( tftp, &socket.sa ) ) != 0 )
			return rc;
	}

	return 0;
}

/** A TFTP option */
struct tftp_option {
	/** Option name */
	const char *name;
	/** Option processor
	 *
	 * @v tftp	TFTP connection
	 * @v value	Option value
	 * @ret rc	Return status code
	 */
	int ( * process ) ( struct tftp_request *tftp, const char *value );
};

/** Recognised TFTP options */
static struct tftp_option tftp_options[] = {
	{ "blksize", tftp_process_blksize },
	{ "tsize", tftp_process_tsize },
	{ "multicast", tftp_process_multicast },
	{ NULL, NULL }
};

/**
 * Process TFTP option
 *
 * @v tftp		TFTP connection
 * @v name		Option name
 * @v value		Option value
 * @ret rc		Return status code
 */
static int tftp_process_option ( struct tftp_request *tftp,
				 const char *name, const char *value ) {
	struct tftp_option *option;

	for ( option = tftp_options ; option->name ; option++ ) {
		if ( strcasecmp ( name, option->name ) == 0 )
			return option->process ( tftp, value );
	}

	DBGC ( tftp, "TFTP %p received unknown option \"%s\" = \"%s\"\n",
	       tftp, name, value );

	/* Unknown options should be silently ignored */
	return 0;
}

/**
 * Receive OACK
 *
 * @v tftp		TFTP connection
 * @v buf		Temporary data buffer
 * @v len		Length of temporary data buffer
 * @ret rc		Return status code
 */
static int tftp_rx_oack ( struct tftp_request *tftp, void *buf, size_t len ) {
	struct tftp_oack *oack = buf;
	char *end = buf + len;
	char *name;
	char *value;
	char *next;
	int rc = 0;

	/* Sanity check */
	if ( len < sizeof ( *oack ) ) {
		DBGC ( tftp, "TFTP %p received underlength OACK packet "
		       "length %zd\n", tftp, len );
		rc = -EINVAL;
		goto done;
	}

	/* Process each option in turn */
	for ( name = oack->data ; name < end ; name = next ) {

		/* Parse option name and value
		 *
		 * We treat parsing errors as non-fatal, because there
		 * exists at least one TFTP server (IBM Tivoli PXE
		 * Server 5.1.0.3) that has been observed to send
		 * malformed OACKs containing trailing garbage bytes.
		 */
		value = ( name + strnlen ( name, ( end - name ) ) + 1 );
		if ( value > end ) {
			DBGC ( tftp, "TFTP %p received OACK with malformed "
			       "option name:\n", tftp );
			DBGC_HD ( tftp, oack, len );
			break;
		}
		if ( value == end ) {
			DBGC ( tftp, "TFTP %p received OACK missing value "
			       "for option \"%s\"\n", tftp, name );
			DBGC_HD ( tftp, oack, len );
			break;
		}
		next = ( value + strnlen ( value, ( end - value ) ) + 1 );
		if ( next > end ) {
			DBGC ( tftp, "TFTP %p received OACK with malformed "
			       "value for option \"%s\":\n", tftp, name );
			DBGC_HD ( tftp, oack, len );
			break;
		}

		/* Process option */
		if ( ( rc = tftp_process_option ( tftp, name, value ) ) != 0 )
			goto done;
	}

	/* Process tsize information, if available */
	if ( tftp->tsize ) {
		if ( ( rc = tftp_presize ( tftp, tftp->tsize ) ) != 0 )
			goto done;
	}

	/* Request next data block */
	tftp_send_packet ( tftp );

 done:
	if ( rc )
		tftp_done ( tftp, rc );
	return rc;
}

/**
 * Receive DATA
 *
 * @v tftp		TFTP connection
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 *
 * Takes ownership of I/O buffer.
 */
static int tftp_rx_data ( struct tftp_request *tftp,
			  struct io_buffer *iobuf ) {
	struct tftp_data *data = iobuf->data;
	struct xfer_metadata meta;
	unsigned int block;
	off_t offset;
	size_t data_len;
	int rc;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *data ) ) {
		DBGC ( tftp, "TFTP %p received underlength DATA packet "
		       "length %zd\n", tftp, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto done;
	}

	/* Calculate block number */
	block = ( ( bitmap_first_gap ( &tftp->bitmap ) + 1 ) & ~0xffff );
	if ( data->block == 0 && block == 0 ) {
		DBGC ( tftp, "TFTP %p received data block 0\n", tftp );
		rc = -EINVAL;
		goto done;
	}
	block += ( ntohs ( data->block ) - 1 );

	/* Extract data */
	offset = ( block * tftp->blksize );
	iob_pull ( iobuf, sizeof ( *data ) );
	data_len = iob_len ( iobuf );
	if ( data_len > tftp->blksize ) {
		DBGC ( tftp, "TFTP %p received overlength DATA packet "
		       "length %zd\n", tftp, data_len );
		rc = -EINVAL;
		goto done;
	}

	/* Deliver data */
	memset ( &meta, 0, sizeof ( meta ) );
	meta.flags = XFER_FL_ABS_OFFSET;
	meta.offset = offset;
	if ( ( rc = xfer_deliver ( &tftp->xfer, iob_disown ( iobuf ),
				   &meta ) ) != 0 ) {
		DBGC ( tftp, "TFTP %p could not deliver data: %s\n",
		       tftp, strerror ( rc ) );
		goto done;
	}

	/* Ensure block bitmap is ready */
	if ( ( rc = tftp_presize ( tftp, ( offset + data_len ) ) ) != 0 )
		goto done;

	/* Mark block as received */
	bitmap_set ( &tftp->bitmap, block );

	/* Acknowledge block */
	tftp_send_packet ( tftp );

	/* If all blocks have been received, finish. */
	if ( bitmap_full ( &tftp->bitmap ) )
		tftp_done ( tftp, 0 );

 done:
	free_iob ( iobuf );
	if ( rc )
		tftp_done ( tftp, rc );
	return rc;
}

/**
 * Convert TFTP error code to return status code
 *
 * @v errcode		TFTP error code
 * @ret rc		Return status code
 */
static int tftp_errcode_to_rc ( unsigned int errcode ) {
	switch ( errcode ) {
	case TFTP_ERR_FILE_NOT_FOUND:	return -ENOENT;
	case TFTP_ERR_ACCESS_DENIED:	return -EACCES;
	case TFTP_ERR_ILLEGAL_OP:	return -ENOTTY;
	default:			return -ENOTSUP;
	}
}

/**
 * Receive ERROR
 *
 * @v tftp		TFTP connection
 * @v buf		Temporary data buffer
 * @v len		Length of temporary data buffer
 * @ret rc		Return status code
 */
static int tftp_rx_error ( struct tftp_request *tftp, void *buf, size_t len ) {
	struct tftp_error *error = buf;
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *error ) ) {
		DBGC ( tftp, "TFTP %p received underlength ERROR packet "
		       "length %zd\n", tftp, len );
		return -EINVAL;
	}

	DBGC ( tftp, "TFTP %p received ERROR packet with code %d, message "
	       "\"%s\"\n", tftp, ntohs ( error->errcode ), error->errmsg );
	
	/* Determine final operation result */
	rc = tftp_errcode_to_rc ( ntohs ( error->errcode ) );

	/* Close TFTP request */
	tftp_done ( tftp, rc );

	return 0;
}

/**
 * Receive new data
 *
 * @v tftp		TFTP connection
 * @v iobuf		I/O buffer
 * @v meta		Transfer metadata
 * @ret rc		Return status code
 */
static int tftp_rx ( struct tftp_request *tftp,
		     struct io_buffer *iobuf,
		     struct xfer_metadata *meta ) {
	struct sockaddr_tcpip *st_src;
	struct tftp_common *common = iobuf->data;
	size_t len = iob_len ( iobuf );
	int rc = -EINVAL;
	
	/* Sanity checks */
	if ( len < sizeof ( *common ) ) {
		DBGC ( tftp, "TFTP %p received underlength packet length "
		       "%zd\n", tftp, len );
		goto done;
	}
	if ( ! meta->src ) {
		DBGC ( tftp, "TFTP %p received packet without source port\n",
		       tftp );
		goto done;
	}

	/* Filter by TID.  Set TID on first response received */
	st_src = ( struct sockaddr_tcpip * ) meta->src;
	if ( ! tftp->peer.st_family ) {
		memcpy ( &tftp->peer, st_src, sizeof ( tftp->peer ) );
		DBGC ( tftp, "TFTP %p using remote port %d\n", tftp,
		       ntohs ( tftp->peer.st_port ) );
	} else if ( memcmp ( &tftp->peer, st_src,
			     sizeof ( tftp->peer ) ) != 0 ) {
		DBGC ( tftp, "TFTP %p received packet from wrong source (got "
		       "%d, wanted %d)\n", tftp, ntohs ( st_src->st_port ),
		       ntohs ( tftp->peer.st_port ) );
		goto done;
	}

	switch ( common->opcode ) {
	case htons ( TFTP_OACK ):
		rc = tftp_rx_oack ( tftp, iobuf->data, len );
		break;
	case htons ( TFTP_DATA ):
		rc = tftp_rx_data ( tftp, iob_disown ( iobuf ) );
		break;
	case htons ( TFTP_ERROR ):
		rc = tftp_rx_error ( tftp, iobuf->data, len );
		break;
	default:
		DBGC ( tftp, "TFTP %p received strange packet type %d\n",
		       tftp, ntohs ( common->opcode ) );
		break;
	};

 done:
	free_iob ( iobuf );
	return rc;
}

/**
 * Receive new data via socket
 *
 * @v tftp		TFTP connection
 * @v iobuf		I/O buffer
 * @v meta		Transfer metadata
 * @ret rc		Return status code
 */
static int tftp_socket_deliver ( struct tftp_request *tftp,
				 struct io_buffer *iobuf,
				 struct xfer_metadata *meta ) {

	/* Enable sending ACKs when we receive a unicast packet.  This
	 * covers three cases:
	 *
	 * 1. Standard TFTP; we should always send ACKs, and will
	 *    always receive a unicast packet before we need to send the
	 *    first ACK.
	 *
	 * 2. RFC2090 multicast TFTP; the only unicast packets we will
         *    receive are the OACKs; enable sending ACKs here (before
         *    processing the OACK) and disable it when processing the
         *    multicast option if we are not the master client.
	 *
	 * 3. MTFTP; receiving a unicast datagram indicates that we
	 *    are the "master client" and should send ACKs.
	 */
	tftp->flags |= TFTP_FL_SEND_ACK;

	return tftp_rx ( tftp, iobuf, meta );
}

/** TFTP socket operations */
static struct interface_operation tftp_socket_operations[] = {
	INTF_OP ( xfer_deliver, struct tftp_request *, tftp_socket_deliver ),
};

/** TFTP socket interface descriptor */
static struct interface_descriptor tftp_socket_desc =
	INTF_DESC ( struct tftp_request, socket, tftp_socket_operations );

/** TFTP multicast socket operations */
static struct interface_operation tftp_mc_socket_operations[] = {
	INTF_OP ( xfer_deliver, struct tftp_request *, tftp_rx ),
};

/** TFTP multicast socket interface descriptor */
static struct interface_descriptor tftp_mc_socket_desc =
	INTF_DESC ( struct tftp_request, mc_socket, tftp_mc_socket_operations );

/**
 * Check flow control window
 *
 * @v tftp		TFTP connection
 * @ret len		Length of window
 */
static size_t tftp_xfer_window ( struct tftp_request *tftp ) {

	/* We abuse this data-xfer method to convey the blocksize to
	 * the caller.  This really should be done using some kind of
	 * stat() method, but we don't yet have the facility to do
	 * that.
	 */
	return tftp->blksize;
}

/**
 * Terminate download
 *
 * @v tftp		TFTP connection
 * @v rc		Reason for close
 */
static void tftp_close ( struct tftp_request *tftp, int rc ) {

	/* Abort download */
	tftp_send_error ( tftp, 0, "TFTP Aborted" );

	/* Close TFTP request */
	tftp_done ( tftp, rc );
}

/** TFTP data transfer interface operations */
static struct interface_operation tftp_xfer_operations[] = {
	INTF_OP ( xfer_window, struct tftp_request *, tftp_xfer_window ),
	INTF_OP ( intf_close, struct tftp_request *, tftp_close ),
};

/** TFTP data transfer interface descriptor */
static struct interface_descriptor tftp_xfer_desc =
	INTF_DESC ( struct tftp_request, xfer, tftp_xfer_operations );

/**
 * Initiate TFTP/TFTM/MTFTP download
 *
 * @v xfer		Data transfer interface
 * @v uri		Uniform Resource Identifier
 * @ret rc		Return status code
 */
static int tftp_core_open ( struct interface *xfer, struct uri *uri,
			    unsigned int default_port,
			    struct sockaddr *multicast,
			    unsigned int flags ) {
	struct tftp_request *tftp;
	int rc;

	/* Sanity checks */
	if ( ! uri->host )
		return -EINVAL;
	if ( ! uri->path )
		return -EINVAL;

	/* Allocate and populate TFTP structure */
	tftp = zalloc ( sizeof ( *tftp ) );
	if ( ! tftp )
		return -ENOMEM;
	ref_init ( &tftp->refcnt, tftp_free );
	intf_init ( &tftp->xfer, &tftp_xfer_desc, &tftp->refcnt );
	intf_init ( &tftp->socket, &tftp_socket_desc, &tftp->refcnt );
	intf_init ( &tftp->mc_socket, &tftp_mc_socket_desc, &tftp->refcnt );
	timer_init ( &tftp->timer, tftp_timer_expired, &tftp->refcnt );
	tftp->uri = uri_get ( uri );
	tftp->blksize = TFTP_DEFAULT_BLKSIZE;
	tftp->flags = flags;

	/* Open socket */
	tftp->port = uri_port ( tftp->uri, default_port );
	if ( ( rc = tftp_reopen ( tftp ) ) != 0 )
		goto err;

	/* Open multicast socket */
	if ( multicast ) {
		if ( ( rc = tftp_reopen_mc ( tftp, multicast ) ) != 0 )
			goto err;
	}

	/* Start timer to initiate RRQ */
	start_timer_nodelay ( &tftp->timer );

	/* Attach to parent interface, mortalise self, and return */
	intf_plug_plug ( &tftp->xfer, xfer );
	ref_put ( &tftp->refcnt );
	return 0;

 err:
	DBGC ( tftp, "TFTP %p could not create request: %s\n",
	       tftp, strerror ( rc ) );
	tftp_done ( tftp, rc );
	ref_put ( &tftp->refcnt );
	return rc;
}

/**
 * Initiate TFTP download
 *
 * @v xfer		Data transfer interface
 * @v uri		Uniform Resource Identifier
 * @ret rc		Return status code
 */
static int tftp_open ( struct interface *xfer, struct uri *uri ) {
	return tftp_core_open ( xfer, uri, TFTP_PORT, NULL,
				TFTP_FL_RRQ_SIZES );

}

/** TFTP URI opener */
struct uri_opener tftp_uri_opener __uri_opener = {
	.scheme	= "tftp",
	.open	= tftp_open,
};

/**
 * Initiate TFTM download
 *
 * @v xfer		Data transfer interface
 * @v uri		Uniform Resource Identifier
 * @ret rc		Return status code
 */
static int tftm_open ( struct interface *xfer, struct uri *uri ) {
	return tftp_core_open ( xfer, uri, TFTP_PORT, NULL,
				( TFTP_FL_RRQ_SIZES |
				  TFTP_FL_RRQ_MULTICAST ) );

}

/** TFTM URI opener */
struct uri_opener tftm_uri_opener __uri_opener = {
	.scheme	= "tftm",
	.open	= tftm_open,
};

/**
 * Initiate MTFTP download
 *
 * @v xfer		Data transfer interface
 * @v uri		Uniform Resource Identifier
 * @ret rc		Return status code
 */
static int mtftp_open ( struct interface *xfer, struct uri *uri ) {
	return tftp_core_open ( xfer, uri, MTFTP_PORT,
				( struct sockaddr * ) &tftp_mtftp_socket,
				TFTP_FL_MTFTP_RECOVERY );
}

/** MTFTP URI opener */
struct uri_opener mtftp_uri_opener __uri_opener = {
	.scheme	= "mtftp",
	.open	= mtftp_open,
};

/******************************************************************************
 *
 * Settings
 *
 ******************************************************************************
 */

/**
 * Apply TFTP configuration settings
 *
 * @ret rc		Return status code
 */
static int tftp_apply_settings ( void ) {
	static struct in_addr tftp_server = { 0 };
	struct in_addr last_tftp_server;
	char uri_string[32];
	struct uri *uri;

	/* Retrieve TFTP server setting */
	last_tftp_server = tftp_server;
	fetch_ipv4_setting ( NULL, &next_server_setting, &tftp_server );

	/* If TFTP server setting has changed, set the current working
	 * URI to match.  Do it only when the TFTP server has changed
	 * to try to minimise surprises to the user, who probably
	 * won't expect the CWURI to change just because they updated
	 * an unrelated setting and triggered all the settings
	 * applicators.
	 */
	if ( tftp_server.s_addr != last_tftp_server.s_addr ) {
		if ( tftp_server.s_addr ) {
			snprintf ( uri_string, sizeof ( uri_string ),
				   "tftp://%s/", inet_ntoa ( tftp_server ) );
			uri = parse_uri ( uri_string );
			if ( ! uri )
				return -ENOMEM;
		} else {
			uri = NULL;
		}
		churi ( uri );
		uri_put ( uri );
	}

	return 0;
}

/** TFTP settings applicator */
struct settings_applicator tftp_settings_applicator __settings_applicator = {
	.apply = tftp_apply_settings,
};
