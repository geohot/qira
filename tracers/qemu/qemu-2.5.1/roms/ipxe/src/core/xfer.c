/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>

/** @file
 *
 * Data transfer interfaces
 *
 */

/**
 * Dummy transfer metadata
 *
 * This gets passed to xfer_interface::deliver() and equivalents when
 * no metadata is available.
 */
static struct xfer_metadata dummy_metadata;

/*****************************************************************************
 *
 * Data transfer interface operations
 *
 */

/**
 * Send redirection event
 *
 * @v intf		Data transfer interface
 * @v type		New location type
 * @v args		Remaining arguments depend upon location type
 * @ret rc		Return status code
 */
int xfer_vredirect ( struct interface *intf, int type, va_list args ) {
	struct interface tmp = INTF_INIT ( null_intf_desc );
	struct interface *dest;
	xfer_vredirect_TYPE ( void * ) *op =
		intf_get_dest_op_no_passthru ( intf, xfer_vredirect, &dest );
	void *object = intf_object ( dest );
	int rc;

	DBGC ( INTF_COL ( intf ), "INTF " INTF_INTF_FMT " redirect\n",
	       INTF_INTF_DBG ( intf, dest ) );

	if ( op ) {
		rc = op ( object, type, args );
	} else {
		/* Default is to reopen the interface as instructed,
		 * then send xfer_window_changed() messages to both
		 * new child and parent interfaces.  Since our
		 * original child interface is likely to be closed and
		 * unplugged as a result of the call to
		 * xfer_vreopen(), we create a temporary interface in
		 * order to be able to send xfer_window_changed() to
		 * the parent.
		 */
		intf_plug ( &tmp, dest );
		rc = xfer_vreopen ( dest, type, args );
		if ( rc == 0 ) {
			xfer_window_changed ( dest );
			xfer_window_changed ( &tmp );
		}
		intf_unplug ( &tmp );
	}

	if ( rc != 0 ) {
		DBGC ( INTF_COL ( intf ), "INTF " INTF_INTF_FMT " redirect "
		       "failed: %s\n", INTF_INTF_DBG ( intf, dest ),
		       strerror ( rc ) );
	}

	intf_put ( dest );
	return rc;
}

/**
 * Check flow control window
 *
 * @v intf		Data transfer interface
 * @ret len		Length of window
 */
size_t xfer_window ( struct interface *intf ) {
	struct interface *dest;
	xfer_window_TYPE ( void * ) *op =
		intf_get_dest_op ( intf, xfer_window, &dest );
	void *object = intf_object ( dest );
	size_t len;

	if ( op ) {
		len = op ( object );
	} else {
		/* Default is to provide an unlimited window */
		len = ~( ( size_t ) 0 );
	}

	intf_put ( dest );
	return len;
}

/**
 * Report change of flow control window
 *
 * @v intf		Data transfer interface
 *
 * Note that this method is used to indicate only unsolicited changes
 * in the flow control window.  In particular, this method must not be
 * called as part of the response to xfer_deliver(), since that could
 * easily lead to an infinite loop.  Callers of xfer_deliver() should
 * assume that the flow control window will have changed without
 * generating an xfer_window_changed() message.
 */
void xfer_window_changed ( struct interface *intf ) {

	intf_poke ( intf, xfer_window_changed );
}

/**
 * Allocate I/O buffer
 *
 * @v intf		Data transfer interface
 * @v len		I/O buffer payload length
 * @ret iobuf		I/O buffer
 */
struct io_buffer * xfer_alloc_iob ( struct interface *intf, size_t len ) {
	struct interface *dest;
	xfer_alloc_iob_TYPE ( void * ) *op =
		intf_get_dest_op ( intf, xfer_alloc_iob, &dest );
	void *object = intf_object ( dest );
	struct io_buffer *iobuf;

	DBGC ( INTF_COL ( intf ), "INTF " INTF_INTF_FMT " alloc_iob %zd\n",
	       INTF_INTF_DBG ( intf, dest ), len );

	if ( op ) {
		iobuf = op ( object, len );
	} else {
		/* Default is to allocate an I/O buffer with no
		 * reserved space.
		 */
		iobuf = alloc_iob ( len );
	}

	if ( ! iobuf ) {
		DBGC ( INTF_COL ( intf ), "INTF " INTF_INTF_FMT " alloc_iob "
		       "failed\n", INTF_INTF_DBG ( intf, dest ) );
	}

	intf_put ( dest );
	return iobuf;
}

/**
 * Deliver datagram
 *
 * @v intf		Data transfer interface
 * @v iobuf		Datagram I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
int xfer_deliver ( struct interface *intf,
		   struct io_buffer *iobuf,
		   struct xfer_metadata *meta ) {
	struct interface *dest;
	xfer_deliver_TYPE ( void * ) *op =
		intf_get_dest_op ( intf, xfer_deliver, &dest );
	void *object = intf_object ( dest );
	int rc;

	DBGC ( INTF_COL ( intf ), "INTF " INTF_INTF_FMT " deliver %zd\n",
	       INTF_INTF_DBG ( intf, dest ), iob_len ( iobuf ) );

	if ( op ) {
		rc = op ( object, iobuf, meta );
	} else {
		/* Default is to discard the I/O buffer */
		free_iob ( iobuf );
		rc = -EPIPE;
	}

	if ( rc != 0 ) {
		DBGC ( INTF_COL ( intf ), "INTF " INTF_INTF_FMT
		       " deliver failed: %s\n",
		       INTF_INTF_DBG ( intf, dest ), strerror ( rc ) );
	}

	intf_put ( dest );
	return rc;
}

/*****************************************************************************
 *
 * Data transfer interface helper functions
 *
 */

/**
 * Send redirection event
 *
 * @v intf		Data transfer interface
 * @v type		New location type
 * @v ...		Remaining arguments depend upon location type
 * @ret rc		Return status code
 */
int xfer_redirect ( struct interface *intf, int type, ... ) {
	va_list args;
	int rc;

	va_start ( args, type );
	rc = xfer_vredirect ( intf, type, args );
	va_end ( args );
	return rc;
}

/**
 * Deliver datagram as I/O buffer without metadata
 *
 * @v intf		Data transfer interface
 * @v iobuf		Datagram I/O buffer
 * @ret rc		Return status code
 */
int xfer_deliver_iob ( struct interface *intf, struct io_buffer *iobuf ) {
	return xfer_deliver ( intf, iobuf, &dummy_metadata );
}

/**
 * Deliver datagram as raw data
 *
 * @v intf		Data transfer interface
 * @v data		Data
 * @v len		Length of data
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
int xfer_deliver_raw_meta ( struct interface *intf, const void *data,
			    size_t len, struct xfer_metadata *meta ) {
	struct io_buffer *iobuf;

	iobuf = xfer_alloc_iob ( intf, len );
	if ( ! iobuf )
		return -ENOMEM;

	memcpy ( iob_put ( iobuf, len ), data, len );
	return xfer_deliver ( intf, iobuf, meta );
}

/**
 * Deliver datagram as raw data without metadata
 *
 * @v intf		Data transfer interface
 * @v data		Data
 * @v len		Length of data
 * @ret rc		Return status code
 */
int xfer_deliver_raw ( struct interface *intf, const void *data, size_t len ) {
	return xfer_deliver_raw_meta ( intf, data, len, &dummy_metadata );
}

/**
 * Deliver formatted string
 *
 * @v intf		Data transfer interface
 * @v format		Format string
 * @v args		Arguments corresponding to the format string
 * @ret rc		Return status code
 */
int xfer_vprintf ( struct interface *intf, const char *format,
		   va_list args ) {
	va_list args_tmp;
	char *buf;
	int len;
	int rc;

	/* Create temporary string */
	va_copy ( args_tmp, args );
	len = vasprintf ( &buf, format, args );
	if ( len < 0 ) {
		rc = len;
		goto err_asprintf;
	}
	va_end ( args_tmp );

	/* Transmit string */
	if ( ( rc = xfer_deliver_raw ( intf, buf, len ) ) != 0 )
		goto err_deliver;

 err_deliver:
	free ( buf );
 err_asprintf:
	return rc;
}

/**
 * Deliver formatted string
 *
 * @v intf		Data transfer interface
 * @v format		Format string
 * @v ...		Arguments corresponding to the format string
 * @ret rc		Return status code
 */
int xfer_printf ( struct interface *intf, const char *format, ... ) {
	va_list args;
	int rc;

	va_start ( args, format );
	rc = xfer_vprintf ( intf, format, args );
	va_end ( args );
	return rc;
}

/**
 * Seek to position
 *
 * @v intf		Data transfer interface
 * @v offset		Offset to new position
 * @ret rc		Return status code
 */
int xfer_seek ( struct interface *intf, off_t offset ) {
	struct io_buffer *iobuf;
	struct xfer_metadata meta = {
		.flags = XFER_FL_ABS_OFFSET,
		.offset = offset,
	};

	DBGC ( INTF_COL ( intf ), "INTF " INTF_FMT " seek to %ld\n",
	       INTF_DBG ( intf ), offset );

	/* Allocate and send a zero-length data buffer */
	iobuf = xfer_alloc_iob ( intf, 0 );
	if ( ! iobuf )
		return -ENOMEM;

	return xfer_deliver ( intf, iobuf, &meta );
}

/**
 * Check that data is delivered strictly in order
 *
 * @v meta		Data transfer metadata
 * @v pos		Current position
 * @v len		Length of data
 * @ret rc		Return status code
 */
int xfer_check_order ( struct xfer_metadata *meta, size_t *pos, size_t len ) {
	size_t new_pos;

	/* Allow out-of-order zero-length packets (as used by xfer_seek()) */
	if ( len == 0 )
		return 0;

	/* Calculate position of this delivery */
	new_pos = *pos;
	if ( meta->flags & XFER_FL_ABS_OFFSET )
		new_pos = 0;
	new_pos += meta->offset;

	/* Fail if delivery position is not equal to current position */
	if ( new_pos != *pos )
		return -EPROTO;

	/* Update current position */
	*pos += len;

	return 0;
}
