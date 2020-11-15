/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <errno.h>
#include <ipxe/xfer.h>
#include <ipxe/iobuf.h>
#include <ipxe/umalloc.h>
#include <ipxe/profile.h>
#include <ipxe/xferbuf.h>

/** @file
 *
 * Data transfer buffer
 *
 */

/** Data delivery profiler */
static struct profiler xferbuf_deliver_profiler __profiler =
	{ .name = "xferbuf.deliver" };

/** Data write profiler */
static struct profiler xferbuf_write_profiler __profiler =
	{ .name = "xferbuf.write" };

/** Data read profiler */
static struct profiler xferbuf_read_profiler __profiler =
	{ .name = "xferbuf.read" };

/**
 * Free data transfer buffer
 *
 * @v xferbuf		Data transfer buffer
 */
void xferbuf_free ( struct xfer_buffer *xferbuf ) {

	xferbuf->op->realloc ( xferbuf, 0 );
	xferbuf->len = 0;
	xferbuf->pos = 0;
}

/**
 * Ensure that data transfer buffer is large enough for the specified size
 *
 * @v xferbuf		Data transfer buffer
 * @v len		Required minimum size
 * @ret rc		Return status code
 */
static int xferbuf_ensure_size ( struct xfer_buffer *xferbuf, size_t len ) {
	int rc;

	/* If buffer is already large enough, do nothing */
	if ( len <= xferbuf->len )
		return 0;

	/* Extend buffer */
	if ( ( rc = xferbuf->op->realloc ( xferbuf, len ) ) != 0 ) {
		DBGC ( xferbuf, "XFERBUF %p could not extend buffer to "
		       "%zd bytes: %s\n", xferbuf, len, strerror ( rc ) );
		return rc;
	}
	xferbuf->len = len;

	return 0;
}

/**
 * Write to data transfer buffer
 *
 * @v xferbuf		Data transfer buffer
 * @v offset		Starting offset
 * @v data		Data to write
 * @v len		Length of data
 */
int xferbuf_write ( struct xfer_buffer *xferbuf, size_t offset,
		    const void *data, size_t len ) {
	size_t max_len;
	int rc;

	/* Check for overflow */
	max_len = ( offset + len );
	if ( max_len < offset )
		return -EOVERFLOW;

	/* Ensure buffer is large enough to contain this write */
	if ( ( rc = xferbuf_ensure_size ( xferbuf, max_len ) ) != 0 )
		return rc;

	/* Copy data to buffer */
	profile_start ( &xferbuf_write_profiler );
	xferbuf->op->write ( xferbuf, offset, data, len );
	profile_stop ( &xferbuf_write_profiler );

	return 0;
}

/**
 * Read from data transfer buffer
 *
 * @v xferbuf		Data transfer buffer
 * @v offset		Starting offset
 * @v data		Data to write
 * @v len		Length of data
 */
int xferbuf_read ( struct xfer_buffer *xferbuf, size_t offset,
		   void *data, size_t len ) {

	/* Check that read is within buffer range */
	if ( ( offset > xferbuf->len ) ||
	     ( len > ( xferbuf->len - offset ) ) )
		return -ENOENT;

	/* Copy data from buffer */
	profile_start ( &xferbuf_read_profiler );
	xferbuf->op->read ( xferbuf, offset, data, len );
	profile_stop ( &xferbuf_read_profiler );

	return 0;
}

/**
 * Add received data to data transfer buffer
 *
 * @v xferbuf		Data transfer buffer
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
int xferbuf_deliver ( struct xfer_buffer *xferbuf, struct io_buffer *iobuf,
		      struct xfer_metadata *meta ) {
	size_t len = iob_len ( iobuf );
	size_t pos;
	int rc;

	/* Start profiling */
	profile_start ( &xferbuf_deliver_profiler );

	/* Calculate new buffer position */
	pos = xferbuf->pos;
	if ( meta->flags & XFER_FL_ABS_OFFSET )
		pos = 0;
	pos += meta->offset;

	/* Write data to buffer */
	if ( ( rc = xferbuf_write ( xferbuf, pos, iobuf->data, len ) ) != 0 )
		goto done;

	/* Update current buffer position */
	xferbuf->pos = ( pos + len );

 done:
	free_iob ( iobuf );
	profile_stop ( &xferbuf_deliver_profiler );
	return rc;
}

/**
 * Reallocate malloc()-based data buffer
 *
 * @v xferbuf		Data transfer buffer
 * @v len		New length (or zero to free buffer)
 * @ret rc		Return status code
 */
static int xferbuf_malloc_realloc ( struct xfer_buffer *xferbuf, size_t len ) {
	void *new_data;

	new_data = realloc ( xferbuf->data, len );
	if ( ! new_data )
		return -ENOSPC;
	xferbuf->data = new_data;
	return 0;
}

/**
 * Write data to malloc()-based data buffer
 *
 * @v xferbuf		Data transfer buffer
 * @v offset		Starting offset
 * @v data		Data to copy
 * @v len		Length of data
 */
static void xferbuf_malloc_write ( struct xfer_buffer *xferbuf, size_t offset,
				   const void *data, size_t len ) {

	memcpy ( ( xferbuf->data + offset ), data, len );
}

/**
 * Read data from malloc()-based data buffer
 *
 * @v xferbuf		Data transfer buffer
 * @v offset		Starting offset
 * @v data		Data to read
 * @v len		Length of data
 */
static void xferbuf_malloc_read ( struct xfer_buffer *xferbuf, size_t offset,
				  void *data, size_t len ) {

	memcpy ( data, ( xferbuf->data + offset ), len );
}

/** malloc()-based data buffer operations */
struct xfer_buffer_operations xferbuf_malloc_operations = {
	.realloc = xferbuf_malloc_realloc,
	.write = xferbuf_malloc_write,
	.read = xferbuf_malloc_read,
};

/**
 * Reallocate umalloc()-based data buffer
 *
 * @v xferbuf		Data transfer buffer
 * @v len		New length (or zero to free buffer)
 * @ret rc		Return status code
 */
static int xferbuf_umalloc_realloc ( struct xfer_buffer *xferbuf, size_t len ) {
	userptr_t *udata = xferbuf->data;
	userptr_t new_udata;

	new_udata = urealloc ( *udata, len );
	if ( ! new_udata )
		return -ENOSPC;
	*udata = new_udata;
	return 0;
}

/**
 * Write data to umalloc()-based data buffer
 *
 * @v xferbuf		Data transfer buffer
 * @v offset		Starting offset
 * @v data		Data to copy
 * @v len		Length of data
 */
static void xferbuf_umalloc_write ( struct xfer_buffer *xferbuf, size_t offset,
				    const void *data, size_t len ) {
	userptr_t *udata = xferbuf->data;

	copy_to_user ( *udata, offset, data, len );
}

/**
 * Read data from umalloc()-based data buffer
 *
 * @v xferbuf		Data transfer buffer
 * @v offset		Starting offset
 * @v data		Data to read
 * @v len		Length of data
 */
static void xferbuf_umalloc_read ( struct xfer_buffer *xferbuf, size_t offset,
				   void *data, size_t len ) {
	userptr_t *udata = xferbuf->data;

	copy_from_user ( data, *udata, offset, len );
}

/** umalloc()-based data buffer operations */
struct xfer_buffer_operations xferbuf_umalloc_operations = {
	.realloc = xferbuf_umalloc_realloc,
	.write = xferbuf_umalloc_write,
	.read = xferbuf_umalloc_read,
};

/**
 * Get underlying data transfer buffer
 *
 * @v interface		Data transfer interface
 * @ret xferbuf		Data transfer buffer, or NULL on error
 *
 * This call will check that the xfer_buffer() handler belongs to the
 * destination interface which also provides xfer_deliver() for this
 * interface.
 *
 * This is done to prevent accidental accesses to a data transfer
 * buffer which may be located behind a non-transparent datapath via a
 * series of pass-through interfaces.
 */
struct xfer_buffer * xfer_buffer ( struct interface *intf ) {
	struct interface *dest;
	xfer_buffer_TYPE ( void * ) *op =
		intf_get_dest_op ( intf, xfer_buffer, &dest );
	void *object = intf_object ( dest );
	struct interface *xfer_deliver_dest;
	struct xfer_buffer *xferbuf;

	/* Check that this operation is provided by the same interface
	 * which handles xfer_deliver().
	 */
	( void ) intf_get_dest_op ( intf, xfer_deliver, &xfer_deliver_dest );

	if ( op && ( dest == xfer_deliver_dest ) ) {
		xferbuf = op ( object );
	} else {
		/* Default is to not have a data transfer buffer */
		xferbuf = NULL;
	}

	intf_put ( xfer_deliver_dest );
	intf_put ( dest );
	return xferbuf;
}
