/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
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

/**
 * @file
 *
 * Block device translator
 *
 */

#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/blockdev.h>
#include <ipxe/blocktrans.h>

/**
 * Reallocate block device translator data buffer
 *
 * @v xferbuf		Data transfer buffer
 * @v len		New length (or zero to free buffer)
 * @ret rc		Return status code
 */
static int blktrans_xferbuf_realloc ( struct xfer_buffer *xferbuf,
				      size_t len ) {
	struct block_translator *blktrans =
		container_of ( xferbuf, struct block_translator, xferbuf );

	/* Record length, if applicable */
	if ( blktrans->buffer ) {

		/* We have a (non-reallocatable) data buffer */
		return -ENOTSUP;

	} else {

		/* Record length (for block device capacity) */
		xferbuf->len = len;
		return 0;
	}
}

/**
 * Write data to block device translator data buffer
 *
 * @v xferbuf		Data transfer buffer
 * @v offset		Starting offset
 * @v data		Data to copy
 * @v len		Length of data
 */
static void blktrans_xferbuf_write ( struct xfer_buffer *xferbuf, size_t offset,
				     const void *data, size_t len ) {
	struct block_translator *blktrans =
		container_of ( xferbuf, struct block_translator, xferbuf );

	/* Write data to buffer, if applicable */
	if ( blktrans->buffer ) {

		/* Write data to buffer */
		copy_to_user ( blktrans->buffer, offset, data, len );

	} else {

		/* Sanity check */
		assert ( len == 0 );
	}
}

/**
 * Read data from block device translator data buffer
 *
 * @v xferbuf		Data transfer buffer
 * @v offset		Starting offset
 * @v data		Data to read
 * @v len		Length of data
 */
static void blktrans_xferbuf_read ( struct xfer_buffer *xferbuf, size_t offset,
				    void *data, size_t len ) {
	struct block_translator *blktrans =
		container_of ( xferbuf, struct block_translator, xferbuf );

	/* Read data from buffer, if applicable */
	if ( blktrans->buffer ) {

		/* Read data from buffer */
		copy_from_user ( data, blktrans->buffer, offset, len );

	} else {

		/* Sanity check */
		assert ( len == 0 );
	}
}

/** Block device translator data transfer buffer operations */
static struct xfer_buffer_operations blktrans_xferbuf_operations = {
	.realloc = blktrans_xferbuf_realloc,
	.write = blktrans_xferbuf_write,
	.read = blktrans_xferbuf_read,
};

/**
 * Close block device translator
 *
 * @v blktrans		Block device translator
 * @v rc		Reason for close
 */
static void blktrans_close ( struct block_translator *blktrans, int rc ) {
	struct block_device_capacity capacity;

	/* Report block device capacity, if applicable */
	if ( ( rc == 0 ) && ( blktrans->blksize ) ) {

		/* Construct block device capacity */
		capacity.blocks =
			( blktrans->xferbuf.len / blktrans->blksize );
		capacity.blksize = blktrans->blksize;
		capacity.max_count = -1U;

		/* Report block device capacity */
		block_capacity ( &blktrans->block, &capacity );
	}

	/* Shut down interfaces */
	intf_shutdown ( &blktrans->xfer, rc );
	intf_shutdown ( &blktrans->block, rc );
}

/**
 * Deliver data
 *
 * @v blktrans		Block device translator
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int blktrans_deliver ( struct block_translator *blktrans,
			      struct io_buffer *iobuf,
			      struct xfer_metadata *meta ) {
	int rc;

	/* Deliver to buffer */
	if ( ( rc = xferbuf_deliver ( &blktrans->xferbuf, iob_disown ( iobuf ),
				      meta ) ) != 0 ) {
		DBGC ( blktrans, "BLKTRANS %p could not deliver: %s\n",
		       blktrans, strerror ( rc ) );
		goto err;
	}

	return 0;

 err:
	blktrans_close ( blktrans, rc );
	return rc;
}

/**
 * Get underlying data transfer buffer
 *
 * @v blktrans		Block device translator
 * @ret xferbuf		Data transfer buffer
 */
static struct xfer_buffer *
blktrans_buffer ( struct block_translator *blktrans ) {

	return &blktrans->xferbuf;
}

/** Block device translator block device interface operations */
static struct interface_operation blktrans_block_operations[] = {
	INTF_OP ( intf_close, struct block_translator *, blktrans_close ),
};

/** Block device translator block device interface descriptor */
static struct interface_descriptor blktrans_block_desc =
	INTF_DESC_PASSTHRU ( struct block_translator, block,
			     blktrans_block_operations, xfer );

/** Block device translator data transfer interface operations */
static struct interface_operation blktrans_xfer_operations[] = {
	INTF_OP ( xfer_deliver, struct block_translator *, blktrans_deliver ),
	INTF_OP ( xfer_buffer, struct block_translator *, blktrans_buffer ),
	INTF_OP ( intf_close, struct block_translator *, blktrans_close ),
};

/** Block device translator data transfer interface descriptor */
static struct interface_descriptor blktrans_xfer_desc =
	INTF_DESC_PASSTHRU ( struct block_translator, xfer,
			     blktrans_xfer_operations, block );

/**
 * Insert block device translator
 *
 * @v block		Block device interface
 * @v buffer		Data buffer (or UNULL)
 * @v size		Length of data buffer, or block size
 * @ret rc		Return status code
 */
int block_translate ( struct interface *block, userptr_t buffer, size_t size ) {
	struct block_translator *blktrans;
	int rc;

	/* Allocate and initialise structure */
	blktrans = zalloc ( sizeof ( *blktrans ) );
	if ( ! blktrans ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	ref_init ( &blktrans->refcnt, NULL );
	intf_init ( &blktrans->block, &blktrans_block_desc, &blktrans->refcnt );
	intf_init ( &blktrans->xfer, &blktrans_xfer_desc, &blktrans->refcnt );
	blktrans->xferbuf.op = &blktrans_xferbuf_operations;
	blktrans->buffer = buffer;
	if ( buffer ) {
		blktrans->xferbuf.len = size;
	} else {
		blktrans->blksize = size;
	}

	/* Attach to interfaces, mortalise self, and return */
	assert ( block->dest != &null_intf );
	intf_plug_plug ( &blktrans->xfer, block->dest );
	intf_plug_plug ( &blktrans->block, block );
	ref_put ( &blktrans->refcnt );

	DBGC2 ( blktrans, "BLKTRANS %p created", blktrans );
	if ( buffer ) {
		DBGC2 ( blktrans, " for %#lx+%#zx",
			user_to_phys ( buffer, 0 ), size );
	}
	DBGC2 ( blktrans, "\n" );
	return 0;

	ref_put ( &blktrans->refcnt );
 err_alloc:
	return rc;
}
