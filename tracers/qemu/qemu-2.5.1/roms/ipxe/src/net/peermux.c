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
#include <errno.h>
#include <ipxe/uri.h>
#include <ipxe/xferbuf.h>
#include <ipxe/peerblk.h>
#include <ipxe/peermux.h>

/** @file
 *
 * Peer Content Caching and Retrieval (PeerDist) protocol multiplexer
 *
 */

/**
 * Free PeerDist download multiplexer
 *
 * @v refcnt		Reference count
 */
static void peermux_free ( struct refcnt *refcnt ) {
	struct peerdist_multiplexer *peermux =
		container_of ( refcnt, struct peerdist_multiplexer, refcnt );

	uri_put ( peermux->uri );
	xferbuf_free ( &peermux->buffer );
	free ( peermux );
}

/**
 * Close PeerDist download multiplexer
 *
 * @v peermux		PeerDist download multiplexer
 * @v rc		Reason for close
 */
static void peermux_close ( struct peerdist_multiplexer *peermux, int rc ) {
	unsigned int i;

	/* Stop block download initiation process */
	process_del ( &peermux->process );

	/* Shut down all block downloads */
	for ( i = 0 ; i < PEERMUX_MAX_BLOCKS ; i++ )
		intf_shutdown ( &peermux->block[i].xfer, rc );

	/* Shut down all other interfaces (which may be connected to
	 * the same object).
	 */
	intf_nullify ( &peermux->info ); /* avoid potential loops */
	intf_shutdown ( &peermux->xfer, rc );
	intf_shutdown ( &peermux->info, rc );
}

/**
 * Receive content information
 *
 * @v peermux		PeerDist download multiplexer
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int peermux_info_deliver ( struct peerdist_multiplexer *peermux,
				  struct io_buffer *iobuf,
				  struct xfer_metadata *meta ) {
	int rc;

	/* Add data to buffer */
	if ( ( rc = xferbuf_deliver ( &peermux->buffer, iobuf, meta ) ) != 0 )
		goto err;

	return 0;

 err:
	peermux_close ( peermux, rc );
	return rc;
}

/**
 * Close content information interface
 *
 * @v peermux		PeerDist download multiplexer
 * @v rc		Reason for close
 */
static void peermux_info_close ( struct peerdist_multiplexer *peermux, int rc ){
	struct peerdist_info *info = &peermux->cache.info;
	size_t len;

	/* Terminate download on error */
	if ( rc != 0 )
		goto err;

	/* Successfully closing the content information interface
	 * indicates that the content information has been fully
	 * received, and initiates the actual PeerDist download.
	 */

	/* Shut down content information interface */
	intf_shutdown ( &peermux->info, rc );

	/* Parse content information */
	if ( ( rc = peerdist_info ( info->raw.data, peermux->buffer.len,
				    info ) ) != 0 ) {
		DBGC ( peermux, "PEERMUX %p could not parse content info: %s\n",
		       peermux, strerror ( rc ) );
		goto err;
	}

	/* Notify recipient of total download size */
	len = ( info->trim.end - info->trim.start );
	if ( ( rc = xfer_seek ( &peermux->xfer, len ) ) != 0 ) {
		DBGC ( peermux, "PEERMUX %p could not presize buffer: %s\n",
		       peermux, strerror ( rc ) );
		goto err;
	}
	xfer_seek ( &peermux->xfer, 0 );

	/* Start block download process */
	process_add ( &peermux->process );

	return;

 err:
	peermux_close ( peermux, rc );
}

/**
 * Initiate multiplexed block download
 *
 * @v peermux		PeerDist download multiplexer
 */
static void peermux_step ( struct peerdist_multiplexer *peermux ) {
	struct peerdist_info *info = &peermux->cache.info;
	struct peerdist_info_segment *segment = &peermux->cache.segment;
	struct peerdist_info_block *block = &peermux->cache.block;
	struct peerdist_multiplexed_block *peermblk;
	unsigned int next_segment;
	unsigned int next_block;
	int rc;

	/* Stop initiation process if all block downloads are busy */
	peermblk = list_first_entry ( &peermux->idle,
				      struct peerdist_multiplexed_block, list );
	if ( ! peermblk ) {
		process_del ( &peermux->process );
		return;
	}

	/* Increment block index */
	next_block = ( block->index + 1 );

	/* Move to first/next segment, if applicable */
	if ( next_block >= segment->blocks ) {

		/* Reset block index */
		next_block = 0;

		/* Calculate segment index */
		next_segment = ( segment->info ? ( segment->index + 1 ) : 0 );

		/* If we have finished all segments and have no
		 * remaining block downloads, then we are finished.
		 */
		if ( next_segment >= info->segments ) {
			process_del ( &peermux->process );
			if ( list_empty ( &peermux->busy ) )
				peermux_close ( peermux, 0 );
			return;
		}

		/* Get content information segment */
		if ( ( rc = peerdist_info_segment ( info, segment,
						    next_segment ) ) != 0 ) {
			DBGC ( peermux, "PEERMUX %p could not get segment %d "
			       "information: %s\n", peermux, next_segment,
			       strerror ( rc ) );
			goto err;
		}
	}

	/* Get content information block */
	if ( ( rc = peerdist_info_block ( segment, block, next_block ) ) != 0 ){
		DBGC ( peermux, "PEERMUX %p could not get segment %d block "
		       "%d information: %s\n", peermux, segment->index,
		       next_block, strerror ( rc ) );
		goto err;
	}

	/* Ignore block if it lies entirely outside the trimmed range */
	if ( block->trim.start == block->trim.end ) {
		DBGC ( peermux, "PEERMUX %p skipping segment %d block %d\n",
		       peermux, segment->index, block->index );
		return;
	}

	/* Start downloading this block */
	if ( ( rc = peerblk_open ( &peermblk->xfer, peermux->uri,
				   block ) ) != 0 ) {
		DBGC ( peermux, "PEERMUX %p could not start download for "
		       "segment %d block %d: %s\n", peermux, segment->index,
		       block->index, strerror ( rc ) );
		goto err;
	}

	/* Move to list of busy block downloads */
	list_del ( &peermblk->list );
	list_add_tail ( &peermblk->list, &peermux->busy );

	return;

 err:
	peermux_close ( peermux, rc );
}

/**
 * Receive data from multiplexed block download
 *
 * @v peermblk		PeerDist multiplexed block download
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int peermux_block_deliver ( struct peerdist_multiplexed_block *peermblk,
				   struct io_buffer *iobuf,
				   struct xfer_metadata *meta ) {
	struct peerdist_multiplexer *peermux = peermblk->peermux;

	/* Sanity check: all block downloads must use absolute
	 * positions for all deliveries, since they run concurrently.
	 */
	assert ( meta->flags & XFER_FL_ABS_OFFSET );

	/* We can't use a simple passthrough interface descriptor,
	 * since there are multiple block download interfaces.
	 */
	return xfer_deliver ( &peermux->xfer, iob_disown ( iobuf ), meta );
}

/**
 * Get multiplexed block download underlying data transfer buffer
 *
 * @v peermblk		PeerDist multiplexed download block
 * @ret xferbuf		Data transfer buffer, or NULL on error
 */
static struct xfer_buffer *
peermux_block_buffer ( struct peerdist_multiplexed_block *peermblk ) {
	struct peerdist_multiplexer *peermux = peermblk->peermux;

	/* We can't use a simple passthrough interface descriptor,
	 * since there are multiple block download interfaces.
	 */
	return xfer_buffer ( &peermux->xfer );
}

/**
 * Close multiplexed block download
 *
 * @v peermblk		PeerDist multiplexed block download
 * @v rc		Reason for close
 */
static void peermux_block_close ( struct peerdist_multiplexed_block *peermblk,
				  int rc ) {
	struct peerdist_multiplexer *peermux = peermblk->peermux;

	/* Move to list of idle downloads */
	list_del ( &peermblk->list );
	list_add_tail ( &peermblk->list, &peermux->idle );

	/* If any error occurred, terminate the whole multiplexer */
	if ( rc != 0 ) {
		peermux_close ( peermux, rc );
		return;
	}

	/* Restart data transfer interface */
	intf_restart ( &peermblk->xfer, rc );

	/* Restart block download initiation process */
	process_add ( &peermux->process );
}

/** Data transfer interface operations */
static struct interface_operation peermux_xfer_operations[] = {
	INTF_OP ( intf_close, struct peerdist_multiplexer *, peermux_close ),
};

/** Data transfer interface descriptor */
static struct interface_descriptor peermux_xfer_desc =
	INTF_DESC_PASSTHRU ( struct peerdist_multiplexer, xfer,
			     peermux_xfer_operations, info );

/** Content information interface operations */
static struct interface_operation peermux_info_operations[] = {
	INTF_OP ( xfer_deliver, struct peerdist_multiplexer *,
		  peermux_info_deliver ),
	INTF_OP ( intf_close, struct peerdist_multiplexer *,
		  peermux_info_close ),
};

/** Content information interface descriptor */
static struct interface_descriptor peermux_info_desc =
	INTF_DESC_PASSTHRU ( struct peerdist_multiplexer, info,
			     peermux_info_operations, xfer );

/** Block download data transfer interface operations */
static struct interface_operation peermux_block_operations[] = {
	INTF_OP ( xfer_deliver, struct peerdist_multiplexed_block *,
		  peermux_block_deliver ),
	INTF_OP ( xfer_buffer, struct peerdist_multiplexed_block *,
		  peermux_block_buffer ),
	INTF_OP ( intf_close, struct peerdist_multiplexed_block *,
		  peermux_block_close ),
};

/** Block download data transfer interface descriptor */
static struct interface_descriptor peermux_block_desc =
	INTF_DESC ( struct peerdist_multiplexed_block, xfer,
		    peermux_block_operations );

/** Block download initiation process descriptor */
static struct process_descriptor peermux_process_desc =
	PROC_DESC ( struct peerdist_multiplexer, process, peermux_step );

/**
 * Add PeerDist content-encoding filter
 *
 * @v xfer		Data transfer interface
 * @v info		Content information interface
 * @v uri		Original URI
 * @ret rc		Return status code
 */
int peermux_filter ( struct interface *xfer, struct interface *info,
		     struct uri *uri ) {
	struct peerdist_multiplexer *peermux;
	struct peerdist_multiplexed_block *peermblk;
	unsigned int i;

	/* Allocate and initialise structure */
	peermux = zalloc ( sizeof ( *peermux ) );
	if ( ! peermux )
		return -ENOMEM;
	ref_init ( &peermux->refcnt, peermux_free );
	intf_init ( &peermux->xfer, &peermux_xfer_desc, &peermux->refcnt );
	intf_init ( &peermux->info, &peermux_info_desc, &peermux->refcnt );
	peermux->uri = uri_get ( uri );
	xferbuf_umalloc_init ( &peermux->buffer,
			       &peermux->cache.info.raw.data );
	process_init_stopped ( &peermux->process, &peermux_process_desc,
			       &peermux->refcnt );
	INIT_LIST_HEAD ( &peermux->busy );
	INIT_LIST_HEAD ( &peermux->idle );
	for ( i = 0 ; i < PEERMUX_MAX_BLOCKS ; i++ ) {
		peermblk = &peermux->block[i];
		peermblk->peermux = peermux;
		list_add_tail ( &peermblk->list, &peermux->idle );
		intf_init ( &peermblk->xfer, &peermux_block_desc,
			    &peermux->refcnt );
	}

	/* Attach to parent interfaces, mortalise self, and return */
	intf_plug_plug ( &peermux->xfer, xfer );
	intf_plug_plug ( &peermux->info, info );
	ref_put ( &peermux->refcnt );
	return 0;
}
