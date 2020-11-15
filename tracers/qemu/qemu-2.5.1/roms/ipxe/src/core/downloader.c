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

#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/job.h>
#include <ipxe/uaccess.h>
#include <ipxe/umalloc.h>
#include <ipxe/image.h>
#include <ipxe/xferbuf.h>
#include <ipxe/downloader.h>

/** @file
 *
 * Image downloader
 *
 */

/** A downloader */
struct downloader {
	/** Reference count for this object */
	struct refcnt refcnt;

	/** Job control interface */
	struct interface job;
	/** Data transfer interface */
	struct interface xfer;

	/** Image to contain downloaded file */
	struct image *image;
	/** Data transfer buffer */
	struct xfer_buffer buffer;
};

/**
 * Free downloader object
 *
 * @v refcnt		Downloader reference counter
 */
static void downloader_free ( struct refcnt *refcnt ) {
	struct downloader *downloader =
		container_of ( refcnt, struct downloader, refcnt );

	image_put ( downloader->image );
	free ( downloader );
}

/**
 * Terminate download
 *
 * @v downloader	Downloader
 * @v rc		Reason for termination
 */
static void downloader_finished ( struct downloader *downloader, int rc ) {

	/* Log download status */
	if ( rc == 0 ) {
		syslog ( LOG_NOTICE, "Downloaded \"%s\"\n",
			 downloader->image->name );
	} else {
		syslog ( LOG_ERR, "Download of \"%s\" failed: %s\n",
			 downloader->image->name, strerror ( rc ) );
	}

	/* Update image length */
	downloader->image->len = downloader->buffer.len;

	/* Shut down interfaces */
	intf_shutdown ( &downloader->xfer, rc );
	intf_shutdown ( &downloader->job, rc );
}

/****************************************************************************
 *
 * Job control interface
 *
 */

/**
 * Report progress of download job
 *
 * @v downloader	Downloader
 * @v progress		Progress report to fill in
 * @ret ongoing_rc	Ongoing job status code (if known)
 */
static int downloader_progress ( struct downloader *downloader,
				 struct job_progress *progress ) {

	/* This is not entirely accurate, since downloaded data may
	 * arrive out of order (e.g. with multicast protocols), but
	 * it's a reasonable first approximation.
	 */
	progress->completed = downloader->buffer.pos;
	progress->total = downloader->buffer.len;

	return 0;
}

/****************************************************************************
 *
 * Data transfer interface
 *
 */

/**
 * Handle received data
 *
 * @v downloader	Downloader
 * @v iobuf		Datagram I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 */
static int downloader_xfer_deliver ( struct downloader *downloader,
				     struct io_buffer *iobuf,
				     struct xfer_metadata *meta ) {
	int rc;

	/* Add data to buffer */
	if ( ( rc = xferbuf_deliver ( &downloader->buffer, iob_disown ( iobuf ),
				      meta ) ) != 0 )
		goto err_deliver;

	return 0;

 err_deliver:
	downloader_finished ( downloader, rc );
	return rc;
}

/**
 * Get underlying data transfer buffer
 *
 * @v downloader	Downloader
 * @ret xferbuf		Data transfer buffer, or NULL on error
 */
static struct xfer_buffer *
downloader_xfer_buffer ( struct downloader *downloader ) {

	/* Provide direct access to underlying data transfer buffer */
	return &downloader->buffer;
}

/** Downloader data transfer interface operations */
static struct interface_operation downloader_xfer_operations[] = {
	INTF_OP ( xfer_deliver, struct downloader *, downloader_xfer_deliver ),
	INTF_OP ( xfer_buffer, struct downloader *, downloader_xfer_buffer ),
	INTF_OP ( intf_close, struct downloader *, downloader_finished ),
};

/** Downloader data transfer interface descriptor */
static struct interface_descriptor downloader_xfer_desc =
	INTF_DESC ( struct downloader, xfer, downloader_xfer_operations );

/****************************************************************************
 *
 * Job control interface
 *
 */

/** Downloader job control interface operations */
static struct interface_operation downloader_job_op[] = {
	INTF_OP ( job_progress, struct downloader *, downloader_progress ),
	INTF_OP ( intf_close, struct downloader *, downloader_finished ),
};

/** Downloader job control interface descriptor */
static struct interface_descriptor downloader_job_desc =
	INTF_DESC ( struct downloader, job, downloader_job_op );

/****************************************************************************
 *
 * Instantiator
 *
 */

/**
 * Instantiate a downloader
 *
 * @v job		Job control interface
 * @v image		Image to fill with downloaded file
 * @ret rc		Return status code
 *
 * Instantiates a downloader object to download the content of the
 * specified image from its URI.
 */
int create_downloader ( struct interface *job, struct image *image ) {
	struct downloader *downloader;
	int rc;

	/* Allocate and initialise structure */
	downloader = zalloc ( sizeof ( *downloader ) );
	if ( ! downloader )
		return -ENOMEM;
	ref_init ( &downloader->refcnt, downloader_free );
	intf_init ( &downloader->job, &downloader_job_desc,
		    &downloader->refcnt );
	intf_init ( &downloader->xfer, &downloader_xfer_desc,
		    &downloader->refcnt );
	downloader->image = image_get ( image );
	xferbuf_umalloc_init ( &downloader->buffer, &image->data );

	/* Instantiate child objects and attach to our interfaces */
	if ( ( rc = xfer_open_uri ( &downloader->xfer, image->uri ) ) != 0 )
		goto err;

	/* Attach parent interface, mortalise self, and return */
	intf_plug_plug ( &downloader->job, job );
	ref_put ( &downloader->refcnt );
	return 0;

 err:
	downloader_finished ( downloader, rc );
	ref_put ( &downloader->refcnt );
	return rc;
}
