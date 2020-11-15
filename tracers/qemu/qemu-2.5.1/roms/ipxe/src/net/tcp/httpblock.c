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
 * Hyper Text Transfer Protocol (HTTP) block device
 *
 */

#include <stdint.h>
#include <ipxe/uaccess.h>
#include <ipxe/blocktrans.h>
#include <ipxe/blockdev.h>
#include <ipxe/acpi.h>
#include <ipxe/http.h>

/** Block size used for HTTP block device requests */
#define HTTP_BLKSIZE 512

/**
 * Read from block device
 *
 * @v http		HTTP transaction
 * @v data		Data interface
 * @v lba		Starting logical block address
 * @v count		Number of logical blocks
 * @v buffer		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
int http_block_read ( struct http_transaction *http, struct interface *data,
		      uint64_t lba, unsigned int count, userptr_t buffer,
		      size_t len ) {
	struct http_request_range range;
	int rc;

	/* Sanity check */
	assert ( len == ( count * HTTP_BLKSIZE ) );

	/* Construct request range descriptor */
	range.start = ( lba * HTTP_BLKSIZE );
	range.len = len;

	/* Start a range request to retrieve the block(s) */
	if ( ( rc = http_open ( data, &http_get, http->uri, &range,
				NULL ) ) != 0 )
		goto err_open;

	/* Insert block device translator */
	if ( ( rc = block_translate ( data, buffer, len ) ) != 0 ) {
		DBGC ( http, "HTTP %p could not insert block translator: %s\n",
		       http, strerror ( rc ) );
		goto err_translate;
	}

	return 0;

 err_translate:
	intf_restart ( data, rc );
 err_open:
	return rc;
}

/**
 * Read block device capacity
 *
 * @v control		Control interface
 * @v data		Data interface
 * @ret rc		Return status code
 */
int http_block_read_capacity ( struct http_transaction *http,
			       struct interface *data ) {
	int rc;

	/* Start a HEAD request to retrieve the capacity */
	if ( ( rc = http_open ( data, &http_head, http->uri, NULL,
				NULL ) ) != 0 )
		goto err_open;

	/* Insert block device translator */
	if ( ( rc = block_translate ( data, UNULL, HTTP_BLKSIZE ) ) != 0 ) {
		DBGC ( http, "HTTP %p could not insert block translator: %s\n",
		       http, strerror ( rc ) );
		goto err_translate;
	}

	return 0;

 err_translate:
	intf_restart ( data, rc );
 err_open:
	return rc;
}

/**
 * Describe device in ACPI table
 *
 * @v http		HTTP transaction
 * @v acpi		ACPI table
 * @v len		Length of ACPI table
 * @ret rc		Return status code
 */
int http_acpi_describe ( struct http_transaction *http,
			 struct acpi_description_header *acpi, size_t len ) {

	DBGC ( http, "HTTP %p cannot yet describe device in an ACPI table\n",
	       http );
	( void ) acpi;
	( void ) len;
	return 0;
}
