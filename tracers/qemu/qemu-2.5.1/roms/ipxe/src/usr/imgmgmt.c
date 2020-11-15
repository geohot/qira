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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ipxe/image.h>
#include <ipxe/downloader.h>
#include <ipxe/monojob.h>
#include <ipxe/open.h>
#include <ipxe/uri.h>
#include <usr/imgmgmt.h>

/** @file
 *
 * Image management
 *
 */

/**
 * Download a new image
 *
 * @v uri		URI
 * @v timeout		Download timeout
 * @v image		Image to fill in
 * @ret rc		Return status code
 */
int imgdownload ( struct uri *uri, unsigned long timeout,
		  struct image **image ) {
	const char *password;
	char *uri_string_redacted;
	int rc;

	/* Construct redacted URI */
	password = uri->password;
	if ( password )
		uri->password = "***";
	uri_string_redacted = format_uri_alloc ( uri );
	uri->password = password;
	if ( ! uri_string_redacted ) {
		rc = -ENOMEM;
		goto err_uri_string;
	}

	/* Resolve URI */
	uri = resolve_uri ( cwuri, uri );
	if ( ! uri ) {
		rc = -ENOMEM;
		goto err_resolve_uri;
	}

	/* Allocate image */
	*image = alloc_image ( uri );
	if ( ! *image ) {
		rc = -ENOMEM;
		goto err_alloc_image;
	}

	/* Create downloader */
	if ( ( rc = create_downloader ( &monojob, *image ) ) != 0 ) {
		printf ( "Could not start download: %s\n", strerror ( rc ) );
		goto err_create_downloader;
	}

	/* Wait for download to complete */
	if ( ( rc = monojob_wait ( uri_string_redacted, timeout ) ) != 0 )
		goto err_monojob_wait;

	/* Register image */
	if ( ( rc = register_image ( *image ) ) != 0 ) {
		printf ( "Could not register image: %s\n", strerror ( rc ) );
		goto err_register_image;
	}

 err_register_image:
 err_monojob_wait:
 err_create_downloader:
	image_put ( *image );
 err_alloc_image:
	uri_put ( uri );
 err_resolve_uri:
	free ( uri_string_redacted );
 err_uri_string:
	return rc;
}

/**
 * Download a new image
 *
 * @v uri_string	URI string
 * @v timeout		Download timeout
 * @v image		Image to fill in
 * @ret rc		Return status code
 */
int imgdownload_string ( const char *uri_string, unsigned long timeout,
			 struct image **image ) {
	struct uri *uri;
	int rc;

	if ( ! ( uri = parse_uri ( uri_string ) ) )
		return -ENOMEM;

	rc = imgdownload ( uri, timeout, image );

	uri_put ( uri );
	return rc;
}

/**
 * Acquire an image
 *
 * @v name_uri		Name or URI string
 * @v timeout		Download timeout
 * @v image		Image to fill in
 * @ret rc		Return status code
 */
int imgacquire ( const char *name_uri, unsigned long timeout,
		 struct image **image ) {

	/* If we already have an image with the specified name, use it */
	*image = find_image ( name_uri );
	if ( *image )
		return 0;

	/* Otherwise, download a new image */
	return imgdownload_string ( name_uri, timeout, image );
}

/**
 * Display status of an image
 *
 * @v image		Executable/loadable image
 */
void imgstat ( struct image *image ) {
	printf ( "%s : %zd bytes", image->name, image->len );
	if ( image->type )
		printf ( " [%s]", image->type->name );
	if ( image->flags & IMAGE_TRUSTED )
		printf ( " [TRUSTED]" );
	if ( image->flags & IMAGE_SELECTED )
		printf ( " [SELECTED]" );
	if ( image->flags & IMAGE_AUTO_UNREGISTER )
		printf ( " [AUTOFREE]" );
	if ( image->cmdline )
		printf ( " \"%s\"", image->cmdline );
	printf ( "\n" );
}
