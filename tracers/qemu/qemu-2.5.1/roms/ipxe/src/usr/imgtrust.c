/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <time.h>
#include <syslog.h>
#include <ipxe/uaccess.h>
#include <ipxe/image.h>
#include <ipxe/cms.h>
#include <ipxe/validator.h>
#include <ipxe/monojob.h>
#include <usr/imgtrust.h>

/** @file
 *
 * Image trust management
 *
 */

/**
 * Verify image using downloaded signature
 *
 * @v image		Image to verify
 * @v signature		Image containing signature
 * @v name		Required common name, or NULL to allow any name
 * @ret rc		Return status code
 */
int imgverify ( struct image *image, struct image *signature,
		const char *name ) {
	size_t len;
	void *data;
	struct cms_signature *sig;
	struct cms_signer_info *info;
	time_t now;
	int rc;

	/* Mark image as untrusted */
	image_untrust ( image );

	/* Copy signature to internal memory */
	len = signature->len;
	data = malloc ( len );
	if ( ! data ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	copy_from_user ( data, signature->data, 0, len );

	/* Parse signature */
	if ( ( rc = cms_signature ( data, len, &sig ) ) != 0 )
		goto err_parse;

	/* Free internal copy of signature */
	free ( data );
	data = NULL;

	/* Complete all certificate chains */
	list_for_each_entry ( info, &sig->info, list ) {
		if ( ( rc = create_validator ( &monojob, info->chain ) ) != 0 )
			goto err_create_validator;
		if ( ( rc = monojob_wait ( NULL, 0 ) ) != 0 )
			goto err_validator_wait;
	}

	/* Use signature to verify image */
	now = time ( NULL );
	if ( ( rc = cms_verify ( sig, image->data, image->len,
				 name, now, NULL, NULL ) ) != 0 )
		goto err_verify;

	/* Drop reference to signature */
	cms_put ( sig );
	sig = NULL;

	/* Mark image as trusted */
	image_trust ( image );
	syslog ( LOG_NOTICE, "Image \"%s\" signature OK\n", image->name );

	return 0;

 err_verify:
 err_validator_wait:
 err_create_validator:
	cms_put ( sig );
 err_parse:
	free ( data );
 err_alloc:
	syslog ( LOG_ERR, "Image \"%s\" signature bad: %s\n",
		 image->name, strerror ( rc ) );
	return rc;
}
