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

/** @file
 *
 * Pixel buffer self-tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <assert.h>
#include <ipxe/image.h>
#include <ipxe/pixbuf.h>
#include <ipxe/test.h>
#include "pixbuf_test.h"

/**
 * Report pixel buffer test result
 *
 * @v test		Pixel buffer test
 * @v file		Test code file
 * @v line		Test code line
 */
void pixbuf_okx ( struct pixel_buffer_test *test, const char *file,
		  unsigned int line ) {
	struct pixel_buffer *pixbuf;
	int rc;

	/* Sanity check */
	assert ( ( test->width * test->height * sizeof ( test->data[0] ) )
		 == test->len );

	/* Correct image data pointer */
	test->image->data = virt_to_user ( ( void * ) test->image->data );

	/* Check that image is detected as correct type */
	okx ( register_image ( test->image ) == 0, file, line );
	okx ( test->image->type == test->type, file, line );

	/* Check that a pixel buffer can be created from the image */
	okx ( ( rc = image_pixbuf ( test->image, &pixbuf ) ) == 0, file, line );
	if ( rc == 0 ) {

		/* Check pixel buffer dimensions */
		okx ( pixbuf->width == test->width, file, line );
		okx ( pixbuf->height == test->height, file, line );

		/* Check pixel buffer data */
		okx ( pixbuf->len == test->len, file, line );
		okx ( memcmp_user ( pixbuf->data, 0,
				    virt_to_user ( test->data ), 0,
				    test->len ) == 0, file, line );

		pixbuf_put ( pixbuf );
	}

	/* Unregister image */
	unregister_image ( test->image );
}
