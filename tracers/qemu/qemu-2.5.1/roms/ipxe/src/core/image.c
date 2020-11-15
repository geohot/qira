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

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <syslog.h>
#include <ipxe/list.h>
#include <ipxe/umalloc.h>
#include <ipxe/uri.h>
#include <ipxe/image.h>

/** @file
 *
 * Executable images
 *
 */

/* Disambiguate the various error causes */
#define EACCES_UNTRUSTED \
	__einfo_error ( EINFO_EACCES_UNTRUSTED )
#define EINFO_EACCES_UNTRUSTED \
	__einfo_uniqify ( EINFO_EACCES, 0x01, "Untrusted image" )
#define EACCES_PERMANENT \
	__einfo_error ( EINFO_EACCES_PERMANENT )
#define EINFO_EACCES_PERMANENT \
	__einfo_uniqify ( EINFO_EACCES, 0x02, "Trust requirement is permanent" )

/** List of registered images */
struct list_head images = LIST_HEAD_INIT ( images );

/** Currently-executing image */
struct image *current_image;

/** Current image trust requirement */
static int require_trusted_images = 0;

/** Prevent changes to image trust requirement */
static int require_trusted_images_permanent = 0;

/**
 * Free executable image
 *
 * @v refcnt		Reference counter
 */
static void free_image ( struct refcnt *refcnt ) {
	struct image *image = container_of ( refcnt, struct image, refcnt );

	DBGC ( image, "IMAGE %s freed\n", image->name );
	free ( image->name );
	free ( image->cmdline );
	uri_put ( image->uri );
	ufree ( image->data );
	image_put ( image->replacement );
	free ( image );
}

/**
 * Allocate executable image
 *
 * @v uri		URI, or NULL
 * @ret image		Executable image
 */
struct image * alloc_image ( struct uri *uri ) {
	const char *name;
	struct image *image;
	int rc;

	/* Allocate image */
	image = zalloc ( sizeof ( *image ) );
	if ( ! image )
		goto err_alloc;

	/* Initialise image */
	ref_init ( &image->refcnt, free_image );
	if ( uri ) {
		image->uri = uri_get ( uri );
		if ( uri->path ) {
			name = basename ( ( char * ) uri->path );
			if ( ( rc = image_set_name ( image, name ) ) != 0 )
				goto err_set_name;
		}
	}

	return image;

 err_set_name:
	image_put ( image );
 err_alloc:
	return NULL;
}

/**
 * Set image name
 *
 * @v image		Image
 * @v name		New image name
 * @ret rc		Return status code
 */
int image_set_name ( struct image *image, const char *name ) {
	char *name_copy;

	/* Duplicate name */
	name_copy = strdup ( name );
	if ( ! name_copy )
		return -ENOMEM;

	/* Replace existing name */
	free ( image->name );
	image->name = name_copy;

	return 0;
}

/**
 * Set image command line
 *
 * @v image		Image
 * @v cmdline		New image command line, or NULL
 * @ret rc		Return status code
 */
int image_set_cmdline ( struct image *image, const char *cmdline ) {

	free ( image->cmdline );
	image->cmdline = NULL;
	if ( cmdline ) {
		image->cmdline = strdup ( cmdline );
		if ( ! image->cmdline )
			return -ENOMEM;
	}
	return 0;
}

/**
 * Determine image type
 *
 * @v image		Executable image
 * @ret rc		Return status code
 */
static int image_probe ( struct image *image ) {
	struct image_type *type;
	int rc;

	/* Try each type in turn */
	for_each_table_entry ( type, IMAGE_TYPES ) {
		if ( ( rc = type->probe ( image ) ) == 0 ) {
			image->type = type;
			DBGC ( image, "IMAGE %s is %s\n",
			       image->name, type->name );
			break;
		}
		DBGC ( image, "IMAGE %s is not %s: %s\n", image->name,
		       type->name, strerror ( rc ) );
	}

	DBGC ( image, "IMAGE %s format not recognised\n", image->name );
	return -ENOTSUP;
}

/**
 * Register executable image
 *
 * @v image		Executable image
 * @ret rc		Return status code
 */
int register_image ( struct image *image ) {
	static unsigned int imgindex = 0;
	char name[8]; /* "imgXXXX" */
	int rc;

	/* Create image name if it doesn't already have one */
	if ( ! image->name ) {
		snprintf ( name, sizeof ( name ), "img%d", imgindex++ );
		if ( ( rc = image_set_name ( image, name ) ) != 0 )
			return rc;
	}

	/* Avoid ending up with multiple "selected" images on
	 * re-registration
	 */
	if ( image_find_selected() )
		image->flags &= ~IMAGE_SELECTED;

	/* Add to image list */
	image_get ( image );
	image->flags |= IMAGE_REGISTERED;
	list_add_tail ( &image->list, &images );
	DBGC ( image, "IMAGE %s at [%lx,%lx) registered\n",
	       image->name, user_to_phys ( image->data, 0 ),
	       user_to_phys ( image->data, image->len ) );

	/* Try to detect image type, if applicable.  Ignore failures,
	 * since we expect to handle some unrecognised images
	 * (e.g. kernel initrds, multiboot modules, random files
	 * provided via our EFI virtual filesystem, etc).
	 */
	if ( ! image->type )
		image_probe ( image );

	return 0;
}

/**
 * Unregister executable image
 *
 * @v image		Executable image
 */
void unregister_image ( struct image *image ) {

	/* Do nothing unless image is registered */
	if ( ! ( image->flags & IMAGE_REGISTERED ) )
		return;

	DBGC ( image, "IMAGE %s unregistered\n", image->name );
	list_del ( &image->list );
	image->flags &= ~IMAGE_REGISTERED;
	image_put ( image );
}

/**
 * Find image by name
 *
 * @v name		Image name
 * @ret image		Executable image, or NULL
 */
struct image * find_image ( const char *name ) {
	struct image *image;

	list_for_each_entry ( image, &images, list ) {
		if ( strcmp ( image->name, name ) == 0 )
			return image;
	}

	return NULL;
}

/**
 * Execute image
 *
 * @v image		Executable image
 * @ret rc		Return status code
 *
 * The image must already be registered.  Note that executing an image
 * may cause it to unregister itself.  The caller must therefore
 * assume that the image pointer becomes invalid.
 */
int image_exec ( struct image *image ) {
	struct image *saved_current_image;
	struct image *replacement = NULL;
	struct uri *old_cwuri;
	int rc;

	/* Sanity check */
	assert ( image->flags & IMAGE_REGISTERED );

	/* Switch current working directory to be that of the image itself */
	old_cwuri = uri_get ( cwuri );
	churi ( image->uri );

	/* Preserve record of any currently-running image */
	saved_current_image = current_image;

	/* Take out a temporary reference to the image.  This allows
	 * the image to unregister itself if necessary, without
	 * automatically freeing itself.
	 */
	current_image = image_get ( image );

	/* Check that this image can be executed */
	if ( ! ( image->type && image->type->exec ) ) {
		rc = -ENOEXEC;
		goto err;
	}

	/* Check that image is trusted (if applicable) */
	if ( require_trusted_images && ! ( image->flags & IMAGE_TRUSTED ) ) {
		DBGC ( image, "IMAGE %s is not trusted\n", image->name );
		rc = -EACCES_UNTRUSTED;
		goto err;
	}

	/* Record boot attempt */
	syslog ( LOG_NOTICE, "Executing \"%s\"\n", image->name );

	/* Try executing the image */
	if ( ( rc = image->type->exec ( image ) ) != 0 ) {
		DBGC ( image, "IMAGE %s could not execute: %s\n",
		       image->name, strerror ( rc ) );
		/* Do not return yet; we still have clean-up to do */
	}

	/* Record result of boot attempt */
	if ( rc == 0 ) {
		syslog ( LOG_NOTICE, "Execution of \"%s\" completed\n",
			 image->name );
	} else {
		syslog ( LOG_ERR, "Execution of \"%s\" failed: %s\n",
			 image->name, strerror ( rc ) );
	}

	/* Pick up replacement image before we drop the original
	 * image's temporary reference.  The replacement image must
	 * already be registered, so we don't need to hold a temporary
	 * reference (which would complicate the tail-recursion).
	 */
	replacement = image->replacement;
	if ( replacement )
		assert ( replacement->flags & IMAGE_REGISTERED );

 err:
	/* Unregister image if applicable */
	if ( image->flags & IMAGE_AUTO_UNREGISTER )
		unregister_image ( image );

	/* Debug message for tail-recursion.  Placed here because the
	 * image_put() may end up freeing the image.
	 */
	if ( replacement ) {
		DBGC ( image, "IMAGE %s replacing self with IMAGE %s\n",
		       image->name, replacement->name );
	}

	/* Drop temporary reference to the original image */
	image_put ( image );

	/* Restore previous currently-running image */
	current_image = saved_current_image;

	/* Reset current working directory */
	churi ( old_cwuri );
	uri_put ( old_cwuri );

	/* Tail-recurse into replacement image, if one exists */
	if ( replacement )
		return image_exec ( replacement );

	return rc;
}

/**
 * Set replacement image
 *
 * @v replacement	Replacement image
 * @ret rc		Return status code
 *
 * The replacement image must already be registered, and must remain
 * registered until the currently-executing image returns.
 */
int image_replace ( struct image *replacement ) {
	struct image *image = current_image;
	int rc;

	/* Sanity check */
	assert ( replacement->flags & IMAGE_REGISTERED );

	/* Fail unless there is a currently-executing image */
	if ( ! image ) {
		rc = -ENOTTY;
		DBGC ( replacement, "IMAGE %s cannot replace non-existent "
		       "image: %s\n", replacement->name, strerror ( rc ) );
		return rc;
	}

	/* Check that the replacement image can be executed */
	if ( ! ( replacement->type && replacement->type->exec ) )
		return -ENOEXEC;

	/* Clear any existing replacement */
	image_put ( image->replacement );

	/* Set replacement */
	image->replacement = image_get ( replacement );
	DBGC ( image, "IMAGE %s will replace self with IMAGE %s\n",
	       image->name, replacement->name );

	return 0;
}

/**
 * Select image for execution
 *
 * @v image		Executable image
 * @ret rc		Return status code
 */
int image_select ( struct image *image ) {
	struct image *tmp;

	/* Unselect all other images */
	for_each_image ( tmp )
		tmp->flags &= ~IMAGE_SELECTED;

	/* Check that this image can be executed */
	if ( ! ( image->type && image->type->exec ) )
		return -ENOEXEC;

	/* Mark image as selected */
	image->flags |= IMAGE_SELECTED;

	return 0;
}

/**
 * Find selected image
 *
 * @ret image		Executable image, or NULL
 */
struct image * image_find_selected ( void ) {
	struct image *image;

	for_each_image ( image ) {
		if ( image->flags & IMAGE_SELECTED )
			return image;
	}
	return NULL;
}

/**
 * Change image trust requirement
 *
 * @v require_trusted	Require trusted images
 * @v permanent		Make trust requirement permanent
 * @ret rc		Return status code
 */
int image_set_trust ( int require_trusted, int permanent ) {

	/* Update trust requirement, if permitted to do so */
	if ( ! require_trusted_images_permanent ) {
		require_trusted_images = require_trusted;
		require_trusted_images_permanent = permanent;
	}

	/* Fail if we attempted to change the trust requirement but
	 * were not permitted to do so.
	 */
	if ( require_trusted_images != require_trusted )
		return -EACCES_PERMANENT;

	return 0;
}

/**
 * Create pixel buffer from image
 *
 * @v image		Image
 * @v pixbuf		Pixel buffer to fill in
 * @ret rc		Return status code
 */
int image_pixbuf ( struct image *image, struct pixel_buffer **pixbuf ) {
	int rc;

	/* Check that this image can be used to create a pixel buffer */
	if ( ! ( image->type && image->type->pixbuf ) )
		return -ENOTSUP;

	/* Try creating pixel buffer */
	if ( ( rc = image->type->pixbuf ( image, pixbuf ) ) != 0 ) {
		DBGC ( image, "IMAGE %s could not create pixel buffer: %s\n",
		       image->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}
