#ifndef _IPXE_IMAGE_H
#define _IPXE_IMAGE_H

/**
 * @file
 *
 * Executable images
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/tables.h>
#include <ipxe/list.h>
#include <ipxe/uaccess.h>
#include <ipxe/refcnt.h>

struct uri;
struct pixel_buffer;
struct image_type;

/** An executable image */
struct image {
	/** Reference count */
	struct refcnt refcnt;

	/** List of registered images */
	struct list_head list;

	/** URI of image */
	struct uri *uri;
	/** Name */
	char *name;
	/** Flags */
	unsigned int flags;

	/** Command line to pass to image */
	char *cmdline;
	/** Raw file image */
	userptr_t data;
	/** Length of raw file image */
	size_t len;

	/** Image type, if known */
	struct image_type *type;

	/** Replacement image
	 *
	 * An image wishing to replace itself with another image (in a
	 * style similar to a Unix exec() call) should return from its
	 * exec() method with the replacement image set to point to
	 * the new image.
	 *
	 * If an image unregisters itself as a result of being
	 * executed, it must make sure that its replacement image (if
	 * any) is registered, otherwise the replacement is likely to
	 * be freed before it can be executed.
	 */
	struct image *replacement;
};

/** Image is registered */
#define IMAGE_REGISTERED 0x00001

/** Image is selected for execution */
#define IMAGE_SELECTED 0x0002

/** Image is trusted */
#define IMAGE_TRUSTED 0x0004

/** Image will be automatically unregistered after execution */
#define IMAGE_AUTO_UNREGISTER 0x0008

/** An executable image type */
struct image_type {
	/** Name of this image type */
	char *name;
	/**
	 * Probe image
	 *
	 * @v image		Image
	 * @ret rc		Return status code
	 *
	 * Return success if the image is of this image type.
	 */
	int ( * probe ) ( struct image *image );
	/**
	 * Execute image
	 *
	 * @v image		Image
	 * @ret rc		Return status code
	 */
	int ( * exec ) ( struct image *image );
	/**
	 * Create pixel buffer from image
	 *
	 * @v image		Image
	 * @v pixbuf		Pixel buffer to fill in
	 * @ret rc		Return status code
	 */
	int ( * pixbuf ) ( struct image *image, struct pixel_buffer **pixbuf );
};

/**
 * Multiboot image probe priority
 *
 * Multiboot images are also valid executables in another format
 * (e.g. ELF), so we must perform the multiboot probe first.
 */
#define PROBE_MULTIBOOT	01

/**
 * Normal image probe priority
 */
#define PROBE_NORMAL 02

/**
 * PXE image probe priority
 *
 * PXE images have no signature checks, so will claim all image files.
 * They must therefore be tried last in the probe order list.
 */
#define PROBE_PXE 03

/** Executable image type table */
#define IMAGE_TYPES __table ( struct image_type, "image_types" )

/** An executable image type */
#define __image_type( probe_order ) __table_entry ( IMAGE_TYPES, probe_order )

extern struct list_head images;
extern struct image *current_image;

/** Iterate over all registered images */
#define for_each_image( image ) \
	list_for_each_entry ( (image), &images, list )

/** Iterate over all registered images, safe against deletion */
#define for_each_image_safe( image, tmp ) \
	list_for_each_entry_safe ( (image), (tmp), &images, list )

/**
 * Test for existence of images
 *
 * @ret existence	Some images exist
 */
static inline int have_images ( void ) {
	return ( ! list_empty ( &images ) );
}

/**
 * Retrieve first image
 *
 * @ret image		Image, or NULL
 */
static inline struct image * first_image ( void ) {
	return list_first_entry ( &images, struct image, list );
}

extern struct image * alloc_image ( struct uri *uri );
extern int image_set_name ( struct image *image, const char *name );
extern int image_set_cmdline ( struct image *image, const char *cmdline );
extern int register_image ( struct image *image );
extern void unregister_image ( struct image *image );
struct image * find_image ( const char *name );
extern int image_exec ( struct image *image );
extern int image_replace ( struct image *replacement );
extern int image_select ( struct image *image );
extern struct image * image_find_selected ( void );
extern int image_set_trust ( int require_trusted, int permanent );
extern int image_pixbuf ( struct image *image, struct pixel_buffer **pixbuf );

/**
 * Increment reference count on an image
 *
 * @v image		Image
 * @ret image		Image
 */
static inline struct image * image_get ( struct image *image ) {
	ref_get ( &image->refcnt );
	return image;
}

/**
 * Decrement reference count on an image
 *
 * @v image		Image
 */
static inline void image_put ( struct image *image ) {
	ref_put ( &image->refcnt );
}

/**
 * Clear image command line
 *
 * @v image		Image
 */
static inline void image_clear_cmdline ( struct image *image ) {
	image_set_cmdline ( image, NULL );
}

/**
 * Set image as trusted
 *
 * @v image		Image
 */
static inline void image_trust ( struct image *image ) {
	image->flags |= IMAGE_TRUSTED;
}

/**
 * Set image as untrusted
 *
 * @v image		Image
 */
static inline void image_untrust ( struct image *image ) {
	image->flags &= ~IMAGE_TRUSTED;
}

#endif /* _IPXE_IMAGE_H */
