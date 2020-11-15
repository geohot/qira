#ifndef _IPXE_PIXBUF_H
#define _IPXE_PIXBUF_H

/** @file
 *
 * Pixel buffer
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>
#include <ipxe/refcnt.h>
#include <ipxe/uaccess.h>

/** A pixel buffer */
struct pixel_buffer {
	/** Reference count */
	struct refcnt refcnt;
	/** Width */
	unsigned int width;
	/** Height */
	unsigned int height;
	/** 32-bit (8:8:8:8) xRGB pixel data, in host-endian order */
	userptr_t data;
	/** Total length */
	size_t len;
};

/**
 * Get reference to pixel buffer
 *
 * @v pixbuf		Pixel buffer
 * @ret pixbuf		Pixel buffer
 */
static inline __attribute__ (( always_inline )) struct pixel_buffer *
pixbuf_get ( struct pixel_buffer *pixbuf ) {
	ref_get ( &pixbuf->refcnt );
	return pixbuf;
}

/**
 * Drop reference to pixel buffer
 *
 * @v pixbuf		Pixel buffer
 */
static inline __attribute__ (( always_inline )) void
pixbuf_put ( struct pixel_buffer *pixbuf ) {
	ref_put ( &pixbuf->refcnt );
}

extern struct pixel_buffer * alloc_pixbuf ( unsigned int width,
					    unsigned int height );

#endif /* _IPXE_PIXBUF_H */
