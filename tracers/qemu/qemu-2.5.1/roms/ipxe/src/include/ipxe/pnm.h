#ifndef _IPXE_PNM_H
#define _IPXE_PNM_H

/** @file
 *
 * Portable anymap format (PNM)
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/uaccess.h>
#include <ipxe/image.h>

/** PNM signature */
struct pnm_signature {
	/** Magic byte ('P') */
	char magic;
	/** PNM type */
	char type;
	/** Whitespace */
	char space;
} __attribute__ (( packed ));

/** PNM magic byte */
#define PNM_MAGIC 'P'

/** PNM context */
struct pnm_context {
	/** PNM type */
	struct pnm_type *type;
	/** Current byte offset */
	size_t offset;
	/** Maximum length of ASCII values */
	size_t ascii_len;
	/** Maximum pixel value */
	unsigned int max;
};

/** Default maximum length of ASCII values */
#define PNM_ASCII_LEN 16

/** PNM type */
struct pnm_type {
	/** PNM type */
	char type;
	/** Number of scalar values per pixel */
	uint8_t depth;
	/** Number of pixels per composite value */
	uint8_t packing;
	/** Flags */
	uint8_t flags;
	/** Extract scalar value
	 *
	 * @v image		PNM image
	 * @v pnm		PNM context
	 * @ret value		Value, or negative error
	 */
	int ( * scalar ) ( struct image *image, struct pnm_context *pnm );
	/** Convert composite value to 24-bit RGB
	 *
	 * @v composite		Composite value
	 * @v index		Pixel index within this composite value
	 * @ret rgb		24-bit RGB value
	 */
	uint32_t ( * rgb ) ( uint32_t composite, unsigned int index );
};

/** PNM flags */
enum pnm_flags {
	/** Bitmap format
	 *
	 * If set, this flag indicates that:
	 *
	 * - the maximum scalar value is predefined as being equal to
	 *   (2^packing-1), and is not present within the file, and
	 *
	 * - the maximum length of ASCII values is 1.
	 */
	PNM_BITMAP = 0x01,
};

extern struct image_type pnm_image_type __image_type ( PROBE_NORMAL );

#endif /* _IPXE_PNM_H */
