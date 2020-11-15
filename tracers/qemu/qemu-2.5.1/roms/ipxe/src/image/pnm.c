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
 * Portable anymap format (PNM)
 *
 */

#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <ipxe/image.h>
#include <ipxe/pixbuf.h>
#include <ipxe/pnm.h>

/**
 * Extract PNM ASCII value
 *
 * @v image		PNM image
 * @v pnm		PNM context
 * @ret value		Value, or negative error
 */
static int pnm_ascii ( struct image *image, struct pnm_context *pnm ) {
	char buf[ pnm->ascii_len + 1 /* NUL */ ];
	char *endp;
	size_t len;
	int value;
	int in_comment = 0;

	/* Skip any leading whitespace and comments */
	for ( ; pnm->offset < image->len ; pnm->offset++ ) {
		copy_from_user ( &buf[0], image->data, pnm->offset,
				 sizeof ( buf[0] ) );
		if ( in_comment ) {
			if ( buf[0] == '\n' )
				in_comment = 0;
		} else {
			if ( buf[0] == '#' ) {
				in_comment = 1;
			} else if ( ! isspace ( buf[0] ) ) {
				break;
			}
		}
	}

	/* Fail if no value is present */
	len = ( image->len - pnm->offset );
	if ( len == 0 ) {
		DBGC ( image, "PNM %s ran out of ASCII data\n", image->name );
		return -EINVAL;
	}

	/* Copy ASCII value to buffer and ensure string is NUL-terminated */
	if ( len > ( sizeof ( buf ) - 1 /* NUL */ ) )
		len = ( sizeof ( buf ) - 1 /* NUL */ );
	copy_from_user ( buf, image->data, pnm->offset, len );
	buf[len] = '\0';

	/* Parse value and update offset */
	value = strtoul ( buf, &endp, 0 );
	pnm->offset += ( endp - buf );

	/* Check and skip terminating whitespace character, if present */
	if ( ( pnm->offset != image->len ) && ( *endp != '\0' ) ) {
		if ( ! isspace ( *endp ) ) {
			DBGC ( image, "PNM %s invalid ASCII integer\n",
			       image->name );
			return -EINVAL;
		}
		pnm->offset++;
	}

	return value;
}

/**
 * Extract PNM binary value
 *
 * @v image		PNM image
 * @v pnm		PNM context
 * @ret value		Value, or negative error
 */
static int pnm_binary ( struct image *image, struct pnm_context *pnm ) {
	uint8_t value;

	/* Sanity check */
	if ( pnm->offset == image->len ) {
		DBGC ( image, "PNM %s ran out of binary data\n",
		       image->name );
		return -EINVAL;
	}

	/* Extract value */
	copy_from_user ( &value, image->data, pnm->offset, sizeof ( value ) );
	pnm->offset++;

	return value;
}

/**
 * Scale PNM scalar value
 *
 * @v image		PNM image
 * @v pnm		PNM context
 * @v value		Raw value
 * @ret value		Scaled value (in range 0-255)
 */
static int pnm_scale ( struct image *image, struct pnm_context *pnm,
		       unsigned int value ) {

	if ( value > pnm->max ) {
		DBGC ( image, "PNM %s has out-of-range value %d (max %d)\n",
		       image->name, value, pnm->max );
		return -EINVAL;
	}
	return ( ( 255 * value ) / pnm->max );
}

/**
 * Convert PNM bitmap composite value to RGB
 *
 * @v composite		Composite value
 * @v index		Pixel index within this composite value
 * @ret rgb		24-bit RGB value
 */
static uint32_t pnm_bitmap ( uint32_t composite, unsigned int index ) {

	/* Composite value is an 8-bit bitmask */
	return ( ( ( composite << index ) & 0x80 ) ? 0x000000 : 0xffffff );
}

/**
 * Convert PNM greymap composite value to RGB
 *
 * @v composite		Composite value
 * @v index		Pixel index within this composite value
 * @ret rgb		24-bit RGB value
 */
static uint32_t pnm_greymap ( uint32_t composite, unsigned int index __unused ){

	/* Composite value is an 8-bit greyscale value */
	return ( ( composite << 16 ) | ( composite << 8 ) | composite );
}

/**
 * Convert PNM pixmap composite value to RGB
 *
 * @v composite		Composite value
 * @v index		Pixel index within this composite value
 * @ret rgb		24-bit RGB value
 */
static uint32_t pnm_pixmap ( uint32_t composite, unsigned int index __unused ) {

	/* Composite value is already an RGB value */
	return composite;
}

/**
 * Extract PNM pixel data
 *
 * @v image		PNM image
 * @v pnm		PNM context
 * @v pixbuf		Pixel buffer
 * @ret rc		Return status code
 */
static int pnm_data ( struct image *image, struct pnm_context *pnm,
		      struct pixel_buffer *pixbuf ) {
	struct pnm_type *type = pnm->type;
	size_t offset = 0;
	unsigned int xpos = 0;
	int scalar;
	uint32_t composite;
	uint32_t rgb;
	unsigned int i;

	/* Fill pixel buffer */
	while ( offset < pixbuf->len ) {

		/* Extract a scaled composite scalar value from the file */
		composite = 0;
		for ( i = 0 ; i < type->depth ; i++ ) {
			scalar = type->scalar ( image, pnm );
			if ( scalar < 0 )
				return scalar;
			scalar = pnm_scale ( image, pnm, scalar );
			if ( scalar < 0 )
				return scalar;
			composite = ( ( composite << 8 ) | scalar );
		}

		/* Extract 24-bit RGB values from composite value */
		for ( i = 0 ; i < type->packing ; i++ ) {
			if ( offset >= pixbuf->len ) {
				DBGC ( image, "PNM %s has too many pixels\n",
				       image->name );
				return -EINVAL;
			}
			rgb = type->rgb ( composite, i );
			copy_to_user ( pixbuf->data, offset, &rgb,
				       sizeof ( rgb ) );
			offset += sizeof ( rgb );
			if ( ++xpos == pixbuf->width ) {
				xpos = 0;
				break;
			}
		}
	}

	return 0;
}

/** PNM image types */
static struct pnm_type pnm_types[] = {
	{
		.type = '1',
		.depth = 1,
		.packing = 1,
		.flags = PNM_BITMAP,
		.scalar = pnm_ascii,
		.rgb = pnm_bitmap,
	},
	{
		.type = '2',
		.depth = 1,
		.packing = 1,
		.scalar = pnm_ascii,
		.rgb = pnm_greymap,
	},
	{
		.type = '3',
		.depth = 3,
		.packing = 1,
		.scalar = pnm_ascii,
		.rgb = pnm_pixmap,
	},
	{
		.type = '4',
		.depth = 1,
		.packing = 8,
		.flags = PNM_BITMAP,
		.scalar = pnm_binary,
		.rgb = pnm_bitmap,
	},
	{
		.type = '5',
		.depth = 1,
		.packing = 1,
		.scalar = pnm_binary,
		.rgb = pnm_greymap,
	},
	{
		.type = '6',
		.depth = 3,
		.packing = 1,
		.scalar = pnm_binary,
		.rgb = pnm_pixmap,
	},
};

/**
 * Determine PNM image type
 *
 * @v image		PNM image
 * @ret type		PNM image type, or NULL if not found
 */
static struct pnm_type * pnm_type ( struct image *image ) {
	struct pnm_signature signature;
	struct pnm_type *type;
	unsigned int i;

	/* Extract signature */
	assert ( image->len >= sizeof ( signature ) );
	copy_from_user ( &signature, image->data, 0, sizeof ( signature ) );

	/* Check for supported types */
	for ( i = 0 ; i < ( sizeof ( pnm_types ) /
			    sizeof ( pnm_types[0] ) ) ; i++ ) {
		type = &pnm_types[i];
		if ( type->type == signature.type )
			return type;
	}
	return NULL;
}

/**
 * Convert PNM image to pixel buffer
 *
 * @v image		PNM image
 * @v pixbuf		Pixel buffer to fill in
 * @ret rc		Return status code
 */
static int pnm_pixbuf ( struct image *image, struct pixel_buffer **pixbuf ) {
	struct pnm_context pnm;
	int width;
	int height;
	int max;
	int rc;

	/* Initialise PNM context */
	pnm.type = pnm_type ( image );
	if ( ! pnm.type ) {
		rc = -ENOTSUP;
		goto err_type;
	}
	pnm.offset = sizeof ( struct pnm_signature );
	pnm.ascii_len = PNM_ASCII_LEN;

	/* Extract width */
	if ( ( width = pnm_ascii ( image, &pnm ) ) < 0 ) {
		rc = width;
		goto err_width;
	}

	/* Extract height */
	if ( ( height = pnm_ascii ( image, &pnm ) ) < 0 ) {
		rc = height;
		goto err_height;
	}

	/* Extract maximum scalar value, if not predefined */
	if ( pnm.type->flags & PNM_BITMAP ) {
		pnm.max = ( ( 1 << pnm.type->packing ) - 1 );
		pnm.ascii_len = 1;
	} else {
		if ( ( max = pnm_ascii ( image, &pnm ) ) < 0 ) {
			rc = max;
			goto err_max;
		}
		pnm.max = max;
	}
	if ( pnm.max == 0 ) {
		DBGC ( image, "PNM %s has invalid maximum value 0\n",
		       image->name );
		rc = -EINVAL;
		goto err_max;
	}
	DBGC ( image, "PNM %s is type %c width %d height %d max %d\n",
	       image->name, pnm.type->type, width, height, pnm.max );

	/* Allocate pixel buffer */
	*pixbuf = alloc_pixbuf ( width, height );
	if ( ! *pixbuf ) {
		rc = -ENOMEM;
		goto err_alloc_pixbuf;
	}

	/* Extract pixel data */
	if ( ( rc = pnm_data ( image, &pnm, *pixbuf ) ) != 0 )
		goto err_data;

	return 0;

 err_data:
	pixbuf_put ( *pixbuf );
 err_alloc_pixbuf:
 err_max:
 err_height:
 err_width:
 err_type:
	return rc;
}

/**
 * Probe PNM image
 *
 * @v image		PNM image
 * @ret rc		Return status code
 */
static int pnm_probe ( struct image *image ) {
	struct pnm_signature signature;

	/* Sanity check */
	if ( image->len < sizeof ( signature ) ) {
		DBGC ( image, "PNM %s is too short\n", image->name );
		return -ENOEXEC;
	}

	/* Check signature */
	copy_from_user ( &signature, image->data, 0, sizeof ( signature ) );
	if ( ! ( ( signature.magic == PNM_MAGIC ) &&
		 ( isdigit ( signature.type ) ) &&
		 ( isspace ( signature.space ) ) ) ) {
		DBGC ( image, "PNM %s has invalid signature\n", image->name );
		return -ENOEXEC;
	}
	DBGC ( image, "PNM %s is type %c\n", image->name, signature.type );

	return 0;
}

/** PNM image type */
struct image_type pnm_image_type __image_type ( PROBE_NORMAL ) = {
	.name = "PNM",
	.probe = pnm_probe,
	.pixbuf = pnm_pixbuf,
};
