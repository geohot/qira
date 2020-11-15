/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <string.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/umalloc.h>
#include <ipxe/pixbuf.h>
#include <ipxe/deflate.h>
#include <ipxe/png.h>

/** @file
 *
 * Portable Network Graphics (PNG) format
 *
 * The PNG format is defined in RFC 2083.
 */

/** PNG context */
struct png_context {
	/** Offset within image */
	size_t offset;

	/** Pixel buffer */
	struct pixel_buffer *pixbuf;

	/** Bit depth */
	unsigned int depth;
	/** Colour type */
	unsigned int colour_type;
	/** Number of channels */
	unsigned int channels;
	/** Number of interlace passes */
	unsigned int passes;
	/** Palette, in iPXE's pixel buffer format */
	uint32_t palette[PNG_PALETTE_COUNT];

	/** Decompression buffer for raw PNG data */
	struct deflate_chunk raw;
	/** Decompressor */
	struct deflate deflate;
};

/** A PNG interlace pass */
struct png_interlace {
	/** Pass number */
	unsigned int pass;
	/** X starting indent */
	unsigned int x_indent;
	/** Y starting indent */
	unsigned int y_indent;
	/** X stride */
	unsigned int x_stride;
	/** Y stride */
	unsigned int y_stride;
	/** Width */
	unsigned int width;
	/** Height */
	unsigned int height;
};

/** PNG file signature */
static struct png_signature png_signature = PNG_SIGNATURE;

/** Number of interlacing passes */
static uint8_t png_interlace_passes[] = {
	[PNG_INTERLACE_NONE] = 1,
	[PNG_INTERLACE_ADAM7] = 7,
};

/**
 * Transcribe PNG chunk type name (for debugging)
 *
 * @v type		Chunk type
 * @ret name		Chunk type name
 */
static const char * png_type_name ( uint32_t type ) {
	static union {
		uint32_t type;
		char name[ sizeof ( uint32_t ) + 1 /* NUL */ ];
	} u;

	u.type = type;
	return u.name;
}

/**
 * Calculate PNG interlace pass parameters
 *
 * @v png		PNG context
 * @v pass		Pass number (0=first pass)
 * @v interlace		Interlace pass to fill in
 */
static void png_interlace ( struct png_context *png, unsigned int pass,
			    struct png_interlace *interlace ) {
	unsigned int grid_width_log2;
	unsigned int grid_height_log2;
	unsigned int x_indent;
	unsigned int y_indent;
	unsigned int x_stride_log2;
	unsigned int y_stride_log2;
	unsigned int x_stride;
	unsigned int y_stride;
	unsigned int width;
	unsigned int height;

	/* Sanity check */
	assert ( png->passes > 0 );

	/* Store pass number */
	interlace->pass = pass;

	/* Calculate interlace grid dimensions */
	grid_width_log2 = ( png->passes / 2 );
	grid_height_log2 = ( ( png->passes - 1 ) / 2 );

	/* Calculate starting indents */
	interlace->x_indent = x_indent =
		( ( pass & 1 ) ?
		  ( 1 << ( grid_width_log2 - ( pass / 2 ) - 1 ) ) : 0 );
	interlace->y_indent = y_indent =
		( ( pass && ! ( pass & 1 ) ) ?
		  ( 1 << ( grid_height_log2 - ( ( pass - 1 ) / 2 ) - 1 ) ) : 0);

	/* Calculate strides */
	x_stride_log2 = ( grid_width_log2 - ( pass / 2 ) );
	y_stride_log2 =
		( grid_height_log2 - ( pass ? ( ( pass - 1 ) / 2 ) : 0 ) );
	interlace->x_stride = x_stride = ( 1 << x_stride_log2 );
	interlace->y_stride = y_stride = ( 1 << y_stride_log2 );

	/* Calculate pass dimensions */
	width = png->pixbuf->width;
	height = png->pixbuf->height;
	interlace->width =
		( ( width - x_indent + x_stride - 1 ) >> x_stride_log2 );
	interlace->height =
		( ( height - y_indent + y_stride - 1 ) >> y_stride_log2 );
}

/**
 * Calculate PNG pixel length
 *
 * @v png		PNG context
 * @ret pixel_len	Pixel length
 */
static unsigned int png_pixel_len ( struct png_context *png ) {

	return ( ( ( png->channels * png->depth ) + 7 ) / 8 );
}

/**
 * Calculate PNG scanline length
 *
 * @v png		PNG context
 * @v interlace		Interlace pass
 * @ret scanline_len	Scanline length (including filter byte)
 */
static size_t png_scanline_len ( struct png_context *png,
				 struct png_interlace *interlace ) {

	return ( 1 /* Filter byte */ +
		 ( ( interlace->width * png->channels * png->depth ) + 7 ) / 8);
}

/**
 * Handle PNG image header chunk
 *
 * @v image		PNG image
 * @v png		PNG context
 * @v len		Chunk length
 * @ret rc		Return status code
 */
static int png_image_header ( struct image *image, struct png_context *png,
			      size_t len ) {
	struct png_image_header ihdr;
	struct png_interlace interlace;
	unsigned int pass;

	/* Sanity check */
	if ( len != sizeof ( ihdr ) ) {
		DBGC ( image, "PNG %s invalid IHDR length %zd\n",
		       image->name, len );
		return -EINVAL;
	}
	if ( png->pixbuf ) {
		DBGC ( image, "PNG %s duplicate IHDR\n", image->name );
		return -EINVAL;
	}

	/* Extract image header */
	copy_from_user ( &ihdr, image->data, png->offset, len );
	DBGC ( image, "PNG %s %dx%d depth %d type %d compression %d filter %d "
	       "interlace %d\n", image->name, ntohl ( ihdr.width ),
	       ntohl ( ihdr.height ), ihdr.depth, ihdr.colour_type,
	       ihdr.compression, ihdr.filter, ihdr.interlace );

	/* Sanity checks */
	if ( ihdr.compression >= PNG_COMPRESSION_UNKNOWN ) {
		DBGC ( image, "PNG %s unknown compression method %d\n",
		       image->name, ihdr.compression );
		return -ENOTSUP;
	}
	if ( ihdr.filter >= PNG_FILTER_UNKNOWN ) {
		DBGC ( image, "PNG %s unknown filter method %d\n",
		       image->name, ihdr.filter );
		return -ENOTSUP;
	}
	if ( ihdr.interlace >= PNG_INTERLACE_UNKNOWN ) {
		DBGC ( image, "PNG %s unknown interlace method %d\n",
		       image->name, ihdr.interlace );
		return -ENOTSUP;
	}

	/* Allocate pixel buffer */
	png->pixbuf = alloc_pixbuf ( ntohl ( ihdr.width ),
				     ntohl ( ihdr.height ) );
	if ( ! png->pixbuf ) {
		DBGC ( image, "PNG %s could not allocate pixel buffer\n",
		       image->name );
		return -ENOMEM;
	}

	/* Extract bit depth */
	png->depth = ihdr.depth;
	if ( ( png->depth == 0 ) ||
	     ( ( png->depth & ( png->depth - 1 ) ) != 0 ) ) {
		DBGC ( image, "PNG %s invalid depth %d\n",
		       image->name, png->depth );
		return -EINVAL;
	}

	/* Calculate number of channels */
	png->colour_type = ihdr.colour_type;
	png->channels = 1;
	if ( ! ( ihdr.colour_type & PNG_COLOUR_TYPE_PALETTE ) ) {
		if ( ihdr.colour_type & PNG_COLOUR_TYPE_RGB )
			png->channels += 2;
		if ( ihdr.colour_type & PNG_COLOUR_TYPE_ALPHA )
			png->channels += 1;
	}

	/* Calculate number of interlace passes */
	png->passes = png_interlace_passes[ihdr.interlace];

	/* Calculate length of raw data buffer */
	for ( pass = 0 ; pass < png->passes ; pass++ ) {
		png_interlace ( png, pass, &interlace );
		if ( interlace.width == 0 )
			continue;
		png->raw.len += ( interlace.height *
				  png_scanline_len ( png, &interlace ) );
	}

	/* Allocate raw data buffer */
	png->raw.data = umalloc ( png->raw.len );
	if ( ! png->raw.data ) {
		DBGC ( image, "PNG %s could not allocate data buffer\n",
		       image->name );
		return -ENOMEM;
	}

	return 0;
}

/**
 * Handle PNG palette chunk
 *
 * @v image		PNG image
 * @v png		PNG context
 * @v len		Chunk length
 * @ret rc		Return status code
 */
static int png_palette ( struct image *image, struct png_context *png,
			 size_t len ) {
	size_t offset = png->offset;
	struct png_palette_entry palette;
	unsigned int i;

	/* Populate palette */
	for ( i = 0 ; i < ( sizeof ( png->palette ) /
			    sizeof ( png->palette[0] ) ) ; i++ ) {

		/* Stop when we run out of palette data */
		if ( len < sizeof ( palette ) )
			break;

		/* Extract palette entry */
		copy_from_user ( &palette, image->data, offset,
				 sizeof ( palette ) );
		png->palette[i] = ( ( palette.red << 16 ) |
				    ( palette.green << 8 ) |
				    ( palette.blue << 0 ) );
		DBGC2 ( image, "PNG %s palette entry %d is %#06x\n",
			image->name, i, png->palette[i] );

		/* Move to next entry */
		offset += sizeof ( palette );
		len -= sizeof ( palette );
	}

	return 0;
}

/**
 * Handle PNG image data chunk
 *
 * @v image		PNG image
 * @v png		PNG context
 * @v len		Chunk length
 * @ret rc		Return status code
 */
static int png_image_data ( struct image *image, struct png_context *png,
			    size_t len ) {
	struct deflate_chunk in;
	int rc;

	/* Deflate this chunk */
	deflate_chunk_init ( &in, image->data, png->offset,
			     ( png->offset + len ) );
	if ( ( rc = deflate_inflate ( &png->deflate, &in, &png->raw ) ) != 0 ) {
		DBGC ( image, "PNG %s could not decompress: %s\n",
		       image->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Unfilter byte using the "None" filter
 *
 * @v current		Filtered current byte
 * @v left		Unfiltered left byte
 * @v above		Unfiltered above byte
 * @v above_left	Unfiltered above-left byte
 * @ret current		Unfiltered current byte
 */
static unsigned int png_unfilter_none ( unsigned int current,
					unsigned int left __unused,
					unsigned int above __unused,
					unsigned int above_left __unused ) {

	return current;
}

/**
 * Unfilter byte using the "Sub" filter
 *
 * @v current		Filtered current byte
 * @v left		Unfiltered left byte
 * @v above		Unfiltered above byte
 * @v above_left	Unfiltered above-left byte
 * @ret current		Unfiltered current byte
 */
static unsigned int png_unfilter_sub ( unsigned int current,
				       unsigned int left,
				       unsigned int above __unused,
				       unsigned int above_left __unused ) {

	return ( current + left );
}

/**
 * Unfilter byte using the "Up" filter
 *
 * @v current		Filtered current byte
 * @v left		Unfiltered left byte
 * @v above		Unfiltered above byte
 * @v above_left	Unfiltered above-left byte
 * @ret current		Unfiltered current byte
 */
static unsigned int png_unfilter_up ( unsigned int current,
				      unsigned int left __unused,
				      unsigned int above,
				      unsigned int above_left __unused ) {

	return ( current + above );
}

/**
 * Unfilter byte using the "Average" filter
 *
 * @v current		Filtered current byte
 * @v left		Unfiltered left byte
 * @v above		Unfiltered above byte
 * @v above_left	Unfiltered above-left byte
 * @ret current		Unfiltered current byte
 */
static unsigned int png_unfilter_average ( unsigned int current,
					   unsigned int left,
					   unsigned int above,
					   unsigned int above_left __unused ) {

	return ( current + ( ( above + left ) >> 1 ) );
}

/**
 * Paeth predictor function (defined in RFC 2083)
 *
 * @v a			Pixel A
 * @v b			Pixel B
 * @v c			Pixel C
 * @ret predictor	Predictor pixel
 */
static unsigned int png_paeth_predictor ( unsigned int a, unsigned int b,
					  unsigned int c ) {
	unsigned int p;
	unsigned int pa;
	unsigned int pb;
	unsigned int pc;

	/* Algorithm as defined in RFC 2083 section 6.6 */
	p = ( a + b - c );
	pa = abs ( p - a );
	pb = abs ( p - b );
	pc = abs ( p - c );
	if ( ( pa <= pb ) && ( pa <= pc ) ) {
		return a;
	} else if ( pb <= pc ) {
		return b;
	} else {
		return c;
	}
}

/**
 * Unfilter byte using the "Paeth" filter
 *
 * @v current		Filtered current byte
 * @v above_left	Unfiltered above-left byte
 * @v above		Unfiltered above byte
 * @v left		Unfiltered left byte
 * @ret current		Unfiltered current byte
 */
static unsigned int png_unfilter_paeth ( unsigned int current,
					 unsigned int left,
					 unsigned int above,
					 unsigned int above_left ) {

	return ( current + png_paeth_predictor ( left, above, above_left ) );
}

/** A PNG filter */
struct png_filter {
	/**
	 * Unfilter byte
	 *
	 * @v current		Filtered current byte
	 * @v left		Unfiltered left byte
	 * @v above		Unfiltered above byte
	 * @v above_left	Unfiltered above-left byte
	 * @ret current		Unfiltered current byte
	 */
	unsigned int ( * unfilter ) ( unsigned int current,
				      unsigned int left,
				      unsigned int above,
				      unsigned int above_left );
};

/** PNG filter types */
static struct png_filter png_filters[] = {
	[PNG_FILTER_BASIC_NONE] = { png_unfilter_none },
	[PNG_FILTER_BASIC_SUB] = { png_unfilter_sub },
	[PNG_FILTER_BASIC_UP] = { png_unfilter_up },
	[PNG_FILTER_BASIC_AVERAGE] = { png_unfilter_average },
	[PNG_FILTER_BASIC_PAETH] = { png_unfilter_paeth },
};

/**
 * Unfilter one interlace pass of PNG raw data
 *
 * @v image		PNG image
 * @v png		PNG context
 * @v interlace		Interlace pass
 * @ret rc		Return status code
 *
 * This routine may assume that it is impossible to overrun the raw
 * data buffer, since the size is determined by the image dimensions.
 */
static int png_unfilter_pass ( struct image *image, struct png_context *png,
			       struct png_interlace *interlace ) {
	size_t offset = png->raw.offset;
	size_t pixel_len = png_pixel_len ( png );
	size_t scanline_len = png_scanline_len ( png, interlace );
	struct png_filter *filter;
	unsigned int scanline;
	unsigned int byte;
	uint8_t filter_type;
	uint8_t left;
	uint8_t above;
	uint8_t above_left;
	uint8_t current;

	/* On the first scanline of a pass, above bytes are assumed to
	 * be zero.
	 */
	above = 0;

	/* Iterate over each scanline in turn */
	for ( scanline = 0 ; scanline < interlace->height ; scanline++ ) {

		/* Extract filter byte and determine filter type */
		copy_from_user ( &filter_type, png->raw.data, offset++,
				 sizeof ( filter_type ) );
		if ( filter_type >= ( sizeof ( png_filters ) /
				      sizeof ( png_filters[0] ) ) ) {
			DBGC ( image, "PNG %s unknown filter type %d\n",
			       image->name, filter_type );
			return -ENOTSUP;
		}
		filter = &png_filters[filter_type];
		assert ( filter->unfilter != NULL );
		DBGC2 ( image, "PNG %s pass %d scanline %d filter type %d\n",
			image->name, interlace->pass, scanline, filter_type );

		/* At the start of a line, both above-left and left
		 * bytes are taken to be zero.
		 */
		left = 0;
		above_left = 0;

		/* Iterate over each byte (not pixel) in turn */
		for ( byte = 0 ; byte < ( scanline_len - 1 ) ; byte++ ) {

			/* Extract predictor bytes, if applicable */
			if ( byte >= pixel_len ) {
				copy_from_user ( &left, png->raw.data,
						 ( offset - pixel_len ),
						 sizeof ( left ) );
			}
			if ( scanline > 0 ) {
				copy_from_user ( &above, png->raw.data,
						 ( offset - scanline_len ),
						 sizeof ( above ) );
			}
			if ( ( scanline > 0 ) && ( byte >= pixel_len ) ) {
				copy_from_user ( &above_left, png->raw.data,
						 ( offset - scanline_len -
						   pixel_len ),
						 sizeof ( above_left ) );
			}

			/* Unfilter current byte */
			copy_from_user ( &current, png->raw.data,
					 offset, sizeof ( current ) );
			current = filter->unfilter ( current, left, above,
						     above_left );
			copy_to_user ( png->raw.data, offset++,
				       &current, sizeof ( current ) );
		}
	}

	/* Update offset */
	png->raw.offset = offset;

	return 0;
}

/**
 * Unfilter PNG raw data
 *
 * @v image		PNG image
 * @v png		PNG context
 * @ret rc		Return status code
 *
 * This routine may assume that it is impossible to overrun the raw
 * data buffer, since the size is determined by the image dimensions.
 */
static int png_unfilter ( struct image *image, struct png_context *png ) {
	struct png_interlace interlace;
	unsigned int pass;
	int rc;

	/* Process each interlace pass */
	png->raw.offset = 0;
	for ( pass = 0 ; pass < png->passes ; pass++ ) {

		/* Calculate interlace pass parameters */
		png_interlace ( png, pass, &interlace );

		/* Skip zero-width rows (which have no filter bytes) */
		if ( interlace.width == 0 )
			continue;

		/* Unfilter this pass */
		if ( ( rc = png_unfilter_pass ( image, png,
						&interlace ) ) != 0 )
			return rc;
	}
	assert ( png->raw.offset == png->raw.len );

	return 0;
}

/**
 * Calculate PNG pixel component value
 *
 * @v raw		Raw component value
 * @v alpha		Alpha value
 * @v max		Maximum raw/alpha value
 * @ret value		Component value in range 0-255
 */
static inline unsigned int png_pixel ( unsigned int raw, unsigned int alpha,
				       unsigned int max ) {

	/* The basic calculation is 255*(raw/max)*(value/max).  We use
	 * fixed-point arithmetic (scaling up to the maximum range for
	 * a 32-bit integer), in order to get the same results for
	 * alpha blending as the test cases (produced using
	 * ImageMagick).
	 */
	return ( ( ( ( ( 0xff00 * raw * alpha ) / max ) / max ) + 0x80 ) >> 8 );
}

/**
 * Fill one interlace pass of PNG pixels
 *
 * @v image		PNG image
 * @v png		PNG context
 * @v interlace		Interlace pass
 *
 * This routine may assume that it is impossible to overrun either the
 * raw data buffer or the pixel buffer, since the sizes of both are
 * determined by the image dimensions.
 */
static void png_pixels_pass ( struct image *image,
			      struct png_context *png,
			      struct png_interlace *interlace ) {
	size_t raw_offset = png->raw.offset;
	uint8_t channel[png->channels];
	int is_indexed = ( png->colour_type & PNG_COLOUR_TYPE_PALETTE );
	int is_rgb = ( png->colour_type & PNG_COLOUR_TYPE_RGB );
	int has_alpha = ( png->colour_type & PNG_COLOUR_TYPE_ALPHA );
	size_t pixbuf_y_offset;
	size_t pixbuf_offset;
	size_t pixbuf_x_stride;
	size_t pixbuf_y_stride;
	size_t raw_stride;
	unsigned int y;
	unsigned int x;
	unsigned int c;
	unsigned int bits;
	unsigned int depth;
	unsigned int max;
	unsigned int alpha;
	unsigned int raw;
	unsigned int value;
	uint8_t current = 0;
	uint32_t pixel;

	/* We only ever use the top byte of 16-bit pixels.  Model this
	 * as a bit depth of 8 with a stride of more than one.
	 */
	depth = png->depth;
	raw_stride = ( ( depth + 7 ) / 8 );
	if ( depth > 8 )
		depth = 8;
	max = ( ( 1 << depth ) - 1 );

	/* Calculate pixel buffer offset and strides */
	pixbuf_y_offset = ( ( ( interlace->y_indent * png->pixbuf->width ) +
			      interlace->x_indent ) * sizeof ( pixel ) );
	pixbuf_x_stride = ( interlace->x_stride * sizeof ( pixel ) );
	pixbuf_y_stride = ( interlace->y_stride * png->pixbuf->width *
			    sizeof ( pixel ) );
	DBGC2 ( image, "PNG %s pass %d %dx%d at (%d,%d) stride (%d,%d)\n",
		image->name, interlace->pass, interlace->width,
		interlace->height, interlace->x_indent, interlace->y_indent,
		interlace->x_stride, interlace->y_stride );

	/* Iterate over each scanline in turn */
	for ( y = 0 ; y < interlace->height ; y++ ) {

		/* Skip filter byte */
		raw_offset++;

		/* Iterate over each pixel in turn */
		bits = depth;
		pixbuf_offset = pixbuf_y_offset;
		for ( x = 0 ; x < interlace->width ; x++ ) {

			/* Extract sample value */
			for ( c = 0 ; c < png->channels ; c++ ) {

				/* Get sample value into high bits of current */
				current <<= depth;
				bits -= depth;
				if ( ! bits ) {
					copy_from_user ( &current,
							 png->raw.data,
							 raw_offset,
							 sizeof ( current ) );
					raw_offset += raw_stride;
					bits = 8;
				}

				/* Extract sample value */
				channel[c] = ( current >> ( 8 - depth ) );
			}

			/* Convert to native pixel format */
			if ( is_indexed ) {

				/* Indexed */
				pixel = png->palette[channel[0]];

			} else {

				/* Determine alpha value */
				alpha = ( has_alpha ?
					  channel[ png->channels - 1 ] : max );

				/* Convert to RGB value */
				pixel = 0;
				for ( c = 0 ; c < 3 ; c++ ) {
					raw = channel[ is_rgb ? c : 0 ];
					value = png_pixel ( raw, alpha, max );
					assert ( value <= 255 );
					pixel = ( ( pixel << 8 ) | value );
				}
			}

			/* Store pixel */
			copy_to_user ( png->pixbuf->data, pixbuf_offset,
				       &pixel, sizeof ( pixel ) );
			pixbuf_offset += pixbuf_x_stride;
		}

		/* Move to next output row */
		pixbuf_y_offset += pixbuf_y_stride;
	}

	/* Update offset */
	png->raw.offset = raw_offset;
}

/**
 * Fill PNG pixels
 *
 * @v image		PNG image
 * @v png		PNG context
 *
 * This routine may assume that it is impossible to overrun either the
 * raw data buffer or the pixel buffer, since the sizes of both are
 * determined by the image dimensions.
 */
static void png_pixels ( struct image *image, struct png_context *png ) {
	struct png_interlace interlace;
	unsigned int pass;

	/* Process each interlace pass */
	png->raw.offset = 0;
	for ( pass = 0 ; pass < png->passes ; pass++ ) {

		/* Calculate interlace pass parameters */
		png_interlace ( png, pass, &interlace );

		/* Skip zero-width rows (which have no filter bytes) */
		if ( interlace.width == 0 )
			continue;

		/* Unfilter this pass */
		png_pixels_pass ( image, png, &interlace );
	}
	assert ( png->raw.offset == png->raw.len );
}

/**
 * Handle PNG image end chunk
 *
 * @v image		PNG image
 * @v png		PNG context
 * @v len		Chunk length
 * @ret rc		Return status code
 */
static int png_image_end ( struct image *image, struct png_context *png,
			   size_t len ) {
	int rc;

	/* Sanity checks */
	if ( len != 0 ) {
		DBGC ( image, "PNG %s invalid IEND length %zd\n",
		       image->name, len );
		return -EINVAL;
	}
	if ( ! png->pixbuf ) {
		DBGC ( image, "PNG %s missing pixel buffer (no IHDR?)\n",
		       image->name );
		return -EINVAL;
	}
	if ( ! deflate_finished ( &png->deflate ) ) {
		DBGC ( image, "PNG %s decompression not complete\n",
		       image->name );
		return -EINVAL;
	}
	if ( png->raw.offset != png->raw.len ) {
		DBGC ( image, "PNG %s incorrect decompressed length (expected "
		       "%zd, got %zd)\n", image->name, png->raw.len,
		       png->raw.offset );
		return -EINVAL;
	}

	/* Unfilter raw data */
	if ( ( rc = png_unfilter ( image, png ) ) != 0 )
		return rc;

	/* Fill pixel buffer */
	png_pixels ( image, png );

	return 0;
}

/** A PNG chunk handler */
struct png_chunk_handler {
	/** Chunk type */
	uint32_t type;
	/**
	 * Handle chunk
	 *
	 * @v image		PNG image
	 * @v png		PNG context
	 * @v len		Chunk length
	 * @ret rc		Return status code
	 */
	int ( * handle ) ( struct image *image, struct png_context *png,
			   size_t len );
};

/** PNG chunk handlers */
static struct png_chunk_handler png_chunk_handlers[] = {
	{ htonl ( PNG_TYPE_IHDR ), png_image_header },
	{ htonl ( PNG_TYPE_PLTE ), png_palette },
	{ htonl ( PNG_TYPE_IDAT ), png_image_data },
	{ htonl ( PNG_TYPE_IEND ), png_image_end },
};

/**
 * Handle PNG chunk
 *
 * @v image		PNG image
 * @v png		PNG context
 * @v type		Chunk type
 * @v len		Chunk length
 * @ret rc		Return status code
 */
static int png_chunk ( struct image *image, struct png_context *png,
		       uint32_t type, size_t len ) {
	struct png_chunk_handler *handler;
	unsigned int i;

	DBGC ( image, "PNG %s chunk type %s offset %zd length %zd\n",
	       image->name, png_type_name ( type ), png->offset, len );

	/* Handle according to chunk type */
	for ( i = 0 ; i < ( sizeof ( png_chunk_handlers ) /
			    sizeof ( png_chunk_handlers[0] ) ) ; i++ ) {
		handler = &png_chunk_handlers[i];
		if ( handler->type == type )
			return handler->handle ( image, png, len );
	}

	/* Fail if unknown chunk type is critical */
	if ( ! ( type & htonl ( PNG_CHUNK_ANCILLARY ) ) ) {
		DBGC ( image, "PNG %s unknown critical chunk type %s\n",
		       image->name, png_type_name ( type ) );
		return -ENOTSUP;
	}

	/* Ignore non-critical unknown chunk types */
	return 0;
}

/**
 * Convert PNG image to pixel buffer
 *
 * @v image		PNG image
 * @v pixbuf		Pixel buffer to fill in
 * @ret rc		Return status code
 */
static int png_pixbuf ( struct image *image, struct pixel_buffer **pixbuf ) {
	struct png_context *png;
	struct png_chunk_header header;
	struct png_chunk_footer footer;
	size_t remaining;
	size_t chunk_len;
	int rc;

	/* Allocate and initialise context */
	png = zalloc ( sizeof ( *png ) );
	if ( ! png ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	png->offset = sizeof ( struct png_signature );
	deflate_init ( &png->deflate, DEFLATE_ZLIB );

	/* Process chunks */
	do {

		/* Extract chunk header */
		remaining = ( image->len - png->offset );
		if ( remaining < sizeof ( header ) ) {
			DBGC ( image, "PNG %s truncated chunk header at offset "
			       "%zd\n", image->name, png->offset );
			rc = -EINVAL;
			goto err_truncated;
		}
		copy_from_user ( &header, image->data, png->offset,
				 sizeof ( header ) );
		png->offset += sizeof ( header );

		/* Validate chunk length */
		chunk_len = ntohl ( header.len );
		if ( remaining < ( sizeof ( header ) + chunk_len +
				   sizeof ( footer ) ) ) {
			DBGC ( image, "PNG %s truncated chunk data/footer at "
			       "offset %zd\n", image->name, png->offset );
			rc = -EINVAL;
			goto err_truncated;
		}

		/* Handle chunk */
		if ( ( rc = png_chunk ( image, png, header.type,
					chunk_len ) ) != 0 )
			goto err_chunk;

		/* Move to next chunk */
		png->offset += ( chunk_len + sizeof ( footer ) );

	} while ( png->offset < image->len );

	/* Check that we finished with an IEND chunk */
	if ( header.type != htonl ( PNG_TYPE_IEND ) ) {
		DBGC ( image, "PNG %s did not finish with IEND\n",
		       image->name );
		rc = -EINVAL;
		goto err_iend;
	}

	/* Return pixel buffer */
	*pixbuf = pixbuf_get ( png->pixbuf );

	/* Success */
	rc = 0;

 err_iend:
 err_chunk:
 err_truncated:
	pixbuf_put ( png->pixbuf );
	ufree ( png->raw.data );
	free ( png );
 err_alloc:
	return rc;
}

/**
 * Probe PNG image
 *
 * @v image		PNG image
 * @ret rc		Return status code
 */
static int png_probe ( struct image *image ) {
	struct png_signature signature;

	/* Sanity check */
	if ( image->len < sizeof ( signature ) ) {
		DBGC ( image, "PNG %s is too short\n", image->name );
		return -ENOEXEC;
	}

	/* Check signature */
	copy_from_user ( &signature, image->data, 0, sizeof ( signature ) );
	if ( memcmp ( &signature, &png_signature, sizeof ( signature ) ) != 0 ){
		DBGC ( image, "PNG %s has invalid signature\n", image->name );
		return -ENOEXEC;
	}

	return 0;
}

/** PNG image type */
struct image_type png_image_type __image_type ( PROBE_NORMAL ) = {
	.name = "PNG",
	.probe = png_probe,
	.pixbuf = png_pixbuf,
};
