#ifndef _IPXE_PNG_H
#define _IPXE_PNG_H

/** @file
 *
 * Portable Network Graphics (PNG) format
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <byteswap.h>
#include <ipxe/image.h>

/** A PNG file signature */
struct png_signature {
	/** Signature bytes */
	uint8_t bytes[8];
} __attribute__ (( packed ));

/** PNG file signature */
#define PNG_SIGNATURE { { 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n' } }

/** A PNG chunk header */
struct png_chunk_header {
	/** Length of the chunk (excluding header and footer) */
	uint32_t len;
	/** Chunk type */
	uint32_t type;
} __attribute__ (( packed ));

/** A PNG chunk footer */
struct png_chunk_footer {
	/** CRC */
	uint32_t crc;
} __attribute__ (( packed ));

/** PNG chunk type property bits */
enum png_chunk_type_bits {
	/** Chunk is ancillary */
	PNG_CHUNK_ANCILLARY = 0x20000000UL,
	/** Chunk is private */
	PNG_CHUNK_PRIVATE = 0x00200000UL,
	/** Reserved */
	PNG_CHUNK_RESERVED = 0x00002000UL,
	/** Chunk is safe to copy */
	PNG_CHUNK_SAFE = 0x00000020UL,
};

/**
 * Canonicalise PNG chunk type
 *
 * @v type		Raw chunk type
 * @ret type		Canonicalised chunk type (excluding property bits)
 */
static inline __attribute__ (( always_inline )) uint32_t
png_canonical_type ( uint32_t type ) {
	return ( type & ~( htonl ( PNG_CHUNK_ANCILLARY | PNG_CHUNK_PRIVATE |
				   PNG_CHUNK_RESERVED | PNG_CHUNK_SAFE ) ) );
}

/**
 * Define a canonical PNG chunk type
 *
 * @v first		First letter (in upper case)
 * @v second		Second letter (in upper case)
 * @v third		Third letter (in upper case)
 * @v fourth		Fourth letter (in upper case)
 * @ret type		Canonical chunk type
 */
#define PNG_TYPE( first, second, third, fourth ) \
	( ( (first) << 24 ) | ( (second) << 16 ) | ( (third) << 8 ) | (fourth) )

/** PNG image header chunk type */
#define PNG_TYPE_IHDR PNG_TYPE ( 'I', 'H', 'D', 'R' )

/** A PNG image header */
struct png_image_header {
	/** Width */
	uint32_t width;
	/** Height */
	uint32_t height;
	/** Bit depth */
	uint8_t depth;
	/** Colour type */
	uint8_t colour_type;
	/** Compression method */
	uint8_t compression;
	/** Filter method */
	uint8_t filter;
	/** Interlace method */
	uint8_t interlace;
} __attribute__ (( packed ));

/** PNG colour type bits */
enum png_colour_type {
	/** Palette is used */
	PNG_COLOUR_TYPE_PALETTE = 0x01,
	/** RGB colour is used */
	PNG_COLOUR_TYPE_RGB = 0x02,
	/** Alpha channel is used */
	PNG_COLOUR_TYPE_ALPHA = 0x04,
};

/** PNG colour type mask */
#define PNG_COLOUR_TYPE_MASK 0x07

/** PNG compression methods */
enum png_compression_method {
	/** DEFLATE compression with 32kB sliding window */
	PNG_COMPRESSION_DEFLATE = 0x00,
	/** First unknown compression method */
	PNG_COMPRESSION_UNKNOWN = 0x01,
};

/** PNG filter methods */
enum png_filter_method {
	/** Adaptive filtering with five basic types */
	PNG_FILTER_BASIC = 0x00,
	/** First unknown filter method */
	PNG_FILTER_UNKNOWN = 0x01,
};

/** PNG interlace methods */
enum png_interlace_method {
	/** No interlacing */
	PNG_INTERLACE_NONE = 0x00,
	/** Adam7 interlacing */
	PNG_INTERLACE_ADAM7 = 0x01,
	/** First unknown interlace method */
	PNG_INTERLACE_UNKNOWN = 0x02,
};

/** PNG palette chunk type */
#define PNG_TYPE_PLTE PNG_TYPE ( 'P', 'L', 'T', 'E' )

/** A PNG palette entry */
struct png_palette_entry {
	/** Red */
	uint8_t red;
	/** Green */
	uint8_t green;
	/** Blue */
	uint8_t blue;
} __attribute__ (( packed ));

/** A PNG palette chunk */
struct png_palette {
	/** Palette entries */
	struct png_palette_entry entries[0];
} __attribute__ (( packed ));

/** Maximum number of PNG palette entries */
#define PNG_PALETTE_COUNT 256

/** PNG image data chunk type */
#define PNG_TYPE_IDAT PNG_TYPE ( 'I', 'D', 'A', 'T' )

/** PNG basic filter types */
enum png_basic_filter_type {
	/** No filtering */
	PNG_FILTER_BASIC_NONE = 0,
	/** Left byte used as predictor */
	PNG_FILTER_BASIC_SUB = 1,
	/** Above byte used as predictor */
	PNG_FILTER_BASIC_UP = 2,
	/** Above and left bytes used as predictors */
	PNG_FILTER_BASIC_AVERAGE = 3,
	/** Paeth filter */
	PNG_FILTER_BASIC_PAETH = 4,
};

/** PNG image end chunk type */
#define PNG_TYPE_IEND PNG_TYPE ( 'I', 'E', 'N', 'D' )

extern struct image_type png_image_type __image_type ( PROBE_NORMAL );

#endif /* _IPXE_PNG_H */
