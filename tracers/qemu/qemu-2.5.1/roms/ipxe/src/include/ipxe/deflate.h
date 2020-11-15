#ifndef _IPXE_DEFLATE_H
#define _IPXE_DEFLATE_H

/** @file
 *
 * DEFLATE decompression algorithm
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <string.h>
#include <ipxe/uaccess.h>

/** Compression formats */
enum deflate_format {
	/** Raw DEFLATE data (no header or footer) */
	DEFLATE_RAW,
	/** ZLIB header and footer */
	DEFLATE_ZLIB,
};

/** Block header length (in bits) */
#define DEFLATE_HEADER_BITS 3

/** Block header final block flags bit */
#define DEFLATE_HEADER_BFINAL_BIT 0

/** Block header type LSB */
#define DEFLATE_HEADER_BTYPE_LSB 1

/** Block header type mask */
#define DEFLATE_HEADER_BTYPE_MASK 0x03

/** Block header type: literal data */
#define DEFLATE_HEADER_BTYPE_LITERAL 0

/** Block header type: static Huffman alphabet */
#define DEFLATE_HEADER_BTYPE_STATIC 1

/** Block header type: dynamic Huffman alphabet */
#define DEFLATE_HEADER_BTYPE_DYNAMIC 2

/** Literal header LEN/NLEN field length (in bits) */
#define DEFLATE_LITERAL_LEN_BITS 16

/** Dynamic header length (in bits) */
#define DEFLATE_DYNAMIC_BITS 14

/** Dynamic header HLIT field LSB */
#define DEFLATE_DYNAMIC_HLIT_LSB 0

/** Dynamic header HLIT field mask */
#define DEFLATE_DYNAMIC_HLIT_MASK 0x1f

/** Dynamic header HDIST field LSB */
#define DEFLATE_DYNAMIC_HDIST_LSB 5

/** Dynamic header HDIST field mask */
#define DEFLATE_DYNAMIC_HDIST_MASK 0x1f

/** Dynamic header HCLEN field LSB */
#define DEFLATE_DYNAMIC_HCLEN_LSB 10

/** Dynamic header HCLEN field mask */
#define DEFLATE_DYNAMIC_HCLEN_MASK 0x0f

/** Dynamic header code length length (in bits) */
#define DEFLATE_CODELEN_BITS 3

/** Maximum length of a Huffman symbol (in bits) */
#define DEFLATE_HUFFMAN_BITS 15

/** Quick lookup length for a Huffman symbol (in bits)
 *
 * This is a policy decision.
 */
#define DEFLATE_HUFFMAN_QL_BITS 7

/** Quick lookup shift */
#define DEFLATE_HUFFMAN_QL_SHIFT ( 16 - DEFLATE_HUFFMAN_QL_BITS )

/** Literal/length end of block code */
#define DEFLATE_LITLEN_END 256

/** Maximum value of a literal/length code */
#define DEFLATE_LITLEN_MAX_CODE 287

/** Maximum value of a distance code */
#define DEFLATE_DISTANCE_MAX_CODE 31

/** Maximum value of a code length code */
#define DEFLATE_CODELEN_MAX_CODE 18

/** ZLIB header length (in bits) */
#define ZLIB_HEADER_BITS 16

/** ZLIB header compression method LSB */
#define ZLIB_HEADER_CM_LSB 0

/** ZLIB header compression method mask */
#define ZLIB_HEADER_CM_MASK 0x0f

/** ZLIB header compression method: DEFLATE */
#define ZLIB_HEADER_CM_DEFLATE 8

/** ZLIB header preset dictionary flag bit */
#define ZLIB_HEADER_FDICT_BIT 13

/** ZLIB ADLER32 length (in bits) */
#define ZLIB_ADLER32_BITS 32

/** A Huffman-coded set of symbols of a given length */
struct deflate_huf_symbols {
	/** Length of Huffman-coded symbols */
	uint8_t bits;
	/** Shift to normalise symbols of this length to 16 bits */
	uint8_t shift;
	/** Number of Huffman-coded symbols having this length */
	uint16_t freq;
	/** First symbol of this length (normalised to 16 bits)
	 *
	 * Stored as a 32-bit value to allow the value 0x10000 to be
	 * used for empty sets of symbols longer than the maximum
	 * utilised length.
	 */
	uint32_t start;
	/** Raw symbols having this length */
	uint16_t *raw;
};

/** A Huffman-coded alphabet */
struct deflate_alphabet {
	/** Huffman-coded symbol set for each length */
	struct deflate_huf_symbols huf[DEFLATE_HUFFMAN_BITS];
	/** Quick lookup table */
	uint8_t lookup[ 1 << DEFLATE_HUFFMAN_QL_BITS ];
	/** Raw symbols
	 *
	 * Ordered by Huffman-coded symbol length, then by symbol
	 * value.  This field has a variable length.
	 */
	uint16_t raw[0];
};

/** A static Huffman alphabet length pattern */
struct deflate_static_length_pattern {
	/** Length pair */
	uint8_t fill;
	/** Repetition count */
	uint8_t count;
} __attribute__ (( packed ));

/** Decompressor */
struct deflate {
	/** Resume point
	 *
	 * Used as the target of a computed goto to jump to the
	 * appropriate point within the state machine.
	 */
	void *resume;
	/** Format */
	enum deflate_format format;

	/** Accumulator */
	uint32_t accumulator;
	/** Bit-reversed accumulator
	 *
	 * Don't ask.
	 */
	uint32_t rotalumucca;
	/** Number of bits within the accumulator */
	unsigned int bits;

	/** Current block header */
	unsigned int header;
	/** Remaining length of data (e.g. within a literal block) */
	size_t remaining;
	/** Current length index within a set of code lengths */
	unsigned int length_index;
	/** Target length index within a set of code lengths */
	unsigned int length_target;
	/** Current length within a set of code lengths */
	unsigned int length;
	/** Number of extra bits required */
	unsigned int extra_bits;
	/** Length of a duplicated string */
	size_t dup_len;
	/** Distance of a duplicated string */
	size_t dup_distance;

	/** Literal/length Huffman alphabet */
	struct deflate_alphabet litlen;
	/** Literal/length raw symbols
	 *
	 * Must immediately follow the literal/length Huffman alphabet.
	 */
	uint16_t litlen_raw[ DEFLATE_LITLEN_MAX_CODE + 1 ];
	/** Number of symbols in the literal/length Huffman alphabet */
	unsigned int litlen_count;

	/** Distance and code length Huffman alphabet
	 *
	 * The code length Huffman alphabet has a maximum Huffman
	 * symbol length of 7 and a maximum code value of 18, and is
	 * thus strictly smaller than the distance Huffman alphabet.
	 * Since we never need both alphabets simultaneously, we can
	 * reuse the storage space for the distance alphabet to
	 * temporarily hold the code length alphabet.
	 */
	struct deflate_alphabet distance_codelen;
	/** Distance and code length raw symbols
	 *
	 * Must immediately follow the distance and code length
	 * Huffman alphabet.
	 */
	uint16_t distance_codelen_raw[ DEFLATE_DISTANCE_MAX_CODE + 1 ];
	/** Number of symbols in the distance Huffman alphabet */
	unsigned int distance_count;

	/** Huffman code lengths
	 *
	 * The literal/length and distance code lengths are
	 * constructed as a single set of lengths.
	 *
	 * The code length Huffman alphabet has a maximum code value
	 * of 18 and the set of lengths is thus strictly smaller than
	 * the combined literal/length and distance set of lengths.
	 * Since we never need both alphabets simultaneously, we can
	 * reuse the storage space for the literal/length and distance
	 * code lengths to temporarily hold the code length code
	 * lengths.
	 */
	uint8_t lengths[ ( ( DEFLATE_LITLEN_MAX_CODE + 1 ) +
			   ( DEFLATE_DISTANCE_MAX_CODE + 1 ) +
			   1 /* round up */ ) / 2 ];
};

/** A chunk of data */
struct deflate_chunk {
	/** Data */
	userptr_t data;
	/** Current offset */
	size_t offset;
	/** Length of data */
	size_t len;
};

/**
 * Initialise chunk of data
 *
 * @v chunk		Chunk of data to initialise
 * @v data		Data
 * @v offset		Starting offset
 * @v len		Length
 */
static inline __attribute__ (( always_inline )) void
deflate_chunk_init ( struct deflate_chunk *chunk, userptr_t data,
		     size_t offset, size_t len ) {

	chunk->data = data;
	chunk->offset = offset;
	chunk->len = len;
}

/**
 * Check if decompression has finished
 *
 * @v deflate		Decompressor
 * @ret finished	Decompression has finished
 */
static inline int deflate_finished ( struct deflate *deflate ) {
	return ( deflate->resume == NULL );
}

extern void deflate_init ( struct deflate *deflate,
			   enum deflate_format format );
extern int deflate_inflate ( struct deflate *deflate,
			     struct deflate_chunk *in,
			     struct deflate_chunk *out );

#endif /* _IPXE_DEFLATE_H */
