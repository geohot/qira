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

#include <string.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <ipxe/uaccess.h>
#include <ipxe/deflate.h>

/** @file
 *
 * DEFLATE decompression algorithm
 *
 * This file implements the decompression half of the DEFLATE
 * algorithm specified in RFC 1951.
 *
 * Portions of this code are derived from wimboot's xca.c.
 *
 */

/**
 * Byte reversal table
 *
 * For some insane reason, the DEFLATE format stores some values in
 * bit-reversed order.
 */
static uint8_t deflate_reverse[256];

/** Literal/length base values
 *
 * We include entries only for literal/length codes 257-284.  Code 285
 * does not fit the pattern (it represents a length of 258; following
 * the pattern from the earlier codes would give a length of 259), and
 * has no extra bits.  Codes 286-287 are invalid, but can occur.  We
 * treat any code greater than 284 as meaning "length 285, no extra
 * bits".
 */
static uint8_t deflate_litlen_base[28];

/** Distance base values
 *
 * We include entries for all possible codes 0-31, avoiding the need
 * to check for undefined codes 30 and 31 before performing the
 * lookup.  Codes 30 and 31 are never initialised, and will therefore
 * be treated as meaning "14 extra bits, base distance 0".
 */
static uint16_t deflate_distance_base[32];

/** Code length map */
static uint8_t deflate_codelen_map[19] = {
	16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

/** Static Huffman alphabet length patterns */
static struct deflate_static_length_pattern deflate_static_length_patterns[] = {
	/* Literal/length code lengths */
	{ 0x88, ( ( ( 143 -   0 ) + 1 ) / 2 ) },
	{ 0x99, ( ( ( 255 - 144 ) + 1 ) / 2 ) },
	{ 0x77, ( ( ( 279 - 256 ) + 1 ) / 2 ) },
	{ 0x88, ( ( ( 287 - 280 ) + 1 ) / 2 ) },
	/* Distance code lengths */
	{ 0x55, ( ( (  31 -   0 ) + 1 ) / 2 ) },
	/* End marker */
	{ 0, 0 }
};

/**
 * Transcribe binary value (for debugging)
 *
 * @v value		Value
 * @v bits		Length of value (in bits)
 * @ret string		Transcribed value
 */
static const char * deflate_bin ( unsigned long value, unsigned int bits ) {
	static char buf[ ( 8 * sizeof ( value ) ) + 1 /* NUL */ ];
	char *out = buf;

	/* Sanity check */
	assert ( bits < sizeof ( buf ) );

	/* Transcribe value */
	while ( bits-- )
		*(out++) = ( ( value & ( 1 << bits ) ) ? '1' : '0' );
	*out = '\0';

	return buf;
}

/**
 * Set Huffman symbol length
 *
 * @v deflate		Decompressor
 * @v index		Index within lengths
 * @v bits		Symbol length (in bits)
 */
static void deflate_set_length ( struct deflate *deflate, unsigned int index,
				 unsigned int bits ) {

	deflate->lengths[ index / 2 ] |= ( bits << ( 4 * ( index % 2 ) ) );
}

/**
 * Get Huffman symbol length
 *
 * @v deflate		Decompressor
 * @v index		Index within lengths
 * @ret bits		Symbol length (in bits)
 */
static unsigned int deflate_length ( struct deflate *deflate,
				     unsigned int index ) {

	return ( ( deflate->lengths[ index / 2 ] >> ( 4 * ( index % 2 ) ) )
		 & 0x0f );
}

/**
 * Determine Huffman alphabet name (for debugging)
 *
 * @v deflate		Decompressor
 * @v alphabet		Huffman alphabet
 * @ret name		Alphabet name
 */
static const char * deflate_alphabet_name ( struct deflate *deflate,
					    struct deflate_alphabet *alphabet ){

	if ( alphabet == &deflate->litlen ) {
		return "litlen";
	} else if ( alphabet == &deflate->distance_codelen ) {
		return "distance/codelen";
	} else {
		return "<UNKNOWN>";
	}
}

/**
 * Dump Huffman alphabet (for debugging)
 *
 * @v deflate		Decompressor
 * @v alphabet		Huffman alphabet
 */
static void deflate_dump_alphabet ( struct deflate *deflate,
				    struct deflate_alphabet *alphabet ) {
	struct deflate_huf_symbols *huf_sym;
	unsigned int bits;
	unsigned int huf;
	unsigned int i;

	/* Do nothing unless debugging is enabled */
	if ( ! DBG_EXTRA )
		return;

	/* Dump symbol table for each utilised length */
	for ( bits = 1 ; bits <= ( sizeof ( alphabet->huf ) /
				   sizeof ( alphabet->huf[0] ) ) ; bits++ ) {
		huf_sym = &alphabet->huf[ bits - 1 ];
		if ( huf_sym->freq == 0 )
			continue;
		huf = ( huf_sym->start >> huf_sym->shift );
		DBGC2 ( alphabet, "DEFLATE %p \"%s\" length %d start \"%s\" "
			"freq %d:", deflate,
			deflate_alphabet_name ( deflate, alphabet ), bits,
			deflate_bin ( huf, huf_sym->bits ), huf_sym->freq );
		for ( i = 0 ; i < huf_sym->freq ; i++ ) {
			DBGC2 ( alphabet, " %03x",
				huf_sym->raw[ huf + i ] );
		}
		DBGC2 ( alphabet, "\n" );
	}

	/* Dump quick lookup table */
	DBGC2 ( alphabet, "DEFLATE %p \"%s\" quick lookup:", deflate,
		deflate_alphabet_name ( deflate, alphabet ) );
	for ( i = 0 ; i < ( sizeof ( alphabet->lookup ) /
			    sizeof ( alphabet->lookup[0] ) ) ; i++ ) {
		DBGC2 ( alphabet, " %d", ( alphabet->lookup[i] + 1 ) );
	}
	DBGC2 ( alphabet, "\n" );
}

/**
 * Construct Huffman alphabet
 *
 * @v deflate		Decompressor
 * @v alphabet		Huffman alphabet
 * @v count		Number of symbols
 * @v offset		Starting offset within length table
 * @ret rc		Return status code
 */
static int deflate_alphabet ( struct deflate *deflate,
			      struct deflate_alphabet *alphabet,
			      unsigned int count, unsigned int offset ) {
	struct deflate_huf_symbols *huf_sym;
	unsigned int huf;
	unsigned int cum_freq;
	unsigned int bits;
	unsigned int raw;
	unsigned int adjustment;
	unsigned int prefix;
	int complete;

	/* Clear symbol table */
	memset ( alphabet->huf, 0, sizeof ( alphabet->huf ) );

	/* Count number of symbols with each Huffman-coded length */
	for ( raw = 0 ; raw < count ; raw++ ) {
		bits = deflate_length ( deflate, ( raw + offset ) );
		if ( bits )
			alphabet->huf[ bits - 1 ].freq++;
	}

	/* Populate Huffman-coded symbol table */
	huf = 0;
	cum_freq = 0;
	for ( bits = 1 ; bits <= ( sizeof ( alphabet->huf ) /
				   sizeof ( alphabet->huf[0] ) ) ; bits++ ) {
		huf_sym = &alphabet->huf[ bits - 1 ];
		huf_sym->bits = bits;
		huf_sym->shift = ( 16 - bits );
		huf_sym->start = ( huf << huf_sym->shift );
		huf_sym->raw = &alphabet->raw[cum_freq];
		huf += huf_sym->freq;
		if ( huf > ( 1U << bits ) ) {
			DBGC ( alphabet, "DEFLATE %p \"%s\" has too many "
			       "symbols with lengths <=%d\n", deflate,
			       deflate_alphabet_name ( deflate, alphabet ),
			       bits );
			return -EINVAL;
		}
		huf <<= 1;
		cum_freq += huf_sym->freq;
	}
	complete = ( huf == ( 1U << bits ) );

	/* Populate raw symbol table */
	for ( raw = 0 ; raw < count ; raw++ ) {
		bits = deflate_length ( deflate, ( raw + offset ) );
		if ( bits ) {
			huf_sym = &alphabet->huf[ bits - 1 ];
			*(huf_sym->raw++) = raw;
		}
	}

	/* Adjust Huffman-coded symbol table raw pointers and populate
	 * quick lookup table.
	 */
	for ( bits = 1 ; bits <= ( sizeof ( alphabet->huf ) /
				   sizeof ( alphabet->huf[0] ) ) ; bits++ ) {
		huf_sym = &alphabet->huf[ bits - 1 ];

		/* Adjust raw pointer */
		huf_sym->raw -= huf_sym->freq; /* Reset to first symbol */
		adjustment = ( huf_sym->start >> huf_sym->shift );
		huf_sym->raw -= adjustment; /* Adjust for quick indexing */

		/* Populate quick lookup table */
		for ( prefix = ( huf_sym->start >> DEFLATE_HUFFMAN_QL_SHIFT ) ;
		      prefix < ( 1 << DEFLATE_HUFFMAN_QL_BITS ) ; prefix++ ) {
			alphabet->lookup[prefix] = ( bits - 1 );
		}
	}

	/* Dump alphabet (for debugging) */
	deflate_dump_alphabet ( deflate, alphabet );

	/* Check that there are no invalid codes */
	if ( ! complete ) {
		DBGC ( alphabet, "DEFLATE %p \"%s\" is incomplete\n", deflate,
		       deflate_alphabet_name ( deflate, alphabet ) );
		return -EINVAL;
	}

	return 0;
}

/**
 * Attempt to accumulate bits from input stream
 *
 * @v deflate		Decompressor
 * @v in		Compressed input data
 * @v target		Number of bits to accumulate
 * @ret excess		Number of excess bits accumulated (may be negative)
 */
static int deflate_accumulate ( struct deflate *deflate,
				struct deflate_chunk *in,
				unsigned int target ) {
	uint8_t byte;

	while ( deflate->bits < target ) {

		/* Check for end of input */
		if ( in->offset >= in->len )
			break;

		/* Acquire byte from input */
		copy_from_user ( &byte, in->data, in->offset++,
				 sizeof ( byte ) );
		deflate->accumulator = ( deflate->accumulator |
					 ( byte << deflate->bits ) );
		deflate->rotalumucca = ( deflate->rotalumucca |
					 ( deflate_reverse[byte] <<
					   ( 24 - deflate->bits ) ) );
		deflate->bits += 8;

		/* Sanity check */
		assert ( deflate->bits <=
			 ( 8 * sizeof ( deflate->accumulator ) ) );
	}

	return ( deflate->bits - target );
}

/**
 * Consume accumulated bits from the input stream
 *
 * @v deflate		Decompressor
 * @v count		Number of accumulated bits to consume
 * @ret data		Consumed bits
 */
static int deflate_consume ( struct deflate *deflate, unsigned int count ) {
	int data;

	/* Sanity check */
	assert ( count <= deflate->bits );

	/* Extract data and consume bits */
	data = ( deflate->accumulator & ( ( 1 << count ) - 1 ) );
	deflate->accumulator >>= count;
	deflate->rotalumucca <<= count;
	deflate->bits -= count;

	return data;
}

/**
 * Attempt to extract a fixed number of bits from input stream
 *
 * @v deflate		Decompressor
 * @v in		Compressed input data
 * @v target		Number of bits to extract
 * @ret data		Extracted bits (or negative if not yet accumulated)
 */
static int deflate_extract ( struct deflate *deflate, struct deflate_chunk *in,
			     unsigned int target ) {
	int excess;
	int data;

	/* Return immediately if we are attempting to extract zero bits */
	if ( target == 0 )
		return 0;

	/* Attempt to accumulate bits */
	excess = deflate_accumulate ( deflate, in, target );
	if ( excess < 0 )
		return excess;

	/* Extract data and consume bits */
	data = deflate_consume ( deflate, target );
	DBGCP ( deflate, "DEFLATE %p extracted %s = %#x = %d\n", deflate,
		deflate_bin ( data, target ), data, data );

	return data;
}

/**
 * Attempt to decode a Huffman-coded symbol from input stream
 *
 * @v deflate		Decompressor
 * @v in		Compressed input data
 * @v alphabet		Huffman alphabet
 * @ret code		Raw code (or negative if not yet accumulated)
 */
static int deflate_decode ( struct deflate *deflate,
			    struct deflate_chunk *in,
			    struct deflate_alphabet *alphabet ) {
	struct deflate_huf_symbols *huf_sym;
	uint16_t huf;
	unsigned int lookup_index;
	int excess;
	unsigned int raw;

	/* Attempt to accumulate maximum required number of bits.
	 * There may be fewer bits than this remaining in the stream,
	 * even if the stream still contains some complete
	 * Huffman-coded symbols.
	 */
	deflate_accumulate ( deflate, in, DEFLATE_HUFFMAN_BITS );

	/* Normalise the bit-reversed accumulated value to 16 bits */
	huf = ( deflate->rotalumucca >> 16 );

	/* Find symbol set for this length */
	lookup_index = ( huf >> DEFLATE_HUFFMAN_QL_SHIFT );
	huf_sym = &alphabet->huf[ alphabet->lookup[ lookup_index ] ];
	while ( huf < huf_sym->start )
		huf_sym--;

	/* Calculate number of excess bits, and return if not yet complete */
	excess = ( deflate->bits - huf_sym->bits );
	if ( excess < 0 )
		return excess;

	/* Consume bits */
	deflate_consume ( deflate, huf_sym->bits );

	/* Look up raw symbol */
	raw = huf_sym->raw[ huf >> huf_sym->shift ];
	DBGCP ( deflate, "DEFLATE %p decoded %s = %#x = %d\n", deflate,
		deflate_bin ( ( huf >> huf_sym->shift ), huf_sym->bits ),
		raw, raw );

	return raw;
}

/**
 * Discard bits up to the next byte boundary
 *
 * @v deflate		Decompressor
 */
static void deflate_discard_to_byte ( struct deflate *deflate ) {

	deflate_consume ( deflate, ( deflate->bits & 7 ) );
}

/**
 * Copy data to output buffer (if available)
 *
 * @v out		Output data buffer
 * @v start		Source data
 * @v offset		Starting offset within source data
 * @v len		Length to copy
 */
static void deflate_copy ( struct deflate_chunk *out,
			   userptr_t start, size_t offset, size_t len ) {
	size_t out_offset = out->offset;
	size_t copy_len;

	/* Copy data one byte at a time, to allow for overlap */
	if ( out_offset < out->len ) {
		copy_len = ( out->len - out_offset );
		if ( copy_len > len )
			copy_len = len;
		while ( copy_len-- ) {
			memcpy_user ( out->data, out_offset++,
				      start, offset++, 1 );
		}
	}
	out->offset += len;
}

/**
 * Inflate compressed data
 *
 * @v deflate		Decompressor
 * @v in		Compressed input data
 * @v out		Output data buffer
 * @ret rc		Return status code
 *
 * The caller can use deflate_finished() to determine whether a
 * successful return indicates that the decompressor is merely waiting
 * for more input.
 *
 * Data will not be written beyond the specified end of the output
 * data buffer, but the offset within the output data buffer will be
 * updated to reflect the amount that should have been written.  The
 * caller can use this to find the length of the decompressed data
 * before allocating the output data buffer.
 */
int deflate_inflate ( struct deflate *deflate,
		      struct deflate_chunk *in,
		      struct deflate_chunk *out ) {

	/* This could be implemented more neatly if gcc offered a
	 * means for enforcing tail recursion.
	 */
	if ( deflate->resume ) {
		goto *(deflate->resume);
	} else switch ( deflate->format ) {
		case DEFLATE_RAW:	goto block_header;
		case DEFLATE_ZLIB:	goto zlib_header;
		default:		assert ( 0 );
	}

 zlib_header: {
		int header;
		int cm;

		/* Extract header */
		header = deflate_extract ( deflate, in, ZLIB_HEADER_BITS );
		if ( header < 0 ) {
			deflate->resume = &&zlib_header;
			return 0;
		}

		/* Parse header */
		cm = ( ( header >> ZLIB_HEADER_CM_LSB ) & ZLIB_HEADER_CM_MASK );
		if ( cm != ZLIB_HEADER_CM_DEFLATE ) {
			DBGC ( deflate, "DEFLATE %p unsupported ZLIB "
			       "compression method %d\n", deflate, cm );
			return -ENOTSUP;
		}
		if ( header & ( 1 << ZLIB_HEADER_FDICT_BIT ) ) {
			DBGC ( deflate, "DEFLATE %p unsupported ZLIB preset "
			       "dictionary\n", deflate );
			return -ENOTSUP;
		}

		/* Process first block header */
		goto block_header;
	}

 block_header: {
		int header;
		int bfinal;
		int btype;

		/* Extract block header */
		header = deflate_extract ( deflate, in, DEFLATE_HEADER_BITS );
		if ( header < 0 ) {
			deflate->resume = &&block_header;
			return 0;
		}

		/* Parse header */
		deflate->header = header;
		bfinal = ( header & ( 1 << DEFLATE_HEADER_BFINAL_BIT ) );
		btype = ( header >> DEFLATE_HEADER_BTYPE_LSB );
		DBGC ( deflate, "DEFLATE %p found %sblock type %#x\n",
		       deflate, ( bfinal ? "final " : "" ), btype );
		switch ( btype ) {
		case DEFLATE_HEADER_BTYPE_LITERAL:
			goto literal_block;
		case DEFLATE_HEADER_BTYPE_STATIC:
			goto static_block;
		case DEFLATE_HEADER_BTYPE_DYNAMIC:
			goto dynamic_block;
		default:
			DBGC ( deflate, "DEFLATE %p unsupported block type "
			       "%#x\n", deflate, btype );
			return -ENOTSUP;
		}
	}

 literal_block: {

		/* Discard any bits up to the next byte boundary */
		deflate_discard_to_byte ( deflate );
	}

 literal_len: {
		int len;

		/* Extract LEN field */
		len = deflate_extract ( deflate, in, DEFLATE_LITERAL_LEN_BITS );
		if ( len < 0 ) {
			deflate->resume = &&literal_len;
			return 0;
		}

		/* Record length of literal data */
		deflate->remaining = len;
		DBGC2 ( deflate, "DEFLATE %p literal block length %#04zx\n",
			deflate, deflate->remaining );
	}

 literal_nlen: {
		int nlen;

		/* Extract NLEN field */
		nlen = deflate_extract ( deflate, in, DEFLATE_LITERAL_LEN_BITS);
		if ( nlen < 0 ) {
			deflate->resume = &&literal_nlen;
			return 0;
		}

		/* Verify NLEN */
		if ( ( ( deflate->remaining ^ ~nlen ) &
		       ( ( 1 << DEFLATE_LITERAL_LEN_BITS ) - 1 ) ) != 0 ) {
			DBGC ( deflate, "DEFLATE %p invalid len/nlen "
			       "%#04zx/%#04x\n", deflate,
			       deflate->remaining, nlen );
			return -EINVAL;
		}
	}

 literal_data: {
		size_t in_remaining;
		size_t len;

		/* Calculate available amount of literal data */
		in_remaining = ( in->len - in->offset );
		len = deflate->remaining;
		if ( len > in_remaining )
			len = in_remaining;

		/* Copy data to output buffer */
		deflate_copy ( out, in->data, in->offset, len );

		/* Consume data from input buffer */
		in->offset += len;
		deflate->remaining -= len;

		/* Finish processing if we are blocked */
		if ( deflate->remaining ) {
			deflate->resume = &&literal_data;
			return 0;
		}

		/* Otherwise, finish block */
		goto block_done;
	}

 static_block: {
		struct deflate_static_length_pattern *pattern;
		uint8_t *lengths = deflate->lengths;

		/* Construct static Huffman lengths as per RFC 1950 */
		for ( pattern = deflate_static_length_patterns ;
		      pattern->count ; pattern++ ) {
			memset ( lengths, pattern->fill, pattern->count );
			lengths += pattern->count;
		}
		deflate->litlen_count = 288;
		deflate->distance_count = 32;
		goto construct_alphabets;
	}

 dynamic_block:

 dynamic_header: {
		int header;
		unsigned int hlit;
		unsigned int hdist;
		unsigned int hclen;

		/* Extract block header */
		header = deflate_extract ( deflate, in, DEFLATE_DYNAMIC_BITS );
		if ( header < 0 ) {
			deflate->resume = &&dynamic_header;
			return 0;
		}

		/* Parse header */
		hlit = ( ( header >> DEFLATE_DYNAMIC_HLIT_LSB ) &
			 DEFLATE_DYNAMIC_HLIT_MASK );
		hdist = ( ( header >> DEFLATE_DYNAMIC_HDIST_LSB ) &
			  DEFLATE_DYNAMIC_HDIST_MASK );
		hclen = ( ( header >> DEFLATE_DYNAMIC_HCLEN_LSB ) &
			  DEFLATE_DYNAMIC_HCLEN_MASK );
		deflate->litlen_count = ( hlit + 257 );
		deflate->distance_count = ( hdist + 1 );
		deflate->length_index = 0;
		deflate->length_target = ( hclen + 4 );
		DBGC2 ( deflate, "DEFLATE %p dynamic block %d codelen, %d "
			"litlen, %d distance\n", deflate,
			deflate->length_target, deflate->litlen_count,
			deflate->distance_count );

		/* Prepare for decoding code length code lengths */
		memset ( &deflate->lengths, 0, sizeof ( deflate->lengths ) );
	}

 dynamic_codelen: {
		int len;
		unsigned int index;
		int rc;

		/* Extract all code lengths */
		while ( deflate->length_index < deflate->length_target ) {

			/* Extract code length length */
			len = deflate_extract ( deflate, in,
						DEFLATE_CODELEN_BITS );
			if ( len < 0 ) {
				deflate->resume = &&dynamic_codelen;
				return 0;
			}

			/* Store code length */
			index = deflate_codelen_map[deflate->length_index++];
			deflate_set_length ( deflate, index, len );
			DBGCP ( deflate, "DEFLATE %p codelen for %d is %d\n",
				deflate, index, len );
		}

		/* Generate code length alphabet */
		if ( ( rc = deflate_alphabet ( deflate,
					       &deflate->distance_codelen,
					       ( DEFLATE_CODELEN_MAX_CODE + 1 ),
					       0 ) ) != 0 )
			return rc;

		/* Prepare for decoding literal/length/distance code lengths */
		memset ( &deflate->lengths, 0, sizeof ( deflate->lengths ) );
		deflate->length_index = 0;
		deflate->length_target = ( deflate->litlen_count +
					   deflate->distance_count );
		deflate->length = 0;
	}

 dynamic_litlen_distance: {
		int len;
		int index;

		/* Decode literal/length/distance code length */
		len = deflate_decode ( deflate, in, &deflate->distance_codelen);
		if ( len < 0 ) {
			deflate->resume = &&dynamic_litlen_distance;
			return 0;
		}

		/* Prepare for extra bits */
		if ( len < 16 ) {
			deflate->length = len;
			deflate->extra_bits = 0;
			deflate->dup_len = 1;
		} else {
			static const uint8_t dup_len[3] = { 3, 3, 11 };
			static const uint8_t extra_bits[3] = { 2, 3, 7 };
			index = ( len - 16 );
			deflate->dup_len = dup_len[index];
			deflate->extra_bits = extra_bits[index];
			if ( index )
				deflate->length = 0;
		}
	}

 dynamic_litlen_distance_extra: {
		int extra;
		unsigned int dup_len;

		/* Extract extra bits */
		extra = deflate_extract ( deflate, in, deflate->extra_bits );
		if ( extra < 0 ) {
			deflate->resume = &&dynamic_litlen_distance_extra;
			return 0;
		}

		/* Store code lengths */
		dup_len = ( deflate->dup_len + extra );
		while ( ( deflate->length_index < deflate->length_target ) &&
			dup_len-- ) {
			deflate_set_length ( deflate, deflate->length_index++,
					     deflate->length );
		}

		/* Process next literal/length or distance code
		 * length, if more are required.
		 */
		if ( deflate->length_index < deflate->length_target )
			goto dynamic_litlen_distance;

		/* Construct alphabets */
		goto construct_alphabets;
	}

 construct_alphabets: {
		unsigned int distance_offset = deflate->litlen_count;
		unsigned int distance_count = deflate->distance_count;
		int rc;

		/* Generate literal/length alphabet */
		if ( ( rc = deflate_alphabet ( deflate, &deflate->litlen,
					       deflate->litlen_count, 0 ) ) !=0)
			return rc;

		/* Handle degenerate case of a single distance code
		 * (for which it is impossible to construct a valid,
		 * complete Huffman alphabet).  RFC 1951 states:
		 *
		 *   If only one distance code is used, it is encoded
		 *   using one bit, not zero bits; in this case there
		 *   is a single code length of one, with one unused
		 *   code.  One distance code of zero bits means that
		 *   there are no distance codes used at all (the data
		 *   is all literals).
		 *
		 * If we have only a single distance code, then we
		 * instead use two distance codes both with length 1.
		 * This results in a valid Huffman alphabet.  The code
		 * "0" will mean distance code 0 (which is either
		 * correct or irrelevant), and the code "1" will mean
		 * distance code 1 (which is always irrelevant).
		 */
		if ( deflate->distance_count == 1 ) {

			deflate->lengths[0] = 0x11;
			distance_offset = 0;
			distance_count = 2;
		}

		/* Generate distance alphabet */
		if ( ( rc = deflate_alphabet ( deflate,
					       &deflate->distance_codelen,
					       distance_count,
					       distance_offset ) ) != 0 )
			return rc;
	}

 lzhuf_litlen: {
		int code;
		uint8_t byte;
		unsigned int extra;
		unsigned int bits;

		/* Decode Huffman codes */
		while ( 1 ) {

			/* Decode Huffman code */
			code = deflate_decode ( deflate, in, &deflate->litlen );
			if ( code < 0 ) {
				deflate->resume = &&lzhuf_litlen;
				return 0;
			}

			/* Handle according to code type */
			if ( code < DEFLATE_LITLEN_END ) {

				/* Literal value: copy to output buffer */
				byte = code;
				DBGCP ( deflate, "DEFLATE %p literal %#02x "
					"('%c')\n", deflate, byte,
					( isprint ( byte ) ? byte : '.' ) );
				deflate_copy ( out, virt_to_user ( &byte ), 0,
					       sizeof ( byte ) );

			} else if ( code == DEFLATE_LITLEN_END ) {

				/* End of block */
				goto block_done;

			} else {

				/* Length code: process extra bits */
				extra = ( code - DEFLATE_LITLEN_END - 1 );
				if ( extra < 28 ) {
					bits = ( extra / 4 );
					if ( bits )
						bits--;
					deflate->extra_bits = bits;
					deflate->dup_len =
						deflate_litlen_base[extra];
				} else {
					deflate->extra_bits = 0;
					deflate->dup_len = 258;
				}
				goto lzhuf_litlen_extra;
			}
		}
	}

 lzhuf_litlen_extra: {
		int extra;

		/* Extract extra bits */
		extra = deflate_extract ( deflate, in, deflate->extra_bits );
		if ( extra < 0 ) {
			deflate->resume = &&lzhuf_litlen_extra;
			return 0;
		}

		/* Update duplicate length */
		deflate->dup_len += extra;
	}

 lzhuf_distance: {
		int code;
		unsigned int extra;
		unsigned int bits;

		/* Decode Huffman code */
		code = deflate_decode ( deflate, in,
					&deflate->distance_codelen );
		if ( code < 0 ) {
			deflate->resume = &&lzhuf_distance;
			return 0;
		}

		/* Process extra bits */
		extra = code;
		bits = ( extra / 2 );
		if ( bits )
			bits--;
		deflate->extra_bits = bits;
		deflate->dup_distance = deflate_distance_base[extra];
	}

 lzhuf_distance_extra: {
		int extra;
		size_t dup_len;
		size_t dup_distance;

		/* Extract extra bits */
		extra = deflate_extract ( deflate, in, deflate->extra_bits );
		if ( extra < 0 ) {
			deflate->resume = &&lzhuf_distance_extra;
			return 0;
		}

		/* Update duplicate distance */
		dup_distance = ( deflate->dup_distance + extra );
		dup_len = deflate->dup_len;
		DBGCP ( deflate, "DEFLATE %p duplicate length %zd distance "
			"%zd\n", deflate, dup_len, dup_distance );

		/* Sanity check */
		if ( dup_distance > out->offset ) {
			DBGC ( deflate, "DEFLATE %p bad distance %zd (max "
			       "%zd)\n", deflate, dup_distance, out->offset );
			return -EINVAL;
		}

		/* Copy data, allowing for overlap */
		deflate_copy ( out, out->data, ( out->offset - dup_distance ),
			       dup_len );

		/* Process next literal/length symbol */
		goto lzhuf_litlen;
	}

 block_done: {

		DBGCP ( deflate, "DEFLATE %p end of block\n", deflate );

		/* If this was not the final block, process next block header */
		if ( ! ( deflate->header & ( 1 << DEFLATE_HEADER_BFINAL_BIT ) ))
			goto block_header;

		/* Otherwise, process footer (if any) */
		switch ( deflate->format ) {
		case DEFLATE_RAW:	goto finished;
		case DEFLATE_ZLIB:	goto zlib_footer;
		default:		assert ( 0 );
		}
	}

 zlib_footer: {

		/* Discard any bits up to the next byte boundary */
		deflate_discard_to_byte ( deflate );
	}

 zlib_adler32: {
		int excess;

		/* Accumulate the 32 bits of checksum.  We don't check
		 * the value, stop processing immediately afterwards,
		 * and so don't have to worry about the nasty corner
		 * cases involved in calling deflate_extract() to
		 * obtain a full 32 bits.
		 */
		excess = deflate_accumulate ( deflate, in, ZLIB_ADLER32_BITS );
		if ( excess < 0 ) {
			deflate->resume = &&zlib_adler32;
			return 0;
		}

		/* Finish processing */
		goto finished;
	}

 finished: {
		/* Mark as finished and terminate */
		DBGCP ( deflate, "DEFLATE %p finished\n", deflate );
		deflate->resume = NULL;
		return 0;
	}
}

/**
 * Initialise decompressor
 *
 * @v deflate		Decompressor
 * @v format		Compression format code
 */
void deflate_init ( struct deflate *deflate, enum deflate_format format ) {
	static int global_init_done;
	uint8_t i;
	uint8_t bit;
	uint8_t byte;
	unsigned int base;
	unsigned int bits;

	/* Perform global initialisation if required */
	if ( ! global_init_done ) {

		/* Initialise byte reversal table */
		for ( i = 255 ; i ; i-- ) {
			for ( bit = 1, byte = 0 ; bit ; bit <<= 1 ) {
				byte <<= 1;
				if ( i & bit )
					byte |= 1;
			}
			deflate_reverse[i] = byte;
		}

		/* Initialise literal/length extra bits table */
		base = 3;
		for ( i = 0 ; i < 28 ; i++ ) {
			bits = ( i / 4 );
			if ( bits )
				bits--;
			deflate_litlen_base[i] = base;
			base += ( 1 << bits );
		}
		assert ( base == 259 ); /* sic */

		/* Initialise distance extra bits table */
		base = 1;
		for ( i = 0 ; i < 30 ; i++ ) {
			bits = ( i / 2 );
			if ( bits )
				bits--;
			deflate_distance_base[i] = base;
			base += ( 1 << bits );
		}
		assert ( base == 32769 );

		/* Record global initialisation as complete */
		global_init_done = 1;
	}

	/* Initialise structure */
	memset ( deflate, 0, sizeof ( *deflate ) );
	deflate->format = format;
}
