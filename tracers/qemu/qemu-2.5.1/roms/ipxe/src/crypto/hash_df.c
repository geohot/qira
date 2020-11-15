/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
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
 * Hash-based derivation function (Hash_df)
 *
 * This algorithm is designed to comply with ANS X9.82 Part 3-2007
 * Section 10.5.2.  This standard is not freely available, but most of
 * the text appears to be shared with NIST SP 800-90, which can be
 * downloaded from
 *
 *     http://csrc.nist.gov/publications/nistpubs/800-90/SP800-90revised_March2007.pdf
 *
 * Where possible, references are given to both documents.  In the
 * case of any disagreement, ANS X9.82 takes priority over NIST SP
 * 800-90.  (In particular, note that some algorithms that are
 * Approved by NIST SP 800-90 are not Approved by ANS X9.82.)
 */

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/crypto.h>
#include <ipxe/hash_df.h>

/**
 * Distribute entropy throughout a buffer
 *
 * @v hash		Underlying hash algorithm
 * @v input		Input data
 * @v input_len		Length of input data, in bytes
 * @v output		Output buffer
 * @v output_len	Length of output buffer, in bytes
 *
 * This is the Hash_df function defined in ANS X9.82 Part 3-2007
 * Section 10.5.2 (NIST SP 800-90 Section 10.4.1).
 *
 * The number of bits requested is implicit in the length of the
 * output buffer.  Requests must be for an integral number of bytes.
 *
 * The output buffer is filled incrementally with each iteration of
 * the central loop, rather than constructing an overall "temp" and
 * then taking the leftmost(no_of_bits_to_return) bits.
 *
 * There is no way for the Hash_df function to fail.  The returned
 * status SUCCESS is implicit.
 */
void hash_df ( struct digest_algorithm *hash, const void *input,
	       size_t input_len, void *output, size_t output_len ) {
	uint8_t context[hash->ctxsize];
	uint8_t digest[hash->digestsize];
	size_t frag_len;
	struct {
		uint8_t pad[3];
		uint8_t counter;
		uint32_t no_of_bits_to_return;
	} __attribute__ (( packed )) prefix;
	void *temp;
	size_t remaining;

	DBGC ( &hash_df, "HASH_DF input:\n" );
	DBGC_HDA ( &hash_df, 0, input, input_len );

	/* Sanity checks */
	assert ( input != NULL );
	assert ( output != NULL );

	/* 1.  temp = the Null string
	 * 2.  len = ceil ( no_of_bits_to_return / outlen )
	 *
	 * (Nothing to do.  We fill the output buffer incrementally,
	 * rather than constructing the complete "temp" in-memory.
	 * "len" is implicit in the number of iterations required to
	 * fill the output buffer, and so is not calculated
	 * explicitly.)
	 */

	/* 3.  counter = an 8-bit binary value representing the integer "1" */
	prefix.counter = 1;

	/* 4.  For i = 1 to len do */
	for ( temp = output, remaining = output_len ; remaining > 0 ; ) {

		/* Comment: in step 5.1 (sic), no_of_bits_to_return is
		 * used as a 32-bit string.
		 *
		 * 4.1  temp = temp || Hash ( counter || no_of_bits_to_return
		 *                            || input_string )
		 */
		prefix.no_of_bits_to_return = htonl ( output_len * 8 );
		digest_init ( hash, context );
		digest_update ( hash, context, &prefix.counter,
				( sizeof ( prefix ) -
				  offsetof ( typeof ( prefix ), counter ) ) );
		digest_update ( hash, context, input, input_len );
		digest_final ( hash, context, digest );

		/* 4.2  counter = counter + 1 */
		prefix.counter++;

		/* 5.    requested_bits = Leftmost ( no_of_bits_to_return )
		 *       of temp
		 *
		 * (We fill the output buffer incrementally.)
		 */
		frag_len = sizeof ( digest );
		if ( frag_len > remaining )
			frag_len = remaining;
		memcpy ( temp, digest, frag_len );
		temp += frag_len;
		remaining -= frag_len;
	}

	/* 6.  Return SUCCESS and requested_bits */
	DBGC ( &hash_df, "HASH_DF output:\n" );
	DBGC_HDA ( &hash_df, 0, output, output_len );
	return;
}
