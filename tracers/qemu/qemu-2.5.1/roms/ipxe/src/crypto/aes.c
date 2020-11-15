/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
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
 * AES algorithm
 *
 */

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/rotate.h>
#include <ipxe/crypto.h>
#include <ipxe/ecb.h>
#include <ipxe/cbc.h>
#include <ipxe/aes.h>

/** AES strides
 *
 * These are the strides (modulo 16) used to walk through the AES
 * input state bytes in order of byte position after [Inv]ShiftRows.
 */
enum aes_stride {
	/** Input stride for ShiftRows
	 *
	 *    0 4 8 c
	 *     \ \ \
	 *    1 5 9 d
	 *     \ \ \
	 *    2 6 a e
	 *     \ \ \
	 *    3 7 b f
	 */
	AES_STRIDE_SHIFTROWS = +5,
	/** Input stride for InvShiftRows
	 *
	 *    0 4 8 c
	 *     / / /
	 *    1 5 9 d
	 *     / / /
	 *    2 6 a e
	 *     / / /
	 *    3 7 b f
	 */
	AES_STRIDE_INVSHIFTROWS = -3,
};

/** A single AES lookup table entry
 *
 * This represents the product (in the Galois field GF(2^8)) of an
 * eight-byte vector multiplier with a single scalar multiplicand.
 *
 * The vector multipliers used for AES will be {1,1,1,3,2,1,1,3} for
 * MixColumns and {1,9,13,11,14,9,13,11} for InvMixColumns.  This
 * allows for the result of multiplying any single column of the
 * [Inv]MixColumns matrix by a scalar value to be obtained simply by
 * extracting the relevant four-byte subset from the lookup table
 * entry.
 *
 * For example, to find the result of multiplying the second column of
 * the MixColumns matrix by the scalar value 0x80:
 *
 * MixColumns column[0]: {			      2,    1,    1,    3 }
 * MixColumns column[1]: {			3,    2,    1,    1	  }
 * MixColumns column[2]: {		  1,    3,    2,    1		  }
 * MixColumns column[3]: {	    1,    1,    3,    2			  }
 * Vector multiplier:	 {    1,    1,    1,    3,    2,    1,    1,    3 }
 * Scalar multiplicand:	   0x80
 * Lookup table entry:	 { 0x80, 0x80, 0x80, 0x9b, 0x1b, 0x80, 0x80, 0x9b }
 *
 * The second column of the MixColumns matrix is {3,2,1,1}.  The
 * product of this column with the scalar value 0x80 can be obtained
 * by extracting the relevant four-byte subset of the lookup table
 * entry:
 *
 * MixColumns column[1]: {			3,    2,    1,    1	  }
 * Vector multiplier:	 {    1,    1,    1,    3,    2,    1,    1,    3 }
 * Lookup table entry:	 { 0x80, 0x80, 0x80, 0x9b, 0x1b, 0x80, 0x80, 0x9b }
 * Product:		 {		     0x9b, 0x1b, 0x80, 0x80	  }
 *
 * The column lookups require only seven bytes of the eight-byte
 * entry: the remaining (first) byte is used to hold the scalar
 * multiplicand itself (i.e. the first byte of the vector multiplier
 * is always chosen to be 1).
 */
union aes_table_entry {
	/** Viewed as an array of bytes */
	uint8_t byte[8];
} __attribute__ (( packed ));

/** An AES lookup table
 *
 * This represents the products (in the Galois field GF(2^8)) of a
 * constant eight-byte vector multiplier with all possible 256 scalar
 * multiplicands.
 *
 * The entries are indexed by the AES [Inv]SubBytes S-box output
 * values (denoted S(N)).  This allows for the result of multiplying
 * any single column of the [Inv]MixColumns matrix by S(N) to be
 * obtained simply by extracting the relevant four-byte subset from
 * the Nth table entry.  For example:
 *
 * Input byte (N):	   0x3a
 * SubBytes output S(N):   0x80
 * MixColumns column[1]: {			3,    2,    1,    1	  }
 * Vector multiplier:	 {    1,    1,    1,    3,    2,    1,    1,    3 }
 * Table entry[0x3a]:	 { 0x80, 0x80, 0x80, 0x9b, 0x1b, 0x80, 0x80, 0x9b }
 * Product:		 {		     0x9b, 0x1b, 0x80, 0x80	  }
 *
 * Since the first byte of the eight-byte vector multiplier is always
 * chosen to be 1, the value of S(N) may be lookup up by extracting
 * the first byte of the Nth table entry.
 */
struct aes_table {
	/** Table entries, indexed by S(N) */
	union aes_table_entry entry[256];
} __attribute__ (( aligned ( 8 ) ));

/** AES MixColumns lookup table */
static struct aes_table aes_mixcolumns;

/** AES InvMixColumns lookup table */
static struct aes_table aes_invmixcolumns;

/**
 * Multiply [Inv]MixColumns matrix column by scalar multiplicand
 *
 * @v entry		AES lookup table entry for scalar multiplicand
 * @v column		[Inv]MixColumns matrix column index
 * @ret product		Product of matrix column with scalar multiplicand
 */
static inline __attribute__ (( always_inline )) uint32_t
aes_entry_column ( const union aes_table_entry *entry, unsigned int column ) {
	const union {
		uint8_t byte;
		uint32_t column;
	} __attribute__ (( may_alias )) *product;

	/* Locate relevant four-byte subset */
	product = container_of ( &entry->byte[ 4 - column ],
				 typeof ( *product ), byte );

	/* Extract this four-byte subset */
	return product->column;
}

/**
 * Multiply [Inv]MixColumns matrix column by S-boxed input byte
 *
 * @v table		AES lookup table
 * @v stride		AES row shift stride
 * @v in		AES input state
 * @v offset		Output byte offset (after [Inv]ShiftRows)
 * @ret product		Product of matrix column with S(input byte)
 *
 * Note that the specified offset is not the offset of the input byte;
 * it is the offset of the output byte which corresponds to the input
 * byte.  This output byte offset is used to calculate both the input
 * byte offset and to select the appropriate matric column.
 *
 * With a compile-time constant offset, this function will optimise
 * down to a single "movzbl" (to extract the input byte) and will
 * generate a single x86 memory reference expression which can then be
 * used directly within a single "xorl" instruction.
 */
static inline __attribute__ (( always_inline )) uint32_t
aes_column ( const struct aes_table *table, size_t stride,
	     const union aes_matrix *in, size_t offset ) {
	const union aes_table_entry *entry;
	unsigned int byte;

	/* Extract input byte corresponding to this output byte offset
	 * (i.e. perform [Inv]ShiftRows).
	 */
	byte = in->byte[ ( stride * offset ) & 0xf ];

	/* Locate lookup table entry for this input byte (i.e. perform
	 * [Inv]SubBytes).
	 */
	entry = &table->entry[byte];

	/* Multiply appropriate matrix column by this input byte
	 * (i.e. perform [Inv]MixColumns).
	 */
	return aes_entry_column ( entry, ( offset & 0x3 ) );
}

/**
 * Calculate intermediate round output column
 *
 * @v table		AES lookup table
 * @v stride		AES row shift stride
 * @v in		AES input state
 * @v key		AES round key
 * @v column		Column index
 * @ret output		Output column value
 */
static inline __attribute__ (( always_inline )) uint32_t
aes_output ( const struct aes_table *table, size_t stride,
	     const union aes_matrix *in, const union aes_matrix *key,
	     unsigned int column ) {
	size_t offset = ( column * 4 );

	/* Perform [Inv]ShiftRows, [Inv]SubBytes, [Inv]MixColumns, and
	 * AddRoundKey for this column.  The loop is unrolled to allow
	 * for the required compile-time constant optimisations.
	 */
	return ( aes_column ( table, stride, in, ( offset + 0 ) ) ^
		 aes_column ( table, stride, in, ( offset + 1 ) ) ^
		 aes_column ( table, stride, in, ( offset + 2 ) ) ^
		 aes_column ( table, stride, in, ( offset + 3 ) ) ^
		 key->column[column] );
}

/**
 * Perform a single intermediate round
 *
 * @v table		AES lookup table
 * @v stride		AES row shift stride
 * @v in		AES input state
 * @v out		AES output state
 * @v key		AES round key
 */
static inline __attribute__ (( always_inline )) void
aes_round ( const struct aes_table *table, size_t stride,
	    const union aes_matrix *in, union aes_matrix *out,
	    const union aes_matrix *key ) {

	/* Perform [Inv]ShiftRows, [Inv]SubBytes, [Inv]MixColumns, and
	 * AddRoundKey for all columns.  The loop is unrolled to allow
	 * for the required compile-time constant optimisations.
	 */
	out->column[0] = aes_output ( table, stride, in, key, 0 );
	out->column[1] = aes_output ( table, stride, in, key, 1 );
	out->column[2] = aes_output ( table, stride, in, key, 2 );
	out->column[3] = aes_output ( table, stride, in, key, 3 );
}

/**
 * Perform encryption intermediate rounds
 *
 * @v in		AES input state
 * @v out		AES output state
 * @v key		Round keys
 * @v rounds		Number of rounds (must be odd)
 *
 * This function is deliberately marked as non-inlinable to ensure
 * maximal availability of registers for GCC's register allocator,
 * which has a tendency to otherwise spill performance-critical
 * registers to the stack.
 */
static __attribute__ (( noinline )) void
aes_encrypt_rounds ( union aes_matrix *in, union aes_matrix *out,
		     const union aes_matrix *key, unsigned int rounds ) {
	union aes_matrix *tmp;

	/* Perform intermediate rounds */
	do {
		/* Perform one intermediate round */
		aes_round ( &aes_mixcolumns, AES_STRIDE_SHIFTROWS,
			    in, out, key++ );

		/* Swap input and output states for next round */
		tmp = in;
		in = out;
		out = tmp;

	} while ( --rounds );
}

/**
 * Perform decryption intermediate rounds
 *
 * @v in		AES input state
 * @v out		AES output state
 * @v key		Round keys
 * @v rounds		Number of rounds (must be odd)
 *
 * As with aes_encrypt_rounds(), this function is deliberately marked
 * as non-inlinable.
 *
 * This function could potentially use the same binary code as is used
 * for encryption.  To compensate for the difference between ShiftRows
 * and InvShiftRows, half of the input byte offsets would have to be
 * modifiable at runtime (half by an offset of +4/-4, half by an
 * offset of -4/+4 for ShiftRows/InvShiftRows).  This can be
 * accomplished in x86 assembly within the number of available
 * registers, but GCC's register allocator struggles to do so,
 * resulting in a significant performance decrease due to registers
 * being spilled to the stack.  We therefore use two separate but very
 * similar binary functions based on the same C source.
 */
static __attribute__ (( noinline )) void
aes_decrypt_rounds ( union aes_matrix *in, union aes_matrix *out,
		     const union aes_matrix *key, unsigned int rounds ) {
	union aes_matrix *tmp;

	/* Perform intermediate rounds */
	do {
		/* Perform one intermediate round */
		aes_round ( &aes_invmixcolumns, AES_STRIDE_INVSHIFTROWS,
			    in, out, key++ );

		/* Swap input and output states for next round */
		tmp = in;
		in = out;
		out = tmp;

	} while ( --rounds );
}

/**
 * Perform standalone AddRoundKey
 *
 * @v state		AES state
 * @v key		AES round key
 */
static inline __attribute__ (( always_inline )) void
aes_addroundkey ( union aes_matrix *state, const union aes_matrix *key ) {

	state->column[0] ^= key->column[0];
	state->column[1] ^= key->column[1];
	state->column[2] ^= key->column[2];
	state->column[3] ^= key->column[3];
}

/**
 * Perform final round
 *
 * @v table		AES lookup table
 * @v stride		AES row shift stride
 * @v in		AES input state
 * @v out		AES output state
 * @v key		AES round key
 */
static void aes_final ( const struct aes_table *table, size_t stride,
			const union aes_matrix *in, union aes_matrix *out,
			const union aes_matrix *key ) {
	const union aes_table_entry *entry;
	unsigned int byte;
	size_t out_offset;
	size_t in_offset;

	/* Perform [Inv]ShiftRows and [Inv]SubBytes */
	for ( out_offset = 0, in_offset = 0 ; out_offset < 16 ;
	      out_offset++, in_offset = ( ( in_offset + stride ) & 0xf ) ) {

		/* Extract input byte (i.e. perform [Inv]ShiftRows) */
		byte = in->byte[in_offset];

		/* Locate lookup table entry for this input byte
		 * (i.e. perform [Inv]SubBytes).
		 */
		entry = &table->entry[byte];

		/* Store output byte */
		out->byte[out_offset] = entry->byte[0];
	}

	/* Perform AddRoundKey */
	aes_addroundkey ( out, key );
}

/**
 * Encrypt data
 *
 * @v ctx		Context
 * @v src		Data to encrypt
 * @v dst		Buffer for encrypted data
 * @v len		Length of data
 */
static void aes_encrypt ( void *ctx, const void *src, void *dst, size_t len ) {
	struct aes_context *aes = ctx;
	union aes_matrix buffer[2];
	union aes_matrix *in = &buffer[0];
	union aes_matrix *out = &buffer[1];
	unsigned int rounds = aes->rounds;

	/* Sanity check */
	assert ( len == sizeof ( *in ) );

	/* Initialise input state */
	memcpy ( in, src, sizeof ( *in ) );

	/* Perform initial round (AddRoundKey) */
	aes_addroundkey ( in, &aes->encrypt.key[0] );

	/* Perform intermediate rounds (ShiftRows, SubBytes,
	 * MixColumns, AddRoundKey).
	 */
	aes_encrypt_rounds ( in, out, &aes->encrypt.key[1], ( rounds - 2 ) );
	in = out;

	/* Perform final round (ShiftRows, SubBytes, AddRoundKey) */
	out = dst;
	aes_final ( &aes_mixcolumns, AES_STRIDE_SHIFTROWS, in, out,
		    &aes->encrypt.key[ rounds - 1 ] );
}

/**
 * Decrypt data
 *
 * @v ctx		Context
 * @v src		Data to decrypt
 * @v dst		Buffer for decrypted data
 * @v len		Length of data
 */
static void aes_decrypt ( void *ctx, const void *src, void *dst, size_t len ) {
	struct aes_context *aes = ctx;
	union aes_matrix buffer[2];
	union aes_matrix *in = &buffer[0];
	union aes_matrix *out = &buffer[1];
	unsigned int rounds = aes->rounds;

	/* Sanity check */
	assert ( len == sizeof ( *in ) );

	/* Initialise input state */
	memcpy ( in, src, sizeof ( *in ) );

	/* Perform initial round (AddRoundKey) */
	aes_addroundkey ( in, &aes->decrypt.key[0] );

	/* Perform intermediate rounds (InvShiftRows, InvSubBytes,
	 * InvMixColumns, AddRoundKey).
	 */
	aes_decrypt_rounds ( in, out, &aes->decrypt.key[1], ( rounds - 2 ) );
	in = out;

	/* Perform final round (InvShiftRows, InvSubBytes, AddRoundKey) */
	out = dst;
	aes_final ( &aes_invmixcolumns, AES_STRIDE_INVSHIFTROWS, in, out,
		    &aes->decrypt.key[ rounds - 1 ] );
}

/**
 * Multiply a polynomial by (x) modulo (x^8 + x^4 + x^3 + x^2 + 1) in GF(2^8)
 *
 * @v poly		Polynomial to be multiplied
 * @ret result		Result
 */
static __attribute__ (( const )) unsigned int aes_double ( unsigned int poly ) {

	/* Multiply polynomial by (x), placing the resulting x^8
	 * coefficient in the LSB (i.e. rotate byte left by one).
	 */
	poly = rol8 ( poly, 1 );

	/* If coefficient of x^8 (in LSB) is non-zero, then reduce by
	 * subtracting (x^8 + x^4 + x^3 + x^2 + 1) in GF(2^8).
	 */
	if ( poly & 0x01 ) {
		poly ^= 0x01; /* Subtract x^8 (currently in LSB) */
		poly ^= 0x1b; /* Subtract (x^4 + x^3 + x^2 + 1) */
	}

	return poly;
}

/**
 * Fill in MixColumns lookup table entry
 *
 * @v entry		AES lookup table entry for scalar multiplicand
 *
 * The MixColumns lookup table vector multiplier is {1,1,1,3,2,1,1,3}.
 */
static void aes_mixcolumns_entry ( union aes_table_entry *entry ) {
	unsigned int scalar_x_1;
	unsigned int scalar_x;
	unsigned int scalar;

	/* Retrieve scalar multiplicand */
	scalar = entry->byte[0];
	entry->byte[1] = scalar;
	entry->byte[2] = scalar;
	entry->byte[5] = scalar;
	entry->byte[6] = scalar;

	/* Calculate scalar multiplied by (x) */
	scalar_x = aes_double ( scalar );
	entry->byte[4] = scalar_x;

	/* Calculate scalar multiplied by (x + 1) */
	scalar_x_1 = ( scalar_x ^ scalar );
	entry->byte[3] = scalar_x_1;
	entry->byte[7] = scalar_x_1;
}

/**
 * Fill in InvMixColumns lookup table entry
 *
 * @v entry		AES lookup table entry for scalar multiplicand
 *
 * The InvMixColumns lookup table vector multiplier is {1,9,13,11,14,9,13,11}.
 */
static void aes_invmixcolumns_entry ( union aes_table_entry *entry ) {
	unsigned int scalar_x3_x2_x;
	unsigned int scalar_x3_x2_1;
	unsigned int scalar_x3_x2;
	unsigned int scalar_x3_x_1;
	unsigned int scalar_x3_1;
	unsigned int scalar_x3;
	unsigned int scalar_x2;
	unsigned int scalar_x;
	unsigned int scalar;

	/* Retrieve scalar multiplicand */
	scalar = entry->byte[0];

	/* Calculate scalar multiplied by (x) */
	scalar_x = aes_double ( scalar );

	/* Calculate scalar multiplied by (x^2) */
	scalar_x2 = aes_double ( scalar_x );

	/* Calculate scalar multiplied by (x^3) */
	scalar_x3 = aes_double ( scalar_x2 );

	/* Calculate scalar multiplied by (x^3 + 1) */
	scalar_x3_1 = ( scalar_x3 ^ scalar );
	entry->byte[1] = scalar_x3_1;
	entry->byte[5] = scalar_x3_1;

	/* Calculate scalar multiplied by (x^3 + x + 1) */
	scalar_x3_x_1 = ( scalar_x3_1 ^ scalar_x );
	entry->byte[3] = scalar_x3_x_1;
	entry->byte[7] = scalar_x3_x_1;

	/* Calculate scalar multiplied by (x^3 + x^2) */
	scalar_x3_x2 = ( scalar_x3 ^ scalar_x2 );

	/* Calculate scalar multiplied by (x^3 + x^2 + 1) */
	scalar_x3_x2_1 = ( scalar_x3_x2 ^ scalar );
	entry->byte[2] = scalar_x3_x2_1;
	entry->byte[6] = scalar_x3_x2_1;

	/* Calculate scalar multiplied by (x^3 + x^2 + x) */
	scalar_x3_x2_x = ( scalar_x3_x2 ^ scalar_x );
	entry->byte[4] = scalar_x3_x2_x;
}

/**
 * Generate AES lookup tables
 *
 */
static void aes_generate ( void ) {
	union aes_table_entry *entry;
	union aes_table_entry *inventry;
	unsigned int poly = 0x01;
	unsigned int invpoly = 0x01;
	unsigned int transformed;
	unsigned int i;

	/* Iterate over non-zero values of GF(2^8) using generator (x + 1) */
	do {

		/* Multiply polynomial by (x + 1) */
		poly ^= aes_double ( poly );

		/* Divide inverse polynomial by (x + 1).  This code
		 * fragment is taken directly from the Wikipedia page
		 * on the Rijndael S-box.  An explanation of why it
		 * works would be greatly appreciated.
		 */
		invpoly ^= ( invpoly << 1 );
		invpoly ^= ( invpoly << 2 );
		invpoly ^= ( invpoly << 4 );
		if ( invpoly & 0x80 )
			invpoly ^= 0x09;
		invpoly &= 0xff;

		/* Apply affine transformation */
		transformed = ( 0x63 ^ invpoly ^ rol8 ( invpoly, 1 ) ^
				rol8 ( invpoly, 2 ) ^ rol8 ( invpoly, 3 ) ^
				rol8 ( invpoly, 4 ) );

		/* Populate S-box (within MixColumns lookup table) */
		aes_mixcolumns.entry[poly].byte[0] = transformed;

	} while ( poly != 0x01 );

	/* Populate zeroth S-box entry (which has no inverse) */
	aes_mixcolumns.entry[0].byte[0] = 0x63;

	/* Fill in MixColumns and InvMixColumns lookup tables */
	for ( i = 0 ; i < 256 ; i++ ) {

		/* Fill in MixColumns lookup table entry */
		entry = &aes_mixcolumns.entry[i];
		aes_mixcolumns_entry ( entry );

		/* Populate inverse S-box (within InvMixColumns lookup table) */
		inventry = &aes_invmixcolumns.entry[ entry->byte[0] ];
		inventry->byte[0] = i;

		/* Fill in InvMixColumns lookup table entry */
		aes_invmixcolumns_entry ( inventry );
	}
}

/**
 * Rotate key column
 *
 * @v column		Key column
 * @ret column		Updated key column
 */
static inline __attribute__ (( always_inline )) uint32_t
aes_key_rotate ( uint32_t column ) {

	return ( ( __BYTE_ORDER == __LITTLE_ENDIAN ) ?
		 ror32 ( column, 8 ) : rol32 ( column, 8 ) );
}

/**
 * Apply S-box to key column
 *
 * @v column		Key column
 * @ret column		Updated key column
 */
static uint32_t aes_key_sbox ( uint32_t column ) {
	unsigned int i;
	uint8_t byte;

	for ( i = 0 ; i < 4 ; i++ ) {
		byte = ( column & 0xff );
		byte = aes_mixcolumns.entry[byte].byte[0];
		column = ( ( column & ~0xff ) | byte );
		column = rol32 ( column, 8 );
	}
	return column;
}

/**
 * Apply schedule round constant to key column
 *
 * @v column		Key column
 * @v rcon		Round constant
 * @ret column		Updated key column
 */
static inline __attribute__ (( always_inline )) uint32_t
aes_key_rcon ( uint32_t column, unsigned int rcon ) {

	return ( ( __BYTE_ORDER == __LITTLE_ENDIAN ) ?
		 ( column ^ rcon ) : ( column ^ ( rcon << 24 ) ) );
}

/**
 * Set key
 *
 * @v ctx		Context
 * @v key		Key
 * @v keylen		Key length
 * @ret rc		Return status code
 */
static int aes_setkey ( void *ctx, const void *key, size_t keylen ) {
	struct aes_context *aes = ctx;
	union aes_matrix *enc;
	union aes_matrix *dec;
	union aes_matrix temp;
	union aes_matrix zero;
	unsigned int rcon = 0x01;
	unsigned int rounds;
	size_t offset = 0;
	uint32_t *prev;
	uint32_t *next;
	uint32_t *end;
	uint32_t tmp;

	/* Generate lookup tables, if not already done */
	if ( ! aes_mixcolumns.entry[0].byte[0] )
		aes_generate();

	/* Validate key length and calculate number of intermediate rounds */
	switch ( keylen ) {
	case ( 128 / 8 ) :
		rounds = 11;
		break;
	case ( 192 / 8 ) :
		rounds = 13;
		break;
	case ( 256 / 8 ) :
		rounds = 15;
		break;
	default:
		DBGC ( aes, "AES %p unsupported key length (%zd bits)\n",
		       aes, ( keylen * 8 ) );
		return -EINVAL;
	}
	aes->rounds = rounds;
	enc = aes->encrypt.key;
	end = enc[rounds].column;

	/* Copy raw key */
	memcpy ( enc, key, keylen );
	prev = enc->column;
	next = ( ( ( void * ) prev ) + keylen );
	tmp = next[-1];

	/* Construct expanded key */
	while ( next < end ) {

		/* If this is the first column of an expanded key
		 * block, or the middle column of an AES-256 key
		 * block, then apply the S-box.
		 */
		if ( ( offset == 0 ) || ( ( offset | keylen ) == 48 ) )
			tmp = aes_key_sbox ( tmp );

		/* If this is the first column of an expanded key
		 * block then rotate and apply the round constant.
		 */
		if ( offset == 0 ) {
			tmp = aes_key_rotate ( tmp );
			tmp = aes_key_rcon ( tmp, rcon );
			rcon = aes_double ( rcon );
		}

		/* XOR with previous key column */
		tmp ^= *prev;

		/* Store column */
		*next = tmp;

		/* Move to next column */
		offset += sizeof ( *next );
		if ( offset == keylen )
			offset = 0;
		next++;
		prev++;
	}
	DBGC2 ( aes, "AES %p expanded %zd-bit key:\n", aes, ( keylen * 8 ) );
	DBGC2_HDA ( aes, 0, &aes->encrypt, ( rounds * sizeof ( *enc ) ) );

	/* Convert to decryption key */
	memset ( &zero, 0, sizeof ( zero ) );
	dec = &aes->decrypt.key[ rounds - 1 ];
	memcpy ( dec--, enc++, sizeof ( *dec ) );
	while ( dec > aes->decrypt.key ) {
		/* Perform InvMixColumns (by reusing the encryption
		 * final-round code to perform ShiftRows+SubBytes and
		 * reusing the decryption intermediate-round code to
		 * perform InvShiftRows+InvSubBytes+InvMixColumns, all
		 * with a zero encryption key).
		 */
		aes_final ( &aes_mixcolumns, AES_STRIDE_SHIFTROWS,
			    enc++, &temp, &zero );
		aes_decrypt_rounds ( &temp, dec--, &zero, 1 );
	}
	memcpy ( dec--, enc++, sizeof ( *dec ) );
	DBGC2 ( aes, "AES %p inverted %zd-bit key:\n", aes, ( keylen * 8 ) );
	DBGC2_HDA ( aes, 0, &aes->decrypt, ( rounds * sizeof ( *dec ) ) );

	return 0;
}

/**
 * Set initialisation vector
 *
 * @v ctx		Context
 * @v iv		Initialisation vector
 */
static void aes_setiv ( void *ctx __unused, const void *iv __unused ) {
	/* Nothing to do */
}

/** Basic AES algorithm */
struct cipher_algorithm aes_algorithm = {
	.name = "aes",
	.ctxsize = sizeof ( struct aes_context ),
	.blocksize = AES_BLOCKSIZE,
	.setkey = aes_setkey,
	.setiv = aes_setiv,
	.encrypt = aes_encrypt,
	.decrypt = aes_decrypt,
};

/* AES in Electronic Codebook mode */
ECB_CIPHER ( aes_ecb, aes_ecb_algorithm,
	     aes_algorithm, struct aes_context, AES_BLOCKSIZE );

/* AES in Cipher Block Chaining mode */
CBC_CIPHER ( aes_cbc, aes_cbc_algorithm,
	     aes_algorithm, struct aes_context, AES_BLOCKSIZE );
