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
 * SHA-512 algorithm
 *
 */

#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include <assert.h>
#include <ipxe/rotate.h>
#include <ipxe/crypto.h>
#include <ipxe/asn1.h>
#include <ipxe/sha512.h>

/** SHA-512 variables */
struct sha512_variables {
	/* This layout matches that of struct sha512_digest_data,
	 * allowing for efficient endianness-conversion,
	 */
	uint64_t a;
	uint64_t b;
	uint64_t c;
	uint64_t d;
	uint64_t e;
	uint64_t f;
	uint64_t g;
	uint64_t h;
	uint64_t w[SHA512_ROUNDS];
} __attribute__ (( packed ));

/** SHA-512 constants */
static const uint64_t k[SHA512_ROUNDS] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
	0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
	0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
	0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
	0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
	0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
	0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
	0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
	0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
	0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
	0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
	0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
	0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
	0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

/** SHA-512 initial digest values */
static const struct sha512_digest sha512_init_digest = {
	.h = {
		cpu_to_be64 ( 0x6a09e667f3bcc908ULL ),
		cpu_to_be64 ( 0xbb67ae8584caa73bULL ),
		cpu_to_be64 ( 0x3c6ef372fe94f82bULL ),
		cpu_to_be64 ( 0xa54ff53a5f1d36f1ULL ),
		cpu_to_be64 ( 0x510e527fade682d1ULL ),
		cpu_to_be64 ( 0x9b05688c2b3e6c1fULL ),
		cpu_to_be64 ( 0x1f83d9abfb41bd6bULL ),
		cpu_to_be64 ( 0x5be0cd19137e2179ULL ),
	},
};

/**
 * Initialise SHA-512 family algorithm
 *
 * @v context		SHA-512 context
 * @v init		Initial digest values
 * @v digestsize	Digest size
 */
void sha512_family_init ( struct sha512_context *context,
			  const struct sha512_digest *init,
			  size_t digestsize ) {

	context->len = 0;
	context->digestsize = digestsize;
	memcpy ( &context->ddq.dd.digest, init,
		 sizeof ( context->ddq.dd.digest ) );
}

/**
 * Initialise SHA-512 algorithm
 *
 * @v ctx		SHA-512 context
 */
static void sha512_init ( void *ctx ) {
	struct sha512_context *context = ctx;

	sha512_family_init ( context, &sha512_init_digest,
			     sizeof ( struct sha512_digest ) );
}

/**
 * Calculate SHA-512 digest of accumulated data
 *
 * @v context		SHA-512 context
 */
static void sha512_digest ( struct sha512_context *context ) {
        union {
		union sha512_digest_data_qwords ddq;
		struct sha512_variables v;
	} u;
	uint64_t *a = &u.v.a;
	uint64_t *b = &u.v.b;
	uint64_t *c = &u.v.c;
	uint64_t *d = &u.v.d;
	uint64_t *e = &u.v.e;
	uint64_t *f = &u.v.f;
	uint64_t *g = &u.v.g;
	uint64_t *h = &u.v.h;
	uint64_t *w = u.v.w;
	uint64_t s0;
	uint64_t s1;
	uint64_t maj;
	uint64_t t1;
	uint64_t t2;
	uint64_t ch;
	unsigned int i;

	/* Sanity checks */
	assert ( ( context->len % sizeof ( context->ddq.dd.data ) ) == 0 );
	linker_assert ( &u.ddq.dd.digest.h[0] == a, sha512_bad_layout );
	linker_assert ( &u.ddq.dd.digest.h[1] == b, sha512_bad_layout );
	linker_assert ( &u.ddq.dd.digest.h[2] == c, sha512_bad_layout );
	linker_assert ( &u.ddq.dd.digest.h[3] == d, sha512_bad_layout );
	linker_assert ( &u.ddq.dd.digest.h[4] == e, sha512_bad_layout );
	linker_assert ( &u.ddq.dd.digest.h[5] == f, sha512_bad_layout );
	linker_assert ( &u.ddq.dd.digest.h[6] == g, sha512_bad_layout );
	linker_assert ( &u.ddq.dd.digest.h[7] == h, sha512_bad_layout );
	linker_assert ( &u.ddq.dd.data.qword[0] == w, sha512_bad_layout );

	DBGC ( context, "SHA512 digesting:\n" );
	DBGC_HDA ( context, 0, &context->ddq.dd.digest,
		   sizeof ( context->ddq.dd.digest ) );
	DBGC_HDA ( context, context->len, &context->ddq.dd.data,
		   sizeof ( context->ddq.dd.data ) );

	/* Convert h[0..7] to host-endian, and initialise a, b, c, d,
	 * e, f, g, h, and w[0..15]
	 */
	for ( i = 0 ; i < ( sizeof ( u.ddq.qword ) /
			    sizeof ( u.ddq.qword[0] ) ) ; i++ ) {
		be64_to_cpus ( &context->ddq.qword[i] );
		u.ddq.qword[i] = context->ddq.qword[i];
	}

	/* Initialise w[16..79] */
	for ( i = 16 ; i < SHA512_ROUNDS ; i++ ) {
		s0 = ( ror64 ( w[i-15], 1 ) ^ ror64 ( w[i-15], 8 ) ^
		       ( w[i-15] >> 7 ) );
		s1 = ( ror64 ( w[i-2], 19 ) ^ ror64 ( w[i-2], 61 ) ^
		       ( w[i-2] >> 6 ) );
		w[i] = ( w[i-16] + s0 + w[i-7] + s1 );
	}

	/* Main loop */
	for ( i = 0 ; i < SHA512_ROUNDS ; i++ ) {
		s0 = ( ror64 ( *a, 28 ) ^ ror64 ( *a, 34 ) ^ ror64 ( *a, 39 ) );
		maj = ( ( *a & *b ) ^ ( *a & *c ) ^ ( *b & *c ) );
		t2 = ( s0 + maj );
		s1 = ( ror64 ( *e, 14 ) ^ ror64 ( *e, 18 ) ^ ror64 ( *e, 41 ) );
		ch = ( ( *e & *f ) ^ ( (~*e) & *g ) );
		t1 = ( *h + s1 + ch + k[i] + w[i] );
		*h = *g;
		*g = *f;
		*f = *e;
		*e = ( *d + t1 );
		*d = *c;
		*c = *b;
		*b = *a;
		*a = ( t1 + t2 );
		DBGC2 ( context, "%2d : %016llx %016llx %016llx %016llx "
			"%016llx %016llx %016llx %016llx\n",
			i, *a, *b, *c, *d, *e, *f, *g, *h );
	}

	/* Add chunk to hash and convert back to big-endian */
	for ( i = 0 ; i < 8 ; i++ ) {
		context->ddq.dd.digest.h[i] =
			cpu_to_be64 ( context->ddq.dd.digest.h[i] +
				      u.ddq.dd.digest.h[i] );
	}

	DBGC ( context, "SHA512 digested:\n" );
	DBGC_HDA ( context, 0, &context->ddq.dd.digest,
		   sizeof ( context->ddq.dd.digest ) );
}

/**
 * Accumulate data with SHA-512 algorithm
 *
 * @v ctx		SHA-512 context
 * @v data		Data
 * @v len		Length of data
 */
void sha512_update ( void *ctx, const void *data, size_t len ) {
	struct sha512_context *context = ctx;
	const uint8_t *byte = data;
	size_t offset;

	/* Accumulate data a byte at a time, performing the digest
	 * whenever we fill the data buffer
	 */
	while ( len-- ) {
		offset = ( context->len % sizeof ( context->ddq.dd.data ) );
		context->ddq.dd.data.byte[offset] = *(byte++);
		context->len++;
		if ( ( context->len % sizeof ( context->ddq.dd.data ) ) == 0 )
			sha512_digest ( context );
	}
}

/**
 * Generate SHA-512 digest
 *
 * @v ctx		SHA-512 context
 * @v out		Output buffer
 */
void sha512_final ( void *ctx, void *out ) {
	struct sha512_context *context = ctx;
	uint64_t len_bits_hi;
	uint64_t len_bits_lo;
	uint8_t pad;

	/* Record length before pre-processing */
	len_bits_hi = 0;
	len_bits_lo = cpu_to_be64 ( ( ( uint64_t ) context->len ) * 8 );

	/* Pad with a single "1" bit followed by as many "0" bits as required */
	pad = 0x80;
	do {
		sha512_update ( ctx, &pad, sizeof ( pad ) );
		pad = 0x00;
	} while ( ( context->len % sizeof ( context->ddq.dd.data ) ) !=
		  offsetof ( typeof ( context->ddq.dd.data ), final.len_hi ) );

	/* Append length (in bits) */
	sha512_update ( ctx, &len_bits_hi, sizeof ( len_bits_hi ) );
	sha512_update ( ctx, &len_bits_lo, sizeof ( len_bits_lo ) );
	assert ( ( context->len % sizeof ( context->ddq.dd.data ) ) == 0 );

	/* Copy out final digest */
	memcpy ( out, &context->ddq.dd.digest, context->digestsize );
}

/** SHA-512 algorithm */
struct digest_algorithm sha512_algorithm = {
	.name		= "sha512",
	.ctxsize	= sizeof ( struct sha512_context ),
	.blocksize	= sizeof ( union sha512_block ),
	.digestsize	= sizeof ( struct sha512_digest ),
	.init		= sha512_init,
	.update		= sha512_update,
	.final		= sha512_final,
};

/** "sha512" object identifier */
static uint8_t oid_sha512[] = { ASN1_OID_SHA512 };

/** "sha512" OID-identified algorithm */
struct asn1_algorithm oid_sha512_algorithm __asn1_algorithm = {
	.name = "sha512",
	.digest = &sha512_algorithm,
	.oid = ASN1_OID_CURSOR ( oid_sha512 ),
};
