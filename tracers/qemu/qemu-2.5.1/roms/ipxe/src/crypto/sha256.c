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
 * SHA-256 algorithm
 *
 */

#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include <assert.h>
#include <ipxe/rotate.h>
#include <ipxe/crypto.h>
#include <ipxe/asn1.h>
#include <ipxe/sha256.h>

/** SHA-256 variables */
struct sha256_variables {
	/* This layout matches that of struct sha256_digest_data,
	 * allowing for efficient endianness-conversion,
	 */
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t e;
	uint32_t f;
	uint32_t g;
	uint32_t h;
	uint32_t w[SHA256_ROUNDS];
} __attribute__ (( packed ));

/** SHA-256 constants */
static const uint32_t k[SHA256_ROUNDS] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/** SHA-256 initial digest values */
static const struct sha256_digest sha256_init_digest = {
	.h = {
		cpu_to_be32 ( 0x6a09e667 ),
		cpu_to_be32 ( 0xbb67ae85 ),
		cpu_to_be32 ( 0x3c6ef372 ),
		cpu_to_be32 ( 0xa54ff53a ),
		cpu_to_be32 ( 0x510e527f ),
		cpu_to_be32 ( 0x9b05688c ),
		cpu_to_be32 ( 0x1f83d9ab ),
		cpu_to_be32 ( 0x5be0cd19 ),
	},
};

/**
 * Initialise SHA-256 family algorithm
 *
 * @v context		SHA-256 context
 * @v init		Initial digest values
 * @v digestsize	Digest size
 */
void sha256_family_init ( struct sha256_context *context,
			  const struct sha256_digest *init,
			  size_t digestsize ) {

	context->len = 0;
	context->digestsize = digestsize;
	memcpy ( &context->ddd.dd.digest, init,
		 sizeof ( context->ddd.dd.digest ) );
}

/**
 * Initialise SHA-256 algorithm
 *
 * @v ctx		SHA-256 context
 */
static void sha256_init ( void *ctx ) {
	struct sha256_context *context = ctx;

	sha256_family_init ( context, &sha256_init_digest,
			     sizeof ( struct sha256_digest ) );
}

/**
 * Calculate SHA-256 digest of accumulated data
 *
 * @v context		SHA-256 context
 */
static void sha256_digest ( struct sha256_context *context ) {
        union {
		union sha256_digest_data_dwords ddd;
		struct sha256_variables v;
	} u;
	uint32_t *a = &u.v.a;
	uint32_t *b = &u.v.b;
	uint32_t *c = &u.v.c;
	uint32_t *d = &u.v.d;
	uint32_t *e = &u.v.e;
	uint32_t *f = &u.v.f;
	uint32_t *g = &u.v.g;
	uint32_t *h = &u.v.h;
	uint32_t *w = u.v.w;
	uint32_t s0;
	uint32_t s1;
	uint32_t maj;
	uint32_t t1;
	uint32_t t2;
	uint32_t ch;
	unsigned int i;

	/* Sanity checks */
	assert ( ( context->len % sizeof ( context->ddd.dd.data ) ) == 0 );
	linker_assert ( &u.ddd.dd.digest.h[0] == a, sha256_bad_layout );
	linker_assert ( &u.ddd.dd.digest.h[1] == b, sha256_bad_layout );
	linker_assert ( &u.ddd.dd.digest.h[2] == c, sha256_bad_layout );
	linker_assert ( &u.ddd.dd.digest.h[3] == d, sha256_bad_layout );
	linker_assert ( &u.ddd.dd.digest.h[4] == e, sha256_bad_layout );
	linker_assert ( &u.ddd.dd.digest.h[5] == f, sha256_bad_layout );
	linker_assert ( &u.ddd.dd.digest.h[6] == g, sha256_bad_layout );
	linker_assert ( &u.ddd.dd.digest.h[7] == h, sha256_bad_layout );
	linker_assert ( &u.ddd.dd.data.dword[0] == w, sha256_bad_layout );

	DBGC ( context, "SHA256 digesting:\n" );
	DBGC_HDA ( context, 0, &context->ddd.dd.digest,
		   sizeof ( context->ddd.dd.digest ) );
	DBGC_HDA ( context, context->len, &context->ddd.dd.data,
		   sizeof ( context->ddd.dd.data ) );

	/* Convert h[0..7] to host-endian, and initialise a, b, c, d,
	 * e, f, g, h, and w[0..15]
	 */
	for ( i = 0 ; i < ( sizeof ( u.ddd.dword ) /
			    sizeof ( u.ddd.dword[0] ) ) ; i++ ) {
		be32_to_cpus ( &context->ddd.dword[i] );
		u.ddd.dword[i] = context->ddd.dword[i];
	}

	/* Initialise w[16..63] */
	for ( i = 16 ; i < SHA256_ROUNDS ; i++ ) {
		s0 = ( ror32 ( w[i-15], 7 ) ^ ror32 ( w[i-15], 18 ) ^
		       ( w[i-15] >> 3 ) );
		s1 = ( ror32 ( w[i-2], 17 ) ^ ror32 ( w[i-2], 19 ) ^
		       ( w[i-2] >> 10 ) );
		w[i] = ( w[i-16] + s0 + w[i-7] + s1 );
	}

	/* Main loop */
	for ( i = 0 ; i < SHA256_ROUNDS ; i++ ) {
		s0 = ( ror32 ( *a, 2 ) ^ ror32 ( *a, 13 ) ^ ror32 ( *a, 22 ) );
		maj = ( ( *a & *b ) ^ ( *a & *c ) ^ ( *b & *c ) );
		t2 = ( s0 + maj );
		s1 = ( ror32 ( *e, 6 ) ^ ror32 ( *e, 11 ) ^ ror32 ( *e, 25 ) );
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
		DBGC2 ( context, "%2d : %08x %08x %08x %08x %08x %08x %08x "
			"%08x\n", i, *a, *b, *c, *d, *e, *f, *g, *h );
	}

	/* Add chunk to hash and convert back to big-endian */
	for ( i = 0 ; i < 8 ; i++ ) {
		context->ddd.dd.digest.h[i] =
			cpu_to_be32 ( context->ddd.dd.digest.h[i] +
				      u.ddd.dd.digest.h[i] );
	}

	DBGC ( context, "SHA256 digested:\n" );
	DBGC_HDA ( context, 0, &context->ddd.dd.digest,
		   sizeof ( context->ddd.dd.digest ) );
}

/**
 * Accumulate data with SHA-256 algorithm
 *
 * @v ctx		SHA-256 context
 * @v data		Data
 * @v len		Length of data
 */
void sha256_update ( void *ctx, const void *data, size_t len ) {
	struct sha256_context *context = ctx;
	const uint8_t *byte = data;
	size_t offset;

	/* Accumulate data a byte at a time, performing the digest
	 * whenever we fill the data buffer
	 */
	while ( len-- ) {
		offset = ( context->len % sizeof ( context->ddd.dd.data ) );
		context->ddd.dd.data.byte[offset] = *(byte++);
		context->len++;
		if ( ( context->len % sizeof ( context->ddd.dd.data ) ) == 0 )
			sha256_digest ( context );
	}
}

/**
 * Generate SHA-256 digest
 *
 * @v ctx		SHA-256 context
 * @v out		Output buffer
 */
void sha256_final ( void *ctx, void *out ) {
	struct sha256_context *context = ctx;
	uint64_t len_bits;
	uint8_t pad;

	/* Record length before pre-processing */
	len_bits = cpu_to_be64 ( ( ( uint64_t ) context->len ) * 8 );

	/* Pad with a single "1" bit followed by as many "0" bits as required */
	pad = 0x80;
	do {
		sha256_update ( ctx, &pad, sizeof ( pad ) );
		pad = 0x00;
	} while ( ( context->len % sizeof ( context->ddd.dd.data ) ) !=
		  offsetof ( typeof ( context->ddd.dd.data ), final.len ) );

	/* Append length (in bits) */
	sha256_update ( ctx, &len_bits, sizeof ( len_bits ) );
	assert ( ( context->len % sizeof ( context->ddd.dd.data ) ) == 0 );

	/* Copy out final digest */
	memcpy ( out, &context->ddd.dd.digest, context->digestsize );
}

/** SHA-256 algorithm */
struct digest_algorithm sha256_algorithm = {
	.name		= "sha256",
	.ctxsize	= sizeof ( struct sha256_context ),
	.blocksize	= sizeof ( union sha256_block ),
	.digestsize	= sizeof ( struct sha256_digest ),
	.init		= sha256_init,
	.update		= sha256_update,
	.final		= sha256_final,
};

/** "sha256" object identifier */
static uint8_t oid_sha256[] = { ASN1_OID_SHA256 };

/** "sha256" OID-identified algorithm */
struct asn1_algorithm oid_sha256_algorithm __asn1_algorithm = {
	.name = "sha256",
	.digest = &sha256_algorithm,
	.oid = ASN1_OID_CURSOR ( oid_sha256 ),
};
