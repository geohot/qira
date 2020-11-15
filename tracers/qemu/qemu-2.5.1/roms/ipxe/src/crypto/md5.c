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
 * MD5 algorithm
 *
 */

#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include <assert.h>
#include <ipxe/rotate.h>
#include <ipxe/crypto.h>
#include <ipxe/asn1.h>
#include <ipxe/md5.h>

/** MD5 variables */
struct md5_variables {
	/* This layout matches that of struct md5_digest_data,
	 * allowing for efficient endianness-conversion,
	 */
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t w[16];
} __attribute__ (( packed ));

/** MD5 constants */
static const uint32_t k[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
	0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
	0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
	0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
	0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
	0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/** MD5 shift amounts */
static const uint8_t r[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

/**
 * f(b,c,d) for steps 0 to 15
 *
 * @v v		MD5 variables
 * @ret f	f(b,c,d)
 */
static uint32_t md5_f_0_15 ( struct md5_variables *v ) {
	return ( v->d ^ ( v->b & ( v->c ^ v->d ) ) );
}

/**
 * f(b,c,d) for steps 16 to 31
 *
 * @v v		MD5 variables
 * @ret f	f(b,c,d)
 */
static uint32_t md5_f_16_31 ( struct md5_variables *v ) {
	return ( v->c ^ ( v->d & ( v->b ^ v->c ) ) );
}

/**
 * f(b,c,d) for steps 32 to 47
 *
 * @v v		MD5 variables
 * @ret f	f(b,c,d)
 */
static uint32_t md5_f_32_47 ( struct md5_variables *v ) {
	return ( v->b ^ v->c ^ v->d );
}

/**
 * f(b,c,d) for steps 48 to 63
 *
 * @v v		MD5 variables
 * @ret f	f(b,c,d)
 */
static uint32_t md5_f_48_63 ( struct md5_variables *v ) {
	return ( v->c ^ ( v->b | (~v->d) ) );
}

/** An MD5 step function */
struct md5_step {
	/**
	 * Calculate f(b,c,d)
	 *
	 * @v v		MD5 variables
	 * @ret f	f(b,c,d)
	 */
	uint32_t ( * f ) ( struct md5_variables *v );
	/** Coefficient of i in g=ni+m */
	uint8_t coefficient;
	/** Constant term in g=ni+m */
	uint8_t constant;
};

/** MD5 steps */
static struct md5_step md5_steps[4] = {
	/** 0 to 15 */
	{ .f = md5_f_0_15,	.coefficient = 1,	.constant = 0 },
	/** 16 to 31 */
	{ .f = md5_f_16_31,	.coefficient = 5,	.constant = 1 },
	/** 32 to 47 */
	{ .f = md5_f_32_47,	.coefficient = 3,	.constant = 5 },
	/** 48 to 63 */
	{ .f = md5_f_48_63,	.coefficient = 7,	.constant = 0 },
};

/**
 * Initialise MD5 algorithm
 *
 * @v ctx		MD5 context
 */
static void md5_init ( void *ctx ) {
	struct md5_context *context = ctx;

	context->ddd.dd.digest.h[0] = cpu_to_le32 ( 0x67452301 );
	context->ddd.dd.digest.h[1] = cpu_to_le32 ( 0xefcdab89 );
	context->ddd.dd.digest.h[2] = cpu_to_le32 ( 0x98badcfe );
	context->ddd.dd.digest.h[3] = cpu_to_le32 ( 0x10325476 );
	context->len = 0;
}

/**
 * Calculate MD5 digest of accumulated data
 *
 * @v context		MD5 context
 */
static void md5_digest ( struct md5_context *context ) {
        union {
		union md5_digest_data_dwords ddd;
		struct md5_variables v;
	} u;
	uint32_t *a = &u.v.a;
	uint32_t *b = &u.v.b;
	uint32_t *c = &u.v.c;
	uint32_t *d = &u.v.d;
	uint32_t *w = u.v.w;
	uint32_t f;
	uint32_t g;
	uint32_t temp;
	struct md5_step *step;
	unsigned int i;

	/* Sanity checks */
	assert ( ( context->len % sizeof ( context->ddd.dd.data ) ) == 0 );
	linker_assert ( &u.ddd.dd.digest.h[0] == a, md5_bad_layout );
	linker_assert ( &u.ddd.dd.digest.h[1] == b, md5_bad_layout );
	linker_assert ( &u.ddd.dd.digest.h[2] == c, md5_bad_layout );
	linker_assert ( &u.ddd.dd.digest.h[3] == d, md5_bad_layout );
	linker_assert ( &u.ddd.dd.data.dword[0] == w, md5_bad_layout );

	DBGC ( context, "MD5 digesting:\n" );
	DBGC_HDA ( context, 0, &context->ddd.dd.digest,
		   sizeof ( context->ddd.dd.digest ) );
	DBGC_HDA ( context, context->len, &context->ddd.dd.data,
		   sizeof ( context->ddd.dd.data ) );

	/* Convert h[0..3] to host-endian, and initialise a, b, c, d,
	 * and w[0..15]
	 */
	for ( i = 0 ; i < ( sizeof ( u.ddd.dword ) /
			    sizeof ( u.ddd.dword[0] ) ) ; i++ ) {
		le32_to_cpus ( &context->ddd.dword[i] );
		u.ddd.dword[i] = context->ddd.dword[i];
	}

	/* Main loop */
	for ( i = 0 ; i < 64 ; i++ ) {
		step = &md5_steps[ i / 16 ];
		f = step->f ( &u.v );
		g = ( ( ( step->coefficient * i ) + step->constant ) % 16 );
		temp = *d;
		*d = *c;
		*c = *b;
		*b = ( *b + rol32 ( ( *a + f + k[i] + w[g] ), r[i] ) );
		*a = temp;
		DBGC2 ( context, "%2d : %08x %08x %08x %08x\n",
			i, *a, *b, *c, *d );
	}

	/* Add chunk to hash and convert back to big-endian */
	for ( i = 0 ; i < 4 ; i++ ) {
		context->ddd.dd.digest.h[i] =
			cpu_to_le32 ( context->ddd.dd.digest.h[i] +
				      u.ddd.dd.digest.h[i] );
	}

	DBGC ( context, "MD5 digested:\n" );
	DBGC_HDA ( context, 0, &context->ddd.dd.digest,
		   sizeof ( context->ddd.dd.digest ) );
}

/**
 * Accumulate data with MD5 algorithm
 *
 * @v ctx		MD5 context
 * @v data		Data
 * @v len		Length of data
 */
static void md5_update ( void *ctx, const void *data, size_t len ) {
	struct md5_context *context = ctx;
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
			md5_digest ( context );
	}
}

/**
 * Generate MD5 digest
 *
 * @v ctx		MD5 context
 * @v out		Output buffer
 */
static void md5_final ( void *ctx, void *out ) {
	struct md5_context *context = ctx;
	uint64_t len_bits;
	uint8_t pad;

	/* Record length before pre-processing */
	len_bits = cpu_to_le64 ( ( ( uint64_t ) context->len ) * 8 );

	/* Pad with a single "1" bit followed by as many "0" bits as required */
	pad = 0x80;
	do {
		md5_update ( ctx, &pad, sizeof ( pad ) );
		pad = 0x00;
	} while ( ( context->len % sizeof ( context->ddd.dd.data ) ) !=
		  offsetof ( typeof ( context->ddd.dd.data ), final.len ) );

	/* Append length (in bits) */
	md5_update ( ctx, &len_bits, sizeof ( len_bits ) );
	assert ( ( context->len % sizeof ( context->ddd.dd.data ) ) == 0 );

	/* Copy out final digest */
	memcpy ( out, &context->ddd.dd.digest,
		 sizeof ( context->ddd.dd.digest ) );
}

/** MD5 algorithm */
struct digest_algorithm md5_algorithm = {
	.name		= "md5",
	.ctxsize	= sizeof ( struct md5_context ),
	.blocksize	= sizeof ( union md5_block ),
	.digestsize	= sizeof ( struct md5_digest ),
	.init		= md5_init,
	.update		= md5_update,
	.final		= md5_final,
};

/** "md5" object identifier */
static uint8_t oid_md5[] = { ASN1_OID_MD5 };

/** "md5" OID-identified algorithm */
struct asn1_algorithm oid_md5_algorithm __asn1_algorithm = {
	.name = "md5",
	.digest = &md5_algorithm,
	.oid = ASN1_OID_CURSOR ( oid_md5 ),
};
