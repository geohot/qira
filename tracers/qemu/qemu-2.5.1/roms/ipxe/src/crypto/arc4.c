/*
 * The ARC4 stream cipher.
 *
 * Copyright (c) 2009 Joshua Oreman <oremanj@rwcr.net>.
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
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/crypto.h>
#include <ipxe/arc4.h>

#define SWAP( ary, i, j )	\
	({ u8 temp = ary[i]; ary[i] = ary[j]; ary[j] = temp; })

/**
 * Set ARC4 key
 *
 * @v ctxv	ARC4 encryption context
 * @v keyv	Key to set
 * @v keylen	Length of key
 *
 * If an initialisation vector is to be used, it should be prepended
 * to the key; ARC4 does not implement the @c setiv function because
 * there is no standard length for an initialisation vector in the
 * cipher.
 */
static int arc4_setkey ( void *ctxv, const void *keyv, size_t keylen )
{
	struct arc4_ctx *ctx = ctxv;
	const u8 *key = keyv;
	u8 *S = ctx->state;
	int i, j;

	for ( i = 0; i < 256; i++ ) {
		S[i] = i;
	}

	for ( i = j = 0; i < 256; i++ ) {
		j = ( j + S[i] + key[i % keylen] ) & 0xff;
		SWAP ( S, i, j );
	}

	ctx->i = ctx->j = 0;
	return 0;
}

/**
 * Perform ARC4 encryption or decryption
 *
 * @v ctxv	ARC4 encryption context
 * @v srcv	Data to encrypt or decrypt
 * @v dstv	Location to store encrypted or decrypted data
 * @v len	Length of data to operate on
 *
 * ARC4 is a stream cipher that works by generating a stream of PRNG
 * data based on the key, and XOR'ing it with the data to be
 * encrypted. Since XOR is symmetric, encryption and decryption in
 * ARC4 are the same operation.
 *
 * If you pass a @c NULL source or destination pointer, @a len
 * keystream bytes will be consumed without encrypting any data.
 */
static void arc4_xor ( void *ctxv, const void *srcv, void *dstv,
		       size_t len )
{
	struct arc4_ctx *ctx = ctxv;
	const u8 *src = srcv;
	u8 *dst = dstv;
	u8 *S = ctx->state;
	int i = ctx->i, j = ctx->j;

	while ( len-- ) {
		i = ( i + 1 ) & 0xff;
		j = ( j + S[i] ) & 0xff;
		SWAP ( S, i, j );
		if ( srcv && dstv )
			*dst++ = *src++ ^ S[(S[i] + S[j]) & 0xff];
	}

	ctx->i = i;
	ctx->j = j;
}

static void arc4_setiv ( void *ctx __unused, const void *iv __unused )
{
	/* ARC4 does not use a fixed-length IV */
}


/**
 * Perform ARC4 encryption or decryption, skipping initial keystream bytes
 *
 * @v key	ARC4 encryption key
 * @v keylen	Key length
 * @v skip	Number of bytes of keystream to skip
 * @v src	Message to encrypt or decrypt
 * @v msglen	Length of message
 * @ret dst	Encrypted or decrypted message
 */
void arc4_skip ( const void *key, size_t keylen, size_t skip,
		 const void *src, void *dst, size_t msglen )
{
	struct arc4_ctx ctx;
	arc4_setkey ( &ctx, key, keylen );
	arc4_xor ( &ctx, NULL, NULL, skip );
	arc4_xor ( &ctx, src, dst, msglen );
}

struct cipher_algorithm arc4_algorithm = {
	.name = "ARC4",
	.ctxsize = ARC4_CTX_SIZE,
	.blocksize = 1,
	.setkey = arc4_setkey,
	.setiv = arc4_setiv,
	.encrypt = arc4_xor,
	.decrypt = arc4_xor,
};
