/*
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

#include <stdlib.h>
#include <string.h>
#include <ipxe/crypto.h>
#include <ipxe/aes.h>

/**
 * Wrap a key or other data using AES Key Wrap (RFC 3394)
 *
 * @v kek	Key Encryption Key, 16 bytes
 * @v src	Data to encrypt
 * @v nblk	Number of 8-byte blocks in @a data
 * @ret dest	Encrypted data (8 bytes longer than input)
 *
 * The algorithm is implemented such that @a src and @a dest may point
 * to the same buffer.
 */
int aes_wrap ( const void *kek, const void *src, void *dest, int nblk )
{
	u8 *A = dest;
	u8 B[16];
	u8 *R;
	int i, j;
	void *aes_ctx = malloc ( AES_CTX_SIZE );

	if ( ! aes_ctx )
		return -1;

	cipher_setkey ( &aes_algorithm, aes_ctx, kek, 16 );

	/* Set up */
	memset ( A, 0xA6, 8 );
	memmove ( dest + 8, src, nblk * 8 );

	/* Wrap */
	for ( j = 0; j < 6; j++ ) {
		R = dest + 8;
		for ( i = 1; i <= nblk; i++ ) {
			memcpy ( B, A, 8 );
			memcpy ( B + 8, R, 8 );
			cipher_encrypt ( &aes_algorithm, aes_ctx, B, B, 16 );
			memcpy ( A, B, 8 );
			A[7] ^= ( nblk * j ) + i;
			memcpy ( R, B + 8, 8 );
			R += 8;
		}
	}

	free ( aes_ctx );
	return 0;
}

/**
 * Unwrap a key or other data using AES Key Wrap (RFC 3394)
 *
 * @v kek	Key Encryption Key, 16 bytes
 * @v src	Data to decrypt
 * @v nblk	Number of 8-byte blocks in @e plaintext key
 * @ret dest	Decrypted data (8 bytes shorter than input)
 * @ret rc	Zero on success, nonzero on IV mismatch
 *
 * The algorithm is implemented such that @a src and @a dest may point
 * to the same buffer.
 */
int aes_unwrap ( const void *kek, const void *src, void *dest, int nblk )
{
	u8 A[8], B[16];
	u8 *R;
	int i, j;
	void *aes_ctx = malloc ( AES_CTX_SIZE );

	if ( ! aes_ctx )
		return -1;

	cipher_setkey ( &aes_algorithm, aes_ctx, kek, 16 );

	/* Set up */
	memcpy ( A, src, 8 );
	memmove ( dest, src + 8, nblk * 8 );

	/* Unwrap */
	for ( j = 5; j >= 0; j-- ) {
		R = dest + ( nblk - 1 ) * 8;
		for ( i = nblk; i >= 1; i-- ) {
			memcpy ( B, A, 8 );
			memcpy ( B + 8, R, 8 );
			B[7] ^= ( nblk * j ) + i;
			cipher_decrypt ( &aes_algorithm, aes_ctx, B, B, 16 );
			memcpy ( A, B, 8 );
			memcpy ( R, B + 8, 8 );
			R -= 8;
		}
	}

	free ( aes_ctx );

	/* Check IV */
	for ( i = 0; i < 8; i++ ) {
		if ( A[i] != 0xA6 )
			return -1;
	}

	return 0;
}
