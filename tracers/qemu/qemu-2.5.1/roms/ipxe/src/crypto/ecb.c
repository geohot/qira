/*
 * Copyright (C) 2009 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <assert.h>
#include <ipxe/crypto.h>
#include <ipxe/ecb.h>

/** @file
 *
 * Electronic codebook (ECB)
 *
 */

/**
 * Encrypt data
 *
 * @v ctx		Context
 * @v src		Data to encrypt
 * @v dst		Buffer for encrypted data
 * @v len		Length of data
 * @v raw_cipher	Underlying cipher algorithm
 */
void ecb_encrypt ( void *ctx, const void *src, void *dst, size_t len,
		   struct cipher_algorithm *raw_cipher ) {
	size_t blocksize = raw_cipher->blocksize;

	assert ( ( len % blocksize ) == 0 );

	while ( len ) {
		cipher_encrypt ( raw_cipher, ctx, src, dst, blocksize );
		dst += blocksize;
		src += blocksize;
		len -= blocksize;
	}
}

/**
 * Decrypt data
 *
 * @v ctx		Context
 * @v src		Data to decrypt
 * @v dst		Buffer for decrypted data
 * @v len		Length of data
 * @v raw_cipher	Underlying cipher algorithm
 */
void ecb_decrypt ( void *ctx, const void *src, void *dst, size_t len,
		   struct cipher_algorithm *raw_cipher ) {
	size_t blocksize = raw_cipher->blocksize;

	assert ( ( len % blocksize ) == 0 );

	while ( len ) {
		cipher_decrypt ( raw_cipher, ctx, src, dst, blocksize );
		dst += blocksize;
		src += blocksize;
		len -= blocksize;
	}
}
