/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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

/**
 * @file
 *
 * Keyed-Hashing for Message Authentication
 */

#include <string.h>
#include <assert.h>
#include <ipxe/crypto.h>
#include <ipxe/hmac.h>

/**
 * Reduce HMAC key length
 *
 * @v digest		Digest algorithm to use
 * @v digest_ctx	Digest context
 * @v key		Key
 * @v key_len		Length of key
 */
static void hmac_reduce_key ( struct digest_algorithm *digest,
			      void *key, size_t *key_len ) {
	uint8_t digest_ctx[digest->ctxsize];

	digest_init ( digest, digest_ctx );
	digest_update ( digest, digest_ctx, key, *key_len );
	digest_final ( digest, digest_ctx, key );
	*key_len = digest->digestsize;
}

/**
 * Initialise HMAC
 *
 * @v digest		Digest algorithm to use
 * @v digest_ctx	Digest context
 * @v key		Key
 * @v key_len		Length of key
 *
 * The length of the key should be less than the block size of the
 * digest algorithm being used.  (If the key length is greater, it
 * will be replaced with its own digest, and key_len will be updated
 * accordingly).
 */
void hmac_init ( struct digest_algorithm *digest, void *digest_ctx,
		 void *key, size_t *key_len ) {
	unsigned char k_ipad[digest->blocksize];
	unsigned int i;

	/* Reduce key if necessary */
	if ( *key_len > sizeof ( k_ipad ) )
		hmac_reduce_key ( digest, key, key_len );

	/* Construct input pad */
	memset ( k_ipad, 0, sizeof ( k_ipad ) );
	memcpy ( k_ipad, key, *key_len );
	for ( i = 0 ; i < sizeof ( k_ipad ) ; i++ ) {
		k_ipad[i] ^= 0x36;
	}
	
	/* Start inner hash */
	digest_init ( digest, digest_ctx );
	digest_update ( digest, digest_ctx, k_ipad, sizeof ( k_ipad ) );
}

/**
 * Finalise HMAC
 *
 * @v digest		Digest algorithm to use
 * @v digest_ctx	Digest context
 * @v key		Key
 * @v key_len		Length of key
 * @v hmac		HMAC digest to fill in
 *
 * The length of the key should be less than the block size of the
 * digest algorithm being used.  (If the key length is greater, it
 * will be replaced with its own digest, and key_len will be updated
 * accordingly).
 */
void hmac_final ( struct digest_algorithm *digest, void *digest_ctx,
		  void *key, size_t *key_len, void *hmac ) {
	unsigned char k_opad[digest->blocksize];
	unsigned int i;

	/* Reduce key if necessary */
	if ( *key_len > sizeof ( k_opad ) )
		hmac_reduce_key ( digest, key, key_len );

	/* Construct output pad */
	memset ( k_opad, 0, sizeof ( k_opad ) );
	memcpy ( k_opad, key, *key_len );
	for ( i = 0 ; i < sizeof ( k_opad ) ; i++ ) {
		k_opad[i] ^= 0x5c;
	}
	
	/* Finish inner hash */
	digest_final ( digest, digest_ctx, hmac );

	/* Perform outer hash */
	digest_init ( digest, digest_ctx );
	digest_update ( digest, digest_ctx, k_opad, sizeof ( k_opad ) );
	digest_update ( digest, digest_ctx, hmac, digest->digestsize );
	digest_final ( digest, digest_ctx, hmac );
}
