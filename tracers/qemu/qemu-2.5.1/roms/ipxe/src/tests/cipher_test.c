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
 * Cipher self-tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ipxe/crypto.h>
#include <ipxe/profile.h>
#include <ipxe/test.h>
#include "cipher_test.h"

/** Number of sample iterations for profiling */
#define PROFILE_COUNT 16

/**
 * Report a cipher encryption test result
 *
 * @v test		Cipher test
 * @v file		Test code file
 * @v line		Test code line
 */
void cipher_encrypt_okx ( struct cipher_test *test, const char *file,
			  unsigned int line ) {
	struct cipher_algorithm *cipher = test->cipher;
	size_t len = test->len;
	uint8_t ctx[cipher->ctxsize];
	uint8_t ciphertext[len];

	/* Initialise cipher */
	okx ( cipher_setkey ( cipher, ctx, test->key, test->key_len ) == 0,
	      file, line );
	cipher_setiv ( cipher, ctx, test->iv );

	/* Perform encryption */
	cipher_encrypt ( cipher, ctx, test->plaintext, ciphertext, len );

	/* Compare against expected ciphertext */
	okx ( memcmp ( ciphertext, test->ciphertext, len ) == 0, file, line );
}

/**
 * Report a cipher decryption test result
 *
 * @v test		Cipher test
 * @v file		Test code file
 * @v line		Test code line
 */
void cipher_decrypt_okx ( struct cipher_test *test, const char *file,
			  unsigned int line ) {
	struct cipher_algorithm *cipher = test->cipher;
	size_t len = test->len;
	uint8_t ctx[cipher->ctxsize];
	uint8_t plaintext[len];

	/* Initialise cipher */
	okx ( cipher_setkey ( cipher, ctx, test->key, test->key_len ) == 0,
	      file, line );
	cipher_setiv ( cipher, ctx, test->iv );

	/* Perform encryption */
	cipher_decrypt ( cipher, ctx, test->ciphertext, plaintext, len );

	/* Compare against expected plaintext */
	okx ( memcmp ( plaintext, test->plaintext, len ) == 0, file, line );
}

/**
 * Report a cipher encryption and decryption test result
 *
 * @v test		Cipher test
 * @v file		Test code file
 * @v line		Test code line
 */
void cipher_okx ( struct cipher_test *test, const char *file,
		  unsigned int line ) {

	cipher_encrypt_okx ( test, file, line );
	cipher_decrypt_okx ( test, file, line );
}

/**
 * Calculate cipher encryption or decryption cost
 *
 * @v cipher			Cipher algorithm
 * @v key_len			Length of key
 * @v op			Encryption or decryption operation
 * @ret cost			Cost (in cycles per byte)
 */
static unsigned long
cipher_cost ( struct cipher_algorithm *cipher, size_t key_len,
	      void ( * op ) ( struct cipher_algorithm *cipher, void *ctx,
			      const void *src, void *dst, size_t len ) ) {
	static uint8_t random[8192]; /* Too large for stack */
	uint8_t key[key_len];
	uint8_t iv[cipher->blocksize];
	uint8_t ctx[cipher->ctxsize];
	struct profiler profiler;
	unsigned long cost;
	unsigned int i;
	int rc;

	/* Fill buffer with pseudo-random data */
	srand ( 0x1234568 );
	for ( i = 0 ; i < sizeof ( random ) ; i++ )
		random[i] = rand();
	for ( i = 0 ; i < sizeof ( key ) ; i++ )
		key[i] = rand();
	for ( i = 0 ; i < sizeof ( iv ) ; i++ )
		iv[i] = rand();

	/* Initialise cipher */
	rc = cipher_setkey ( cipher, ctx, key, key_len );
	assert ( rc == 0 );
	cipher_setiv ( cipher, ctx, iv );

	/* Profile cipher operation */
	memset ( &profiler, 0, sizeof ( profiler ) );
	for ( i = 0 ; i < PROFILE_COUNT ; i++ ) {
		profile_start ( &profiler );
		op ( cipher, ctx, random, random, sizeof ( random ) );
		profile_stop ( &profiler );
	}

	/* Round to nearest whole number of cycles per byte */
	cost = ( ( profile_mean ( &profiler ) + ( sizeof ( random ) / 2 ) ) /
		 sizeof ( random ) );

	return cost;
}

/**
 * Calculate cipher encryption cost
 *
 * @v cipher			Cipher algorithm
 * @v key_len			Length of key
 * @ret cost			Cost (in cycles per byte)
 */
unsigned long cipher_cost_encrypt ( struct cipher_algorithm *cipher,
				    size_t key_len ) {
	return cipher_cost ( cipher, key_len, cipher_encrypt );
}

/**
 * Calculate cipher decryption cost
 *
 * @v cipher			Cipher algorithm
 * @v key_len			Length of key
 * @ret cost			Cost (in cycles per byte)
 */
unsigned long cipher_cost_decrypt ( struct cipher_algorithm *cipher,
				    size_t key_len ) {
	return cipher_cost ( cipher, key_len, cipher_decrypt );
}
