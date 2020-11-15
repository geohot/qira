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

#include <string.h>
#include <ipxe/crypto.h>
#include <ipxe/sha1.h>
#include <ipxe/hmac.h>
#include <stdint.h>
#include <byteswap.h>

/**
 * SHA1 pseudorandom function for creating derived keys
 *
 * @v key	Master key with which this call is associated
 * @v key_len	Length of key
 * @v label	NUL-terminated ASCII string describing purpose of PRF data
 * @v data	Further data that should be included in the PRF
 * @v data_len	Length of further PRF data
 * @v prf_len	Bytes of PRF to generate
 * @ret prf	Pseudorandom function bytes
 *
 * This is the PRF variant used by 802.11, defined in IEEE 802.11-2007
 * 8.5.5.1. EAP-FAST uses a different SHA1-based PRF, and TLS uses an
 * MD5-based PRF.
 */
void prf_sha1 ( const void *key, size_t key_len, const char *label,
		const void *data, size_t data_len, void *prf, size_t prf_len )
{
	u32 blk;
	u8 keym[key_len];	/* modifiable copy of key */
	u8 in[strlen ( label ) + 1 + data_len + 1]; /* message to HMAC */
	u8 *in_blknr;		/* pointer to last byte of in, block number */
	u8 out[SHA1_DIGEST_SIZE]; /* HMAC-SHA1 result */
	u8 sha1_ctx[SHA1_CTX_SIZE]; /* SHA1 context */
	const size_t label_len = strlen ( label );

	/* The HMAC-SHA-1 is calculated using the given key on the
	   message text `label', followed by a NUL, followed by one
	   byte indicating the block number (0 for first). */

	memcpy ( keym, key, key_len );

	memcpy ( in, label, strlen ( label ) + 1 );
	memcpy ( in + label_len + 1, data, data_len );
	in_blknr = in + label_len + 1 + data_len;

	for ( blk = 0 ;; blk++ ) {
		*in_blknr = blk;

		hmac_init ( &sha1_algorithm, sha1_ctx, keym, &key_len );
		hmac_update ( &sha1_algorithm, sha1_ctx, in, sizeof ( in ) );
		hmac_final ( &sha1_algorithm, sha1_ctx, keym, &key_len, out );

		if ( prf_len <= sizeof ( out ) ) {
			memcpy ( prf, out, prf_len );
			break;
		}

		memcpy ( prf, out, sizeof ( out ) );
		prf_len -= sizeof ( out );
		prf += sizeof ( out );
	}
}

/**
 * PBKDF2 key derivation function inner block operation
 *
 * @v passphrase	Passphrase from which to derive key
 * @v pass_len		Length of passphrase
 * @v salt		Salt to include in key
 * @v salt_len		Length of salt
 * @v iterations	Number of iterations of SHA1 to perform
 * @v blocknr		Index of this block, starting at 1
 * @ret block		SHA1_SIZE bytes of PBKDF2 data
 *
 * The operation of this function is described in RFC 2898.
 */
static void pbkdf2_sha1_f ( const void *passphrase, size_t pass_len,
			    const void *salt, size_t salt_len,
			    int iterations, u32 blocknr, u8 *block )
{
	u8 pass[pass_len];	/* modifiable passphrase */
	u8 in[salt_len + 4];	/* input buffer to first round */
	u8 last[SHA1_DIGEST_SIZE]; /* output of round N, input of N+1 */
	u8 sha1_ctx[SHA1_CTX_SIZE];
	u8 *next_in = in;	/* changed to `last' after first round */
	int next_size = sizeof ( in );
	int i;
	unsigned int j;

	blocknr = htonl ( blocknr );

	memcpy ( pass, passphrase, pass_len );
	memcpy ( in, salt, salt_len );
	memcpy ( in + salt_len, &blocknr, 4 );
	memset ( block, 0, sizeof ( last ) );

	for ( i = 0; i < iterations; i++ ) {
		hmac_init ( &sha1_algorithm, sha1_ctx, pass, &pass_len );
		hmac_update ( &sha1_algorithm, sha1_ctx, next_in, next_size );
		hmac_final ( &sha1_algorithm, sha1_ctx, pass, &pass_len, last );

		for ( j = 0; j < sizeof ( last ); j++ ) {
			block[j] ^= last[j];
		}

		next_in = last;
		next_size = sizeof ( last );
	}
}

/**
 * PBKDF2 key derivation function using SHA1
 *
 * @v passphrase	Passphrase from which to derive key
 * @v pass_len		Length of passphrase
 * @v salt		Salt to include in key
 * @v salt_len		Length of salt
 * @v iterations	Number of iterations of SHA1 to perform
 * @v key_len		Length of key to generate
 * @ret key		Generated key bytes
 *
 * This is used most notably in 802.11 WPA passphrase hashing, in
 * which case the salt is the SSID, 4096 iterations are used, and a
 * 32-byte key is generated that serves as the Pairwise Master Key for
 * EAPOL authentication.
 *
 * The operation of this function is further described in RFC 2898.
 */
void pbkdf2_sha1 ( const void *passphrase, size_t pass_len,
		   const void *salt, size_t salt_len,
		   int iterations, void *key, size_t key_len )
{
	u32 blocks = ( key_len + SHA1_DIGEST_SIZE - 1 ) / SHA1_DIGEST_SIZE;
	u32 blk;
	u8 buf[SHA1_DIGEST_SIZE];

	for ( blk = 1; blk <= blocks; blk++ ) {
		pbkdf2_sha1_f ( passphrase, pass_len, salt, salt_len,
				iterations, blk, buf );
		if ( key_len <= sizeof ( buf ) ) {
			memcpy ( key, buf, key_len );
			break;
		}

		memcpy ( key, buf, sizeof ( buf ) );
		key_len -= sizeof ( buf );
		key += sizeof ( buf );
	}
}
