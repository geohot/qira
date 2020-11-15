/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

#include <config/crypto.h>

/** @file
 *
 * Cryptographic configuration
 *
 * Cryptographic configuration is slightly messy since we need to drag
 * in objects based on combinations of build options.
 */

PROVIDE_REQUIRING_SYMBOL();

/* RSA and MD5 */
#if defined ( CRYPTO_PUBKEY_RSA ) && defined ( CRYPTO_DIGEST_MD5 )
REQUIRE_OBJECT ( rsa_md5 );
#endif

/* RSA and SHA-1 */
#if defined ( CRYPTO_PUBKEY_RSA ) && defined ( CRYPTO_DIGEST_SHA1 )
REQUIRE_OBJECT ( rsa_sha1 );
#endif

/* RSA and SHA-224 */
#if defined ( CRYPTO_PUBKEY_RSA ) && defined ( CRYPTO_DIGEST_SHA224 )
REQUIRE_OBJECT ( rsa_sha224 );
#endif

/* RSA and SHA-256 */
#if defined ( CRYPTO_PUBKEY_RSA ) && defined ( CRYPTO_DIGEST_SHA256 )
REQUIRE_OBJECT ( rsa_sha256 );
#endif

/* RSA and SHA-384 */
#if defined ( CRYPTO_PUBKEY_RSA ) && defined ( CRYPTO_DIGEST_SHA384 )
REQUIRE_OBJECT ( rsa_sha384 );
#endif

/* RSA and SHA-512 */
#if defined ( CRYPTO_PUBKEY_RSA ) && defined ( CRYPTO_DIGEST_SHA512 )
REQUIRE_OBJECT ( rsa_sha512 );
#endif

/* RSA, AES-CBC, and SHA-1 */
#if defined ( CRYPTO_PUBKEY_RSA ) && defined ( CRYPTO_CIPHER_AES_CBC ) && \
    defined ( CRYPTO_DIGEST_SHA1 )
REQUIRE_OBJECT ( rsa_aes_cbc_sha1 );
#endif

/* RSA, AES-CBC, and SHA-256 */
#if defined ( CRYPTO_PUBKEY_RSA ) && defined ( CRYPTO_CIPHER_AES_CBC ) && \
    defined ( CRYPTO_DIGEST_SHA256 )
REQUIRE_OBJECT ( rsa_aes_cbc_sha256 );
#endif
