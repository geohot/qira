#ifndef CONFIG_CRYPTO_H
#define CONFIG_CRYPTO_H

/** @file
 *
 * Cryptographic configuration
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** RSA public-key algorithm */
#define CRYPTO_PUBKEY_RSA

/** AES-CBC block cipher */
#define CRYPTO_CIPHER_AES_CBC

/** MD5 digest algorithm
 *
 * Note that use of MD5 is implicit when using TLSv1.1 or earlier.
 */
#define CRYPTO_DIGEST_MD5

/** SHA-1 digest algorithm
 *
 * Note that use of SHA-1 is implicit when using TLSv1.1 or earlier.
 */
#define CRYPTO_DIGEST_SHA1

/** SHA-224 digest algorithm */
#define CRYPTO_DIGEST_SHA224

/** SHA-256 digest algorithm
 *
 * Note that use of SHA-256 is implicit when using TLSv1.2.
 */
#define CRYPTO_DIGEST_SHA256

/** SHA-384 digest algorithm */
#define CRYPTO_DIGEST_SHA384

/** SHA-512 digest algorithm */
#define CRYPTO_DIGEST_SHA512

/** Margin of error (in seconds) allowed in signed timestamps
 *
 * We default to allowing a reasonable margin of error: 12 hours to
 * allow for the local time zone being non-GMT, plus 30 minutes to
 * allow for general clock drift.
 */
#define TIMESTAMP_ERROR_MARGIN ( ( 12 * 60 + 30 ) * 60 )

#include <config/named.h>
#include NAMED_CONFIG(crypto.h)
#include <config/local/crypto.h>
#include LOCAL_NAMED_CONFIG(crypto.h)

#endif /* CONFIG_CRYPTO_H */
