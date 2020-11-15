#ifndef _IPXE_SHA1_H
#define _IPXE_SHA1_H

/** @file
 *
 * SHA-1 algorithm
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <ipxe/crypto.h>

/** An SHA-1 digest */
struct sha1_digest {
	/** Hash output */
	uint32_t h[5];
};

/** An SHA-1 data block */
union sha1_block {
	/** Raw bytes */
	uint8_t byte[64];
	/** Raw dwords */
	uint32_t dword[16];
	/** Final block structure */
	struct {
		/** Padding */
		uint8_t pad[56];
		/** Length in bits */
		uint64_t len;
	} final;
};

/** SHA-1 digest and data block
 *
 * The order of fields within this structure is designed to minimise
 * code size.
 */
struct sha1_digest_data {
	/** Digest of data already processed */
	struct sha1_digest digest;
	/** Accumulated data */
	union sha1_block data;
} __attribute__ (( packed ));

/** SHA-1 digest and data block */
union sha1_digest_data_dwords {
	/** Digest and data block */
	struct sha1_digest_data dd;
	/** Raw dwords */
	uint32_t dword[ sizeof ( struct sha1_digest_data ) /
			sizeof ( uint32_t ) ];
};

/** An SHA-1 context */
struct sha1_context {
	/** Amount of accumulated data */
	size_t len;
	/** Digest and accumulated data */
	union sha1_digest_data_dwords ddd;
} __attribute__ (( packed ));

/** SHA-1 context size */
#define SHA1_CTX_SIZE sizeof ( struct sha1_context )

/** SHA-1 digest size */
#define SHA1_DIGEST_SIZE sizeof ( struct sha1_digest )

extern struct digest_algorithm sha1_algorithm;

extern void prf_sha1 ( const void *key, size_t key_len, const char *label,
		       const void *data, size_t data_len, void *prf,
		       size_t prf_len );
extern void pbkdf2_sha1 ( const void *passphrase, size_t pass_len,
			  const void *salt, size_t salt_len,
			  int iterations, void *key, size_t key_len );

#endif /* _IPXE_SHA1_H */
