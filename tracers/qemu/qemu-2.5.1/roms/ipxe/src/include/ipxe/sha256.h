#ifndef _IPXE_SHA256_H
#define _IPXE_SHA256_H

/** @file
 *
 * SHA-256 algorithm
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/crypto.h>

/** SHA-256 number of rounds */
#define SHA256_ROUNDS 64

/** An SHA-256 digest */
struct sha256_digest {
	/** Hash output */
	uint32_t h[8];
};

/** An SHA-256 data block */
union sha256_block {
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

/** SHA-256 digest and data block
 *
 * The order of fields within this structure is designed to minimise
 * code size.
 */
struct sha256_digest_data {
	/** Digest of data already processed */
	struct sha256_digest digest;
	/** Accumulated data */
	union sha256_block data;
} __attribute__ (( packed ));

/** SHA-256 digest and data block */
union sha256_digest_data_dwords {
	/** Digest and data block */
	struct sha256_digest_data dd;
	/** Raw dwords */
	uint32_t dword[ sizeof ( struct sha256_digest_data ) /
			sizeof ( uint32_t ) ];
};

/** An SHA-256 context */
struct sha256_context {
	/** Amount of accumulated data */
	size_t len;
	/** Digest size */
	size_t digestsize;
	/** Digest and accumulated data */
	union sha256_digest_data_dwords ddd;
} __attribute__ (( packed ));

/** SHA-256 context size */
#define SHA256_CTX_SIZE sizeof ( struct sha256_context )

/** SHA-256 digest size */
#define SHA256_DIGEST_SIZE sizeof ( struct sha256_digest )

/** SHA-224 digest size */
#define SHA224_DIGEST_SIZE ( SHA256_DIGEST_SIZE * 224 / 256 )

extern void sha256_family_init ( struct sha256_context *context,
				 const struct sha256_digest *init,
				 size_t digestsize );
extern void sha256_update ( void *ctx, const void *data, size_t len );
extern void sha256_final ( void *ctx, void *out );

extern struct digest_algorithm sha256_algorithm;
extern struct digest_algorithm sha224_algorithm;

#endif /* _IPXE_SHA256_H */
