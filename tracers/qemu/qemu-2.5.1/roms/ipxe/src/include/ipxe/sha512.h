#ifndef _IPXE_SHA512_H
#define _IPXE_SHA512_H

/** @file
 *
 * SHA-512 algorithm
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/crypto.h>

/** SHA-512 number of rounds */
#define SHA512_ROUNDS 80

/** An SHA-512 digest */
struct sha512_digest {
	/** Hash output */
	uint64_t h[8];
};

/** An SHA-512 data block */
union sha512_block {
	/** Raw bytes */
	uint8_t byte[128];
	/** Raw qwords */
	uint64_t qword[16];
	/** Final block structure */
	struct {
		/** Padding */
		uint8_t pad[112];
		/** High 64 bits of length in bits */
		uint64_t len_hi;
		/** Low 64 bits of length in bits */
		uint64_t len_lo;
	} final;
};

/** SHA-512 digest and data block
 *
 * The order of fields within this structure is designed to minimise
 * code size.
 */
struct sha512_digest_data {
	/** Digest of data already processed */
	struct sha512_digest digest;
	/** Accumulated data */
	union sha512_block data;
} __attribute__ (( packed ));

/** SHA-512 digest and data block */
union sha512_digest_data_qwords {
	/** Digest and data block */
	struct sha512_digest_data dd;
	/** Raw qwords */
	uint64_t qword[ sizeof ( struct sha512_digest_data ) /
			sizeof ( uint64_t ) ];
};

/** An SHA-512 context */
struct sha512_context {
	/** Amount of accumulated data */
	size_t len;
	/** Digest size */
	size_t digestsize;
	/** Digest and accumulated data */
	union sha512_digest_data_qwords ddq;
} __attribute__ (( packed ));

/** SHA-512 context size */
#define SHA512_CTX_SIZE sizeof ( struct sha512_context )

/** SHA-512 digest size */
#define SHA512_DIGEST_SIZE sizeof ( struct sha512_digest )

/** SHA-384 digest size */
#define SHA384_DIGEST_SIZE ( SHA512_DIGEST_SIZE * 384 / 512 )

/** SHA-512/256 digest size */
#define SHA512_256_DIGEST_SIZE ( SHA512_DIGEST_SIZE * 256 / 512 )

/** SHA-512/224 digest size */
#define SHA512_224_DIGEST_SIZE ( SHA512_DIGEST_SIZE * 224 / 512 )

extern void sha512_family_init ( struct sha512_context *context,
				 const struct sha512_digest *init,
				 size_t digestsize );
extern void sha512_update ( void *ctx, const void *data, size_t len );
extern void sha512_final ( void *ctx, void *out );

extern struct digest_algorithm sha512_algorithm;
extern struct digest_algorithm sha384_algorithm;
extern struct digest_algorithm sha512_256_algorithm;
extern struct digest_algorithm sha512_224_algorithm;

#endif /* IPXE_SHA512_H */
