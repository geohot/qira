#ifndef _IPXE_MD5_H
#define _IPXE_MD5_H

/** @file
 *
 * MD5 algorithm
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/crypto.h>

/** An MD5 digest */
struct md5_digest {
	/** Hash output */
	uint32_t h[4];
};

/** An MD5 data block */
union md5_block {
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

/** MD5 digest and data block
 *
 * The order of fields within this structure is designed to minimise
 * code size.
 */
struct md5_digest_data {
	/** Digest of data already processed */
	struct md5_digest digest;
	/** Accumulated data */
	union md5_block data;
} __attribute__ (( packed ));

/** MD5 digest and data block */
union md5_digest_data_dwords {
	/** Digest and data block */
	struct md5_digest_data dd;
	/** Raw dwords */
	uint32_t dword[ sizeof ( struct md5_digest_data ) /
			sizeof ( uint32_t ) ];
};

/** An MD5 context */
struct md5_context {
	/** Amount of accumulated data */
	size_t len;
	/** Digest and accumulated data */
	union md5_digest_data_dwords ddd;
} __attribute__ (( packed ));

/** MD5 context size */
#define MD5_CTX_SIZE sizeof ( struct md5_context )

/** MD5 digest size */
#define MD5_DIGEST_SIZE sizeof ( struct md5_digest )

extern struct digest_algorithm md5_algorithm;

#endif /* _IPXE_MD5_H */
