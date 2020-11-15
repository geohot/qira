#ifndef _IPXE_HMAC_H
#define _IPXE_HMAC_H

/** @file
 *
 * Keyed-Hashing for Message Authentication
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/crypto.h>

/**
 * Update HMAC
 *
 * @v digest		Digest algorithm to use
 * @v digest_ctx	Digest context
 * @v data		Data
 * @v len		Length of data
 */
static inline void hmac_update ( struct digest_algorithm *digest,
				 void *digest_ctx, const void *data,
				 size_t len ) {
	digest_update ( digest, digest_ctx, data, len );
}

extern void hmac_init ( struct digest_algorithm *digest, void *digest_ctx,
			void *key, size_t *key_len );
extern void hmac_final ( struct digest_algorithm *digest, void *digest_ctx,
			 void *key, size_t *key_len, void *hmac );

#endif /* _IPXE_HMAC_H */
