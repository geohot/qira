#ifndef _IPXE_HASH_DF_H
#define _IPXE_HASH_DF_H

/** @file
 *
 * Hash-based derivation function (Hash_df)
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/crypto.h>

extern void hash_df ( struct digest_algorithm *hash, const void *input,
		      size_t input_len, void *output, size_t output_len );

#endif /* _IPXE_HASH_DF_H */
