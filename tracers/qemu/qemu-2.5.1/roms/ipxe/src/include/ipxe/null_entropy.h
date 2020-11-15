#ifndef _IPXE_NULL_ENTROPY_H
#define _IPXE_NULL_ENTROPY_H

/** @file
 *
 * Nonexistent entropy source
 *
 * This source provides no entropy and must NOT be used in a
 * security-sensitive environment.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

#ifdef ENTROPY_NULL
#define ENTROPY_PREFIX_null
#else
#define ENTROPY_PREFIX_null __null_
#endif

static inline __always_inline int
ENTROPY_INLINE ( null, entropy_enable ) ( void ) {
	/* Do nothing */
	return 0;
}

static inline __always_inline void
ENTROPY_INLINE ( null, entropy_disable ) ( void ) {
	/* Do nothing */
}

static inline __always_inline double
ENTROPY_INLINE ( null, min_entropy_per_sample ) ( void ) {
	/* Actual amount of min-entropy is zero.  To avoid
	 * division-by-zero errors and to allow compilation of
	 * entropy-consuming code, pretend to have 1 bit of entropy in
	 * each sample.
	 */
	return 1.0;
}

static inline __always_inline int
ENTROPY_INLINE ( null, get_noise ) ( noise_sample_t *noise ) {

	/* All sample values are constant */
	*noise = 0x01;

	return 0;
}

#endif /* _IPXE_NULL_ENTROPY_H */
