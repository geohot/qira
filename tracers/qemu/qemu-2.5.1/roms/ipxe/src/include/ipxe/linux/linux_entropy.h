#ifndef _IPXE_LINUX_ENTROPY_H
#define _IPXE_LINUX_ENTROPY_H

/** @file
 *
 * /dev/random-based entropy source
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef ENTROPY_LINUX
#define ENTROPY_PREFIX_linux
#else
#define ENTROPY_PREFIX_linux __linux_
#endif

/**
 * min-entropy per sample
 *
 * @ret min_entropy	min-entropy of each sample
 */
static inline __always_inline double
ENTROPY_INLINE ( linux, min_entropy_per_sample ) ( void ) {

	/* linux_get_noise() reads a single byte from /dev/random,
	 * which is supposed to block until a sufficient amount of
	 * entropy is available.  We therefore assume that each sample
	 * contains exactly 8 bits of entropy.
	 */
	return 8.0;
}

#endif /* _IPXE_LINUX_ENTROPY_H */
