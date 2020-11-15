#ifndef _BITS_PROFILE_H
#define _BITS_PROFILE_H

/** @file
 *
 * Profiling
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

/**
 * Get profiling timestamp
 *
 * @ret timestamp	Timestamp
 */
static inline __attribute__ (( always_inline )) uint64_t
profile_timestamp ( void ) {
	uint64_t tsc;

	/* Read timestamp counter */
	__asm__ __volatile__ ( "rdtsc" : "=A" ( tsc ) );
	return tsc;
}

#endif /* _BITS_PROFILE_H */
