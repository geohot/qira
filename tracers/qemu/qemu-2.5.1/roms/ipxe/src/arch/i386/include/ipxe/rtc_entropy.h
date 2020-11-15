#ifndef _IPXE_RTC_ENTROPY_H
#define _IPXE_RTC_ENTROPY_H

/** @file
 *
 * RTC-based entropy source
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

#ifdef ENTROPY_RTC
#define ENTROPY_PREFIX_rtc
#else
#define ENTROPY_PREFIX_rtc __rtc_
#endif

/**
 * min-entropy per sample
 *
 * @ret min_entropy	min-entropy of each sample
 */
static inline __always_inline double
ENTROPY_INLINE ( rtc, min_entropy_per_sample ) ( void ) {

	/* The min-entropy has been measured on several platforms
	 * using the entropy_sample test code.  Modelling the samples
	 * as independent, and using a confidence level of 99.99%, the
	 * measurements were as follows:
	 *
	 *    qemu-kvm		: 7.38 bits
	 *    VMware		: 7.46 bits
	 *    Physical hardware	: 2.67 bits
	 *
	 * We choose the lowest of these (2.67 bits) and apply a 50%
	 * safety margin to allow for some potential non-independence
	 * of samples.
	 */
	return 1.3;
}

extern uint8_t rtc_sample ( void );

/**
 * Get noise sample
 *
 * @ret noise		Noise sample
 * @ret rc		Return status code
 */
static inline __always_inline int
ENTROPY_INLINE ( rtc, get_noise ) ( noise_sample_t *noise ) {

	/* Get sample */
	*noise = rtc_sample();

	/* Always successful */
	return 0;
}

#endif /* _IPXE_RTC_ENTROPY_H */
