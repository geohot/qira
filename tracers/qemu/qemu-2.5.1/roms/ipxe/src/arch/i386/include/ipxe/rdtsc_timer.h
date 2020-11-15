#ifndef _IPXE_RDTSC_TIMER_H
#define _IPXE_RDTSC_TIMER_H

/** @file
 *
 * RDTSC timer
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef TIMER_RDTSC
#define TIMER_PREFIX_rdtsc
#else
#define TIMER_PREFIX_rdtsc __rdtsc_
#endif

/**
 * RDTSC values can easily overflow an unsigned long.  We discard the
 * low-order bits in order to obtain sensibly-scaled values.
 */
#define TSC_SHIFT 8

/**
 * Get current system time in ticks
 *
 * @ret ticks		Current time, in ticks
 */
static inline __always_inline unsigned long
TIMER_INLINE ( rdtsc, currticks ) ( void ) {
	unsigned long ticks;

	__asm__ __volatile__ ( "rdtsc\n\t"
			       "shrdl %1, %%edx, %%eax\n\t"
			       : "=a" ( ticks ) : "i" ( TSC_SHIFT ) : "edx" );
	return ticks;
}

#endif /* _IPXE_RDTSC_TIMER_H */
