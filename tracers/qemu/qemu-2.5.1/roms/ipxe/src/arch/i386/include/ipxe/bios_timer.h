#ifndef _IPXE_BIOS_TIMER_H
#define _IPXE_BIOS_TIMER_H

/** @file
 *
 * BIOS timer
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef TIMER_PCBIOS
#define TIMER_PREFIX_pcbios
#else
#define TIMER_PREFIX_pcbios __pcbios_
#endif

#include <ipxe/pit8254.h>

/**
 * Delay for a fixed number of microseconds
 *
 * @v usecs		Number of microseconds for which to delay
 */
static inline __always_inline void
TIMER_INLINE ( pcbios, udelay ) ( unsigned long usecs ) {
	/* BIOS timer is not high-resolution enough for udelay(), so
	 * we use the 8254 Programmable Interval Timer.
	 */
	pit8254_udelay ( usecs );
}

/**
 * Get number of ticks per second
 *
 * @ret ticks_per_sec	Number of ticks per second
 */
static inline __always_inline unsigned long
TIMER_INLINE ( pcbios, ticks_per_sec ) ( void ) {
	/* BIOS timer ticks over at 18.2 ticks per second */
	return 18;
}

#endif /* _IPXE_BIOS_TIMER_H */
