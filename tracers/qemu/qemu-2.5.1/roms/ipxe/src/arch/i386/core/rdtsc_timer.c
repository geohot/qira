/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * RDTSC timer
 *
 */

#include <assert.h>
#include <ipxe/timer.h>
#include <ipxe/pit8254.h>

/**
 * Number of TSC ticks per microsecond
 *
 * This is calibrated on the first use of the timer.
 */
static unsigned long rdtsc_ticks_per_usec;

/**
 * Delay for a fixed number of microseconds
 *
 * @v usecs		Number of microseconds for which to delay
 */
static void rdtsc_udelay ( unsigned long usecs ) {
	unsigned long start;
	unsigned long elapsed;

	/* Sanity guard, since we may divide by this */
	if ( ! usecs )
		usecs = 1;

	start = currticks();
	if ( rdtsc_ticks_per_usec ) {
		/* Already calibrated; busy-wait until done */
		do {
			elapsed = ( currticks() - start );
		} while ( elapsed < ( usecs * rdtsc_ticks_per_usec ) );
	} else {
		/* Not yet calibrated; use 8254 PIT and calibrate
		 * based on result.
		 */
		pit8254_udelay ( usecs );
		elapsed = ( currticks() - start );
		rdtsc_ticks_per_usec = ( elapsed / usecs );
		DBG ( "RDTSC timer calibrated: %ld ticks in %ld usecs "
		      "(%ld MHz)\n", elapsed, usecs,
		      ( rdtsc_ticks_per_usec << TSC_SHIFT ) );
	}
}

/**
 * Get number of ticks per second
 *
 * @ret ticks_per_sec	Number of ticks per second
 */
static unsigned long rdtsc_ticks_per_sec ( void ) {

	/* Calibrate timer, if not already done */
	if ( ! rdtsc_ticks_per_usec )
		udelay ( 1 );

	/* Sanity check */
	assert ( rdtsc_ticks_per_usec != 0 );

	return ( rdtsc_ticks_per_usec * 1000 * 1000 );
}

PROVIDE_TIMER ( rdtsc, udelay, rdtsc_udelay );
PROVIDE_TIMER_INLINE ( rdtsc, currticks );
PROVIDE_TIMER ( rdtsc, ticks_per_sec, rdtsc_ticks_per_sec );
