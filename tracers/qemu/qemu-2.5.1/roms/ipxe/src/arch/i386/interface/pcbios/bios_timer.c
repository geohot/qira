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
 * BIOS timer
 *
 */

#include <ipxe/timer.h>
#include <realmode.h>
#include <bios.h>

/**
 * Get current system time in ticks
 *
 * @ret ticks		Current time, in ticks
 *
 * Use direct memory access to BIOS variables, longword 0040:006C
 * (ticks today) and byte 0040:0070 (midnight crossover flag) instead
 * of calling timeofday BIOS interrupt.
 */
static unsigned long bios_currticks ( void ) {
	static int days = 0;
	uint32_t ticks;
	uint8_t midnight;

	/* Re-enable interrupts so that the timer interrupt can occur */
	__asm__ __volatile__ ( "sti\n\t"
			       "nop\n\t"
			       "nop\n\t"
			       "cli\n\t" );

	get_real ( ticks, BDA_SEG, 0x006c );
	get_real ( midnight, BDA_SEG, 0x0070 );

	if ( midnight ) {
		midnight = 0;
		put_real ( midnight, BDA_SEG, 0x0070 );
		days += 0x1800b0;
	}

	return ( days + ticks );
}

PROVIDE_TIMER_INLINE ( pcbios, udelay );
PROVIDE_TIMER ( pcbios, currticks, bios_currticks );
PROVIDE_TIMER_INLINE ( pcbios, ticks_per_sec );
