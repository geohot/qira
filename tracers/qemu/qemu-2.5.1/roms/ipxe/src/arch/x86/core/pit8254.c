/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

#include <assert.h>
#include <ipxe/io.h>
#include <ipxe/pit8254.h>

/** @file
 *
 * 8254 Programmable Interval Timer
 *
 */

/**
 * Delay for a fixed number of timer ticks using the speaker channel
 *
 * @v ticks		Number of timer ticks for which to delay
 */
void pit8254_speaker_delay ( unsigned int ticks ) {
	uint8_t spkr;
	uint8_t cmd;
	uint8_t low;
	uint8_t high;

	/* Sanity check */
	assert ( ticks <= 0xffff );

	/* Disable speaker, set speaker channel gate input high */
	spkr = inb ( PIT8254_SPKR );
	spkr &= ~PIT8254_SPKR_ENABLE;
	spkr |= PIT8254_SPKR_GATE;
	outb ( spkr, PIT8254_SPKR );

	/* Program speaker channel to "interrupt" on terminal count */
	cmd = ( PIT8254_CMD_CHANNEL ( PIT8254_CH_SPKR ) |
		PIT8254_CMD_ACCESS_LOHI | PIT8254_CMD_OP_TERMINAL |
		PIT8254_CMD_BINARY );
	low = ( ( ticks >> 0 ) & 0xff );
	high = ( ( ticks >> 8 ) & 0xff );
	outb ( cmd, PIT8254_CMD );
	outb ( low, PIT8254_DATA ( PIT8254_CH_SPKR ) );
	outb ( high, PIT8254_DATA ( PIT8254_CH_SPKR ) );

	/* Wait for channel to "interrupt" */
	do {
		spkr = inb ( PIT8254_SPKR );
	} while ( ! ( spkr & PIT8254_SPKR_OUT ) );
}
