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

#include <string.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>
#include <unistd.h>
#include <ipxe/timer.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/Cpu.h>

/** @file
 *
 * iPXE timer API for EFI
 *
 */

/** Scale factor to apply to CPU timer 0
 *
 * The timer is scaled down in order to ensure that reasonable values
 * for "number of ticks" don't exceed the size of an unsigned long.
 */
#define EFI_TIMER0_SHIFT 12

/** Calibration time */
#define EFI_CALIBRATE_DELAY_MS 1

/** CPU protocol */
static EFI_CPU_ARCH_PROTOCOL *cpu_arch;
EFI_REQUIRE_PROTOCOL ( EFI_CPU_ARCH_PROTOCOL, &cpu_arch );

/**
 * Delay for a fixed number of microseconds
 *
 * @v usecs		Number of microseconds for which to delay
 */
static void efi_udelay ( unsigned long usecs ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_STATUS efirc;
	int rc;

	if ( ( efirc = bs->Stall ( usecs ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBG ( "EFI could not delay for %ldus: %s\n",
		      usecs, strerror ( rc ) );
		/* Probably screwed */
	}
}

/**
 * Get current system time in ticks
 *
 * @ret ticks		Current time, in ticks
 */
static unsigned long efi_currticks ( void ) {
	UINT64 time;
	EFI_STATUS efirc;
	int rc;

	/* Read CPU timer 0 (TSC) */
	if ( ( efirc = cpu_arch->GetTimerValue ( cpu_arch, 0, &time,
						 NULL ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBG ( "EFI could not read CPU timer: %s\n", strerror ( rc ) );
		/* Probably screwed */
		return -1UL;
	}

	return ( time >> EFI_TIMER0_SHIFT );
}

/**
 * Get number of ticks per second
 *
 * @ret ticks_per_sec	Number of ticks per second
 */
static unsigned long efi_ticks_per_sec ( void ) {
	static unsigned long ticks_per_sec = 0;

	/* Calibrate timer, if necessary.  EFI does nominally provide
	 * the timer speed via the (optional) TimerPeriod parameter to
	 * the GetTimerValue() call, but it gets the speed slightly
	 * wrong.  By up to three orders of magnitude.  Not helpful.
	 */
	if ( ! ticks_per_sec ) {
		unsigned long start;
		unsigned long elapsed;

		DBG ( "Calibrating EFI timer with a %d ms delay\n",
		      EFI_CALIBRATE_DELAY_MS );
		start = currticks();
		mdelay ( EFI_CALIBRATE_DELAY_MS );
		elapsed = ( currticks() - start );
		ticks_per_sec = ( elapsed * ( 1000 / EFI_CALIBRATE_DELAY_MS ));
		DBG ( "EFI CPU timer calibrated at %ld ticks in %d ms (%ld "
		      "ticks/sec)\n", elapsed, EFI_CALIBRATE_DELAY_MS,
		      ticks_per_sec );
	}

	return ticks_per_sec;
}

PROVIDE_TIMER ( efi, udelay, efi_udelay );
PROVIDE_TIMER ( efi, currticks, efi_currticks );
PROVIDE_TIMER ( efi, ticks_per_sec, efi_ticks_per_sec );
