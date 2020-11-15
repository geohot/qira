/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
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

/**
 * @file
 *
 * EFI watchdog holdoff timer
 *
 */

#include <errno.h>
#include <string.h>
#include <ipxe/retry.h>
#include <ipxe/timer.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_watchdog.h>

/** Watchdog holdoff interval (in seconds) */
#define WATCHDOG_HOLDOFF_SECS 10

/** Watchdog timeout (in seconds) */
#define WATCHDOG_TIMEOUT_SECS ( 5 * 60 )

/** Watchdog code (to be logged on watchdog timeout) */
#define WATCHDOG_CODE 0x6950584544454144ULL

/** Watchdog data (to be logged on watchdog timeout) */
#define WATCHDOG_DATA L"iPXE";

/**
 * Hold off watchdog timer
 *
 * @v retry		Retry timer
 * @v over		Failure indicator
 */
static void efi_watchdog_expired ( struct retry_timer *timer,
				   int over __unused ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	static CHAR16 data[] = WATCHDOG_DATA;
	EFI_STATUS efirc;
	int rc;

	DBGC2 ( timer, "EFI holding off watchdog timer\n" );

	/* Restart this holdoff timer */
	start_timer_fixed ( timer, ( WATCHDOG_HOLDOFF_SECS * TICKS_PER_SEC ) );

	/* Reset watchdog timer */
	if ( ( efirc = bs->SetWatchdogTimer ( WATCHDOG_TIMEOUT_SECS,
					      WATCHDOG_CODE, sizeof ( data ),
					      data ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBGC ( timer, "EFI could not set watchdog timer: %s\n",
		       strerror ( rc ) );
		return;
	}
}

/** Watchdog holdoff timer */
struct retry_timer efi_watchdog = TIMER_INIT ( efi_watchdog_expired );
