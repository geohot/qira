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

#include <string.h>
#include <errno.h>
#include <time.h>
#include <ipxe/time.h>
#include <ipxe/efi/efi.h>

/** @file
 *
 * EFI time source
 *
 */

/**
 * Get current time in seconds
 *
 * @ret time		Time, in seconds
 */
static time_t efi_get_time ( void ) {
	EFI_RUNTIME_SERVICES *rs = efi_systab->RuntimeServices;
	EFI_TIME time;
	struct tm tm;
	EFI_STATUS efirc;
	int rc;

	/* Get current time and date */
	if ( ( efirc = rs->GetTime ( &time, NULL ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBGC ( rs, "EFITIME could not get system time: %s\n",
		       strerror ( rc ) );
		/* Nothing meaningful we can return */
		return 0;
	}

	/* Construct broken-down time */
	memset ( &tm, 0, sizeof ( tm ) );
	tm.tm_sec = time.Second;
	tm.tm_min = time.Minute;
	tm.tm_hour = time.Hour;
	tm.tm_mday = time.Day;
	tm.tm_mon = ( time.Month - 1 );
	tm.tm_year = ( time.Year - 1900 );
	DBGC ( rs, "EFITIME is %04d-%02d-%02d %02d:%02d:%02d\n",
	       ( tm.tm_year + 1900 ), ( tm.tm_mon + 1 ),
	       tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec );

	/* Convert to seconds since the Epoch */
	return mktime ( &tm );
}

PROVIDE_TIME ( efi, time_now, efi_get_time );
