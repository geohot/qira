/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
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
 * EFI reboot mechanism
 *
 */

#include <errno.h>
#include <ipxe/efi/efi.h>
#include <ipxe/reboot.h>

/**
 * Reboot system
 *
 * @v warm		Perform a warm reboot
 */
static void efi_reboot ( int warm ) {
	EFI_RUNTIME_SERVICES *rs = efi_systab->RuntimeServices;

	/* Use runtime services to reset system */
	rs->ResetSystem ( ( warm ? EfiResetWarm : EfiResetCold ), 0, 0, NULL );
}

/**
 * Power off system
 *
 * @ret rc		Return status code
 */
static int efi_poweroff ( void ) {
	EFI_RUNTIME_SERVICES *rs = efi_systab->RuntimeServices;

	/* Use runtime services to power off system */
	rs->ResetSystem ( EfiResetShutdown, 0, 0, NULL );

	/* Should never happen */
	return -ECANCELED;
}

PROVIDE_REBOOT ( efi, reboot, efi_reboot );
PROVIDE_REBOOT ( efi, poweroff, efi_poweroff );
