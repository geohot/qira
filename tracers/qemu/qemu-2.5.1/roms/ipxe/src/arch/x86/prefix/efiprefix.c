/*
 * Copyright (C) 2009 Michael Brown <mbrown@fensystems.co.uk>.
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
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdlib.h>
#include <errno.h>
#include <ipxe/device.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_driver.h>
#include <ipxe/efi/efi_snp.h>
#include <ipxe/efi/efi_autoboot.h>
#include <ipxe/efi/efi_watchdog.h>

/**
 * EFI entry point
 *
 * @v image_handle	Image handle
 * @v systab		System table
 * @ret efirc		EFI return status code
 */
EFI_STATUS EFIAPI _efi_start ( EFI_HANDLE image_handle,
			       EFI_SYSTEM_TABLE *systab ) {
	EFI_STATUS efirc;
	int rc;

	/* Initialise EFI environment */
	if ( ( efirc = efi_init ( image_handle, systab ) ) != 0 )
		goto err_init;

	/* Record autoboot device (if any) */
	efi_set_autoboot();

	/* Claim SNP devices for use by iPXE */
	efi_snp_claim();

	/* Start watchdog holdoff timer */
	efi_watchdog_start();

	/* Call to main() */
	if ( ( rc = main() ) != 0 ) {
		efirc = EFIRC ( rc );
		goto err_main;
	}

 err_main:
	efi_watchdog_stop();
	efi_snp_release();
	efi_loaded_image->Unload ( image_handle );
	efi_driver_reconnect_all();
 err_init:
	return efirc;
}

/**
 * Probe EFI root bus
 *
 * @v rootdev		EFI root device
 */
static int efi_probe ( struct root_device *rootdev __unused ) {

	return efi_driver_connect_all();
}

/**
 * Remove EFI root bus
 *
 * @v rootdev		EFI root device
 */
static void efi_remove ( struct root_device *rootdev __unused ) {

	efi_driver_disconnect_all();
}

/** EFI root device driver */
static struct root_driver efi_root_driver = {
	.probe = efi_probe,
	.remove = efi_remove,
};

/** EFI root device */
struct root_device efi_root_device __root_device = {
	.dev = { .name = "EFI" },
	.driver = &efi_root_driver,
};
