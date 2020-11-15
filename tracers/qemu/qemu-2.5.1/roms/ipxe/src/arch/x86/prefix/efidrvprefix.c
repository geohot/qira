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
#include <ipxe/init.h>
#include <ipxe/device.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_driver.h>

/**
 * EFI entry point
 *
 * @v image_handle	Image handle
 * @v systab		System table
 * @ret efirc		EFI return status code
 */
EFI_STATUS EFIAPI _efidrv_start ( EFI_HANDLE image_handle,
				  EFI_SYSTEM_TABLE *systab ) {
	EFI_STATUS efirc;

	/* Initialise EFI environment */
	if ( ( efirc = efi_init ( image_handle, systab ) ) != 0 )
		return efirc;

	/* Initialise iPXE environment */
	initialise();
	startup();

	return 0;
}

/**
 * Probe EFI root bus
 *
 * @v rootdev		EFI root device
 */
static int efi_probe ( struct root_device *rootdev __unused ) {

	/* Do nothing */
	return 0;
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
