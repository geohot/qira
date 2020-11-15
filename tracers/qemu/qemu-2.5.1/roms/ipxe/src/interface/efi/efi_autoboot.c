/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_autoboot.h>
#include <ipxe/efi/Protocol/SimpleNetwork.h>
#include <usr/autoboot.h>

/** @file
 *
 * EFI autoboot device
 *
 */

/**
 * Identify autoboot device
 *
 */
void efi_set_autoboot ( void ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	union {
		EFI_SIMPLE_NETWORK_PROTOCOL *snp;
		void *interface;
	} snp;
	EFI_SIMPLE_NETWORK_MODE *mode;
	EFI_STATUS efirc;

	/* Look for an SNP instance on the image's device handle */
	if ( ( efirc = bs->OpenProtocol ( efi_loaded_image->DeviceHandle,
					  &efi_simple_network_protocol_guid,
					  &snp.interface, efi_image_handle,
					  NULL,
					  EFI_OPEN_PROTOCOL_GET_PROTOCOL ))!=0){
		DBGC ( efi_loaded_image, "EFI found no autoboot device\n" );
		return;
	}

	/* Record autoboot device */
	mode = snp.snp->Mode;
	set_autoboot_ll_addr ( &mode->CurrentAddress, mode->HwAddressSize );
	DBGC ( efi_loaded_image, "EFI found autoboot link-layer address:\n" );
	DBGC_HDA ( efi_loaded_image, 0, &mode->CurrentAddress,
		   mode->HwAddressSize );

	/* Close protocol */
	bs->CloseProtocol ( efi_loaded_image->DeviceHandle,
			    &efi_simple_network_protocol_guid,
			    efi_image_handle, NULL );
}
