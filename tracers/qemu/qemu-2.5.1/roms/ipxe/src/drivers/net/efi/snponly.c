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

#include <string.h>
#include <errno.h>
#include <ipxe/init.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_driver.h>
#include <ipxe/efi/efi_utils.h>
#include <ipxe/efi/Protocol/SimpleNetwork.h>
#include <ipxe/efi/Protocol/NetworkInterfaceIdentifier.h>
#include "snpnet.h"
#include "nii.h"

/** @file
 *
 * EFI chainloaded-device-only driver
 *
 */

/** A chainloaded protocol */
struct chained_protocol {
	/** Protocol GUID */
	EFI_GUID *protocol;
	/**
	 * Protocol instance installed on the loaded image's device handle
	 *
	 * We match against the protocol instance (rather than simply
	 * matching against the device handle itself) because some
	 * systems load us via a child of the underlying device, with
	 * a duplicate protocol installed on the child handle.
	 */
	void *interface;
};

/** Chainloaded SNP protocol */
static struct chained_protocol chained_snp = {
	.protocol = &efi_simple_network_protocol_guid,
};

/** Chainloaded NII protocol */
static struct chained_protocol chained_nii = {
	.protocol = &efi_nii31_protocol_guid,
};

/**
 * Locate chainloaded protocol instance
 *
 * @v chained		Chainloaded protocol
 * @ret rc		Return status code
 */
static int chained_locate ( struct chained_protocol *chained ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_HANDLE device = efi_loaded_image->DeviceHandle;
	EFI_HANDLE parent;
	EFI_STATUS efirc;
	int rc;

	/* Locate handle supporting this protocol */
	if ( ( rc = efi_locate_device ( device, chained->protocol,
					&parent ) ) != 0 ) {
		DBGC ( device, "CHAINED %p %s does not support %s: %s\n",
		       device, efi_handle_name ( device ),
		       efi_guid_ntoa ( chained->protocol ), strerror ( rc ) );
		goto err_locate_device;
	}
	DBGC ( device, "CHAINED %p %s found %s on ", device,
	       efi_handle_name ( device ), efi_guid_ntoa ( chained->protocol ));
	DBGC ( device, "%p %s\n", parent, efi_handle_name ( parent ) );

	/* Get protocol instance */
	if ( ( efirc = bs->OpenProtocol ( parent, chained->protocol,
					  &chained->interface, efi_image_handle,
					  device,
					  EFI_OPEN_PROTOCOL_GET_PROTOCOL ))!=0){
		rc = -EEFI ( efirc );
		DBGC ( device, "CHAINED %p %s could not open %s on ",
		       device, efi_handle_name ( device ),
		       efi_guid_ntoa ( chained->protocol ) );
		DBGC ( device, "%p %s: %s\n",
		       parent, efi_handle_name ( parent ), strerror ( rc ) );
		goto err_open_protocol;
	}

 err_locate_device:
	bs->CloseProtocol ( parent, chained->protocol, efi_image_handle,
			    device );
 err_open_protocol:
	return rc;
}

/**
 * Check to see if driver supports a device
 *
 * @v device		EFI device handle
 * @v chained		Chainloaded protocol
 * @ret rc		Return status code
 */
static int chained_supported ( EFI_HANDLE device,
			       struct chained_protocol *chained ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_STATUS efirc;
	void *interface;
	int rc;

	/* Get protocol */
	if ( ( efirc = bs->OpenProtocol ( device, chained->protocol, &interface,
					  efi_image_handle, device,
					  EFI_OPEN_PROTOCOL_GET_PROTOCOL ))!=0){
		rc = -EEFI ( efirc );
		DBGCP ( device, "CHAINED %p %s is not a %s device\n",
			device, efi_handle_name ( device ),
			efi_guid_ntoa ( chained->protocol ) );
		goto err_open_protocol;
	}

	/* Test for a match against the chainloading device */
	if ( interface != chained->interface ) {
		DBGC ( device, "CHAINED %p %s %p is not the chainloaded "
		       "%s\n", device, efi_handle_name ( device ),
		       interface, efi_guid_ntoa ( chained->protocol ) );
		rc = -ENOTTY;
		goto err_no_match;
	}

	/* Success */
	rc = 0;
	DBGC ( device, "CHAINED %p %s %p is the chainloaded %s\n",
	       device, efi_handle_name ( device ), interface,
	       efi_guid_ntoa ( chained->protocol ) );

 err_no_match:
	bs->CloseProtocol ( device, chained->protocol, efi_image_handle,
			    device );
 err_open_protocol:
	return rc;
}

/**
 * Check to see if driver supports a device
 *
 * @v device		EFI device handle
 * @ret rc		Return status code
 */
static int snponly_supported ( EFI_HANDLE device ) {

	return chained_supported ( device, &chained_snp );
}

/**
 * Check to see if driver supports a device
 *
 * @v device		EFI device handle
 * @ret rc		Return status code
 */
static int niionly_supported ( EFI_HANDLE device ) {

	return chained_supported ( device, &chained_nii );
}

/** EFI SNP chainloading-device-only driver */
struct efi_driver snponly_driver __efi_driver ( EFI_DRIVER_NORMAL ) = {
	.name = "SNPONLY",
	.supported = snponly_supported,
	.start = snpnet_start,
	.stop = snpnet_stop,
};

/** EFI NII chainloading-device-only driver */
struct efi_driver niionly_driver __efi_driver ( EFI_DRIVER_NORMAL ) = {
	.name = "NIIONLY",
	.supported = niionly_supported,
	.start = nii_start,
	.stop = nii_stop,
};

/**
 * Initialise EFI chainloaded-device-only driver
 *
 */
static void chained_init ( void ) {

	chained_locate ( &chained_snp );
	chained_locate ( &chained_nii );
}

/** EFI chainloaded-device-only initialisation function */
struct init_fn chained_init_fn __init_fn ( INIT_LATE ) = {
	.initialise = chained_init,
};
