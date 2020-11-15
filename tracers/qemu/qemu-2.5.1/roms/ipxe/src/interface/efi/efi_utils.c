/*
 * Copyright (C) 2011 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_pci.h>
#include <ipxe/efi/efi_utils.h>

/** @file
 *
 * EFI utilities
 *
 */

/**
 * Find end of device path
 *
 * @v path		Path to device
 * @ret path_end	End of device path
 */
EFI_DEVICE_PATH_PROTOCOL * efi_devpath_end ( EFI_DEVICE_PATH_PROTOCOL *path ) {

	while ( path->Type != END_DEVICE_PATH_TYPE ) {
		path = ( ( ( void * ) path ) +
			 /* There's this amazing new-fangled thing known as
			  * a UINT16, but who wants to use one of those? */
			 ( ( path->Length[1] << 8 ) | path->Length[0] ) );
	}

	return path;
}

/**
 * Locate parent device supporting a given protocol
 *
 * @v device		EFI device handle
 * @v protocol		Protocol GUID
 * @v parent		Parent EFI device handle to fill in
 * @ret rc		Return status code
 */
int efi_locate_device ( EFI_HANDLE device, EFI_GUID *protocol,
			EFI_HANDLE *parent ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	union {
		EFI_DEVICE_PATH_PROTOCOL *path;
		void *interface;
	} path;
	EFI_DEVICE_PATH_PROTOCOL *devpath;
	EFI_STATUS efirc;
	int rc;

	/* Get device path */
	if ( ( efirc = bs->OpenProtocol ( device,
					  &efi_device_path_protocol_guid,
					  &path.interface,
					  efi_image_handle, device,
					  EFI_OPEN_PROTOCOL_GET_PROTOCOL ))!=0){
		rc = -EEFI ( efirc );
		DBGC ( device, "EFIDEV %p %s cannot open device path: %s\n",
		       device, efi_handle_name ( device ), strerror ( rc ) );
		goto err_open_device_path;
	}
	devpath = path.path;

	/* Check for presence of specified protocol */
	if ( ( efirc = bs->LocateDevicePath ( protocol, &devpath,
					      parent ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBGC ( device, "EFIDEV %p %s has no parent supporting %s: %s\n",
		       device, efi_handle_name ( device ),
		       efi_guid_ntoa ( protocol ), strerror ( rc ) );
		goto err_locate_protocol;
	}

	/* Success */
	rc = 0;

 err_locate_protocol:
	bs->CloseProtocol ( device, &efi_device_path_protocol_guid,
			    efi_image_handle, device );
 err_open_device_path:
	return rc;
}

/**
 * Add EFI device as child of another EFI device
 *
 * @v parent		EFI parent device handle
 * @v child		EFI child device handle
 * @ret rc		Return status code
 */
int efi_child_add ( EFI_HANDLE parent, EFI_HANDLE child ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	void *devpath;
	EFI_STATUS efirc;
	int rc;

	/* Re-open the device path protocol */
	if ( ( efirc = bs->OpenProtocol ( parent,
					  &efi_device_path_protocol_guid,
					  &devpath,
					  efi_image_handle, child,
					  EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER
					  ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBGC ( parent, "EFIDEV %p %s could not add child",
		       parent, efi_handle_name ( parent ) );
		DBGC ( parent, " %p %s: %s\n", child,
		       efi_handle_name ( child ), strerror ( rc ) );
		DBGC_EFI_OPENERS ( parent, parent,
				   &efi_device_path_protocol_guid );
		return rc;
	}

	DBGC2 ( parent, "EFIDEV %p %s added child",
		parent, efi_handle_name ( parent ) );
	DBGC2 ( parent, " %p %s\n", child, efi_handle_name ( child ) );
	return 0;
}

/**
 * Remove EFI device as child of another EFI device
 *
 * @v parent		EFI parent device handle
 * @v child		EFI child device handle
 */
void efi_child_del ( EFI_HANDLE parent, EFI_HANDLE child ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;

	bs->CloseProtocol ( parent, &efi_device_path_protocol_guid,
			    efi_image_handle, child );
	DBGC2 ( parent, "EFIDEV %p %s removed child",
		parent, efi_handle_name ( parent ) );
	DBGC2 ( parent, " %p %s\n",
		child, efi_handle_name ( child ) );
}

/**
 * Get underlying PCI device information
 *
 * @v device		EFI device handle
 * @v prefix		Device name prefix
 * @v dev		Generic device to fill in
 * @ret rc		Return status code
 */
static int efi_pci_info ( EFI_HANDLE device, const char *prefix,
			  struct device *dev ) {
	EFI_HANDLE pci_device;
	struct pci_device pci;
	int rc;

	/* Find parent PCI device */
	if ( ( rc = efi_locate_device ( device, &efi_pci_io_protocol_guid,
					&pci_device ) ) != 0 ) {
		DBGC ( device, "EFIDEV %p %s is not a PCI device: %s\n",
		       device, efi_handle_name ( device ), strerror ( rc ) );
		return rc;
	}

	/* Get PCI device information */
	if ( ( rc = efipci_info ( pci_device, &pci ) ) != 0 ) {
		DBGC ( device, "EFIDEV %p %s could not get PCI information: "
		       "%s\n", device, efi_handle_name ( device ),
		       strerror ( rc ) );
		return rc;
	}

	/* Populate device information */
	memcpy ( &dev->desc, &pci.dev.desc, sizeof ( dev->desc ) );
	snprintf ( dev->name, sizeof ( dev->name ), "%s-%s",
		   prefix, pci.dev.name );

	return 0;
}

/**
 * Get underlying device information
 *
 * @v device		EFI device handle
 * @v prefix		Device name prefix
 * @v dev		Generic device to fill in
 */
void efi_device_info ( EFI_HANDLE device, const char *prefix,
		       struct device *dev ) {
	int rc;

	/* Try getting underlying PCI device information */
	if ( ( rc = efi_pci_info ( device, prefix, dev ) ) == 0 )
		return;

	/* If we cannot get any underlying device information, fall
	 * back to providing information about the EFI handle.
	 */
	DBGC ( device, "EFIDEV %p %s could not get underlying device "
	       "information\n", device, efi_handle_name ( device ) );
	dev->desc.bus_type = BUS_TYPE_EFI;
	snprintf ( dev->name, sizeof ( dev->name ), "%s-%p", prefix, device );
}
