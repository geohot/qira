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

#include <stdlib.h>
#include <errno.h>
#include <ipxe/pci.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_pci.h>
#include <ipxe/efi/efi_driver.h>
#include <ipxe/efi/Protocol/PciIo.h>
#include <ipxe/efi/Protocol/PciRootBridgeIo.h>

/** @file
 *
 * iPXE PCI I/O API for EFI
 *
 */

/* Disambiguate the various error causes */
#define EINFO_EEFI_PCI							\
	__einfo_uniqify ( EINFO_EPLATFORM, 0x01,			\
			  "Could not open PCI I/O protocol" )
#define EINFO_EEFI_PCI_NOT_PCI						\
	__einfo_platformify ( EINFO_EEFI_PCI, EFI_UNSUPPORTED,		\
			      "Not a PCI device" )
#define EEFI_PCI_NOT_PCI __einfo_error ( EINFO_EEFI_PCI_NOT_PCI )
#define EINFO_EEFI_PCI_IN_USE						\
	__einfo_platformify ( EINFO_EEFI_PCI, EFI_ACCESS_DENIED,	\
			      "PCI device already has a driver" )
#define EEFI_PCI_IN_USE __einfo_error ( EINFO_EEFI_PCI_IN_USE )
#define EEFI_PCI( efirc )						\
	EPLATFORM ( EINFO_EEFI_PCI, efirc,				\
		    EEFI_PCI_NOT_PCI, EEFI_PCI_IN_USE )

/******************************************************************************
 *
 * iPXE PCI API
 *
 ******************************************************************************
 */

/** PCI root bridge I/O protocol */
static EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *efipci;
EFI_REQUEST_PROTOCOL ( EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL, &efipci );

static unsigned long efipci_address ( struct pci_device *pci,
				      unsigned long location ) {
	return EFI_PCI_ADDRESS ( PCI_BUS ( pci->busdevfn ),
				 PCI_SLOT ( pci->busdevfn ),
				 PCI_FUNC ( pci->busdevfn ),
				 EFIPCI_OFFSET ( location ) );
}

int efipci_read ( struct pci_device *pci, unsigned long location,
		  void *value ) {
	EFI_STATUS efirc;
	int rc;

	if ( ! efipci )
		return -ENOTSUP;

	if ( ( efirc = efipci->Pci.Read ( efipci, EFIPCI_WIDTH ( location ),
					  efipci_address ( pci, location ), 1,
					  value ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBG ( "EFIPCI config read from " PCI_FMT " offset %02lx "
		      "failed: %s\n", PCI_ARGS ( pci ),
		      EFIPCI_OFFSET ( location ), strerror ( rc ) );
		return -EIO;
	}

	return 0;
}

int efipci_write ( struct pci_device *pci, unsigned long location,
		   unsigned long value ) {
	EFI_STATUS efirc;
	int rc;

	if ( ! efipci )
		return -ENOTSUP;

	if ( ( efirc = efipci->Pci.Write ( efipci, EFIPCI_WIDTH ( location ),
					   efipci_address ( pci, location ), 1,
					   &value ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBG ( "EFIPCI config write to " PCI_FMT " offset %02lx "
		      "failed: %s\n", PCI_ARGS ( pci ),
		      EFIPCI_OFFSET ( location ), strerror ( rc ) );
		return -EIO;
	}

	return 0;
}

PROVIDE_PCIAPI_INLINE ( efi, pci_num_bus );
PROVIDE_PCIAPI_INLINE ( efi, pci_read_config_byte );
PROVIDE_PCIAPI_INLINE ( efi, pci_read_config_word );
PROVIDE_PCIAPI_INLINE ( efi, pci_read_config_dword );
PROVIDE_PCIAPI_INLINE ( efi, pci_write_config_byte );
PROVIDE_PCIAPI_INLINE ( efi, pci_write_config_word );
PROVIDE_PCIAPI_INLINE ( efi, pci_write_config_dword );

/******************************************************************************
 *
 * EFI PCI device instantiation
 *
 ******************************************************************************
 */

/**
 * Open EFI PCI device
 *
 * @v device		EFI device handle
 * @v attributes	Protocol opening attributes
 * @v pci		PCI device to fill in
 * @ret rc		Return status code
 */
int efipci_open ( EFI_HANDLE device, UINT32 attributes,
		  struct pci_device *pci ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	union {
		EFI_PCI_IO_PROTOCOL *pci_io;
		void *interface;
	} pci_io;
	UINTN pci_segment, pci_bus, pci_dev, pci_fn;
	EFI_STATUS efirc;
	int rc;

	/* See if device is a PCI device */
	if ( ( efirc = bs->OpenProtocol ( device, &efi_pci_io_protocol_guid,
					  &pci_io.interface, efi_image_handle,
					  device, attributes ) ) != 0 ) {
		rc = -EEFI_PCI ( efirc );
		DBGCP ( device, "EFIPCI %p %s cannot open PCI protocols: %s\n",
			device, efi_handle_name ( device ), strerror ( rc ) );
		goto err_open_protocol;
	}

	/* Get PCI bus:dev.fn address */
	if ( ( efirc = pci_io.pci_io->GetLocation ( pci_io.pci_io, &pci_segment,
						    &pci_bus, &pci_dev,
						    &pci_fn ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBGC ( device, "EFIPCI %p %s could not get PCI location: %s\n",
		       device, efi_handle_name ( device ), strerror ( rc ) );
		goto err_get_location;
	}
	DBGC2 ( device, "EFIPCI %p %s is PCI %04lx:%02lx:%02lx.%lx\n", device,
		efi_handle_name ( device ), ( ( unsigned long ) pci_segment ),
		( ( unsigned long ) pci_bus ), ( ( unsigned long ) pci_dev ),
		( ( unsigned long ) pci_fn ) );

	/* Try to enable I/O cycles, memory cycles, and bus mastering.
	 * Some platforms will 'helpfully' report errors if these bits
	 * can't be enabled (for example, if the card doesn't actually
	 * support I/O cycles).  Work around any such platforms by
	 * enabling bits individually and simply ignoring any errors.
	 */
	pci_io.pci_io->Attributes ( pci_io.pci_io,
				    EfiPciIoAttributeOperationEnable,
				    EFI_PCI_IO_ATTRIBUTE_IO, NULL );
	pci_io.pci_io->Attributes ( pci_io.pci_io,
				    EfiPciIoAttributeOperationEnable,
				    EFI_PCI_IO_ATTRIBUTE_MEMORY, NULL );
	pci_io.pci_io->Attributes ( pci_io.pci_io,
				    EfiPciIoAttributeOperationEnable,
				    EFI_PCI_IO_ATTRIBUTE_BUS_MASTER, NULL );

	/* Populate PCI device */
	pci_init ( pci, PCI_BUSDEVFN ( pci_bus, pci_dev, pci_fn ) );
	if ( ( rc = pci_read_config ( pci ) ) != 0 ) {
		DBGC ( device, "EFIPCI %p %s cannot read PCI configuration: "
		       "%s\n", device, efi_handle_name ( device ),
		       strerror ( rc ) );
		goto err_pci_read_config;
	}

	return 0;

 err_pci_read_config:
 err_get_location:
	bs->CloseProtocol ( device, &efi_pci_io_protocol_guid,
			    efi_image_handle, device );
 err_open_protocol:
	return rc;
}

/**
 * Close EFI PCI device
 *
 * @v device		EFI device handle
 */
void efipci_close ( EFI_HANDLE device ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;

	bs->CloseProtocol ( device, &efi_pci_io_protocol_guid,
			    efi_image_handle, device );
}

/**
 * Get EFI PCI device information
 *
 * @v device		EFI device handle
 * @v pci		PCI device to fill in
 * @ret rc		Return status code
 */
int efipci_info ( EFI_HANDLE device, struct pci_device *pci ) {
	int rc;

	/* Open PCI device, if possible */
	if ( ( rc = efipci_open ( device, EFI_OPEN_PROTOCOL_GET_PROTOCOL,
				  pci ) ) != 0 )
		return rc;

	/* Close PCI device */
	efipci_close ( device );

	return 0;
}

/******************************************************************************
 *
 * EFI PCI driver
 *
 ******************************************************************************
 */

/**
 * Check to see if driver supports a device
 *
 * @v device		EFI device handle
 * @ret rc		Return status code
 */
static int efipci_supported ( EFI_HANDLE device ) {
	struct pci_device pci;
	int rc;

	/* Get PCI device information */
	if ( ( rc = efipci_info ( device, &pci ) ) != 0 )
		return rc;

	/* Look for a driver */
	if ( ( rc = pci_find_driver ( &pci ) ) != 0 ) {
		DBGCP ( device, "EFIPCI %p %s has no driver\n",
			device, efi_handle_name ( device ) );
		return rc;
	}
	DBGC ( device, "EFIPCI %p %s has driver \"%s\"\n",
	       device, efi_handle_name ( device ), pci.id->name );

	return 0;
}

/**
 * Attach driver to device
 *
 * @v efidev		EFI device
 * @ret rc		Return status code
 */
static int efipci_start ( struct efi_device *efidev ) {
	EFI_HANDLE device = efidev->device;
	struct pci_device *pci;
	int rc;

	/* Allocate PCI device */
	pci = zalloc ( sizeof ( *pci ) );
	if ( ! pci ) {
		rc = -ENOMEM;
		goto err_alloc;
	}

	/* Open PCI device */
	if ( ( rc = efipci_open ( device, ( EFI_OPEN_PROTOCOL_BY_DRIVER |
					    EFI_OPEN_PROTOCOL_EXCLUSIVE ),
				  pci ) ) != 0 ) {
		DBGC ( device, "EFIPCI %p %s could not open PCI device: %s\n",
		       device, efi_handle_name ( device ), strerror ( rc ) );
		DBGC_EFI_OPENERS ( device, device, &efi_pci_io_protocol_guid );
		goto err_open;
	}

	/* Find driver */
	if ( ( rc = pci_find_driver ( pci ) ) != 0 ) {
		DBGC ( device, "EFIPCI %p %s has no driver\n",
		       device, efi_handle_name ( device ) );
		goto err_find_driver;
	}

	/* Mark PCI device as a child of the EFI device */
	pci->dev.parent = &efidev->dev;
	list_add ( &pci->dev.siblings, &efidev->dev.children );

	/* Probe driver */
	if ( ( rc = pci_probe ( pci ) ) != 0 ) {
		DBGC ( device, "EFIPCI %p %s could not probe driver \"%s\": "
		       "%s\n", device, efi_handle_name ( device ),
		       pci->id->name, strerror ( rc ) );
		goto err_probe;
	}
	DBGC ( device, "EFIPCI %p %s using driver \"%s\"\n",
	       device, efi_handle_name ( device ), pci->id->name );

	efidev_set_drvdata ( efidev, pci );
	return 0;

	pci_remove ( pci );
 err_probe:
	list_del ( &pci->dev.siblings );
 err_find_driver:
	efipci_close ( device );
 err_open:
	free ( pci );
 err_alloc:
	return rc;
}

/**
 * Detach driver from device
 *
 * @v efidev		EFI device
  */
static void efipci_stop ( struct efi_device *efidev ) {
	struct pci_device *pci = efidev_get_drvdata ( efidev );
	EFI_HANDLE device = efidev->device;

	pci_remove ( pci );
	list_del ( &pci->dev.siblings );
	efipci_close ( device );
	free ( pci );
}

/** EFI PCI driver */
struct efi_driver efipci_driver __efi_driver ( EFI_DRIVER_NORMAL ) = {
	.name = "PCI",
	.supported = efipci_supported,
	.start = efipci_start,
	.stop = efipci_stop,
};
