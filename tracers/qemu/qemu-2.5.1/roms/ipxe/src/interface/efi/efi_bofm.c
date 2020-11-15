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
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <errno.h>
#include <ipxe/bofm.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_pci.h>
#include <ipxe/efi/efi_driver.h>

/** @file
 *
 * IBM BladeCenter Open Fabric Manager (BOFM) EFI interface
 *
 */

/***************************************************************************
 *
 * EFI BOFM definitions
 *
 ***************************************************************************
 *
 * Taken from the BOFM UEFI Vendor Specification document
 *
 */

#define IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL_GUID			\
	{ 0x03207ce2, 0xd9c7, 0x11dc,					\
	  { 0xa9, 0x4d, 0x00, 0x19, 0x7d, 0x89, 0x02, 0x38 } }

#define IBM_BOFM_DRIVER_CONFIGURATION2_PROTOCOL_GUID			\
	{ 0xe82a9763, 0x0584, 0x4e41,					\
	  { 0xbb, 0x39, 0xe0, 0xcd, 0xb8, 0xc1, 0xf0, 0xfc } }

typedef struct {
	UINT8 Id;
	UINT8 ResultByte;
} __attribute__ (( packed )) BOFM_EPID_Results_t;

typedef struct {
	UINT8 Version;
	UINT8 Level;
	UINT16 Length;
	UINT8 Checksum;
	UINT8 Profile[32];
	UINT8 GlobalOption0;
	UINT8 GlobalOption1;
	UINT8 GlobalOption2;
	UINT8 GlobalOption3;
	UINT32 SequenceStamp;
	UINT8 Regions[911]; // For use by BOFM Driver
	UINT32 Reserved1;
} __attribute__ (( packed )) BOFM_Parameters_t;

typedef struct {
	UINT32 Reserved1;
	UINT8 Version;
	UINT8 Level;
	UINT8 Checksum;
	UINT32 SequenceStamp;
	UINT8 SUIDResults;
	UINT8 EntryResults[32];
	UINT8 Reserved2;
	UINT8 Reserved3;
	UINT8 FCTgtResults[2];
	UINT8 SASTgtResults[2];
	BOFM_EPID_Results_t EPIDResults[2];
	UINT8 Results4[10];
} __attribute__ (( packed )) BOFM_Results_t;

typedef struct {
	UINT32 Signature;
	UINT32 SubSignature;
	BOFM_Parameters_t Parameters;
	BOFM_Results_t Results;
} __attribute__ (( packed )) BOFM_DataStructure_t;

#define IBM_BOFM_TABLE BOFM_DataStructure_t

typedef struct _IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL
	IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL;

typedef struct _IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL2
	IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL2;

typedef EFI_STATUS ( EFIAPI *IBM_BOFM_DRIVER_CONFIGURATION_SUPPORT ) (
	IN IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL *This,
	EFI_HANDLE ControllerHandle,
	UINT8 SupporttedOptions,
	UINT8 iSCSI_Parameter_Version,
	UINT8 BOFM_Parameter_Version
);

typedef EFI_STATUS ( EFIAPI *IBM_BOFM_DRIVER_CONFIGURATION_STATUS ) (
	IN IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL *This,
	EFI_HANDLE ControllerHandle,
	BOOLEAN ResetRequired,
	UINT8 BOFMReturnCode
);

typedef EFI_STATUS ( EFIAPI *IBM_BOFM_DRIVER_CONFIGURATION_STATUS2 ) (
	IN IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL2 *This,
	EFI_HANDLE ControllerHandle,
	BOOLEAN ResetRequired,
	UINT8 BOFMReturnCode
);

struct _IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL {
	IBM_BOFM_TABLE BofmTable;
	IBM_BOFM_DRIVER_CONFIGURATION_STATUS SetStatus;
	IBM_BOFM_DRIVER_CONFIGURATION_SUPPORT RegisterSupport;
};

struct _IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL2 {
	UINT32 Signature;
	UINT32 Reserved1;
	UINT64 Reserved2;
	IBM_BOFM_DRIVER_CONFIGURATION_STATUS2 SetStatus;
	IBM_BOFM_DRIVER_CONFIGURATION_SUPPORT RegisterSupport;
	IBM_BOFM_TABLE BofmTable;
};

/***************************************************************************
 *
 * EFI BOFM interface
 *
 ***************************************************************************
 */

/** BOFM1 protocol GUID */
static EFI_GUID bofm1_protocol_guid =
	IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL_GUID;

/** BOFM2 protocol GUID */
static EFI_GUID bofm2_protocol_guid =
	IBM_BOFM_DRIVER_CONFIGURATION2_PROTOCOL_GUID;

/**
 * Check if device is supported
 *
 * @v device		EFI device handle
 * @ret rc		Return status code
 */
static int efi_bofm_supported ( EFI_HANDLE device ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	struct pci_device pci;
	union {
		IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL *bofm1;
		void *interface;
	} bofm1;
	EFI_STATUS efirc;
	int rc;

	/* Get PCI device information */
	if ( ( rc = efipci_info ( device, &pci ) ) != 0 )
		return rc;

	/* Look for a BOFM driver */
	if ( ( rc = bofm_find_driver ( &pci ) ) != 0 ) {
		DBGCP ( device, "EFIBOFM %p %s has no driver\n",
			device, efi_handle_name ( device ) );
		return rc;
	}

	/* Locate BOFM protocol */
	if ( ( efirc = bs->LocateProtocol ( &bofm1_protocol_guid, NULL,
					    &bofm1.interface ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBGC ( device, "EFIBOFM %p %s cannot find BOFM protocol\n",
		       device, efi_handle_name ( device ) );
		return rc;
	}

	/* Register support for this device */
	if ( ( efirc = bofm1.bofm1->RegisterSupport ( bofm1.bofm1, device,
						      0x04 /* Can change MAC */,
						      0x00 /* No iSCSI */,
						      0x02 /* Version */ ))!=0){
		rc = -EEFI ( efirc );
		DBGC ( device, "EFIBOFM %p %s could not register support: %s\n",
		       device, efi_handle_name ( device ), strerror ( rc ) );
		return rc;
	}

	DBGC ( device, "EFIBOFM %p %s has driver \"%s\"\n",
	       device, efi_handle_name ( device ), pci.id->name );
	return 0;
}

/**
 * Attach driver to device
 *
 * @v efidev		EFI device
 * @ret rc		Return status code
 */
static int efi_bofm_start ( struct efi_device *efidev ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_HANDLE device = efidev->device;
	union {
		IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL *bofm1;
		void *interface;
	} bofm1;
	union {
		IBM_BOFM_DRIVER_CONFIGURATION_PROTOCOL2 *bofm2;
		void *interface;
	} bofm2;
	struct pci_device pci;
	IBM_BOFM_TABLE *bofmtab;
	IBM_BOFM_TABLE *bofmtab2;
	int bofmrc;
	EFI_STATUS efirc;
	int rc;

	/* Open PCI device, if possible */
	if ( ( rc = efipci_open ( device, EFI_OPEN_PROTOCOL_GET_PROTOCOL,
				  &pci ) ) != 0 )
		goto err_open;

	/* Locate BOFM protocol */
	if ( ( efirc = bs->LocateProtocol ( &bofm1_protocol_guid, NULL,
					    &bofm1.interface ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBGC ( device, "EFIBOFM %p %s cannot find BOFM protocol\n",
		       device, efi_handle_name ( device ) );
		goto err_locate_bofm;
	}
	bofmtab = &bofm1.bofm1->BofmTable;
	DBGC ( device, "EFIBOFM %p %s found version 1 BOFM table at %p+%04x\n",
	       device, efi_handle_name ( device ), bofmtab,
	       bofmtab->Parameters.Length );

	/* Locate BOFM2 protocol, if available */
	if ( ( efirc = bs->LocateProtocol ( &bofm2_protocol_guid, NULL,
					    &bofm2.interface ) ) == 0 ) {
		bofmtab2 = &bofm2.bofm2->BofmTable;
		DBGC ( device, "EFIBOFM %p %s found version 2 BOFM table at "
		       "%p+%04x\n", device, efi_handle_name ( device ),
		       bofmtab2, bofmtab2->Parameters.Length );
		assert ( bofm2.bofm2->RegisterSupport ==
			 bofm1.bofm1->RegisterSupport );
	} else {
		DBGC ( device, "EFIBOFM %p %s cannot find BOFM2 protocol\n",
		       device, efi_handle_name ( device ) );
		/* Not a fatal error; may be a BOFM1-only system */
		bofmtab2 = NULL;
	}

	/* Process BOFM table */
	DBGC2 ( device, "EFIBOFM %p %s version 1 before processing:\n",
		device, efi_handle_name ( device ) );
	DBGC2_HD ( device, bofmtab, bofmtab->Parameters.Length );
	if ( bofmtab2 ) {
		DBGC2 ( device, "EFIBOFM %p %s version 2 before processing:\n",
			device, efi_handle_name ( device ) );
		DBGC2_HD ( device, bofmtab2, bofmtab2->Parameters.Length );
	}
	bofmrc = bofm ( virt_to_user ( bofmtab2 ? bofmtab2 : bofmtab ), &pci );
	DBGC ( device, "EFIBOFM %p %s status %08x\n",
	       device, efi_handle_name ( device ), bofmrc );
	DBGC2 ( device, "EFIBOFM %p %s version 1 after processing:\n",
		device, efi_handle_name ( device ) );
	DBGC2_HD ( device, bofmtab, bofmtab->Parameters.Length );
	if ( bofmtab2 ) {
		DBGC2 ( device, "EFIBOFM %p %s version 2 after processing:\n",
			device, efi_handle_name ( device ) );
		DBGC2_HD ( device, bofmtab2, bofmtab2->Parameters.Length );
	}

	/* Return BOFM status */
	if ( bofmtab2 ) {
		if ( ( efirc = bofm2.bofm2->SetStatus ( bofm2.bofm2, device,
							FALSE, bofmrc ) ) != 0){
			rc = -EEFI ( efirc );
			DBGC ( device, "EFIBOFM %p %s could not set BOFM2 "
			       "status: %s\n", device,
			       efi_handle_name ( device ), strerror ( rc ) );
			goto err_set_status;
		}
	} else {
		if ( ( efirc = bofm1.bofm1->SetStatus ( bofm1.bofm1, device,
							FALSE, bofmrc ) ) != 0){
			rc = -EEFI ( efirc );
			DBGC ( device, "EFIBOFM %p %s could not set BOFM "
			       "status: %s\n", device,
			       efi_handle_name ( device ), strerror ( rc ) );
			goto err_set_status;
		}
	}

	/* BOFM (ab)uses the "start" method to mean "process and exit" */
	rc = -EAGAIN;

 err_set_status:
 err_locate_bofm:
	efipci_close ( device );
 err_open:
	return rc;
}

/**
 * Detach driver from device
 *
 * @v device		EFI device
 */
static void efi_bofm_stop ( struct efi_device *efidev __unused ) {

	/* Should never happen */
	assert ( 0 );
}

/** EFI BOFM driver */
struct efi_driver efi_bofm_driver __efi_driver ( EFI_DRIVER_EARLY ) = {
	.name = "BOFM",
	.supported = efi_bofm_supported,
	.start = efi_bofm_start,
	.stop = efi_bofm_stop,
};
