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

/**
 * @file
 *
 * EFI image wrapping
 *
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/LoadedImage.h>
#include <ipxe/efi/efi_wrap.h>

/** EFI system table wrapper */
static EFI_SYSTEM_TABLE efi_systab_wrapper;

/** EFI boot services table wrapper */
static EFI_BOOT_SERVICES efi_bs_wrapper;

/** Colour for debug messages */
#define colour &efi_systab_wrapper

/**
 * Convert EFI status code to text
 *
 * @v efirc		EFI status code
 * @ret text		EFI status code text
 */
static const char * efi_status ( EFI_STATUS efirc ) {
	static char buf[ 19 /* "0xXXXXXXXXXXXXXXXX" + NUL */ ];

	switch ( efirc ) {
	case EFI_SUCCESS :			return "0";
	case EFI_LOAD_ERROR :			return "LOAD_ERROR";
	case EFI_INVALID_PARAMETER :		return "INVALID_PARAMETER";
	case EFI_UNSUPPORTED :			return "UNSUPPORTED";
	case EFI_BAD_BUFFER_SIZE :		return "BAD_BUFFER_SIZE";
	case EFI_BUFFER_TOO_SMALL :		return "BUFFER_TOO_SMALL";
	case EFI_NOT_READY :			return "NOT_READY";
	case EFI_DEVICE_ERROR :			return "DEVICE_ERROR";
	case EFI_WRITE_PROTECTED :		return "WRITE_PROTECTED";
	case EFI_OUT_OF_RESOURCES :		return "OUT_OF_RESOURCES";
	case EFI_VOLUME_CORRUPTED :		return "VOLUME_CORRUPTED";
	case EFI_VOLUME_FULL :			return "VOLUME_FULL";
	case EFI_NO_MEDIA :			return "NO_MEDIA";
	case EFI_MEDIA_CHANGED :		return "MEDIA_CHANGED";
	case EFI_NOT_FOUND :			return "NOT_FOUND";
	case EFI_ACCESS_DENIED :		return "ACCESS_DENIED";
	case EFI_NO_RESPONSE :			return "NO_RESPONSE";
	case EFI_NO_MAPPING :			return "NO_MAPPING";
	case EFI_TIMEOUT :			return "TIMEOUT";
	case EFI_NOT_STARTED :			return "NOT_STARTED";
	case EFI_ALREADY_STARTED :		return "ALREADY_STARTED";
	case EFI_ABORTED :			return "ABORTED";
	case EFI_ICMP_ERROR :			return "ICMP_ERROR";
	case EFI_TFTP_ERROR :			return "TFTP_ERROR";
	case EFI_PROTOCOL_ERROR :		return "PROTOCOL_ERROR";
	case EFI_INCOMPATIBLE_VERSION :		return "INCOMPATIBLE_VERSION";
	case EFI_SECURITY_VIOLATION :		return "SECURITY_VIOLATION";
	case EFI_CRC_ERROR :			return "CRC_ERROR";
	case EFI_END_OF_MEDIA :			return "END_OF_MEDIA";
	case EFI_END_OF_FILE :			return "END_OF_FILE";
	case EFI_INVALID_LANGUAGE :		return "INVALID_LANGUAGE";
	case EFI_COMPROMISED_DATA :		return "COMPROMISED_DATA";
	case EFI_WARN_UNKNOWN_GLYPH :		return "WARN_UNKNOWN_GLYPH";
	case EFI_WARN_DELETE_FAILURE :		return "WARN_DELETE_FAILURE";
	case EFI_WARN_WRITE_FAILURE :		return "WARN_WRITE_FAILURE";
	case EFI_WARN_BUFFER_TOO_SMALL :	return "WARN_BUFFER_TOO_SMALL";
	case EFI_WARN_STALE_DATA :		return "WARN_STALE_DATA";
	default:
		snprintf ( buf, sizeof ( buf ), "%#lx",
			   ( unsigned long ) efirc );
		return buf;
	}
}

/**
 * Wrap HandleProtocol()
 *
 */
static EFI_STATUS EFIAPI
efi_handle_protocol_wrapper ( EFI_HANDLE handle, EFI_GUID *protocol,
			      VOID **interface ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	void *retaddr = __builtin_return_address ( 0 );
	EFI_STATUS efirc;

	DBGC ( colour, "HandleProtocol ( %p %s, %s, ... ) ", handle,
	       efi_handle_name ( handle ), efi_guid_ntoa ( protocol ) );
	efirc = bs->HandleProtocol ( handle, protocol, interface );
	DBGC ( colour, "= %s ( %p ) -> %p\n",
	       efi_status ( efirc ), *interface, retaddr );
	return efirc;
}

/**
 * Wrap LocateHandle()
 *
 */
static EFI_STATUS EFIAPI
efi_locate_handle_wrapper ( EFI_LOCATE_SEARCH_TYPE search_type,
			    EFI_GUID *protocol, VOID *search_key,
			    UINTN *buffer_size, EFI_HANDLE *buffer ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	void *retaddr = __builtin_return_address ( 0 );
	EFI_STATUS efirc;

	DBGC ( colour, "LocateHandle ( %d, %s, ..., %zd, ... ) ", search_type,
	       efi_guid_ntoa ( protocol ), ( ( size_t ) *buffer_size ) );
	efirc = bs->LocateHandle ( search_type, protocol, search_key,
				   buffer_size, buffer );
	DBGC ( colour, "= %s ( %zd ) -> %p\n",
	       efi_status ( efirc ), ( ( size_t ) *buffer_size ), retaddr );
	return efirc;
}

/**
 * Wrap LocateDevicePath()
 *
 */
static EFI_STATUS EFIAPI
efi_locate_device_path_wrapper ( EFI_GUID *protocol,
				 EFI_DEVICE_PATH_PROTOCOL **device_path,
				 EFI_HANDLE *device ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	void *retaddr = __builtin_return_address ( 0 );
	EFI_STATUS efirc;

	DBGC ( colour, "LocateDevicePath ( %s, %s, ... ) ",
	       efi_guid_ntoa ( protocol ), efi_devpath_text ( *device_path ) );
	efirc = bs->LocateDevicePath ( protocol, device_path, device );
	DBGC ( colour, "= %s ( %p, ",
	       efi_status ( efirc ), efi_devpath_text ( *device_path ) );
	DBGC ( colour, "%p %s ) -> %p\n",
	       *device, efi_handle_name ( *device ), retaddr );
	return efirc;
}

/**
 * Wrap LoadImage()
 *
 */
static EFI_STATUS EFIAPI
efi_load_image_wrapper ( BOOLEAN boot_policy, EFI_HANDLE parent_image_handle,
			 EFI_DEVICE_PATH_PROTOCOL *device_path,
			 VOID *source_buffer, UINTN source_size,
			 EFI_HANDLE *image_handle ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	void *retaddr = __builtin_return_address ( 0 );
	EFI_STATUS efirc;

	DBGC ( colour, "LoadImage ( %d, %p %s, ", boot_policy,
	       parent_image_handle, efi_handle_name ( parent_image_handle ) );
	DBGC ( colour, "%s, %p, %#llx, ... ) ",
	       efi_devpath_text ( device_path ), source_buffer,
	       ( ( unsigned long long ) source_size ) );
	efirc = bs->LoadImage ( boot_policy, parent_image_handle, device_path,
				source_buffer, source_size, image_handle );
	DBGC ( colour, "= %s ( ", efi_status ( efirc ) );
	if ( efirc == 0 ) {
		DBGC ( colour, "%p %s ", *image_handle,
		       efi_handle_name ( *image_handle ) );
	}
	DBGC ( colour, ") -> %p\n", retaddr );

	/* Wrap the new image */
	if ( efirc == 0 )
		efi_wrap ( *image_handle );

	return efirc;
}

/**
 * Wrap ExitBootServices()
 *
 */
static EFI_STATUS EFIAPI
efi_exit_boot_services_wrapper ( EFI_HANDLE image_handle, UINTN map_key ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	void *retaddr = __builtin_return_address ( 0 );
	EFI_STATUS efirc;

	DBGC ( colour, "ExitBootServices ( %p %s, %#llx ) ",
	       image_handle, efi_handle_name ( image_handle ),
	       ( ( unsigned long long ) map_key ) );
	efirc = bs->ExitBootServices ( image_handle, map_key );
	DBGC ( colour, "= %s -> %p\n", efi_status ( efirc ), retaddr );
	return efirc;
}

/**
 * Wrap OpenProtocol()
 *
 */
static EFI_STATUS EFIAPI
efi_open_protocol_wrapper ( EFI_HANDLE handle, EFI_GUID *protocol,
			    VOID **interface, EFI_HANDLE agent_handle,
			    EFI_HANDLE controller_handle, UINT32 attributes ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	void *retaddr = __builtin_return_address ( 0 );
	EFI_STATUS efirc;

	DBGC ( colour, "OpenProtocol ( %p %s, %s, ..., ", handle,
	       efi_handle_name ( handle ), efi_guid_ntoa ( protocol ) );
	DBGC ( colour, "%p %s, ", agent_handle,
	       efi_handle_name ( agent_handle ) );
	DBGC ( colour, "%p %s, %#x ) ", controller_handle,
	       efi_handle_name ( controller_handle ), attributes );
	efirc = bs->OpenProtocol ( handle, protocol, interface, agent_handle,
				   controller_handle, attributes );
	DBGC ( colour, "= %s ( %p ) -> %p\n",
	       efi_status ( efirc ), *interface, retaddr );
	return efirc;
}

/**
 * Wrap LocateProtocol()
 *
 */
static EFI_STATUS EFIAPI
efi_locate_protocol_wrapper ( EFI_GUID *protocol, VOID *registration,
			      VOID **interface ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	void *retaddr = __builtin_return_address ( 0 );
	EFI_STATUS efirc;

	DBGC ( colour, "LocateProtocol ( %s, %p, ... ) ",
	       efi_guid_ntoa ( protocol ), registration );
	efirc = bs->LocateProtocol ( protocol, registration, interface );
	DBGC ( colour, "= %s ( %p ) -> %p\n",
	       efi_status ( efirc ), *interface, retaddr );
	return efirc;
}

/**
 * Wrap the calls made by a loaded image
 *
 * @v handle		Image handle
 */
 void efi_wrap ( EFI_HANDLE handle ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	union {
		EFI_LOADED_IMAGE_PROTOCOL *image;
		void *intf;
	} loaded;
	EFI_STATUS efirc;
	int rc;

	/* Do nothing unless debugging is enabled */
	if ( ! DBG_LOG )
		return;

	/* Populate table wrappers */
	memcpy ( &efi_systab_wrapper, efi_systab,
		 sizeof ( efi_systab_wrapper ) );
	memcpy ( &efi_bs_wrapper, bs, sizeof ( efi_bs_wrapper ) );
	efi_systab_wrapper.BootServices	= &efi_bs_wrapper;
	efi_bs_wrapper.HandleProtocol	= efi_handle_protocol_wrapper;
	efi_bs_wrapper.LocateHandle	= efi_locate_handle_wrapper;
	efi_bs_wrapper.LocateDevicePath	= efi_locate_device_path_wrapper;
	efi_bs_wrapper.LoadImage	= efi_load_image_wrapper;
	efi_bs_wrapper.ExitBootServices	= efi_exit_boot_services_wrapper;
	efi_bs_wrapper.OpenProtocol	= efi_open_protocol_wrapper;
	efi_bs_wrapper.LocateProtocol	= efi_locate_protocol_wrapper;

	/* Open loaded image protocol */
	if ( ( efirc = bs->OpenProtocol ( handle,
					  &efi_loaded_image_protocol_guid,
					  &loaded.intf, efi_image_handle, NULL,
					  EFI_OPEN_PROTOCOL_GET_PROTOCOL ))!=0){
		rc = -EEFI ( efirc );
		DBGC ( colour, "Could not get loaded image protocol for %p %s: "
		       "%s\n", handle, efi_handle_name ( handle ),
		       strerror ( rc ) );
		return;
	}

	/* Provide system table wrapper to image */
	loaded.image->SystemTable = &efi_systab_wrapper;
	DBGC ( colour, "Wrapped image %p %s at base %p has protocols:\n",
	       handle, efi_handle_name ( handle ), loaded.image->ImageBase );
	DBGC_EFI_PROTOCOLS ( colour, handle );
	DBGC ( colour, "Parent image %p %s\n", loaded.image->ParentHandle,
	       efi_handle_name ( loaded.image->ParentHandle ) );
	DBGC ( colour, "Device %p %s ", loaded.image->DeviceHandle,
	       efi_handle_name ( loaded.image->DeviceHandle ) );
	DBGC ( colour, "file %p %s\n", loaded.image->FilePath,
	       efi_devpath_text ( loaded.image->FilePath ) );

	/* Close loaded image protocol */
	bs->CloseProtocol ( handle, &efi_loaded_image_protocol_guid,
			    efi_image_handle, NULL );
}
