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
 * EFI debugging utilities
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ipxe/uuid.h>
#include <ipxe/base16.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_utils.h>
#include <ipxe/efi/Protocol/ComponentName.h>
#include <ipxe/efi/Protocol/ComponentName2.h>
#include <ipxe/efi/Protocol/DevicePathToText.h>
#include <ipxe/efi/IndustryStandard/PeImage.h>

/** Device path to text protocol */
static EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *efidpt;
EFI_REQUEST_PROTOCOL ( EFI_DEVICE_PATH_TO_TEXT_PROTOCOL, &efidpt );

/** Iscsi4Dxe module GUID */
static EFI_GUID efi_iscsi4_dxe_guid = {
	0x4579b72d, 0x7ec4, 0x4dd4,
	{ 0x84, 0x86, 0x08, 0x3c, 0x86, 0xb1, 0x82, 0xa7 }
};

/** VlanConfigDxe module GUID */
static EFI_GUID efi_vlan_config_dxe_guid = {
	0xe4f61863, 0xfe2c, 0x4b56,
	{ 0xa8, 0xf4, 0x08, 0x51, 0x9b, 0xc4, 0x39, 0xdf }
};

/** A well-known GUID */
struct efi_well_known_guid {
	/** GUID */
	EFI_GUID *guid;
	/** Name */
	const char *name;
};

/** Well-known GUIDs */
static struct efi_well_known_guid efi_well_known_guids[] = {
	{ &efi_arp_protocol_guid,
	  "Arp" },
	{ &efi_arp_service_binding_protocol_guid,
	  "ArpSb" },
	{ &efi_block_io_protocol_guid,
	  "BlockIo" },
	{ &efi_bus_specific_driver_override_protocol_guid,
	  "BusSpecificDriverOverride" },
	{ &efi_component_name_protocol_guid,
	  "ComponentName" },
	{ &efi_component_name2_protocol_guid,
	  "ComponentName2" },
	{ &efi_device_path_protocol_guid,
	  "DevicePath" },
	{ &efi_driver_binding_protocol_guid,
	  "DriverBinding" },
	{ &efi_dhcp4_protocol_guid,
	  "Dhcp4" },
	{ &efi_dhcp4_service_binding_protocol_guid,
	  "Dhcp4Sb" },
	{ &efi_disk_io_protocol_guid,
	  "DiskIo" },
	{ &efi_graphics_output_protocol_guid,
	  "GraphicsOutput" },
	{ &efi_hii_config_access_protocol_guid,
	  "HiiConfigAccess" },
	{ &efi_ip4_protocol_guid,
	  "Ip4" },
	{ &efi_ip4_config_protocol_guid,
	  "Ip4Config" },
	{ &efi_ip4_service_binding_protocol_guid,
	  "Ip4Sb" },
	{ &efi_iscsi4_dxe_guid,
	  "IScsi4Dxe" },
	{ &efi_load_file_protocol_guid,
	  "LoadFile" },
	{ &efi_load_file2_protocol_guid,
	  "LoadFile2" },
	{ &efi_loaded_image_protocol_guid,
	  "LoadedImage" },
	{ &efi_loaded_image_device_path_protocol_guid,
	  "LoadedImageDevicePath"},
	{ &efi_managed_network_protocol_guid,
	  "ManagedNetwork" },
	{ &efi_managed_network_service_binding_protocol_guid,
	  "ManagedNetworkSb" },
	{ &efi_mtftp4_protocol_guid,
	  "Mtftp4" },
	{ &efi_mtftp4_service_binding_protocol_guid,
	  "Mtftp4Sb" },
	{ &efi_nii_protocol_guid,
	  "Nii" },
	{ &efi_nii31_protocol_guid,
	  "Nii31" },
	{ &efi_pci_io_protocol_guid,
	  "PciIo" },
	{ &efi_pci_root_bridge_io_protocol_guid,
	  "PciRootBridgeIo" },
	{ &efi_pxe_base_code_protocol_guid,
	  "PxeBaseCode" },
	{ &efi_simple_file_system_protocol_guid,
	  "SimpleFileSystem" },
	{ &efi_simple_network_protocol_guid,
	  "SimpleNetwork" },
	{ &efi_tcg_protocol_guid,
	  "Tcg" },
	{ &efi_tcp4_protocol_guid,
	  "Tcp4" },
	{ &efi_tcp4_service_binding_protocol_guid,
	  "Tcp4Sb" },
	{ &efi_udp4_protocol_guid,
	  "Udp4" },
	{ &efi_udp4_service_binding_protocol_guid,
	  "Udp4Sb" },
	{ &efi_vlan_config_protocol_guid,
	  "VlanConfig" },
	{ &efi_vlan_config_dxe_guid,
	  "VlanConfigDxe" },
};

/**
 * Convert GUID to a printable string
 *
 * @v guid		GUID
 * @ret string		Printable string
 */
const char * efi_guid_ntoa ( EFI_GUID *guid ) {
	union {
		union uuid uuid;
		EFI_GUID guid;
	} u;
	unsigned int i;

	/* Sanity check */
	if ( ! guid )
		return NULL;

	/* Check for a match against well-known GUIDs */
	for ( i = 0 ; i < ( sizeof ( efi_well_known_guids ) /
			    sizeof ( efi_well_known_guids[0] ) ) ; i++ ) {
		if ( memcmp ( guid, efi_well_known_guids[i].guid,
			      sizeof ( *guid ) ) == 0 ) {
			return efi_well_known_guids[i].name;
		}
	}

	/* Convert GUID to standard endianness */
	memcpy ( &u.guid, guid, sizeof ( u.guid ) );
	uuid_mangle ( &u.uuid );
	return uuid_ntoa ( &u.uuid );
}

/**
 * Name protocol open attributes
 *
 * @v attributes	Protocol open attributes
 * @ret name		Protocol open attributes name
 *
 * Returns a (static) string with characters for each set bit
 * corresponding to BY_(H)ANDLE_PROTOCOL, (G)ET_PROTOCOL,
 * (T)EST_PROTOCOL, BY_(C)HILD_CONTROLLER, BY_(D)RIVER, and
 * E(X)CLUSIVE.
 */
static const char * efi_open_attributes_name ( unsigned int attributes ) {
	static char attribute_chars[] = "HGTCDX";
	static char name[ sizeof ( attribute_chars ) ];
	char *tmp = name;
	unsigned int i;

	for ( i = 0 ; i < ( sizeof ( attribute_chars ) - 1 ) ; i++ ) {
		if ( attributes & ( 1 << i ) )
			*(tmp++) = attribute_chars[i];
	}
	*tmp = '\0';

	return name;
}

/**
 * Print list of openers of a given protocol on a given handle
 *
 * @v handle		EFI handle
 * @v protocol		Protocol GUID
 */
void dbg_efi_openers ( EFI_HANDLE handle, EFI_GUID *protocol ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_OPEN_PROTOCOL_INFORMATION_ENTRY *openers;
	EFI_OPEN_PROTOCOL_INFORMATION_ENTRY *opener;
	UINTN count;
	unsigned int i;
	EFI_STATUS efirc;
	int rc;

	/* Sanity check */
	if ( ( ! handle ) || ( ! protocol ) ) {
		printf ( "EFI could not retrieve openers for %s on %p\n",
			 efi_guid_ntoa ( protocol ), handle );
		return;
	}

	/* Retrieve list of openers */
	if ( ( efirc = bs->OpenProtocolInformation ( handle, protocol, &openers,
						     &count ) ) != 0 ) {
		rc = -EEFI ( efirc );
		printf ( "EFI could not retrieve openers for %s on %p: %s\n",
			 efi_guid_ntoa ( protocol ), handle, strerror ( rc ) );
		return;
	}

	/* Dump list of openers */
	for ( i = 0 ; i < count ; i++ ) {
		opener = &openers[i];
		printf ( "HANDLE %p %s %s opened %dx (%s)",
			 handle, efi_handle_name ( handle ),
			 efi_guid_ntoa ( protocol ), opener->OpenCount,
			 efi_open_attributes_name ( opener->Attributes ) );
		printf ( " by %p %s", opener->AgentHandle,
			 efi_handle_name ( opener->AgentHandle ) );
		if ( opener->ControllerHandle == handle ) {
			printf ( "\n" );
		} else {
			printf ( " for %p %s\n", opener->ControllerHandle,
				 efi_handle_name ( opener->ControllerHandle ) );
		}
	}

	/* Free list */
	bs->FreePool ( openers );
}

/**
 * Print list of protocol handlers attached to a handle
 *
 * @v handle		EFI handle
 */
void dbg_efi_protocols ( EFI_HANDLE handle ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_GUID **protocols;
	EFI_GUID *protocol;
	UINTN count;
	unsigned int i;
	EFI_STATUS efirc;
	int rc;

	/* Sanity check */
	if ( ! handle ) {
		printf ( "EFI could not retrieve protocols for %p\n", handle );
		return;
	}

	/* Retrieve list of protocols */
	if ( ( efirc = bs->ProtocolsPerHandle ( handle, &protocols,
						&count ) ) != 0 ) {
		rc = -EEFI ( efirc );
		printf ( "EFI could not retrieve protocols for %p: %s\n",
			 handle, strerror ( rc ) );
		return;
	}

	/* Dump list of protocols */
	for ( i = 0 ; i < count ; i++ ) {
		protocol = protocols[i];
		printf ( "HANDLE %p %s %s supported\n",
			 handle, efi_handle_name ( handle ),
			 efi_guid_ntoa ( protocol ) );
		dbg_efi_openers ( handle, protocol );
	}

	/* Free list */
	bs->FreePool ( protocols );
}

/**
 * Get textual representation of device path
 *
 * @v path		Device path
 * @ret text		Textual representation of device path, or NULL
 */
const char * efi_devpath_text ( EFI_DEVICE_PATH_PROTOCOL *path ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	static char text[256];
	void *start;
	void *end;
	size_t max_len;
	size_t len;
	CHAR16 *wtext;

	/* Sanity checks */
	if ( ! path ) {
		DBG ( "[NULL DevicePath]" );
		return NULL;
	}

	/* If we have no DevicePathToText protocol then use a raw hex string */
	if ( ! efidpt ) {
		DBG ( "[No DevicePathToText]" );
		start = path;
		end = efi_devpath_end ( path );
		len = ( end - start );
		max_len = ( ( sizeof ( text ) - 1 /* NUL */ ) / 2 /* "xx" */ );
		if ( len > max_len )
			len = max_len;
		base16_encode ( start, len, text, sizeof ( text ) );
		return text;
	}

	/* Convert path to a textual representation */
	wtext = efidpt->ConvertDevicePathToText ( path, TRUE, FALSE );
	if ( ! wtext )
		return NULL;

	/* Store path in buffer */
	snprintf ( text, sizeof ( text ), "%ls", wtext );

	/* Free path */
	bs->FreePool ( wtext );

	return text;
}

/**
 * Get driver name
 *
 * @v wtf		Component name protocol
 * @ret name		Driver name, or NULL
 */
static const char * efi_driver_name ( EFI_COMPONENT_NAME_PROTOCOL *wtf ) {
	static char name[64];
	CHAR16 *driver_name;
	EFI_STATUS efirc;

	/* Sanity check */
	if ( ! wtf ) {
		DBG ( "[NULL ComponentName]" );
		return NULL;
	}

	/* Try "eng" first; if that fails then try the first language */
	if ( ( ( efirc = wtf->GetDriverName ( wtf, "eng",
					      &driver_name ) ) != 0 ) &&
	     ( ( efirc = wtf->GetDriverName ( wtf, wtf->SupportedLanguages,
					      &driver_name ) ) != 0 ) ) {
		return NULL;
	}

	/* Convert name from CHAR16 to char */
	snprintf ( name, sizeof ( name ), "%ls", driver_name );
	return name;
}

/**
 * Get driver name
 *
 * @v wtf		Component name protocol
 * @ret name		Driver name, or NULL
 */
static const char * efi_driver_name2 ( EFI_COMPONENT_NAME2_PROTOCOL *wtf ) {
	static char name[64];
	CHAR16 *driver_name;
	EFI_STATUS efirc;

	/* Sanity check */
	if ( ! wtf ) {
		DBG ( "[NULL ComponentName2]" );
		return NULL;
	}

	/* Try "en" first; if that fails then try the first language */
	if ( ( ( efirc = wtf->GetDriverName ( wtf, "en",
					      &driver_name ) ) != 0 ) &&
	     ( ( efirc = wtf->GetDriverName ( wtf, wtf->SupportedLanguages,
					      &driver_name ) ) != 0 ) ) {
		return NULL;
	}

	/* Convert name from CHAR16 to char */
	snprintf ( name, sizeof ( name ), "%ls", driver_name );
	return name;
}

/**
 * Get PE/COFF debug filename
 *
 * @v loaded		Loaded image
 * @ret name		PE/COFF debug filename, or NULL
 */
static const char *
efi_pecoff_debug_name ( EFI_LOADED_IMAGE_PROTOCOL *loaded ) {
	static char buf[32];
	EFI_IMAGE_DOS_HEADER *dos;
	EFI_IMAGE_OPTIONAL_HEADER_UNION *pe;
	EFI_IMAGE_OPTIONAL_HEADER32 *opt32;
	EFI_IMAGE_OPTIONAL_HEADER64 *opt64;
	EFI_IMAGE_DATA_DIRECTORY *datadir;
	EFI_IMAGE_DEBUG_DIRECTORY_ENTRY *debug;
	EFI_IMAGE_DEBUG_CODEVIEW_NB10_ENTRY *codeview_nb10;
	EFI_IMAGE_DEBUG_CODEVIEW_RSDS_ENTRY *codeview_rsds;
	EFI_IMAGE_DEBUG_CODEVIEW_MTOC_ENTRY *codeview_mtoc;
	uint16_t dos_magic;
	uint32_t pe_magic;
	uint16_t opt_magic;
	uint32_t codeview_magic;
	size_t max_len;
	char *name;
	char *tmp;

	/* Sanity check */
	if ( ! loaded ) {
		DBG ( "[NULL LoadedImage]" );
		return NULL;
	}

	/* Parse DOS header */
	dos = loaded->ImageBase;
	if ( ! dos ) {
		DBG ( "[Missing DOS header]" );
		return NULL;
	}
	dos_magic = dos->e_magic;
	if ( dos_magic != EFI_IMAGE_DOS_SIGNATURE ) {
		DBG ( "[Bad DOS signature %#04x]", dos_magic );
		return NULL;
	}
	pe = ( loaded->ImageBase + dos->e_lfanew );

	/* Parse PE header */
	pe_magic = pe->Pe32.Signature;
	if ( pe_magic != EFI_IMAGE_NT_SIGNATURE ) {
		DBG ( "[Bad PE signature %#08x]", pe_magic );
		return NULL;
	}
	opt32 = &pe->Pe32.OptionalHeader;
	opt64 = &pe->Pe32Plus.OptionalHeader;
	opt_magic = opt32->Magic;
	if ( opt_magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC ) {
		datadir = opt32->DataDirectory;
	} else if ( opt_magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC ) {
		datadir = opt64->DataDirectory;
	} else {
		DBG ( "[Bad optional header signature %#04x]", opt_magic );
		return NULL;
	}

	/* Parse data directory entry */
	if ( ! datadir[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress ) {
		DBG ( "[Empty debug directory entry]" );
		return NULL;
	}
	debug = ( loaded->ImageBase +
		  datadir[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress );

	/* Parse debug directory entry */
	if ( debug->Type != EFI_IMAGE_DEBUG_TYPE_CODEVIEW ) {
		DBG ( "[Not a CodeView debug directory entry (type %d)]",
		      debug->Type );
		return NULL;
	}
	codeview_nb10 = ( loaded->ImageBase + debug->RVA );
	codeview_rsds = ( loaded->ImageBase + debug->RVA );
	codeview_mtoc = ( loaded->ImageBase + debug->RVA );
	codeview_magic = codeview_nb10->Signature;

	/* Parse CodeView entry */
	if ( codeview_magic == CODEVIEW_SIGNATURE_NB10 ) {
		name = ( ( void * ) ( codeview_nb10 + 1 ) );
	} else if ( codeview_magic == CODEVIEW_SIGNATURE_RSDS ) {
		name = ( ( void * ) ( codeview_rsds + 1 ) );
	} else if ( codeview_magic == CODEVIEW_SIGNATURE_MTOC ) {
		name = ( ( void * ) ( codeview_mtoc + 1 ) );
	} else {
		DBG ( "[Bad CodeView signature %#08x]", codeview_magic );
		return NULL;
	}

	/* Sanity check - avoid scanning endlessly through memory */
	max_len = EFI_PAGE_SIZE; /* Reasonably sane */
	if ( strnlen ( name, max_len ) == max_len ) {
		DBG ( "[Excessively long or invalid CodeView name]" );
		return NULL;
	}

	/* Skip any directory components.  We cannot modify this data
	 * or create a temporary buffer, so do not use basename().
	 */
	while ( ( ( tmp = strchr ( name, '/' ) ) != NULL ) ||
		( ( tmp = strchr ( name, '\\' ) ) != NULL ) ) {
		name = ( tmp + 1 );
	}

	/* Copy base name to buffer */
	snprintf ( buf, sizeof ( buf ), "%s", name );

	/* Strip file suffix, if present */
	if ( ( tmp = strrchr ( name, '.' ) ) != NULL )
		*tmp = '\0';

	return name;
}

/**
 * Get initial loaded image name
 *
 * @v loaded		Loaded image
 * @ret name		Initial loaded image name, or NULL
 */
static const char *
efi_first_loaded_image_name ( EFI_LOADED_IMAGE_PROTOCOL *loaded ) {

	/* Sanity check */
	if ( ! loaded ) {
		DBG ( "[NULL LoadedImage]" );
		return NULL;
	}

	return ( ( loaded->ParentHandle == NULL ) ? "DxeCore(?)" : NULL );
}

/**
 * Get loaded image name from file path
 *
 * @v loaded		Loaded image
 * @ret name		Loaded image name, or NULL
 */
static const char *
efi_loaded_image_filepath_name ( EFI_LOADED_IMAGE_PROTOCOL *loaded ) {

	/* Sanity check */
	if ( ! loaded ) {
		DBG ( "[NULL LoadedImage]" );
		return NULL;
	}

	return efi_devpath_text ( loaded->FilePath );
}

/** An EFI handle name type */
struct efi_handle_name_type {
	/** Protocol */
	EFI_GUID *protocol;
	/**
	 * Get name
	 *
	 * @v interface		Protocol interface
	 * @ret name		Name of handle, or NULL on failure
	 */
	const char * ( * name ) ( void *interface );
};

/**
 * Define an EFI handle name type
 *
 * @v protocol		Protocol interface
 * @v name		Method to get name
 * @ret type		EFI handle name type
 */
#define EFI_HANDLE_NAME_TYPE( protocol, name ) {	\
	(protocol),					\
	( const char * ( * ) ( void * ) ) (name),	\
	}

/** EFI handle name types */
static struct efi_handle_name_type efi_handle_name_types[] = {
	/* Device path */
	EFI_HANDLE_NAME_TYPE ( &efi_device_path_protocol_guid,
			       efi_devpath_text ),
	/* Driver name (for driver image handles) */
	EFI_HANDLE_NAME_TYPE ( &efi_component_name2_protocol_guid,
			       efi_driver_name2 ),
	/* Driver name (via obsolete original ComponentName protocol) */
	EFI_HANDLE_NAME_TYPE ( &efi_component_name_protocol_guid,
			       efi_driver_name ),
	/* PE/COFF debug filename (for image handles) */
	EFI_HANDLE_NAME_TYPE ( &efi_loaded_image_protocol_guid,
			       efi_pecoff_debug_name ),
	/* Loaded image device path (for image handles) */
	EFI_HANDLE_NAME_TYPE ( &efi_loaded_image_device_path_protocol_guid,
			       efi_devpath_text ),
	/* First loaded image name (for the DxeCore image) */
	EFI_HANDLE_NAME_TYPE ( &efi_loaded_image_protocol_guid,
			       efi_first_loaded_image_name ),
	/* Handle's loaded image file path (for image handles) */
	EFI_HANDLE_NAME_TYPE ( &efi_loaded_image_protocol_guid,
			       efi_loaded_image_filepath_name ),
};

/**
 * Get name of an EFI handle
 *
 * @v handle		EFI handle
 * @ret text		Name of handle, or NULL
 */
const char * efi_handle_name ( EFI_HANDLE handle ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	struct efi_handle_name_type *type;
	unsigned int i;
	void *interface;
	const char *name;
	EFI_STATUS efirc;

	/* Fail immediately for NULL handles */
	if ( ! handle )
		return NULL;

	/* Try each name type in turn */
	for ( i = 0 ; i < ( sizeof ( efi_handle_name_types ) /
			    sizeof ( efi_handle_name_types[0] ) ) ; i++ ) {
		type = &efi_handle_name_types[i];
		DBG2 ( "<%d", i );

		/* Try to open the applicable protocol */
		efirc = bs->OpenProtocol ( handle, type->protocol, &interface,
					   efi_image_handle, handle,
					   EFI_OPEN_PROTOCOL_GET_PROTOCOL );
		if ( efirc != 0 ) {
			DBG2 ( ">" );
			continue;
		}

		/* Try to get name from this protocol */
		DBG2 ( "-" );
		name = type->name ( interface );
		DBG2 ( "%c", ( name ? ( name[0] ? 'Y' : 'E' ) : 'N' ) );

		/* Close protocol */
		bs->CloseProtocol ( handle, type->protocol,
				    efi_image_handle, handle );
		DBG2 ( ">" );

		/* Use this name, if possible */
		if ( name && name[0] )
			return name;
	}

	return "UNKNOWN";
}
