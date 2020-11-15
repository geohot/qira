/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
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
 * EFI SNP HII protocol
 *
 * The HII protocols are some of the less-well designed parts of the
 * entire EFI specification.  This is a significant accomplishment.
 *
 * The face-slappingly ludicrous query string syntax seems to be
 * motivated by the desire to allow a caller to query multiple drivers
 * simultaneously via the single-instance HII_CONFIG_ROUTING_PROTOCOL,
 * which is supposed to pass relevant subsets of the query string to
 * the relevant drivers.
 *
 * Nobody uses the HII_CONFIG_ROUTING_PROTOCOL.  Not even the EFI
 * setup browser uses the HII_CONFIG_ROUTING_PROTOCOL.  To the best of
 * my knowledge, there has only ever been one implementation of the
 * HII_CONFIG_ROUTING_PROTOCOL (as part of EDK2), and it just doesn't
 * work.  It's so badly broken that I can't even figure out what the
 * code is _trying_ to do.
 *
 * Fundamentally, the problem seems to be that Javascript programmers
 * should not be allowed to design APIs for C code.
 */

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <errno.h>
#include <ipxe/settings.h>
#include <ipxe/nvo.h>
#include <ipxe/device.h>
#include <ipxe/netdevice.h>
#include <ipxe/version.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_hii.h>
#include <ipxe/efi/efi_snp.h>
#include <ipxe/efi/efi_strings.h>
#include <config/branding.h>

/** EFI platform setup formset GUID */
static EFI_GUID efi_hii_platform_setup_formset_guid
	= EFI_HII_PLATFORM_SETUP_FORMSET_GUID;

/** EFI IBM UCM compliant formset GUID */
static EFI_GUID efi_hii_ibm_ucm_compliant_formset_guid
	= EFI_HII_IBM_UCM_COMPLIANT_FORMSET_GUID;

/** EFI HII database protocol */
static EFI_HII_DATABASE_PROTOCOL *efihii;
EFI_REQUEST_PROTOCOL ( EFI_HII_DATABASE_PROTOCOL, &efihii );

/**
 * Identify settings to be exposed via HII
 *
 * @v snpdev		SNP device
 * @ret settings	Settings, or NULL
 */
static struct settings * efi_snp_hii_settings ( struct efi_snp_device *snpdev ){

	return find_child_settings ( netdev_settings ( snpdev->netdev ),
				     NVO_SETTINGS_NAME );
}

/**
 * Check whether or not setting is applicable
 *
 * @v snpdev		SNP device
 * @v setting		Setting
 * @ret applies		Setting applies
 */
static int efi_snp_hii_setting_applies ( struct efi_snp_device *snpdev,
					 struct setting *setting ) {

	return nvo_applies ( efi_snp_hii_settings ( snpdev ), setting );
}

/**
 * Generate a random GUID
 *
 * @v guid		GUID to fill in
 */
static void efi_snp_hii_random_guid ( EFI_GUID *guid ) {
	uint8_t *byte = ( ( uint8_t * ) guid );
	unsigned int i;

	for ( i = 0 ; i < sizeof ( *guid ) ; i++ )
		*(byte++) = random();
}

/**
 * Generate EFI SNP questions
 *
 * @v snpdev		SNP device
 * @v ifr		IFR builder
 * @v varstore_id	Variable store identifier
 */
static void efi_snp_hii_questions ( struct efi_snp_device *snpdev,
				    struct efi_ifr_builder *ifr,
				    unsigned int varstore_id ) {
	struct setting *setting;
	struct setting *previous = NULL;
	unsigned int name_id;
	unsigned int prompt_id;
	unsigned int help_id;
	unsigned int question_id;

	/* Add all applicable settings */
	for_each_table_entry ( setting, SETTINGS ) {
		if ( ! efi_snp_hii_setting_applies ( snpdev, setting ) )
			continue;
		if ( previous && ( setting_cmp ( setting, previous ) == 0 ) )
			continue;
		previous = setting;
		name_id = efi_ifr_string ( ifr, "%s", setting->name );
		prompt_id = efi_ifr_string ( ifr, "%s", setting->description );
		help_id = efi_ifr_string ( ifr, PRODUCT_SETTING_URI,
					   setting->name );
		question_id = setting->tag;
		efi_ifr_string_op ( ifr, prompt_id, help_id,
				    question_id, varstore_id, name_id,
				    0, 0x00, 0xff, 0 );
	}
}

/**
 * Build HII package list for SNP device
 *
 * @v snpdev		SNP device
 * @ret package		Package list, or NULL on error
 */
static EFI_HII_PACKAGE_LIST_HEADER *
efi_snp_hii_package_list ( struct efi_snp_device *snpdev ) {
	struct net_device *netdev = snpdev->netdev;
	struct device *dev = netdev->dev;
	struct efi_ifr_builder ifr;
	EFI_HII_PACKAGE_LIST_HEADER *package;
	const char *name;
	EFI_GUID package_guid;
	EFI_GUID formset_guid;
	EFI_GUID varstore_guid;
	unsigned int title_id;
	unsigned int varstore_id;

	/* Initialise IFR builder */
	efi_ifr_init ( &ifr );

	/* Determine product name */
	name = ( product_name[0] ? product_name : product_short_name );

	/* Generate GUIDs */
	efi_snp_hii_random_guid ( &package_guid );
	efi_snp_hii_random_guid ( &formset_guid );
	efi_snp_hii_random_guid ( &varstore_guid );

	/* Generate title string (used more than once) */
	title_id = efi_ifr_string ( &ifr, "%s (%s)", name,
				    netdev_addr ( netdev ) );

	/* Generate opcodes */
	efi_ifr_form_set_op ( &ifr, &formset_guid, title_id,
			      efi_ifr_string ( &ifr, "Configure %s",
					       product_short_name ),
			      &efi_hii_platform_setup_formset_guid,
			      &efi_hii_ibm_ucm_compliant_formset_guid, NULL );
	efi_ifr_guid_class_op ( &ifr, EFI_NETWORK_DEVICE_CLASS );
	efi_ifr_guid_subclass_op ( &ifr, 0x03 );
	varstore_id = efi_ifr_varstore_name_value_op ( &ifr, &varstore_guid );
	efi_ifr_form_op ( &ifr, title_id );
	efi_ifr_text_op ( &ifr,
			  efi_ifr_string ( &ifr, "Name" ),
			  efi_ifr_string ( &ifr, "Firmware product name" ),
			  efi_ifr_string ( &ifr, "%s", name ) );
	efi_ifr_text_op ( &ifr,
			  efi_ifr_string ( &ifr, "Version" ),
			  efi_ifr_string ( &ifr, "Firmware version" ),
			  efi_ifr_string ( &ifr, "%s", product_version ) );
	efi_ifr_text_op ( &ifr,
			  efi_ifr_string ( &ifr, "Driver" ),
			  efi_ifr_string ( &ifr, "Firmware driver" ),
			  efi_ifr_string ( &ifr, "%s", dev->driver_name ) );
	efi_ifr_text_op ( &ifr,
			  efi_ifr_string ( &ifr, "Device" ),
			  efi_ifr_string ( &ifr, "Hardware device" ),
			  efi_ifr_string ( &ifr, "%s", dev->name ) );
	efi_snp_hii_questions ( snpdev, &ifr, varstore_id );
	efi_ifr_end_op ( &ifr );
	efi_ifr_end_op ( &ifr );

	/* Build package */
	package = efi_ifr_package ( &ifr, &package_guid, "en-us",
				    efi_ifr_string ( &ifr, "English" ) );
	if ( ! package ) {
		DBGC ( snpdev, "SNPDEV %p could not build IFR package\n",
		       snpdev );
		efi_ifr_free ( &ifr );
		return NULL;
	}

	/* Free temporary storage */
	efi_ifr_free ( &ifr );
	return package;
}

/**
 * Append response to result string
 *
 * @v snpdev		SNP device
 * @v key		Key
 * @v value		Value
 * @v results		Result string
 * @ret rc		Return status code
 *
 * The result string is allocated dynamically using
 * BootServices::AllocatePool(), and the caller is responsible for
 * eventually calling BootServices::FreePool().
 */
static int efi_snp_hii_append ( struct efi_snp_device *snpdev __unused,
				const char *key, const char *value,
				wchar_t **results ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	size_t len;
	void *new;

	/* Allocate new string */
	len = ( ( *results ? ( wcslen ( *results ) + 1 /* "&" */ ) : 0 ) +
		strlen ( key ) + 1 /* "=" */ + strlen ( value ) + 1 /* NUL */ );
	bs->AllocatePool ( EfiBootServicesData, ( len * sizeof ( wchar_t ) ),
			   &new );
	if ( ! new )
		return -ENOMEM;

	/* Populate string */
	efi_snprintf ( new, len, "%ls%s%s=%s", ( *results ? *results : L"" ),
		       ( *results ? L"&" : L"" ), key, value );
	bs->FreePool ( *results );
	*results = new;

	return 0;
}

/**
 * Fetch HII setting
 *
 * @v snpdev		SNP device
 * @v key		Key
 * @v value		Value
 * @v results		Result string
 * @v have_setting	Flag indicating detection of a setting
 * @ret rc		Return status code
 */
static int efi_snp_hii_fetch ( struct efi_snp_device *snpdev,
			       const char *key, const char *value,
			       wchar_t **results, int *have_setting ) {
	struct settings *settings = efi_snp_hii_settings ( snpdev );
	struct settings *origin;
	struct setting *setting;
	struct setting fetched;
	int len;
	char *buf;
	char *encoded;
	int i;
	int rc;

	/* Handle ConfigHdr components */
	if ( ( strcasecmp ( key, "GUID" ) == 0 ) ||
	     ( strcasecmp ( key, "NAME" ) == 0 ) ||
	     ( strcasecmp ( key, "PATH" ) == 0 ) ) {
		return efi_snp_hii_append ( snpdev, key, value, results );
	}
	if ( have_setting )
		*have_setting = 1;

	/* Do nothing more unless we have a settings block */
	if ( ! settings ) {
		rc = -ENOTSUP;
		goto err_no_settings;
	}

	/* Identify setting */
	setting = find_setting ( key );
	if ( ! setting ) {
		DBGC ( snpdev, "SNPDEV %p no such setting \"%s\"\n",
		       snpdev, key );
		rc = -ENODEV;
		goto err_find_setting;
	}

	/* Encode value */
	if ( setting_exists ( settings, setting ) ) {

		/* Calculate formatted length */
		len = fetchf_setting ( settings, setting, &origin, &fetched,
				       NULL, 0 );
		if ( len < 0 ) {
			rc = len;
			DBGC ( snpdev, "SNPDEV %p could not fetch %s: %s\n",
			       snpdev, setting->name, strerror ( rc ) );
			goto err_fetchf_len;
		}

		/* Allocate buffer for formatted value and HII-encoded value */
		buf = zalloc ( len + 1 /* NUL */ + ( len * 4 ) + 1 /* NUL */ );
		if ( ! buf ) {
			rc = -ENOMEM;
			goto err_alloc;
		}
		encoded = ( buf + len + 1 /* NUL */ );

		/* Format value */
		fetchf_setting ( origin, &fetched, NULL, NULL, buf,
				 ( len + 1 /* NUL */ ) );
		for ( i = 0 ; i < len ; i++ ) {
			sprintf ( ( encoded + ( 4 * i ) ), "%04x",
				  *( ( uint8_t * ) buf + i ) );
		}

	} else {

		/* Non-existent or inapplicable setting */
		buf = NULL;
		encoded = "";
	}

	/* Append results */
	if ( ( rc = efi_snp_hii_append ( snpdev, key, encoded,
					 results ) ) != 0 ) {
		goto err_append;
	}

	/* Success */
	rc = 0;

 err_append:
	free ( buf );
 err_alloc:
 err_fetchf_len:
 err_find_setting:
 err_no_settings:
	return rc;
}

/**
 * Fetch HII setting
 *
 * @v snpdev		SNP device
 * @v key		Key
 * @v value		Value
 * @v results		Result string (unused)
 * @v have_setting	Flag indicating detection of a setting (unused)
 * @ret rc		Return status code
 */
static int efi_snp_hii_store ( struct efi_snp_device *snpdev,
			       const char *key, const char *value,
			       wchar_t **results __unused,
			       int *have_setting __unused ) {
	struct settings *settings = efi_snp_hii_settings ( snpdev );
	struct setting *setting;
	char *buf;
	char tmp[5];
	char *endp;
	int len;
	int i;
	int rc;

	/* Handle ConfigHdr components */
	if ( ( strcasecmp ( key, "GUID" ) == 0 ) ||
	     ( strcasecmp ( key, "NAME" ) == 0 ) ||
	     ( strcasecmp ( key, "PATH" ) == 0 ) ) {
		/* Nothing to do */
		return 0;
	}

	/* Do nothing more unless we have a settings block */
	if ( ! settings ) {
		rc = -ENOTSUP;
		goto err_no_settings;
	}

	/* Identify setting */
	setting = find_setting ( key );
	if ( ! setting ) {
		DBGC ( snpdev, "SNPDEV %p no such setting \"%s\"\n",
		       snpdev, key );
		rc = -ENODEV;
		goto err_find_setting;
	}

	/* Allocate buffer */
	len = ( strlen ( value ) / 4 );
	buf = zalloc ( len + 1 /* NUL */ );
	if ( ! buf ) {
		rc = -ENOMEM;
		goto err_alloc;
	}

	/* Decode value */
	tmp[4] = '\0';
	for ( i = 0 ; i < len ; i++ ) {
		memcpy ( tmp, ( value + ( i * 4 ) ), 4 );
		buf[i] = strtoul ( tmp, &endp, 16 );
		if ( endp != &tmp[4] ) {
			DBGC ( snpdev, "SNPDEV %p invalid character %s\n",
			       snpdev, tmp );
			rc = -EINVAL;
			goto err_inval;
		}
	}

	/* Store value */
	if ( ( rc = storef_setting ( settings, setting, buf ) ) != 0 ) {
		DBGC ( snpdev, "SNPDEV %p could not store \"%s\" into %s: %s\n",
		       snpdev, buf, setting->name, strerror ( rc ) );
		goto err_storef;
	}

	/* Success */
	rc = 0;

 err_storef:
 err_inval:
	free ( buf );
 err_alloc:
 err_find_setting:
 err_no_settings:
	return rc;
}

/**
 * Process portion of HII configuration string
 *
 * @v snpdev		SNP device
 * @v string		HII configuration string
 * @v progress		Progress through HII configuration string
 * @v results		Results string
 * @v have_setting	Flag indicating detection of a setting (unused)
 * @v process		Function used to process key=value pairs
 * @ret rc		Return status code
 */
static int efi_snp_hii_process ( struct efi_snp_device *snpdev,
				 wchar_t *string, wchar_t **progress,
				 wchar_t **results, int *have_setting,
				 int ( * process ) ( struct efi_snp_device *,
						     const char *key,
						     const char *value,
						     wchar_t **results,
						     int *have_setting ) ) {
	wchar_t *wkey = string;
	wchar_t *wend = string;
	wchar_t *wvalue = NULL;
	size_t key_len;
	size_t value_len;
	void *temp;
	char *key;
	char *value;
	int rc;

	/* Locate key, value (if any), and end */
	while ( *wend ) {
		if ( *wend == L'&' )
			break;
		if ( *(wend++) == L'=' )
			wvalue = wend;
	}

	/* Allocate memory for key and value */
	key_len = ( ( wvalue ? ( wvalue - 1 ) : wend ) - wkey );
	value_len = ( wvalue ? ( wend - wvalue ) : 0 );
	temp = zalloc ( key_len + 1 /* NUL */ + value_len + 1 /* NUL */ );
	if ( ! temp )
		return -ENOMEM;
	key = temp;
	value = ( temp + key_len + 1 /* NUL */ );

	/* Copy key and value */
	while ( key_len-- )
		key[key_len] = wkey[key_len];
	while ( value_len-- )
		value[value_len] = wvalue[value_len];

	/* Process key and value */
	if ( ( rc = process ( snpdev, key, value, results,
			      have_setting ) ) != 0 ) {
		goto err;
	}

	/* Update progress marker */
	*progress = wend;

 err:
	/* Free temporary storage */
	free ( temp );

	return rc;
}

/**
 * Fetch configuration
 *
 * @v hii		HII configuration access protocol
 * @v request		Configuration to fetch
 * @ret progress	Progress made through configuration to fetch
 * @ret results		Query results
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_hii_extract_config ( const EFI_HII_CONFIG_ACCESS_PROTOCOL *hii,
			     EFI_STRING request, EFI_STRING *progress,
			     EFI_STRING *results ) {
	struct efi_snp_device *snpdev =
		container_of ( hii, struct efi_snp_device, hii );
	int have_setting = 0;
	wchar_t *pos;
	int rc;

	DBGC ( snpdev, "SNPDEV %p ExtractConfig request \"%ls\"\n",
	       snpdev, request );

	/* Initialise results */
	*results = NULL;

	/* Process all request fragments */
	for ( pos = *progress = request ; *progress && **progress ;
	      pos = *progress + 1 ) {
		if ( ( rc = efi_snp_hii_process ( snpdev, pos, progress,
						  results, &have_setting,
						  efi_snp_hii_fetch ) ) != 0 ) {
			return EFIRC ( rc );
		}
	}

	/* If we have no explicit request, return all settings */
	if ( ! have_setting ) {
		struct setting *setting;

		for_each_table_entry ( setting, SETTINGS ) {
			if ( ! efi_snp_hii_setting_applies ( snpdev, setting ) )
				continue;
			if ( ( rc = efi_snp_hii_fetch ( snpdev, setting->name,
							NULL, results,
							NULL ) ) != 0 ) {
				return EFIRC ( rc );
			}
		}
	}

	DBGC ( snpdev, "SNPDEV %p ExtractConfig results \"%ls\"\n",
	       snpdev, *results );
	return 0;
}

/**
 * Store configuration
 *
 * @v hii		HII configuration access protocol
 * @v config		Configuration to store
 * @ret progress	Progress made through configuration to store
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_hii_route_config ( const EFI_HII_CONFIG_ACCESS_PROTOCOL *hii,
			   EFI_STRING config, EFI_STRING *progress ) {
	struct efi_snp_device *snpdev =
		container_of ( hii, struct efi_snp_device, hii );
	wchar_t *pos;
	int rc;

	DBGC ( snpdev, "SNPDEV %p RouteConfig \"%ls\"\n", snpdev, config );

	/* Process all request fragments */
	for ( pos = *progress = config ; *progress && **progress ;
	      pos = *progress + 1 ) {
		if ( ( rc = efi_snp_hii_process ( snpdev, pos, progress,
						  NULL, NULL,
						  efi_snp_hii_store ) ) != 0 ) {
			return EFIRC ( rc );
		}
	}

	return 0;
}

/**
 * Handle form actions
 *
 * @v hii		HII configuration access protocol
 * @v action		Form browser action
 * @v question_id	Question ID
 * @v type		Type of value
 * @v value		Value
 * @ret action_request	Action requested by driver
 * @ret efirc		EFI status code
 */
static EFI_STATUS EFIAPI
efi_snp_hii_callback ( const EFI_HII_CONFIG_ACCESS_PROTOCOL *hii,
		       EFI_BROWSER_ACTION action __unused,
		       EFI_QUESTION_ID question_id __unused,
		       UINT8 type __unused, EFI_IFR_TYPE_VALUE *value __unused,
		       EFI_BROWSER_ACTION_REQUEST *action_request __unused ) {
	struct efi_snp_device *snpdev =
		container_of ( hii, struct efi_snp_device, hii );

	DBGC ( snpdev, "SNPDEV %p Callback\n", snpdev );
	return EFI_UNSUPPORTED;
}

/** HII configuration access protocol */
static EFI_HII_CONFIG_ACCESS_PROTOCOL efi_snp_device_hii = {
	.ExtractConfig	= efi_snp_hii_extract_config,
	.RouteConfig	= efi_snp_hii_route_config,
	.Callback	= efi_snp_hii_callback,
};

/**
 * Install HII protocol and packages for SNP device
 *
 * @v snpdev		SNP device
 * @ret rc		Return status code
 */
int efi_snp_hii_install ( struct efi_snp_device *snpdev ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	int efirc;
	int rc;

	/* Do nothing if HII database protocol is not supported */
	if ( ! efihii ) {
		rc = -ENOTSUP;
		goto err_no_hii;
	}

	/* Initialise HII protocol */
	memcpy ( &snpdev->hii, &efi_snp_device_hii, sizeof ( snpdev->hii ) );

	/* Create HII package list */
	snpdev->package_list = efi_snp_hii_package_list ( snpdev );
	if ( ! snpdev->package_list ) {
		DBGC ( snpdev, "SNPDEV %p could not create HII package list\n",
		       snpdev );
		rc = -ENOMEM;
		goto err_build_package_list;
	}

	/* Add HII packages */
	if ( ( efirc = efihii->NewPackageList ( efihii, snpdev->package_list,
						snpdev->handle,
						&snpdev->hii_handle ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBGC ( snpdev, "SNPDEV %p could not add HII packages: %s\n",
		       snpdev, strerror ( rc ) );
		goto err_new_package_list;
	}

	/* Install HII protocol */
	if ( ( efirc = bs->InstallMultipleProtocolInterfaces (
			 &snpdev->handle,
			 &efi_hii_config_access_protocol_guid, &snpdev->hii,
			 NULL ) ) != 0 ) {
		rc = -EEFI ( efirc );
		DBGC ( snpdev, "SNPDEV %p could not install HII protocol: %s\n",
		       snpdev, strerror ( rc ) );
		goto err_install_protocol;
	}

	return 0;

	bs->UninstallMultipleProtocolInterfaces (
			snpdev->handle,
			&efi_hii_config_access_protocol_guid, &snpdev->hii,
			NULL );
 err_install_protocol:
	efihii->RemovePackageList ( efihii, snpdev->hii_handle );
 err_new_package_list:
	free ( snpdev->package_list );
	snpdev->package_list = NULL;
 err_build_package_list:
 err_no_hii:
	return rc;
}

/**
 * Uninstall HII protocol and package for SNP device
 *
 * @v snpdev		SNP device
 */
void efi_snp_hii_uninstall ( struct efi_snp_device *snpdev ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;

	/* Do nothing if HII database protocol is not supported */
	if ( ! efihii )
		return;

	/* Uninstall protocols and remove package list */
	bs->UninstallMultipleProtocolInterfaces (
			snpdev->handle,
			&efi_hii_config_access_protocol_guid, &snpdev->hii,
			NULL );
	efihii->RemovePackageList ( efihii, snpdev->hii_handle );
	free ( snpdev->package_list );
	snpdev->package_list = NULL;
}
