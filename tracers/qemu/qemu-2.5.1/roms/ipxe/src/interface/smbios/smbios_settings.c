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

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <ipxe/settings.h>
#include <ipxe/init.h>
#include <ipxe/uuid.h>
#include <ipxe/smbios.h>

/** SMBIOS settings scope */
static const struct settings_scope smbios_settings_scope;

/**
 * Construct SMBIOS raw-data tag
 *
 * @v _type		SMBIOS structure type number
 * @v _structure	SMBIOS structure data type
 * @v _field		Field within SMBIOS structure data type
 * @ret tag		SMBIOS setting tag
 */
#define SMBIOS_RAW_TAG( _type, _structure, _field )		\
	( ( (_type) << 16 ) |					\
	  ( offsetof ( _structure, _field ) << 8 ) |		\
	  ( sizeof ( ( ( _structure * ) 0 )->_field ) ) )

/**
 * Construct SMBIOS string tag
 *
 * @v _type		SMBIOS structure type number
 * @v _structure	SMBIOS structure data type
 * @v _field		Field within SMBIOS structure data type
 * @ret tag		SMBIOS setting tag
 */
#define SMBIOS_STRING_TAG( _type, _structure, _field )		\
	( ( (_type) << 16 ) |					\
	  ( offsetof ( _structure, _field ) << 8 ) )

/**
 * Check applicability of SMBIOS setting
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @ret applies		Setting applies within this settings block
 */
static int smbios_applies ( struct settings *settings __unused,
			    const struct setting *setting ) {

	return ( setting->scope == &smbios_settings_scope );
}

/**
 * Fetch value of SMBIOS setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int smbios_fetch ( struct settings *settings __unused,
			  struct setting *setting,
			  void *data, size_t len ) {
	struct smbios_structure structure;
	unsigned int tag_instance;
	unsigned int tag_type;
	unsigned int tag_offset;
	unsigned int tag_len;
	int rc;

	/* Split tag into instance, type, offset and length */
	tag_instance = ( ( setting->tag >> 24 ) & 0xff );
	tag_type = ( ( setting->tag >> 16 ) & 0xff );
	tag_offset = ( ( setting->tag >> 8 ) & 0xff );
	tag_len = ( setting->tag & 0xff );

	/* Find SMBIOS structure */
	if ( ( rc = find_smbios_structure ( tag_type, tag_instance,
					    &structure ) ) != 0 )
		return rc;

	{
		uint8_t buf[structure.header.len];
		const void *raw;
		union uuid uuid;
		unsigned int index;

		/* Read SMBIOS structure */
		if ( ( rc = read_smbios_structure ( &structure, buf,
						    sizeof ( buf ) ) ) != 0 )
			return rc;

		/* A <length> of zero indicates that the byte at
		 * <offset> contains a string index.  An <offset> of
		 * zero indicates that the <length> contains a literal
		 * string index.
		 */
		if ( ( tag_len == 0 ) || ( tag_offset == 0 ) ) {
			index = ( ( tag_offset == 0 ) ?
				  tag_len : buf[tag_offset] );
			if ( ( rc = read_smbios_string ( &structure, index,
							 data, len ) ) < 0 ) {
				return rc;
			}
			if ( ! setting->type )
				setting->type = &setting_type_string;
			return rc;
		}

		/* Mangle UUIDs if necessary.  iPXE treats UUIDs as
		 * being in network byte order (big-endian).  SMBIOS
		 * specification version 2.6 states that UUIDs are
		 * stored with little-endian values in the first three
		 * fields; earlier versions did not specify an
		 * endianness.  dmidecode assumes that the byte order
		 * is little-endian if and only if the SMBIOS version
		 * is 2.6 or higher; we match this behaviour.
		 */
		raw = &buf[tag_offset];
		if ( ( setting->type == &setting_type_uuid ) &&
		     ( tag_len == sizeof ( uuid ) ) &&
		     ( smbios_version() >= SMBIOS_VERSION ( 2, 6 ) ) ) {
			DBG ( "SMBIOS detected mangled UUID\n" );
			memcpy ( &uuid, &buf[tag_offset], sizeof ( uuid ) );
			uuid_mangle ( &uuid );
			raw = &uuid;
		}

		/* Return data */
		if ( len > tag_len )
			len = tag_len;
		memcpy ( data, raw, len );
		if ( ! setting->type )
			setting->type = &setting_type_hex;
		return tag_len;
	}
}

/** SMBIOS settings operations */
static struct settings_operations smbios_settings_operations = {
	.applies = smbios_applies,
	.fetch = smbios_fetch,
};

/** SMBIOS settings */
static struct settings smbios_settings = {
	.refcnt = NULL,
	.siblings = LIST_HEAD_INIT ( smbios_settings.siblings ),
	.children = LIST_HEAD_INIT ( smbios_settings.children ),
	.op = &smbios_settings_operations,
	.default_scope = &smbios_settings_scope,
};

/** Initialise SMBIOS settings */
static void smbios_init ( void ) {
	int rc;

	if ( ( rc = register_settings ( &smbios_settings, NULL,
					"smbios" ) ) != 0 ) {
		DBG ( "SMBIOS could not register settings: %s\n",
		      strerror ( rc ) );
		return;
	}
}

/** SMBIOS settings initialiser */
struct init_fn smbios_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = smbios_init,
};

/** UUID setting obtained via SMBIOS */
const struct setting uuid_setting __setting ( SETTING_HOST, uuid ) = {
	.name = "uuid",
	.description = "UUID",
	.tag = SMBIOS_RAW_TAG ( SMBIOS_TYPE_SYSTEM_INFORMATION,
				struct smbios_system_information, uuid ),
	.type = &setting_type_uuid,
	.scope = &smbios_settings_scope,
};

/** Manufacturer name setting */
const struct setting manufacturer_setting __setting ( SETTING_HOST_EXTRA,
						      manufacturer ) = {
	.name = "manufacturer",
	.description = "Manufacturer",
	.tag = SMBIOS_STRING_TAG ( SMBIOS_TYPE_SYSTEM_INFORMATION,
				   struct smbios_system_information,
				   manufacturer ),
	.type = &setting_type_string,
	.scope = &smbios_settings_scope,
};

/** Product name setting */
const struct setting product_setting __setting ( SETTING_HOST_EXTRA, product )={
	.name = "product",
	.description = "Product name",
	.tag = SMBIOS_STRING_TAG ( SMBIOS_TYPE_SYSTEM_INFORMATION,
				   struct smbios_system_information,
				   product ),
	.type = &setting_type_string,
	.scope = &smbios_settings_scope,
};

/** Serial number setting */
const struct setting serial_setting __setting ( SETTING_HOST_EXTRA, serial ) = {
	.name = "serial",
	.description = "Serial number",
	.tag = SMBIOS_STRING_TAG ( SMBIOS_TYPE_SYSTEM_INFORMATION,
				   struct smbios_system_information,
				   serial ),
	.type = &setting_type_string,
	.scope = &smbios_settings_scope,
};

/** Asset tag setting */
const struct setting asset_setting __setting ( SETTING_HOST_EXTRA, asset ) = {
	.name = "asset",
	.description = "Asset tag",
	.tag = SMBIOS_STRING_TAG ( SMBIOS_TYPE_ENCLOSURE_INFORMATION,
				   struct smbios_enclosure_information,
				   asset_tag ),
	.type = &setting_type_string,
	.scope = &smbios_settings_scope,
};

/** Board serial number setting (may differ from chassis serial number) */
const struct setting board_serial_setting __setting ( SETTING_HOST_EXTRA,
						      board_serial ) = {
	.name = "board-serial",
	.description = "Base board serial",
	.tag = SMBIOS_STRING_TAG ( SMBIOS_TYPE_BASE_BOARD_INFORMATION,
				   struct smbios_base_board_information,
				   serial ),
	.type = &setting_type_string,
	.scope = &smbios_settings_scope,
};
