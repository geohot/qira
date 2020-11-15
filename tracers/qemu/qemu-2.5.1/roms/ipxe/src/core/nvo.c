/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ipxe/dhcp.h>
#include <ipxe/nvs.h>
#include <ipxe/nvo.h>

/** @file
 *
 * Non-volatile stored options
 *
 */

/**
 * Calculate checksum over non-volatile stored options
 *
 * @v nvo		Non-volatile options block
 * @ret sum		Checksum
 */
static unsigned int nvo_checksum ( struct nvo_block *nvo ) {
	uint8_t *data = nvo->data;
	uint8_t sum = 0;
	unsigned int i;

	for ( i = 0 ; i < nvo->len ; i++ ) {
		sum += *(data++);
	}
	return sum;
}

/**
 * Reallocate non-volatile stored options block
 *
 * @v nvo		Non-volatile options block
 * @v len		New length
 * @ret rc		Return status code
 */
static int nvo_realloc ( struct nvo_block *nvo, size_t len ) {
	void *new_data;

	/* Reallocate data */
	new_data = realloc ( nvo->data, len );
	if ( ! new_data ) {
		DBGC ( nvo, "NVO %p could not allocate %zd bytes\n",
		       nvo, len );
		return -ENOMEM;
	}
	nvo->data = new_data;
	nvo->len = len;

	/* Update DHCP option block */
	if ( len ) {
		nvo->dhcpopts.data = ( nvo->data + 1 /* checksum */ );
		nvo->dhcpopts.alloc_len = ( len - 1 /* checksum */ );
	} else {
		nvo->dhcpopts.data = NULL;
		nvo->dhcpopts.used_len = 0;
		nvo->dhcpopts.alloc_len = 0;
	}

	return 0;
}

/**
 * Reallocate non-volatile stored options DHCP option block
 *
 * @v options		DHCP option block
 * @v len		New length
 * @ret rc		Return status code
 */
static int nvo_realloc_dhcpopt ( struct dhcp_options *options, size_t len ) {
	struct nvo_block *nvo =
		container_of ( options, struct nvo_block, dhcpopts );
	int rc;

	/* Refuse to reallocate if we have no way to resize the block */
	if ( ! nvo->resize )
		return dhcpopt_no_realloc ( options, len );

	/* Allow one byte for the checksum (if any data is present) */
	if ( len )
		len += 1;

	/* Resize underlying non-volatile options block */
	if ( ( rc = nvo->resize ( nvo, len ) ) != 0 ) {
		DBGC ( nvo, "NVO %p could not resize to %zd bytes: %s\n",
		       nvo, len, strerror ( rc ) );
		return rc;
	}

	/* Reallocate in-memory options block */
	if ( ( rc = nvo_realloc ( nvo, len ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Load non-volatile stored options from non-volatile storage device
 *
 * @v nvo		Non-volatile options block
 * @ret rc		Return status code
 */
static int nvo_load ( struct nvo_block *nvo ) {
	uint8_t *options_data = nvo->dhcpopts.data;
	int rc;

	/* Skip reading zero-length NVO fields */
	if ( nvo->len == 0 ) {
		DBGC ( nvo, "NVO %p is empty; skipping load\n", nvo );
		return 0;
	}

	/* Read data */
	if ( ( rc = nvs_read ( nvo->nvs, nvo->address, nvo->data,
			       nvo->len ) ) != 0 ) {
		DBGC ( nvo, "NVO %p could not read %zd bytes at %#04x: %s\n",
		       nvo, nvo->len, nvo->address, strerror ( rc ) );
		return rc;
	}

	/* If checksum fails, or options data starts with a zero,
	 * assume the whole block is invalid.  This should capture the
	 * case of random initial contents.
	 */
	if ( ( nvo_checksum ( nvo ) != 0 ) || ( options_data[0] == 0 ) ) {
		DBGC ( nvo, "NVO %p has checksum %02x and initial byte %02x; "
		       "assuming empty\n", nvo, nvo_checksum ( nvo ),
		       options_data[0] );
		memset ( nvo->data, 0, nvo->len );
	}

	/* Rescan DHCP option block */
	dhcpopt_update_used_len ( &nvo->dhcpopts );

	DBGC ( nvo, "NVO %p loaded from non-volatile storage\n", nvo );
	return 0;
}

/**
 * Save non-volatile stored options back to non-volatile storage device
 *
 * @v nvo		Non-volatile options block
 * @ret rc		Return status code
 */
static int nvo_save ( struct nvo_block *nvo ) {
	uint8_t *checksum = nvo->data;
	int rc;

	/* Recalculate checksum, if applicable */
	if ( nvo->len > 0 )
		*checksum -= nvo_checksum ( nvo );

	/* Write data */
	if ( ( rc = nvs_write ( nvo->nvs, nvo->address, nvo->data,
				nvo->len ) ) != 0 ) {
		DBGC ( nvo, "NVO %p could not write %zd bytes at %#04x: %s\n",
		       nvo, nvo->len, nvo->address, strerror ( rc ) );
		return rc;
	}

	DBGC ( nvo, "NVO %p saved to non-volatile storage\n", nvo );
	return 0;
}

/**
 * Check applicability of NVO setting
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @ret applies		Setting applies within this settings block
 */
int nvo_applies ( struct settings *settings __unused,
		  const struct setting *setting ) {

	return ( ( setting->scope == NULL ) &&
		 dhcpopt_applies ( setting->tag ) );
}

/**
 * Store value of NVO setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v data		Setting data, or NULL to clear setting
 * @v len		Length of setting data
 * @ret rc		Return status code
 */
static int nvo_store ( struct settings *settings, const struct setting *setting,
		       const void *data, size_t len ) {
	struct nvo_block *nvo =
		container_of ( settings, struct nvo_block, settings );
	int rc;

	/* Update stored options */
	if ( ( rc = dhcpopt_store ( &nvo->dhcpopts, setting->tag,
				    data, len ) ) != 0 ) {
		DBGC ( nvo, "NVO %p could not store %zd bytes: %s\n",
		       nvo, len, strerror ( rc ) );
		return rc;
	}

	/* Save updated options to NVS */
	if ( ( rc = nvo_save ( nvo ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Fetch value of NVO setting
 *
 * @v settings		Settings block
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 *
 * The actual length of the setting will be returned even if
 * the buffer was too small.
 */
static int nvo_fetch ( struct settings *settings, struct setting *setting,
		       void *data, size_t len ) {
	struct nvo_block *nvo =
		container_of ( settings, struct nvo_block, settings );

	return dhcpopt_fetch ( &nvo->dhcpopts, setting->tag, data, len );
}

/** NVO settings operations */
static struct settings_operations nvo_settings_operations = {
	.applies = nvo_applies,
	.store = nvo_store,
	.fetch = nvo_fetch,
};

/**
 * Initialise non-volatile stored options
 *
 * @v nvo		Non-volatile options block
 * @v nvs		Underlying non-volatile storage device
 * @v address		Address within NVS device
 * @v len		Length of non-volatile options data
 * @v resize		Resize method
 * @v refcnt		Containing object reference counter, or NULL
 */
void nvo_init ( struct nvo_block *nvo, struct nvs_device *nvs,
		size_t address, size_t len,
		int ( * resize ) ( struct nvo_block *nvo, size_t len ),
		struct refcnt *refcnt ) {
	nvo->nvs = nvs;
	nvo->address = address;
	nvo->len = len;
	nvo->resize = resize;
	dhcpopt_init ( &nvo->dhcpopts, NULL, 0, nvo_realloc_dhcpopt );
	settings_init ( &nvo->settings, &nvo_settings_operations,
			refcnt, NULL );
}

/**
 * Register non-volatile stored options
 *
 * @v nvo		Non-volatile options block
 * @v parent		Parent settings block, or NULL
 * @ret rc		Return status code
 */
int register_nvo ( struct nvo_block *nvo, struct settings *parent ) {
	int rc;

	/* Allocate memory for options */
	if ( ( rc = nvo_realloc ( nvo, nvo->len ) ) != 0 )
		goto err_realloc;

	/* Read data from NVS */
	if ( ( rc = nvo_load ( nvo ) ) != 0 )
		goto err_load;

	/* Register settings */
	if ( ( rc = register_settings ( &nvo->settings, parent,
					NVO_SETTINGS_NAME ) ) != 0 )
		goto err_register;

	DBGC ( nvo, "NVO %p registered\n", nvo );
	return 0;
	
 err_register:
 err_load:
	nvo_realloc ( nvo, 0 );
 err_realloc:
	return rc;
}

/**
 * Unregister non-volatile stored options
 *
 * @v nvo		Non-volatile options block
 */
void unregister_nvo ( struct nvo_block *nvo ) {
	unregister_settings ( &nvo->settings );
	nvo_realloc ( nvo, 0 );
	DBGC ( nvo, "NVO %p unregistered\n", nvo );
}
