/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

#include <stdio.h>
#include <errno.h>
#include <ipxe/pci.h>
#include <ipxe/settings.h>
#include <ipxe/init.h>

/** @file
 *
 * PCI device settings
 *
 */

/** PCI device settings scope */
static const struct settings_scope pci_settings_scope;

/**
 * Check applicability of PCI device setting
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @ret applies		Setting applies within this settings block
 */
static int pci_settings_applies ( struct settings *settings __unused,
				  const struct setting *setting ) {

	return ( setting->scope == &pci_settings_scope );
}

/**
 * Fetch value of PCI device setting
 *
 * @v settings		Settings block
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int pci_settings_fetch ( struct settings *settings __unused,
				struct setting *setting,
				void *data, size_t len ) {
	struct pci_device pci;
	unsigned int tag_busdevfn;
	unsigned int tag_offset;
	unsigned int tag_len;
	unsigned int i;

	/* Extract busdevfn, offset, and length from tag */
	tag_busdevfn = ( ( setting->tag >> 16 ) & 0xffff );
	tag_offset = ( ( setting->tag >> 8 ) & 0xff );
	tag_len = ( ( setting->tag >> 0 ) & 0xff );

	/* Locate PCI device */
	memset ( &pci, 0, sizeof ( pci ) );
	pci_init ( &pci, tag_busdevfn );
	DBG ( PCI_FMT " reading %#02x+%#x\n", PCI_ARGS ( &pci ),
	      tag_offset, tag_len );

	/* Read data one byte at a time, in reverse order (since PCI
	 * is little-endian and iPXE settings are essentially
	 * big-endian).
	 */
	tag_offset += tag_len;
	for ( i = 0 ; ( ( i < tag_len ) && ( i < len ) ); i++ ) {
		pci_read_config_byte ( &pci, --tag_offset, data++ );
	}

	/* Set type to ":hexraw" if not already specified */
	if ( ! setting->type )
		setting->type = &setting_type_hexraw;

	return tag_len;
}

/** PCI device settings operations */
static struct settings_operations pci_settings_operations = {
	.applies = pci_settings_applies,
	.fetch = pci_settings_fetch,
};

/** PCI device settings */
static struct settings pci_settings = {
	.refcnt = NULL,
	.siblings = LIST_HEAD_INIT ( pci_settings.siblings ),
	.children = LIST_HEAD_INIT ( pci_settings.children ),
	.op = &pci_settings_operations,
	.default_scope = &pci_settings_scope,
};

/** Initialise PCI device settings */
static void pci_settings_init ( void ) {
	int rc;

	if ( ( rc = register_settings ( &pci_settings, NULL, "pci" ) ) != 0 ) {
		DBG ( "PCI could not register settings: %s\n",
		      strerror ( rc ) );
		return;
	}
}

/** PCI device settings initialiser */
struct init_fn pci_settings_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = pci_settings_init,
};
