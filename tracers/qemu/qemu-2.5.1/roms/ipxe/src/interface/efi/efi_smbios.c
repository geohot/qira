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
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <errno.h>
#include <ipxe/smbios.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/Guid/SmBios.h>

/** @file
 *
 * iPXE SMBIOS API for EFI
 *
 */

/** SMBIOS configuration table */
static struct smbios_entry *smbios_entry;
EFI_USE_TABLE ( SMBIOS_TABLE, &smbios_entry, 0 );

/**
 * Find SMBIOS
 *
 * @v smbios		SMBIOS entry point descriptor structure to fill in
 * @ret rc		Return status code
 */
static int efi_find_smbios ( struct smbios *smbios ) {

	if ( ! smbios_entry ) {
		DBG ( "No SMBIOS table provided\n" );
		return -ENODEV;
	}

	if ( smbios_entry->signature != SMBIOS_SIGNATURE ) {
		DBG ( "Invalid SMBIOS signature\n" );
		return -ENODEV;
	}

	smbios->address = phys_to_user ( smbios_entry->smbios_address );
	smbios->len = smbios_entry->smbios_len;
	smbios->count = smbios_entry->smbios_count;
	smbios->version =
		SMBIOS_VERSION ( smbios_entry->major, smbios_entry->minor );
	DBG ( "Found SMBIOS v%d.%d entry point at %p (%x+%zx)\n",
	      smbios_entry->major, smbios_entry->minor, smbios_entry,
	      smbios_entry->smbios_address, smbios->len );

	return 0;
}

PROVIDE_SMBIOS ( efi, find_smbios, efi_find_smbios );
