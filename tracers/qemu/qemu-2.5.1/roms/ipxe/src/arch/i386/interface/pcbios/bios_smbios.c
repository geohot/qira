/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <assert.h>
#include <ipxe/uaccess.h>
#include <ipxe/smbios.h>
#include <realmode.h>
#include <pnpbios.h>

/** @file
 *
 * System Management BIOS
 *
 */

/**
 * Find SMBIOS
 *
 * @v smbios		SMBIOS entry point descriptor structure to fill in
 * @ret rc		Return status code
 */
static int bios_find_smbios ( struct smbios *smbios ) {
	struct smbios_entry entry;
	int rc;

	/* Scan through BIOS segment to find SMBIOS entry point */
	if ( ( rc = find_smbios_entry ( real_to_user ( BIOS_SEG, 0 ), 0x10000,
					&entry ) ) != 0 )
		return rc;

	/* Fill in entry point descriptor structure */
	smbios->address = phys_to_user ( entry.smbios_address );
	smbios->len = entry.smbios_len;
	smbios->count = entry.smbios_count;
	smbios->version = SMBIOS_VERSION ( entry.major, entry.minor );

	return 0;
}

PROVIDE_SMBIOS ( pcbios, find_smbios, bios_find_smbios );
