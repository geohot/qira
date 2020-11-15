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
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <errno.h>
#include <linux_api.h>
#include <ipxe/linux.h>
#include <ipxe/smbios.h>

/** SMBIOS filename */
static const char smbios_filename[] = "/dev/mem";

/** SMBIOS entry point scan region start address */
#define SMBIOS_ENTRY_START 0xf0000

/** SMBIOS entry point scan region length */
#define SMBIOS_ENTRY_LEN 0x10000

/** SMBIOS mapping alignment */
#define SMBIOS_ALIGN 0x1000

/**
 * Find SMBIOS
 *
 * @v smbios		SMBIOS entry point descriptor structure to fill in
 * @ret rc		Return status code
 */
static int linux_find_smbios ( struct smbios *smbios ) {
	struct smbios_entry entry;
	void *entry_mem;
	void *smbios_mem;
	size_t smbios_offset;
	size_t smbios_indent;
	size_t smbios_len;
	int fd;
	int rc;

	/* Open SMBIOS file */
	fd = linux_open ( smbios_filename, O_RDONLY );
	if ( fd < 0 ) {
		rc = -ELINUX ( linux_errno );
		DBGC ( smbios, "SMBIOS could not open %s: %s\n",
		       smbios_filename, linux_strerror ( linux_errno ) );
		goto err_open;
	}

	/* Map the region potentially containing the SMBIOS entry point */
	entry_mem = linux_mmap ( NULL, SMBIOS_ENTRY_LEN, PROT_READ, MAP_SHARED,
				 fd, SMBIOS_ENTRY_START );
	if ( entry_mem == MAP_FAILED ) {
		rc = -ELINUX ( linux_errno );
		DBGC ( smbios, "SMBIOS could not mmap %s (%#x+%#x): %s\n",
		       smbios_filename, SMBIOS_ENTRY_START, SMBIOS_ENTRY_LEN,
		       linux_strerror ( linux_errno ) );
		goto err_mmap_entry;
	}

	/* Scan for the SMBIOS entry point */
	if ( ( rc = find_smbios_entry ( virt_to_user ( entry_mem ),
					SMBIOS_ENTRY_LEN, &entry ) ) != 0 )
		goto err_find_entry;

	/* Map the region containing the SMBIOS structures */
	smbios_indent = ( entry.smbios_address & ( SMBIOS_ALIGN - 1 ) );
	smbios_offset = ( entry.smbios_address - smbios_indent );
	smbios_len = ( entry.smbios_len + smbios_indent );
	smbios_mem = linux_mmap ( NULL, smbios_len, PROT_READ, MAP_SHARED,
				  fd, smbios_offset );
	if ( smbios_mem == MAP_FAILED ) {
		rc = -ELINUX ( linux_errno );
		DBGC ( smbios, "SMBIOS could not mmap %s (%#zx+%#zx): %s\n",
		       smbios_filename, smbios_offset, smbios_len,
		       linux_strerror ( linux_errno ) );
		goto err_mmap_smbios;
	}

	/* Fill in entry point descriptor structure */
	smbios->address = virt_to_user ( smbios_mem + smbios_indent );
	smbios->len = entry.smbios_len;
	smbios->count = entry.smbios_count;
	smbios->version = SMBIOS_VERSION ( entry.major, entry.minor );

	/* Unmap the entry point region (no longer required) */
	linux_munmap ( entry_mem, SMBIOS_ENTRY_LEN );

	return 0;

	linux_munmap ( smbios_mem, smbios_len );
 err_mmap_smbios:
 err_find_entry:
	linux_munmap ( entry_mem, SMBIOS_ENTRY_LEN );
 err_mmap_entry:
	linux_close ( fd );
 err_open:
	return rc;
}

PROVIDE_SMBIOS ( linux, find_smbios, linux_find_smbios );
