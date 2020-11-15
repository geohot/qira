/*
 * Copyright (C) 2009 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <ipxe/pci.h>
#include <ipxe/pcibackup.h>

/** @file
 *
 * PCI configuration space backup and restoration
 *
 */

/**
 * Check PCI configuration space offset against exclusion list
 *
 * @v pci		PCI device
 * @v offset		Offset within PCI configuration space
 * @v exclude		PCI configuration space backup exclusion list, or NULL
 */
static int
pci_backup_excluded ( struct pci_device *pci, unsigned int offset,
		      const uint8_t *exclude ) {

	if ( ! exclude )
		return 0;
	for ( ; *exclude != PCI_CONFIG_BACKUP_EXCLUDE_END ; exclude++ ) {
		if ( offset == *exclude ) {
			DBGC ( pci, "PCI %p skipping configuration offset "
			       "%02x\n", pci, offset );
			return 1;
		}
	}
	return 0;
}

/**
 * Back up PCI configuration space
 *
 * @v pci		PCI device
 * @v backup		PCI configuration space backup
 * @v exclude		PCI configuration space backup exclusion list, or NULL
 */
void pci_backup ( struct pci_device *pci, struct pci_config_backup *backup,
		  const uint8_t *exclude ) {
	unsigned int offset;
	uint32_t *dword;

	for ( offset = 0, dword = backup->dwords ; offset < 0x100 ;
	      offset += sizeof ( *dword ) , dword++ ) {
		if ( ! pci_backup_excluded ( pci, offset, exclude ) )
			pci_read_config_dword ( pci, offset, dword );
	}
}

/**
 * Restore PCI configuration space
 *
 * @v pci		PCI device
 * @v backup		PCI configuration space backup
 * @v exclude		PCI configuration space backup exclusion list, or NULL
 */
void pci_restore ( struct pci_device *pci, struct pci_config_backup *backup,
		   const uint8_t *exclude ) {
	unsigned int offset;
	uint32_t *dword;

	for ( offset = 0, dword = backup->dwords ; offset < 0x100 ;
	      offset += sizeof ( *dword ) , dword++ ) {
		if ( ! pci_backup_excluded ( pci, offset, exclude ) )
			pci_write_config_dword ( pci, offset, *dword );
	}
}
