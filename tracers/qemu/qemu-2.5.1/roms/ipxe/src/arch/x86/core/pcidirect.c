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

#include <ipxe/io.h>
#include <ipxe/pci.h>

/** @file
 *
 * PCI configuration space access via Type 1 accesses
 *
 */

/**
 * Prepare for Type 1 PCI configuration space access
 *
 * @v pci		PCI device
 * @v where	Location within PCI configuration space
 */
void pcidirect_prepare ( struct pci_device *pci, int where ) {
	outl ( ( 0x80000000 | ( pci->busdevfn << 8 ) | ( where & ~3 ) ),
	       PCIDIRECT_CONFIG_ADDRESS );
}

PROVIDE_PCIAPI_INLINE ( direct, pci_num_bus );
PROVIDE_PCIAPI_INLINE ( direct, pci_read_config_byte );
PROVIDE_PCIAPI_INLINE ( direct, pci_read_config_word );
PROVIDE_PCIAPI_INLINE ( direct, pci_read_config_dword );
PROVIDE_PCIAPI_INLINE ( direct, pci_write_config_byte );
PROVIDE_PCIAPI_INLINE ( direct, pci_write_config_word );
PROVIDE_PCIAPI_INLINE ( direct, pci_write_config_dword );
