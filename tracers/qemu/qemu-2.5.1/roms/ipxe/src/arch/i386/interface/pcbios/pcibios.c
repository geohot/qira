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
#include <ipxe/pci.h>
#include <realmode.h>

/** @file
 *
 * PCI configuration space access via PCI BIOS
 *
 */

/**
 * Determine number of PCI buses within system
 *
 * @ret num_bus		Number of buses
 */
static int pcibios_num_bus ( void ) {
	int discard_a, discard_D;
	uint8_t max_bus;

	/* We issue this call using flat real mode, to work around a
	 * bug in some HP BIOSes.
	 */
	__asm__ __volatile__ ( REAL_CODE ( "call flatten_real_mode\n\t"
					   "stc\n\t"
					   "int $0x1a\n\t"
					   "jnc 1f\n\t"
					   "xorw %%cx, %%cx\n\t"
					   "\n1:\n\t" )
			       : "=c" ( max_bus ), "=a" ( discard_a ),
				 "=D" ( discard_D )
			       : "a" ( PCIBIOS_INSTALLATION_CHECK >> 16 ),
				 "D" ( 0 )
			       : "ebx", "edx" );

	return ( max_bus + 1 );
}

/**
 * Read configuration space via PCI BIOS
 *
 * @v pci	PCI device
 * @v command	PCI BIOS command
 * @v value	Value read
 * @ret rc	Return status code
 */
int pcibios_read ( struct pci_device *pci, uint32_t command, uint32_t *value ){
	int discard_b, discard_D;
	int status;

	__asm__ __volatile__ ( REAL_CODE ( "stc\n\t"
					   "int $0x1a\n\t"
					   "jnc 1f\n\t"
					   "xorl %%eax, %%eax\n\t"
					   "decl %%eax\n\t"
					   "movl %%eax, %%ecx\n\t"
					   "\n1:\n\t" )
			       : "=a" ( status ), "=b" ( discard_b ),
				 "=c" ( *value ), "=D" ( discard_D )
			       : "a" ( command >> 16 ), "D" ( command ),
				 "b" ( pci->busdevfn )
			       : "edx" );

	return ( ( status >> 8 ) & 0xff );
}

/**
 * Write configuration space via PCI BIOS
 *
 * @v pci	PCI device
 * @v command	PCI BIOS command
 * @v value	Value to be written
 * @ret rc	Return status code
 */
int pcibios_write ( struct pci_device *pci, uint32_t command, uint32_t value ){
	int discard_b, discard_c, discard_D;
	int status;

	__asm__ __volatile__ ( REAL_CODE ( "stc\n\t"
					   "int $0x1a\n\t"
					   "jnc 1f\n\t"
					   "movb $0xff, %%ah\n\t"
					   "\n1:\n\t" )
			       : "=a" ( status ), "=b" ( discard_b ),
				 "=c" ( discard_c ), "=D" ( discard_D )
			       : "a" ( command >> 16 ),	"D" ( command ),
			         "b" ( pci->busdevfn ), "c" ( value )
			       : "edx" );
	
	return ( ( status >> 8 ) & 0xff );
}

PROVIDE_PCIAPI ( pcbios, pci_num_bus, pcibios_num_bus );
PROVIDE_PCIAPI_INLINE ( pcbios, pci_read_config_byte );
PROVIDE_PCIAPI_INLINE ( pcbios, pci_read_config_word );
PROVIDE_PCIAPI_INLINE ( pcbios, pci_read_config_dword );
PROVIDE_PCIAPI_INLINE ( pcbios, pci_write_config_byte );
PROVIDE_PCIAPI_INLINE ( pcbios, pci_write_config_word );
PROVIDE_PCIAPI_INLINE ( pcbios, pci_write_config_dword );
