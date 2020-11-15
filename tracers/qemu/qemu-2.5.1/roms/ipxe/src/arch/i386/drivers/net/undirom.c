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
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pxe.h>
#include <realmode.h>
#include <undirom.h>

/** @file
 *
 * UNDI expansion ROMs
 *
 */

/** List of all UNDI ROMs */
static LIST_HEAD ( undiroms );

/**
 * Parse PXE ROM ID structure
 *
 * @v undirom		UNDI ROM
 * @v pxeromid		Offset within ROM to PXE ROM ID structure
 * @ret rc		Return status code
 */
static int undirom_parse_pxeromid ( struct undi_rom *undirom,
				   unsigned int pxeromid ) {
	struct undi_rom_id undi_rom_id;
	unsigned int undiloader;

	DBGC ( undirom, "UNDIROM %p has PXE ROM ID at %04x:%04x\n", undirom,
	       undirom->rom_segment, pxeromid );

	/* Read PXE ROM ID structure and verify */
	copy_from_real ( &undi_rom_id, undirom->rom_segment, pxeromid,
			 sizeof ( undi_rom_id ) );
	if ( undi_rom_id.Signature != UNDI_ROM_ID_SIGNATURE ) {
		DBGC ( undirom, "UNDIROM %p has bad PXE ROM ID signature "
		       "%08x\n", undirom, undi_rom_id.Signature );
		return -EINVAL;
	}

	/* Check for UNDI loader */
	undiloader = undi_rom_id.UNDILoader;
	if ( ! undiloader ) {
		DBGC ( undirom, "UNDIROM %p has no UNDI loader\n", undirom );
		return -EINVAL;
	}

	/* Fill in UNDI ROM loader fields */
	undirom->loader_entry.segment = undirom->rom_segment;
	undirom->loader_entry.offset = undiloader;
	undirom->code_size = undi_rom_id.CodeSize;
	undirom->data_size = undi_rom_id.DataSize;

	DBGC ( undirom, "UNDIROM %p has UNDI loader at %04x:%04x "
	       "(code %04zx data %04zx)\n", undirom,
	       undirom->loader_entry.segment, undirom->loader_entry.offset,
	       undirom->code_size, undirom->data_size );
	return 0;
}

/**
 * Parse PCI expansion header
 *
 * @v undirom		UNDI ROM
 * @v pcirheader	Offset within ROM to PCI expansion header
 */
static int undirom_parse_pcirheader ( struct undi_rom *undirom,
				     unsigned int pcirheader ) {
	struct pcir_header pcir_header;

	DBGC ( undirom, "UNDIROM %p has PCI expansion header at %04x:%04x\n",
	       undirom, undirom->rom_segment, pcirheader );

	/* Read PCI expansion header and verify */
	copy_from_real ( &pcir_header, undirom->rom_segment, pcirheader,
			 sizeof ( pcir_header ) );
	if ( pcir_header.signature != PCIR_SIGNATURE ) {
		DBGC ( undirom, "UNDIROM %p has bad PCI expansion header "
		       "signature %08x\n", undirom, pcir_header.signature );
		return -EINVAL;
	}

	/* Fill in UNDI ROM PCI device fields */
	undirom->bus_type = PCI_NIC;
	undirom->bus_id.pci.vendor_id = pcir_header.vendor_id;
	undirom->bus_id.pci.device_id = pcir_header.device_id;

	DBGC ( undirom, "UNDIROM %p is for PCI devices %04x:%04x\n", undirom,
	       undirom->bus_id.pci.vendor_id, undirom->bus_id.pci.device_id );
	return 0;
	
}

/**
 * Probe UNDI ROM
 *
 * @v rom_segment	ROM segment address
 * @ret rc		Return status code
 */
static int undirom_probe ( unsigned int rom_segment ) {
	struct undi_rom *undirom = NULL;
	struct undi_rom_header romheader;
	size_t rom_len;
	unsigned int pxeromid;
	unsigned int pcirheader;
	int rc;

	/* Read expansion ROM header and verify */
	copy_from_real ( &romheader, rom_segment, 0, sizeof ( romheader ) );
	if ( romheader.Signature != ROM_SIGNATURE ) {
		rc = -EINVAL;
		goto err;
	}
	rom_len = ( romheader.ROMLength * 512 );

	/* Allocate memory for UNDI ROM */
	undirom = zalloc ( sizeof ( *undirom ) );
	if ( ! undirom ) {
		DBG ( "Could not allocate UNDI ROM structure\n" );
		rc = -ENOMEM;
		goto err;
	}
	DBGC ( undirom, "UNDIROM %p trying expansion ROM at %04x:0000 "
	       "(%zdkB)\n", undirom, rom_segment, ( rom_len / 1024 ) );
	undirom->rom_segment = rom_segment;

	/* Check for and parse PXE ROM ID */
	pxeromid = romheader.PXEROMID;
	if ( ! pxeromid ) {
		DBGC ( undirom, "UNDIROM %p has no PXE ROM ID\n", undirom );
		rc = -EINVAL;
		goto err;
	}
	if ( pxeromid > rom_len ) {
		DBGC ( undirom, "UNDIROM %p PXE ROM ID outside ROM\n",
		       undirom );
		rc = -EINVAL;
		goto err;
	}
	if ( ( rc = undirom_parse_pxeromid ( undirom, pxeromid ) ) != 0 )
		goto err;

	/* Parse PCIR header, if present */
	pcirheader = romheader.PCIRHeader;
	if ( pcirheader )
		undirom_parse_pcirheader ( undirom, pcirheader );

	/* Add to UNDI ROM list and return */
	DBGC ( undirom, "UNDIROM %p registered\n", undirom );
	list_add ( &undirom->list, &undiroms );
	return 0;

 err:
	free ( undirom );
	return rc;
}

/**
 * Create UNDI ROMs for all possible expansion ROMs
 *
 * @ret 
 */
static void undirom_probe_all_roms ( void ) {
	static int probed = 0;
	unsigned int rom_segment;

	/* Perform probe only once */
	if ( probed )
		return;

	DBG ( "Scanning for PXE expansion ROMs\n" );

	/* Scan through expansion ROM region at 512 byte intervals */
	for ( rom_segment = 0xc000 ; rom_segment < 0x10000 ;
	      rom_segment += 0x20 ) {
		undirom_probe ( rom_segment );
	}

	probed = 1;
}

/**
 * Find UNDI ROM for PCI device
 *
 * @v vendor_id		PCI vendor ID
 * @v device_id		PCI device ID
 * @v rombase		ROM base address, or 0 for any
 * @ret undirom		UNDI ROM, or NULL
 */
struct undi_rom * undirom_find_pci ( unsigned int vendor_id,
				     unsigned int device_id,
				     unsigned int rombase ) {
	struct undi_rom *undirom;

	undirom_probe_all_roms();

	list_for_each_entry ( undirom, &undiroms, list ) {
		if ( undirom->bus_type != PCI_NIC )
			continue;
		if ( undirom->bus_id.pci.vendor_id != vendor_id )
			continue;
		if ( undirom->bus_id.pci.device_id != device_id )
			continue;
		if ( rombase && ( ( undirom->rom_segment << 4 ) != rombase ) )
			continue;
		DBGC ( undirom, "UNDIROM %p matched PCI %04x:%04x (%08x)\n",
		       undirom, vendor_id, device_id, rombase );
		return undirom;
	}

	DBG ( "No UNDI ROM matched PCI %04x:%04x (%08x)\n",
	      vendor_id, device_id, rombase );
	return NULL;
}
