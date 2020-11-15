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
#include <stdlib.h>
#include <string.h>
#include <pxe.h>
#include <realmode.h>
#include <bios.h>
#include <pnpbios.h>
#include <basemem.h>
#include <ipxe/pci.h>
#include <undi.h>
#include <undirom.h>
#include <undiload.h>

/** @file
 *
 * UNDI load/unload
 *
 */

/* Disambiguate the various error causes */
#define EINFO_EUNDILOAD							\
	__einfo_uniqify ( EINFO_EPLATFORM, 0x01,			\
			  "UNDI loader error" )
#define EUNDILOAD( status ) EPLATFORM ( EINFO_EUNDILOAD, status )

/** Parameter block for calling UNDI loader */
static struct s_UNDI_LOADER __bss16 ( undi_loader );
#define undi_loader __use_data16 ( undi_loader )

/** UNDI loader entry point */
static SEGOFF16_t __bss16 ( undi_loader_entry );
#define undi_loader_entry __use_data16 ( undi_loader_entry )

/**
 * Call UNDI loader to create a pixie
 *
 * @v undi		UNDI device
 * @v undirom		UNDI ROM
 * @ret rc		Return status code
 */
int undi_load ( struct undi_device *undi, struct undi_rom *undirom ) {
	struct s_PXE ppxe;
	unsigned int fbms_seg;
	uint16_t exit;
	int rc;

	/* Only one UNDI instance may be loaded at any given time */
	if ( undi_loader_entry.segment ) {
		DBG ( "UNDI %p cannot load multiple instances\n", undi );
		return -EBUSY;
	}

	/* Set up START_UNDI parameters */
	memset ( &undi_loader, 0, sizeof ( undi_loader ) );
	undi_loader.AX = undi->pci_busdevfn;
	undi_loader.BX = undi->isapnp_csn;
	undi_loader.DX = undi->isapnp_read_port;
	undi_loader.ES = BIOS_SEG;
	undi_loader.DI = find_pnp_bios();

	/* Allocate base memory for PXE stack */
	undi->restore_fbms = get_fbms();
	fbms_seg = ( undi->restore_fbms << 6 );
	fbms_seg -= ( ( undirom->code_size + 0x0f ) >> 4 );
	undi_loader.UNDI_CS = fbms_seg;
	fbms_seg -= ( ( undirom->data_size + 0x0f ) >> 4 );
	undi_loader.UNDI_DS = fbms_seg;

	/* Debug info */
	DBGC ( undi, "UNDI %p loading UNDI ROM %p to CS %04x DS %04x for ",
	       undi, undirom, undi_loader.UNDI_CS, undi_loader.UNDI_DS );
	if ( undi->pci_busdevfn != UNDI_NO_PCI_BUSDEVFN ) {
		unsigned int bus = ( undi->pci_busdevfn >> 8 );
		unsigned int devfn = ( undi->pci_busdevfn & 0xff );
		DBGC ( undi, "PCI %02x:%02x.%x\n",
		       bus, PCI_SLOT ( devfn ), PCI_FUNC ( devfn ) );
	}
	if ( undi->isapnp_csn != UNDI_NO_ISAPNP_CSN ) {
		DBGC ( undi, "ISAPnP(%04x) CSN %04x\n",
		       undi->isapnp_read_port, undi->isapnp_csn );
	}

	/* Call loader */
	undi_loader_entry = undirom->loader_entry;
	__asm__ __volatile__ ( REAL_CODE ( "pushl %%ebp\n\t" /* gcc bug */
					   "pushw %%ds\n\t"
					   "pushw %%ax\n\t"
					   "lcall *undi_loader_entry\n\t"
					   "popl %%ebp\n\t" /* discard */
					   "popl %%ebp\n\t" /* gcc bug */ )
			       : "=a" ( exit )
			       : "a" ( __from_data16 ( &undi_loader ) )
			       : "ebx", "ecx", "edx", "esi", "edi" );

	if ( exit != PXENV_EXIT_SUCCESS ) {
		/* Clear entry point */
		memset ( &undi_loader_entry, 0, sizeof ( undi_loader_entry ) );

		rc = -EUNDILOAD ( undi_loader.Status );
		DBGC ( undi, "UNDI %p loader failed: %s\n",
		       undi, strerror ( rc ) );
		return rc;
	}

	/* Populate PXE device structure */
	undi->pxenv = undi_loader.PXENVptr;
	undi->ppxe = undi_loader.PXEptr;
	copy_from_real ( &ppxe, undi->ppxe.segment, undi->ppxe.offset,
			 sizeof ( ppxe ) );
	undi->entry = ppxe.EntryPointSP;
	DBGC ( undi, "UNDI %p loaded PXENV+ %04x:%04x !PXE %04x:%04x "
	       "entry %04x:%04x\n", undi, undi->pxenv.segment,
	       undi->pxenv.offset, undi->ppxe.segment, undi->ppxe.offset,
	       undi->entry.segment, undi->entry.offset );

	/* Update free base memory counter */
	undi->fbms = ( fbms_seg >> 6 );
	set_fbms ( undi->fbms );
	DBGC ( undi, "UNDI %p using [%d,%d) kB of base memory\n",
	       undi, undi->fbms, undi->restore_fbms );

	return 0;
}

/**
 * Unload a pixie
 *
 * @v undi		UNDI device
 * @ret rc		Return status code
 *
 * Erases the PXENV+ and !PXE signatures, and frees the used base
 * memory (if possible).
 */
int undi_unload ( struct undi_device *undi ) {
	static uint32_t dead = 0xdeaddead;

	DBGC ( undi, "UNDI %p unloading\n", undi );

	/* Clear entry point */
	memset ( &undi_loader_entry, 0, sizeof ( undi_loader_entry ) );

	/* Erase signatures */
	if ( undi->pxenv.segment )
		put_real ( dead, undi->pxenv.segment, undi->pxenv.offset );
	if ( undi->ppxe.segment )
		put_real ( dead, undi->ppxe.segment, undi->ppxe.offset );

	/* Free base memory, if possible */
	if ( undi->fbms == get_fbms() ) {
		DBGC ( undi, "UNDI %p freeing [%d,%d) kB of base memory\n",
		       undi, undi->fbms, undi->restore_fbms );
		set_fbms ( undi->restore_fbms );
		return 0;
	} else {
		DBGC ( undi, "UNDI %p leaking [%d,%d) kB of base memory\n",
		       undi, undi->fbms, undi->restore_fbms );
		return -EBUSY;
	}
}
