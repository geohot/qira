/*
 * Copyright (C) 2011 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <stdio.h>
#include <string.h>
#include <ipxe/uaccess.h>
#include <ipxe/init.h>
#include <ipxe/pci.h>
#include <ipxe/ethernet.h>
#include <ipxe/bofm.h>

/** @file
 *
 * IBM BladeCenter Open Fabric Manager (BOFM) tests
 *
 */

/** Harvest test table */
static struct {
	struct bofm_global_header header;
	struct bofm_section_header en_header;
	struct bofm_en en;
	struct bofm_section_header done;
} __attribute__ (( packed )) bofmtab_harvest = {
	.header = {
		.magic = BOFM_IOAA_MAGIC,
		.action = BOFM_ACTION_HVST,
		.version = 0x01,
		.level = 0x01,
		.length = sizeof ( bofmtab_harvest ),
		.profile = "Harvest test profile",
	},
	.en_header = {
		.magic = BOFM_EN_MAGIC,
		.length = sizeof ( bofmtab_harvest.en ),
	},
	.en = {
		.options = ( BOFM_EN_MAP_PFA | BOFM_EN_USAGE_HARVEST |
			     BOFM_EN_RQ_HVST_ACTIVE ),
		.mport = 1,
	},
	.done = {
		.magic = BOFM_DONE_MAGIC,
	},
};

/** Update test table */
static struct {
	struct bofm_global_header header;
	struct bofm_section_header en_header;
	struct bofm_en en;
	struct bofm_section_header done;
} __attribute__ (( packed )) bofmtab_update = {
	.header = {
		.magic = BOFM_IOAA_MAGIC,
		.action = BOFM_ACTION_UPDT,
		.version = 0x01,
		.level = 0x01,
		.length = sizeof ( bofmtab_update ),
		.profile = "Update test profile",
	},
	.en_header = {
		.magic = BOFM_EN_MAGIC,
		.length = sizeof ( bofmtab_update.en ),
	},
	.en = {
		.options = ( BOFM_EN_MAP_PFA | BOFM_EN_EN_A |
			     BOFM_EN_USAGE_ENTRY ),
		.mport = 1,
		.mac_a = { 0x02, 0x00, 0x69, 0x50, 0x58, 0x45 },
	},
	.done = {
		.magic = BOFM_DONE_MAGIC,
	},
};

/**
 * Perform BOFM test
 *
 * @v pci		PCI device
 */
void bofm_test ( struct pci_device *pci ) {
	int bofmrc;

	printf ( "BOFMTEST using " PCI_FMT "\n", PCI_ARGS ( pci ) );

	/* Perform harvest test */
	printf ( "BOFMTEST performing harvest\n" );
	bofmtab_harvest.en.busdevfn = pci->busdevfn;
	DBG_HDA ( 0, &bofmtab_harvest, sizeof ( bofmtab_harvest ) );
	bofmrc = bofm ( virt_to_user ( &bofmtab_harvest ), pci );
	printf ( "BOFMTEST harvest result %08x\n", bofmrc );
	if ( bofmtab_harvest.en.options & BOFM_EN_HVST ) {
		printf ( "BOFMTEST harvested MAC address %s\n",
			 eth_ntoa ( &bofmtab_harvest.en.mac_a ) );
	} else {
		printf ( "BOFMTEST failed to harvest a MAC address\n" );
	}
	DBG_HDA ( 0, &bofmtab_harvest, sizeof ( bofmtab_harvest ) );

	/* Perform update test */
	printf ( "BOFMTEST performing update\n" );
	bofmtab_update.en.busdevfn = pci->busdevfn;
	DBG_HDA ( 0, &bofmtab_update, sizeof ( bofmtab_update ) );
	bofmrc = bofm ( virt_to_user ( &bofmtab_update ), pci );
	printf ( "BOFMTEST update result %08x\n", bofmrc );
	if ( bofmtab_update.en.options & BOFM_EN_CSM_SUCCESS ) {
		printf ( "BOFMTEST updated MAC address to %s\n",
			 eth_ntoa ( &bofmtab_update.en.mac_a ) );
	} else {
		printf ( "BOFMTEST failed to update MAC address\n" );
	}
	DBG_HDA ( 0, &bofmtab_update, sizeof ( bofmtab_update ) );
}

/**
 * Perform BOFM test at initialisation time
 *
 */
static void bofm_test_init ( void ) {
	struct pci_device pci;
	int busdevfn = -1;
	int rc;

	/* Uncomment the following line and specify the correct PCI
	 * bus:dev.fn address in order to perform a BOFM test at
	 * initialisation time.
	 */
	// busdevfn = PCI_BUSDEVFN ( <bus>, <dev>, <fn> );

	/* Skip test if no PCI bus:dev.fn is defined */
	if ( busdevfn < 0 )
		return;

	/* Initialise PCI device */
	memset ( &pci, 0, sizeof ( pci ) );
	pci_init ( &pci, busdevfn );
	if ( ( rc = pci_read_config ( &pci ) ) != 0 ) {
		printf ( "BOFMTEST could not create " PCI_FMT " device: %s\n",
			 PCI_ARGS ( &pci ), strerror ( rc ) );
		return;
	}

	/* Perform test */
	bofm_test ( &pci );
}

/** BOFM test initialisation function */
struct init_fn bofm_test_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = bofm_test_init,
};
