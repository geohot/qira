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
#include <stdio.h>
#include <string.h>
#include <ipxe/pci.h>
#include <undi.h>
#include <undirom.h>
#include <undiload.h>
#include <undinet.h>
#include <undipreload.h>

/** @file
 *
 * UNDI PCI driver
 *
 */

/**
 * Find UNDI ROM for PCI device
 *
 * @v pci		PCI device
 * @ret undirom		UNDI ROM, or NULL
 *
 * Try to find a driver for this device.  Try an exact match on the
 * ROM address first, then fall back to a vendor/device ID match only
 */
static struct undi_rom * undipci_find_rom ( struct pci_device *pci ) {
	struct undi_rom *undirom;
	unsigned long rombase;
	
	rombase = pci_bar_start ( pci, PCI_ROM_ADDRESS );
	undirom = undirom_find_pci ( pci->vendor, pci->device, rombase );
	if ( ! undirom )
		undirom = undirom_find_pci ( pci->vendor, pci->device, 0 );
	return undirom;
}

/**
 * Probe PCI device
 *
 * @v pci		PCI device
 * @v id		PCI ID
 * @ret rc		Return status code
 */
static int undipci_probe ( struct pci_device *pci ) {
	struct undi_device *undi;
	struct undi_rom *undirom;
	int rc;

	/* Allocate UNDI device structure */
	undi = zalloc ( sizeof ( *undi ) );
	if ( ! undi )
		return -ENOMEM;
	pci_set_drvdata ( pci, undi );

	/* Find/create our pixie */
	if ( preloaded_undi.pci_busdevfn == pci->busdevfn ) {
		/* Claim preloaded UNDI device */
		DBGC ( undi, "UNDI %p using preloaded UNDI device\n", undi );
		memcpy ( undi, &preloaded_undi, sizeof ( *undi ) );
		memset ( &preloaded_undi, 0, sizeof ( preloaded_undi ) );
	} else {
		/* Find UNDI ROM for PCI device */
		if ( ! ( undirom = undipci_find_rom ( pci ) ) ) {
			rc = -ENODEV;
			goto err_find_rom;
		}

		/* Call UNDI ROM loader to create pixie */
		if ( ( rc = undi_load_pci ( undi, undirom,
					    pci->busdevfn ) ) != 0 ) {
			goto err_load_pci;
		}
	}

	/* Add to device hierarchy */
	snprintf ( undi->dev.name, sizeof ( undi->dev.name ),
		   "UNDI-%s", pci->dev.name );
	memcpy ( &undi->dev.desc, &pci->dev.desc, sizeof ( undi->dev.desc ) );
	undi->dev.parent = &pci->dev;
	INIT_LIST_HEAD ( &undi->dev.children );
	list_add ( &undi->dev.siblings, &pci->dev.children );

	/* Create network device */
	if ( ( rc = undinet_probe ( undi ) ) != 0 )
		goto err_undinet_probe;
	
	return 0;

 err_undinet_probe:
	undi_unload ( undi );
	list_del ( &undi->dev.siblings );
 err_find_rom:
 err_load_pci:
	free ( undi );
	pci_set_drvdata ( pci, NULL );
	return rc;
}

/**
 * Remove PCI device
 *
 * @v pci	PCI device
 */
static void undipci_remove ( struct pci_device *pci ) {
	struct undi_device *undi = pci_get_drvdata ( pci );

	undinet_remove ( undi );
	undi_unload ( undi );
	list_del ( &undi->dev.siblings );
	free ( undi );
	pci_set_drvdata ( pci, NULL );
}

static struct pci_device_id undipci_nics[] = {
	PCI_ROM ( 0xffff, 0xffff, "undipci", "UNDI (PCI)", 0 ),
};

struct pci_driver undipci_driver __pci_driver_fallback = {
	.ids = undipci_nics,
	.id_count = ( sizeof ( undipci_nics ) / sizeof ( undipci_nics[0] ) ),
	.class = PCI_CLASS_ID ( PCI_CLASS_NETWORK, PCI_ANY_ID, PCI_ANY_ID ),
	.probe = undipci_probe,
	.remove = undipci_remove,
};
