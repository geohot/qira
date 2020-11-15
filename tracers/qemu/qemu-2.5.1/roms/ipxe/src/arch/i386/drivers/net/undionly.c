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
#include <stdio.h>
#include <string.h>
#include <ipxe/device.h>
#include <ipxe/init.h>
#include <ipxe/pci.h>
#include <undi.h>
#include <undinet.h>
#include <undipreload.h>

/** @file
 *
 * "Pure" UNDI driver
 *
 * This is the UNDI driver without explicit support for PCI or any
 * other bus type.  It is capable only of using the preloaded UNDI
 * device.  It must not be combined in an image with any other
 * drivers.
 *
 * If you want a PXE-loadable image that contains only the UNDI
 * driver, build "bin/undionly.kpxe".
 *
 * If you want any other image format, or any other drivers in
 * addition to the UNDI driver, build e.g. "bin/undi.dsk".
 */

/**
 * Probe UNDI root bus
 *
 * @v rootdev		UNDI bus root device
 *
 * Scans the UNDI bus for devices and registers all devices it can
 * find.
 */
static int undibus_probe ( struct root_device *rootdev ) {
	struct undi_device *undi = &preloaded_undi;
	int rc;

	/* Check for a valie preloaded UNDI device */
	if ( ! undi->entry.segment ) {
		DBG ( "No preloaded UNDI device found!\n" );
		return -ENODEV;
	}

	/* Add to device hierarchy */
	undi->dev.driver_name = "undionly";
	if ( undi->pci_busdevfn != UNDI_NO_PCI_BUSDEVFN ) {
		undi->dev.desc.bus_type = BUS_TYPE_PCI;
		undi->dev.desc.location = undi->pci_busdevfn;
		undi->dev.desc.vendor = undi->pci_vendor;
		undi->dev.desc.device = undi->pci_device;
		snprintf ( undi->dev.name, sizeof ( undi->dev.name ),
			   "UNDI-PCI%02x:%02x.%x",
			   PCI_BUS ( undi->pci_busdevfn ),
			   PCI_SLOT ( undi->pci_busdevfn ),
			   PCI_FUNC ( undi->pci_busdevfn ) );
	} else if ( undi->isapnp_csn != UNDI_NO_ISAPNP_CSN ) {
		undi->dev.desc.bus_type = BUS_TYPE_ISAPNP;
		snprintf ( undi->dev.name, sizeof ( undi->dev.name ),
			   "UNDI-ISAPNP" );
	}
	undi->dev.parent = &rootdev->dev;
	list_add ( &undi->dev.siblings, &rootdev->dev.children);
	INIT_LIST_HEAD ( &undi->dev.children );

	/* Create network device */
	if ( ( rc = undinet_probe ( undi ) ) != 0 )
		goto err;

	return 0;

 err:
	list_del ( &undi->dev.siblings );
	return rc;
}

/**
 * Remove UNDI root bus
 *
 * @v rootdev		UNDI bus root device
 */
static void undibus_remove ( struct root_device *rootdev __unused ) {
	struct undi_device *undi = &preloaded_undi;

	undinet_remove ( undi );
	list_del ( &undi->dev.siblings );
}

/** UNDI bus root device driver */
static struct root_driver undi_root_driver = {
	.probe = undibus_probe,
	.remove = undibus_remove,
};

/** UNDI bus root device */
struct root_device undi_root_device __root_device = {
	.dev = { .name = "UNDI" },
	.driver = &undi_root_driver,
};

/**
 * Prepare for exit
 *
 * @v booting		System is shutting down for OS boot
 */
static void undionly_shutdown ( int booting ) {
	/* If we are shutting down to boot an OS, clear the "keep PXE
	 * stack" flag.
	 */
	if ( booting )
		preloaded_undi.flags &= ~UNDI_FL_KEEP_ALL;
}

struct startup_fn startup_undionly __startup_fn ( STARTUP_LATE ) = {
	.shutdown = undionly_shutdown,
};
