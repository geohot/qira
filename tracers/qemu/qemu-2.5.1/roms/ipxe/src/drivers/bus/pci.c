/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * Based in part on pci.c from Etherboot 5.4, by Ken Yap and David
 * Munro, in turn based on the Linux kernel's PCI implementation.
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
#include <errno.h>
#include <ipxe/tables.h>
#include <ipxe/device.h>
#include <ipxe/pci.h>

/** @file
 *
 * PCI bus
 *
 */

static void pcibus_remove ( struct root_device *rootdev );

/**
 * Read PCI BAR
 *
 * @v pci		PCI device
 * @v reg		PCI register number
 * @ret bar		Base address register
 *
 * Reads the specified PCI base address register, including the flags
 * portion.  64-bit BARs will be handled automatically.  If the value
 * of the 64-bit BAR exceeds the size of an unsigned long (i.e. if the
 * high dword is non-zero on a 32-bit platform), then the value
 * returned will be zero plus the flags for a 64-bit BAR.  Unreachable
 * 64-bit BARs are therefore returned as uninitialised 64-bit BARs.
 */
static unsigned long pci_bar ( struct pci_device *pci, unsigned int reg ) {
	uint32_t low;
	uint32_t high;

	pci_read_config_dword ( pci, reg, &low );
	if ( ( low & (PCI_BASE_ADDRESS_SPACE_IO|PCI_BASE_ADDRESS_MEM_TYPE_MASK))
	     == PCI_BASE_ADDRESS_MEM_TYPE_64 ) {
		pci_read_config_dword ( pci, reg + 4, &high );
		if ( high ) {
			if ( sizeof ( unsigned long ) > sizeof ( uint32_t ) ) {
				return ( ( ( uint64_t ) high << 32 ) | low );
			} else {
				DBGC ( pci, PCI_FMT " unhandled 64-bit BAR "
				       "%08x%08x\n",
				       PCI_ARGS ( pci ), high, low );
				return PCI_BASE_ADDRESS_MEM_TYPE_64;
			}
		}
	}
	return low;
}

/**
 * Find the start of a PCI BAR
 *
 * @v pci		PCI device
 * @v reg		PCI register number
 * @ret start		BAR start address
 *
 * Reads the specified PCI base address register, and returns the
 * address portion of the BAR (i.e. without the flags).
 *
 * If the address exceeds the size of an unsigned long (i.e. if a
 * 64-bit BAR has a non-zero high dword on a 32-bit machine), the
 * return value will be zero.
 */
unsigned long pci_bar_start ( struct pci_device *pci, unsigned int reg ) {
	unsigned long bar;

	bar = pci_bar ( pci, reg );
	if ( bar & PCI_BASE_ADDRESS_SPACE_IO ) {
		return ( bar & ~PCI_BASE_ADDRESS_IO_MASK );
	} else {
		return ( bar & ~PCI_BASE_ADDRESS_MEM_MASK );
	}
}

/**
 * Read membase and ioaddr for a PCI device
 *
 * @v pci		PCI device
 *
 * This scans through all PCI BARs on the specified device.  The first
 * valid memory BAR is recorded as pci_device::membase, and the first
 * valid IO BAR is recorded as pci_device::ioaddr.
 *
 * 64-bit BARs are handled automatically.  On a 32-bit platform, if a
 * 64-bit BAR has a non-zero high dword, it will be regarded as
 * invalid.
 */
static void pci_read_bases ( struct pci_device *pci ) {
	unsigned long bar;
	int reg;

	for ( reg = PCI_BASE_ADDRESS_0; reg <= PCI_BASE_ADDRESS_5; reg += 4 ) {
		bar = pci_bar ( pci, reg );
		if ( bar & PCI_BASE_ADDRESS_SPACE_IO ) {
			if ( ! pci->ioaddr )
				pci->ioaddr = 
					( bar & ~PCI_BASE_ADDRESS_IO_MASK );
		} else {
			if ( ! pci->membase )
				pci->membase =
					( bar & ~PCI_BASE_ADDRESS_MEM_MASK );
			/* Skip next BAR if 64-bit */
			if ( bar & PCI_BASE_ADDRESS_MEM_TYPE_64 )
				reg += 4;
		}
	}
}

/**
 * Enable PCI device
 *
 * @v pci		PCI device
 *
 * Set device to be a busmaster in case BIOS neglected to do so.  Also
 * adjust PCI latency timer to a reasonable value, 32.
 */
void adjust_pci_device ( struct pci_device *pci ) {
	unsigned short new_command, pci_command;
	unsigned char pci_latency;

	pci_read_config_word ( pci, PCI_COMMAND, &pci_command );
	new_command = ( pci_command | PCI_COMMAND_MASTER |
			PCI_COMMAND_MEM | PCI_COMMAND_IO );
	if ( pci_command != new_command ) {
		DBGC ( pci, PCI_FMT " device not enabled by BIOS! Updating "
		       "PCI command %04x->%04x\n",
		       PCI_ARGS ( pci ), pci_command, new_command );
		pci_write_config_word ( pci, PCI_COMMAND, new_command );
	}

	pci_read_config_byte ( pci, PCI_LATENCY_TIMER, &pci_latency);
	if ( pci_latency < 32 ) {
		DBGC ( pci, PCI_FMT " latency timer is unreasonably low at "
		       "%d. Setting to 32.\n", PCI_ARGS ( pci ), pci_latency );
		pci_write_config_byte ( pci, PCI_LATENCY_TIMER, 32);
	}
}

/**
 * Read PCI device configuration
 *
 * @v pci		PCI device
 * @ret rc		Return status code
 */
int pci_read_config ( struct pci_device *pci ) {
	uint16_t busdevfn;
	uint8_t hdrtype;
	uint32_t tmp;

	/* Ignore all but the first function on non-multifunction devices */
	if ( PCI_FUNC ( pci->busdevfn ) != 0 ) {
		busdevfn = pci->busdevfn;
		pci->busdevfn = PCI_FIRST_FUNC ( pci->busdevfn );
		pci_read_config_byte ( pci, PCI_HEADER_TYPE, &hdrtype );
		pci->busdevfn = busdevfn;
		if ( ! ( hdrtype & PCI_HEADER_TYPE_MULTI ) )
			return -ENODEV;
	}

	/* Check for physical device presence */
	pci_read_config_dword ( pci, PCI_VENDOR_ID, &tmp );
	if ( ( tmp == 0xffffffff ) || ( tmp == 0 ) )
		return -ENODEV;

	/* Populate struct pci_device */
	pci->vendor = ( tmp & 0xffff );
	pci->device = ( tmp >> 16 );
	pci_read_config_dword ( pci, PCI_REVISION, &tmp );
	pci->class = ( tmp >> 8 );
	pci_read_config_byte ( pci, PCI_INTERRUPT_LINE, &pci->irq );
	pci_read_bases ( pci );

	/* Initialise generic device component */
	snprintf ( pci->dev.name, sizeof ( pci->dev.name ),
		   "PCI%02x:%02x.%x", PCI_BUS ( pci->busdevfn ),
		   PCI_SLOT ( pci->busdevfn ), PCI_FUNC ( pci->busdevfn ) );
	pci->dev.desc.bus_type = BUS_TYPE_PCI;
	pci->dev.desc.location = pci->busdevfn;
	pci->dev.desc.vendor = pci->vendor;
	pci->dev.desc.device = pci->device;
	pci->dev.desc.class = pci->class;
	pci->dev.desc.ioaddr = pci->ioaddr;
	pci->dev.desc.irq = pci->irq;
	INIT_LIST_HEAD ( &pci->dev.siblings );
	INIT_LIST_HEAD ( &pci->dev.children );

	return 0;
}

/**
 * Find next device on PCI bus
 *
 * @v pci		PCI device to fill in
 * @v busdevfn		Starting bus:dev.fn address
 * @ret busdevfn	Bus:dev.fn address of next PCI device, or negative error
 */
int pci_find_next ( struct pci_device *pci, unsigned int busdevfn ) {
	static unsigned int end;
	int rc;

	/* Determine number of PCI buses */
	if ( ! end )
		end = PCI_BUSDEVFN ( pci_num_bus(), 0, 0 );

	/* Find next PCI device, if any */
	for ( ; busdevfn < end ; busdevfn++ ) {
		memset ( pci, 0, sizeof ( *pci ) );
		pci_init ( pci, busdevfn );
		if ( ( rc = pci_read_config ( pci ) ) == 0 )
			return busdevfn;
	}

	return -ENODEV;
}

/**
 * Find driver for PCI device
 *
 * @v pci		PCI device
 * @ret rc		Return status code
 */
int pci_find_driver ( struct pci_device *pci ) {
	struct pci_driver *driver;
	struct pci_device_id *id;
	unsigned int i;

	for_each_table_entry ( driver, PCI_DRIVERS ) {
		if ( ( driver->class.class ^ pci->class ) & driver->class.mask )
			continue;
		for ( i = 0 ; i < driver->id_count ; i++ ) {
			id = &driver->ids[i];
			if ( ( id->vendor != PCI_ANY_ID ) &&
			     ( id->vendor != pci->vendor ) )
				continue;
			if ( ( id->device != PCI_ANY_ID ) &&
			     ( id->device != pci->device ) )
				continue;
			pci_set_driver ( pci, driver, id );
			return 0;
		}
	}
	return -ENOENT;
}

/**
 * Probe a PCI device
 *
 * @v pci		PCI device
 * @ret rc		Return status code
 *
 * Searches for a driver for the PCI device.  If a driver is found,
 * its probe() routine is called.
 */
int pci_probe ( struct pci_device *pci ) {
	int rc;

	DBGC ( pci, PCI_FMT " (%04x:%04x) has driver \"%s\"\n",
	       PCI_ARGS ( pci ), pci->vendor, pci->device, pci->id->name );
	DBGC ( pci, PCI_FMT " has mem %lx io %lx irq %d\n",
	       PCI_ARGS ( pci ), pci->membase, pci->ioaddr, pci->irq );

	if ( ( rc = pci->driver->probe ( pci ) ) != 0 ) {
		DBGC ( pci, PCI_FMT " probe failed: %s\n",
		       PCI_ARGS ( pci ), strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Remove a PCI device
 *
 * @v pci		PCI device
 */
void pci_remove ( struct pci_device *pci ) {
	pci->driver->remove ( pci );
	DBGC ( pci, PCI_FMT " removed\n", PCI_ARGS ( pci ) );
}

/**
 * Probe PCI root bus
 *
 * @v rootdev		PCI bus root device
 *
 * Scans the PCI bus for devices and registers all devices it can
 * find.
 */
static int pcibus_probe ( struct root_device *rootdev ) {
	struct pci_device *pci = NULL;
	int busdevfn = 0;
	int rc;

	for ( busdevfn = 0 ; 1 ; busdevfn++ ) {

		/* Allocate struct pci_device */
		if ( ! pci )
			pci = malloc ( sizeof ( *pci ) );
		if ( ! pci ) {
			rc = -ENOMEM;
			goto err;
		}

		/* Find next PCI device, if any */
		busdevfn = pci_find_next ( pci, busdevfn );
		if ( busdevfn < 0 )
			break;

		/* Look for a driver */
		if ( ( rc = pci_find_driver ( pci ) ) != 0 ) {
			DBGC ( pci, PCI_FMT " (%04x:%04x class %06x) has no "
			       "driver\n", PCI_ARGS ( pci ), pci->vendor,
			       pci->device, pci->class );
			continue;
		}

		/* Add to device hierarchy */
		pci->dev.parent = &rootdev->dev;
		list_add ( &pci->dev.siblings, &rootdev->dev.children );

		/* Look for a driver */
		if ( ( rc = pci_probe ( pci ) ) == 0 ) {
			/* pcidev registered, we can drop our ref */
			pci = NULL;
		} else {
			/* Not registered; re-use struct pci_device */
			list_del ( &pci->dev.siblings );
		}
	}

	free ( pci );
	return 0;

 err:
	free ( pci );
	pcibus_remove ( rootdev );
	return rc;
}

/**
 * Remove PCI root bus
 *
 * @v rootdev		PCI bus root device
 */
static void pcibus_remove ( struct root_device *rootdev ) {
	struct pci_device *pci;
	struct pci_device *tmp;

	list_for_each_entry_safe ( pci, tmp, &rootdev->dev.children,
				   dev.siblings ) {
		pci_remove ( pci );
		list_del ( &pci->dev.siblings );
		free ( pci );
	}
}

/** PCI bus root device driver */
static struct root_driver pci_root_driver = {
	.probe = pcibus_probe,
	.remove = pcibus_remove,
};

/** PCI bus root device */
struct root_device pci_root_device __root_device = {
	.dev = { .name = "PCI" },
	.driver = &pci_root_driver,
};
