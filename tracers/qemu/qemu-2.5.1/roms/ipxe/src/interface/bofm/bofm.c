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
#include <string.h>
#include <errno.h>
#include <ipxe/uaccess.h>
#include <ipxe/list.h>
#include <ipxe/ethernet.h>
#include <ipxe/bofm.h>

/** @file
 *
 * IBM BladeCenter Open Fabric Manager (BOFM)
 *
 */

/** List of BOFM devices */
static LIST_HEAD ( bofmdevs );

/**
 * Register BOFM device
 *
 * @v bofm		BOFM device
 * @ret rc		Return status code
 */
int bofm_register ( struct bofm_device *bofm ) {

	list_add ( &bofm->list, &bofmdevs );
	DBG ( "BOFM: " PCI_FMT " registered using driver \"%s\"\n",
	      PCI_ARGS ( bofm->pci ), bofm->pci->id->name );
	return 0;
}

/**
 * Unregister BOFM device
 *
 * @v bofm		BOFM device
 */
void bofm_unregister ( struct bofm_device *bofm ) {

	list_del ( &bofm->list );
	DBG ( "BOFM: " PCI_FMT " unregistered\n", PCI_ARGS ( bofm->pci ) );
}

/**
 * Find BOFM device matching PCI bus:dev.fn address
 *
 * @v busdevfn		PCI bus:dev.fn address
 * @ret bofm		BOFM device, or NULL
 */
static struct bofm_device * bofm_find_busdevfn ( unsigned int busdevfn ) {
	struct bofm_device *bofm;

	list_for_each_entry ( bofm, &bofmdevs, list ) {
		if ( bofm->pci->busdevfn == busdevfn )
			return bofm;
	}
	return NULL;
}

/**
 * Find BOFM driver for PCI device
 *
 * @v pci		PCI device
 * @ret rc		Return status code
 */
int bofm_find_driver ( struct pci_device *pci ) {
	struct pci_driver *driver;
	struct pci_device_id *id;
	unsigned int i;

	for_each_table_entry ( driver, BOFM_DRIVERS ) {
		for ( i = 0 ; i < driver->id_count ; i++ ) {
			id = &driver->ids[i];
			if ( ( id->vendor == pci->vendor ) &&
			     ( id->device == pci->device ) ) {
				pci_set_driver ( pci, driver, id );
				return 0;
			}
		}
	}
	return -ENOENT;
}

/**
 * Probe PCI device for BOFM driver
 *
 * @v pci		PCI device
 * @ret rc		Return status code
 */
static int bofm_probe ( struct pci_device *pci ) {
	int rc;

	/* Probe device */
	if ( ( rc = pci_probe ( pci ) ) != 0 ) {
		DBG ( "BOFM: " PCI_FMT " could not load driver: %s\n",
		      PCI_ARGS ( pci ), strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Remove PCI device
 *
 * @v pci		PCI device
 */
static void bofm_remove ( struct pci_device *pci ) {

	/* Note that the IBM BIOS may re-read the expansion ROM after
	 * the BOFM initialisation call.  The BOFM driver must ensure
	 * that the card is left in a state in which expansion ROM
	 * reads will succeed.  (For example, if a card contains an
	 * embedded CPU that may issue reads to the same underlying
	 * flash device, and these reads are not locked against reads
	 * via the expansion ROM BAR, then the CPU must be stopped.)
	 *
	 * If this is not done, then occasional corrupted reads from
	 * the expansion ROM will be seen, and the BIOS may complain
	 * about a ROM checksum error.
	 */
	pci_remove ( pci );
	DBG ( "BOFM: " PCI_FMT " removed\n", PCI_ARGS ( pci ) );
}

/**
 * Locate BOFM table section
 *
 * @v bofmtab		BOFM table
 * @v len		Length of BOFM table
 * @v magic		Section magic
 * @v bofmsec		BOFM section header to fill in
 * @ret offset		Offset to section, or 0 if not found
 */
static size_t bofm_locate_section ( userptr_t bofmtab, size_t len,
				    uint32_t magic,
				    struct bofm_section_header *bofmsec ) {
	size_t offset = sizeof ( struct bofm_global_header );

	while ( offset < len ) {
		copy_from_user ( bofmsec, bofmtab, offset,
				 sizeof ( *bofmsec ) );
		if ( bofmsec->magic == magic )
			return offset;
		if ( bofmsec->magic == BOFM_DONE_MAGIC )
			break;
		offset += ( sizeof ( *bofmsec ) + bofmsec->length );
	}
	return 0;
}

/**
 * Process BOFM Ethernet parameter entry
 *
 * @v bofm		BOFM device
 * @v en		EN parameter entry
 * @ret rc		Return status code
 */
static int bofm_en ( struct bofm_device *bofm, struct bofm_en *en ) {
	uint8_t mac[6];
	int rc;

	/* Retrieve current MAC address */
	if ( ( rc = bofm->op->harvest ( bofm, en->mport, mac ) ) != 0 ) {
		DBG ( "BOFM: " PCI_FMT " mport %d could not harvest: %s\n",
		      PCI_ARGS ( bofm->pci ), en->mport, strerror ( rc ) );
		return rc;
	}

	/* Harvest MAC address if necessary */
	if ( en->options & BOFM_EN_RQ_HVST_MASK ) {
		DBG ( "BOFM: " PCI_FMT " mport %d harvested MAC %s\n",
		      PCI_ARGS ( bofm->pci ), en->mport, eth_ntoa ( mac ) );
		memcpy ( en->mac_a, mac, sizeof ( en->mac_a ) );
		en->options |= ( BOFM_EN_EN_A | BOFM_EN_HVST );
	}

	/* Mark as changed if necessary */
	if ( ( en->options & BOFM_EN_EN_A ) &&
	     ( memcmp ( en->mac_a, mac, sizeof ( en->mac_a ) ) != 0 ) ) {
		DBG ( "BOFM: " PCI_FMT " mport %d MAC %s",
		      PCI_ARGS ( bofm->pci ), en->mport, eth_ntoa ( mac ) );
		DBG ( " changed to %s\n", eth_ntoa ( en->mac_a ) );
		en->options |= BOFM_EN_CHG_CHANGED;
	}

	/* Apply MAC address if necessary */
	if ( ( en->options & BOFM_EN_EN_A ) &&
	     ( en->options & BOFM_EN_USAGE_ENTRY ) &&
	     ( ! ( en->options & BOFM_EN_USAGE_HARVEST ) ) ) {
		DBG ( "BOFM: " PCI_FMT " mport %d applied MAC %s\n",
		      PCI_ARGS ( bofm->pci ), en->mport,
		      eth_ntoa ( en->mac_a ) );
		memcpy ( mac, en->mac_a, sizeof ( mac ) );
	}

	/* Store MAC address */
	if ( ( rc = bofm->op->update ( bofm, en->mport, mac ) ) != 0 ) {
		DBG ( "BOFM: " PCI_FMT " mport %d could not update: %s\n",
		      PCI_ARGS ( bofm->pci ), en->mport, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Process BOFM table
 *
 * @v bofmtab		BOFM table
 * @v pci		PCI device
 * @ret bofmrc		BOFM return status
 */
int bofm ( userptr_t bofmtab, struct pci_device *pci ) {
	struct bofm_global_header bofmhdr;
	struct bofm_section_header bofmsec;
	struct bofm_en en;
	struct bofm_device *bofm;
	size_t en_region_offset;
	size_t en_offset;
	int skip;
	int rc;
	int bofmrc;

	/* Read BOFM structure */
	copy_from_user ( &bofmhdr, bofmtab, 0, sizeof ( bofmhdr ) );
	if ( bofmhdr.magic != BOFM_IOAA_MAGIC ) {
		DBG ( "BOFM: invalid table signature " BOFM_MAGIC_FMT "\n",
		      BOFM_MAGIC_ARGS ( bofmhdr.magic ) );
		bofmrc = BOFM_ERR_INVALID_ACTION;
		goto err_bad_signature;
	}
	DBG ( "BOFM: " BOFM_MAGIC_FMT " (profile \"%s\")\n",
	      BOFM_MAGIC_ARGS ( bofmhdr.action ), bofmhdr.profile );

	/* Determine whether or not we should skip normal POST
	 * initialisation.
	 */
	switch ( bofmhdr.action ) {
	case BOFM_ACTION_UPDT:
	case BOFM_ACTION_DFLT:
	case BOFM_ACTION_HVST:
		skip = BOFM_SKIP_INIT;
		break;
	case BOFM_ACTION_PARM:
	case BOFM_ACTION_NONE:
		skip = 0;
		break;
	default:
		DBG ( "BOFM: invalid action " BOFM_MAGIC_FMT "\n",
		      BOFM_MAGIC_ARGS ( bofmhdr.action ) );
		bofmrc = BOFM_ERR_INVALID_ACTION;
		goto err_bad_action;
	}

	/* Find BOFM driver */
	if ( ( rc = bofm_find_driver ( pci ) ) != 0 ) {
		DBG ( "BOFM: " PCI_FMT " has no driver\n", PCI_ARGS ( pci ) );
		bofmrc = BOFM_ERR_DEVICE_ERROR;
		goto err_find_driver;
	}

	/* Probe driver for PCI device */
	if ( ( rc = bofm_probe ( pci ) ) != 0 ) {
		bofmrc = BOFM_ERR_DEVICE_ERROR;
		goto err_probe;
	}

	/* Locate EN section, if present */
	en_region_offset = bofm_locate_section ( bofmtab, bofmhdr.length,
						 BOFM_EN_MAGIC, &bofmsec );
	if ( ! en_region_offset ) {
		DBG ( "BOFM: No EN section found\n" );
		bofmrc = ( BOFM_SUCCESS | skip );
		goto err_no_en_section;
	}

	/* Iterate through EN entries */
	for ( en_offset = ( en_region_offset + sizeof ( bofmsec ) ) ;
	      en_offset < ( en_region_offset + sizeof ( bofmsec ) +
			    bofmsec.length ) ; en_offset += sizeof ( en ) ) {
		copy_from_user ( &en, bofmtab, en_offset, sizeof ( en ) );
		DBG2 ( "BOFM: EN entry found:\n" );
		DBG2_HDA ( en_offset, &en, sizeof ( en ) );
		if ( ( en.options & BOFM_EN_MAP_MASK ) != BOFM_EN_MAP_PFA ) {
			DBG ( "BOFM: slot %d port %d has no PCI mapping\n",
			      en.slot, ( en.port + 1 ) );
			continue;
		}
		DBG ( "BOFM: slot %d port %d%s is " PCI_FMT " mport %d\n",
		      en.slot, ( en.port + 1 ),
		      ( ( en.slot || en.port ) ? "" : "(?)" ),
		      PCI_BUS ( en.busdevfn ), PCI_SLOT ( en.busdevfn ),
		      PCI_FUNC ( en.busdevfn ), en.mport );
		bofm = bofm_find_busdevfn ( en.busdevfn );
		if ( ! bofm ) {
			DBG ( "BOFM: " PCI_FMT " mport %d ignored\n",
			      PCI_BUS ( en.busdevfn ), PCI_SLOT ( en.busdevfn ),
			      PCI_FUNC ( en.busdevfn ), en.mport );
			continue;
		}
		if ( ( rc = bofm_en ( bofm, &en ) ) == 0 ) {
			en.options |= BOFM_EN_CSM_SUCCESS;
		} else {
			en.options |= BOFM_EN_CSM_FAILED;
		}
		DBG2 ( "BOFM: EN entry after processing:\n" );
		DBG2_HDA ( en_offset, &en, sizeof ( en ) );
		copy_to_user ( bofmtab, en_offset, &en, sizeof ( en ) );
	}

	bofmrc = ( BOFM_SUCCESS | skip );

 err_no_en_section:
	bofm_remove ( pci );
 err_probe:
 err_find_driver:
 err_bad_action:
 err_bad_signature:
	return bofmrc;
}
