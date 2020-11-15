/*
 * Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdio.h>
#include <errno.h>
#include <ipxe/nvs.h>
#include <ipxe/pci.h>
#include <ipxe/pcivpd.h>
#include <ipxe/nvo.h>
#include <ipxe/nvsvpd.h>

/** @file
 *
 * Non-Volatile Storage using Vital Product Data
 *
 */

/**
 * Read from VPD field
 *
 * @v nvs		NVS device
 * @v field		VPD field descriptor
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
static int nvs_vpd_read ( struct nvs_device *nvs, unsigned int field,
			  void *data, size_t len ) {
	struct nvs_vpd_device *nvsvpd =
		container_of ( nvs, struct nvs_vpd_device, nvs );
	struct pci_device *pci = nvsvpd->vpd.pci;
	unsigned int address;
	size_t max_len;
	int rc;

	/* Allow reading non-existent field */
	if ( len == 0 )
		return 0;

	/* Locate VPD field */
	if ( ( rc = pci_vpd_find ( &nvsvpd->vpd, field, &address,
				   &max_len ) ) != 0 ) {
		DBGC ( pci, PCI_FMT " NVS VPD could not locate field "
		       PCI_VPD_FIELD_FMT ": %s\n", PCI_ARGS ( pci ),
		       PCI_VPD_FIELD_ARGS ( field ), strerror ( rc ) );
		return rc;
	}

	/* Sanity check */
	if ( len > max_len ) {
		DBGC ( pci, PCI_FMT " NVS VPD cannot read %#02zx bytes "
		       "beyond field " PCI_VPD_FIELD_FMT " at [%04x,%04zx)\n",
		       PCI_ARGS ( pci ), len, PCI_VPD_FIELD_ARGS ( field ),
		       address, ( address + max_len ) );
		return -ENXIO;
	}

	/* Read from VPD field */
	if ( ( rc = pci_vpd_read ( &nvsvpd->vpd, address, data, len ) ) != 0 ) {
		DBGC ( pci, PCI_FMT " NVS VPD could not read field "
		       PCI_VPD_FIELD_FMT " at [%04x,%04zx): %s\n",
		       PCI_ARGS ( pci ), PCI_VPD_FIELD_ARGS ( field ),
		       address, ( address + len ), strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Write to VPD field
 *
 * @v nvs		NVS device
 * @v field		VPD field descriptor
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
static int nvs_vpd_write ( struct nvs_device *nvs, unsigned int field,
			   const void *data, size_t len ) {
	struct nvs_vpd_device *nvsvpd =
		container_of ( nvs, struct nvs_vpd_device, nvs );
	struct pci_device *pci = nvsvpd->vpd.pci;
	unsigned int address;
	size_t max_len;
	int rc;

	/* Locate VPD field */
	if ( ( rc = pci_vpd_find ( &nvsvpd->vpd, field, &address,
				   &max_len ) ) != 0 ) {
		DBGC ( pci, PCI_FMT " NVS VPD could not locate field "
		       PCI_VPD_FIELD_FMT ": %s\n", PCI_ARGS ( pci ),
		       PCI_VPD_FIELD_ARGS ( field ), strerror ( rc ) );
		return rc;
	}

	/* Sanity check */
	if ( len > max_len ) {
		DBGC ( pci, PCI_FMT " NVS VPD cannot write %#02zx bytes "
		       "beyond field " PCI_VPD_FIELD_FMT " at [%04x,%04zx)\n",
		       PCI_ARGS ( pci ), len, PCI_VPD_FIELD_ARGS ( field ),
		       address, ( address + max_len ) );
		return -ENXIO;
	}

	/* Write field */
	if ( ( rc = pci_vpd_write ( &nvsvpd->vpd, address, data,
				    len ) ) != 0 ) {
		DBGC ( pci, PCI_FMT " NVS VPD could not write field "
		       PCI_VPD_FIELD_FMT " at [%04x,%04zx): %s\n",
		       PCI_ARGS ( pci ), PCI_VPD_FIELD_ARGS ( field ),
		       address, ( address + len ), strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Resize VPD field
 *
 * @v nvs		NVS device
 * @v field		VPD field descriptor
 * @v data		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
static int nvs_vpd_resize ( struct nvs_device *nvs, unsigned int field,
			    size_t len ) {
	struct nvs_vpd_device *nvsvpd =
		container_of ( nvs, struct nvs_vpd_device, nvs );
	struct pci_device *pci = nvsvpd->vpd.pci;
	unsigned int address;
	int rc;

	/* Resize field */
	if ( ( rc = pci_vpd_resize ( &nvsvpd->vpd, field, len,
				     &address ) ) != 0 ) {
		DBGC ( pci, PCI_FMT " NVS VPD could not resize field "
		       PCI_VPD_FIELD_FMT " to %#02zx bytes: %s\n",
		       PCI_ARGS ( pci ), PCI_VPD_FIELD_ARGS ( field ),
		       len, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Initialise NVS VPD device
 *
 * @v nvsvpd		NVS VPD device
 * @v pci		PCI device
 * @ret rc		Return status code
 */
int nvs_vpd_init ( struct nvs_vpd_device *nvsvpd, struct pci_device *pci ) {
	int rc;

	/* Initialise VPD device */
	if ( ( rc = pci_vpd_init ( &nvsvpd->vpd, pci ) ) != 0 ) {
		DBGC ( pci, PCI_FMT " NVS could not initialise "
		       "VPD: %s\n", PCI_ARGS ( pci ), strerror ( rc ) );
		return rc;
	}

	/* Initialise NVS device */
	nvsvpd->nvs.read = nvs_vpd_read;
	nvsvpd->nvs.write = nvs_vpd_write;

	return 0;
}

/**
 * Resize non-volatile option storage within NVS VPD device
 *
 * @v nvo		Non-volatile options block
 * @v len		New length
 * @ret rc		Return status code
 */
static int nvs_vpd_nvo_resize ( struct nvo_block *nvo, size_t len ) {
	int rc;

	/* Resize VPD field */
	if ( ( rc = nvs_vpd_resize ( nvo->nvs, nvo->address, len ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Initialise non-volatile option storage within NVS VPD device
 *
 * @v nvsvpd		NVS VPD device
 * @v field		VPD field descriptor
 * @v nvo		Non-volatile options block
 * @v refcnt		Containing object reference counter, or NULL
 */
void nvs_vpd_nvo_init ( struct nvs_vpd_device *nvsvpd, unsigned int field,
			struct nvo_block *nvo, struct refcnt *refcnt ) {
	struct pci_device *pci = nvsvpd->vpd.pci;
	unsigned int address;
	size_t len;
	int rc;

	/* Locate VPD field, if present */
	if ( ( rc = pci_vpd_find ( &nvsvpd->vpd, field, &address,
				   &len ) ) != 0 ) {
		DBGC ( pci, PCI_FMT " NVS VPD field " PCI_VPD_FIELD_FMT
		       " not present; assuming empty\n",
		       PCI_ARGS ( pci ), PCI_VPD_FIELD_ARGS ( field ) );
		len = 0;
	}

	/* Initialise non-volatile options block */
	nvo_init ( nvo, &nvsvpd->nvs, field, len, nvs_vpd_nvo_resize, refcnt );
}
