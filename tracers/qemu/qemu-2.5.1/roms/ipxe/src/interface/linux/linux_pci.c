/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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
#include <byteswap.h>
#include <linux_api.h>
#include <ipxe/linux.h>
#include <ipxe/pci.h>

/** @file
 *
 * iPXE PCI API for Linux
 *
 */

/**
 * Open PCI configuration space
 *
 * @v pci		PCI device
 * @v flags		Access mode flags
 * @v where		Address within configuration space
 * @ret fd		File handle, or negative error
 */
static int linux_pci_open ( struct pci_device *pci, int flags,
			    unsigned long where ) {
	char filename[ 22 /* "/proc/bus/pci/xx/xx.x" + NUL */ ];
	int fd;
	int rc;

	/* Construct filename */
	snprintf ( filename, sizeof ( filename ), "/proc/bus/pci/%02x/%02x.%x",
		   PCI_BUS ( pci->busdevfn ), PCI_SLOT ( pci->busdevfn ),
		   PCI_FUNC ( pci->busdevfn ) );

	/* Open file */
	fd = linux_open ( filename, flags );
	if ( fd < 0 ) {
		DBGC ( pci, "PCI could not open %s: %s\n", filename,
		       linux_strerror ( linux_errno ) );
		rc = -ELINUX ( linux_errno );
		goto err_open;
	}

	/* Seek to location */
	if ( linux_lseek ( fd, where, SEEK_SET ) < 0 ) {
		DBGC ( pci, "PCI could not seek to %s offset %#02lx: %s\n",
		       filename, where, linux_strerror ( linux_errno ) );
		rc = -ELINUX ( linux_errno );
		goto err_seek;
	}

	return fd;

 err_seek:
	linux_close ( fd );
 err_open:
	return rc;
}

/**
 * Read from PCI configuration space
 *
 * @v pci		PCI device
 * @v where		Address within configuration space
 * @v value		Data buffer
 * @v len		Length to read
 * @ret rc		Return status code
 */
int linux_pci_read ( struct pci_device *pci, unsigned long where,
		     unsigned long *value, size_t len ) {
	uint32_t tmp = 0;
	int fd;
	int check_len;
	int rc;

	/* Return "missing device" in case of error */
	*value = -1UL;

	/* Open configuration space */
	fd = linux_pci_open ( pci, O_RDONLY, where );
	if ( fd < 0 ) {
		rc = fd;
		goto err_open;
	}

	/* Read value */
	check_len = linux_read ( fd, &tmp, len );
	if ( check_len < 0 ) {
		DBGC ( pci, "PCI could not read from " PCI_FMT " %#02lx+%#zx: "
		       "%s\n", PCI_ARGS ( pci ), where, len,
		       linux_strerror ( linux_errno ) );
		rc = -ELINUX ( linux_errno );
		goto err_read;
	}
	if ( ( size_t ) check_len != len ) {
		DBGC ( pci, "PCI read only %#x bytes from " PCI_FMT
		       " %#02lx+%#zx\n", check_len, PCI_ARGS ( pci ),
		       where, len );
		rc = -EIO;
		goto err_read;
	}

	/* Return value */
	*value = le32_to_cpu ( tmp );

	/* Success */
	rc = 0;

 err_read:
	linux_close ( fd );
 err_open:
	return rc;
}

/**
 * Write to PCI configuration space
 *
 * @v pci		PCI device
 * @v where		Address within configuration space
 * @v value		Value to write
 * @v len		Length of value
 * @ret rc		Return status code
 */
int linux_pci_write ( struct pci_device *pci, unsigned long where,
		      unsigned long value, size_t len ) {
	uint32_t tmp;
	int fd;
	int check_len;
	int rc;

	/* Open configuration space */
	fd = linux_pci_open ( pci, O_WRONLY, where );
	if ( fd < 0 ) {
		rc = fd;
		goto err_open;
	}

	/* Prepare value for writing */
	tmp = cpu_to_le32 ( value );
	assert ( len <= sizeof ( tmp ) );

	/* Write value */
	check_len = linux_write ( fd, &tmp, len );
	if ( check_len < 0 ) {
		DBGC ( pci, "PCI could not write to " PCI_FMT " %#02lx+%#zx: "
		       "%s\n", PCI_ARGS ( pci ), where, len,
		       linux_strerror ( linux_errno ) );
		rc = -ELINUX ( linux_errno );
		goto err_write;
	}
	if ( ( size_t ) check_len != len ) {
		DBGC ( pci, "PCI wrote only %#x bytes to " PCI_FMT
		       " %#02lx+%#zx\n", check_len, PCI_ARGS ( pci ),
		       where, len );
		rc = -EIO;
		goto err_write;
	}

	/* Success */
	rc = 0;

 err_write:
	linux_close ( fd );
 err_open:
	return rc;
}
