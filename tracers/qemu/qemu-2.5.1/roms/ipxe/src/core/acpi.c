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

#include <errno.h>
#include <ipxe/acpi.h>
#include <ipxe/interface.h>

/** @file
 *
 * ACPI support functions
 *
 */

/******************************************************************************
 *
 * Utility functions
 *
 ******************************************************************************
 */

/**
 * Fix up ACPI table checksum
 *
 * @v acpi		ACPI table header
 */
void acpi_fix_checksum ( struct acpi_description_header *acpi ) {
	unsigned int i = 0;
	uint8_t sum = 0;

	for ( i = 0 ; i < acpi->length ; i++ ) {
		sum += *( ( ( uint8_t * ) acpi ) + i );
	}
	acpi->checksum -= sum;
}

/******************************************************************************
 *
 * Interface methods
 *
 ******************************************************************************
 */

/**
 * Describe object in an ACPI table
 *
 * @v intf		Interface
 * @v acpi		ACPI table
 * @v len		Length of ACPI table
 * @ret rc		Return status code
 */
int acpi_describe ( struct interface *intf,
		    struct acpi_description_header *acpi, size_t len ) {
	struct interface *dest;
	acpi_describe_TYPE ( void * ) *op =
		intf_get_dest_op ( intf, acpi_describe, &dest );
	void *object = intf_object ( dest );
	int rc;

	if ( op ) {
		rc = op ( object, acpi, len );
	} else {
		/* Default is to fail to describe */
		rc = -EOPNOTSUPP;
	}

	intf_put ( dest );
	return rc;
}
