/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
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

/** @file
 *
 * VMware backdoor mechanism
 *
 * Based on the unofficial documentation at
 *
 *   http://sites.google.com/site/chitchatvmback/backdoor
 *
 */

#include <stdint.h>
#include <errno.h>
#include <ipxe/vmware.h>

/**
 * Detect VMware presence
 *
 * @ret rc		Return status code
 */
int vmware_present ( void ) {
	uint32_t version;
	uint32_t magic;
	uint32_t product_type;

	/* Perform backdoor call */
	vmware_cmd_get_version ( &version, &magic, &product_type );

	/* Check for VMware presence */
	if ( magic != VMW_MAGIC ) {
		DBGC ( VMW_MAGIC, "VMware not present\n" );
		return -ENOENT;
	}

	DBGC ( VMW_MAGIC, "VMware product type %04x version %08x detected\n",
	       product_type, version );
	return 0;
}
