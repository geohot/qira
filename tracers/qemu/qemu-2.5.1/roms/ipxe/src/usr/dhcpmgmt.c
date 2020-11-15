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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ipxe/netdevice.h>
#include <ipxe/dhcp.h>
#include <ipxe/monojob.h>
#include <usr/ifmgmt.h>
#include <usr/dhcpmgmt.h>

/** @file
 *
 * DHCP management
 *
 */

int pxebs ( struct net_device *netdev, unsigned int pxe_type ) {
	int rc;

	/* Perform PXE Boot Server Discovery */
	printf ( "PXEBS (%s type %d)", netdev->name, pxe_type );
	if ( ( rc = start_pxebs ( &monojob, netdev, pxe_type ) ) == 0 )
		rc = monojob_wait ( "", 0 );

	return rc;
}
