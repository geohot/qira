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

#include <errno.h>
#include <ipxe/interface.h>
#include <ipxe/edd.h>

/** @file
 *
 * Enhanced Disk Drive specification
 *
 */

/**
 * Describe a disk device using EDD
 *
 * @v intf		Interface
 * @v type		EDD interface type
 * @v path		EDD device path
 * @ret rc		Return status code
 */
int edd_describe ( struct interface *intf, struct edd_interface_type *type,
		   union edd_device_path *path ) {
	struct interface *dest;
	edd_describe_TYPE ( void * ) *op =
		intf_get_dest_op ( intf, edd_describe, &dest );
	void *object = intf_object ( dest );
	int rc;

	if ( op ) {
		rc = op ( object, type, path );
	} else {
		/* Default is to not support this operation */
		rc = -ENOTSUP;
	}

	intf_put ( dest );
	return rc;
}
