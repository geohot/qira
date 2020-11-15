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
#include <ipxe/blockdev.h>

/** @file
 *
 * Block devices
 *
 */

/**
 * Read from block device
 *
 * @v control		Control interface
 * @v data		Data interface
 * @v lba		Starting logical block address
 * @v count		Number of logical blocks
 * @v buffer		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
int block_read ( struct interface *control, struct interface *data,
		 uint64_t lba, unsigned int count,
		 userptr_t buffer, size_t len ) {
	struct interface *dest;
	block_read_TYPE ( void * ) *op =
		intf_get_dest_op ( control, block_read, &dest );
	void *object = intf_object ( dest );
	int rc;

	if ( op ) {
		rc = op ( object, data, lba, count, buffer, len );
	} else {
		/* Default is to fail to issue the command */
		rc = -EOPNOTSUPP;
	}

	intf_put ( dest );
	return rc;
}

/**
 * Write to block device
 *
 * @v control		Control interface
 * @v data		Data interface
 * @v lba		Starting logical block address
 * @v count		Number of logical blocks
 * @v buffer		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
int block_write ( struct interface *control, struct interface *data,
		  uint64_t lba, unsigned int count,
		  userptr_t buffer, size_t len ) {
	struct interface *dest;
	block_write_TYPE ( void * ) *op =
		intf_get_dest_op ( control, block_write, &dest );
	void *object = intf_object ( dest );
	int rc;

	if ( op ) {
		rc = op ( object, data, lba, count, buffer, len );
	} else {
		/* Default is to fail to issue the command */
		rc = -EOPNOTSUPP;
	}

	intf_put ( dest );
	return rc;
}

/**
 * Read block device capacity
 *
 * @v control		Control interface
 * @v data		Data interface
 * @ret rc		Return status code
 */
int block_read_capacity ( struct interface *control, struct interface *data ) {
	struct interface *dest;
	block_read_capacity_TYPE ( void * ) *op =
		intf_get_dest_op ( control, block_read_capacity, &dest );
	void *object = intf_object ( dest );
	int rc;

	if ( op ) {
		rc = op ( object, data );
	} else {
		/* Default is to fail to issue the command */
		rc = -EOPNOTSUPP;
	}

	intf_put ( dest );
	return rc;
}

/**
 * Report block device capacity
 *
 * @v intf		Interface
 * @v capacity		Block device capacity
 */
void block_capacity ( struct interface *intf,
		      struct block_device_capacity *capacity ) {
	struct interface *dest;
	block_capacity_TYPE ( void * ) *op =
		intf_get_dest_op ( intf, block_capacity, &dest );
	void *object = intf_object ( dest );

	if ( op ) {
		op ( object, capacity );
	} else {
		/* Default is to do nothing */
	}

	intf_put ( dest );
}
