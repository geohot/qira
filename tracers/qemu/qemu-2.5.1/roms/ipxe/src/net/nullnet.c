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

#include <stdint.h>
#include <errno.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>

/** @file
 *
 * Null network device
 *
 */

static int null_open ( struct net_device *netdev __unused ) {
	return -ENODEV;
};

static void null_close ( struct net_device *netdev __unused ) {
	/* Do nothing */
};

static int null_transmit ( struct net_device *netdev __unused,
			   struct io_buffer *iobuf __unused ) {
	return -ENODEV;
};

static void null_poll ( struct net_device *netdev __unused ) {
	/* Do nothing */
}

static void null_irq ( struct net_device *netdev __unused,
		       int enable __unused ) {
	/* Do nothing */
}

struct net_device_operations null_netdev_operations = {
	.open		= null_open,
	.close		= null_close,
	.transmit	= null_transmit,
	.poll		= null_poll,
	.irq   		= null_irq,
};
