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

#include <stdint.h>
#include <byteswap.h>
#include <ipxe/netdevice.h>
#include <ipxe/iobuf.h>
#include <ipxe/if_ether.h>
#include <ipxe/rarp.h>

/** @file
 *
 * Reverse Address Resolution Protocol
 *
 */

/**
 * Process incoming ARP packets
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v ll_dest		Link-layer destination address
 * @v ll_source		Link-layer source address
 * @v flags		Packet flags
 * @ret rc		Return status code
 *
 * This is a dummy method which simply discards RARP packets.
 */
static int rarp_rx ( struct io_buffer *iobuf,
		     struct net_device *netdev __unused,
		     const void *ll_dest __unused,
		     const void *ll_source __unused,
		     unsigned int flags __unused ) {
	free_iob ( iobuf );
	return 0;
}


/**
 * Transcribe RARP address
 *
 * @v net_addr	RARP address
 * @ret string	"<RARP>"
 *
 * This operation is meaningless for the RARP protocol.
 */
static const char * rarp_ntoa ( const void *net_addr __unused ) {
	return "<RARP>";
}

/** RARP protocol */
struct net_protocol rarp_protocol __net_protocol = {
	.name = "RARP",
	.net_proto = htons ( ETH_P_RARP ),
	.rx = rarp_rx,
	.ntoa = rarp_ntoa,
};
