/*
 * Copyright (c) 2009 Joshua Oreman <oremanj@rwcr.net>.
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
 */

FILE_LICENCE ( GPL2_OR_LATER );

/** @file
 *
 * 802.1X Extensible Authentication Protocol over LANs demultiplexer
 *
 */

#include <ipxe/netdevice.h>
#include <ipxe/iobuf.h>
#include <ipxe/if_ether.h>
#include <ipxe/eapol.h>
#include <errno.h>
#include <byteswap.h>

/**
 * Receive EAPOL network-layer packet
 *
 * @v iob	I/O buffer
 * @v netdev	Network device
 * @v ll_dest	Link-layer destination address
 * @v ll_source	Link-layer source address
 * @v flags	Packet flags
 *
 * This function takes ownership of the I/O buffer passed to it.
 */
static int eapol_rx ( struct io_buffer *iob, struct net_device *netdev,
		      const void *ll_dest, const void *ll_source,
		      unsigned int flags __unused ) {
	struct eapol_frame *eapol = iob->data;
	struct eapol_handler *handler;

	if ( iob_len ( iob ) < EAPOL_HDR_LEN ) {
		free_iob ( iob );
		return -EINVAL;
	}

	for_each_table_entry ( handler, EAPOL_HANDLERS ) {
		if ( handler->type == eapol->type ) {
			iob_pull ( iob, EAPOL_HDR_LEN );
			return handler->rx ( iob, netdev, ll_dest, ll_source );
		}
	}

	free_iob ( iob );
	return -( ENOTSUP | ( ( eapol->type & 0x1f ) << 8 ) );
}

/**
 * Transcribe EAPOL network-layer address
 *
 * @v net_addr	Network-layer address
 * @ret str	String representation of network-layer address
 *
 * EAPOL doesn't have network-layer addresses, so we just return the
 * string @c "<EAPOL>".
 */
static const char * eapol_ntoa ( const void *net_addr __unused )
{
	return "<EAPOL>";
}

/** EAPOL network protocol */
struct net_protocol eapol_protocol __net_protocol = {
	.name = "EAPOL",
	.rx = eapol_rx,
	.ntoa = eapol_ntoa,
	.net_proto = htons ( ETH_P_EAPOL ),
};
