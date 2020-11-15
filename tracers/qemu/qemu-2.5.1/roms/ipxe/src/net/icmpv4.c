/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <errno.h>
#include <ipxe/iobuf.h>
#include <ipxe/in.h>
#include <ipxe/tcpip.h>
#include <ipxe/icmp.h>

/** @file
 *
 * ICMPv4 protocol
 *
 */

struct icmp_echo_protocol icmpv4_echo_protocol __icmp_echo_protocol;

/**
 * Process a received packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v st_src		Partially-filled source address
 * @v st_dest		Partially-filled destination address
 * @v pshdr_csum	Pseudo-header checksum
 * @ret rc		Return status code
 */
static int icmpv4_rx ( struct io_buffer *iobuf,
		       struct net_device *netdev __unused,
		       struct sockaddr_tcpip *st_src,
		       struct sockaddr_tcpip *st_dest __unused,
		       uint16_t pshdr_csum __unused ) {
	struct icmp_header *icmp = iobuf->data;
	size_t len = iob_len ( iobuf );
	unsigned int csum;
	unsigned int type;
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *icmp ) ) {
		DBG ( "ICMP packet too short at %zd bytes (min %zd bytes)\n",
		      len, sizeof ( *icmp ) );
		rc = -EINVAL;
		goto discard;
	}

	/* Verify checksum */
	csum = tcpip_chksum ( icmp, len );
	if ( csum != 0 ) {
		DBG ( "ICMP checksum incorrect (is %04x, should be 0000)\n",
		      csum );
		DBG_HD ( icmp, len );
		rc = -EINVAL;
		goto discard;
	}

	/* Handle ICMP packet */
	type = icmp->type;
	switch ( type ) {
	case ICMP_ECHO_REQUEST:
		return icmp_rx_echo_request ( iobuf, st_src,
					      &icmpv4_echo_protocol );
	case ICMP_ECHO_REPLY:
		return icmp_rx_echo_reply ( iobuf, st_src );
	default:
		DBG ( "ICMP ignoring type %d\n", type );
		rc = 0;
		break;
	}

 discard:
	free_iob ( iobuf );
	return rc;
}

/** ICMPv4 TCP/IP protocol */
struct tcpip_protocol icmpv4_protocol __tcpip_protocol = {
	.name = "ICMPv4",
	.rx = icmpv4_rx,
	.tcpip_proto = IP_ICMP,
};

/** ICMPv4 echo protocol */
struct icmp_echo_protocol icmpv4_echo_protocol __icmp_echo_protocol = {
	.family = AF_INET,
	.request = ICMP_ECHO_REQUEST,
	.reply = ICMP_ECHO_REPLY,
	.tcpip_protocol = &icmpv4_protocol,
	.net_checksum = 0,
};
