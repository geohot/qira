/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <errno.h>
#include <byteswap.h>
#include <ipxe/netdevice.h>
#include <ipxe/ethernet.h>
#include <ipxe/iobuf.h>
#include <ipxe/timer.h>
#include <ipxe/stp.h>

/** @file
 *
 * Spanning Tree Protocol (STP)
 *
 */

/* Disambiguate the various error causes */
#define ENOTSUP_PROTOCOL __einfo_error ( EINFO_ENOTSUP_PROTOCOL )
#define EINFO_ENOTSUP_PROTOCOL					\
	__einfo_uniqify ( EINFO_ENOTSUP, 0x01,			\
			  "Non-STP packet received" )
#define ENOTSUP_VERSION __einfo_error ( EINFO_ENOTSUP_VERSION )
#define EINFO_ENOTSUP_VERSION					\
	__einfo_uniqify ( EINFO_ENOTSUP, 0x01,			\
			  "Legacy STP packet received" )
#define ENOTSUP_TYPE __einfo_error ( EINFO_ENOTSUP_TYPE )
#define EINFO_ENOTSUP_TYPE					\
	__einfo_uniqify ( EINFO_ENOTSUP, 0x01,			\
			  "Non-RSTP packet received" )

/**
 * Process incoming STP packets
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v ll_source		Link-layer source address
 * @v flags		Packet flags
 * @ret rc		Return status code
 */
static int stp_rx ( struct io_buffer *iobuf, struct net_device *netdev,
		    const void *ll_dest __unused,
		    const void *ll_source __unused,
		    unsigned int flags __unused ) {
	struct stp_bpdu *stp;
	unsigned int hello;
	int rc;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *stp ) ) {
		DBGC ( netdev, "STP %s received underlength packet (%zd "
		       "bytes):\n", netdev->name, iob_len ( iobuf ) );
		DBGC_HDA ( netdev, 0, iobuf->data, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto done;
	}
	stp = iobuf->data;

	/* Ignore non-RSTP packets */
	if ( stp->protocol != htons ( STP_PROTOCOL ) ) {
		DBGC ( netdev, "STP %s ignoring non-STP packet (protocol "
		       "%#04x)\n", netdev->name, ntohs ( stp->protocol ) );
		rc = -ENOTSUP_PROTOCOL;
		goto done;
	}
	if ( stp->version < STP_VERSION_RSTP ) {
		DBGC ( netdev, "STP %s received legacy STP packet (version "
		       "%#02x)\n", netdev->name, stp->version );
		rc = -ENOTSUP_VERSION;
		goto done;
	}
	if ( stp->type != STP_TYPE_RSTP ) {
		DBGC ( netdev, "STP %s received non-RSTP packet (type %#02x)\n",
		       netdev->name, stp->type );
		rc = -ENOTSUP_TYPE;
		goto done;
	}

	/* Dump information */
	DBGC2 ( netdev, "STP %s %s port %#04x flags %#02x hello %d delay %d\n",
		netdev->name, eth_ntoa ( stp->sender.mac ), ntohs ( stp->port ),
		stp->flags, ntohs ( stp->hello ), ntohs ( stp->delay ) );

	/* Check if port is forwarding */
	if ( ! ( stp->flags & STP_FL_FORWARDING ) ) {
		/* Port is not forwarding: block link for two hello times */
		DBGC ( netdev, "STP %s %s port %#04x flags %#02x is not "
		       "forwarding\n",
		       netdev->name, eth_ntoa ( stp->sender.mac ),
		       ntohs ( stp->port ), stp->flags );
		hello = ( ( ntohs ( stp->hello ) * TICKS_PER_SEC ) / 256 );
		netdev_link_block ( netdev, ( hello * 2 ) );
		rc = -ENETUNREACH;
		goto done;
	}

	/* Success */
	if ( netdev_link_blocked ( netdev ) ) {
		DBGC ( netdev, "STP %s %s port %#04x flags %#02x is "
		       "forwarding\n",
		       netdev->name, eth_ntoa ( stp->sender.mac ),
		       ntohs ( stp->port ), stp->flags );
	}
	netdev_link_unblock ( netdev );
	rc = 0;

 done:
	free_iob ( iobuf );
	return rc;
}

/**
 * Transcribe STP address
 *
 * @v net_addr		STP address
 * @ret string		"<STP>"
 *
 * This operation is meaningless for the STP protocol.
 */
static const char * stp_ntoa ( const void *net_addr __unused ) {
	return "<STP>";
}

/** STP network protocol */
struct net_protocol stp_protocol __net_protocol = {
	.name = "STP",
	.net_proto = htons ( ETH_P_STP ),
	.rx = stp_rx,
	.ntoa = stp_ntoa,
};
