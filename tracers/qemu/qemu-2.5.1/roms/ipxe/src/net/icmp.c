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
#include <byteswap.h>
#include <errno.h>
#include <ipxe/iobuf.h>
#include <ipxe/in.h>
#include <ipxe/tcpip.h>
#include <ipxe/ping.h>
#include <ipxe/crc32.h>
#include <ipxe/icmp.h>

/** @file
 *
 * ICMP protocol
 *
 */

/**
 * Identify ICMP echo protocol
 *
 * @v st_family		Address family
 * @ret echo_protocol	ICMP echo protocol, or NULL
 */
static struct icmp_echo_protocol * icmp_echo_protocol ( sa_family_t family ) {
	struct icmp_echo_protocol *echo_protocol;

	for_each_table_entry ( echo_protocol, ICMP_ECHO_PROTOCOLS ) {
		if ( echo_protocol->family == family )
			return echo_protocol;
	}
	return NULL;
}

/**
 *
 * Determine debugging colour for ICMP debug messages
 *
 * @v st_peer		Peer address
 * @ret col		Debugging colour (for DBGC())
 */
static uint32_t icmpcol ( struct sockaddr_tcpip *st_peer ) {

	return crc32_le ( 0, st_peer, sizeof ( *st_peer ) );
}

/**
 * Transmit ICMP echo packet
 *
 * @v iobuf		I/O buffer
 * @v st_dest		Destination socket address
 * @v echo_protocol	ICMP echo protocol
 * @ret rc		Return status code
 */
static int icmp_tx_echo ( struct io_buffer *iobuf,
			  struct sockaddr_tcpip *st_dest,
			  struct icmp_echo_protocol *echo_protocol ) {
	struct icmp_echo *echo = iobuf->data;
	int rc;

	/* Set ICMP type and (re)calculate checksum */
	echo->icmp.chksum = 0;
	echo->icmp.chksum = tcpip_chksum ( echo, iob_len ( iobuf ) );

	/* Transmit packet */
	if ( ( rc = tcpip_tx ( iobuf, echo_protocol->tcpip_protocol, NULL,
			       st_dest, NULL,
			       ( echo_protocol->net_checksum ?
				 &echo->icmp.chksum : NULL ) ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Transmit ICMP echo request
 *
 * @v iobuf		I/O buffer
 * @v st_dest		Destination socket address
 * @ret rc		Return status code
 */
int icmp_tx_echo_request ( struct io_buffer *iobuf,
			   struct sockaddr_tcpip *st_dest ) {
	struct icmp_echo *echo = iobuf->data;
	struct icmp_echo_protocol *echo_protocol;
	int rc;

	/* Identify ICMP echo protocol */
	echo_protocol = icmp_echo_protocol ( st_dest->st_family );
	if ( ! echo_protocol ) {
		DBGC ( icmpcol ( st_dest ), "ICMP TX echo request unknown "
		       "address family %d\n", st_dest->st_family );
		free_iob ( iobuf );
		return -ENOTSUP;
	}

	/* Set type */
	echo->icmp.type = echo_protocol->request;

	/* Transmit request */
	DBGC ( icmpcol ( st_dest ), "ICMP TX echo request id %04x seq %04x\n",
	       ntohs ( echo->ident ), ntohs ( echo->sequence ) );
	if ( ( rc = icmp_tx_echo ( iobuf, st_dest, echo_protocol ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Transmit ICMP echo reply
 *
 * @v iobuf		I/O buffer
 * @v st_dest		Destination socket address
 * @ret rc		Return status code
 */
static int icmp_tx_echo_reply ( struct io_buffer *iobuf,
				struct sockaddr_tcpip *st_dest,
				struct icmp_echo_protocol *echo_protocol ) {
	struct icmp_echo *echo = iobuf->data;
	int rc;

	/* Set type */
	echo->icmp.type = echo_protocol->reply;

	/* Transmit reply */
	DBGC ( icmpcol ( st_dest ), "ICMP TX echo reply id %04x seq %04x\n",
	       ntohs ( echo->ident ), ntohs ( echo->sequence ) );
	if ( ( rc = icmp_tx_echo ( iobuf, st_dest, echo_protocol ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Process a received ICMP echo request
 *
 * @v iobuf		I/O buffer
 * @v st_src		Source socket address
 * @v echo_protocol	ICMP echo protocol
 * @ret rc		Return status code
 */
int icmp_rx_echo_request ( struct io_buffer *iobuf,
			   struct sockaddr_tcpip *st_src,
			   struct icmp_echo_protocol *echo_protocol ) {
	struct icmp_echo *echo = iobuf->data;
	int rc;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *echo ) ) {
		DBGC ( icmpcol ( st_src ), "ICMP RX echo request too short at "
		       "%zd bytes (min %zd bytes)\n",
		       iob_len ( iobuf ), sizeof ( *echo ) );
		free_iob ( iobuf );
		return -EINVAL;
	}
	DBGC ( icmpcol ( st_src ), "ICMP RX echo request id %04x seq %04x\n",
	       ntohs ( echo->ident ), ntohs ( echo->sequence ) );

	/* Transmit echo reply */
	if ( ( rc = icmp_tx_echo_reply ( iobuf, st_src, echo_protocol ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Process a received ICMP echo request
 *
 * @v iobuf		I/O buffer
 * @v st_src		Source socket address
 * @ret rc		Return status code
 */
int icmp_rx_echo_reply ( struct io_buffer *iobuf,
			 struct sockaddr_tcpip *st_src ) {
	struct icmp_echo *echo = iobuf->data;
	int rc;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *echo ) ) {
		DBGC ( icmpcol ( st_src ), "ICMP RX echo reply too short at "
		       "%zd bytes (min %zd bytes)\n",
		       iob_len ( iobuf ), sizeof ( *echo ) );
		free_iob ( iobuf );
		return -EINVAL;
	}
	DBGC ( icmpcol ( st_src ), "ICMP RX echo reply id %04x seq %04x\n",
	       ntohs ( echo->ident ), ntohs ( echo->sequence ) );

	/* Deliver to ping protocol */
	if ( ( rc = ping_rx ( iobuf, st_src ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Receive ping reply (when no ping protocol is present)
 *
 * @v iobuf		I/O buffer
 * @v st_src		Source socket address
 * @ret rc		Return status code
 */
__weak int ping_rx ( struct io_buffer *iobuf,
		     struct sockaddr_tcpip *st_src __unused ) {
	free_iob ( iobuf );
	return 0;
}
