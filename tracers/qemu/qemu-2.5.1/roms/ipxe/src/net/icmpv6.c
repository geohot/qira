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
#include <byteswap.h>
#include <ipxe/in.h>
#include <ipxe/iobuf.h>
#include <ipxe/tcpip.h>
#include <ipxe/ping.h>
#include <ipxe/icmpv6.h>

/** @file
 *
 * ICMPv6 protocol
 *
 */

/* Disambiguate the various error causes */
#define EHOSTUNREACH_ROUTE						\
	__einfo_error ( EINFO_EHOSTUNREACH_ROUTE )
#define EINFO_EHOSTUNREACH_ROUTE					\
	__einfo_uniqify ( EINFO_EHOSTUNREACH, 0,			\
			  "No route to destination" )
#define EHOSTUNREACH_PROHIBITED						\
	__einfo_error ( EINFO_EHOSTUNREACH_PROHIBITED )
#define EINFO_EHOSTUNREACH_PROHIBITED					\
	__einfo_uniqify ( EINFO_EHOSTUNREACH, 1,			\
			  "Communication administratively prohibited" )
#define EHOSTUNREACH_ADDRESS						\
	__einfo_error ( EINFO_EHOSTUNREACH_ADDRESS )
#define EINFO_EHOSTUNREACH_ADDRESS					\
	__einfo_uniqify ( EINFO_EHOSTUNREACH, 3,			\
			  "Address unreachable" )
#define EHOSTUNREACH_PORT						\
	__einfo_error ( EINFO_EHOSTUNREACH_PORT )
#define EINFO_EHOSTUNREACH_PORT						\
	__einfo_uniqify ( EINFO_EHOSTUNREACH, 4,			\
			  "Port unreachable" )
#define EHOSTUNREACH_CODE( code )					\
	EUNIQ ( EINFO_EHOSTUNREACH, ( (code) & 0x1f ),			\
		EHOSTUNREACH_ROUTE, EHOSTUNREACH_PROHIBITED,		\
		EHOSTUNREACH_ADDRESS, EHOSTUNREACH_PORT )

#define ETIMEDOUT_HOP							\
	__einfo_error ( EINFO_ETIMEDOUT_HOP )
#define EINFO_ETIMEDOUT_HOP						\
	__einfo_uniqify ( EINFO_ETIMEDOUT, 0,				\
			  "Hop limit exceeded in transit" )
#define ETIMEDOUT_REASSEMBLY						\
	__einfo_error ( EINFO_ETIMEDOUT_REASSEMBLY )
#define EINFO_ETIMEDOUT_REASSEMBLY					\
	__einfo_uniqify ( EINFO_ETIMEDOUT, 1,				\
			  "Fragment reassembly time exceeded" )
#define ETIMEDOUT_CODE( code )						\
	EUNIQ ( EINFO_ETIMEDOUT, ( (code) & 0x1f ),			\
		ETIMEDOUT_HOP, ETIMEDOUT_REASSEMBLY )

#define EPROTO_BAD_HEADER						\
	__einfo_error ( EINFO_EPROTO_BAD_HEADER )
#define EINFO_EPROTO_BAD_HEADER						\
	__einfo_uniqify ( EINFO_EPROTO, 0,				\
			  "Erroneous header field" )
#define EPROTO_NEXT_HEADER						\
	__einfo_error ( EINFO_EPROTO_NEXT_HEADER )
#define EINFO_EPROTO_NEXT_HEADER					\
	__einfo_uniqify ( EINFO_EPROTO, 1,				\
			  "Unrecognised next header type" )
#define EPROTO_OPTION							\
	__einfo_error ( EINFO_EPROTO_OPTION )
#define EINFO_EPROTO_OPTION						\
	__einfo_uniqify ( EINFO_EPROTO, 2,				\
			  "Unrecognised IPv6 option" )
#define EPROTO_CODE( code )						\
	EUNIQ ( EINFO_EPROTO, ( (code) & 0x1f ),			\
		EPROTO_BAD_HEADER, EPROTO_NEXT_HEADER, EPROTO_OPTION )

struct icmp_echo_protocol icmpv6_echo_protocol __icmp_echo_protocol;

/**
 * Process received ICMPv6 echo request packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v sin6_src		Source socket address
 * @v sin6_dest		Destination socket address
 * @ret rc		Return status code
 */
static int icmpv6_rx_echo_request ( struct io_buffer *iobuf,
				    struct net_device *netdev __unused,
				    struct sockaddr_in6 *sin6_src,
				    struct sockaddr_in6 *sin6_dest __unused ) {
	struct sockaddr_tcpip *st_src =
		( ( struct sockaddr_tcpip * ) sin6_src );

	return icmp_rx_echo_request ( iobuf, st_src, &icmpv6_echo_protocol );
}

/** ICMPv6 echo request handler */
struct icmpv6_handler icmpv6_echo_request_handler __icmpv6_handler = {
	.type = ICMPV6_ECHO_REQUEST,
	.rx = icmpv6_rx_echo_request,
};

/**
 * Process received ICMPv6 echo reply packet
 *
 * @v iobuf		I/O buffer
 * @v netdev		Network device
 * @v sin6_src		Source socket address
 * @v sin6_dest		Destination socket address
 * @ret rc		Return status code
 */
static int icmpv6_rx_echo_reply ( struct io_buffer *iobuf,
				  struct net_device *netdev __unused,
				  struct sockaddr_in6 *sin6_src,
				  struct sockaddr_in6 *sin6_dest __unused ) {
	struct sockaddr_tcpip *st_src =
		( ( struct sockaddr_tcpip * ) sin6_src );

	return icmp_rx_echo_reply ( iobuf, st_src );
}

/** ICMPv6 echo reply handler */
struct icmpv6_handler icmpv6_echo_reply_handler __icmpv6_handler = {
	.type = ICMPV6_ECHO_REPLY,
	.rx = icmpv6_rx_echo_reply,
};

/**
 * Identify ICMPv6 handler
 *
 * @v type		ICMPv6 type
 * @ret handler		ICMPv6 handler, or NULL if not found
 */
static struct icmpv6_handler * icmpv6_handler ( unsigned int type ) {
	struct icmpv6_handler *handler;

	for_each_table_entry ( handler, ICMPV6_HANDLERS ) {
		if ( handler->type == type )
			return handler;
	}
	return NULL;
}

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
static int icmpv6_rx ( struct io_buffer *iobuf, struct net_device *netdev,
		       struct sockaddr_tcpip *st_src,
		       struct sockaddr_tcpip *st_dest, uint16_t pshdr_csum ) {
	struct sockaddr_in6 *sin6_src = ( ( struct sockaddr_in6 * ) st_src );
	struct sockaddr_in6 *sin6_dest = ( ( struct sockaddr_in6 * ) st_dest );
	struct icmp_header *icmp = iobuf->data;
	size_t len = iob_len ( iobuf );
	struct icmpv6_handler *handler;
	unsigned int csum;
	int rc;

	/* Sanity check */
	if ( len < sizeof ( *icmp ) ) {
		DBGC ( netdev, "ICMPv6 packet too short at %zd bytes (min %zd "
		       "bytes)\n", len, sizeof ( *icmp ) );
		rc = -EINVAL;
		goto done;
	}

	/* Verify checksum */
	csum = tcpip_continue_chksum ( pshdr_csum, icmp, len );
	if ( csum != 0 ) {
		DBGC ( netdev, "ICMPv6 checksum incorrect (is %04x, should be "
		       "0000)\n", csum );
		DBGC_HDA ( netdev, 0, icmp, len );
		rc = -EINVAL;
		goto done;
	}

	/* Identify handler */
	handler = icmpv6_handler ( icmp->type );
	if ( ! handler ) {
		switch ( icmp->type ) {
		case ICMPV6_DESTINATION_UNREACHABLE:
			rc = -EHOSTUNREACH_CODE ( icmp->code );
			break;
		case ICMPV6_PACKET_TOO_BIG:
			rc = -ERANGE;
			break;
		case ICMPV6_TIME_EXCEEDED:
			rc = -ETIMEDOUT_CODE ( icmp->code );
			break;
		case ICMPV6_PARAMETER_PROBLEM:
			rc = -EPROTO_CODE ( icmp->code );
			break;
		default:
			DBGC ( netdev, "ICMPv6 unrecognised type %d code %d\n",
			       icmp->type, icmp->code );
			rc = -ENOTSUP;
			break;
		};
		goto done;
	}

	/* Pass to handler */
	if ( ( rc = handler->rx ( iob_disown ( iobuf ), netdev, sin6_src,
				  sin6_dest ) ) != 0 ) {
		DBGC ( netdev, "ICMPv6 could not handle type %d: %s\n",
		       icmp->type, strerror ( rc ) );
		goto done;
	}

 done:
	free_iob ( iobuf );
	return rc;
}

/** ICMPv6 TCP/IP protocol */
struct tcpip_protocol icmpv6_protocol __tcpip_protocol = {
	.name = "ICMPv6",
	.rx = icmpv6_rx,
	.tcpip_proto = IP_ICMP6,
};

/** ICMPv6 echo protocol */
struct icmp_echo_protocol icmpv6_echo_protocol __icmp_echo_protocol = {
	.family = AF_INET6,
	.request = ICMPV6_ECHO_REQUEST,
	.reply = ICMPV6_ECHO_REPLY,
	.tcpip_protocol = &icmpv6_protocol,
	.net_checksum = 1,
};
