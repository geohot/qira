#ifndef _IPXE_ICMP6_H
#define _IPXE_ICMP6_H

/** @file
 *
 * ICMPv6 protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/tables.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/icmp.h>

/** An ICMPv6 handler */
struct icmpv6_handler {
	/** Type */
	unsigned int type;
	/** Process received packet
	 *
	 * @v iobuf		I/O buffer
	 * @v netdev		Network device
	 * @v sin6_src		Source socket address
	 * @v sin6_dest		Destination socket address
	 * @ret rc		Return status code
	 *
	 * This function takes ownership of the I/O buffer.
	 */
	int ( * rx ) ( struct io_buffer *iobuf, struct net_device *netdev,
		       struct sockaddr_in6 *sin6_src,
		       struct sockaddr_in6 *sin6_dest );
};

/** ICMPv6 handler table */
#define ICMPV6_HANDLERS __table ( struct icmpv6_handler, "icmpv6_handlers" )

/** Declare an ICMPv6 handler */
#define __icmpv6_handler __table_entry ( ICMPV6_HANDLERS, 01 )

/** ICMPv6 destination unreachable */
#define ICMPV6_DESTINATION_UNREACHABLE 1

/** ICMPv6 packet too big */
#define ICMPV6_PACKET_TOO_BIG 2

/** ICMPv6 time exceeded */
#define ICMPV6_TIME_EXCEEDED 3

/** ICMPv6 parameter problem */
#define ICMPV6_PARAMETER_PROBLEM 4

/** ICMPv6 echo request */
#define ICMPV6_ECHO_REQUEST 128

/** ICMPv6 echo reply */
#define ICMPV6_ECHO_REPLY 129

/** ICMPv6 router solicitation */
#define ICMPV6_ROUTER_SOLICITATION 133

/** ICMPv6 router advertisement */
#define ICMPV6_ROUTER_ADVERTISEMENT 134

/** ICMPv6 neighbour solicitation */
#define ICMPV6_NEIGHBOUR_SOLICITATION 135

/** ICMPv6 neighbour advertisement */
#define ICMPV6_NEIGHBOUR_ADVERTISEMENT 136

extern struct tcpip_protocol icmpv6_protocol __tcpip_protocol;

#endif /* _IPXE_ICMP6_H */
