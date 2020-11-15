#ifndef _IPXE_UDP_H
#define _IPXE_UDP_H

/** @file
 *
 * UDP protocol
 *
 * This file defines the iPXE UDP API.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>
#include <ipxe/iobuf.h>
#include <ipxe/tcpip.h>
#include <ipxe/if_ether.h>

struct interface;
struct sockaddr;

/**
 * UDP constants
 */

/**
 * A UDP header
 */
struct udp_header {
	/** Source port */
	uint16_t src;
	/** Destination port */
	uint16_t dest;
	/** Length */
	uint16_t len;
	/** Checksum */
	uint16_t chksum;
};

extern int udp_open_promisc ( struct interface *xfer );
extern int udp_open ( struct interface *xfer, struct sockaddr *peer,
		      struct sockaddr *local );

#endif /* _IPXE_UDP_H */

