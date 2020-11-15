#ifndef _IPXE_PING_H
#define _IPXE_PING_H

/** @file
 *
 * ICMP ping protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/iobuf.h>
#include <ipxe/tcpip.h>

extern int ping_rx ( struct io_buffer *iobuf,
		     struct sockaddr_tcpip *st_src );

#endif /* _IPXE_PING_H */
