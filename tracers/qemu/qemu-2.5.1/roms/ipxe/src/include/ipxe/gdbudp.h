#ifndef _IPXE_GDBUDP_H
#define _IPXE_GDBUDP_H

/** @file
 *
 * GDB remote debugging over UDP
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

struct sockaddr_in;
struct gdb_transport;

/**
 * Set up the UDP transport with network address
 *
 * @name network device name
 * @addr IP address and UDP listen port, may be NULL and fields may be zero
 * @ret transport suitable for starting the GDB stub or NULL on error
 */
struct gdb_transport *gdbudp_configure ( const char *name, struct sockaddr_in *addr );

#endif /* _IPXE_GDBUDP_H */
