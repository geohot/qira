#ifndef _IPXE_GDBSERIAL_H
#define _IPXE_GDBSERIAL_H

/** @file
 *
 * GDB remote debugging over serial
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

struct gdb_transport;

extern struct gdb_transport * gdbserial_configure ( unsigned int port,
						    unsigned int baud,
						    uint8_t lcr );

#endif /* _IPXE_GDBSERIAL_H */
