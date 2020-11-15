#ifndef _IPXE_GDBSTUB_H
#define _IPXE_GDBSTUB_H

/** @file
 *
 * GDB remote debugging
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/tables.h>
#include <gdbmach.h>

/**
 * A transport mechanism for the GDB protocol
 *
 */
struct gdb_transport {
	/** Transport name */
	const char *name;
	/**
	 * Set up the transport given a list of arguments
	 *
	 * @v argc Number of arguments
	 * @v argv Argument list
	 * @ret Return status code
	 *
	 * Note that arguments start at argv[0].
	 */
	int ( * init ) ( int argc, char **argv );
	/**
	 * Perform a blocking read
	 *
	 * @v buf Buffer
	 * @v len Size of buffer
	 * @ret Number of bytes read into buffer
	 */
	size_t ( * recv ) ( char *buf, size_t len );
	/**
	 * Write, may block
	 *
	 * @v buf Buffer
	 * @v len Size of buffer
	 */
	void ( * send ) ( const char *buf, size_t len );
};

#define GDB_TRANSPORTS __table ( struct gdb_transport, "gdb_transports" )

#define __gdb_transport __table_entry ( GDB_TRANSPORTS, 01 )

/**
 * Look up GDB transport by name
 *
 * @v name Name of transport
 * @ret GDB transport or NULL
 */
extern struct gdb_transport *find_gdb_transport ( const char *name );

/**
 * Break into the debugger using the given transport
 *
 * @v trans GDB transport
 */
extern void gdbstub_start ( struct gdb_transport *trans );

/**
 * Interrupt handler
 *
 * @signo POSIX signal number
 * @regs CPU register snapshot
 **/
extern void gdbstub_handler ( int signo, gdbreg_t *regs );

#endif /* _IPXE_GDBSTUB_H */
