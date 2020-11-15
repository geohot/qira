#ifndef _IPXE_GUESTRPC_H
#define _IPXE_GUESTRPC_H

/** @file
 *
 * VMware GuestRPC mechanism
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/vmware.h>

/** GuestRPC magic number */
#define GUESTRPC_MAGIC 0x49435052 /* "RPCI" */

/** Open RPC channel */
#define GUESTRPC_OPEN 0x00

/** Open RPC channel success status */
#define GUESTRPC_OPEN_SUCCESS 0x00010000

/** Send RPC command length */
#define GUESTRPC_COMMAND_LEN 0x01

/** Send RPC command length success status */
#define GUESTRPC_COMMAND_LEN_SUCCESS 0x00810000

/** Send RPC command data */
#define GUESTRPC_COMMAND_DATA 0x02

/** Send RPC command data success status */
#define GUESTRPC_COMMAND_DATA_SUCCESS 0x00010000

/** Receive RPC reply length */
#define GUESTRPC_REPLY_LEN 0x03

/** Receive RPC reply length success status */
#define GUESTRPC_REPLY_LEN_SUCCESS 0x00830000

/** Receive RPC reply data */
#define GUESTRPC_REPLY_DATA 0x04

/** Receive RPC reply data success status */
#define GUESTRPC_REPLY_DATA_SUCCESS 0x00010000

/** Finish receiving RPC reply */
#define GUESTRPC_REPLY_FINISH 0x05

/** Finish receiving RPC reply success status */
#define GUESTRPC_REPLY_FINISH_SUCCESS 0x00010000

/** Close RPC channel */
#define GUESTRPC_CLOSE 0x06

/** Close RPC channel success status */
#define GUESTRPC_CLOSE_SUCCESS 0x00010000

/** RPC command success status */
#define GUESTRPC_SUCCESS 0x2031 /* "1 " */

extern int guestrpc_open ( void );
extern void guestrpc_close ( int channel );
extern int guestrpc_command ( int channel, const char *command, char *reply,
			      size_t reply_len );

#endif /* _IPXE_GUESTRPC_H */
