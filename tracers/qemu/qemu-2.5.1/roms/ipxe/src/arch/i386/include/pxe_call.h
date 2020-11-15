#ifndef _PXE_CALL_H
#define _PXE_CALL_H

/** @file
 *
 * PXE API entry point
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <pxe_api.h>
#include <realmode.h>
#include <setjmp.h>

struct net_device;

/** PXE load address segment */
#define PXE_LOAD_SEGMENT 0

/** PXE load address offset */
#define PXE_LOAD_OFFSET 0x7c00

/** PXE physical load address */
#define PXE_LOAD_PHYS ( ( PXE_LOAD_SEGMENT << 4 ) + PXE_LOAD_OFFSET )

/** !PXE structure */
extern struct s_PXE __text16 ( ppxe );
#define ppxe __use_text16 ( ppxe )

/** PXENV+ structure */
extern struct s_PXENV __text16 ( pxenv );
#define pxenv __use_text16 ( pxenv )

/** PXENV_RESTART_TFTP jump buffer */
extern rmjmp_buf pxe_restart_nbp;

extern void pxe_activate ( struct net_device *netdev );
extern int pxe_deactivate ( void );
extern int pxe_start_nbp ( void );
extern __asmcall void pxe_api_call ( struct i386_all_regs *ix86 );
extern int pxe_api_call_weak ( struct i386_all_regs *ix86 );

#endif /* _PXE_CALL_H */
