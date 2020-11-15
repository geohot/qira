#ifndef GDBMACH_H
#define GDBMACH_H

/** @file
 *
 * GDB architecture specifics
 *
 * This file declares functions for manipulating the machine state and
 * debugging context.
 *
 */

#include <stdint.h>

typedef unsigned long gdbreg_t;

/* The register snapshot, this must be in sync with interrupt handler and the
 * GDB protocol. */
enum {
	// STUB: don't expect this to work!
	GDBMACH_EIP,
	GDBMACH_EFLAGS,
	GDBMACH_NREGS,
	GDBMACH_SIZEOF_REGS = GDBMACH_NREGS * sizeof ( gdbreg_t )
};

/* Breakpoint types */
enum {
	GDBMACH_BPMEM,
	GDBMACH_BPHW,
	GDBMACH_WATCH,
	GDBMACH_RWATCH,
	GDBMACH_AWATCH,
};

static inline void gdbmach_set_pc ( gdbreg_t *regs, gdbreg_t pc ) {
	regs [ GDBMACH_EIP ] = pc;
}

static inline void gdbmach_set_single_step ( gdbreg_t *regs, int step ) {
	regs [ GDBMACH_EFLAGS ] &= ~( 1 << 8 ); /* Trace Flag (TF) */
	regs [ GDBMACH_EFLAGS ] |= ( step << 8 );
}

static inline void gdbmach_breakpoint ( void ) {
	__asm__ __volatile__ ( "int $3\n" );
}

extern int gdbmach_set_breakpoint ( int type, unsigned long addr, size_t len, int enable );

extern void gdbmach_init ( void );

#endif /* GDBMACH_H */
