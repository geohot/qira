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
	GDBMACH_EAX,
	GDBMACH_ECX,
	GDBMACH_EDX,
	GDBMACH_EBX,
	GDBMACH_ESP,
	GDBMACH_EBP,
	GDBMACH_ESI,
	GDBMACH_EDI,
	GDBMACH_EIP,
	GDBMACH_EFLAGS,
	GDBMACH_CS,
	GDBMACH_SS,
	GDBMACH_DS,
	GDBMACH_ES,
	GDBMACH_FS,
	GDBMACH_GS,
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

/* Interrupt vectors */
extern void gdbmach_nocode_sigfpe ( void );
extern void gdbmach_nocode_sigtrap ( void );
extern void gdbmach_nocode_sigstkflt ( void );
extern void gdbmach_nocode_sigill ( void );
extern void gdbmach_withcode_sigbus ( void );
extern void gdbmach_withcode_sigsegv ( void );

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
