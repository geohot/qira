#define __ASSEMBLY
#include "psr.h"
#include "asm/asi.h"

	.text
	.align	4

#define STACKFRAME_SZ     0x60

/* These are just handy. */
#define _SV	save	%sp, -STACKFRAME_SZ, %sp
#define _RS     restore

#define FLUSH_ALL_KERNEL_WINDOWS \
	_SV; _SV; _SV; _SV; _SV; _SV; _SV; \
	_RS; _RS; _RS; _RS; _RS; _RS; _RS;

/* Macro for romvec handlers */
#define ROMVEC_HANDLER(type) \
	\
	.globl type##_handler; \
	\
type##_handler: \
	\
	FLUSH_ALL_KERNEL_WINDOWS; \
	\
	save %sp, -STACKFRAME_SZ - 0x20, %sp; \
	\
	st %g1, [ %sp + STACKFRAME_SZ + 0x0]; \
	st %g2, [ %sp + STACKFRAME_SZ + 0x4]; \
	st %g3, [ %sp + STACKFRAME_SZ + 0x8]; \
	st %g4, [ %sp + STACKFRAME_SZ + 0xc]; \
	st %g5, [ %sp + STACKFRAME_SZ + 0x10]; \
	st %g6, [ %sp + STACKFRAME_SZ + 0x14]; \
	st %g7, [ %sp + STACKFRAME_SZ + 0x18]; \
	\
	mov %i0, %o0; \
	mov %i1, %o1; \
	mov %i2, %o2; \
	mov %i3, %o3; \
	mov %i4, %o4; \
	mov %i5, %o5; \
	\
	call	type; \
	 nop; \
	\
	mov %o0, %i0; \
	\
	ld [ %sp + STACKFRAME_SZ + 0x0], %g1; \
	ld [ %sp + STACKFRAME_SZ + 0x4], %g2; \
	ld [ %sp + STACKFRAME_SZ + 0x8], %g3; \
	ld [ %sp + STACKFRAME_SZ + 0xc], %g4; \
	ld [ %sp + STACKFRAME_SZ + 0x10], %g5; \
	ld [ %sp + STACKFRAME_SZ + 0x14], %g6; \
	ld [ %sp + STACKFRAME_SZ + 0x18], %g7; \
	\
	ret; \
	 restore; \


/* Generate handlers which are proxy functions to the 
   real C functions that correctly save the globals
   and stack */
ROMVEC_HANDLER(obp_devopen)
ROMVEC_HANDLER(obp_devclose)
ROMVEC_HANDLER(obp_rdblkdev)
ROMVEC_HANDLER(obp_nbgetchar)
ROMVEC_HANDLER(obp_nbputchar)
ROMVEC_HANDLER(obp_putstr)
ROMVEC_HANDLER(obp_printf)
ROMVEC_HANDLER(obp_reboot)
ROMVEC_HANDLER(obp_abort)
ROMVEC_HANDLER(obp_halt)
ROMVEC_HANDLER(obp_fortheval_v2)
ROMVEC_HANDLER(obp_inst2pkg)
ROMVEC_HANDLER(obp_dumb_memalloc)
ROMVEC_HANDLER(obp_dumb_memfree)
ROMVEC_HANDLER(obp_dumb_mmap)
ROMVEC_HANDLER(obp_dumb_munmap)
ROMVEC_HANDLER(obp_devread)
ROMVEC_HANDLER(obp_devwrite)
ROMVEC_HANDLER(obp_devseek)
ROMVEC_HANDLER(obp_cpustart)
ROMVEC_HANDLER(obp_cpustop)
ROMVEC_HANDLER(obp_cpuidle)
ROMVEC_HANDLER(obp_cpuresume)
ROMVEC_HANDLER(obp_nextnode)
ROMVEC_HANDLER(obp_child)
ROMVEC_HANDLER(obp_proplen)
ROMVEC_HANDLER(obp_getprop)
ROMVEC_HANDLER(obp_setprop)
ROMVEC_HANDLER(obp_nextprop)
ROMVEC_HANDLER(obp_memalloc)

