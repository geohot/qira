/*
 * Copyright (C) 2008 Stefan Hajnoczi <stefanha@gmail.com>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <ipxe/uaccess.h>
#include <ipxe/gdbstub.h>
#include <librm.h>
#include <gdbmach.h>

/** @file
 *
 * GDB architecture-specific bits for i386
 *
 */

enum {
	DR7_CLEAR = 0x00000400,    /* disable hardware breakpoints */
	DR6_CLEAR = 0xffff0ff0,    /* clear breakpoint status */
};

/** Hardware breakpoint, fields stored in x86 bit pattern form */
struct hwbp {
	int type;           /* type (1=write watchpoint, 3=access watchpoint) */
	unsigned long addr; /* linear address */
	size_t len;         /* length (0=1-byte, 1=2-byte, 3=4-byte) */
	int enabled;
};

static struct hwbp hwbps [ 4 ];
static gdbreg_t dr7 = DR7_CLEAR;

static struct hwbp *gdbmach_find_hwbp ( int type, unsigned long addr, size_t len ) {
	struct hwbp *available = NULL;
	unsigned int i;
	for ( i = 0; i < sizeof hwbps / sizeof hwbps [ 0 ]; i++ ) {
		if ( hwbps [ i ].type == type && hwbps [ i ].addr == addr && hwbps [ i ].len == len ) {
			return &hwbps [ i ];
		}
		if ( !hwbps [ i ].enabled ) {
			available = &hwbps [ i ];
		}
	}
	return available;
}

static void gdbmach_commit_hwbp ( struct hwbp *bp ) {
	unsigned int regnum = bp - hwbps;

	/* Set breakpoint address */
	assert ( regnum < ( sizeof hwbps / sizeof hwbps [ 0 ] ) );
	switch ( regnum ) {
		case 0:
			__asm__ __volatile__ ( "movl %0, %%dr0\n" : : "r" ( bp->addr ) );
			break;
		case 1:
			__asm__ __volatile__ ( "movl %0, %%dr1\n" : : "r" ( bp->addr ) );
			break;
		case 2:
			__asm__ __volatile__ ( "movl %0, %%dr2\n" : : "r" ( bp->addr ) );
			break;
		case 3:
			__asm__ __volatile__ ( "movl %0, %%dr3\n" : : "r" ( bp->addr ) );
			break;
	}

	/* Set type */
	dr7 &= ~( 0x3 << ( 16 + 4 * regnum ) );
	dr7 |= bp->type << ( 16 + 4 * regnum );

	/* Set length */
	dr7 &= ~( 0x3 << ( 18 + 4 * regnum ) );
	dr7 |= bp->len << ( 18 + 4 * regnum );

	/* Set/clear local enable bit */
	dr7 &= ~( 0x3 << 2 * regnum );
 	dr7 |= bp->enabled << 2 * regnum;
}

int gdbmach_set_breakpoint ( int type, unsigned long addr, size_t len, int enable ) {
	struct hwbp *bp;
	
	/* Check and convert breakpoint type to x86 type */
	switch ( type ) {
		case GDBMACH_WATCH:
			type = 0x1;
			break;
		case GDBMACH_AWATCH:
			type = 0x3;
			break;
		default:
			return 0; /* unsupported breakpoint type */
	}

	/* Only lengths 1, 2, and 4 are supported */
	if ( len != 2 && len != 4 ) {
		len = 1;
	}
	len--; /* convert to x86 breakpoint length bit pattern */

	/* Calculate linear address by adding segment base */
	addr += virt_offset;

	/* Set up the breakpoint */
	bp = gdbmach_find_hwbp ( type, addr, len );
	if ( !bp ) {
		return 0; /* ran out of hardware breakpoints */
	}
	bp->type = type;
	bp->addr = addr;
	bp->len = len;
	bp->enabled = enable;
	gdbmach_commit_hwbp ( bp );
	return 1;
}

static void gdbmach_disable_hwbps ( void ) {
	/* Store and clear hardware breakpoints */
	__asm__ __volatile__ ( "movl %0, %%dr7\n" : : "r" ( DR7_CLEAR ) );
}

static void gdbmach_enable_hwbps ( void ) {
	/* Clear breakpoint status register */
	__asm__ __volatile__ ( "movl %0, %%dr6\n" : : "r" ( DR6_CLEAR ) );

	/* Restore hardware breakpoints */
	__asm__ __volatile__ ( "movl %0, %%dr7\n" : : "r" ( dr7 ) );
}

__asmcall void gdbmach_handler ( int signo, gdbreg_t *regs ) {
	gdbmach_disable_hwbps();
	gdbstub_handler ( signo, regs );
	gdbmach_enable_hwbps();
}

static void * gdbmach_interrupt_vectors[] = {
	gdbmach_nocode_sigfpe,		/* Divide by zero */
	gdbmach_nocode_sigtrap,		/* Debug trap */
	NULL,				/* Non-maskable interrupt */
	gdbmach_nocode_sigtrap,		/* Breakpoint */
	gdbmach_nocode_sigstkflt,	/* Overflow */
	gdbmach_nocode_sigstkflt,	/* Bound range exceeded */
	gdbmach_nocode_sigill,		/* Invalid opcode */
	NULL,				/* Device not available */
	gdbmach_withcode_sigbus,	/* Double fault */
	NULL,				/* Coprocessor segment overrun */
	gdbmach_withcode_sigsegv,	/* Invalid TSS */
	gdbmach_withcode_sigsegv,	/* Segment not present */
	gdbmach_withcode_sigsegv,	/* Stack segment fault */
	gdbmach_withcode_sigsegv,	/* General protection fault */
	gdbmach_withcode_sigsegv,	/* Page fault */
};

void gdbmach_init ( void ) {
	unsigned int i;

	for ( i = 0 ; i < ( sizeof ( gdbmach_interrupt_vectors ) /
			    sizeof ( gdbmach_interrupt_vectors[0] ) ) ; i++ ) {
		set_interrupt_vector ( i, gdbmach_interrupt_vectors[i] );
	}
}
