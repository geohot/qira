/*
 * Window fill (underflow) trap, based on code from Sparclinux.
 *
 * Copyright (C) 1995 David S. Miller
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2 as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *   MA  02110-1301, USA.
 */

// #include <psr.h>
// #include <asi.h>

/* Reg_window offsets */
#define RW_L0     0x00
#define RW_L1     0x04
#define RW_L2     0x08
#define RW_L3     0x0c
#define RW_L4     0x10
#define RW_L5     0x14
#define RW_L6     0x18
#define RW_L7     0x1c
#define RW_I0     0x20
#define RW_I1     0x24
#define RW_I2     0x28
#define RW_I3     0x2c
#define RW_I4     0x30
#define RW_I5     0x34
#define RW_I6     0x38
#define RW_I7     0x3c

/* Load a register window from the area beginning at %reg. */
#define LOAD_WINDOW(reg) \
	ldd	[%reg + RW_L0], %l0; \
	ldd	[%reg + RW_L2], %l2; \
	ldd	[%reg + RW_L4], %l4; \
	ldd	[%reg + RW_L6], %l6; \
	ldd	[%reg + RW_I0], %i0; \
	ldd	[%reg + RW_I2], %i2; \
	ldd	[%reg + RW_I4], %i4; \
	ldd	[%reg + RW_I6], %i6;

#define WRITE_PAUSE	nop; nop; nop; /* Have to do this after %wim/%psr chg */

/* Just like the overflow handler we define macros for registers
 * with fixed meanings in this routine.
 */
#define t_psr       l0
#define t_pc        l1
#define t_npc       l2
#define t_wim       l3
/* Don't touch the above registers or else you die horribly... */

/* Now macros for the available scratch registers in this routine. */
#define twin_tmp1    l4
#define twin_tmp2    l5

	.text
	.align	4

	/* The trap entry point has executed the following:
	 *
	 * rd    %psr, %l0
	 * rd    %wim, %l3
	 * b     fill_window_entry
	 * andcc %l0, PSR_PS, %g0
	 */

	/* To get an idea of what has just happened to cause this
	 * trap take a look at this diagram:
	 *
	 *      1  2  3  4     <--  Window number
	 *      ----------
	 *      T  O  W  I     <--  Symbolic name
	 *
	 *      O == the window that execution was in when
	 *           the restore was attempted
	 *
	 *      T == the trap itself has save'd us into this
	 *           window
	 *
	 *      W == this window is the one which is now invalid
	 *           and must be made valid plus loaded from the
	 *           stack
	 *
	 *      I == this window will be the invalid one when we
	 *           are done and return from trap if successful
	 */

	/* BEGINNING OF PATCH INSTRUCTIONS */

	/* On 7-window Sparc the boot code patches fnwin_patch1
	 * with the following instruction.
	 */
	.globl	fnwin_patch1_7win, fnwin_patch2_7win
fnwin_patch1_7win:	srl	%t_wim, 6, %twin_tmp2
fnwin_patch2_7win:	and	%twin_tmp1, 0x7f, %twin_tmp1
	/* END OF PATCH INSTRUCTIONS */


	.globl	fill_window_entry, fnwin_patch1, fnwin_patch2
fill_window_entry:
	/* LOCATION: Window 'T' */

	/* Compute what the new %wim is going to be if we retrieve
	 * the proper window off of the stack.
	 */
		sll	%t_wim, 1, %twin_tmp1
fnwin_patch1:	srl	%t_wim, 7, %twin_tmp2
		or	%twin_tmp1, %twin_tmp2, %twin_tmp1
fnwin_patch2:	and	%twin_tmp1, 0xff, %twin_tmp1

	wr	%twin_tmp1, 0x0, %wim	/* Make window 'I' invalid */

	restore	%g0, %g0, %g0		/* Restore to window 'O' */

	/* Trapped from kernel, we trust that the kernel does not
	 * 'over restore' sorta speak and just grab the window
	 * from the stack and return.  Easy enough.
	 */
	/* LOCATION: Window 'O' */

	restore %g0, %g0, %g0
        WRITE_PAUSE

	/* LOCATION: Window 'W' */

	LOAD_WINDOW(sp)	                /* Load it up */

	/* Spin the wheel... */
	save	%g0, %g0, %g0
	save	%g0, %g0, %g0
	/* I'd like to buy a vowel please... */

	/* LOCATION: Window 'T' */

	/* Now preserve the condition codes in %psr, pause, and
	 * return from trap.  This is the simplest case of all.
	 */
	wr	%t_psr, 0x0, %psr
	WRITE_PAUSE

	jmp	%t_pc
	rett	%t_npc
