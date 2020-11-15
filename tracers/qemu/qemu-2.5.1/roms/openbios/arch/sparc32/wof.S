/*
 * Proll takes this from Sparclinux kernel, ruthlessly truncated
 * because we have no user windows.
 *
 *   Copyright (C) 1995 David S. Miller (davem@caip.rutgers.edu)
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
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 */

// #include <asm/winmacro.h>
// #include <asm/asmmacro.h>

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

/* Store the register window onto the 8-byte aligned area starting
 * at %reg.  It might be %sp, it might not, we don't care.
 */
#define STORE_WINDOW(reg) \
	std	%l0, [%reg + RW_L0]; \
	std	%l2, [%reg + RW_L2]; \
	std	%l4, [%reg + RW_L4]; \
	std	%l6, [%reg + RW_L6]; \
	std	%i0, [%reg + RW_I0]; \
	std	%i2, [%reg + RW_I2]; \
	std	%i4, [%reg + RW_I4]; \
	std	%i6, [%reg + RW_I6];

/* We define macro's for registers which have a fixed
 * meaning throughout this entire routine.  The 'T' in
 * the comments mean that the register can only be
 * accessed when in the 'trap' window, 'G' means
 * accessible in any window.  Do not change these registers
 * after they have been set, until you are ready to return
 * from the trap.
 */
#define t_psr       l0 /* %psr at trap time                     T */
#define t_pc        l1 /* PC for trap return                    T */
#define t_npc       l2 /* NPC for trap return                   T */
#define t_wim       l3 /* %wim at trap time                     T */
#define saved_g5    l5 /* Global save register                  T */
#define saved_g6    l6 /* Global save register                  T */

/* Now registers whose values can change within the handler.      */
#define twin_tmp    l4 /* Temp reg, only usable in trap window  T */
#define glob_tmp    g5 /* Global temporary reg, usable anywhere G */

	.text
	.align	4

	/* BEGINNING OF PATCH INSTRUCTIONS */
	/* On a 7-window Sparc the boot code patches spnwin_*
	 * instructions with the following ones.
	 */
	.globl	spnwin_patch1_7win, spnwin_patch2_7win, spnwin_patch3_7win
spnwin_patch1_7win:	sll	%t_wim, 6, %glob_tmp
spnwin_patch2_7win:	and	%glob_tmp, 0x7f, %glob_tmp
spnwin_patch3_7win:	and	%twin_tmp, 0x7f, %twin_tmp
	/* END OF PATCH INSTRUCTIONS */

	/* The trap entry point has done the following:
	 *
	 * rd    %psr, %l0
	 * rd    %wim, %l3
	 * b     spill_window_entry
	 * nop
	 */

	.globl	spill_window_entry
	.globl	spnwin_patch1, spnwin_patch2
spill_window_entry:
	/* LOCATION: Trap Window */

	mov	%g5, %saved_g5		! save away global temp register
	mov	%g6, %saved_g6		! save away 'current' ptr register

	/* Compute what the new %wim will be if we save the
	 * window properly in this trap handler.
	 *
	 * newwim = ((%wim>>1) | (%wim<<(nwindows - 1)));
	 */
		srl	%t_wim, 0x1, %twin_tmp
spnwin_patch1:	sll	%t_wim, 7, %glob_tmp
		or	%glob_tmp, %twin_tmp, %glob_tmp
spnwin_patch2:	and	%glob_tmp, 0xff, %glob_tmp

	/* Save into the window which must be saved and do it.
	 */
	save	%g0, %g0, %g0		! save into the window to stash away
	wr	%glob_tmp, 0x0, %wim	! set new %wim, this is safe now

	/* LOCATION: Window to be saved */

	STORE_WINDOW(sp)		! stash the window
	restore	%g0, %g0, %g0		! go back into trap window

	/* LOCATION: Trap window */
	mov	%saved_g5, %g5		! restore %glob_tmp
	mov	%saved_g6, %g6		! restore %curptr
	wr	%t_psr, 0x0, %psr	! restore condition codes in %psr
	nop; nop; nop			! waste some time
	jmp	%t_pc			! Return from trap
	rett	%t_npc			! we are done
