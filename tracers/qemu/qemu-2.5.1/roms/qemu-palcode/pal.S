/* QEMU Emulation PALcode.

   Copyright (C) 2011 Richard Henderson

   This file is part of QEMU PALcode.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the text
   of the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.  If not see
   <http://www.gnu.org/licenses/>.  */

	.set		noat
	.set		nomacro
	.text

#include "pal.h"
#include "osf.h"
#include SYSTEM_H

/*
 * Create a standard kernel entry stack frame.
 */

.macro	STACK_FRAME save_ps, save_pc, temp, do_ps
	// Test if we're currently in user mode
	and	\save_ps, PS_M_CM, \temp
	beq	\temp, 0f
	// Switch to kernel mode
.ifne \do_ps
	mtpr	$31, qemu_ps
.endif
	mtpr	$sp, qemu_usp
	mfpr	$sp, ptKsp
	// Allocate the stack frame
0:	lda	$sp, -FRM_K_SIZE($sp)
	stq	\save_ps, FRM_Q_PS($sp)
	stq	\save_pc, FRM_Q_PC($sp)
	stq	$gp, FRM_Q_GP($sp)
	stq	a0, FRM_Q_A0($sp)
	stq	a1, FRM_Q_A1($sp)
	stq	a2, FRM_Q_A2($sp)
.endm

/*
 * Allocate a 1 page stack for use by the console.
 */
#define STACK_SIZE	8192

/*
 * QEMU emulator "hardware" entry points.
 */

/*
 * Reset
 * 
 * INPUT PARAMETERS:
 * 
 *	trap_arg0 = Memory size
 *	trap_arg1 = Kernel entry (if loaded)
 */ 
        .org	0x0000
	.globl	__start
__start:
	// Initialize GP.
	br	$gp, .+4
	ldah	$gp, 0($gp)			!gpdisp!1
	lda	$gp, 0($gp)			!gpdisp!1
	mtpr	$gp, ptPgp

	// Disable interrupts; kernel mode
	lda	t0, IPL_K_HIGH
	mtpr	t0, qemu_ps

	// Initialize Stack.
	SYS_WHAMI a0
	lda	t0, STACK_SIZE
	addq	a0, 1, t1
	mull	t0, t1, t0
	ldah	t1, stack($gp)			!gprelhigh
	lda	t1, stack(t1)			!gprellow
	addq	t0, t1, $sp

	// Do any necessary system setup required for PALmode,
	// e.g. setting up ptSys[01].
	bsr	$26, Sys_Setup

	// Non-boot CPUs can go wait now.
	bne	a0, 1f

	// Load boot arguments
	mfpr	a0, qemu_trap_arg0
	mfpr	a1, qemu_trap_arg1
	mfpr	a2, qemu_trap_arg2

	// Continue in do_start, outside PALmode.
	ldah	$27, do_start($gp)		!gprelhigh
	lda	$27, do_start($27)		!gprellow
	hw_ret	($27)

1:	ldah	$27, do_start_wait($gp)		!gprelhigh
	lda	$27, do_start_wait($27)		!gprellow
	hw_ret	($27)
ENDFN	__start

/*
 * Machine Check
 *
 * INPUT PARAMETERS:
 * 
 *	trap_arg0 = 
 *	trap_arg1 = 
 *	trap_arg2 = 
 */
	.org	0x0080
Pal_Mchk:
	halt
ENDFN	Pal_Mchk

/*
 * Interprocessor Interrupt
 *
 * INPUT PARAMETERS:
 *
 *	trap_arg0 = 
 *	trap_arg1 =
 *	trap_arg2 =
 *
 * The interprocessor interrupt is special, in that PALcode is supposed
 * to clear the interupt and not wait for the OS to do it.
 */
	.org	0x0100
Pal_Smp_Interrupt:
	mfpr	p6, qemu_exc_addr

	SYS_ACK_SMP p0, p1, p2

	mfpr	p0, qemu_ps

	STACK_FRAME p0, p6, p2, 0

	mov	IPL_K_IP, p0		// Raise IPL
	mtpr	p0, qemu_ps

	mfpr	p6, ptEntInt
	mfpr	$gp, ptKgp
	lda	a0, INT_K_IP
	lda	a1, 0
	lda	a2, 0

	hw_ret	(p6)
ENDFN	Pal_Smp_Interrupt

/*
 * Clock Interrupt
 *
 * INPUT PARAMETERS:
 *
 *	trap_arg0 = 
 *	trap_arg1 =
 *	trap_arg2 =
 *
 * The clock interrupt is special, in that PALcode is supposed
 * to clear the interupt and not wait for the OS to do it.
 */
	.org	0x0180
Pal_Clk_Interrupt:
	mfpr	p6, qemu_exc_addr

	SYS_ACK_CLK p0, p1, p2

	mfpr	p0, qemu_ps

	STACK_FRAME p0, p6, p2, 0

	mov	IPL_K_CLK, p0		// Raise IPL
	mtpr	p0, qemu_ps

	mfpr	p6, ptEntInt
	mfpr	$gp, ptKgp
	lda	a0, INT_K_CLK
	lda	a1, 0
	lda	a2, 0

9:	hw_ret	(p6)
ENDFN	Pal_Clk_Interrupt

/*
 * Device Interrupt
 *
 * INPUT PARAMETERS:
 *
 *	trap_arg0 = 
 *	trap_arg1 =
 *	trap_arg2 =
 */ 
	.org	0x0200
Pal_Dev_Interrupt:
	mfpr	p6, qemu_exc_addr
	mfpr	p0, qemu_ps

	STACK_FRAME p0, p6, p2, 0

	mov	IPL_K_DEV1, p0		// Raise IPL
	mtpr	p0, qemu_ps

	bsr	p7, Sys_Dev_Vector

	mfpr	p7, ptEntInt
	mfpr	$gp, ptKgp
	lda	a0, INT_K_DEV
	lda	a2, 0
	hw_ret	(p7)
ENDFN	Pal_Dev_Interrupt

/*
 * Memory Fault
 *
 * INPUT PARAMETERS:
 *
 *	trap_arg0 = faulting address
 *	trap_arg1 = fault type (TNV, ACV, FOR, FOW, FOE)
 *	trap_arg2 = access type (exec=-1, read=0, write=1)
 */ 
	.org	0x0280
Pal_MMFault:
	mfpr	p0, qemu_ps
	mfpr	p6, qemu_exc_addr
	blbs	p6, MchkBugCheck

	STACK_FRAME p0, p6, p2, 1

	mfpr	p0, ptEntMM
	mfpr	$gp, ptKgp
	mfpr	a0, qemu_trap_arg0
	mfpr	a1, qemu_trap_arg1
	mfpr	a2, qemu_trap_arg2
	hw_ret	(p0)
ENDFN	Pal_MMFault

/*
 * Unaligned Data
 * 
 * INPUT PARAMETERS:
 *
 *	trap_arg0 = faulting address
 *	trap_arg1 = opcode of faulting insn
 *	trap_arg2 = src/dst register number
 */ 
	.org	0x0300
Pal_Unalign:
	mfpr	p0, qemu_ps
	mfpr	p6, qemu_exc_addr
	addq	p6, 4, p1		// increment past the faulting insn
	blbs	p6, MchkBugCheck

	STACK_FRAME p0, p1, p2, 1

	mfpr	p0, ptEntUna
	mfpr	$gp, ptKgp
	mfpr	a0, qemu_trap_arg0
	mfpr	a1, qemu_trap_arg1
	mfpr	a2, qemu_trap_arg2
	hw_ret	(p0)
ENDFN	Pal_Unalign

/*
 * Illegal Opcode
 *
 * INPUT PARAMETERS:
 *
 *	trap_arg0 = UNDEFINED
 *	trap_arg1 = UNDEFINED
 *	trap_arg2 = UNDEFINED
 *
 * OUTPUT PARAMETERS:
 *
 *	r16 (a0) = Instruction fault code
 *	r17 (a1) = UNPREDICTABLE
 *	r18 (a2) = UNPREDICTABLE
 */ 
	.org	0x0380
Pal_OpcDec:
	mfpr	p0, qemu_ps
	mfpr	p6, qemu_exc_addr
	addq	p6, 4, p1		// increment past the faulting insn
	blbs	p6, MchkBugCheck

	STACK_FRAME p0, p1, p2, 1

	mfpr	p0, ptEntIF
	mfpr	$gp, ptKgp
	mov	IF_K_OPCDEC, a0
	hw_ret	(p0)
ENDFN	Pal_OpcDec

/*
 * Arithmetic Trap
 *
 * INPUT PARAMETERS:
 *
 *	trap_arg0 = exception type
 *	trap_arg1 = register modification mask
 *	trap_arg2 = UNDEFINED
 */
	.org	0x0400
Pal_Arith:
	mfpr	p0, qemu_ps
	mfpr	p6, qemu_exc_addr
	blbs	p6, MchkBugCheck

	STACK_FRAME p0, p6, p2, 1

	mfpr	p0, ptEntArith
	mfpr	$gp, ptKgp
	mfpr	a0, qemu_trap_arg0
	mfpr	a1, qemu_trap_arg1
	hw_ret	(p0)
ENDFN	Pal_Arith

/*
 * Floating Point Disabled
 *
 * INPUT PARAMETERS:
 *
 *	trap_arg0 = UNDEFINED
 *	trap_arg1 = UNDEFINED
 *	trap_arg2 = UNDEFINED
 *
 * OUTPUT PARAMETERS:
 *
 *	r16 (a0) = Instruction fault code
 *	r17 (a1) = UNPREDICTABLE
 *	r18 (a2) = UNPREDICTABLE
 */ 
	.org	0x0480
Pal_Fen:
	mfpr	p0, qemu_ps
	mfpr	p6, qemu_exc_addr
	blbs	p6, MchkBugCheck

	STACK_FRAME p0, p6, p2, 1

	mfpr	p0, ptEntIF
	mfpr	$gp, ptKgp
	mov	IF_K_FEN, a0
	hw_ret	(p0)
ENDFN	Pal_Fen

/*
 * OSF/1 Privileged CALL_PAL Entry Points
 */

#define ORG_CALL_PAL_PRIV(X)	.org	0x1000+64*X

/*
 * Halt
 *
 * SIDE EFFECTS:
 *
 *	We either power down the system or re-enter the console.
 *	But given that we're not returning to the kernel, there's
 *	no reason to continue processing in assembler.  Go to C.
 */
	ORG_CALL_PAL_PRIV(0x00)
CallPal_Halt:
	bsr	p7, UpdatePCB		// Save kernel data
	lda	v0, HLT_K_SW_HALT	// FIXME store this somewhere.

	mtpr	$31, qemu_halt

	br	Sys_EnterConsole
ENDFN	CallPal_Halt

/*
 * Cache Flush
 *
 * For QEMU, this is of course a no-op.
 */
	ORG_CALL_PAL_PRIV(0x01)
CallPal_Cflush:
	hw_rei
ENDFN	CallPal_Cflush

/*
 * Drain Aborts
 *
 * For QEMU, this is of course a no-op.
 */
        ORG_CALL_PAL_PRIV(0x02)
CallPal_Draina:
	hw_rei
ENDFN	CallPal_Draina

	ORG_CALL_PAL_PRIV(0x03)
CallPal_OpcDec03:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec03

	ORG_CALL_PAL_PRIV(0x04)
CallPal_OpcDec04:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec04

	ORG_CALL_PAL_PRIV(0x05)
CallPal_OpcDec05:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec05

	ORG_CALL_PAL_PRIV(0x06)
CallPal_OpcDec06:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec06

	ORG_CALL_PAL_PRIV(0x07)
CallPal_OpcDec07:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec07

	ORG_CALL_PAL_PRIV(0x08)
CallPal_OpcDec08:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec08

/*
 * Console Service
 * 
 * INPUT PARAMETERS:
 * 
 *	r16 (a0)          = Option selector
 *	r17..r21 (a1..a5) = Implementation specific entry parameters
 *
 * SIDE EFFECTS:
 *
 *	Registers a0..a5, and v0 are UNPREDICTABLE upon return.
 */ 
	ORG_CALL_PAL_PRIV(0x09)
CallPal_Cserve:
	// Most of the entries are densely clustered around 0.
	mov	0, v0
	cmpule	a0, 7, p0
	cmovne	p0, a0, v0
	br	p0, 1f
1:	lda	p0, Cserve_Table-1b(p0)
	s8addq	v0, p0, p0
	jmp	$31, (p0), 0
ENDFN	CallPal_Cserve

	.text	1
	.align	3
/* Note that the entries in the following table are all 2 insns.
   The first entry is unused, and is also where all out-of-range
   commands are vectored.  */
Cserve_Table:
	br	CallPal_Cserve_Cont
	nop
Cserve_Ldqp:
	ldq_p	v0, 0(a1)
	hw_rei
ENDFN	Cserve_Ldqp
Cserve_Stqp:
	stq_p	a2, 0(a1)
	hw_rei
ENDFN	Cserve_Stqp
Cserve_Get_Wall_Time:
	mfpr	v0, qemu_walltime
	hw_rei
ENDFN	Cserve_Get_Wall_Time
Cserve_Get_Alarm:
	mfpr	v0, qemu_alarm
	hw_rei
ENDFN	Cserve_Get_Alarm
Cserve_Set_Alarm_Rel:
	// Cheating here: create the absolute time and fall thru.
	mfpr	p0, qemu_vmtime
	addq	p0, a1, a1
ENDFN	Cserve_Set_Alarm_Rel
Cserve_Set_Alarm_Abs:
	mtpr	a1, qemu_alarm
	hw_rei
ENDFN	Cserve_Set_Alarm_Abs
Cserve_Get_VM_Time:
	mfpr	v0, qemu_vmtime
	hw_rei
ENDFN	Cserve_Get_VM_Time


CallPal_Cserve_Cont:
	// ??? For SRM compatibility and their use within Linux, use 52/53
	// for these.  Anyone know what other "standard" SRM Cserve entry
	// points are?  Certainly we don't want to be compatible with MILO,
	// which puts the selector at A2.
	cmpeq	a0, 52, v0
	bne	v0, Cserve_Ena
	cmpeq	a0, 53, v0
	bne	v0, Cserve_Dis
	hw_rei
ENDFN	CallPal_Cserve_Cont
	.previous

/*
 * Swap PALcode
 *
 * FUNCTIONAL DESCRIPTION:
 *
 *	The swap PALcode (swppal) function replaces the current 
 *	(active) PALcode by the specified new PALcode image.  
 *	This function is intended for use by operating systems 
 *	only during bootstraps and restarts, or during transitions 
 *	to console I/O mode.
 * 
 *	The PALcode descriptor passed in a0 is interpreted as
 *	either a PALcode variant or the base physical address
 *	of the new PALcode image.  If a variant, the PALcode
 *	image must have been previously loaded.  No PALcode
 *	loading occurs as a result of this function. 
 *
 *	NOTE:
 *	This implementation of SWPPAL does not support PALcode
 *	variants.  If a variant is specified in a0, a check is
 *	performed to determine whether the variant is OSF/1 or
 *	not and the returned status is either unknown variant
 *	(if not OSF/1) or variant not loaded.
 *
 * INPUT PARAMETERS:
 *
 *	r16 (a0) = New PALcode variant or base physical address
 *	r17 (a1) = New PC
 *	r18 (a2) = New PCB
 *	r19 (a3) = New VptPtr
 * 
 * OUTPUT PARAMETERS:
 *
 *	r0 (v0) = Returned status indicating:
 *			0 - Success (PALcode was switched)
 *			1 - Unknown PALcode variant
 *			2 - Known PALcode variant, but PALcode not loaded
 *
 *	r26 (ra) = r27 (pv) = New PC
 *		Note that this is non-architected, but is relied on by
 *		the usage of SwpPal within our own console code in order
 *		to simplify its use within C code.
 *
 */
	ORG_CALL_PAL_PRIV(0x0A)
CallPal_SwpPal:
	// Save a copy of the return address in case of machine check.
	mfpr	p6, qemu_exc_addr

	// Accept swapping to OSF PALcode.  The side effect here is to
	// load the other parameters for the kernel.
	cmpeq	a0, 2, v0
	bne	v0, CallPal_SwpPal_Cont

	// Return as an unknown PALcode variant
	mov	1, v0
	hw_rei
ENDFN	CallPal_SwpPal

	.text	1
CallPal_SwpPal_Cont:
	rpcc	p0
	mtpr	a2, ptPcbb
	mtpr	a3, qemu_vptptr

	ldq_p	$sp, PCB_Q_KSP(a2)
	ldq_p	t0, PCB_Q_USP(a2)
	ldq_p	t1, PCB_Q_PTBR(a2)
	ldl_p	t2, PCB_L_PCC(a2)
	ldq_p	t3, PCB_Q_UNIQUE(a2)
	ldq_p	t4, PCB_Q_FEN(a2)

	mtpr	t0, qemu_usp

	sll	t1, VA_S_OFF, t1
	mtpr	t1, qemu_ptbr

	subl	t2, p0, t2
	mtpr	t2, qemu_pcc_ofs

	mtpr	t3, qemu_unique

	and	t4, 1, t4
	mtpr	t4, qemu_fen

	mtpr	$31, qemu_tbia		// Flush TLB for new PTBR

	mov	a1, $26
	mov	a1, $27
	hw_ret	(a1)
ENDFN	CallPal_SwpPal_Cont
	.previous

	ORG_CALL_PAL_PRIV(0x0B)
CallPal_OpcDec0B:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec0B

	ORG_CALL_PAL_PRIV(0x0C)
CallPal_OpcDec0C:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec0C

/*
 * Write Interprocessor Interrupt Request
 *
 * INPUT PARAMETERS:
 *
 *	r16 (a0) = target processor number 
 * 
 * OUTPUT PARAMETERS:
 *
 * SIDE EFFECTS:
 * 
 */ 
        ORG_CALL_PAL_PRIV(0x0D)
CallPal_WrIpir:
	// Save a copy of the return address in case of machine check.
	mfpr	p6, qemu_exc_addr

	SYS_WRIPIR	a0, p0, p1, p2

	hw_rei
ENDFN	CallPal_WrIpir

	ORG_CALL_PAL_PRIV(0x0E)
CallPal_OpcDec0E:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec0E

	ORG_CALL_PAL_PRIV(0x0F)
CallPal_OpcDec0F:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec0F

/*
 * Read Machine Check Error Summary
 *
 * INPUT PARAMETERS:
 * 
 * OUTPUT PARAMETERS:
 *
 *	r0 (v0) = returned MCES value
 * 
 * SIDE EFFECTS:
 *
 */ 
        ORG_CALL_PAL_PRIV(0x10)
CallPal_RdMces:
	mfpr	v0, ptMces		// Get current MCES value
	and	v0, MCES_M_ALL, v0	// Clear all other bits
	hw_rei
ENDFN	CallPal_RdMces

/*
 * Write Machine Check Error Summary
 *
 * INPUT PARAMETERS:
 * 
 *	r16 (a0) = MCES<DPC> <- a0<3>,  MCES<DSC> <- a0<4>
 * 
 * OUTPUT PARAMETERS:
 *
 * SIDE EFFECTS:
 *
 *	Registers t0, t8..t11, and a0 are UNPREDICTABLE upon return.
 */ 
        ORG_CALL_PAL_PRIV(0x11)
CallPal_WrMces:
	// Clear MIP, SCE, PCE
	and	a0, (MCES_M_MIP | MCES_M_SCE | MCES_M_PCE), p0
	mfpr	p1, ptMces
	bic	p1, p0, p1

	// Copy DPC and DSC
	and	a0, (MCES_M_DPC | MCES_M_DSC), p0
	bic	p1, (MCES_M_DPC | MCES_M_DSC), p1
	or	p1, p0, p1

	mtpr	p1, ptMces
	hw_rei
ENDFN	CallPal_WrMces

	ORG_CALL_PAL_PRIV(0x12)
CallPal_OpcDec12:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec12

	ORG_CALL_PAL_PRIV(0x13)
CallPal_OpcDec13:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec13

	ORG_CALL_PAL_PRIV(0x14)
CallPal_OpcDec14:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec14

	ORG_CALL_PAL_PRIV(0x15)
CallPal_OpcDec15:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec15

	ORG_CALL_PAL_PRIV(0x16)
CallPal_OpcDec16:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec16

	ORG_CALL_PAL_PRIV(0x17)
CallPal_OpcDec17:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec17

	ORG_CALL_PAL_PRIV(0x18)
CallPal_OpcDec18:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec18

	ORG_CALL_PAL_PRIV(0x19)
CallPal_OpcDec19:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec19

	ORG_CALL_PAL_PRIV(0x1A)
CallPal_OpcDec1A:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec1A

	ORG_CALL_PAL_PRIV(0x1B)
CallPal_OpcDec1B:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec1B

	ORG_CALL_PAL_PRIV(0x1C)
CallPal_OpcDec1C:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec1C

	ORG_CALL_PAL_PRIV(0x1D)
CallPal_OpcDec1D:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec1D

	ORG_CALL_PAL_PRIV(0x1E)
CallPal_OpcDec1E:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec1E

	ORG_CALL_PAL_PRIV(0x1F)
CallPal_OpcDec1F:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec1F

	ORG_CALL_PAL_PRIV(0x20)
CallPal_OpcDec20:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec20

	ORG_CALL_PAL_PRIV(0x21)
CallPal_OpcDec21:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec21

	ORG_CALL_PAL_PRIV(0x22)
CallPal_OpcDec22:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec22

	ORG_CALL_PAL_PRIV(0x23)
CallPal_OpcDec23:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec23

	ORG_CALL_PAL_PRIV(0x24)
CallPal_OpcDec24:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec24

	ORG_CALL_PAL_PRIV(0x25)
CallPal_OpcDec25:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec25

	ORG_CALL_PAL_PRIV(0x26)
CallPal_OpcDec26:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec26

	ORG_CALL_PAL_PRIV(0x27)
CallPal_OpcDec27:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec27

	ORG_CALL_PAL_PRIV(0x28)
CallPal_OpcDec28:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec28

	ORG_CALL_PAL_PRIV(0x29)
CallPal_OpcDec29:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec29

	ORG_CALL_PAL_PRIV(0x2A)
CallPal_OpcDec2A:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec2A

/*
 * Write Floating Point Enable
 *
 * INPUT PARAMETERS:
 * 
 *	r16 (a0) = ICSR<FPE> <- a0<0>
 * 
 * SIDE EFFECTS:
 *
 *	Registers t0, t8..t11, and a0 are UNPREDICTABLE upon return.
 */ 
        ORG_CALL_PAL_PRIV(0x2B)
CallPal_WrFen:
	mfpr	p0, ptPcbb		// Get PCBB
	and	a0, 1, a0		// Clean new FEN value to single bit
	mtpr	a0, qemu_fen
	stl_p	a0, PCB_Q_FEN(p0)	// Write new PCB<FEN>
	hw_rei
ENDFN	CallPal_WrFen

	ORG_CALL_PAL_PRIV(0x2C)
CallPal_OpcDec2C:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec2C

/*
 * Write Virtual Page Table Pointer
 *
 * INPUT PARAMETERS:
 *
 *	r16 (a0) = New virtual page table pointer 
 *
 * SIDE EFFECTS:
 *
 *	Registers t0, t8..t11, and a0 are UNPREDICTABLE upon return.
 */ 
        ORG_CALL_PAL_PRIV(0x2D)
CallPal_WrVptPtr:
	mtpr	a0, qemu_vptptr
	hw_rei
ENDFN	CallPal_WrVptPtr

	ORG_CALL_PAL_PRIV(0x2E)
CallPal_OpcDec2E:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec2E

	ORG_CALL_PAL_PRIV(0x2F)
CallPal_OpcDec2F:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec2F

/*
 * Swap Process Context
 *
 * FUNCTIONAL DESCRIPTION:
 *
 *	The swap process context (swpctx) function saves 
 *	the current process data in the current PCB, then 
 *	switches to the PCB passed in a0 and loads the
 *	new process context.  The old PCB is returned in v0.	
 * 
 * INPUT PARAMETERS:
 * 
 *	r16 (a0) = New PCBB 
 * 
 * OUTPUT PARAMETERS:
 *
 *	r0  (v0) = Old PCBB
 * 
 * SIDE EFFECTS:
 *
 *	Registers t0, t8..t11, and a0 are UNPREDICTABLE upon return.
 */ 
	ORG_CALL_PAL_PRIV(0x30)
CallPal_SwpCtx:
	rpcc	p5			// Get cycle counter
	mfpr	p6, qemu_exc_addr	// Save exc_addr for machine check

	mfpr	v0, ptPcbb		// Get current PCBB
	mtpr	a0, ptPcbb		// Save new PCBB
	srl	p5, 32, p7		// Move CC<OFFSET> to low longword

	addl	p5, p7, p7		// Accumulate time for old pcb
	stl_p	p7, PCB_L_PCC(v0)

	ldl_p	t9, PCB_L_PCC(a0)	// Get new PCC
	subl	t9, p5, p5		// Generate and ...
	mtpr	p5, qemu_pcc_ofs	// .. set new CC<OFFSET> bits

	stq_p	$sp, PCB_Q_KSP(v0)	// Store old kernel stack pointer
	mfpr	t10, qemu_usp		// Save old user stack pointer
	stq_p	t10, PCB_Q_USP(v0)

	br	CallPal_SwpCtx_Cont
ENDFN	CallPal_SwpCtx

	.text	1
CallPal_SwpCtx_Cont:
	ldq_p	$sp, PCB_Q_KSP(a0)	// Install new stack pointers
	ldq_p	t10, PCB_Q_USP(a0)
	mtpr	t10, qemu_usp

	mfpr	t10, qemu_unique	// Save old unique value
	stq_p	t10, PCB_Q_UNIQUE(v0)
	ldq_p	t10, PCB_Q_UNIQUE(a0)	// Install new unique value
	mtpr	t10, qemu_unique

	ldq_p	t8, PCB_Q_FEN(a0)	// Install new FEN
	and	t8, 1, t8
	mtpr	t8, qemu_fen

	// QEMU does not implement an ASN; skip that.

	ldq_p	t10, PCB_Q_PTBR(a0)	// Install new page tables
	sll	t10, VA_S_OFF, t10
	mtpr	t10, qemu_ptbr
	mtpr	$31, qemu_tbia		// Flush TLB, since we don't do ASNs

	hw_rei
ENDFN	CallPal_SwpCtx_Cont
	.previous

/*
 * Write System Value
 *
 * INPUT PARAMETERS:
 *
 *	r16 (a0) = New system value 
 * 
 * SIDE EFFECTS:
 *
 *	Registers t0, t8..t11, and a0 are UNPREDICTABLE upon return.
 */ 
        ORG_CALL_PAL_PRIV(0x31)
CallPal_WrVal:
	mtpr	a0, qemu_sysval
	hw_rei
ENDFN	CallPal_WrVal

/*
 * Read System Value
 *
 * OUTPUT PARAMETERS:
 *
 *	r0 (v0) = Returned system value
 * 
 * SIDE EFFECTS:
 *
 *	Registers t0 and t8..t11 are UNPREDICTABLE upon return.
 */ 
        ORG_CALL_PAL_PRIV(0x32)
CallPal_RdVal:
	mfpr	v0, qemu_sysval
	hw_rei
ENDFN	CallPal_RdVal

/*
 * Translation Buffer Invalidate
 * 
 * INPUT PARAMETERS:
 * 
 *	r16 (a0) = tbi selector type:
 *
 *		-2 - Flush all TB entries (tbia)
 *		-1 - Invalidate all TB entries with ASM=0 (tbiap)
 *		 1 - Invalidate ITB entry for va=a1 (tbisi)
 *		 2 - Invalidate DTB entry for va=a1 (tbisd)
 *		 3 - Invalidate both ITB and DTB entry for va=a1 (tbis)
 *
 *	r17 (a1) = VA for TBISx types
 *
 * Qemu does not implement ASNs or split I/D tlbs.  Therefore these
 * collapse to tbia and tbis.
 * 
 * SIDE EFFECTS:
 *
 *	Registers t0, t8..t11, and a0 are UNPREDICTABLE upon return.
 */ 
        ORG_CALL_PAL_PRIV(0x33)
CallPal_Tbi:
	bge	a0, 1f

	mtpr	$31, qemu_tbia
	hw_rei

1:	mtpr	a1, qemu_tbis
	hw_rei
ENDFN	CallPal_Tbi

/*
 * Write System Entry Address
 *
 * INPUT PARAMETERS:
 *
 *	r16 (a0) = VA of system entry point
 *	r17 (a1) = System entry point selector 
 * 
 * SIDE EFFECTS:
 *
 *	Registers t0, t8..t11, and a0..a1 are UNPREDICTABLE
 *	upon return.
 */ 
        ORG_CALL_PAL_PRIV(0x34)
CallPal_WrEnt:
	andnot	a0, 3, a0		// Clean PC<1:0>

	cmpult	a1, 6, t8		// Bound the input
	cmoveq	t8, 6, a1

	br	t0, 1f
1:	lda	t0, WrEnt_Table-1b(t0)
	s8addq	a1, t0, t0
	jmp	$31, (t0), 0
ENDFN	CallPal_WrEnt

	.text	1
WrEnt_Table:
0:	mtpr	a0, ptEntInt
	hw_rei
1:	mtpr	a0, ptEntArith
	hw_rei
2:	mtpr	a0, ptEntMM
	hw_rei
3:	mtpr	a0, ptEntIF
	hw_rei
4:	mtpr	a0, ptEntUna
	hw_rei
5:	mtpr	a0, ptEntSys
	hw_rei
6:	nop
	hw_rei
ENDFN	WrEnt_Table
	.previous

/*
 * Swap Interrupt Priority Level
 * 
 * INPUT PARAMETERS:
 * 
 *	r16 (a0) = New IPL
 * 
 * OUTPUT PARAMETERS:
 *
 *	r0  (v0) = Old IPL
 * 
 * SIDE EFFECTS:
 *
 *	Registers t0, t8..t11, and a0 are UNPREDICTABLE upon return.
 */ 
        ORG_CALL_PAL_PRIV(0x35)
CallPal_SwpIpl:
	mfpr	v0, qemu_ps
	and	a0, PS_M_IPL, a0
	and	v0, PS_M_IPL, v0
	mtpr	a0, qemu_ps
	hw_rei
ENDFN	CallPal_SwpIpl

/*
 * Read Processor Status
 *
 * OUTPUT PARAMETERS:
 *
 *	r0 (v0) = Current PS
 * 
 * SIDE EFFECTS:
 *
 *	Registers t0, t8..t11 are UNPREDICTABLE upon return.
 */ 
        ORG_CALL_PAL_PRIV(0x36)
CallPal_RdPs:
	mfpr	v0, qemu_ps
	hw_rei
ENDFN	CallPal_RdPs

/*
 * Write Kernel Global Pointer
 *
 * INPUT PARAMETERS:
 * 
 *	r16 (a0) = New KGP value
 *
 * SIDE EFFECTS:
 *
 *	Registers t0, t8..t11, and a0 are UNPREDICTABLE upon return.
 */ 
        ORG_CALL_PAL_PRIV(0x37)
CallPal_WrKgp:
	mtpr	a0, ptKgp
	hw_rei
ENDFN	CallPal_WrKgp

/*
 * Write User Stack Pointer
 * 
 * INPUT PARAMETERS:
 * 
 *	r16 (a0) = New user stack pointer value
 * 
 * SIDE EFFECTS:
 *
 *	Registers t0, t8..t11, and a0 are UNPREDICTABLE upon return.
 */ 
        ORG_CALL_PAL_PRIV(0x38)
CallPal_WrUsp:
	mtpr	a0, qemu_usp
	hw_rei
ENDFN	CallPal_WrUsp

/*
 * Write Performance Monitor
 *
 * INPUT PARAMETERS:
 * 
 *	r16 (a0) = New user stack pointer value
 * 
 * SIDE EFFECTS:
 *
 *	Registers t0, t8..t11, and a0 are UNPREDICTABLE upon return.
 */
	ORG_CALL_PAL_PRIV(0x39)
CallPal_WrPerfMon:
	// Not implemented
	hw_rei
ENDFN	CallPal_WrPerfMon

/*
 * Read User Stack Pointer
 * 
 * OUTPUT PARAMETERS:
 *
 *	r0 (v0) = User stack pointer value
 * 
 * SIDE EFFECTS:
 *
 *	Registers t0, and t8..t11 are UNPREDICTABLE upon return.
 */ 
        ORG_CALL_PAL_PRIV(0x3A)
CallPal_RdUsp:
	mfpr	v0, qemu_usp
	hw_rei
ENDFN	CallPal_RdUsp

	ORG_CALL_PAL_PRIV(0x3B)
CallPal_OpcDec3B:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec3B

/*
 * Who Am I
 * 
 * OUTPUT PARAMETERS:
 *
 *	r0 (v0) = Current processor number
 * 
 * SIDE EFFECTS:
 *
 *	Registers t0 and t8..t11 are UNPREDICTABLE upon return.
 */ 
        ORG_CALL_PAL_PRIV(0x3C)
CallPal_Whami:
	SYS_WHAMI v0
	hw_rei
ENDFN	CallPal_Whami

/*
 * Return From System Call
 *
 * INPUT PARAMETERS:
 * 
 *	r30 (sp) = Pointer to the top of the kernel stack
 * 
 * OUTPUT PARAMETERS:
 *
 *	r29 (gp) = Restored user mode global pointer
 *	r30 (sp) = User stack pointer
 * 
 * SIDE EFFECTS:
 *
 *	Registers t0 and t8..t11 are UNPREDICTABLE upon return.
 */ 
        ORG_CALL_PAL_PRIV(0x3D)
CallPal_RetSys:
	ldq	t9, FRM_Q_PC($sp)	// Pop the return address
	ldq	$gp, FRM_Q_GP($sp)	// Get the user mode global pointer
	lda	t8, FRM_K_SIZE($sp)
	mtpr	t8, ptKsp

	mov	PS_K_USER, t8		// Set new mode to user
	mtpr	t8, qemu_ps

	mfpr	$sp, qemu_usp		// Get the user stack pointer

	andnot	t9, 3, t9		// Clean return PC<1:0>
	hw_ret	(t9)
ENDFN	CallPal_RetSys

/*
 * Wait For Interrupt
 *
 * FUNCTIONAL DESCRIPTION:
 *
 *	If possible, wait for the first of either of the following
 *	conditions before returning: any interrupt other than a clock
 *	tick; or the first clock tick after a specified number of clock
 *	ticks have bbeen skipped.
 *
 * INPUT PARAMETERS:
 * 
 *	r16 (a0) = Maximum number of clock ticks to skip
 * 
 * OUTPUT PARAMETERS:
 *
 *	r0 (v0) = Number of clock ticks actually skipped.
 */
	ORG_CALL_PAL_PRIV(0x3E)
CallPal_WtInt:
	mtpr	$31, qemu_wait
	mov	0, v0
	hw_rei
ENDFN	CallPal_WtInt

/*
 * Return From Trap, Fault, or Interrupt
 *
 * INPUT PARAMETERS:
 * 
 *	r30 (sp) = Pointer to the top of the kernel stack
 * 
 * OUTPUT PARAMETERS:
 *
 *	ps       <- (sp+00)
 *	pc       <- (sp+08)
 *	r29 (gp) <- (sp+16)
 *	r16 (a0) <- (sp+24)
 *	r17 (a1) <- (sp+32)
 *	r18 (a2) <- (sp+40)
 */ 
        ORG_CALL_PAL_PRIV(0x3F)
	.globl	CallPal_Rti
CallPal_Rti:
	mfpr	p6, qemu_exc_addr	// Save exc_addr for machine check

	ldq	p4, FRM_Q_PS($sp)	// Get the PS
	ldq	p5, FRM_Q_PC($sp)	// Get the return PC
	ldq	$gp, FRM_Q_GP($sp)	// Get gp
	ldq	a0, FRM_Q_A0($sp)	// Get a0
	ldq	a1, FRM_Q_A1($sp)	// Get a1
	ldq	a2, FRM_Q_A2($sp)	// Get a2
	lda	$sp, FRM_K_SIZE($sp)	// Pop the stack

	andnot	p5, 3, p5		// Clean return PC<1:0>

	and	p4, PS_M_CM, p3
	bne	p3, CallPal_Rti_ToUser

	and	p4, PS_M_IPL, p4
	mtpr	p4, qemu_ps
	hw_ret	(p5)
ENDFN	CallPal_Rti

	.text	1
CallPal_Rti_ToUser:
	mtpr	p3, qemu_ps
	mtpr	$sp, ptKsp
	mfpr	$sp, qemu_usp
	hw_ret	(p5)
ENDFN	CallPal_Rti_ToUser
	.previous

/*
 * OSF/1 Unprivileged CALL_PAL Entry Points
 */

#define ORG_CALL_PAL_UNPRIV(X)	.org	0x2000+64*(X-0x80)

/*
 * A helper routine for the unprivaledged kernel entry points, since the
 * actual stack frame setup code is just a tad too large to fit inline.
 *
 * INPUT PARAMETERS:
 *
 *	p5 = ps
 *	p6 = exc_addr
 *	p7 = return address
 *
 * SIDE EFFECTS:
 *
 *	p0 is clobbered
 *
 */
	.text	1
CallPal_Stack_Frame:
	// Test if we're currently in user mode
	and	p5, PS_M_CM, p0
	beq	p0, 0f
CallPal_Stack_Frame_FromUser:
	// Switch to kernel mode
	mtpr	$31, qemu_ps
	mtpr	$sp, qemu_usp
	mfpr	$sp, ptKsp
0:
	// Allocate the stack frame
	lda	$sp, -FRM_K_SIZE($sp)
	stq	p5, FRM_Q_PS($sp)
	stq	p6, FRM_Q_PC($sp)
	stq	$gp, FRM_Q_GP($sp)
	stq	a0, FRM_Q_A0($sp)
	stq	a1, FRM_Q_A1($sp)
	stq	a2, FRM_Q_A2($sp)
	ret	$31, (p7), 0
ENDFN	CallPal_Stack_Frame
	.previous

/*
 * Breakpoint Trap
 *
 * OUTPUT PARAMETERS:
 *
 *	r16 (a0) = Code for bpt (0)
 *	r17 (a1) = UNPREDICTABLE
 *	r18 (a2) = UNPREDICTABLE
 */ 
        ORG_CALL_PAL_UNPRIV(0x80)
CallPal_Bpt:
	mfpr	p5, qemu_ps
	mfpr	p6, qemu_exc_addr
	bsr	p7, CallPal_Stack_Frame

	mfpr	p0, ptEntIF
	mfpr	$gp, ptKgp
	mov	IF_K_BPT, a0
	hw_ret	(p0)
ENDFN	CallPal_Bpt

/*
 * Bugcheck Trap
 * 
 * OUTPUT PARAMETERS:
 *
 *	r16 (a0) = Code for bugchk (1)
 *	r17 (a1) = UNPREDICTABLE
 *	r18 (a2) = UNPREDICTABLE
 */ 
        ORG_CALL_PAL_UNPRIV(0x81)
CallPal_BugChk:
	mfpr	p5, qemu_ps
	mfpr	p6, qemu_exc_addr
	bsr	p7, CallPal_Stack_Frame

	mfpr	p0, ptEntIF
	mfpr	$gp, ptKgp
	mov	IF_K_BUGCHK, a0
	hw_ret	(p0)
ENDFN	CallPal_BugChk


	ORG_CALL_PAL_UNPRIV(0x82)
CallPal_OpcDec82:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec82

/*
 * System Call
 */ 
        ORG_CALL_PAL_UNPRIV(0x83)
CallPal_CallSys:
	mfpr	p5, qemu_ps
	mfpr	p6, qemu_exc_addr

	and	p5, PS_M_CM, p0
	beq	p0, 0f

	bsr	p7, CallPal_Stack_Frame_FromUser

	mfpr	p0, ptEntSys
	mfpr	$gp, ptKgp
	hw_ret	(p0)

0:	subq	p6, 4, p6		// Get PC of CALL_PAL insn
	br	MchkOSBugCheck
ENDFN	CallPal_CallSys

	ORG_CALL_PAL_UNPRIV(0x84)
CallPal_OpcDec84:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec84

	ORG_CALL_PAL_UNPRIV(0x85)
CallPal_OpcDec85:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec85


/*
 * I-Stream Memory Barrier
 *
 * For QEMU, this is of course a no-op.
 */ 
        ORG_CALL_PAL_UNPRIV(0x86)
CallPal_Imb:
	hw_rei
ENDFN	CallPal_Imb


	ORG_CALL_PAL_UNPRIV(0x87)
CallPal_OpcDec87:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec87

	ORG_CALL_PAL_UNPRIV(0x88)
CallPal_OpcDec88:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec88

	ORG_CALL_PAL_UNPRIV(0x89)
CallPal_OpcDec89:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec89

	ORG_CALL_PAL_UNPRIV(0x8A)
CallPal_OpcDec8A:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec8A

	ORG_CALL_PAL_UNPRIV(0x8B)
CallPal_OpcDec8B:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec8B

	ORG_CALL_PAL_UNPRIV(0x8C)
CallPal_OpcDec8C:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec8C

	ORG_CALL_PAL_UNPRIV(0x8D)
CallPal_OpcDec8D:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec8D

	ORG_CALL_PAL_UNPRIV(0x8E)
CallPal_OpcDec8E:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec8E

	ORG_CALL_PAL_UNPRIV(0x8F)
CallPal_OpcDec8F:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec8F

	ORG_CALL_PAL_UNPRIV(0x90)
CallPal_OpcDec90:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec90

	ORG_CALL_PAL_UNPRIV(0x91)
CallPal_OpcDec91:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec91

	ORG_CALL_PAL_UNPRIV(0x92)
CallPal_OpcDec92:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec92

	ORG_CALL_PAL_UNPRIV(0x93)
CallPal_OpcDec93:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec93

	ORG_CALL_PAL_UNPRIV(0x94)
CallPal_OpcDec94:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec94

	ORG_CALL_PAL_UNPRIV(0x95)
CallPal_OpcDec95:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec95

	ORG_CALL_PAL_UNPRIV(0x96)
CallPal_OpcDec96:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec96

	ORG_CALL_PAL_UNPRIV(0x97)
CallPal_OpcDec97:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec97

	ORG_CALL_PAL_UNPRIV(0x98)
CallPal_OpcDec98:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec98

	ORG_CALL_PAL_UNPRIV(0x99)
CallPal_OpcDec99:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec99

	ORG_CALL_PAL_UNPRIV(0x9A)
CallPal_OpcDec9A:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec9A

	ORG_CALL_PAL_UNPRIV(0x9B)
CallPal_OpcDec9B:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec9B

	ORG_CALL_PAL_UNPRIV(0x9C)
CallPal_OpcDec9C:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec9C

	ORG_CALL_PAL_UNPRIV(0x9D)
CallPal_OpcDec9D:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDec9D

/*
 * Read Unique Value
 * 
 * OUTPUT PARAMETERS:
 *
 *	r0 (v0) = Returned process unique value
*/ 
        ORG_CALL_PAL_UNPRIV(0x9E)
CallPal_RdUnique:
	mfpr	v0, qemu_unique
	hw_rei
ENDFN	CallPal_RdUnique

/*
 * Write Unique Value
 * 
 * INPUT PARAMETERS:
 * 
 *	r16 (a0) = New process unique value
 */ 
        ORG_CALL_PAL_UNPRIV(0x9F)
CallPal_WrUnique:
	mtpr	a0, qemu_unique
	hw_rei
ENDFN	CallPal_WrUnique

	ORG_CALL_PAL_UNPRIV(0xA0)
CallPal_OpcDecA0:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecA0

	ORG_CALL_PAL_UNPRIV(0xA1)
CallPal_OpcDecA1:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecA1

	ORG_CALL_PAL_UNPRIV(0xA2)
CallPal_OpcDecA2:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecA2

	ORG_CALL_PAL_UNPRIV(0xA3)
CallPal_OpcDecA3:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecA3

	ORG_CALL_PAL_UNPRIV(0xA4)
CallPal_OpcDecA4:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecA4

	ORG_CALL_PAL_UNPRIV(0xA5)
CallPal_OpcDecA5:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecA5

	ORG_CALL_PAL_UNPRIV(0xA6)
CallPal_OpcDecA6:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecA6

	ORG_CALL_PAL_UNPRIV(0xA7)
CallPal_OpcDecA7:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecA7

	ORG_CALL_PAL_UNPRIV(0xA8)
CallPal_OpcDecA8:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecA8

	ORG_CALL_PAL_UNPRIV(0xA9)
CallPal_OpcDecA9:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecA9

/*
 * Generate Trap
 *
 * OUTPUT PARAMETERS:
 *
 *	r16 (a0) = Code for gentrap (2)
 *	r17 (a1) = UNPREDICTABLE
 *	r18 (a2) = UNPREDICTABLE
 */ 
        ORG_CALL_PAL_UNPRIV(0xAA)
CallPal_GenTrap:
	mfpr	p5, qemu_ps
	mfpr	p6, qemu_exc_addr
	bsr	p7, CallPal_Stack_Frame

	mfpr	p0, ptEntIF
	mfpr	$gp, ptKgp
	mov	IF_K_GENTRAP, a0
	hw_ret	(p0)
ENDFN	CallPal_GenTrap

	ORG_CALL_PAL_UNPRIV(0xAB)
CallPal_OpcDecAB:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecAB

	ORG_CALL_PAL_UNPRIV(0xAC)
CallPal_OpcDecAC:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecAC

	ORG_CALL_PAL_UNPRIV(0xAD)
CallPal_OpcDecAD:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecAD

	ORG_CALL_PAL_UNPRIV(0xAE)
CallPal_OpcDecAE:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecAE

	ORG_CALL_PAL_UNPRIV(0xAF)
CallPal_OpcDecAF:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecAF

	ORG_CALL_PAL_UNPRIV(0xB0)
CallPal_OpcDecB0:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecB0

	ORG_CALL_PAL_UNPRIV(0xB1)
CallPal_OpcDecB1:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecB1

	ORG_CALL_PAL_UNPRIV(0xB2)
CallPal_OpcDecB2:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecB2

	ORG_CALL_PAL_UNPRIV(0xB3)
CallPal_OpcDecB3:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecB3

	ORG_CALL_PAL_UNPRIV(0xB4)
CallPal_OpcDecB4:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecB4

	ORG_CALL_PAL_UNPRIV(0xB5)
CallPal_OpcDecB5:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecB5

	ORG_CALL_PAL_UNPRIV(0xB6)
CallPal_OpcDecB6:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecB6

	ORG_CALL_PAL_UNPRIV(0xB7)
CallPal_OpcDecB7:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecB7

	ORG_CALL_PAL_UNPRIV(0xB8)
CallPal_OpcDecB8:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecB8

	ORG_CALL_PAL_UNPRIV(0xB9)
CallPal_OpcDecB9:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecB9

	ORG_CALL_PAL_UNPRIV(0xBA)
CallPal_OpcDecBA:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecBA

	ORG_CALL_PAL_UNPRIV(0xBB)
CallPal_OpcDecBB:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecBB

	ORG_CALL_PAL_UNPRIV(0xBC)
CallPal_OpcDecBC:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecBC

	ORG_CALL_PAL_UNPRIV(0xBD)
CallPal_OpcDecBD:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecBD

	ORG_CALL_PAL_UNPRIV(0xBE)
CallPal_OpcDecBE:
	br	CallPal_OpcDec
ENDFN	CallPal_OpcDecBE

	ORG_CALL_PAL_UNPRIV(0xBF)
CallPal_OpcDec:
	mfpr	p5, qemu_ps
	mfpr	p6, qemu_exc_addr
	bsr	p7, CallPal_Stack_Frame

	mfpr	p0, ptEntIF
	mfpr	$gp, ptKgp
	mov	IF_K_OPCDEC, a0
	hw_ret	(p0)
ENDFN	CallPal_OpcDec

	.org	0x3000
	.text	1
/*
 * PALcode detected processor machine check handler.
 *
 *      The PALcode-detected machine check handler loads a code
 *      indicating the type of machine check error, loads 
 *      the System Control Block (SCB) vector for the 
 *      processor machine check service routine, sets the 
 *      Machine-Check-In-Progress (MIP) flag in the Machine
 *      Check Error Summary register (MCES), and merges
 *      with the common machine check flow.
 *
 *      If a second processor machine check error condition 
 *      is detected while the MIP flag is set, the processor 
 *      is forced into console I/O mode indicating "double 
 *      error abort encountered" as the reason for the halt. 
 * 
 * CALLING SEQUENCE:
 * 
 *      Called when an internal processor error is detected
 *      that cannot be successfully corrected by hardware or
 *      PALcode.
 * 
 * INPUT PARAMETERS:
 *
 *      r14 (p6) = Exception address 
 * 
 * OUTPUT PARAMETERS:
 *
 *      ptMchk0         = saved v0
 *      ptMchk1         = saved t0
 *      ptMchk2         = saved t3
 *      ptMchk3         = saved t4
 *      ptMchk4         = saved t5
 *	ptMchk5		= saved exc_addr
 *      ptMisc<47:32>   = MCHK code
 *      ptMisc<31:16>   = SCB vector
 *      ptMces<MIP>     = Set
 * 
 * SIDE EFFECTS:
 *
 *      r0 (v0), r1 (t0), and r4..r6 (t3..t5) are saved in
 *      PAL temporaries and are available for use as scratch
 *      registers by the system specific machine check 
 *      handler.
 */

MchkBugCheck:
MchkOSBugCheck:
	halt
ENDFN	MchkBugCheck

/*
 * Common Machine Check Handler
 *
 * INPUT STATE:
 *
 *      ptMchk0		Saved v0
 *      ptMchk1		Saved t0
 *      ptMchk2		Saved t3
 *      ptMchk3		Saved t4
 *      ptMchk4		Saved t5
 *      ptMchk5		Saved exc_addr
 *      ptMisc<47:32>	MCHK code
 *      ptMisc<31:16>	SCB vector
 *      ptMces<MIP>	Set
 *
 * Registers v0, t0, and t3 .. t5 are available for use, in
 * addition to the shadow registers.
 */

MchkCommon:
	halt
ENDFN	MchkCommon

/*
 * Build Machine Check Logout Frame
 *
 *      This portion of the  machine check handler builds a logout frame
 *      in the PAL impure scratch area, builds a stack frame on the kernel
 *      stack (already built if there was an interrupt machine check),
 *      loads the GP with the KGP, loads the machine check entry 
 *      code in a0, loads a platform-specific interrupt vector 
 *      (typically the same value as the SCB offset) in a1, loads 
 *      the kseg address of the logout area in a2, and dispatches 
 *      to the kernel interrupt handler pointed to by the entInt 
 *      operating system entry point.
 *
 * OUTPUT PARAMETERS:
 * 
 *      a0 (r16) = Machine check entry type
 *      a1 (r17) = Platform-specific interrupt vector
 *      a2 (r18) = Pointer to logout area
 */

.macro	STORE_IPR	which, offset, base
	mfpr	v0, \which
	stq_p	v0, \offset(\base)
.endm

MchkLogOut:
	halt
ENDFN	MchkLogOut

MchkDouble:
	bsr	p7, UpdatePCB
	lda	v0, HLT_K_DBL_MCHK
	br	Sys_EnterConsole
ENDFN	MchkDouble

MchkFromPal:
	bsr	p7, UpdatePCB
	lda	v0, HLT_K_MCHK_FROM_PAL
	br	Sys_EnterConsole
ENDFN	MchkFromPal

MchkKspInvalid:
	bsr	p7, UpdatePCB
	lda	v0, HLT_K_KSP_INVAL
	br	Sys_EnterConsole
ENDFN	MchkKspInvalid

/*
 * Update the current PCB with new SP and CC info.
 *
 * INPUT PARAMETERS:
 *
 *	p7	= return linkage
 */

UpdatePCB:
	rpcc	p5
	mfpr	p4, ptPcbb

	mfpr	p3, qemu_ps		// Check current mode
	and	p3, PS_M_CM, p3
	beq	p3, 1f

	mtpr	$sp, qemu_usp		// Save user stack pointer
	stq_p	$sp, PCB_Q_USP(p4)
	br	2f

1:	mtpr	$sp, ptKsp		// Save kernel stack pointer
	stq_p	$sp, PCB_Q_KSP(p4)

2:	srl	p5, 32, p3		// Merge for new time
	addl	p5, p3, p3
	stl_p	p3, PCB_L_PCC(p4)	// Store new time

	mfpr	p5, qemu_unique		// Save unique
	stq_p	p5, PCB_Q_UNIQUE(p4)

	ret	$31, (p7), 0
ENDFN	UpdatePCB

/*
 * FIXME
 */
Sys_EnterConsole:
	halt

/*
 * Allocate the initial bootup stack.
 */

	.section .bss.stack
	.align 3
	.globl	stack
	.type	stack,@object
	.size	stack,STACK_SIZE
stack:	.skip	STACK_SIZE
