/* Common definitions for QEMU Emulation PALcode

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

#ifndef PAL_H
#define PAL_H 1

/* General Purpose Registers.  */
#define	v0	$0
#define t0	$1
#define t1	$2
#define t2	$3
#define t3	$4
#define t4	$5
#define t5	$6
#define a0	$16
#define a1	$17
#define a2	$18
#define a3	$19
#define a4	$20
#define a5	$21
#define t8	$22
#define t9	$23
#define t10	$24

/* PALcode Shadow Registers.  These registers are swapped out when
   QEMU is in PALmode.  Unlike real hardware, there is no enable bit.
   However, also unlike real hardware, the originals can be accessed
   via MTPR/MFPR.  */
#define p0	$8
#define p1	$9
#define p2	$10
#define p3	$11
#define p4	$12
#define p5	$13
#define p6	$14		// Used to save exc_addr for machine check
#define p7	$25

/* QEMU Processor Registers.  */
#define	qemu_ps		0
#define qemu_fen	1
#define qemu_pcc_ofs	2
#define qemu_trap_arg0	3
#define qemu_trap_arg1	4
#define qemu_trap_arg2	5
#define qemu_exc_addr	6
#define qemu_palbr	7
#define qemu_ptbr	8
#define qemu_vptptr	9
#define qemu_unique	10
#define qemu_sysval	11
#define qemu_usp	12

#define qemu_shadow0	32
#define qemu_shadow1	33
#define qemu_shadow2	34
#define qemu_shadow3	35
#define qemu_shadow4	36
#define qemu_shadow5	37
#define qemu_shadow6	38
#define qemu_shadow7	39

/* PALcode Processor Register Private Storage.  */
#define pt0		40
#define pt1		41
#define pt2		42
#define pt3		43
#define pt4		44
#define pt5		45
#define pt6		46
#define pt7		47
#define pt8		48
#define pt9		49
#define pt10		50
#define pt11		51
#define pt12		52
#define pt13		53
#define pt14		54
#define pt15		55
#define pt16		56
#define pt17		57
#define pt18		58
#define pt19		59
#define pt20		60
#define pt21		61
#define pt22		62
#define pt23		63

/* QEMU function calls, via mtpr.  */
#define qemu_tbia	255
#define qemu_tbis	254
#define qemu_wait	253
#define qemu_halt	252
#define qemu_alarm	251
#define qemu_walltime	250
#define qemu_vmtime	249

/* PALcode uses of the private storage slots.  */
#define ptEntUna	pt0
#define ptEntIF		pt1
#define ptEntSys	pt2
#define ptEntInt	pt3
#define ptEntArith	pt4
#define ptEntMM		pt5
#define ptMces		pt6
#define ptKsp		pt7
#define ptKgp		pt8
#define ptPcbb		pt9
#define ptPgp		pt10
#define ptMisc		pt11
#define ptMchk0		pt12
#define ptMchk1		pt13
#define ptMchk2		pt14
#define ptMchk3		pt15
#define ptMchk4		pt16
#define ptMchk5		pt17
#define ptSys0		pt18
#define ptSys1		pt19

/*
 * Shortcuts for various PALmode instructions.
 */
#define mtpr	hw_mtpr
#define mfpr	hw_mfpr
#define stq_p	hw_stq/p
#define stl_p	hw_stl/p
#define ldl_p	hw_ldl/p
#define ldq_p	hw_ldq/p

/* QEMU recognizes the EV4/EV5 HW_REI instruction as a special case of
   the EV6 HW_RET instruction.  This pulls the destination address from
   the EXC_ADDR processor register.  */
#define hw_rei	hw_ret ($31)


.macro	ENDFN	function
	.type	\function, @function
	.size	\function, . - \function
.endm

#endif /* PAL_H */
