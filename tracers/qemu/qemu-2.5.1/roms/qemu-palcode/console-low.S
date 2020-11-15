/* Assembly helper routines for the emulation SRM console.

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

	.set nomacro
	.set noat
	.text
	.cfi_sections .debug_frame

#define SAVE_ALL_SIZE	(18*8)

	.globl	entInt
	.type	entInt, @function
	.cfi_startproc simple
entInt:
	.cfi_return_column 64
	.cfi_def_cfa	$sp, 48
	.cfi_rel_offset	64, 8
	.cfi_rel_offset	$gp, 16
	.cfi_rel_offset	$16, 24
	.cfi_rel_offset	$17, 32
	.cfi_rel_offset	$18, 40
	lda	$sp, -SAVE_ALL_SIZE($sp)
	.cfi_adjust_cfa_offset SAVE_ALL_SIZE
	stq	$0, 0*8($sp)
	stq	$1, 1*8($sp)
	stq	$2, 2*8($sp)
	stq	$3, 3*8($sp)
	stq	$4, 4*8($sp)
	stq	$5, 5*8($sp)
	stq	$6, 6*8($sp)
	stq	$7, 7*8($sp)
	stq	$8, 9*8($sp)
	stq	$19, 9*8($sp)
	stq	$20, 10*8($sp)
	stq	$21, 11*8($sp)
	stq	$22, 12*8($sp)
	stq	$23, 13*8($sp)
	stq	$24, 14*8($sp)
	stq	$25, 15*8($sp)
	stq	$26, 16*8($sp)
	stq	$27, 17*8($sp)
	stq	$28, 18*8($sp)
	.cfi_rel_offset $0, 0*8
	.cfi_rel_offset $1, 1*8
	.cfi_rel_offset $2, 2*8
	.cfi_rel_offset $3, 3*8
	.cfi_rel_offset $4, 4*8
	.cfi_rel_offset $5, 5*8
	.cfi_rel_offset $6, 6*8
	.cfi_rel_offset $7, 7*8
	.cfi_rel_offset $8, 8*8
	.cfi_rel_offset $19, 9*8
	.cfi_rel_offset $20, 10*8
	.cfi_rel_offset $21, 11*8
	.cfi_rel_offset $22, 12*8
	.cfi_rel_offset $23, 13*8
	.cfi_rel_offset $24, 14*8
	.cfi_rel_offset $25, 15*8
	.cfi_rel_offset $26, 16*8
	.cfi_rel_offset $27, 17*8
	.cfi_rel_offset $28, 18*8

	bsr	$26, do_entInt	!samegp

	ldq	$0, 0*8($sp)
	ldq	$1, 1*8($sp)
	ldq	$2, 2*8($sp)
	ldq	$3, 3*8($sp)
	ldq	$4, 4*8($sp)
	ldq	$5, 5*8($sp)
	ldq	$6, 6*8($sp)
	ldq	$7, 7*8($sp)
	ldq	$8, 9*8($sp)
	ldq	$19, 9*8($sp)
	ldq	$20, 10*8($sp)
	ldq	$21, 11*8($sp)
	ldq	$22, 12*8($sp)
	ldq	$23, 13*8($sp)
	ldq	$24, 14*8($sp)
	ldq	$25, 15*8($sp)
	ldq	$26, 16*8($sp)
	ldq	$27, 17*8($sp)
	ldq	$28, 18*8($sp)
	lda	$sp, SAVE_ALL_SIZE($sp)
	.cfi_adjust_cfa_offset -SAVE_ALL_SIZE
	.cfi_restore	$0
	.cfi_restore	$1
	.cfi_restore	$2
	.cfi_restore	$3
	.cfi_restore	$4
	.cfi_restore	$5
	.cfi_restore	$6
	.cfi_restore	$7
	.cfi_restore	$8
	.cfi_restore	$19
	.cfi_restore	$20
	.cfi_restore	$21
	.cfi_restore	$22
	.cfi_restore	$23
	.cfi_restore	$24
	.cfi_restore	$25
	.cfi_restore	$26
	.cfi_restore	$27
	.cfi_restore	$28

	call_pal 0x3f // rti

	.cfi_endproc
	.size	entInt, . - entInt
