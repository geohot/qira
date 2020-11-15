/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <rtas.h>		


/*
Function:	
	Input:
		r3:   rtas parm structure	
		r4:   base address
	Output:		

Decription: Main entry point, called from OS. Second parameter is not
	used.	
	
*/
	.globl rtas_entry
rtas_entry:	
	mfmsr	r11		# Get MSR to enable 64-bit mode
	mr	r7,r11
	rotldi	r11,r11,1
	ori	r11,r11,1	# Always enable 64-bit mode flag
	rotldi	r11,r11,63
	mtmsrd	r11		# Switch to 64-bit mode
	isync

	mr r9,r1		# save old stack pointer
	mflr r10		# save link register
	bcl 20,31,.over		# branch to over 
.base:	
	.align  3
..got:			.quad   _got-.base
..stack:		.quad   .stack+RTAS_STACKSIZE-0x60-.base
.over:	
	mflr r8			# gpr 8 is the base
	ld r1,..stack-.base(r8)	# load new stack pointer
	add r1,r1,r8		# add base
	std r2,64(r1)		# save toc
	ld r2,..got-.base(r8)	# load got pointer
	std r7,72(r1)		# save original msr
	std r10,80(r1)		# save link register
	std r9,0(r1)		# save stack pointer
	add r2,r2,r8		# add base

	bl save_regs_r3_r12
	bl .rtas_call
	bl restore_regs_r3_r12

rtas_return:
	ld r11,72(r1)		# restore msr value	
	ld r0,80(r1)		# restore link register value
	ld r2,64(r1)		# restore toc
	ld r1,0(r1)		# get old stack
	mtmsrd r11		# restore msr (32 bit ?)
	isync
	mtlr r0
	blr



	.globl 	.stack
	.lcomm	.stack,RTAS_STACKSIZE
