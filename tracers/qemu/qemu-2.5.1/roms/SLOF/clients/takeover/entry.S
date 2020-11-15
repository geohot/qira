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

#include <macros.h>
#include "takeover.h"

	.globl	_wrapclient
	.section        ".start"
	.align 3

_wrapclient:
	bcl	20,31,over	# branch after pointer table
base:
	.align  3
.LCgot:		.quad   _got-base
over:
	mflr	r8		# gpr 8 is the base
	ld	r2, .LCgot-base(r8)	# load got pointer
	add	r2, r2, r8		# add base
	li	14, 0
	oris	14, 14, __bssSize@h
	ori	14, 14, __bssSize@l
	addi 14,14,7
	srwi 14,14,3
	mtctr	14
	li	14, 0
	oris	14, 14, __bssStart@h
	ori	14, 14, __bssStart@l
	subi	14, 14, 8
	li	15, 0
1:
	stdu 15,8(14)
	bdnz	1b

	bl ._entry



    .globl slaveLoopNoTakeover
slaveLoopNoTakeover:
	mr 28,3

	li	14,0
	oris	14, 14, slaveQuitt@h
	ori	14, 14, slaveQuitt@l

	li	3,0
	std	3,0(14)
1:
	ld	3,0(14)
	cmpld	3,28
	bne	1b

	li	3,0
	std	3,0(14)

	LOAD64(r3, (TAKEOVERBASEADDRESS+0x150))
	mtctr	r3
	bctr


    .globl slaveLoop
slaveLoop:
	mr 28,3
	li r3, 0x5124
	li r0, -1; .long 0x44000022
	
	li	14,0
	oris	14, 14, slaveQuitt@h
	ori	14, 14, slaveQuitt@l
	li	3,0
	std	3,0(14)
1:
	ld	3,0(14)
	cmpld	3,28
	bne	1b

	li	3,0
	std	3,0(14)

	LOAD64(r3, (TAKEOVERBASEADDRESS+0x150))
	mtctr	r3
	bctr


C_ENTRY(m_sync)
	isync
	sync
	nop
	blr
