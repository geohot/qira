/******************************************************************************
 * Copyright (c) 2004, 2011 IBM Corporation
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
#include <cpu.h>

	.text

/****************************************************************************
 * prints one character to serial console
 *
 * Input:
 * R3 - character
 *
 * Returns: -
 *
 * Modifies Registers:
 * R3, R4, R5, R6, R7
 ****************************************************************************/
ENTRY(io_putchar)
	sldi	r6,r3,(24+32)
	li	r3,0x58
	li	r4,0
	li	r5,1
	.long 0x44000022
	blr
	
ENTRY(io_getchar)
	mr	r10,r3
	li	r3,0x54
	li	r4,0
	.long 0x44000022
	mr.	r3,r4
	beq	1f
	srdi	r3,r5,(24+32)
	stb	r3,0(r10)
1:	blr
