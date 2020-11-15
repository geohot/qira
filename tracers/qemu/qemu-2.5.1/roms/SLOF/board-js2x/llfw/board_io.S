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
#include <cpu.h>

	.text

C_ENTRY(copy_from_flash)
# size in GPR3 (multiple of 64), from GPR4, to GPR5
	mflr 24 ; mtctr 3 ; addi 4,4,-64 ; addi 5,5,-64
0:	SETCI(r0)
	ldu 16,64(4) ; ld 17,8(4) ; ld 18,16(4) ; ld 19,24(4)
	ld 20,32(4) ; ld 21,40(4) ; ld 22,48(4) ; ld 23,56(4)
	CLRCI(r0)
	stdu 16,64(5) ; std 17,8(5) ; std 18,16(5) ; std 19,24(5)
	std 20,32(5) ; std 21,40(5) ; std 22,48(5) ; std 23,56(5)
	sync ; icbi 0,2 ; bdnz 0b ; sync ; isync ; mtlr 24 ; blr

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
	mflr	r7

	SETCI(r0)

	# always use serial1
	li 4,0x3f8 ; oris 4,4,0xf400

	# print one char
0:	lbz 0,5(4) ; andi. 0,0,0x20 ; beq 0b ; stb 3,0(4) ; eieio 

	# also print char to serial2 if on a JS21
	# read ID register: only if it is a PC87427 (JS21) also use serial2
	addi 4,4,-0x3f8
	li 5,0x20 ; stb 5,0x2e(4) ; lbz 5,0x2f(4) ; cmpdi 5,0xf2 ; bne 1f

	addi 4,4,0x2f8
0:	lbz 0,5(4) ; andi. 0,0,0x20 ; beq 0b ; stb 3,0(4) ; eieio 

1:	CLRCI(r0)

	mtlr	r7
	blr
