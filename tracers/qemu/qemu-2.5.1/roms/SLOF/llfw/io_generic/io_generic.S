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
#include "macros.h"
#include "calculatecrc.h"
#include "calculatecrc.h"

	.text

/****************************************************************************
 * prints a 0-terminated string to serial console
 *
 * Input:
 * R3 - pointer to string in memory
 *
 * Returns: -
 *
 * Modifies Registers:
 * R3, R4, R5, R6, R7, R8, R9
 ****************************************************************************/
ASM_ENTRY(io_print)
	mflr	r8
	mr	r9, r3

0:
	lbz	r3, 0(r9)
	cmpwi	r3, 0
	beq	1f
	bl	io_putchar
	addi	r9, r9, 1
	b		0b
1:
	mtlr	r8
	blr

/****************************************************************************
 * prints Hex integer to the UART and the NVRAM (using board io_putchar)
 *
 * Input:
 * R3 - integer to print
 *
 * Returns: -
 *
 * Modifies Registers:
 * R3, R4, R5, R6, R7, R8, R9
 ****************************************************************************/
#define _io_gen_print_nib(reg, src, shift)	\
	srdi	reg, src, shift;		\
	andi.	reg, reg, 0x0F;			\
	cmpwi	reg, 0x0A;			\
	blt	0f;				\
	addi	reg, reg, ('A'-'0'-10);		\
0:;						\
	addi	reg, reg, '0';			\
	bl	io_putchar

ASM_ENTRY(io_printhex64)
	mflr	r8
	mr	r9, r3

_io_printhex64:
	_io_gen_print_nib(r3, r9, 60)
	_io_gen_print_nib(r3, r9, 56)
	_io_gen_print_nib(r3, r9, 52)
	_io_gen_print_nib(r3, r9, 48)
	_io_gen_print_nib(r3, r9, 44)
	_io_gen_print_nib(r3, r9, 40)
	_io_gen_print_nib(r3, r9, 36)
	_io_gen_print_nib(r3, r9, 32)
_io_printhex32:
	_io_gen_print_nib(r3, r9, 28)
	_io_gen_print_nib(r3, r9, 24)
	_io_gen_print_nib(r3, r9, 20)
	_io_gen_print_nib(r3, r9, 16)
_io_printhex16:
	_io_gen_print_nib(r3, r9, 12)
	_io_gen_print_nib(r3, r9,  8)
_io_printhex8:
	_io_gen_print_nib(r3, r9,  4)
	_io_gen_print_nib(r3, r9,  0)

	mtlr	r8
	blr

ASM_ENTRY(io_printhex32)
	mflr	r8
	mr	r9, r3
	b       _io_printhex32

ASM_ENTRY(io_printhex16)
	mflr	r8
	mr	r9, r3
	b       _io_printhex16

ASM_ENTRY(io_printhex8)
	mflr	r8
	mr	r9, r3
	b       _io_printhex8


/****************************************************************************
 * print the address and its contents as 64-bit hex values
 *
 * Input:
 * R3 - Address to read from
 *
 * Returns: -
 *
 * Modifies Registers:
 * R3, R4, R5, R6, R7, R8, R9, R10
 ****************************************************************************/
#if 0   /* currently unused */
ASM_ENTRY(io_dump)
        mflr    r10
        bl      io_printhex64
        li      r3,':'
        bl      io_putchar
        ld      r9,0(r9)
        mr      r8,r10
        b       _io_printhex64
#endif
