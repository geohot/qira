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

/* SLOF for QEMU -- boot code.
 * Initial entry point
 */

#include <xvect.h>
#include <cpu.h>
#include <macros.h>

	/* qemu entry:
	 *
	 * __start loaded at 0x100
	 *
	 * CPU 0 starts at 0 with GPR3 pointing to the flat devtree
	 *
	 * All other CPUs are held in stopped state by qemu and are
	 * started via RTAS
	 */
	.text
	.globl __start
__start:
	b	_start
	.long 0xDEADBEE0
	.long 0x0       /* size */ 
	.long 0x0       /* crc  */
	.long relTag - __start

	/* Some exception vectors
	 *	
	 * FIXME: Also need 0280, 0380, 0f20, etc.
	 */

	.irp i, 0x0100,0x0180,0x0200,0x0280,0x0300,0x0380,0x0400,0x0500, \
	        0x0600,0x0700,0x0800,0x0900,0x0a00,0x0b00,0x0c00,0x0d00, \
	        0x0e00,0x0f00,0x1000,0x1100,0x1200,0x1300,0x1400,0x1500, \
	        0x1600,0x1700, \
		0x1800,0x1900,0x1a00,0x1b00,0x1c00,0x1d00,0x1e00,0x1f00, \
		0x2000,0x2100,0x2200,0x2300,0x2400,0x2500,0x2600,0x2700, \
		0x2800,0x2900,0x2a00,0x2b00,0x2c00,0x2d00,0x2e00
	. = \i

	/* enable this if you get exceptions before the console works    */
	/* this will allow using the hardware debugger to see where      */
	/* it traps, and with what register values etc.                  */
	// b	$

	mtsprg	0,r0
	mfctr	r0
	mtsprg  2,r0
	mflr	r0
// 10
	mtsprg  3,r0
	ld	r0, (\i + 0x60)(0)
	mtctr	r0
	li	r0, \i + 0x100
// 20
	bctr

	. = \i + 0x60
	.quad	intHandler2C
	.endr

	. = XVECT_M_HANDLER - 0x100
	.quad	0x00
	.text

	/* Here's the startup code for the master CPU */
	.org 0x4000 - 0x100
_start:
	/* Save device-tree pointer */
	mr	r31,r3

	/* Switch to 64-bit mode with 64-bit exceptions */
#define MSR_SF_LG	63              /* Enable 64 bit mode */
#define MSR_ISF_LG	61              /* Interrupt 64b mode valid on 630 */
#define __MASK(X)	(1<<(X))
#define MSR_SF		__MASK(MSR_SF_LG)	/* Enable 64 bit mode */
#define MSR_ISF		__MASK(MSR_ISF_LG)	/* Interrupt 64b mode */
	mfmsr	r11			/* grab the current MSR */
	li	r12,(MSR_SF | MSR_ISF)@highest
	sldi	r12,r12,48
	or	r11,r11,r12
	mtmsrd	r11
	isync

	/* Early greet */
	li	r3,10
	bl	putc
	li	r3,13
	bl	putc
	li	r3,10
	bl	putc
	li	r3,'S'
	bl	putc

	li	r3,'L'
	bl	putc
	li	r3,'O'
	bl	putc
	li	r3,'F'
	bl	putc

	bl	print_version

	/* go! */
	li	r3,__startC@l
	mtctr	r3
	bctrl
	
	/* write a character to the HV console */
putc:	sldi	r6,r3,(24+32)
	li	r3,0x58
	li	r4,0
	li	r5,1
	.long	0x44000022
	blr

relTag:
	.ascii  RELEASE
	.ascii	"\0"
	.align	2

C_ENTRY(proceedInterrupt)

	ld      r3,exception_stack_frame@got(r2)
	ld	r1,0(r3)

	.irp i, 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, \
	        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, \
		27, 28, 29, 30, 31
	ld	r\i, 0x30+\i*8 (r1)
	.endr

	ld	r14,0x138(r1);
	mtsrr0	r14

	ld	r14,0x140(r1);
	mtsrr1	r14

	ld	r14,0x148(r1);
	mtcr	r14

	ld	0,XVECT_M_HANDLER(0)
	mtctr	0

	ld	r0,0x30(r1); # restore vector number
	ld	r1,0x38(r1);

	bctr

intHandler2C:
	mtctr	r1 # save old stack pointer
	lis	r1,0x4
	stdu	r1, -0x160(r1)
	.irp i, 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, \
	        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, \
		27, 28, 29, 30, 31
	std	r\i, 0x30+\i*8 (r1)
	.endr

	std	r0,0x30(r1);  # save vector number

	mfctr	r14
	std	r14,0x38(r1); # save old r1

	mfsrr0	r14
	std	r14,0x138(r1);

	mfsrr1	r14
	std	r14,0x140(r1);

	mfcr	r14
	std	r14,0x148(r1);

	mfxer	r14
	std	r14,0x150(r1);

	bl	toc_init

	ld      r3,exception_stack_frame@got(r2)
	std     r1,0(r3)


	mr 	r3,r0
	bl	.c_interrupt

	ld	r14,0x138(r1);
	mtsrr0	r14

	ld	r14,0x140(r1);
	mtsrr1	r14

	ld	r14,0x148(r1);
	mtcr	r14

	ld	r14,0x150(r1);
	mtxer	r14


	.irp i, 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, \
	        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, \
		27, 28, 29, 30, 31
	ld	r\i, 0x30+\i*8 (r1)
	.endr

	ld	r1,0x38(r1);

	mfsprg	r0,2
	mtctr	r0
	mfsprg	r0,3
	mtlr	r0
	mfsprg	r0,0
	rfid

/* Set exception handler for given exception vector.  
	r3:	exception vector offset
	r4:	exception handler
*/
	.globl .set_exception
.set_exception:
	.globl set_exception
set_exception:
	ld r4,0x0(r4)
	.globl .set_exception_asm
.set_exception_asm:
	.globl set_exception_asm
set_exception_asm:
	std	r4, 0x60(r3)	# fixme diff 1f - 0b
	blr
