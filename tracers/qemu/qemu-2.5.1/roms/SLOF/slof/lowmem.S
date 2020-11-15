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

#include <cpu.h>
#include <xvect.h>

	.globl _start
	/* All exception vectors *******************/
_start:
	.org 0x100
	/* check if Master / Slave *****************/
	/* Master will go to XVECT_M_HANDLER       */
	/* Slave  will go to XVECT_S_HANDLER       */
#ifdef SECONDARY_CPUS_STOPPED
	ld	r3,XVECT_S_HANDLER(0)
	mfspr	r0, PIR
	cmpwi	r0, 0
	bne	0f
#endif
	ld	r3,XVECT_M_HANDLER(0)
0:
	mtctr	r3
	li	r0,0x100
	bctr

	/* FIXME: Also need 0280, 0380, 0f20, etc. */

	.irp i, 0x0200,0x0280,0x0300,0x0380,0x0400,0x0480,0x0500,0x0600,0x0700, \
		0x0800,0x0900,0x0a00,0x0b00,0x0c00,0x0d00,0x0e00,0x0f00, \
		0x1000,0x1100,0x1200,0x1300,0x1400,0x1500,0x1600,0x1700, \
		0x1800,0x1900,0x1a00,0x1b00,0x1c00,0x1d00,0x1e00,0x1f00, \
		0x2000,0x2100,0x2200,0x2300,0x2400,0x2500,0x2600,0x2700, \
		0x2800,0x2900,0x2a00,0x2b00,0x2c00,0x2d00,0x2e00,0x2f00
	.org \i

	/* enable this if you get exceptions before the console works    */
	/* this will allow using the hardware debugger to see where      */
	/* it traps, and with what register values etc.                  */
	// b	$

	mtsprg	0,r0
	mfctr	r0
	mtsprg  2,r0
	mflr	r0
	mtsprg  3,r0
	ld	r0, XVECT_M_HANDLER(0)
	mtctr	r0
	li	r0,\i
	bctr
	.endr


	.org XVECT_M_HANDLER
	.quad 0

	.org XVECT_S_HANDLER
	.quad 0

	.org XVECT_TOPADDR
	.byte 0x36		# to fill out to exactly 16kB
