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

#include <cpu.h>
#include <xvect.h>

	.section ".slof.loader","ax"

	/* this only works if paflof is running below 4GB */
	lis	r31, fdt_start@h	/* save address of */
	ori	r31, r31, fdt_start@l	/* flattened device */
	std	r3, 0(r31)		/* tree */

	/* this only works if paflof is running below 4GB */
	lis	r31, romfs_base@h	/* save address of */
	ori	r31, r31, romfs_base@l	/* the romfs */
	std	r4, 0(r31)

	/* this only works if paflof is running below 4GB */
	lis	r31, epapr_magic@h	/* if it is an epapr compliant */
	ori	r31, r31, epapr_magic@l	/* low level firmware; then r6 */
	std	r6, 0(r31)		/* contains the epapr magic */

	/* this only works if paflof is running below 4GB */
	lis	r31, epapr_ima_size@h
	ori	r31, r31, epapr_ima_size@l
	std	r7, 0(r31)		/* r7 contains the IMA size */

	/* fill in handler address */

	/* this only works if paflof is running below 4GB */
	mfmsr	r0
	mtsrr1	r0
	lis	r3, _slof_text@h
	ori	r3, r3, _slof_text@l
	ld	r3, 0(r3)
	std	r3, XVECT_M_HANDLER(0)

#ifdef BROKEN_SC1
	/* Patch potentially broken sc 1 instructions */
	lis	r3, _slof_text@h
	ori	r3, r3, _slof_text@l
	lis	r4, _slof_text_end@h
	ori	r4, r4, _slof_text_end@l
	li	r5, 0
	bl	.patch_broken_sc1
#endif

	/* GO! */
	ba	0x100
