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

	.globl	_start
        .section        ".text"
        .align 3
		
_start:
	nop
	bl over
	.llong 0x9000000000003000
over:
	li	14, 0
	oris	14, 14, _binary_takeover_tmp_start@h
	ori	14, 14, _binary_takeover_tmp_start@l
	mtsrr0	14
	mflr	15
	ld	14,0(15)
	mtsrr1	14
	rfid

