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
	.text
	.org	0 /* after loading to mem this is at slaveloop_base */
#	. = 0x3f00 loaded to this addr
	.globl __stage_s_entry

__stage_s_entry:
	bl	$+4
	mflr	r4
	li	r3, 0xff
	not 	r3, r3
	and	r4, r4, r3
	li 0,1 ; std 0,0xf8(4)
	li 0,0 ; std 0,0xa0(4)
slaveloop:
	ori 28,28,0x100
	lis 0,10
	mtctr 0
	bdnz $		# do some waiting, to prevent flooding the buses
	lwz 0,0xa0(4)
	cmpw 0,28
	bne $-20	# wait for our flag

	lwz 0,0x80(4)
	lwz 3,0xc0(4)
	mtctr 0
	bctr		# jump to specified address, with specified GPR3

#	.quad	0	
#	.quad	0	



