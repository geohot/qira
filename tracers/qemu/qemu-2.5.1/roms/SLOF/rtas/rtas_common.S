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

.globl save_regs_r3_r12
.globl restore_regs_r3_r12
.globl save_regs_r13_r25
.globl restore_regs_r13_r25


save_regs_r3_r12:
	stdu    r1,-0x80(r1)            # allocate space on stack

	std     r3,0x30(r1)
	std     r4,0x38(r1)
	std     r5,0x40(r1)
	std     r6,0x48(r1)
	std     r7,0x50(r1)
	std     r8,0x58(r1)
	std     r9,0x60(r1)
	std     r10,0x68(r1)
	std     r11,0x70(r1)
	std     r12,0x78(r1)

	blr
	
restore_regs_r3_r12:
	ld      r3,0x30(r1)
	ld      r4,0x38(r1)
	ld      r5,0x40(r1)
	ld      r6,0x48(r1)
	ld      r7,0x50(r1)
	ld      r8,0x58(r1)
	ld      r9,0x60(r1)
	ld      r10,0x68(r1)
	ld      r11,0x70(r1)
	ld      r12,0x78(r1)

	addi    r1,r1,0x80		# cleanup stack

	blr

save_regs_r13_r25:
	stdu    r1,-0x98(r1)            # allocate space on stack

	std     r13,0x30(r1)
	std     r14,0x38(r1)
	std     r15,0x40(r1)
	std     r16,0x48(r1)
	std     r17,0x50(r1)
	std     r18,0x58(r1)
	std     r19,0x60(r1)
	std     r20,0x68(r1)
	std     r21,0x70(r1)
	std     r22,0x78(r1)
	std     r23,0x80(r1)
	std     r24,0x88(r1)
	std     r25,0x90(r1)

	blr

restore_regs_r13_r25:
	ld      r13,0x30(r1)            # restore registers from stack
	ld      r14,0x38(r1)
	ld      r15,0x40(r1)
	ld      r16,0x48(r1)
	ld      r17,0x50(r1)
	ld      r18,0x58(r1)
	ld      r19,0x60(r1)
	ld      r20,0x68(r1)
	ld      r21,0x70(r1)
	ld      r22,0x78(r1)
	ld      r23,0x80(r1)
	ld      r24,0x88(r1)
	ld      r25,0x90(r1)

	addi    r1,r1,0x98		# cleanup stack

	blr
