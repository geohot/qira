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

#define STACKSIZE 0x2000

	#
	# The generic exception code.
	#
	# Enter with GPR0 = vector, SPRG0 = saved GPR0
	#

	.section ".entry_text"

the_handler:
	.quad	handler

eregs:
	/* the_exception_frame is a C variable which is usually
	 * defined in $(TARG).c
	 * the_exception_frame can be accessed from paflof through
	 * the word eregs
	 * in the case an excpetion is handled paflof will read
	 * from eregs the values of all registers and print them
	 * out in the exception handler */
	.quad	the_exception_frame

handler:
	mtsprg 1,1	# SPRG1 = saved GPR1
	bcl 20,31,$+4
	mflr 1
	ld 1,eregs-$+4(1)	# GPR1 = address of register save area

	.irp i, 2,3,4,5,6,7,8,9,10,11,12,13,14,15, \
		16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
	std \i,\i*8(1)
	.endr		# save GPR2..GPR31

	li r3, 3        // GPR3 = mode (param_1, param_2)
	mr 4,0		// GPR4 = vector

	mfsprg 0,0
	std 0,0(1)	# save GPR0
	mfsprg 0,1
	std 0,8(1)	# save GPR1

	cmpwi	r4, 0x900	# Decrementer interrupt
	bne	0f
	mfdec	r5		# Save old value of decrementer as reason
	lis	r0,0x7fff	# Set decrementer to highest value 
	mtdec	r0
0:
	mfcr 0
	std 0,0x100(1)
	mfxer 0
	std 0,0x108(1)
	mfsprg 0,3	# save lr	
	std 0,0x110(1)
	mfsprg 0,2	# save ctr	
	std 0,0x118(1)
	mfsrr0 0
	std 0,0x120(1)
	mfsrr1 0
	std 0,0x128(1)
	mfdar 0
	std 0,0x130(1)
	mfdsisr 0
	std 0,0x138(1)	# save special regs

	bcl	20, 31, over
base:
	.align	3
.the_system_stack:
	.quad   the_system_stack+STACKSIZE-base
over:
	mflr	r2				/* gpr 2 is the base */
	ld	r1, .the_system_stack-base(r2)	/* load stack pointer */
	add	r1, r1, r2			/* add base */
	li	r0, 0
	stdu	r0, -0x10(r1)
	stdu	r1, -0x100(r1)

	lis 2,engine@ha
	ld 0,engine@l(2) # set up entry
	mtsrr0	0
		
	ld 2,8+engine@l(2) # set up TOC pointer

	rfid
#	b .engine	# ...and run!



	#
	# Swap non-volatile client interface regs, plus GPR3..GPR7.
	#

swap_ci_regs:
	/* save lr */
	mflr	r0
	/* let's find out where our client stack is */
	bcl	20, 31, client_over
client_base:
	.align	3
.the_client_frame:
	.quad   the_client_frame-client_base
client_over:
	mflr	r8				/* gpr 2 is the client_base */
	mtlr	r0				/* restore the original lr */
	ld	r0, .the_client_frame-client_base(r8)
	add	r8, r0, r8			/* add the client_base */
	/* r8 now contains the address of the_client_frame */

	.irp i, 1,2,3,4,5,6,7, \
		13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
	ld 0,\i*8(8)
	std \i,\i*8(8)
	mr \i,0
	.endr		# swap GPR1..7, GPR13..31

	ld 0,0x100(8)
	mfcr 9
	mtcrf 0xff,0
	std 9,0x100(8)	# swap CR

	ld 0,0x128(8)
	mfmsr 9
	mtmsrd 0
	sync
	isync
	std 9,0x128(8)	# swap MSR

	blr

	#
	# Entry point for the OF client interface.
	#

        .globl client_entry_point
        .section        ".opd","aw"
        .align 3
client_entry_point:
        .quad   .client_entry_point,.TOC.@tocbase,0
        .previous
        .type   .client_entry_point,@function
        .globl  .client_entry_point
.client_entry_point:
	mflr 4
	bl swap_ci_regs	# swap regs
	mtlr 4
	li 3, 0 # client call
	blr	

	#
	# Start the client.
	#

        .globl call_client
        .section        ".opd","aw"
        .align 3
call_client:
        .quad   .call_client,.TOC.@tocbase,0
        .previous
        .type   .call_client,@function
        .globl  .call_client

.call_client:	# called with r3 = address, returns r3
	mflr 4
	mtctr 3
	bl swap_ci_regs
	/* Check if LE loading */
	cmpwi 0,13,1
	beq 0f
	bctrl
	b 1f
0:	/* handle LE */
	mfmsr 13
	xori  13,13,1
	mtsrr1 13
	mfctr 13
	mr 12,13
	mtsrr0 13
	rfid
#if 0 /* in case we return back, still to be tested */
	.long 0x05009f42; /* bcl 20,31,$+4   */
	.long 0xa602c87d; /* mflr r14    */
	.long 0x1c00ce39; /* addi r14,r14,28   */
	.long 0xa600e07d; /* mfmsr r15    */
	.long 0x0100ef69; /* xori r15,r15,1   */
	.long 0xa603da7d; /* mtsrr0 r14    */
	.long 0xa603fb7d; /* mtsrr1 r15    */
	.long 0x2400004c; /* rfid */
#endif
1:
	bl swap_ci_regs
	mtlr 4
	li 3, -1 # client app return
	blr


	# Call another function via pointer in r6
	# (arguments can be provided in r3 to r5)
	# Destination function should jump back to lr
C_ENTRY(call_c)
	mtctr	r6
	bctr


	.lcomm	the_system_stack, STACKSIZE, 16
