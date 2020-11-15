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

#include "macros.h"
#include "../../llfw/boot_abort.h"

/*#################### defines #####################*/
#define STACK_SIZE   0x4000

/*#################### code ########################*/
	.text
	.globl .gluon_c_entry
	.globl __toc_start
	.globl __toc_end
	.globl __bss_start
	.globl __bss_size
	.globl __start

ASM_ENTRY(__startC)
	/* clear out bss section                */
	LOAD64(r3, (__bss_start - 8))
	LOAD64(r4, __bss_size)

	/* divide __bss_size by 8 to get number */
	/* of dwords to clear                   */
	srwi.	r4, r4, 3
	beq	bsscdone
	li	r5, 0
	mtctr	r4
bssc:	stdu	r5, 8(r3)
	bdnz	bssc
bsscdone:
	/* setup stack                          */
	LOAD64(r1, __stack_end + STACK_SIZE)

	/* save return address beside stack     */
	addi	r3, r1, 128
	mflr	r0
	std	r0, 0(r3)

	/* setup toc                            */
	bl	toc_init

	/* ------------------------------------ */
	/* jump to c-code                       */
	/* r31 = fdt                    - r5    */
	/* ------------------------------------ */
	li	r3, r0
	mr	r4, r31
	bl	.early_c_entry

	/* return to caller...                  */
	LOAD64(r1, __stack_end + STACK_SIZE)
	addi	r1, r1, 128
	ld	r3, 0(r1)
	mtlr	r3
	blr

	/* #################################### */
	/* Basic Additional Functions           */
	/* for extended lib functions see       */
	/* external library                     */
	/* #################################### */
	.align 	2

	/* ------------------------------------ */
	/* updates toc in r2                    */
	/* ------------------------------------ */
ASM_ENTRY(toc_init)
	LOAD64(r2, __toc_start)
	blr

	/* ------------------------------------ */
	/* stores arg#1 in r27 and stops        */
	/* ------------------------------------ */
ENTRY(do_panic)
ENTRY(halt_sys)
	BOOT_ABORT_R3HINT(ABORT_CANIO, ALTBOOT, msg_e_ierror);

	.section ".bss"
	.balign STACK_SIZE
__stack_end:
	.space STACK_SIZE
	.text
