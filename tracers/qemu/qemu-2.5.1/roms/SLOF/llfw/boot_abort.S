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
#include "termctrl.h"
#include "boot_abort.h"
#include <cpu.h>

#define MSG_LOOK_HDR TERM_CTRL_BRIGHT, TERM_BG_RED, TERM_FG_WHITE

ASM_ENTRY(msg_e_crc)
	.ascii	MSG_LOOK_HDR
	.ascii	"\n\r\n\rE1001 - Boot ROM CRC failure\n\r"
	.ascii	TERM_CTRL_RESET, "\0"
	.align	2

ASM_ENTRY(msg_e_nomem)
	.ascii	MSG_LOOK_HDR
	.ascii	"\n\r\n\rE1002 - Memory could not be initialized\n\r"
	.ascii	TERM_CTRL_RESET, "\0"
	.align	2

ASM_ENTRY(msg_e_nofile)
	.ascii	MSG_LOOK_HDR
	.ascii	"\n\r\n\rE1003 - Firmware image incomplete"
	.ascii	TERM_CTRL_RESET
	.ascii	    "\n\r       internal FLS1-FFS-0.\0"
	.align	2

ASM_ENTRY(msg_e_ierror)
	.ascii	MSG_LOOK_HDR
	.ascii	"\n\r\n\rE1004 - Unspecified Internal Firmware Error"
	.ascii	TERM_CTRL_RESET
	.ascii	    "\n\r       internal FLSX-SE-0.\0"
	.align	2

/* E1005 : used in memory init code */

/*****************************************************************************
 * Boot Abort Handler
 *
 * Input:
 *        R3 - capability informatin (i/o etc.)
 *        R4 - handling suggestion
 *        R5 - error string reference
 *        R6 - error number
 * 
 * Return: 
 *        if possible input to H8 and NVRAM log and console , then reboot/halt
 *
 * Input definitions:
 *
 * R3 bits: 63 (h8/console possible) ... add more
 * R4 bits: 63 (do not attempt reboot)
 * R5 reference to error message string
 * R6 32-bit error enumerator
 *
 ******************************************************************************/
ASM_ENTRY(boot_abort)
	/* save arguments */
	mr	r31, r3
	mr	r30, r4
	mr	r29, r5
	mr	r28, r6
	
	/* check if i/o is possible, if yes then print message */
	li	r10, ABORT_CANIO
	andi.	r3, r31, r10
	bne	abort_noio

	/* use i/o ..., first print reference message */
	/* then add internal number if != 0           */
	mr	r3, r29
	mfspr	r4, HSPRG0 /* get runbase */
	or	r3, r3, r4
	bl	io_print
	mr	r3, r28
	li	r28, 0
	cmpd	r3, r28
	beq	0f
	bl	io_printhex32
0:

  abort_noio:
  	b	$	// FIXME
	/* never reached */

