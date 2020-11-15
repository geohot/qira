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
#define _ASM_
#include "macros.h"
#include "southbridge.h"
#include "nvramlog.h"

#define bootmsg_area_size 128

	.text
	.align	3

// Declare the warning level for all 128 possibilities of AC/pCKG kombinations
	WRNG_LVL:
	        .rept bootmsg_area_size
		.byte 0x0
	        .endr


//*****************************************************************************
// Check UserWarningLevel against SystemWarningLevel
// input : r3=cp-id, r5=level
// change: r6,r7
// output: CR0 ( compared user vs system level )
//      example:
//              bl GET_WRNG_LVL
//              ble print_warning
//              bgt do_not_print_warning
ENTRY(GET_WRNG_LVL)
	mflr    r7                      // save linkage register
	bl      0f                      // get current
0:	mflr    r6                      // Instruction Address
	mtlr    r7                      // restore linkage register
	addi    r6,r6,WRNG_LVL-0b       // calc addr of WRNG_LVL array
	rldic   r7,r3,56,57             // calc index into array
	lbzux   r7,r6,r7                // read the warning level
	cmpw    r5,r7                   // and compare it
	blr

//*****************************************************************************
// Print CheckPoint
// input : r3=cp-id
// change: r3, r4, r5, r6, r7, r11
// output: none
ENTRY(bootmsg_cp)
	mflr	r11
	mr	r9, r3          // save checkpoint ID
	li	r3, 'C'
	bl      io_putchar      // print character
	mr	r3, r9
	bl      io_printhex16   // print checkpoint ID
	.rept   5
	li      r3,'\b'
	bl      io_putchar      // print backspaces
	.endr
	mtlr	r11
	blr

//*****************************************************************************
// Print a general BootMessage
// input : r3=cp-id, r4=string, r5=char (type C,W,E)
// change: r3,r4,r5,r6,r7,r9,r10,r11,r12
// output: none
ENTRY(print_msg)
	mflr	r11             // Save linkage register
	mr	r9, r3          // Save ID
	mr	r10, r4         // Save ptr to string
	mr	r12, r5         // Save type (char [CWE])
	li	r3, '\n'        // make it a new line
	bl      io_putchar
	li	r3, '\r'
	bl      io_putchar
	mr	r3, r12         // restore type
	bl      io_putchar      // print character
	mr	r3, r9          // restore ID
	bl      io_printhex16   // print checkpoint ID
	li	r3, ' '         // print a space
	bl      io_putchar
	mr	r3, r10         // restore ptr to string
	bl      io_print        // print message
	li	r3, '\n'        // add a new line
	bl      io_putchar
	li	r3, '\r'
	bl      io_putchar
	mtlr	r11             // restore linkage register
	blr

//*****************************************************************************
// Print an Error Boot Message
// input  : r3=cp-id, r4=string-ptr
// change : r3,r4,r5,r6,r7,r9,r10,r11,r12
// output : none
ENTRY(bootmsg_error)
	li	r5, 'E'         // E is for Error
	b	print_msg       // and print this message

//*****************************************************************************
// Print a Warning Boot Message
// input  : r3=cp-id, r4=string-ptr, r5=level
// change : r3,r4,r5,r6,r7,r9,r10,r11,r12
// output : none
ENTRY(bootmsg_warning)
	mflr	r11             // save linkage register
	bl	GET_WRNG_LVL    // check UserLevel against SystemLevel
	mtlr	r11             // restore linkage register
	li	r5, 'W'         // 'W' is for Warning
	ble     print_msg       // if UserLevel<=SystemLevel print and return
	blr                     // else return

//*****************************************************************************
// Print a Debug Checkpoint
// input  : r3=cp-id, r4=string-ptr, r5=level
// change : r3,r4,r5,r6,r7,r9,r10,r11,r12
// output : none
// r3=cp-id, r4=string, r5=level
ENTRY(bootmsg_debugcp)
	mflr	r11             // save linkage register
	addi	r5,r5,0x20      // add checkpoint offset
	bl	GET_WRNG_LVL    // check UserLevel against SystemLevel
	mtlr	r11             // restore linkage register
	li	r5, 'D'         // 'D' is for Debug CheckPoint
	ble     print_msg       // if UserLevel<=SystemLevel print and return
	blr                     // else return

//*****************************************************************************
// Check warning level
// input  : r3=cp-id, r4=level
// change : r3,r4,r5,r6,r7,r9,r10,r11
// output : r3 (true, false)
// r3=cp-id, r4=level
ENTRY(bootmsg_checklevel)
	mflr    r11
	mr      r5, r4
	slwi    r3, r3, 8
	bl	GET_WRNG_LVL    // check UserLevel against SystemLevel
	li      r3, 0           // return 0
	bgt     0f              // IF ( UserLevel < SystemLevel )
	li      r3, 1           // | return 1
0:	mtlr    r11             // FI
	blr

// r3=area|pkg, r4=level
ENTRY(bootmsg_setlevel)
	mflr    r5
	bl	WarningMsg	// calc current IA
	WarningMsg:
	mflr	r6		// get current IA
	addi	r6,r6,WRNG_LVL-WarningMsg
	andi.	r3, r3, 0x7F
	add     r6,r3,r6        // address     |
	stb     r4,0(r6)        // store level |_ stwbrx r4,r3,r6
	
#if !defined(DISABLE_NVRAM) && !defined(RTAS_NVRAM)
	LOAD64(r6, SB_NVRAM_FWONLY_adr + 8 )
	add	r6,r6,r3
	stb     r4,0(r6)
#endif
	mtlr    r5
	blr

ENTRY(bootmsg_nvupdate)
#if !defined(DISABLE_NVRAM) && !defined(RTAS_NVRAM)
	mflr	r10
	LOAD64(r3, SB_NVRAM_FWONLY_adr)
	lwz	r4, 0(r3)
	cmpwi	r4, 0x424E                 // find bootmsg area header
	bne	0f

	LOAD64(r5, bootmsg_area_size/8)
	mtctr	r5
	bl	WngMsg
	WngMsg:
	mflr	r5
	addi	r5,r5,WRNG_LVL-WngMsg-8

1:
	ldu	r4, 8(r3)
	stdu	r4, 8(r5)
	bdnz+   1b
	b	2f

0:
	LOAD64(r5, bootmsg_area_size)
	mtctr	r5
	li	r4, 0x424E              // clear bootmsg log area
	stw	r4, 0(r3)
	li	r4, 0

1:	stdu	r4, 8(r3)
	bdnz+   1b

2:                              // the end
	mtlr	r10
#endif
	blr
