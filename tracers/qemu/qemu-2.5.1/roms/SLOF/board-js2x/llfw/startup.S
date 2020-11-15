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

# SLOF for JS20/JS21 -- ROM boot code.
# Initial entry point, copy code from flash to cache, memory setup.
# Also sets up serial console and optimizes some settings.

#include "termctrl.h"
#include <product.h>
#include <xvect.h>
#include <cpu.h>
#include <macros.h>
#include <southbridge.h>

	.text
	.globl __start
__start:
	/* put rombase in sprg1 ***********************/

	bl	postHeader
	.long 0xDEADBEE0
	.long 0x0       /* size */ 
	.long 0x0       /* crc  */
	.long relTag - __start
postHeader:
	mflr	r3
	li	r4, 0x7fff
	not	r4, r4
	and	r3, r3, r4
	mtsprg	1, r3      /* romfs base */
	bl	_start

	.org 0x150 - 0x100
__startSlave:
	bl setup_cpu
	bl set_ci_bit
#	b slaveWithNumber
	b slave

	.org 0x180 - 0x100
__startMaster:
	li 3,0
	mtsprg	1, r3      /* romfs base */
	bl setup_cpu
	bl set_ci_bit
	b master


	/* FIXME: Also need 0280, 0380, 0f20, etc. */

	.irp i, 0x0100,0x0180,0x0200,0x0280,0x0300,0x0380,0x0400,0x0500,0x0600,0x0700, \
		0x0800,0x0900,0x0a00,0x0b00,0x0c00,0x0d00,0x0e00,0x0f00, \
		0x1000,0x1100,0x1200,0x1300,0x1400,0x1500,0x1600,0x1700, \
		0x1800,0x1900,0x1a00,0x1b00,0x1c00,0x1d00,0x1e00,0x1f00, \
		0x2000,0x2100,0x2200,0x2300,0x2400,0x2500,0x2600,0x2700, \
		0x2800,0x2900,0x2a00,0x2b00,0x2c00,0x2d00,0x2e00
	. = \i

	/* enable this if you get exceptions before the console works    */
	/* this will allow using the hardware debugger to see where      */
	/* it traps, and with what register values etc.                  */
	// b	$

	mtsprg	0, r0
	mfctr	r0
	mtsprg  2,r0
	mflr	r0
// 10
	mtsprg  3,r0
	ld	r0, (\i + 0x160)(0)
	mtctr	r0
	li	r0, \i + 0x100
// 20
	bctr

	. = \i + 0x60

	.quad intHandler2C

	.endr


	. = XVECT_M_HANDLER - 0x100
	.quad 0x00
	. = XVECT_S_HANDLER - 0x100

	.quad 0



	.org 0x4000 - 0x100
_start:
	# optimize HID register settings
	bl setup_cpu
	bl set_ci_bit

	# read semaphore, run as slave if not the first to do so
	li 3,0 ; oris 3,3,0xf800 ; lwz 3,0x60(3) ; andi. 3,3,1 ; beq slave
master:
	# setup flash, serial
	bl setup_sio

	# early greet
	li	r3, 10
	bl	putc
	li 3,13 ; bl putc ; li 3,10 ; bl putc ; li 3,'S' ; bl putc


	#do we run from ram ?
	mfsprg	r3, 1	/* rombase */
	cmpdi	r3,0	/* rombase is 0 when running from RAM */

	bne copy_to_cache

	# wait a bit, start scripts are slow...  need to get all cores running!
	lis 3,0x4000 ; mtctr 3 ; bdnz $

	# copy 4MB from 0 to temp memory
   lis 4,0x8 ; mtctr 4 ; lis 4,0x200  ; li 3,0 ; addi 4,4,-8 ; addi 3,3,-8
0:	ldu 5,8(3) ; stdu 5,8(4) ; bdnz 0b

	lis 4,0x200
	mtsprg	1, r4

	lis 4,0x1
	lis 3,0x20 ; addi 3,3,0x200-8 ;
	FLUSH_CACHE(r3, r4)

	lis 4,0x200
	addi 4,4,copy_to_cache@l
	mtctr 4
	bctr

# make all data accesses cache-inhibited
set_ci_bit:
	SETCI(r0)
	blr

# make all data accesses cacheable
clr_ci_bit:
	CLRCI(r0)
	blr

# write a character to the serial port
putc:
# always write to serial1
0:	lbz 0,5(13) ; andi. 0,0,0x20 ; beq 0b ; stb 3,0(13) ; eieio

# read ID register: only if it is a PC87427 (JS21) also use serial2
	li 4,0 ; oris 4,4,0xf400
	li 5,0x20 ; stb 5,0x2e(4) ; lbz 5,0x2f(4); cmpdi 5,0xf2 ; bne 1f

	addi 4,4,0x2f8
0:	lbz 0,5(4) ; andi. 0,0,0x20 ; beq 0b ; stb 3,0(4) ; eieio

1:	blr

# transfer from running from flash to running from cache
return_cacheable:
	# find and set address to start running from cache, set msr value 
	mflr 3 ; rldicl 3,3,0,44 
jump_cacheable:
	mtsrr0 3 ; 
	mfmsr 3 ; ori 3,3,0x1000 ; mtsrr1 3 # enable MCE, as well

	# set cacheable insn fetches, jump to cache
	mfspr 3,HID1 ; rldicl 3,3,32,0 ; oris 3,3,0x0020 ; rldicl 3,3,32,0
	sync ; mtspr HID1,3 ; mtspr HID1,3 ; rfid ; b .




copy_to_cache:
	# zero the whole cache
	# also, invalidate the insn cache, to clear parity errors
	# 128kB @ 0MB (boot code and vectors from 0x0 up to 0x20000)
	li 4,0x400 ; mtctr 4 ; li 5,0x0 ; bl clr_ci_bit
0:	dcbz 0,5 ; sync ; icbi 0,5 ; sync ; isync ; addi 5,5,0x80 ; bdnz 0b

	# 0x2000 to 0x100000/0x80000 (smaller on 970/970FX)
	li 4,0x1C00 ; mfpvr 0 ; srdi 0,0,16 ; cmpdi 0,0x0044 ; bge 0f ; li 4,0xC00
0:
	mtctr 4 ; li 5,0x2000
0:	dcbz 0,5 ; sync ; isync ; addi 5,5,0x80 ; bdnz 0b ; bl set_ci_bit

	# find base address
	bcl 20,31,$+4 ; mflr 31 ; rldicr 31,31,0,43

	# copy 1kB from 0x4000
	li 4,0x80 ; mtctr 4 ; 
	li	5,0x3ff8
	addi 3,31,0x3ff8
0:	ldu 4,8(3) ; bl clr_ci_bit ; stdu 4,8(5) ; bl set_ci_bit ; bdnz 0b
	# now start executing from cache -- insn cache is huge speed boost

	bl return_cacheable

	li 3,'L' ; bl putc

	# copy 128kB of flash to cache
	li 4,0x800 ; mtctr 4 ; li 5,0x200-64 ; addi 3,31,0x200-64 ; 
0:	ldu 16,64(3) ; ld 17,8(3) ; ld 18,16(3) ; ld 19,24(3)
	ld 20,32(3) ; ld 21,40(3) ; ld 22,48(3) ; ld 23,56(3)
	bl clr_ci_bit
	stdu 16,64(5) ; std 17,8(5) ; std 18,16(5) ; std 19,24(5)
	std 20,32(5) ; std 21,40(5) ; std 22,48(5) ; std 23,56(5)
	icbi 0,5 ; bl set_ci_bit ; bdnz 0b ; isync


	li 3,'O' ; bl putc

	lis 4,0x20
	mfsprg	r3,1
	cmpd r3,r4
	beq 1f

	// at 0xf8000000 we decide if it is u3 or u4
	li 4,0 ; oris 4,4,0xf800 ; lwz 3,0(4) ; srdi 3,3,4 ; cmpdi 3,3 ; bne 0f
	bl setup_mem_u3
	bl setup_mem_size
	b 1f
0:

1:
	li 3,'F' ; bl putc

	# setup nvram logging only when not running from RAM
	mfsprg	r3, 1	/* rombase */
	cmpdi	r3, 0	/* rombase is 0 when running from RAM */
	beq	0f

	// at 0xf8000000 we decide if it is u3 or u4
	li	r4, 0
	oris	r4, r4, 0xf800
	lwz	r3, 0(r4)
	srdi	r3, r3, 4
	cmpdi	r3, 3	/* 3 means js20; no nvram logging on js20 */
	beq	0f

	bl	io_log_init
0:

	#bl print_mem

	# data is cacheable by default from now on
	bl clr_ci_bit


	/* give live sign *****************************/
	bl	0f
	.ascii	TERM_CTRL_RESET
	.ascii	TERM_CTRL_CRSOFF
	.ascii  " **********************************************************************"
	.ascii	"\r\n"
	.ascii	TERM_CTRL_BRIGHT
	.ascii	PRODUCT_NAME
	.ascii  " Starting\r\n"
	.ascii  TERM_CTRL_RESET
	.ascii  " Build Date = ", __DATE__, " ", __TIME__
	.ascii	"\r\n"
	.ascii  " FW Version = " , RELEASE
	.ascii	"\r\n\0"
	.align	2
0:	mflr	r3
	bl	io_print

	# go!
	li	r3,__startC@l
	mtctr	r3
	mfsprg	r10, 1
	bctrl

relTag:
	.ascii  RELEASE
	.ascii	"\0"
	.align	2

slave:

	# get cpu number
	li 3,0 ; oris 3,3,0xf800 ; lwz 28,0x50(3)

slaveWithNumber:
	# create our slave loop address
	sldi 3,28,24 ; oris 3,3,0x3000

	# invalidate the insn cache, to clear parity errors
	# clear the L2 cache as well, to get ECC right
	li 4,0x2000 ; mfpvr 0 ; srdi 0,0,16 ; cmpdi 0,0x0044 ; bge 0f ; li 4,0x1000
0:	mtctr 4 ; mr 5,3 ; bl clr_ci_bit

0:	dcbz 0,5 ; sync ; icbi 0,5 ; sync ; isync ; addi 5,5,0x80 ; bdnz 0b


	# write a "b $" insn in there
	lis 4,0x4800 ; stw 4,0(3)
/*
	mr 5,3

	# jump there
	bl set_ci_bit
	li 13,0 ; oris 13,13,0xf400
	# device address
	addi 13,13,0x2f8
	li 3,'O' ; add 3,3,28 ; bl putc
	bl clr_ci_bit
	mr 3,5
*/
	b jump_cacheable




# allow the flash chip to be accessed faster
# initialize the 16550-compatible uart on serial port 1 of the sio
setup_sio:

	# i/o base address
	li 3,0 ; oris 3,3,0xf400

	# i/o base address
	li 3,0 ; oris 3,3,0xf400

	# put x-bus in turbo mode
	li 4,0xf1 ; stb 4,0x400(3) ; eieio


	# select sio serial1
	li 4,7 ; stb 4,0x2e(3) ; eieio ; li 4,3 ; stb 4,0x2f(3) ; eieio

	# set base address to 3f8
	li 4,0x60 ; stb 4,0x2e(3) ; eieio ; li 4,3 ; stb 4,0x2f(3) ; eieio

	# enable device
	li 4,0x30 ; stb 4,0x2e(3) ; eieio ; li 4,1 ; stb 4,0x2f(3) ; eieio

	# read ID register: only if it is a PC87427, enable serial2
	li 4,0x20 ; stb 4,0x2e(3) ; eieio ; lbz 4,0x2f(3) ; cmpdi 4,0xf2 ; bne 0f

	# select sio serial2
	li 4,7 ; stb 4,0x2e(3) ; eieio ; li 4,2 ; stb 4,0x2f(3) ; eieio

	# set base address to 2f8
	li 4,0x60 ; stb 4,0x2e(3) ; eieio ; li 4,2 ; stb 4,0x2f(3) ; eieio

	# enable device
	li 4,0x30 ; stb 4,0x2e(3) ; eieio ; li 4,1 ; stb 4,0x2f(3) ; eieio

	# uart @0x2f8
	addi 3,3,0x2f8

	# disable interrupts, fifo off
	li 4,0 ; stb 4,1(3) ; eieio ; stb 4,2(3) ; eieio

	# set serial speed
	li 4,0x80 ; stb 4,3(3) ; eieio
	li 4,115200/19200 ; stb 4,0(3) ; eieio ; li 4,0 ; stb 4,1(3) ; eieio

	# set 8-N-1, set RTS and DTR
	li 4,3 ; stb 4,3(3) ; eieio ; stb 4,4(3) ; eieio

	eieio

	addi 3,3,-0x2f8

	# uart @0x3f8
0:	addi 3,3,0x3f8

	# disable interrupts, fifo off
	li 4,0 ; stb 4,1(3) ; eieio ; stb 4,2(3) ; eieio

	# set serial speed
	li 4,0x80 ; stb 4,3(3) ; eieio
	li 4,115200/19200 ; stb 4,0(3) ; eieio ; li 4,0 ; stb 4,1(3) ; eieio

	# set 8-N-1, set RTS and DTR
	li 4,3 ; stb 4,3(3) ; eieio ; stb 4,4(3) ; eieio

	eieio

	# save UART base for putc routine
0:	mr 13,3

	blr




# set the HID registers of the 970 for optimally executing from flash
setup_cpu:

	/* clear all the HV cruft */
	li	r0, 0
	sync
	mtspr	HID4, r0
	isync

	/* enable dpm, disable attn insn, enable external mce
	 * first, try external time base; if clock doesn't run, switch to
	 * internal */
	li	r0, 1			/* do the setup for external timebase */
	rldicl	r0, r0, 44, 0		/* bit 19 has to be set */
	oris	r0, r0, 0x8000		/* Enable external machine check */
					/* interrupts (preferred state */
					/* equals `1'). */
	sync
	mtspr	HID0, r0
	isync

	mftb	r3			/* read the timebase */
	li	r1, 0x4000		/* wait long enough for the external */
	mtctr	r1			/* timebase (14MHz) to tick a bit */
	bdnz	$			/* 0x4000 seems to be enough (for now) */
	mftb	r4			/* read the timebase a second time */
	cmpld	r3, r4			/* see if it changed */
	bne	0f
	/* timebase did not change, do the setup for internal */
	rldicl	r0, r0, 19, 1
	rldicl	r0, r0, 45, 0
	sync
	mtspr	HID0, r0
	isync

0:
	/* enable insn prefetch, speculative table walks */
	mfspr	r0, HID1
	rldicl	r0, r0, 20, 0
	ori	r0, r0, 0x1002
	mfsprg	r3, 1			/* read rombase */
	cmpdi	r3, 0			/* check if running from ram */
	bne	0f
	/* running from ram */
	/* Enable instruction fetch cacheability control */
	ori	r0, r0, 0x200
0:
	rldicl	r0, r0, 44, 0
	sync
	mtspr	HID1, r0
	isync

	/* enable cache parity */
	mfspr	r0, HID4
	oris	r0, r0, 0xfff0
	xoris	r0, r0, 0xfff0
	sync
	mtspr	HID4, r0
	isync

	/* exception offset at 0 */
	li	r3, 0
	mtspr	HIOR, r3

	blr

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


	ld 0,XVECT_M_HANDLER(0)
	mtctr 0

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

	bl toc_init

	ld      r3,exception_stack_frame@got(r2)
	std     r1,0(r3)


	mr 	r3,r0
	bl .c_interrupt

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


setup_mem_u3:
	li 4,0x2000 ; oris 4,4,0xf800

	# MemTimingParam -- CAS lat 2.5 / 4 (read-to-read / read-to-write)
	lis 3,0x49e1 ; ori 3,3,0xa000 ; stw 3,0x50(4)

	# MRSRegCntl -- CAS lat 2.5
	li 3,0x6a ; stw 3,0xf0(4)

	# MemBusConfig -- 128 bit bus
	lis 3,0x8500 ; stw 3,0x190(4)

	# CKDelAdj -- clock delay 75
	lis 3,0x12c3 ; ori 3,3,0x30cc ; stw 3,0x520(4)

	# IOModeCntl -- no termination on differential and 3-state drivers
	lis 3,0x0350 ; stw 3,0x530(4)

	li 3,18 ; mtctr 3 ; addi 5,4,0x5f0
0:	# DQSDelAdj -- read delay offset -10
	lis 3,0x3d8f ; ori 3,3,0x6000 ; stwu 3,0x10(5)

	# DQSDataDelAdj -- write delay offset -32, write data delay offset +15
	lis 3,0x380e ; ori 3,3,0x003c ; stwu 3,0x10(5)
	bdnz 0b

	# MemProgCntl -- set all
	lis 3,0xc000 ; stw 3,0xe0(4)

	eieio

	blr


# read dimm SPDs, program memory size and type
setup_mem_size:
	mflr 14

	li 15,0 ; oris 15,15,0xf800 ; li 17,0
	li 3,0xa0 ; li 4,3 ; li 5,3 ; bl i2c_read
	mr 16,4 ; cmpdi 3,0 ; beq 0f ; li 16,0
0:	li 3,0xa2 ; li 4,3 ; li 5,3 ; bl i2c_read
	cmpd 16,4 ; bne 0f ; cmpdi 3,0 ; beq 1f
0:	li 16,0x1e00
1:	#li 3,0xd ; bl print_byte ; li 3,0xa ; bl print_byte
	#mr 3,16 ; bl print_hex

	#li 3,0x20 ; bl print_byte
	sldi 3,16,7 ; add 3,3,16 ; rlwinm 3,3,10,0,6 ; subis 3,3,0x3c00
	stw 3,0x21c0(15) ; andi. 0,16,2 ; beq 0f ; stw 3,0x21e0(15)
0:	#bl print_hex
	sldi 3,16,8 ; add 3,3,16 ; rldicl 3,3,48,56 ; li 0,8 ; slw 3,0,3
		# slw, not sld, so that empty/bad banks translate into size 0
	stw 17,0x21d0(15) ; bl add17173 ; stw 17,0x21f0(15)
	andi. 0,16,2 ; beq 0f ; bl add17173
0:	#bl print_hex

	li 3,0xa4 ; li 4,3 ; li 5,3 ; bl i2c_read
	mr 16,4 ; cmpdi 3,0 ; beq 0f ; li 16,0
0:	li 3,0xa6 ; li 4,3 ; li 5,3 ; bl i2c_read
	cmpd 16,4 ; bne 0f ; cmpdi 3,0 ; beq 1f
0:	li 16,0x1e00
1:	#li 3,0xd ; bl print_byte ; li 3,0xa ; bl print_byte
	#mr 3,16 ; bl print_hex

	#li 3,0x20 ; bl print_byte
	sldi 3,16,7 ; add 3,3,16 ; rlwinm 3,3,10,0,6 ; subis 3,3,0x3c00
	stw 3,0x2200(15) ; andi. 0,16,2 ; beq 0f ; stw 3,0x2220(15)
0:	#bl print_hex
	sldi 3,16,8 ; add 3,3,16 ; rldicl 3,3,48,56 ; li 0,8 ; slw 3,0,3
	stw 17,0x2210(15) ; bl add17173 ; stw 17,0x2230(15)
	andi. 0,16,2 ; beq 0f ; bl add17173
0:	#bl print_hex
	#mr 3,17 ; bl print_hex
	stw 17,0x2250(15) ; stw 17,0x2270(15)
	stw 17,0x2290(15) ; stw 17,0x22b0(15)

	mtlr 14
	blr




# print GPR3 as 8-digit hex.  uses GPR18,19
print_hex:
	mflr 18 ; mr 19,3 ; li 3,8 ; mtctr 3
1:	rlwinm 3,19,4,28,31 ; sldi 19,19,4
	cmpdi 3,0xa ; blt 0f ; addi 3,3,0x27
0:	addi 3,3,0x30 ; bl putc
	bdnz 1b ; mtlr 18 ; blr


# i2c stuff uses GPR20..GPR24

# terminate any i2c transaction, at any point during that transaction
i2c_stop:
0:	lwz 3,0x30(20) ; stw 3,0x30(20) ; andi. 3,3,4 ; beq 0b
	mr 3,21 ; mr 4,22 ; mtlr 24 ; eieio ; blr

# do a combined-mode read
# in: GPR3 = addr, GPR4 = subaddr, GPR5 = len
# out: GPR3 = error, GPR4 = result (right-aligned, msb)
i2c_read:
	mflr 24
	li 20,0x1000 ; oris 20,20,0xf800	# uni-n i2c base
	mr 21,3 ; mr 22,4 ; mr 23,5		# save params
	li 4,0xc ; stw 4,0(20)			# set mode (combined)
	ori 4,21,1 ; stw 4,0x50(20)		# set addr, read
	stw 22,0x60(20)				# set subaddr
	li 4,2 ; stw 4,0x10(20) ; eieio		# start address phase
	li 21,1					# error
	li 22,0					# result accumulator
0:	lwz 3,0x30(20) ; andi. 3,3,2 ; beq 0b	# wait until sent
	lwz 3,0x20(20) ; andi. 3,3,2 ; beq i2c_stop # check result
	li 4,1 ; cmpdi 23,1 ; bne 0f ; li 4,0
0:	stw 4,0x10(20)				# AAK for next byte (or not)
	li 4,2 ; stw 4,0x30(20) ; eieio		# ack address phase
i2c_read_loop:
	lwz 3,0x30(20) ; andi. 3,3,1 ; beq 1f	# if byte recv'd:
	subi 23,23,1 ; sldi 22,22,8		# shift byte accum
	lwz 3,0x70(20) ; rlwimi 22,3,0,24,31	# get byte
	cmpdi 23,0 ; bne 0f ; li 21,0 ; b i2c_stop # all done
0:	li 4,1 ; cmpdi 23,1 ; bne 0f ; li 4,0
0:      stw 4,0x10(20)				# AAK for next byte (or not)
	li 4,1 ; stw 4,0x30(20) ; eieio		# ack data phase
1:	lwz 3,0x30(20) ; andi. 3,3,4 ; beq i2c_read_loop
	li 4,0 ; stw 4,0x10(20) ; eieio ; b i2c_stop # stop bit received

add17173: # add GPR3 into GPR17; if passing 2GB (0x10000000), add another 2GB.
	lis 0,0x1000 ; cmpld 17,0 ; add 17,17,3 ; bgtlr
	cmpld 17,0 ; blelr ; add 17,17,0 ; blr

io_log_init:
	LOAD64(r3, SB_NVRAM_adr)
	b checkinitLog
