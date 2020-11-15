/*
 *   Creation Date: <2001/06/16 21:30:18 samuel>
 *   Time-stamp: <2003/04/04 16:32:06 samuel>
 *
 *	<init.S>
 *
 *	Asm glue for ELF images run inside MOL
 *
 *   Copyright (C) 2001, 2002, 2003 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "asm/asmdefs.h"
#include "asm/processor.h"
#include "osi.h"

/************************************************************************/
/*	Macros								*/
/************************************************************************/

#define ILLEGAL_VECTOR( v )	.org __vectors + v ; bl trap_error ;
#define VECTOR( v, dummystr )	.org __vectors + v ; vector__##v

#define EXCEPTION_PREAMBLE \
	mtsprg1	r1 ;		/* scratch */ \
	mfsprg0	r1 ;		/* exception stack in sprg0 */ \
	addi	r1,r1,-80 ;	/* push exception frame */ \
 \
	stw	r0,0(r1) ;	/* save r0 */ \
	mfsprg1	r0 ; \
	stw	r0,4(r1) ;	/* save r1 */ \
	stw	r2,8(r1) ;	/* save r2 */ \
	stw	r3,12(r1) ;	/* save r3 */ \
	stw	r4,16(r1) ; \
	stw	r5,20(r1) ; \
	stw	r6,24(r1) ; \
	stw	r7,28(r1) ; \
	stw	r8,32(r1) ; \
	stw	r9,36(r1) ; \
	stw	r10,40(r1) ; \
	stw	r11,44(r1) ; \
	stw	r12,48(r1) ; \
 \
	mflr	r0 ; \
	stw	r0,52(r1) ; \
	mfcr	r0 ; \
	stw	r0,56(r1) ; \
	mfctr	r0 ; \
	stw	r0,60(r1) ; \
	mfxer	r0 ; \
	stw	r0,64(r1) ; \
 \
	/* 76(r1) unused */ \
	addi	r1,r1,-16 ;	/* call conventions uses 0(r1) and 4(r1)... */


/************************************************************************/
/*	stack space							*/
/************************************************************************/

	.section .bss
	.balign 32
	.space  32*1024		// 32 K client stack
client_stack:
	.space	128

	.space	64*1024		// 64 K stack
stack:	.space  64

	.space  32*1024		// 32 K exception stack
estack:	.space	128


/************************************************************************/
/*	entry								*/
/************************************************************************/

	.text
GLOBL(_start):
	li	r0,0
	mtmsr	r0

	lis	r1,HA(estack)
	addi	r1,r1,LO(estack)
	mtsprg0 r1			// setup exception stack
	lis	r1,HA(stack)
	addi	r1,r1,LO(stack)

	// copy exception vectors
	lis	r3,HA(__vectors)
	addi	r3,r3,LO(__vectors)
	li	r4,0
	li	r5,__vectors_end - __vectors + 16
	rlwinm	r5,r5,0,0,28
1:	lwz	r6,0(r3)
	lwz	r7,4(r3)
	lwz	r8,8(r3)
	lwz	r9,12(r3)
	stw	r6,0(r4)
	stw	r7,4(r4)
	stw	r8,8(r4)
	stw	r9,12(r4)
	dcbst	0,r4
	sync
	icbi	0,r4
	sync
	addi	r5,r5,-16
	addi	r3,r3,16
	addi	r4,r4,16
	cmpwi	r5,0
	bgt	1b
	isync

	bl	setup_mmu
	bl	entry
1:	nop
	b	1b


	/* According to IEEE 1275, PPC bindings:
	 *
	 * 	MSR = FP, ME + (DR|IR)
	 *	r1 = stack (32 K + 32 bytes link area above)
	 *	r5 = clint interface handler
	 *	r6 = address of client program arguments (unused)
	 *	r7 = length of client program arguments (unsed)
	 */
saved_stack:
	.long	0
	/* void call_elf( entry ) */
GLOBL(call_elf):
	mflr	r0
	stwu	r1,-16(r1)
	stw	r0,20(r1)
	mtlr	r3
	lis	r8,HA(saved_stack)
	addi	r8,r8,LO(saved_stack)		// save our stack pointer
	stw	r1,0(r8)
	lis	r1,HA(client_stack)
	addi	r1,r1,LO(client_stack)
	lis	r5,HA(of_client_callback)
	addi	r5,r5,LO(of_client_callback)	// r5 = callback
	li	r6,0			// r6 = address of client program arguments (unused)
	li	r7,0			// r7 = length of client program arguments (unused)
	li	r0,MSR_FP | MSR_ME | MSR_DR | MSR_IR
	mtmsr	r0
	blrl

	lis	r8,HA(saved_stack)
	addi	r8,r8,LO(saved_stack)		// restore stack pointer
	mr	r1,r8
	lwz	r0,20(r1)
	mtlr	r0
	addi	r1,r1,16
	// XXX: should restore r12-r31 etc..
	// we should not really come here though
	blr

GLOBL(of_client_callback):
	lis	r4,HA(saved_stack)
	addi	r4,r4,LO(saved_stack)
	lwz	r4,0(r4)
	stwu	r4,-32(r4)
	mflr	r5
	stw	r5,32+4(r4)
	stw	r1,8(r4)		// save caller stack
	mr	r1,r4
	stw	r2,12(r1)
	stw	r0,16(r1)
	mfctr	r2
	stw	r2,20(r1)
	mfcr	r2
	stw	r2,24(r1)
	mfxer	r2
	stw	r2,28(r1)
	// do we need to save more registers?
	bl	of_client_interface
	lwz	r4,32+4(r1)
	mtlr	r4
	lwz	r2,20(r1)
	mtctr	r2
	lwz	r2,24(r1)
	mtcr	r2
	lwz	r2,28(r1)
	mtxer	r2
	lwz	r2,12(r1)
	lwz	r0,16(r1)
	lwz	r1,8(r1)		// restore caller stack
	blr

	/* rtas glue (must be reloctable) */
GLOBL(of_rtas_start):
	/* r3 = argument buffer, r4 = of_rtas_start */
	/* according to the CHRP standard, cr must be preserved (cr0/cr1 too?) */
	mr      r6,r3
	lis	r3,HA(OSI_SC_MAGIC_R3)
	addi	r3,r3,LO(OSI_SC_MAGIC_R3)
	lis	r4,HA(OSI_SC_MAGIC_R4)
	addi	r4,r4,LO(OSI_SC_MAGIC_R4)
	li	r5,OSI_OF_RTAS
	sc
	blr
GLOBL(of_rtas_end):


	/* used in a hack to the newworld calibration */
GLOBL(nw_dec_calibration):
	.long	0
GLOBL(timer_calib_start):
	lis	r3,HA(nw_dec_calibration)
	addi	r3,r3,LO(nw_dec_calibration)
	lwz	r3,0(r3)
	blr
GLOBL(timer_calib_end):


/************************************************************************/
/*	vectors								*/
/************************************************************************/

GLOBL(__vectors):
	nop			// NULL-jmp trap
1:	nop			//
	b	1b

exception_return:
	addi	r1,r1,16	// pop ABI frame

	lwz	r0,52(r1)
	mtlr	r0
	lwz	r0,56(r1)
	mtcr	r0
	lwz	r0,60(r1)
	mtctr	r0
	lwz	r0,64(r1)
	mtxer	r0

	lwz	r0,0(r1)	// restore r0
	lwz	r2,8(r1)	// restore r2
	lwz	r3,12(r1)	// restore r3
	lwz	r4,16(r1)
	lwz	r5,20(r1)
	lwz	r6,24(r1)
	lwz	r7,28(r1)
	lwz	r8,32(r1)
	lwz	r9,36(r1)
	lwz	r10,40(r1)
	lwz	r11,44(r1)
	lwz	r12,48(r1)
	lwz	r1,4(r1)	// restore r1
	rfi

trap_error:
	mflr	r3
	b	unexpected_excep

ILLEGAL_VECTOR( 0x100 )
ILLEGAL_VECTOR( 0x200 )

VECTOR( 0x300, "DSI" ):
	EXCEPTION_PREAMBLE
	lis	r3,HA(dsi_exception)
	addi	r3,r3,LO(dsi_exception)
	mtctr	r3
	bctrl
	b	exception_return

VECTOR( 0x400, "ISI" ):
	EXCEPTION_PREAMBLE
	lis	r3,HA(isi_exception)
	addi	r3,r3,LO(isi_exception)
	mtctr	r3
	bctrl
	b	exception_return

	ILLEGAL_VECTOR( 0x500 )
	ILLEGAL_VECTOR( 0x600 )
	ILLEGAL_VECTOR( 0x700 )

VECTOR( 0x800, "FPU" ):
	mtsprg1	r3
	mfsrr1	r3
	ori	r3,r3,0x2000
	mtsrr1	r3
	mfsprg1	r3
	rfi

ILLEGAL_VECTOR( 0x900 )
ILLEGAL_VECTOR( 0xa00 )
ILLEGAL_VECTOR( 0xb00 )
ILLEGAL_VECTOR( 0xc00 )
ILLEGAL_VECTOR( 0xd00 )
ILLEGAL_VECTOR( 0xe00 )
ILLEGAL_VECTOR( 0xf00 )
ILLEGAL_VECTOR( 0xf20 )
ILLEGAL_VECTOR( 0x1000 )
ILLEGAL_VECTOR( 0x1100 )
ILLEGAL_VECTOR( 0x1200 )
ILLEGAL_VECTOR( 0x1300 )
ILLEGAL_VECTOR( 0x1400 )
ILLEGAL_VECTOR( 0x1500 )
ILLEGAL_VECTOR( 0x1600 )
ILLEGAL_VECTOR( 0x1700 )

GLOBL(__vectors_end):


#define CACHE_LINE_SIZE         32
#define LG_CACHE_LINE_SIZE      5

/* flush_icache_range( unsigned long start, unsigned long stop) */
GLOBL(flush_icache_range):
        li      r5,CACHE_LINE_SIZE-1
        andc    r3,r3,r5
        subf    r4,r3,r4
        add     r4,r4,r5
        srwi.   r4,r4,LG_CACHE_LINE_SIZE
        beqlr
        mtctr   r4
        mr      r6,r3
1:      dcbst   0,r3
        addi    r3,r3,CACHE_LINE_SIZE
        bdnz    1b
        sync                            /* wait for dcbst's to get to ram */
        mtctr   r4
2:      icbi    0,r6
        addi    r6,r6,CACHE_LINE_SIZE
        bdnz    2b
        sync                            /* additional sync needed on g4 */
        isync
        blr
