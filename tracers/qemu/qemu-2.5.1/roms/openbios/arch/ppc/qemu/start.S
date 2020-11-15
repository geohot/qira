/*
 *   Creation Date: <2001/06/16 21:30:18 samuel>
 *   Time-stamp: <2003/04/04 16:32:06 samuel>
 *
 *	<init.S>
 *
 *	Asm glue for ELF images
 *
 *   Copyright (C) 2001, 2002, 2003 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation
 *
 */

#include "autoconf.h"
#include "asm/asmdefs.h"
#include "asm/processor.h"

/************************************************************************/
/*	Macros								*/
/************************************************************************/

#define ILLEGAL_VECTOR( v )	.org __vectors + v ; vector__##v: bl trap_error ;
#define VECTOR( v, dummystr )	.org __vectors + v ; vector__##v

#ifdef CONFIG_PPC_64BITSUPPORT

/* We're trying to use the same code for the ppc32 and ppc64 handlers here.
 * On ppc32 we only save/restore the registers, C considers volatile.
 *
 * On ppc64 on the other hand, we have to save/restore all registers, because
 * all OF code is 32 bits, which only saves/restores the low 32 bits of the
 * registers it clobbers.
 */

#define EXCEPTION_PREAMBLE_TEMPLATE \
	mtsprg1	r1 ;				/* scratch */ \
	mfcr	r1 ; \
	mtsprg2	r1 ;				/* scratch */ \
	lis	r1, 0x8000 ;			/* r1=0x80000000 */ \
	add.	r1,r1,r1 ;			/* r1=r1+r1 (high 32bit !0) */ \
	beq	1f; \
	\
	mfmsr	r1 ;				/* unset MSR_SF */ \
	clrldi	r1,r1,1 ; \
	mtmsrd	r1 ; \
1: \
	mfsprg0	r1 ;				/* exception stack in sprg0 */ \
.ifc ULONG_SIZE, 8 ; \
	addi	r1,r1,-(40 * ULONG_SIZE) ;	/* push exception frame */ \
.else ; \
	addi	r1,r1,-(20 * ULONG_SIZE) ;	/* push exception frame */ \
.endif ; \
 \
	stl	r0,(0 * ULONG_SIZE)(r1) ;	/* save r0 */ \
	mfsprg1	r0 ; \
	stl	r0,(1 * ULONG_SIZE)(r1) ;	/* save r1 */ \
	stl	r2,(2 * ULONG_SIZE)(r1) ;	/* save r2 */ \
	stl	r3,(3 * ULONG_SIZE)(r1) ;	/* save r3 */ \
	stl	r4,(4 * ULONG_SIZE)(r1) ; \
	stl	r5,(5 * ULONG_SIZE)(r1) ; \
	stl	r6,(6 * ULONG_SIZE)(r1) ; \
	stl	r7,(7 * ULONG_SIZE)(r1) ; \
	stl	r8,(8 * ULONG_SIZE)(r1) ; \
	stl	r9,(9 * ULONG_SIZE)(r1) ; \
	stl	r10,(10 * ULONG_SIZE)(r1) ; \
	stl	r11,(11 * ULONG_SIZE)(r1) ; \
	stl	r12,(12 * ULONG_SIZE)(r1) ; \
.ifc ULONG_SIZE, 8 ; \
	stl	r13,(17 * ULONG_SIZE)(r1) ; \
	stl	r14,(18 * ULONG_SIZE)(r1) ; \
	stl	r15,(19 * ULONG_SIZE)(r1) ; \
	stl	r16,(20 * ULONG_SIZE)(r1) ; \
	stl	r17,(21 * ULONG_SIZE)(r1) ; \
	stl	r18,(22 * ULONG_SIZE)(r1) ; \
	stl	r19,(23 * ULONG_SIZE)(r1) ; \
	stl	r20,(24 * ULONG_SIZE)(r1) ; \
	stl	r21,(25 * ULONG_SIZE)(r1) ; \
	stl	r22,(26 * ULONG_SIZE)(r1) ; \
	stl	r23,(27 * ULONG_SIZE)(r1) ; \
	stl	r24,(28 * ULONG_SIZE)(r1) ; \
	stl	r25,(29 * ULONG_SIZE)(r1) ; \
	stl	r26,(30 * ULONG_SIZE)(r1) ; \
	stl	r27,(31 * ULONG_SIZE)(r1) ; \
	stl	r28,(32 * ULONG_SIZE)(r1) ; \
	stl	r29,(33 * ULONG_SIZE)(r1) ; \
	stl	r30,(34 * ULONG_SIZE)(r1) ; \
	stl	r31,(35 * ULONG_SIZE)(r1) ; \
.endif ; \
 \
	mflr	r0 ; \
	stl	r0,(13 * ULONG_SIZE)(r1) ; \
	mfsprg2	r0 ; \
	stl	r0,(14 * ULONG_SIZE)(r1) ; \
	mfctr	r0 ; \
	stl	r0,(15 * ULONG_SIZE)(r1) ; \
	mfxer	r0 ; \
	stl	r0,(16 * ULONG_SIZE)(r1) ; \
 \
	/* 76(r1) unused */ \
	addi	r1,r1,-16 ;	/* C ABI uses 0(r1) and 4(r1)... */

#define EXCEPTION_EPILOGUE_TEMPLATE \
	addi	r1,r1,16 ;			/* pop ABI frame */ \
\
	ll	r0,(13 * ULONG_SIZE)(r1) ; \
	mtlr	r0 ; \
	ll	r0,(14 * ULONG_SIZE)(r1) ; \
	mtcr	r0 ; \
	ll	r0,(15 * ULONG_SIZE)(r1) ; \
	mtctr	r0 ; \
	ll	r0,(16 * ULONG_SIZE)(r1) ; \
	mtxer	r0 ; \
\
	ll	r0,(0 * ULONG_SIZE)(r1) ; \
	ll	r2,(2 * ULONG_SIZE)(r1) ; \
	ll	r3,(3 * ULONG_SIZE)(r1) ; \
	ll	r4,(4 * ULONG_SIZE)(r1) ; \
	ll	r5,(5 * ULONG_SIZE)(r1) ; \
	ll	r6,(6 * ULONG_SIZE)(r1) ; \
	ll	r7,(7 * ULONG_SIZE)(r1) ; \
	ll	r8,(8 * ULONG_SIZE)(r1) ; \
	ll	r9,(9 * ULONG_SIZE)(r1) ; \
	ll	r10,(10 * ULONG_SIZE)(r1) ; \
	ll	r11,(11 * ULONG_SIZE)(r1) ; \
	ll	r12,(12 * ULONG_SIZE)(r1) ; \
.ifc ULONG_SIZE, 8 ; \
	ll	r13,(17 * ULONG_SIZE)(r1) ; \
	ll	r14,(18 * ULONG_SIZE)(r1) ; \
	ll	r15,(19 * ULONG_SIZE)(r1) ; \
	ll	r16,(20 * ULONG_SIZE)(r1) ; \
	ll	r17,(21 * ULONG_SIZE)(r1) ; \
	ll	r18,(22 * ULONG_SIZE)(r1) ; \
	ll	r19,(23 * ULONG_SIZE)(r1) ; \
	ll	r20,(24 * ULONG_SIZE)(r1) ; \
	ll	r21,(25 * ULONG_SIZE)(r1) ; \
	ll	r22,(26 * ULONG_SIZE)(r1) ; \
	ll	r23,(27 * ULONG_SIZE)(r1) ; \
	ll	r24,(28 * ULONG_SIZE)(r1) ; \
	ll	r25,(29 * ULONG_SIZE)(r1) ; \
	ll	r26,(30 * ULONG_SIZE)(r1) ; \
	ll	r27,(31 * ULONG_SIZE)(r1) ; \
	ll	r28,(32 * ULONG_SIZE)(r1) ; \
	ll	r29,(33 * ULONG_SIZE)(r1) ; \
	ll	r30,(34 * ULONG_SIZE)(r1) ; \
	ll	r31,(35 * ULONG_SIZE)(r1) ; \
.endif ; \
	ll	r1,(1 * ULONG_SIZE)(r1) ;	/* restore stack at last */ \
	rfi

// PPC32

#define ULONG_SIZE		4
#define stl			stw
#define ll			lwz

.macro EXCEPTION_PREAMBLE
	EXCEPTION_PREAMBLE_TEMPLATE
.endm

.macro EXCEPTION_EPILOGUE
	EXCEPTION_EPILOGUE_TEMPLATE
.endm

#undef ULONG_SIZE
#undef stl
#undef ll

// PPC64

#define ULONG_SIZE		8
#define stl			std
#define ll			ld

.macro EXCEPTION_PREAMBLE_64
	EXCEPTION_PREAMBLE_TEMPLATE
.endm

.macro EXCEPTION_EPILOGUE_64
	EXCEPTION_EPILOGUE_TEMPLATE
.endm

#undef ULONG_SIZE
#undef stl
#undef ll

#define ULONG_SIZE 4
#define STACKFRAME_MINSIZE 16

#else /* !CONFIG_PPC_64BITSUPPORT */

#ifdef __powerpc64__

#define ULONG_SIZE 8
#define STACKFRAME_MINSIZE 48
#define stl std
#define ll  ld

#else

#define ULONG_SIZE 4
#define STACKFRAME_MINSIZE 16
#define stl stw
#define ll  lwz

#endif

.macro EXCEPTION_PREAMBLE
    mtsprg1 r1 /* scratch */
    mfsprg0 r1 /* exception stack in sprg0 */
    addi    r1, r1, -(20 * ULONG_SIZE) /* push exception frame */

    stl     r0,  ( 0 * ULONG_SIZE)(r1) /* save r0 */
    mfsprg1 r0
    stl     r0,  ( 1 * ULONG_SIZE)(r1) /* save r1 */
    stl     r2,  ( 2 * ULONG_SIZE)(r1) /* save r2 */
    stl     r3,  ( 3 * ULONG_SIZE)(r1) /* save r3 */
    stl     r4,  ( 4 * ULONG_SIZE)(r1)
    stl     r5,  ( 5 * ULONG_SIZE)(r1)
    stl     r6,  ( 6 * ULONG_SIZE)(r1)
    stl     r7,  ( 7 * ULONG_SIZE)(r1)
    stl     r8,  ( 8 * ULONG_SIZE)(r1)
    stl     r9,  ( 9 * ULONG_SIZE)(r1)
    stl     r10, (10 * ULONG_SIZE)(r1)
    stl     r11, (11 * ULONG_SIZE)(r1)
    stl     r12, (12 * ULONG_SIZE)(r1)

    mflr    r0
    stl     r0,  (13 * ULONG_SIZE)(r1)
    mfcr    r0
    stl     r0,  (14 * ULONG_SIZE)(r1)
    mfctr   r0
    stl     r0,  (15 * ULONG_SIZE)(r1)
    mfxer   r0
    stl     r0,  (16 * ULONG_SIZE)(r1)

    addi r1, r1, -STACKFRAME_MINSIZE /* C ABI saves LR and SP */
.endm

.macro EXCEPTION_EPILOGUE
    addi r1, r1,  STACKFRAME_MINSIZE /* pop ABI frame */

    ll    r0,  (13 * ULONG_SIZE)(r1)
    mtlr  r0
    ll    r0,  (14 * ULONG_SIZE)(r1)
    mtcr  r0
    ll    r0,  (15 * ULONG_SIZE)(r1)
    mtctr r0
    ll    r0,  (16 * ULONG_SIZE)(r1)
    mtxer r0

    ll    r0,  ( 0 * ULONG_SIZE)(r1)
    ll    r2,  ( 2 * ULONG_SIZE)(r1)
    ll    r3,  ( 3 * ULONG_SIZE)(r1)
    ll    r4,  ( 4 * ULONG_SIZE)(r1)
    ll    r5,  ( 5 * ULONG_SIZE)(r1)
    ll    r6,  ( 6 * ULONG_SIZE)(r1)
    ll    r7,  ( 7 * ULONG_SIZE)(r1)
    ll    r8,  ( 8 * ULONG_SIZE)(r1)
    ll    r9,  ( 9 * ULONG_SIZE)(r1)
    ll    r10, (10 * ULONG_SIZE)(r1)
    ll    r11, (11 * ULONG_SIZE)(r1)
    ll    r12, (12 * ULONG_SIZE)(r1)

    ll    r1,  ( 1 * ULONG_SIZE)(r1) /* restore stack at last */
    RFI
.endm

#endif /* !CONFIG_PPC_64BITSUPPORT */

/************************************************************************/
/*	vectors								*/
/************************************************************************/

        .section .text.vectors, "ax"
GLOBL(__vectors):
	nop			// NULL-jmp trap
1:	nop			//
	b	1b

VECTOR( 0x100, "SRE" ):
        b       _entry

trap_error:
	lis	r1, 0x8000			/* r1=0x80000000 */
	add.	r1,r1,r1			/* r1=r1+r1 (high 32bit !0) */
	beq	1f

	mfmsr	r1  				/* unset MSR_SF */
	clrldi	r1,r1,1
	mtmsrd	r1
1:
	mflr	r3
	LOAD_REG_FUNC(r4, unexpected_excep)
	mtctr r4
	bctr

ILLEGAL_VECTOR( 0x200 )

VECTOR( 0x300, "DSI" ):
	b	real_dsi

ILLEGAL_VECTOR( 0x380 )

VECTOR( 0x400, "ISI" ):
	b	real_isi

ILLEGAL_VECTOR( 0x480 )

	ILLEGAL_VECTOR( 0x500 )
	ILLEGAL_VECTOR( 0x600 )
	ILLEGAL_VECTOR( 0x700 )

VECTOR( 0x800, "FPU" ):
	mtsprg1	r3
	mfsrr1	r3
	ori	r3,r3,0x2000
	mtsrr1	r3
	mfsprg1	r3
	RFI

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

#ifdef CONFIG_PPC_64BITSUPPORT

VECTOR( 0x2000, "DSI_64" ):
	EXCEPTION_PREAMBLE_64
	LOAD_REG_IMMEDIATE(r3, dsi_exception)
	mtctr	r3
	bctrl
	EXCEPTION_EPILOGUE_64

VECTOR( 0x2200, "ISI_64" ):
	EXCEPTION_PREAMBLE_64
	LOAD_REG_IMMEDIATE(r3, isi_exception)
	mtctr	r3
	bctrl
	EXCEPTION_EPILOGUE_64

#endif

real_dsi:
	EXCEPTION_PREAMBLE
	LOAD_REG_FUNC(r3, dsi_exception)
	mtctr	r3
	bctrl
	b exception_return

real_isi:
	EXCEPTION_PREAMBLE
	LOAD_REG_FUNC(r3, isi_exception)
	mtctr	r3
	bctrl
	b exception_return

exception_return:
	EXCEPTION_EPILOGUE

GLOBL(__vectors_end):

/************************************************************************/
/*	entry								*/
/************************************************************************/

GLOBL(_entry):

#ifdef CONFIG_PPC_64BITSUPPORT
	li	r0,0

	lis	r3, 0x8000			/* r1=0x80000000 */
	add.	r3,r3,r3			/* r1=r1+r1 (high 32bit !0) */
	beq	no_64bit			/* only true when !MSR_SF */

	/* clear MSR, disable MMU, SF */
	mtmsrd	r0
	b	real_entry

no_64bit:
	/* clear MSR, disable MMU */
	mtmsr	r0

real_entry:
#endif

	/* copy exception vectors */

	LOAD_REG_IMMEDIATE(r3, __vectors)
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

	bl compute_ramsize

	/* Memory map:
	 *
	 * Top +-------------------------+
	 *     |                         |
	 *     | ROM into RAM (1 MB)     |
	 *     |                         |
	 *     +-------------------------+
	 *     |                         |
	 *     | MMU Hash Table (64 kB)  |
	 *     |                         |
	 *     +-------------------------+
	 *     |                         |
	 *     | Exception Stack (32 kB) |
	 *     |                         |
	 *     +-------------------------+
	 *     |                         |
	 *     | Stack (64 kB)           |
	 *     |                         |
	 *     +-------------------------+
	 *     |                         |
	 *     | Client Stack (64 kB)    |
	 *     |                         |
	 *     +-------------------------+
	 *     |                         |
	 *     | Malloc Zone (2 MiB)     |
	 *     |                         |
	 *     +-------------------------+
	 *     :                         :
	 * Bottom
	 */

	addis	r1, r3, -16		/* ramsize - 1MB */

	/* setup hash table */

	addis	r1, r1, -1		/* - 64 kB */
	clrrwi	r1, r1, 5*4		/* & ~0xfffff */

	/* setup exception stack */

	mtsprg0	r1

	/* setup stack */

	addi	r1, r1, -32768		/* - 32 kB */

	/* save memory size in stack */

#ifdef __powerpc64__
	/* set up TOC pointer */

	LOAD_REG_IMMEDIATE(r2, setup_mmu)
	ld r2, 8(r2)
#endif

	bl	BRANCH_LABEL(setup_mmu)
	bl	BRANCH_LABEL(entry)
1:	nop
	b	1b


	/* According to IEEE 1275, PPC bindings:
	 *
	 * 	MSR = FP, ME + (DR|IR)
	 *	r1 = stack (32 K + 32 bytes link area above)
	 *	r5 = client interface handler
	 *	r6 = address of client program arguments (unused)
	 *	r7 = length of client program arguments (unused)
         *
         *      Yaboot and Linux use r3 and r4 for initrd address and size
	 */
        .data
saved_stack:
    DATA_LONG(0)
        .previous
	/* void call_elf( arg1, arg2, entry ) */
_GLOBAL(call_elf):
	mflr	r0
	PPC_STLU r1, -STACKFRAME_MINSIZE(r1)
	PPC_STL  r0, (STACKFRAME_MINSIZE + PPC_LR_STKOFF)(r1)
	mtlr	r5
	LOAD_REG_IMMEDIATE(r8, saved_stack)		// save our stack pointer
	PPC_STL r1,0(r8)
	mfsdr1	r1
	addi	r1, r1, -32768		/* - 32 KiB exception stack */
	addis	r1, r1, -1			/* - 64 KiB stack */
	LOAD_REG_IMMEDIATE(r5, of_client_callback)	// r5 = callback
	li	r6,0			// r6 = address of client program arguments (unused)
	li	r7,0			// r7 = length of client program arguments (unused)
	li	r0,MSR_FP | MSR_ME | MSR_DR | MSR_IR
	MTMSRD(r0)
	blrl

#ifdef CONFIG_PPC64
    /* Restore SF bit */
    LOAD_REG_IMMEDIATE(r0, MSR_SF | MSR_FP | MSR_ME | MSR_DR | MSR_IR)
    MTMSRD(r0)
#endif
	LOAD_REG_IMMEDIATE(r8, saved_stack)		// restore stack pointer
	mr	r1,r8
	PPC_LL r0, (STACKFRAME_MINSIZE + PPC_LR_STKOFF)(r1)
	mtlr	r0
	addi	r1, r1, STACKFRAME_MINSIZE
	// XXX: should restore r12-r31 etc..
	// we should not really come here though
	blr

#ifdef __powerpc64__
#define STKOFF STACKFRAME_MINSIZE
#define SAVE_SPACE 320
#else
#define STKOFF 8
#define SAVE_SPACE 144
#endif
GLOBL(of_client_callback):

#ifdef CONFIG_PPC64
    PPC_STLU r1, -(STACKFRAME_MINSIZE + 16)(r1)
#else
    PPC_STLU r1, -STACKFRAME_MINSIZE(r1) /* fits within alignment */
#endif

	/* save r4 */

    PPC_STL r4, STKOFF(r1)

	/* save lr */

	mflr	r4
    PPC_STL r4, PPC_LR_STKOFF(r1)

	/* restore OF stack */

	LOAD_REG_IMMEDIATE(r4, saved_stack)
    PPC_LL  r4, 0(r4)

	PPC_STLU r4,-SAVE_SPACE(r4)
	PPC_STL r1,(STKOFF)(r4)		// save caller stack
	mr	r1,r4

    PPC_STL r2,  (STKOFF +  1 * ULONG_SIZE)(r1)
    PPC_STL r0,  (STKOFF +  2 * ULONG_SIZE)(r1)

	/* save ctr, cr and xer */

	mfctr	r2
    PPC_STL r2,  (STKOFF +  3 * ULONG_SIZE)(r1)
	mfcr	r2
    PPC_STL r2,  (STKOFF +  4 * ULONG_SIZE)(r1)
	mfxer	r2
    PPC_STL r2,  (STKOFF +  5 * ULONG_SIZE)(r1)

	/* save r5 - r31 */

    PPC_STL r5,  (STKOFF +  6 * ULONG_SIZE)(r1)
    PPC_STL r6,  (STKOFF +  7 * ULONG_SIZE)(r1)
    PPC_STL r7,  (STKOFF +  8 * ULONG_SIZE)(r1)
    PPC_STL r8,  (STKOFF +  9 * ULONG_SIZE)(r1)
    PPC_STL r9,  (STKOFF + 10 * ULONG_SIZE)(r1)
    PPC_STL r10, (STKOFF + 11 * ULONG_SIZE)(r1)
    PPC_STL r11, (STKOFF + 12 * ULONG_SIZE)(r1)
    PPC_STL r12, (STKOFF + 13 * ULONG_SIZE)(r1)
    PPC_STL r13, (STKOFF + 14 * ULONG_SIZE)(r1)
    PPC_STL r14, (STKOFF + 15 * ULONG_SIZE)(r1)
    PPC_STL r15, (STKOFF + 16 * ULONG_SIZE)(r1)
    PPC_STL r16, (STKOFF + 17 * ULONG_SIZE)(r1)
    PPC_STL r17, (STKOFF + 18 * ULONG_SIZE)(r1)
    PPC_STL r18, (STKOFF + 19 * ULONG_SIZE)(r1)
    PPC_STL r19, (STKOFF + 20 * ULONG_SIZE)(r1)
    PPC_STL r20, (STKOFF + 21 * ULONG_SIZE)(r1)
    PPC_STL r21, (STKOFF + 22 * ULONG_SIZE)(r1)
    PPC_STL r22, (STKOFF + 23 * ULONG_SIZE)(r1)
    PPC_STL r23, (STKOFF + 24 * ULONG_SIZE)(r1)
    PPC_STL r24, (STKOFF + 25 * ULONG_SIZE)(r1)
    PPC_STL r25, (STKOFF + 26 * ULONG_SIZE)(r1)
    PPC_STL r26, (STKOFF + 27 * ULONG_SIZE)(r1)
    PPC_STL r27, (STKOFF + 28 * ULONG_SIZE)(r1)
    PPC_STL r28, (STKOFF + 29 * ULONG_SIZE)(r1)
    PPC_STL r29, (STKOFF + 30 * ULONG_SIZE)(r1)
    PPC_STL r30, (STKOFF + 31 * ULONG_SIZE)(r1)
    PPC_STL r31, (STKOFF + 32 * ULONG_SIZE)(r1)

#ifdef CONFIG_PPC64
    LOAD_REG_IMMEDIATE(r2, of_client_interface)
    ld  r2, 8(r2)
#endif
    bl	BRANCH_LABEL(of_client_interface)

	/* restore r5 - r31 */

    PPC_LL  r5,  (STKOFF +  6 * ULONG_SIZE)(r1)
    PPC_LL  r6,  (STKOFF +  7 * ULONG_SIZE)(r1)
    PPC_LL  r7,  (STKOFF +  8 * ULONG_SIZE)(r1)
    PPC_LL  r8,  (STKOFF +  9 * ULONG_SIZE)(r1)
    PPC_LL  r9,  (STKOFF + 10 * ULONG_SIZE)(r1)
    PPC_LL  r10, (STKOFF + 11 * ULONG_SIZE)(r1)
    PPC_LL  r11, (STKOFF + 12 * ULONG_SIZE)(r1)
    PPC_LL  r12, (STKOFF + 13 * ULONG_SIZE)(r1)
    PPC_LL  r13, (STKOFF + 14 * ULONG_SIZE)(r1)
    PPC_LL  r14, (STKOFF + 15 * ULONG_SIZE)(r1)
    PPC_LL  r15, (STKOFF + 16 * ULONG_SIZE)(r1)
    PPC_LL  r16, (STKOFF + 17 * ULONG_SIZE)(r1)
    PPC_LL  r17, (STKOFF + 18 * ULONG_SIZE)(r1)
    PPC_LL  r18, (STKOFF + 19 * ULONG_SIZE)(r1)
    PPC_LL  r19, (STKOFF + 20 * ULONG_SIZE)(r1)
    PPC_LL  r20, (STKOFF + 21 * ULONG_SIZE)(r1)
    PPC_LL  r21, (STKOFF + 22 * ULONG_SIZE)(r1)
    PPC_LL  r22, (STKOFF + 23 * ULONG_SIZE)(r1)
    PPC_LL  r23, (STKOFF + 24 * ULONG_SIZE)(r1)
    PPC_LL  r24, (STKOFF + 25 * ULONG_SIZE)(r1)
    PPC_LL  r25, (STKOFF + 26 * ULONG_SIZE)(r1)
    PPC_LL  r26, (STKOFF + 27 * ULONG_SIZE)(r1)
    PPC_LL  r27, (STKOFF + 28 * ULONG_SIZE)(r1)
    PPC_LL  r28, (STKOFF + 29 * ULONG_SIZE)(r1)
    PPC_LL  r29, (STKOFF + 30 * ULONG_SIZE)(r1)
    PPC_LL  r30, (STKOFF + 31 * ULONG_SIZE)(r1)
    PPC_LL  r31, (STKOFF + 32 * ULONG_SIZE)(r1)

	/* restore ctr, cr and xer */

    PPC_LL  r2,  (STKOFF +  3 * ULONG_SIZE)(r1)
	mtctr	r2
    PPC_LL  r2,  (STKOFF +  4 * ULONG_SIZE)(r1)
	mtcr	r2
    PPC_LL  r2,  (STKOFF +  5 * ULONG_SIZE)(r1)
	mtxer	r2

	/* restore r0 and r2 */

    PPC_LL  r2,  (STKOFF +  1 * ULONG_SIZE)(r1)
    PPC_LL  r0,  (STKOFF +  2 * ULONG_SIZE)(r1)

	/* restore caller stack */

    PPC_LL  r1,  (STKOFF)(r1)

    PPC_LL  r4, PPC_LR_STKOFF(r1)
	mtlr	r4
    PPC_LL  r4, STKOFF(r1)
    PPC_LL  r1, 0(r1)

	blr

	/* rtas glue (must be reloctable) */
GLOBL(of_rtas_start):
	/* r3 = argument buffer, r4 = of_rtas_start */
	/* according to the CHRP standard, cr must be preserved (cr0/cr1 too?) */
	blr
GLOBL(of_rtas_end):


#define CACHE_LINE_SIZE         32
#define LG_CACHE_LINE_SIZE      5

/* flush_icache_range( unsigned long start, unsigned long stop) */
_GLOBAL(flush_icache_range):
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

        /* Get RAM size from QEMU configuration device */

#define CFG_ADDR 0xf0000510
#define FW_CFG_RAM_SIZE         0x03

compute_ramsize:
        LOAD_REG_IMMEDIATE(r9, CFG_ADDR)
        li      r0,FW_CFG_RAM_SIZE
        sth     r0,0(r9)
        LOAD_REG_IMMEDIATE(r9, CFG_ADDR + 2)
        lbz     r1,0(r9)
        lbz     r0,0(r9)
        slwi    r0,r0,8
        or      r1,r1,r0
        lbz     r0,0(r9)
        slwi    r0,r0,16
        or      r1,r1,r0
        lbz     r0,0(r9)
        slwi    r0,r0,24
        or      r3,r1,r0
        blr

        /* Hard reset vector */
	.section .romentry,"ax"
	bl	_entry
