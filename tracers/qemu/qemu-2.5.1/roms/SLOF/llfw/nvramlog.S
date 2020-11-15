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
#include <nvramlog.h>
#include <southbridge.h>
#include <calculatecrc.h>

#if !defined(DISABLE_NVRAM) && !defined(RTAS_NVRAM)

// detect overflow: if(a<b)  return a else return 0
#define NVRAM_LOG_DATA_OVERFLOW( a, b) \
	cmpd    7, a, b; \
	blt+    7, 0f; \
	li      a, 0; \
	0:

// get Pointer(pointer) to next byte in NVRAM data section
//  and size of this data sechtion (modulo)
// modifies register pointer, modulo
#define NVRAM_POINTER_DATASIZE_BE0(pointer, modulo, address) \
	LOAD64(	modulo, LLFW_LOG_BE0_LENGTH); \
	lwz     pointer, LLFW_LOG_POS_POINTER(address); \
	sldi    modulo, modulo, 4; \
	addi    modulo, modulo,-LLFW_LOG_BE0_DATA_OFFSET
#define NVRAM_POINTER_DATASIZE_BE1(pointer, modulo, address) \
	LOAD64(	modulo, LLFW_LOG_BE1_LENGTH); \
	lwz     pointer, LLFW_LOG_POS_POINTER(address); \
	sldi    modulo, modulo, 4; \
	addi    modulo, modulo,-LLFW_LOG_BE1_DATA_OFFSET

/****************************************************************************
 *	checkLogHeaderData
 *	compare the fixed values in the header if any change was done since
 *	last initialisation.
 *	Flags are not checked!
 *
 *	Retrun 0 if no manimulation was found 1 else
 *
 *	input:
 *			r3 - NVRAM Base Address 
 *
 *	output:
 *			r3 - status: 0 = ok, 1 = corrupt
 *			r4 - NVRAM Base Address
 *
 ***************************************************************************/
ASM_ENTRY(checkLogHeaderData)
	li	r4, 0					// init error flag
	lbz	r5, 0(r3)				// check signature
	addi	r5, r5, -LLFW_LOG_BE0_SIGNATURE
	add	r4, r4, r5

	lhz	r5, LLFW_LOG_POS_LENGTH(r3)		// check length
	addi	r5, r5, -LLFW_LOG_BE0_LENGTH
	add 	r4, r4, r5

	lwz	r5, LLFW_LOG_POS_NAME(r3)		// check name prefix
	LOAD64( r6, LLFW_LOG_BE0_NAME_PREFIX)
	subf	r5, r6, r5
	add	r4, r4, r5

	ld	r5, (LLFW_LOG_POS_NAME+4)(r3)		// check name
	LOAD64(	r6, LLFW_LOG_BE0_NAME)
	subf	r5, r6, r5
	add	r4, r4, r5
	
	lhz	r5, LLFW_LOG_POS_DATA_OFFSET(r3)	//check data offset
	addi	r5, r5, -LLFW_LOG_BE0_DATA_OFFSET
	add	r4, r4, r5

	lhz	r5, LLFW_LOG_POS_FLAGS(r3)		//check flags
	addi	r5, r5, -LLFW_LOG_BE0_FLAGS
	add	r4, r4, r5

	cmpldi	7, r4, 0
	beq+	7, 0f
	li	r4, 1
0:
	mr	r5, r3
	mr	r3, r4
	mr	r4, r5
	blr
/*****************************************************************************
 * checkLogPartition:	check Partition Header entries and Checksum
 *			check also the NVRAM-Log-Partition CRC
 *			if Partition is not ok set the following bits to 1
 *			bit 1:	if Partiton Header Checksum is corrupt
 *			bit 2: 	if CRC is corrupt
 *			bit 3: 	if Header entries are corrupt
 *						
 *	input:	
 *		r3 - NVRAM log address (BASE + NVRAM_LOG_OFFSET)
 *
 *	output:	
 *		r3 - CRC status  
 *		r4 - NVRAM log address
 *
 *	Modifies Register:	R3, R4, R5, R6, R7, R8, R9
 ****************************************************************************/
ASM_ENTRY(.checkLogPartition)
	mflr	r8
	mr      r4, r3                  // emulate "bl updateCRC_NVRAM"
	li      r3, 0                   // with successful CRC check
	li      r7, 0
	cmpwi   7, r3, 0
	beq+    7, 0f
	li      r7, 2
0:
	mr	r3, r4
	bl 	.calPartitionHeaderChecksum	// r3=checksum, r4=NVARM addr
	lbz	r6, LLFW_LOG_POS_CHECKSUM(r4)
	cmpw	7, r3, r6
	beq+	7, 0f			// cal checksum must eq checksum
	ori	r7, r7, 1
0:
	cmpwi	7, r3, 0
	bne+	7, 0f
	ori	r7, r7, 1		// 0 as checksum is invalid
0:
	mr	r3, r4
	bl	checkLogHeaderData	
	cmpdi	7, r3, 0
	beq+	7, 0f
	ori	r7, r7, 4
0:
	mr	r3, r7
	mtlr	r8
	blr
/*****************************************************************************
 * checkinitLog:	check the NVRAM Log Partition Header 
 *			initialize the NVRAM if the Header was modified
 *					
 *	input:	
 *		r3 - NVRAM BASE address 
 *
 *	output:	
 *		r3 - 0 = check ok, no new header written
 *		r3 - 1 = check not ok, header and NVRAM initialized
 *		r4 - NVRAM log address
 *
 *	Modifies Register:	R3, R4, R5, R6, R7, r8, r9
 ****************************************************************************/
// init is done if checkLogPartiton returns not 0 (= check failed)
ASM_ENTRY(.checkinitLog)
ASM_ENTRY(checkinitLog)
	mflr	r9
	bl 	.checkLogPartition		//r3..r8, r4_out = r3_in   
	mtlr	r9
	
	cmpwi	7, r3, 0
	mr	r3, r4			// r3=NVRAM_LOG address
	bne-	7, .initLog		// if header is not ok, init header
	li	r3, 0
	blr				// header OK, return 0			


/* this is basically just a copy of .initLog 
   registers used: r3, r4, r5, r6, r7, r9*/
init_log_2nd_be:
	mflr	r9	
	li	r6, LLFW_LOG_BE0_LENGTH
	mulli	r6, r6, 0x10
	add	r6, r7, r6
	li      r5, LLFW_LOG_BE1_SIGNATURE
	li      r4, LLFW_LOG_BE1_LENGTH
	stb     r5, 0(r6)
	sth     r4, LLFW_LOG_POS_LENGTH(r6)
	li      r5, LLFW_LOG_BE1_DATA_OFFSET
	li      r4, LLFW_LOG_BE1_FLAGS
	sth     r5, LLFW_LOG_POS_DATA_OFFSET(r6)
	sth     r4, LLFW_LOG_POS_FLAGS(r6)
	li      r5, 1

	LOAD32( r4, LLFW_LOG_BE1_NAME_PREFIX)
	stw     r5, LLFW_LOG_POS_POINTER(r6)
	stw     r4, (LLFW_LOG_POS_NAME+0x00)(r6)
	LOAD64( r5, LLFW_LOG_BE1_NAME)
	std     r5, (LLFW_LOG_POS_NAME+0x04)(r6)
	mr	r3, r6
	bl 	.calPartitionHeaderChecksum
	stb     r3, LLFW_LOG_POS_CHECKSUM(r6)
	mtlr	r9
	blr
/*****************************************************************************
 * initLog:	initialize the NVRAM with 0
 *		write a new NVRAM Log-Partition-Header
 *					
 *	input:	
 *		r3 - NVRAM BASE address 
 *
 *	output:	
 *		r3 - 0 = check ok, no new header written
 *		r3 - 1 = check not ok, header and NVRAM initialized
 *		r4 - NVRAM log address
 *
 *	Modifies Register:	R3, R4, R5, R6, R7, r8, r9
 ****************************************************************************/
ASM_ENTRY(.initLog)
 	mflr    r8
	mr	r7, r3

	bl clearNVRAM
0:
	li      r5, LLFW_LOG_BE0_SIGNATURE
	li      r4, LLFW_LOG_BE0_LENGTH
	stb     r5, 0(r7)
	sth     r4, LLFW_LOG_POS_LENGTH(r7)
	li      r5, LLFW_LOG_BE0_DATA_OFFSET
	li      r4, LLFW_LOG_BE0_FLAGS
	sth     r5, LLFW_LOG_POS_DATA_OFFSET(r7)
	sth     r4, LLFW_LOG_POS_FLAGS(r7)
	li      r5, 1

	LOAD32( r4, LLFW_LOG_BE0_NAME_PREFIX)
	stw     r5, LLFW_LOG_POS_POINTER(r7)
	stw     r4, (LLFW_LOG_POS_NAME+0x00)(r7)
	LOAD64( r5, LLFW_LOG_BE0_NAME)
	std     r5, (LLFW_LOG_POS_NAME+0x04)(r7)
	bl 	.calPartitionHeaderChecksum
	stb     r3, LLFW_LOG_POS_CHECKSUM(r7)
	bl	init_log_2nd_be			// create a second log partition for BE1
	mr	r4, r7
	li	r3, 1
	mtlr 	r8
	blr
/*****************************************************************************
 *	clearNVRAM:	set all not used NVRAM memory to zero
 *
 *
 *	input:	
 *		R3 - NVRAM BASE ADDRESS
 *
 *	output:	
 *		R3 - NVARM END ADDRESS
 *
 *	Modifies Register: r4, r5
 ****************************************************************************/
ASM_ENTRY(clearNVRAM)
	LOAD64(	r4, NVRAM_LENGTH)
	srdi	r4, r4, 3
	mtctr	r4
	li	r5, 0x0
	LOAD64(	r4, NVRAM_EMPTY_PATTERN)
0:
	stdx	r4, r3,r5
	addi	r5, r5, 8
	bdnz+	0b
	blr	
/*****************************************************************************
 * writeNVRAMbyte:	write next log into NVRAM
 *					
 *
 *	input:	
 *		R3 - byte to be written
 *		R4 - NVRAM Base Address
 *
 *	output:	
 *		R3 - byte that was written
 *		R4 - NVRAM Base Address 
 *
 * 	Modifies Register:	R3, R4, R5, R6
 ****************************************************************************/
ASM_ENTRY(.writeNVRAMbyte)
ENTRY(writeLogByte)
	NVRAM_POINTER_DATASIZE_BE0( r5, r6, r4)	// get pointer,size of data
	NVRAM_LOG_DATA_OVERFLOW( r5, r6)	// check for overflow
	addi    r5, r5, 1                       // increment pointer
	stw     r5, LLFW_LOG_POS_POINTER(r4)    // store pointer
	addi    r5, r5, -1			// restore old pointer
	add     r6, r4, r5                      // byte address in data section 

	stb 	r3, LLFW_LOG_BE0_DATA_OFFSET(r6)	
	blr

/*****************************************************************************
 * writeNVRAMbyte:	write next log into NVRAM
 *					
 *
 *	input:	
 *		R3 - byte to be written
 *		R4 - NVRAM Base Address
 *
 *	output:	
 *		R3 - byte that was written
 *		R4 - NVRAM Base Address 
 *
 * 	Modifies Register:	R3, R4, R5, R6
 ****************************************************************************/
ENTRY(writeLogByteBE1)
	li	r6, LLFW_LOG_BE0_LENGTH
	mulli	r6, r6, 0x10
	add	r4, r6, r4
	NVRAM_POINTER_DATASIZE_BE1( r5, r6, r4)	// get pointer,size of data
	NVRAM_LOG_DATA_OVERFLOW( r5, r6)	// check for overflow
	addi    r5, r5, 1                       // increment pointer
	stw     r5, LLFW_LOG_POS_POINTER(r4)    // store pointer
	addi    r5, r5, -1			// restore old pointer
	add     r6, r4, r5                      // byte address in data section 

	stb 	r3, LLFW_LOG_BE1_DATA_OFFSET(r6)	
	blr

/*****************************************************************************
 * calPartitionHeaderChecksum: 	calculate the Checksum of the 
 *	Partition Header as described in ....
 *
 *	input: r3 - NVRAM BASE adresse
 *
 *	output:	R3 - the calculated checksum as 8 bit value 
 *			R4 - NVRAM log address
 *
 *	Modifies Register:	R3, R4, R5, R6
 ****************************************************************************/
ASM_ENTRY(.calPartitionHeaderChecksum)
	mr	r6, r3
	lbz 	r3,0(r6)			// load first byte
	LOAD64( r4, LLFW_LOG_POS_LENGTH)	// load position of 3rd byte
.L6:
	lbzx 	r5, r4, r6			// r5  nexed byte
	addi 	r4, r4, 1			// r4++ (index)
	add 	r5, r5, r3			// r5 new sum =sum +  nexed byte
	rldicl 	r5, r5, 0, 56
	cmpld 	7, r5, r3					
	cmpldi 	6, r4, LLFW_LOG_POS_DATA_OFFSET
	bge+ 	7,.L5				// if new sum > sum 
	addi 	r5, r5, 1			// new sum ++
	rldicl	r5, r5, 0, 56
.L5:
	mr 	r3,r5				// sum = new sum
	blt+ 	6,.L6

	mr r4, r6
	blr

#else	/* defined(DISABLE_NVRAM) || defined(RTAS_NVRAM) */

ASM_ENTRY(.writeNVRAMbyte)
	ENTRY(writeLogByte)
	blr

#endif
