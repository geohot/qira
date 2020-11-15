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
#include "romfs.h"

/*******************************************************************
 * Wrapper for romfs_lookup.
 *
 * Input:
 * R3 = address of filename string
 * R4 = address of struct romfs_t
 *		 0: file size (return)
 *		 8: flags     (return)
 *		10: fileaddr  (return and input: tells if first search)
 *		18: nextfile  (return)
 *		20: namep     (return)
 *
 * Find File Procedure
 * - set filename and rombase, on return 0 file properties are stored
 *   in romfs_t else struct not valid
 * 
 * Listing procedure
 * - clear romfs_t (important!)
 * - set filename = NULL and rombase and call returns first file 
 *   with properties in romfs_t including next-file pointer
 * - if nextpointer is non-zero then just the next file is returned
 *
 * Returns:
 * <Success>: 
 *      R3 = 0
 *	romfs_t is updated
 * <FileNotFound>:
 *      R3 = 1
 * 	romfs_t not touched
 *
 * Potentially modifies the following registers:
 *
 
 Example usage from C:

  int list_bootrom()
  {
	struct romfs_t rfs;
	int i;

	printf("Build: "__TIME__" "__DATE__" \n");

	i = 0;
	memset((void*) &rfs, 0, sizeof(struct romfs_t));
	printf("         No. File      Data          Size  Name\n");

	while (romfs_stat(NULL, &rfs) == 0) {
		i++;
		printf("         %02d: %08X  %08X   %7d  %s\n",
				i, rfs.fileaddr, rfs.datap, 
				rfs.size, rfs.namep);
	}
	if (0 == i) {
		printf("Error in reading ROMFS\n");
		return 1;
	}
	return 0;
  }
 *******************************************************************/
#define RFS_T_SIZE	0x00
#define RFS_T_FLAGS	0x08
#define RFS_T_FILEADDR	0x10
#define RFS_T_NEXT	0x18
#define RFS_T_NAME	0x20
#define RFS_T_DATA	0x28

#define RFS_H_NEXT	0x00
#define RFS_H_SIZE	0x08
#define RFS_H_FLAGS	0x10
#define RFS_H_DATA	0x18
#define RFS_H_NAME	0x20

ENTRY(romfs_stat_file)
	/* save link register and romfs_t pointer         */
	mflr	r15
	mr	r16, r4

	/* if filename R3 is 0 then its a listing request */
	/* if not then just continue to lookup name       */
	/* save R4 to R8 which is the address of header   */
	li	r7, 0
	cmpd	r3, r7
	beq	romfs_list
	bl	romfs_lookup
	mfsprg	r8, 1

	/* if file found then go to romfs_fill_properties */
	/* else return 1 to caller                        */
	cmpwi	r3, 0
	beq	romfs_fill_properties
	b	romfs_stat_end

  romfs_list:
	/* check if fileaddr == 0, in this case its       */
	/* the first search on this handle, so return all */
	/* info for file at rombase (R8=R4)               */
	ld	r6, RFS_T_FILEADDR(r4)
	mfsprg	r8, 1
	li	r7, 0
	cmpd	r7, r6
	beq	romfs_fill_properties

	/* check if next file != 0   by looking into      */
	/* romfs_t, if not then return (next = 0) 1       */
	li	r7, 0
	ld	r4, RFS_T_NEXT(r4)
	cmpd	r7, r4
	li	r3, 1
	beq	romfs_stat_end

	/* now next file is available so move R8 to next  */
	/* file address                                   */
	mr	r8, r4

  romfs_fill_properties:
	/* set properties in romfs_t takes R8 as address  */
	/* to file header and R16 as address of romfs_t   */
	mfsprg	r3, 1
	std	r8, RFS_T_FILEADDR(r16)

	ld	r4, RFS_H_NEXT(r8)
	li	r7, 0
	cmpd	r7, r4
	beq	$ + (2 * 4) /* =0 so add no rombase */
	add	r4, r4, r3
	std	r4, RFS_T_NEXT(r16)

	ld	r4, RFS_H_SIZE(r8)
	std	r4, RFS_T_SIZE(r16)
	ld	r4, RFS_H_FLAGS(r8)
	std	r4, RFS_T_FLAGS(r16)

	ld	r4, RFS_H_DATA(r8)
	add	r4, r4, r3
	std	r4, RFS_T_DATA(r16)

	addi	r4, r8, RFS_H_NAME
	std	r4, RFS_T_NAME(r16)

	li	r3, 0

	/* restore romfs_t pointer and link register      */
  romfs_stat_end:
	mr	r5, r16
	mtlr	r15
	blr

/*******************************************************************
 * Copies the data of file referenced by name string to address 
 * requires root address of filesystem.
 * FIXME: ignores flags
 *
 * Input:
 * R3 = address of filename string
 * R4 = ROMBASE
 * R5 = destination address
 *
 * Returns:
 * <Success>: R3 = 0, R6 = size, <FileNotFound>: R3 = 1
 * R5 is kept
 *  
 * Potentially modifies the following registers:
 * ctr, r15, r16, r17, r18
 * 
 * Uses the following calls with subsequent register modification:
 * - romfs_lookup
 *******************************************************************/
ASM_ENTRY(romfs_load)
	mflr	r15
	
	/* save R5 twice              */
	/* lookup file, input regs    */
	/* are already set            */
	/* if not found, just return  */
	mr	r16, r5
	mr	r17, r5
	bl	romfs_lookup
	cmpwi	r3, 1
	bne	0f
	mtlr	r15
	blr     /* abort, not found   */

	/* save data size for return  */
	/* found, copy data           */
	/* data size is in R6         */
0:
	//mr	r3, r6
	mtctr	r6
	addi	r16, r16, -1 /* dest  */
	addi	r5, r5, -1   /* source*/

	/* data is expected to be     */
	/* 8 byte aligned             */
	/* copy loop                  */
0:	lbzu	r18, 1(r5)
	stbu	r18, 1(r16)
	bdnz	0b

	/* restore size, keep padding */
	/* restore target address     */
	/* return                     */
	mr	r5, r17
	mtlr	r15
	blr

/*******************************************************************
 * looks up a file based on filename 
 *
 * Input:
 * R3 = address of filename string
 * R4 = ROMBASE
 *
 * Returns:
 * <Success>: 
 *      R3 = 0
 *      R4 = address of file header
 *      R5 = address of data (real address)
 *      R6 = size of data
 *      R7 = flags for file
 * <FileNotFound>:
 *      R3 = 1
 *
 * Potentially modifies the following registers:
 * R3, R4, R5, R6, R7, R8, R9
 * 
 * Uses the following calls with subsequent register modification:
 * - romfs_namematch
 *******************************************************************/
ASM_ENTRY(romfs_lookup)
	mflr	r9
	
  romfs_lookup_next:
  	/* save current file base        */
	mr	r8, r4
  	/* name to look for              */
	mr	r10, r3 
	/* name of file                  */
	mr	r5,  r4
	addi	r5,  r5, (4 /* elems     */ * 8 /* elem-size */)
	mr	r11, r5 /* for namematch */
	/* compare                       */
	bl	romfs_namematch
	cmpwi	r12, 1
	bne	romfs_lookup_match

	/* load next pointer             */
	/* check if next is 0            */
	/* apply root-offset             */
	ld	r5, 0(r4)
	cmpwi	r5, 0
	add	r4, r4, r5
	bne	romfs_lookup_next
	/* last file reached, abort      */
	li	r3, 1
	mtlr	r9
	blr

	/* here the name did match       */
	/* r4 is still usable here and   */
	/* pointing to the initial file  */
	/* load r5 with data ptr         */
	/* load r6 with data size        */
	/* load r7 with flags            */
	/* get abs addr of data          */
  romfs_lookup_match:
	li	r3, 0
	ld	r5, (3 * 8)(r4) /* data  */
	ld	r6, (1 * 8)(r4) /* len   */
	ld	r7, (2 * 8)(r4) /* flags */
	add	r5, r5, r8
	mtlr	r9
	blr

/*******************************************************************
 * compares two strings in memory, 
 * both must be null-terminated and 8-byte aligned
 *
 * Input:
 * R10 = string 1
 * R11 = string 2
 *
 * Returns:
 * <Match>: R12 = 0 <NoMatch>: R12 = 1
 *
 * Potentially modifies the following registers:
 * R10, R11, r12, r13, r14 
 *******************************************************************/
romfs_namematch:
	subi	r10, r10, 8
	subi	r11, r11, 8

	/* 
	 * load chars as 8byte chunk from current pos, name is 
	 * always 8 byte aligned :)
	 */
  romfs_cmp_loop:
	ldu	r13, 8(r10) /* A */
	ldu	r14, 8(r11) /* B */

	cmpd	r13, r14
	li	r12, 1
	beq	1f
	blr

1:	andi.	r14, r14, 0xff
	bne	romfs_cmp_loop

	li	r12, 0
	blr

/*******************************************************************
 * wrapper for romfs_lookup
 * this function saves the registers from r13 - r15 on the stack
 * calls romfs_lookup
 * restores the saved registers
 *
 * the return parameters are copied to (r5) and (r5) has to
 * be 0x20 big
 *******************************************************************/
ENTRY(c_romfs_lookup)
	stdu	r1,-0x50(r1)		# allocate space on stack

	mflr	r0			# save link register
	std	r0,0x30(r1)

	std	r15,0x38(r1)		# save r15
	std	r14,0x40(r1)		# save r14
	std	r13,0x48(r1)		# and r13
	
	mr	r15,r5			# save the pointer for the return value

	bl	romfs_lookup		# do the thing

	ld	r0,0x30(r1)		# restore link register
	mtlr	r0

	std	r4,0x00(r15)		# copy return values
	std	r5,0x08(r15)		# to the return pointer
	std	r6,0x10(r15)
	std	r7,0x18(r15)

	ld	r13,0x48(r1)		# restore registers from stack
	ld	r14,0x40(r1)
	ld	r15,0x38(r1)

	addi	r1,r1,0x50		# cleanup stack

	blr
