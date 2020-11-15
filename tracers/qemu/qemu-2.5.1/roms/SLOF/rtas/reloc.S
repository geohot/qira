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

#include <rtas.h>		
			
/*
Function:	
	Input:
		r3:   Destination to copy rtas code to
		r4:   Configuration	
	Output:		
		r3:   Entry point for rtas calls	
Decription: Called by OpenFirmware to instantiate rtas, needs to copy
	itself to destination, also do a relocations.
	
*/

.extern	rtas_entry
.extern .stack
.extern _got
.extern _got_end
.extern __bss_start
.extern __bss_end
.extern rtas_config


	.section        ".rtasstart","ax";
	.align	3
	.globl _rtas_start
_rtas_start:
	mflr	r10		# save link register
	bcl	20,31,.over	# branch (always) to .over 

.base:
	.align  3

/* Our Open Firmware needs to know the size of the RTAS binary and the
 * size & address of the RTAS function jump table. SLOF always looks for this
 * information in the following three quads here at the very beginning of the
 * RTAS binary at offset 8. So DO NOT DELETE/MOVE them! */

._rtas_size:		.quad	_rtas_end-_rtas_start
._ptr_to_func_tab:	.quad	rtas_func_tab-_rtas_start
._ptr_to_func_tab_size:	.quad	rtas_func_tab_size-_rtas_start

/* The other variables are not accessed by SLOF anymore: */

._rel_offset:		.quad   _reloc_table_start-_rtas_start
._rel_end_offset:	.quad   _reloc_table_end-_rtas_start
._bss_offset:		.quad   __bss_start-_rtas_start
._bss_end_offset:	.quad   __bss_end-_rtas_start
._rtas_entry_offset:	.quad   rtas_entry-_rtas_start
._rtas_config_offset:	.quad   rtas_config-_rtas_start
._rtas_stack:	        .quad   .stack-_rtas_start+RTAS_STACKSIZE-0x60
._rtas_toc:	        .quad   _got-_rtas_start

.over:	
	mflr r8			# gpr 8 is the base
	addi r8,r8,_rtas_start-.base # points to _rtas_start
	mr r11,r4		# Save config value	
	
# Copy rtas code
	
	ld r5,._rtas_size-_rtas_start(r8) 
	mr r4,r8		# Start of rtas
	addi r6,r3,-8		# Destination
	addi r4,r4,-8		# Source
	srdi r5,r5,3		# Count in quads
	mtctr r5
0:				
	ldu r0,8(r4)		
	stdu r0,8(r6)
	bdnz 0b		

# Clear bss

	ld r4,._bss_offset-_rtas_start(r8)
	ld r5,._bss_end_offset-_rtas_start(r8)
	li r0,0
	add r6,r3,r4		# Address bss in copied code
	addi r6,r6,-8
	sub r5,r5,r4		# Calculate bss size
	srdi r5,r5,3		# Count in quads
	mtctr r5	
0:	
	stdu r0,8(r6)
	bdnz 0b

# Relocate got

	ld	r4, ._rel_offset-_rtas_start(r8)
	ld	r5, ._rel_end_offset-_rtas_start(r8)
	sub	r5, r5,r4	# Calculate reloc table size
	cmpdi	r5, 0		# No reloc table ?
	beq	1f

	add	r4, r4, r3	# Calculate reloc table address
	addi	r4, r4, -4
	srdi	r5, r5, 2	# Count in words	
	mtctr	r5
0:	
	lwzu	r6, 4(r4)	# Load offset out of reloc table
	ldx	r0, r6, r3	# Load value 	
	add	r0, r0, r3	# Add relocation offset = load address
	stdx	r0, r6, r3
	bdnz	0b		
1:			

# Save config data

	ld r5,._rtas_config_offset-_rtas_start(r8)
	add r5,r5,r3
	std r11,0(r5)
	
# Flush to memory
	
	mr r4,r3		# Destination address
	ld r5,._rtas_size-_rtas_start(r8) 
		
	add r5,r5,r4
	addi r5,r5,127
	rlwinm r4,r4,0,0,24
	rlwinm r5,r5,0,0,24
	sub r5,r5,r4
	srwi r5,r5,7
	mtctr r5
0:
	dcbst 0,r4
	sync
	icbi 0,r4
	sync
	isync
	addi r4,r4,128
	bdnz 0b

# Call init function
	mfmsr	r11			# Switch to 64 bit mode
	mr	r7,r11
	rotldi	r11,r11,1
	ori	r11,r11,1
	rotldi	r11,r11,63
	mtmsrd	r11
	isync
	mr	r9,r1			# save old stack pointer
	ld	r1,._rtas_stack-_rtas_start(r8)	# load new stack pointer
	add	r1,r1,r3
	std	r9,0(r1)		# save stack pointer
	std	r2,64(r1)		# save toc
	std	r7,72(r1)		# save old msr value

	ld	r2,._rtas_toc-_rtas_start(r8)	# load got pointer
	add	r2,r2,r3

	bl	save_regs_r3_r12
	bl	.rtas_init
	bl	restore_regs_r3_r12

	ld	r11,72(r1)		# restore msr value	
	ld	r2,64(r1)		# restore toc
	ld	r1,0(r1)		# get old stack

	mtmsrd	r11			# restore msr
	isync


# Return rtas entry

	ld r4,._rtas_entry_offset-_rtas_start(r8)
	add r3,r3,r4
	mtlr	r10
	blr	



