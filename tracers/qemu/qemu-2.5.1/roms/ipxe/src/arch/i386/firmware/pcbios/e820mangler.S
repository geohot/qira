/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

	.text
	.arch i386
	.code16

#define SMAP 0x534d4150

/* Most documentation refers to the E820 buffer as being 20 bytes, and
 * the API makes it perfectly legitimate to pass only a 20-byte buffer
 * and expect to get valid data.  However, some morons at ACPI decided
 * to extend the data structure by adding an extra "extended
 * attributes" field and by including critical information within this
 * field, such as whether or not the region is enabled.  A caller who
 * passes in only a 20-byte buffer therefore risks getting very, very
 * misleading information.
 *
 * I have personally witnessed an HP BIOS that returns a value of
 * 0x0009 in the extended attributes field.  If we don't pass this
 * value through to the caller, 32-bit WinPE will die, usually with a
 * PAGE_FAULT_IN_NONPAGED_AREA blue screen of death.
 *
 * Allow a ridiculously large maximum value (64 bytes) for the E820
 * buffer as a guard against insufficiently creative idiots in the
 * future.
 */
#define E820MAXSIZE	64

/****************************************************************************
 *
 * Allowed memory windows
 *
 * There are two ways to view this list.  The first is as a list of
 * (non-overlapping) allowed memory regions, sorted by increasing
 * address.  The second is as a list of (non-overlapping) hidden
 * memory regions, again sorted by increasing address.  The second
 * view is offset by half an entry from the first: think about this
 * for a moment and it should make sense.
 *
 * xxx_memory_window is used to indicate an "allowed region"
 * structure, hidden_xxx_memory is used to indicate a "hidden region"
 * structure.  Each structure is 16 bytes in length.
 *
 ****************************************************************************
 */
	.section ".data16", "aw", @progbits
	.align 16
	.globl hidemem_base
	.globl hidemem_umalloc
	.globl hidemem_textdata
memory_windows:
base_memory_window:	.long 0x00000000, 0x00000000 /* Start of memory */

hidemem_base:		.long 0x000a0000, 0x00000000 /* Changes at runtime */
ext_memory_window:	.long 0x000a0000, 0x00000000 /* 640kB mark */

hidemem_umalloc:	.long 0xffffffff, 0xffffffff /* Changes at runtime */
			.long 0xffffffff, 0xffffffff /* Changes at runtime */

hidemem_textdata:	.long 0xffffffff, 0xffffffff /* Changes at runtime */
			.long 0xffffffff, 0xffffffff /* Changes at runtime */

			.long 0xffffffff, 0xffffffff /* End of memory */
memory_windows_end:

/****************************************************************************
 * Truncate region to memory window
 *
 * Parameters:
 *  %edx:%eax	Start of region
 *  %ecx:%ebx	Length of region
 *  %si		Memory window
 * Returns:
 *  %edx:%eax	Start of windowed region
 *  %ecx:%ebx	Length of windowed region
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
window_region:
	/* Convert (start,len) to (start, end) */
	addl	%eax, %ebx
	adcl	%edx, %ecx
	/* Truncate to window start */
	cmpl	4(%si), %edx
	jne	1f
	cmpl	0(%si), %eax
1:	jae	2f
	movl	4(%si), %edx
	movl	0(%si), %eax
2:	/* Truncate to window end */
	cmpl	12(%si), %ecx
	jne	1f
	cmpl	8(%si), %ebx
1:	jbe	2f
	movl	12(%si), %ecx
	movl	8(%si), %ebx
2:	/* Convert (start, end) back to (start, len) */
	subl	%eax, %ebx
	sbbl	%edx, %ecx
	/* If length is <0, set length to 0 */
	jae	1f
	xorl	%ebx, %ebx
	xorl	%ecx, %ecx
	ret
	.size	window_region, . - window_region

/****************************************************************************
 * Patch "memory above 1MB" figure
 *
 * Parameters:
 *  %ax		Memory above 1MB, in 1kB blocks
 * Returns:
 *  %ax		Modified memory above 1M in 1kB blocks
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
patch_1m:
	pushal
	/* Convert to (start,len) format and call truncate */
	xorl	%ecx, %ecx
	movzwl	%ax, %ebx
	shll	$10, %ebx
	xorl	%edx, %edx
	movl	$0x100000, %eax
	movw	$ext_memory_window, %si
	call	window_region
	/* Convert back to "memory above 1MB" format and return via %ax */
	pushfw
	shrl	$10, %ebx
	popfw
	movw	%sp, %bp
	movw	%bx, 28(%bp)
	popal
	ret
	.size patch_1m, . - patch_1m

/****************************************************************************
 * Patch "memory above 16MB" figure
 *
 * Parameters:
 *  %bx		Memory above 16MB, in 64kB blocks
 * Returns:
 *  %bx		Modified memory above 16M in 64kB blocks
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
patch_16m:
	pushal
	/* Convert to (start,len) format and call truncate */
	xorl	%ecx, %ecx
	shll	$16, %ebx
	xorl	%edx, %edx
	movl	$0x1000000, %eax
	movw	$ext_memory_window, %si
	call	window_region
	/* Convert back to "memory above 16MB" format and return via %bx */
	pushfw
	shrl	$16, %ebx
	popfw
	movw	%sp, %bp
	movw	%bx, 16(%bp)
	popal
	ret
	.size patch_16m, . - patch_16m

/****************************************************************************
 * Patch "memory between 1MB and 16MB" and "memory above 16MB" figures
 *
 * Parameters:
 *  %ax		Memory between 1MB and 16MB, in 1kB blocks
 *  %bx		Memory above 16MB, in 64kB blocks
 * Returns:
 *  %ax		Modified memory between 1MB and 16MB, in 1kB blocks
 *  %bx		Modified memory above 16MB, in 64kB blocks
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
patch_1m_16m:
	call	patch_1m
	call	patch_16m
	/* If 1M region is no longer full-length, kill off the 16M region */
	cmpw	$( 15 * 1024 ), %ax
	je	1f
	xorw	%bx, %bx
1:	ret
	.size patch_1m_16m, . - patch_1m_16m

/****************************************************************************
 * Get underlying e820 memory region to underlying_e820 buffer
 *
 * Parameters:
 *   As for INT 15,e820
 * Returns:
 *   As for INT 15,e820
 *
 * Wraps the underlying INT 15,e820 call so that the continuation
 * value (%ebx) is a 16-bit simple sequence counter (with the high 16
 * bits ignored), and termination is always via CF=1 rather than
 * %ebx=0.
 *
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
get_underlying_e820:

	/* If the requested region is in the cache, return it */
	cmpw	%bx, underlying_e820_index
	jne	2f
	pushw	%di
	pushw	%si
	movw	$underlying_e820_cache, %si
	cmpl	underlying_e820_cache_size, %ecx
	jbe	1f
	movl	underlying_e820_cache_size, %ecx
1:	pushl	%ecx
	rep movsb
	popl	%ecx
	popw	%si
	popw	%di
	incw	%bx
	movl	%edx, %eax
	clc
	ret
2:	
	/* If the requested region is earlier than the cached region,
	 * invalidate the cache.
	 */
	cmpw	%bx, underlying_e820_index
	jbe	1f
	movw	$0xffff, underlying_e820_index
1:
	/* If the cache is invalid, reset the underlying %ebx */
	cmpw	$0xffff, underlying_e820_index
	jne	1f
	andl	$0, underlying_e820_ebx
1:	
	/* If the cache is valid but the continuation value is zero,
	 * this means that the previous underlying call returned with
	 * %ebx=0.  Return with CF=1 in this case.
	 */
	cmpw	$0xffff, underlying_e820_index
	je	1f
	cmpl	$0, underlying_e820_ebx
	jne	1f
	stc
	ret
1:	
	/* Get the next region into the cache */
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	pushl	%esi	/* Some implementations corrupt %esi, so we	*/
	pushl	%edi	/* preserve %esi, %edi and %ebp to be paranoid	*/
	pushl	%ebp
	pushw	%es
	pushw	%ds
	popw	%es
	movw	$underlying_e820_cache, %di
	cmpl	$E820MAXSIZE, %ecx
	jbe	1f
	movl	$E820MAXSIZE, %ecx
1:	movl	underlying_e820_ebx, %ebx
	stc
	pushfw
	lcall	*%cs:int15_vector
	popw	%es
	popl	%ebp
	popl	%edi
	popl	%esi
	/* Check for error return from underlying e820 call */
	jc	2f /* CF set: error */
	cmpl	$SMAP, %eax
	je	3f /* 'SMAP' missing: error */
2:	/* An error occurred: return values returned by underlying e820 call */
	stc	/* Force CF set if SMAP was missing */
	addr32 leal 16(%esp), %esp /* avoid changing other flags */
	ret
3:	/* No error occurred */
	movl	%ebx, underlying_e820_ebx
	movl	%ecx, underlying_e820_cache_size
	popl	%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	/* Mark cache as containing this result */
	incw	underlying_e820_index

	/* Loop until found */
	jmp	get_underlying_e820
	.size	get_underlying_e820, . - get_underlying_e820

	.section ".data16", "aw", @progbits
underlying_e820_index:
	.word	0xffff /* Initialise to an invalid value */
	.size underlying_e820_index, . - underlying_e820_index

	.section ".bss16", "aw", @nobits
underlying_e820_ebx:
	.long	0
	.size underlying_e820_ebx, . - underlying_e820_ebx

	.section ".bss16", "aw", @nobits
underlying_e820_cache:
	.space	E820MAXSIZE
	.size underlying_e820_cache, . - underlying_e820_cache

	.section ".bss16", "aw", @nobits
underlying_e820_cache_size:
	.long	0
	.size	underlying_e820_cache_size, . - underlying_e820_cache_size

/****************************************************************************
 * Get windowed e820 region, without empty region stripping
 *
 * Parameters:
 *   As for INT 15,e820
 * Returns:
 *   As for INT 15,e820
 *
 * Wraps the underlying INT 15,e820 call so that each underlying
 * region is returned N times, windowed to fit within N visible-memory
 * windows.  Termination is always via CF=1.
 *
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
get_windowed_e820:

	/* Preserve registers */
	pushl	%esi
	pushw	%bp

	/* Split %ebx into %si:%bx, store original %bx in %bp */
	pushl	%ebx
	popw	%bp
	popw	%si

	/* %si == 0 => start of memory_windows list */
	testw	%si, %si
	jne	1f
	movw	$memory_windows, %si
1:	
	/* Get (cached) underlying e820 region to buffer */
	call	get_underlying_e820
	jc	99f /* Abort on error */

	/* Preserve registers */
	pushal
	/* start => %edx:%eax, len => %ecx:%ebx */
	movl	%es:0(%di), %eax
	movl	%es:4(%di), %edx
	movl	%es:8(%di), %ebx
	movl	%es:12(%di), %ecx
	/* Truncate region to current window */
	call	window_region
1:	/* Store modified values in e820 map entry */
	movl	%eax, %es:0(%di)
	movl	%edx, %es:4(%di)
	movl	%ebx, %es:8(%di)
	movl	%ecx, %es:12(%di)
	/* Restore registers */
	popal

	/* Derive continuation value for next call */
	addw	$16, %si
	cmpw	$memory_windows_end, %si
	jne	1f
	/* End of memory windows: reset %si and allow %bx to continue */
	xorw	%si, %si
	jmp	2f
1:	/* More memory windows to go: restore original %bx */
	movw	%bp, %bx
2:	/* Construct %ebx from %si:%bx */
	pushw	%si
	pushw	%bx
	popl	%ebx

98:	/* Clear CF */
	clc
99:	/* Restore registers and return */
	popw	%bp
	popl	%esi
	ret
	.size get_windowed_e820, . - get_windowed_e820

/****************************************************************************
 * Get windowed e820 region, with empty region stripping
 *
 * Parameters:
 *   As for INT 15,e820
 * Returns:
 *   As for INT 15,e820
 *
 * Wraps the underlying INT 15,e820 call so that each underlying
 * region is returned up to N times, windowed to fit within N
 * visible-memory windows.  Empty windows are never returned.
 * Termination is always via CF=1.
 *
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
get_nonempty_e820:

	/* Record entry parameters */
	pushl	%eax
	pushl	%ecx
	pushl	%edx

	/* Get next windowed region */
	call	get_windowed_e820
	jc	99f /* abort on error */

	/* If region is non-empty, finish here */
	cmpl	$0, %es:8(%di)
	jne	98f
	cmpl	$0, %es:12(%di)
	jne	98f

	/* Region was empty: restore entry parameters and go to next region */
	popl	%edx
	popl	%ecx
	popl	%eax
	jmp	get_nonempty_e820

98:	/* Clear CF */
	clc
99:	/* Return values from underlying call */
	addr32 leal 12(%esp), %esp /* avoid changing flags */
	ret
	.size get_nonempty_e820, . - get_nonempty_e820

/****************************************************************************
 * Get mangled e820 region, with empty region stripping
 *
 * Parameters:
 *   As for INT 15,e820
 * Returns:
 *   As for INT 15,e820
 *
 * Wraps the underlying INT 15,e820 call so that underlying regions
 * are windowed to the allowed memory regions.  Empty regions are
 * stripped from the map.  Termination is always via %ebx=0.
 *
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
get_mangled_e820:

	/* Get a nonempty region */
	call	get_nonempty_e820
	jc	99f /* Abort on error */

	/* Peek ahead to see if there are any further nonempty regions */
	pushal
	pushw	%es
	movw	%sp, %bp
	subw	%cx, %sp
	movl	$0xe820, %eax
	movl	$SMAP, %edx
	pushw	%ss
	popw	%es
	movw	%sp, %di
	call	get_nonempty_e820
	movw	%bp, %sp
	popw	%es
	popal
	jnc	99f /* There are further nonempty regions */

	/* No futher nonempty regions: zero %ebx and clear CF */
	xorl	%ebx, %ebx
	
99:	/* Return */
	ret
	.size get_mangled_e820, . - get_mangled_e820

/****************************************************************************
 * INT 15,e820 handler
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
int15_e820:
	pushw	%ds
	pushw	%cs:rm_ds
	popw	%ds
	call	get_mangled_e820
	popw	%ds
	call	patch_cf
	iret
	.size int15_e820, . - int15_e820
	
/****************************************************************************
 * INT 15,e801 handler
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
int15_e801:
	/* Call previous handler */
	pushfw
	lcall	*%cs:int15_vector
	call	patch_cf
	/* Edit result */
	pushw	%ds
	pushw	%cs:rm_ds
	popw	%ds
	call	patch_1m_16m
	xchgw	%ax, %cx
	xchgw	%bx, %dx
	call	patch_1m_16m
	xchgw	%ax, %cx
	xchgw	%bx, %dx
	popw	%ds
	iret
	.size int15_e801, . - int15_e801
	
/****************************************************************************
 * INT 15,88 handler
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
int15_88:
	/* Call previous handler */
	pushfw
	lcall	*%cs:int15_vector
	call	patch_cf
	/* Edit result */
	pushw	%ds
	pushw	%cs:rm_ds
	popw	%ds
	call	patch_1m
	popw	%ds
	iret
	.size int15_88, . - int15_88
		
/****************************************************************************
 * INT 15 handler
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
	.globl int15
int15:
	/* See if we want to intercept this call */
	pushfw
	cmpw	$0xe820, %ax
	jne	1f
	cmpl	$SMAP, %edx
	jne	1f
	popfw
	jmp	int15_e820
1:	cmpw	$0xe801, %ax
	jne	2f
	popfw
	jmp	int15_e801
2:	cmpb	$0x88, %ah
	jne	3f
	popfw
	jmp	int15_88
3:	popfw
	ljmp	*%cs:int15_vector
	.size int15, . - int15
	
	.section ".text16.data", "aw", @progbits
	.globl int15_vector
int15_vector:
	.long 0
	.size int15_vector, . - int15_vector
