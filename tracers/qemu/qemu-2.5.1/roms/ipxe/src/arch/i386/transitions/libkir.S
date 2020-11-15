/*
 * libkir: a transition library for -DKEEP_IT_REAL
 *
 * Michael Brown <mbrown@fensystems.co.uk>
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

/****************************************************************************
 * This file defines libkir: an interface between external and
 * internal environments when -DKEEP_IT_REAL is used, so that both
 * internal and external environments are in real mode.  It deals with
 * switching data segments and the stack.  It provides the following
 * functions:
 *
 * ext_to_kir &		switch between external and internal (kir)
 * kir_to_ext		environments, preserving all non-segment
 *			registers
 *
 * kir_call		issue a call to an internal routine from external
 *			code
 *
 * libkir is written to avoid assuming that segments are anything
 * other than opaque data types, and also avoids assuming that the
 * stack pointer is 16-bit.  This should enable it to run just as well
 * in 16:16 or 16:32 protected mode as in real mode.
 ****************************************************************************
 */

/* Breakpoint for when debugging under bochs */
#define BOCHSBP xchgw %bx, %bx

	.text
	.arch i386
	.section ".text16", "awx", @progbits
	.code16
	
/****************************************************************************
 * init_libkir (real-mode or 16:xx protected-mode far call)
 *
 * Initialise libkir ready for transitions to the kir environment
 *
 * Parameters:
 *   %cs : .text16 segment
 *   %ds : .data16 segment
 ****************************************************************************
 */
	.globl	init_libkir
init_libkir:
	/* Record segment registers */
	pushw	%ds
	popw	%cs:kir_ds
	lret
	
/****************************************************************************
 * ext_to_kir (real-mode or 16:xx protected-mode near call)
 *
 * Switch from external stack and segment registers to internal stack
 * and segment registers.  %ss:sp is restored from the saved kir_ds
 * and kir_sp.  %ds, %es, %fs and %gs are all restored from the saved
 * kir_ds.  All other registers are preserved.
 *
 * %cs:0000 must point to the start of the runtime image code segment
 * on entry.
 *
 * Parameters: none
 ****************************************************************************
 */

	.globl	ext_to_kir
ext_to_kir:
	/* Record external segment registers */
	movw	%ds, %cs:ext_ds
	pushw	%cs
	popw	%ds	/* Set %ds = %cs for easier access to variables */
	movw	%es, %ds:ext_es
	movw	%fs, %ds:ext_fs
	movw	%gs, %ds:ext_fs

	/* Preserve registers */
	movw	%ax, %ds:save_ax

	/* Extract near return address from stack */
	popw	%ds:save_retaddr

	/* Record external %ss:esp */
	movw	%ss, %ds:ext_ss
	movl	%esp, %ds:ext_esp

	/* Load internal segment registers and stack pointer */
	movw	%ds:kir_ds, %ax
	movw	%ax, %ss
	movzwl	%ds:kir_sp, %esp
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
1:

	/* Place return address on new stack */
	pushw	%cs:save_retaddr
	
	/* Restore registers and return */
	movw	%cs:save_ax, %ax
	ret

/****************************************************************************
 * kir_to_ext (real-mode or 16:xx protected-mode near call)
 *
 * Switch from internal stack and segment registers to external stack
 * and segment registers.  %ss:%esp is restored from the saved ext_ss
 * and ext_esp.  Other segment registers are restored from the
 * corresponding locations.  All other registers are preserved.
 *
 * Note that it is actually %ss that is recorded as kir_ds, on the
 * assumption that %ss == %ds when kir_to_ext is called.
 *
 * Parameters: none
 ****************************************************************************
 */

	.globl	kir_to_ext
kir_to_ext:
	/* Record near return address */
	pushw	%cs
	popw	%ds	/* Set %ds = %cs for easier access to variables */
	popw	%ds:save_retaddr
	
	/* Record internal segment registers and %sp */
	movw	%ss, %ds:kir_ds
	movw	%sp, %ds:kir_sp

	/* Load external segment registers and stack pointer */
	movw	%ds:ext_ss, %ss
	movl	%ds:ext_esp, %esp
	movw	%ds:ext_gs, %gs
	movw	%ds:ext_fs, %fs
	movw	%ds:ext_es, %es
	movw	%ds:ext_ds, %ds

	/* Return */
	pushw	%cs:save_retaddr
	ret
	
/****************************************************************************
 * kir_call (real-mode or 16:xx protected-mode far call)
 *
 * Call a specific C function in the internal code.  The prototype of
 * the C function must be
 *   void function ( struct i386_all_resg *ix86 ); 
 * ix86 will point to a struct containing the real-mode registers
 * at entry to kir_call.
 *
 * All registers will be preserved across kir_call(), unless the C
 * function explicitly overwrites values in ix86.  Interrupt status
 * will also be preserved.
 *
 * Parameters:
 *   function : (32-bit) virtual address of C function to call
 *
 * Example usage:
 *	pushl	$pxe_api_call
 *	lcall	$UNDI_CS, $kir_call
 *	addw	$4, %sp
 * to call in to the C function
 *      void pxe_api_call ( struct i386_all_regs *ix86 );
 ****************************************************************************
 */

	.globl	kir_call
kir_call:
	/* Preserve flags.  Must do this before any operation that may
	 * affect flags.
	 */
	pushfl
	popl	%cs:save_flags

	/* Disable interrupts.  We do funny things with the stack, and
	 * we're not re-entrant.
	 */
	cli
		
	/* Extract address of internal routine from stack.  We must do
	 * this without using (%bp), because we may be called with
	 * either a 16-bit or a 32-bit stack segment.
	 */
	popl	%cs:save_retaddr	/* Scratch location */
	popl	%cs:save_function
	subl	$8, %esp		/* Restore %esp */
	
	/* Switch to internal stack.  Note that the external stack is
	 * inaccessible once we're running internally (since we have
	 * no concept of 48-bit far pointers)
	 */
	call	ext_to_kir
	
	/* Store external registers on internal stack */
	pushl	%cs:save_flags
	pushal
	pushl	%cs:ext_fs_and_gs
	pushl	%cs:ext_ds_and_es
	pushl	%cs:ext_cs_and_ss

	/* Push &ix86 on stack and call function */
	sti
	pushl	%esp
	data32 call *%cs:save_function
	popl	%eax /* discard */
	
	/* Restore external registers from internal stack */
	popl	%cs:ext_cs_and_ss
	popl	%cs:ext_ds_and_es
	popl	%cs:ext_fs_and_gs
	popal
	popl	%cs:save_flags

	/* Switch to external stack */
	call	kir_to_ext

	/* Restore flags */
	pushl	%cs:save_flags
	popfl

	/* Return */
	lret

/****************************************************************************
 * Stored internal and external stack and segment registers
 ****************************************************************************
 */
	
ext_cs_and_ss:	
ext_cs:		.word 0
ext_ss:		.word 0
ext_ds_and_es:	
ext_ds:		.word 0
ext_es:		.word 0
ext_fs_and_gs:	
ext_fs:		.word 0
ext_gs:		.word 0
ext_esp:	.long 0

		.globl kir_ds
kir_ds:		.word 0
		.globl kir_sp
kir_sp:		.word _estack

/****************************************************************************
 * Temporary variables
 ****************************************************************************
 */
save_ax:	.word 0
save_retaddr:	.long 0
save_flags:	.long 0
save_function:	.long 0
