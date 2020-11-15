	.globl	entry, __switch_context, __exit_context, halt

	.text
	.align	4

/*
 * Entry point
 * We start execution from here.
 * It is assumed that CPU is in 32-bit protected mode and
 * all segments are 4GB and base zero (flat model).
 */
entry:
	/* Save boot context and switch to our main context.
	 * Main context is statically defined in C.
	 */
	pushl	%cs
	call	__switch_context

	/* We get here when the main context switches back to
	 * the boot context.
	 * Return to previous bootloader.
	 */
	ret

/*
 * Switch execution context
 * This saves registers, segments, and GDT in the stack, then
 * switches the stack, and restores everything from the new stack.
 * This function takes no argument. New stack pointer is
 * taken from global variable __context, and old stack pointer
 * is also saved to __context. This way we can just jump to
 * this routine to get back to the original context.
 *
 * Call this routine with lcall or pushl %cs; call.
 */
__switch_context:
	/* Save everything in current stack */
	pushfl		    /* 56 */
	pushl	%ds	    /* 52 */
	pushl	%es	    /* 48 */
	pushl	%fs	    /* 44 */
	pushl	%gs	    /* 40 */
	pushal		    /* 8 */
	subl	$8, %esp
	movw	%ss, (%esp) /* 0 */
	sgdt	2(%esp)	    /* 2 */

#if 0
	/* Swap %cs and %eip on the stack, so lret will work */
	movl	60(%esp), %eax
	xchgl	%eax, 64(%esp)
	movl	%eax, 60(%esp)
#endif

	/* At this point we don't know if we are on flat segment
	 * or relocated. So compute the address offset from %eip.
	 * Assuming CS.base==DS.base==SS.base.
	 */
	call	1f
1:	popl	%ebx
	subl	$1b, %ebx

	/* Interrupts are not allowed... */
	cli

	/* Current context pointer is our stack pointer */
	movl	%esp, %esi

	/* Normalize the ctx pointer */
	subl	%ebx, %esi

	/* Swap it with new value */
	xchgl	%esi, __context(%ebx)

	/* Adjust new ctx pointer for current address offset */
	addl	%ebx, %esi

	/* Load new %ss and %esp to temporary */
	movzwl	(%esi), %edx
	movl	20(%esi), %eax

	/* Load new GDT */
	lgdt	2(%esi)

	/* Load new stack segment with new GDT */
	movl	%edx, %ss

	/* Set new stack pointer, but we have to adjust it because
	 * pushal saves %esp value before pushal, and we want the value
	 * after pushal.
	 */
	leal	-32(%eax), %esp

	/* Load the rest from new stack */
	popal
	popl	%gs
	popl	%fs
	popl	%es
	popl	%ds
	popfl

	/* Finally, load new %cs and %eip */
	lret

__exit_context:
	/* Get back to the original context */
	pushl	%cs
	call	__switch_context

	/* We get here if the other context attempt to switch to this
	 * dead context. This should not happen. */

halt:
	cli
	hlt
	jmp	halt
