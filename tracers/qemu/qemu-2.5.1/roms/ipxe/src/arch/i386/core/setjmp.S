FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

	.text
	.arch i386
	.code32

	/* Must match jmp_buf structure layout */
	.struct	0
env_retaddr:	.long	0
env_stack:	.long	0
env_ebx:	.long	0
env_esi:	.long	0
env_edi:	.long	0
env_ebp:	.long	0
	.previous

/*
 * Save stack context for non-local goto
 */
	.globl	setjmp
setjmp:
	/* Get jmp_buf pointer in %edx */
	movl	4(%esp),%edx
	/* Save return address */
	movl	0(%esp),%eax
	movl	%eax, env_retaddr(%edx)
	/* Save stack pointer */
	movl	%esp, env_stack(%edx)
	/* Save other registers */
	movl	%ebx, env_ebx(%edx)
	movl	%esi, env_esi(%edx)
	movl	%edi, env_edi(%edx)
	movl	%ebp, env_ebp(%edx)
	/* Return 0 when returning as setjmp() */
	xorl	%eax, %eax
	ret
	.size	setjmp, . - setjmp

/*
 * Non-local jump to a saved stack context
 */
	.globl	longjmp
longjmp:
	/* Get jmp_buf pointer in %edx */
	movl	4(%esp),%edx
	/* Get result in %eax */
	movl	8(%esp),%eax
	/* Force result to non-zero */
	testl	%eax, %eax
	jnz	1f
	incl	%eax
1:	/* Restore stack pointer */
	movl	env_stack(%edx), %esp
	/* Restore other registers */
	movl	env_ebx(%edx), %ebx
	movl	env_esi(%edx), %esi
	movl	env_edi(%edx), %edi
	movl	env_ebp(%edx), %ebp
	/* Replace return address on the new stack */
	popl	%ecx	/* discard */
	pushl	env_retaddr(%edx)
	/* Return to setjmp() caller */
	ret
	.size	longjmp, . - longjmp
