FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

	.text
	.code64

	/* Must match jmp_buf structure layout */
	.struct	0
env_retaddr:	.quad	0
env_stack:	.quad	0
env_rbx:	.quad	0
env_rbp:	.quad	0
env_r12:	.quad	0
env_r13:	.quad	0
env_r14:	.quad	0
env_r15:	.quad	0
	.previous

/*
 * Save stack context for non-local goto
 */
	.globl	setjmp
setjmp:
	/* Save return address */
	movq	0(%rsp), %rax
	movq	%rax, env_retaddr(%rdi)
	/* Save stack pointer */
	movq	%rsp, env_stack(%rdi)
	/* Save other registers */
	movq	%rbx, env_rbx(%rdi)
	movq	%rbp, env_rbp(%rdi)
	movq	%r12, env_r12(%rdi)
	movq	%r13, env_r13(%rdi)
	movq	%r14, env_r14(%rdi)
	movq	%r15, env_r15(%rdi)
	/* Return 0 when returning as setjmp() */
	xorq	%rax, %rax
	ret
	.size	setjmp, . - setjmp

/*
 * Non-local jump to a saved stack context
 */
	.globl	longjmp
longjmp:
	/* Get result in %rax */
	movq	%rsi, %rax
	/* Force result to non-zero */
	testq	%rax, %rax
	jnz	1f
	incq	%rax
1:	/* Restore stack pointer */
	movq	env_stack(%rdi), %rsp
	/* Restore other registers */
	movq	env_rbx(%rdi), %rbx
	movq	env_rbp(%rdi), %rbp
	movq	env_r12(%rdi), %r12
	movq	env_r13(%rdi), %r13
	movq	env_r14(%rdi), %r14
	movq	env_r15(%rdi), %r15
	/* Replace return address on the new stack */
	popq	%rcx	/* discard */
	pushq	env_retaddr(%rdi)
	/* Return to setjmp() caller */
	ret
	.size	longjmp, . - longjmp
