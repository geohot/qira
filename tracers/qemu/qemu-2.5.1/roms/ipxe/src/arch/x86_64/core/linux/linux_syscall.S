
	.section ".data"
	.globl linux_errno

linux_errno:	.int 0

	.section ".text"
	.code64
	.globl linux_syscall
	.type  linux_syscall, @function

linux_syscall:
	movq	%rdi, %rax    // C arg1 -> syscall number
	movq	%rsi, %rdi    // C arg2 -> syscall arg1
	movq	%rdx, %rsi    // C arg3 -> syscall arg2
	movq	%rcx, %rdx    // C arg4 -> syscall arg3
	movq	%r8, %r10     // C arg5 -> syscall arg4
	movq	%r9, %r8      // C arg6 -> syscall arg5
	movq	8(%rsp), %r9  // C arg7 -> syscall arg6

	syscall

	cmpq	$-4095, %rax
	jae	1f
	ret

1:
	negq	%rax
	movl	%eax, linux_errno
	movq	$-1, %rax
	ret

	.size linux_syscall, . - linux_syscall
