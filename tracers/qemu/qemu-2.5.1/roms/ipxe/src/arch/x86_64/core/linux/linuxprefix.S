#include <linux/unistd.h>

	.section ".text"
	.code64
	.globl _linux_start
	.type _linux_start, @function

_linux_start:
	xorq	%rbp, %rbp

	popq	%rdi       // argc -> C arg1
	movq	%rsp, %rsi // argv -> C arg2

	andq	$~15, %rsp // 16-byte align the stack

	call	save_args

	/* Our main doesn't use any arguments */
	call	main

	movq	%rax, %rdi // rc -> syscall arg1
	movq	$__NR_exit, %rax
	syscall

	.size _linux_start, . - _linux_start
