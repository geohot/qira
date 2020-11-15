#include <linux/unistd.h>

	.section ".text"
	.code32
	.globl _linux_start
	.type _linux_start, @function

_linux_start:
	xorl	%ebp, %ebp

	popl	%esi       // save argc
	movl	%esp, %edi // save argv

	andl	$~15, %esp // 16-byte align the stack

	pushl	%edi // argv -> C arg2
	pushl	%esi // argc -> C arg1

	call	save_args

	/* Our main doesn't use any arguments */
	call	main

	movl	%eax, %ebx // rc -> syscall arg1
	movl	$__NR_exit, %eax
	int	$0x80

	.size _linux_start, . - _linux_start
