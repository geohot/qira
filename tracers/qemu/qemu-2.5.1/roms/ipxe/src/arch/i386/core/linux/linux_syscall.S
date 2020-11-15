
	.section ".data"
	.globl linux_errno

linux_errno:	.int 0

	.section ".text"
	.code32
	.globl linux_syscall
	.type  linux_syscall, @function

linux_syscall:
	/* Save registers */
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	pushl	%ebp

	movl	20(%esp), %eax  // C arg1 -> syscall number
	movl	24(%esp), %ebx  // C arg2 -> syscall arg1
	movl	28(%esp), %ecx  // C arg3 -> syscall arg2
	movl	32(%esp), %edx  // C arg4 -> syscall arg3
	movl	36(%esp), %esi  // C arg5 -> syscall arg4
	movl	40(%esp), %edi  // C arg6 -> syscall arg5
	movl	44(%esp), %ebp  // C arg7 -> syscall arg6

	int	$0x80

	/* Restore registers */
	popl	%ebp
	popl	%edi
	popl	%esi
	popl	%ebx

	cmpl	$-4095, %eax
	jae	1f
	ret

1:
	negl	%eax
	movl	%eax, linux_errno
	movl	$-1, %eax
	ret

	.size linux_syscall, . - linux_syscall
