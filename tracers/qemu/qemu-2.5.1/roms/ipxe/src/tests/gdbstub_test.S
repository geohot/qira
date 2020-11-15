	.arch i386

	.section ".data", "aw", @progbits
watch_me:
	.long 0xfeedbeef

	.section ".text", "ax", @progbits
	.code32
gdbstub_test:
	/* 1. Read registers test */
	movl    $0xea010203, %eax
	movl    $0xeb040506, %ebx
	movl    $0xec070809, %ecx
	movl    $0xed0a0b0c, %edx
	movl    $0x510d0e0f, %esi
	movl    $0xd1102030, %edi
	int	$3

	/* 2. Write registers test */
	int	$3

	/* 3. Read memory test */
	subl	$8, %esp
	movl	$0x11223344, 4(%esp)
	movw	$0x5566, 2(%esp)
	movb	$0x77, (%esp)
	int	$3

	/* 4. Write memory test */
	int	$3
	addl	$8, %esp

	/* 5. Step test */
	int	$3
	nop

	/* 6. Access watch test */
	movl	$0x600d0000, %ecx
	movl	watch_me, %eax
	movl	$0xbad00000, %ecx
	int	$3
	movl	$0x600d0001, %ecx
	movl	%eax, watch_me
	movl	$0xbad00001, %ecx
	int	$3

	/* 7. Write watch test */
	movl	$0x600d0002, %ecx
	movl	%eax, watch_me
	movl	$0xbad00002, %ecx
	int	$3

1:
	jmp	1b
