/*
 * Interrupt handlers for GDB stub
 */

#define SIZEOF_I386_REGS	32
#define SIZEOF_I386_FLAGS	4

/****************************************************************************
 * Interrupt handlers
 ****************************************************************************
 */
	.section ".text", "ax", @progbits
	.code32

/* POSIX signal numbers for reporting traps to GDB */
#define SIGILL 4
#define SIGTRAP 5
#define SIGBUS 7
#define SIGFPE 8
#define SIGSEGV 11
#define SIGSTKFLT 16

	.globl	gdbmach_nocode_sigfpe
gdbmach_nocode_sigfpe:
	pushl	$SIGFPE
	jmp	gdbmach_interrupt

	.globl	gdbmach_nocode_sigtrap
gdbmach_nocode_sigtrap:
	pushl	$SIGTRAP
	jmp	gdbmach_interrupt

	.globl	gdbmach_nocode_sigstkflt
gdbmach_nocode_sigstkflt:
	pushl	$SIGSTKFLT
	jmp	gdbmach_interrupt

	.globl	gdbmach_nocode_sigill
gdbmach_nocode_sigill:
	pushl	$SIGILL
	jmp	gdbmach_interrupt

	.globl	gdbmach_withcode_sigbus
gdbmach_withcode_sigbus:
	movl	$SIGBUS, (%esp)
	jmp	gdbmach_interrupt

	.globl	gdbmach_withcode_sigsegv
gdbmach_withcode_sigsegv:
	movl	$SIGSEGV, (%esp)
	jmp	gdbmach_interrupt

/* When invoked, the stack contains: eflags, cs, eip, signo. */
#define IH_OFFSET_GDB_REGS ( 0 )
#define IH_OFFSET_GDB_EIP ( IH_OFFSET_GDB_REGS + SIZEOF_I386_REGS )
#define IH_OFFSET_GDB_EFLAGS ( IH_OFFSET_GDB_EIP + 4 )
#define IH_OFFSET_GDB_SEG_REGS ( IH_OFFSET_GDB_EFLAGS + SIZEOF_I386_FLAGS )
#define IH_OFFSET_GDB_END ( IH_OFFSET_GDB_SEG_REGS + 6 * 4 )
#define IH_OFFSET_SIGNO ( IH_OFFSET_GDB_END )
#define IH_OFFSET_OLD_EIP ( IH_OFFSET_SIGNO + 4 )
#define IH_OFFSET_OLD_CS ( IH_OFFSET_OLD_EIP + 4 )
#define IH_OFFSET_OLD_EFLAGS ( IH_OFFSET_OLD_CS + 4 )
#define IH_OFFSET_END ( IH_OFFSET_OLD_EFLAGS + 4 )

/* We also access the stack whilst still storing or restoring
 * the register snapshot.  Since ESP is in flux, we need
 * special offsets.
 */
#define IH_OFFSET_FLUX_OLD_CS ( IH_OFFSET_OLD_CS - 44 )
#define IH_OFFSET_FLUX_OLD_EFLAGS ( IH_OFFSET_OLD_EFLAGS - 40 )
#define IH_OFFSET_FLUX_OLD_EIP ( IH_OFFSET_OLD_EIP - 36 )
#define IH_OFFSET_FLUX_END ( IH_OFFSET_END - 20 )
gdbmach_interrupt:
	/* Store CPU state in GDB register snapshot */
	pushw	$0
	pushw	%gs
	pushw	$0
	pushw	%fs
	pushw	$0
	pushw	%es
	pushw	$0
	pushw	%ds
	pushw	$0
	pushw	%ss
	pushw	$0
	pushw	IH_OFFSET_FLUX_OLD_CS + 2(%esp)
	pushl	IH_OFFSET_FLUX_OLD_EFLAGS(%esp)
	pushl	IH_OFFSET_FLUX_OLD_EIP(%esp)
	pushl	%edi
	pushl	%esi
	pushl	%ebp
	leal	IH_OFFSET_FLUX_END(%esp), %edi
	pushl	%edi /* old ESP */
	pushl	%ebx
	pushl	%edx
	pushl	%ecx
	pushl	%eax

	/* Switch to virtual addressing */
	call	_intr_to_virt

	/* Call GDB stub exception handler */
	pushl	%esp
	pushl	(IH_OFFSET_SIGNO + 4)(%esp)
	call	gdbmach_handler
	addl	$8, %esp

	/* Copy register snapshot to new stack and switch to new stack */
	movl	%esp, %esi
	movl	(IH_OFFSET_GDB_SEG_REGS + 4)(%esp), %eax
	movl	%eax, %es
	movl	(IH_OFFSET_GDB_REGS + 16)(%esp), %edi
	subl	$IH_OFFSET_END, %edi
	movl	$(IH_OFFSET_END / 4), %ecx
	pushl	%edi
	ss rep movsl
	popl	%edi
	movl	%eax, %ss
	movl	%edi, %esp

	/* Restore CPU state from GDB register snapshot */
	popl	%eax
	popl	%ecx
	popl	%edx
	popl	%ebx
	popl	%ebp /* Skip %esp: already loaded */
	popl	%ebp
	popl	%esi
	popl	%edi
	popl	IH_OFFSET_FLUX_OLD_EIP(%esp)
	popl	IH_OFFSET_FLUX_OLD_EFLAGS(%esp)
	popl	IH_OFFSET_FLUX_OLD_CS(%esp)
	popl	%ds /* Skip %ss: already loaded */
	popl	%ds
	popl	%es
	popl	%fs
	popl	%gs

	addl	$4, %esp /* drop signo */
	iret
