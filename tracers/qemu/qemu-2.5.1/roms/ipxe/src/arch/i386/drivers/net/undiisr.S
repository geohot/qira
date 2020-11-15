FILE_LICENCE ( GPL2_OR_LATER )

#define PXENV_UNDI_ISR 0x0014
#define PXENV_UNDI_ISR_IN_START 1
#define PXENV_UNDI_ISR_OUT_OURS 0
#define PXENV_UNDI_ISR_OUT_NOT_OURS 1

#define IRQ_PIC_CUTOFF 8
#define ICR_EOI_NON_SPECIFIC 0x20
#define PIC1_ICR 0x20
#define PIC2_ICR 0xa0
	
	.text
	.arch i386
	.code16

	.section ".text16", "ax", @progbits
	.globl undiisr
undiisr:
	
	/* Preserve registers */
	pushw	%ds
	pushw	%es
	pushw	%fs
	pushw	%gs
	pushfl
	pushal

	/* Set up our segment registers */
	movw	%cs:rm_ds, %ax
	movw	%ax, %ds

	/* Check that we have an UNDI entry point */
	cmpw	$0, pxeparent_entry_point
	je	chain
	
	/* Issue UNDI API call */
	movw	%ax, %es
	movw	$undinet_params, %di
	movw	$PXENV_UNDI_ISR, %bx
	movw	$PXENV_UNDI_ISR_IN_START, funcflag
	pushw	%es
	pushw	%di
	pushw	%bx
	lcall	*pxeparent_entry_point
	cli	/* Just in case */
	addw	$6, %sp
	cmpw	$PXENV_UNDI_ISR_OUT_OURS, funcflag
	jne	eoi
	
trig:	/* Record interrupt occurence */
	incb	undiisr_trigger_count

eoi:	/* Send EOI */
	movb	$ICR_EOI_NON_SPECIFIC, %al
	cmpb	$IRQ_PIC_CUTOFF, undiisr_irq
	jb	1f
	outb	%al, $PIC2_ICR
1:	outb	%al, $PIC1_ICR
	jmp	exit
	
chain:	/* Chain to next handler */
	pushfw
	lcall	*undiisr_next_handler
	
exit:	/* Restore registers and return */
	cli
	popal
	movzwl	%sp, %esp
	addr32	movl -20(%esp), %esp	/* %esp isn't restored by popal */
	popfl
	popw	%gs
	popw	%fs
	popw	%es
	popw	%ds
	iret

	.section ".data16", "aw", @progbits
undinet_params:
status:			.word	0
funcflag:		.word	0
bufferlength:		.word	0
framelength:		.word	0
frameheaderlength:	.word	0
frame:			.word	0, 0
prottype:		.byte	0
pkttype:		.byte	0
