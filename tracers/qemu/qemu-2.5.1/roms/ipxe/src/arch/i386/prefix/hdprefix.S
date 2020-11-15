FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

	.text
	.arch i386
	.section ".prefix", "awx", @progbits
	.code16
	.org 0
	.globl	_hd_start
_hd_start:

	movw	$load_image, %bp
	jmp	find_active_partition

#include "bootpart.S"

load_image:
	/* Get disk geometry */
	pushal
	pushw	%es
	movb	$0x08, %ah
	int	$0x13
	jc	load_failed
	movb	%cl, max_sector
	movb	%dh, max_head
	popw	%es
	popal
	
1:	/* Read to end of current track */
	movb	%cl, %al
	negb	%al
	addb	max_sector, %al
	incb	%al
	andb	$0x3f, %al
	movzbl	%al, %eax
	call	*read_sectors
	jc	load_failed
	
	/* Update %es */
	movw	%es, %bx
	shll	$5, %eax
	addw	%ax, %bx
	movw	%bx, %es
	shrl	$5, %eax
	
	/* Update LBA address */
	addl	%eax, %edi
	adcl	$0, %esi
	
	/* Update CHS address */
	andb	$0xc0, %cl
	orb	$0x01, %cl
	incb	%dh
	cmpb	max_head, %dh
	jbe	2f
	xorb	%dh, %dh
	incb	%ch
	jnc	2f
	addb	$0xc0, %cl
2:
	/* Loop until whole image is read */
	subl	%eax, load_length
	ja	1b
	ljmp	$BOOT_SEG, $start_image

max_sector:
	.byte	0
max_head:
	.byte	0
load_length:
	.long	0
	
	.section ".zinfo.fixup", "a", @progbits	/* Compressor fixups */
	.ascii	"ADDL"
	.long	load_length
	.long	512
	.long	0
	.previous


load_failed:
	movw	$10f, %si
	jmp	boot_error
10:	.asciz	"Could not load iPXE\r\n"

	.org 510
	.byte 0x55, 0xaa

start_image:
	/* Install iPXE */
	call	install

	/* Set up real-mode stack */
	movw	%bx, %ss
	movw	$_estack16, %sp

	/* Jump to .text16 segment */
	pushw	%ax
	pushw	$1f
	lret
	.section ".text16", "awx", @progbits
1:
	pushl	$main
	pushw	%cs
	call	prot_call
	popl	%ecx /* discard */

	/* Uninstall iPXE */
	call	uninstall

	/* Boot next device */
	int $0x18
