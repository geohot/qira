FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

	.text
	.arch i386
	.code16
	.section ".prefix", "ax", @progbits
	.org 0

nbi_header:
	
/*****************************************************************************
 * NBI file header
 *****************************************************************************
 */
file_header:
	.long	0x1b031336	/* Signature */
	.byte	0x04		/* 16 bytes header, no vendor info */
	.byte	0
	.byte	0
	.byte	0		/* No flags */
	.word	0x0000, 0x07c0	/* Load header to 0x07c0:0x0000 */
	.word	_nbi_start, 0x07c0	/* Start execution at 0x07c0:entry */
	.size	file_header, . - file_header

/*****************************************************************************
 * NBI segment header
 *****************************************************************************
 */
segment_header:
	.byte	0x04		/* 16 bytes header, no vendor info */
	.byte	0
	.byte	0
	.byte	0x04		/* Last segment */
	.long	0x00007e00
imglen:	.long	-512
memlen:	.long	-512
	.size	segment_header, . - segment_header

	.section ".zinfo.fixup", "a", @progbits	/* Compressor fixups */
	.ascii	"ADDL"
	.long	imglen
	.long	1
	.long	0
	.ascii	"ADDL"
	.long	memlen
	.long	1
	.long	0
	.previous

/*****************************************************************************
 * NBI entry point
 *****************************************************************************
 */
	.globl	_nbi_start
_nbi_start:
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

	/* Reboot system */
	int $0x19

	.previous
	.size	_nbi_start, . - _nbi_start

nbi_header_end:
	.org 512
