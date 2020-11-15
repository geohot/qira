/*
 * Copyright (C) 2006 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

	.arch i386

/****************************************************************************
 * !PXE structure
 ****************************************************************************
 */
	.section ".text16.data", "aw", @progbits
	.globl ppxe
	.align 16
ppxe:
	.ascii "!PXE"			/* Signature */
	.byte pxe_length		/* StructLength */
	.byte 0				/* StructCksum */
	.byte 0				/* StructRev */
	.byte 0				/* reserved_1 */
	.word undiheader, 0		/* UNDIROMID */
	.word 0, 0			/* BaseROMID */
	.word pxe_entry_sp, 0		/* EntryPointSP */
	.word pxe_entry_esp, 0		/* EntryPointESP */
	.word -1, -1			/* StatusCallout */
	.byte 0				/* reserved_2 */
	.byte SegDescCnt		/* SegDescCnt */
	.word 0				/* FirstSelector */
pxe_segments:
	.word 0, 0, 0, _data16_memsz	/* Stack */
	.word 0, 0, 0, _data16_memsz	/* UNDIData */
	.word 0, 0, 0, _text16_memsz	/* UNDICode */
	.word 0, 0, 0, _text16_memsz	/* UNDICodeWrite */
	.word 0, 0, 0, 0		/* BC_Data */
	.word 0, 0, 0, 0		/* BC_Code */
	.word 0, 0, 0, 0		/* BC_CodeWrite */
	.equ	SegDescCnt, ( ( . - pxe_segments ) / 8 )
	.equ	pxe_length, . - ppxe
	.size	ppxe, . - ppxe

	/* Define undiheader=0 as a weak symbol for non-ROM builds */
	.section ".weak", "a", @nobits
	.weak	undiheader
undiheader:

/****************************************************************************
 * PXENV+ structure
 ****************************************************************************
 */
	.section ".text16.data", "aw", @progbits
	.globl pxenv
	.align 16
pxenv:
	.ascii "PXENV+"			/* Signature */
	.word 0x0201			/* Version */
	.byte pxenv_length		/* Length */
	.byte 0				/* Checksum */
	.word pxenv_entry, 0		/* RMEntry */
	.long 0				/* PMEntry */
	.word 0				/* PMSelector */
	.word 0				/* StackSeg */
	.word _data16_memsz		/* StackSize */
	.word 0				/* BC_CodeSeg */
	.word 0				/* BC_CodeSize */
	.word 0				/* BC_DataSeg */
	.word 0				/* BC_DataSize */
	.word 0				/* UNDIDataSeg */
	.word _data16_memsz		/* UNDIDataSize */
	.word 0				/* UNDICodeSeg */
	.word _text16_memsz		/* UNDICodeSize */
	.word ppxe, 0			/* PXEPtr */
	.equ	pxenv_length, . - pxenv
	.size	pxenv, . - pxenv
 
/****************************************************************************
 * pxenv_entry (16-bit far call)
 *
 * PXE API call PXENV+ entry point
 *
 * Parameters:
 *   %es:di : Far pointer to PXE parameter structure
 *   %bx : PXE API call
 * Returns:
 *   %ax : PXE exit status
 * Corrupts:
 *   none
 ****************************************************************************
 */
	/* Wyse Streaming Manager server (WLDRM13.BIN) assumes that
	 * the PXENV+ entry point is at UNDI_CS:0000; apparently,
	 * somebody at Wyse has difficulty distinguishing between the
	 * words "may" and "must"...
	 */
	.section ".text16.null", "ax", @progbits
	.code16
pxenv_null_entry:
	jmp	pxenv_entry

	.section ".text16", "ax", @progbits
	.code16
pxenv_entry:
	pushl	$pxe_api_call
	pushw	%cs
	call	prot_call
	addl	$4, %esp
	lret
	.size	pxenv_entry, . - pxenv_entry

/****************************************************************************
 * pxe_entry
 *
 * PXE API call !PXE entry point
 *
 * Parameters:
 *   stack : Far pointer to PXE parameter structure
 *   stack : PXE API call
 * Returns:
 *   %ax : PXE exit status
 * Corrupts:
 *   none
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
	.code16
pxe_entry:
pxe_entry_sp:
	/* Preserve original %esp */
	pushl	%esp
	/* Zero high word of %esp to allow use of common code */
	movzwl	%sp, %esp
	jmp	pxe_entry_common
pxe_entry_esp:
	/* Preserve %esp to match behaviour of pxe_entry_sp */
	pushl	%esp
pxe_entry_common:
	/* Save PXENV+ API call registers */
	pushw	%es
	pushw	%di
	pushw	%bx
	/* Load !PXE parameters from stack into PXENV+ registers */
	addr32 movw	18(%esp), %bx
	movw	%bx, %es
	addr32 movw	16(%esp), %di
	addr32 movw	14(%esp), %bx
	/* Make call as for PXENV+ */
	pushw	%cs
	call	pxenv_entry
	/* Restore PXENV+ registers */
	popw	%bx
	popw	%di
	popw	%es
	/* Restore original %esp and return */
	popl	%esp
	lret
	.size	pxe_entry, . - pxe_entry

/****************************************************************************
 * pxe_int_1a
 *
 * PXE INT 1A handler
 *
 * Parameters:
 *   %ax : 0x5650
 * Returns:
 *   %ax : 0x564e
 *   %es:bx : Far pointer to the PXENV+ structure
 *   %edx : Physical address of the PXENV+ structure
 *   CF cleared
 * Corrupts:
 *   none
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
	.code16
	.globl	pxe_int_1a
pxe_int_1a:
	pushfw
	cmpw	$0x5650, %ax
	jne	1f
	/* INT 1A,5650 - PXE installation check */
	xorl	%edx, %edx
	movw	%cs, %dx
	movw	%dx, %es
	movw	$pxenv, %bx
	shll	$4, %edx
	addl	$pxenv, %edx
	movw	$0x564e, %ax
	pushw	%bp
	movw	%sp, %bp
	andb	$~0x01, 8(%bp)	/* Clear CF on return */
	popw	%bp
	popfw
	iret
1:	/* INT 1A,other - pass through */
	popfw
	ljmp	*%cs:pxe_int_1a_vector

	.section ".text16.data", "aw", @progbits
	.globl	pxe_int_1a_vector
pxe_int_1a_vector:	.long 0
