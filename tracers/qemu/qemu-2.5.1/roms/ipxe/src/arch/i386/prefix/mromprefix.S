/*
 * Copyright (C) 2010 Michael Brown <mbrown@fensystems.co.uk>.
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

#define PCIBIOS_READ_CONFIG_WORD	0xb109
#define PCIBIOS_READ_CONFIG_DWORD	0xb10a
#define PCIBIOS_WRITE_CONFIG_WORD	0xb10c
#define PCIBIOS_WRITE_CONFIG_DWORD	0xb10d
#define PCI_COMMAND			0x04
#define PCI_COMMAND_MEM				0x02
#define PCI_BAR_0			0x10
#define PCI_BAR_5			0x24
#define PCI_BAR_EXPROM			0x30

#define PCIR_SIGNATURE ( 'P' + ( 'C' << 8 ) + ( 'I' << 16 ) + ( 'R' << 24 ) )

#define ROMPREFIX_EXCLUDE_PAYLOAD 1
#define ROMPREFIX_MORE_IMAGES 1
#define _pcirom_start _mrom_start
#include "pciromprefix.S"

	.text
	.arch i386
	.code16

/* Obtain access to payload by exposing the expansion ROM BAR at the
 * address currently used by a suitably large memory BAR on the same
 * device.  The memory BAR is temporarily disabled.  Using a memory
 * BAR on the same device means that we don't have to worry about the
 * configuration of any intermediate PCI bridges.
 *
 * Parameters:
 *   %ds:0000 : Prefix
 *   %esi : Buffer for copy of image source (or zero if no buffer available)
 *   %ecx : Expected offset within buffer of first payload block
 * Returns:
 *   %esi : Valid image source address (buffered or unbuffered)
 *   %ecx : Actual offset within buffer of first payload block
 *   CF set on error
 */
	.section ".text16.early", "awx", @progbits
	.globl	open_payload
open_payload:
	/* Preserve registers */
	pushl	%eax
	pushw	%bx
	pushl	%edx
	pushl	%edi
	pushw	%bp
	pushw	%es
	pushw	%ds

	/* Retrieve bus:dev.fn from .prefix */
	movw	init_pci_busdevfn, %bx

	/* Set up %ds for access to .text16.early */
	pushw	%cs
	popw	%ds

	/* Set up %es for access to flat address space */
	xorw	%ax, %ax
	movw	%ax, %es

	/* Store bus:dev.fn to .text16.early */
	movw	%bx, payload_pci_busdevfn

	/* Get expansion ROM BAR current value */
	movw	$PCI_BAR_EXPROM, %di
	call	pci_read_bar
	movl	%eax, rom_bar_orig_value

	/* Get expansion ROM BAR size */
	call	pci_size_mem_bar_low
	movl	%ecx, rom_bar_size

	/* Find a suitable memory BAR to use */
	movw	$PCI_BAR_0, %di		/* %di is PCI BAR register */
	xorw	%bp, %bp		/* %bp is increment */
find_mem_bar:
	/* Move to next BAR */
	addw	%bp, %di
	cmpw	$PCI_BAR_5, %di
	jle	1f
	stc
	movl	$0xbabababa, %esi	/* Report "No suitable BAR" */
	movl	rom_bar_size, %ecx
	jmp	99f
1:	movw	$4, %bp

	/* Get BAR current value */
	call	pci_read_bar

	/* Skip non-existent BARs */
	notl	%eax
	testl	%eax, %eax
	notl	%eax
	jz	find_mem_bar

	/* Skip I/O BARs */
	testb	$0x01, %al
	jnz	find_mem_bar

	/* Set increment to 8 for 64-bit BARs */
	testb	$0x04, %al
	jz	1f
	movw	$8, %bp
1:
	/* Skip 64-bit BARs with high dword set; we couldn't use this
	 * address for the (32-bit) expansion ROM BAR anyway
	 */
	testl	%edx, %edx
	jnz	find_mem_bar

	/* Get low dword of BAR size */
	call	pci_size_mem_bar_low

	/* Skip BARs smaller than the expansion ROM BAR */
	cmpl	%ecx, rom_bar_size
	ja	find_mem_bar

	/* We have a memory BAR with a 32-bit address that is large
	 * enough to use.  Store BAR number and original value.
	 */
	movw	%di, stolen_bar_register
	movl	%eax, stolen_bar_orig_value

	/* Remove flags from BAR address */
	xorb	%al, %al

	/* Write zero to our stolen BAR.  This doesn't technically
	 * disable it, but it's a pretty safe bet that the PCI bridge
	 * won't pass through accesses to this region anyway.  Note
	 * that the high dword (if any) must already be zero.
	 */
	xorl	%ecx, %ecx
	call	pci_write_config_dword

	/* Enable expansion ROM BAR at stolen BAR's address */
	movl	%eax, %ecx
	orb	$0x1, %cl
	movw	$PCI_BAR_EXPROM, %di
	call	pci_write_config_dword

	/* Locate our ROM image */
1:	movl	$0xaa55, %ecx				/* 55aa signature */
	addr32 es cmpw %cx, (%eax)
	jne	2f
	movl	$PCIR_SIGNATURE, %ecx			/* PCIR signature */
	addr32 es movzwl 0x18(%eax), %edx
	addr32 es cmpl %ecx, (%eax,%edx)
	jne	2f
	addr32 es cmpl $_build_id, build_id(%eax)	/* iPXE build ID */
	je	3f
	movl	$0x80, %ecx				/* Last image */
	addr32 es testb %cl, 0x15(%eax,%edx)
	jnz	2f
	addr32 es movzwl 0x10(%eax,%edx), %ecx		/* PCIR image length */
	shll	$9, %ecx
	addl	%ecx, %eax
	jmp	1b
2:	/* Failure */
	stc
	movl	%eax, %esi		/* Report failure address */
	jmp	99f
3:

	/* Copy payload to buffer, or set buffer address to BAR address */
	testl	%esi, %esi
	jz	1f
	/* We have a buffer; copy payload to it.  Since .mrom is
	 * designed specifically for real hardware, we assume that
	 * flat real mode is working properly.  (In the unlikely event
	 * that this code is run inside a hypervisor that doesn't
	 * properly support flat real mode, it will die horribly.)
	 */
	pushl	%esi
	movl	%esi, %edi
	movl	%eax, %esi
	addr32 es movzbl 2(%esi), %ecx
	shll	$7, %ecx
	addr32 es movzwl mpciheader_image_length(%esi,%ecx,4), %edx
	shll	$7, %edx
	addl	%edx, %ecx
	addr32 es rep movsl
	popl	%esi
	jmp	2f
1:	/* We have no buffer; set %esi to the BAR address */
	movl	%eax, %esi
2:

	/* Locate first payload block (after the dummy ROM header) */
	addr32 es movzbl 2(%esi), %ecx
	shll	$9, %ecx
	addl	$_pprefix_skip, %ecx

	clc
	/* Restore registers and return */
99:	popw	%ds
	popw	%es
	popw	%bp
	popl	%edi
	popl	%edx
	popw	%bx
	popl	%eax
	lret
	.size	open_payload, . - open_payload

	.section ".text16.early.data", "aw", @progbits
payload_pci_busdevfn:
	.word	0
	.size	payload_pci_busdevfn, . - payload_pci_busdevfn

	.section ".text16.early.data", "aw", @progbits
rom_bar_orig_value:
	.long	0
	.size	rom_bar_orig_value, . - rom_bar_orig_value

	.section ".text16.early.data", "aw", @progbits
rom_bar_size:
	.long	0
	.size	rom_bar_size, . - rom_bar_size

	.section ".text16.early.data", "aw", @progbits
stolen_bar_register:
	.word	0
	.size	stolen_bar_register, . - stolen_bar_register

	.section ".text16.early.data", "aw", @progbits
stolen_bar_orig_value:
	.long	0
	.size	stolen_bar_orig_value, . - stolen_bar_orig_value

/* Restore original BAR values
 *
 * Parameters:
 *   none
 * Returns:
 *   none
 */
	.section ".text16.early", "awx", @progbits
	.globl	close_payload
close_payload:
	/* Preserve registers */
	pushw	%bx
	pushw	%di
	pushl	%ecx
	pushw	%ds

	/* Set up %ds for access to .text16.early */
	pushw	%cs
	popw	%ds

	/* Retrieve stored bus:dev.fn */
	movw	payload_pci_busdevfn, %bx

	/* Restore expansion ROM BAR original value */
	movw	$PCI_BAR_EXPROM, %di
	movl	rom_bar_orig_value, %ecx
	call	pci_write_config_dword

	/* Restore stolen BAR original value */
	movw	stolen_bar_register, %di
	movl	stolen_bar_orig_value, %ecx
	call	pci_write_config_dword

	/* Restore registers and return */
	popw	%ds
	popl	%ecx
	popw	%di
	popw	%bx
	lret
	.size	close_payload, . - close_payload

/* Get PCI BAR value
 *
 * Parameters:
 *   %bx : PCI bus:dev.fn
 *   %di : PCI BAR register number
 * Returns:
 *   %edx:%eax : PCI BAR value
 */
	.section ".text16.early", "awx", @progbits
pci_read_bar:
	/* Preserve registers */
	pushl	%ecx
	pushw	%di

	/* Read low dword value */
	call	pci_read_config_dword
	movl	%ecx, %eax

	/* Read high dword value, if applicable */
	xorl	%edx, %edx
	andb	$0x07, %cl
	cmpb	$0x04, %cl
	jne	1f
	addw	$4, %di
	call	pci_read_config_dword
	movl	%ecx, %edx
1:
	/* Restore registers and return */
	popw	%di
	popl	%ecx
	ret
	.size	pci_read_bar, . - pci_read_bar

/* Get low dword of PCI memory BAR size
 *
 * Parameters:
 *   %bx : PCI bus:dev.fn
 *   %di : PCI BAR register number
 *   %eax : Low dword of current PCI BAR value
 * Returns:
 *   %ecx : PCI BAR size
 */
	.section ".text16.early", "awx", @progbits
pci_size_mem_bar_low:
	/* Preserve registers */
	pushw	%dx

	/* Disable memory accesses */
	xorw	%dx, %dx
	call	pci_set_mem_access

	/* Write all ones to BAR */
	xorl	%ecx, %ecx
	decl	%ecx
	call	pci_write_config_dword

	/* Read back BAR */
	call	pci_read_config_dword

	/* Calculate size */
	notl	%ecx
	orb	$0x0f, %cl
	incl	%ecx

	/* Restore original value */
	pushl	%ecx
	movl	%eax, %ecx
	call	pci_write_config_dword
	popl	%ecx

	/* Enable memory accesses */
	movw	$PCI_COMMAND_MEM, %dx
	call	pci_set_mem_access

	/* Restore registers and return */
	popw	%dx
	ret
	.size	pci_size_mem_bar_low, . - pci_size_mem_bar_low

/* Read PCI config dword
 *
 * Parameters:
 *   %bx : PCI bus:dev.fn
 *   %di : PCI register number
 * Returns:
 *   %ecx : Dword value
 */
	.section ".text16.early", "awx", @progbits
pci_read_config_dword:
	/* Preserve registers */
	pushl	%eax
	pushl	%ebx
	pushl	%edx

	/* Issue INT 0x1a,b10a */
	movw	$PCIBIOS_READ_CONFIG_DWORD, %ax
	int	$0x1a

	/* Restore registers and return */
	popl	%edx
	popl	%ebx
	popl	%eax
	ret
	.size	pci_read_config_dword, . - pci_read_config_dword

/* Write PCI config dword
 *
 * Parameters:
 *   %bx : PCI bus:dev.fn
 *   %di : PCI register number
 *   %ecx : PCI BAR value
 * Returns:
 *   none
 */
	.section ".text16.early", "awx", @progbits
pci_write_config_dword:
	/* Preserve registers */
	pushal

	/* Issue INT 0x1a,b10d */
	movw	$PCIBIOS_WRITE_CONFIG_DWORD, %ax
	int	$0x1a

	/* Restore registers and return */
	popal
	ret
	.size	pci_write_config_dword, . - pci_write_config_dword

/* Enable/disable memory access response in PCI command word
 *
 * Parameters:
 *   %bx : PCI bus:dev.fn
 *   %dx : PCI_COMMAND_MEM, or zero
 * Returns:
 *   none
 */
	.section ".text16.early", "awx", @progbits
pci_set_mem_access:
	/* Preserve registers */
	pushal

	/* Read current value of command register */
	pushw	%bx
	pushw	%dx
	movw	$PCI_COMMAND, %di
	movw	$PCIBIOS_READ_CONFIG_WORD, %ax
	int	$0x1a
	popw	%dx
	popw	%bx

	/* Set memory access enable as appropriate */
	andw	$~PCI_COMMAND_MEM, %cx
	orw	%dx, %cx

	/* Write new value of command register */
	movw	$PCIBIOS_WRITE_CONFIG_WORD, %ax
	int	$0x1a

	/* Restore registers and return */
	popal
	ret
	.size	pci_set_mem_access, . - pci_set_mem_access

/* Payload prefix
 *
 * We include a dummy ROM header to cover the "hidden" portion of the
 * overall ROM image.
 */
	.globl	_payload_align
	.equ	_payload_align, 512
	.section ".pprefix", "ax", @progbits
	.org	0x00
mromheader:
	.word	0xaa55			/* BIOS extension signature */
	.byte	0x01			/* Dummy size (BIOS bug workaround) */
	.org	0x18
	.word	mpciheader
	.org	0x1a
	.word	0
	.size	mromheader, . - mromheader

mpciheader:
	.ascii	"PCIR"			/* Signature */
	.word	pci_vendor_id		/* Vendor identification */
	.word	pci_device_id		/* Device identification */
	.word	0x0000			/* Device list pointer */
	.word	mpciheader_len		/* PCI data structure length */
	.byte	0x03			/* PCI data structure revision */
	.byte	0x02, 0x00, 0x00	/* Class code */
mpciheader_image_length:
	.word	0			/* Image length */
	.word	0x0001			/* Revision level */
	.byte	0xff			/* Code type */
	.byte	0x80			/* Last image indicator */
mpciheader_runtime_length:
	.word	0			/* Maximum run-time image length */
	.word	0x0000			/* Configuration utility code header */
	.word	0x0000			/* DMTF CLP entry point */
	.equ	mpciheader_len, . - mpciheader
	.size	mpciheader, . - mpciheader

	.section ".zinfo.fixup", "a", @progbits	/* Compressor fixups */
	.ascii	"APPW"
	.long	mpciheader_image_length
	.long	512
	.long	0
	.ascii	"APPW"
	.long	mpciheader_runtime_length
	.long	512
	.long	0
	.previous

/* Fix up additional image source size
 *
 */
	.section ".zinfo.fixup", "a", @progbits	/* Compressor fixups */
	.ascii	"ADPW"
	.long	extra_size
	.long	512
	.long	0
	.previous
