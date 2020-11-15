/*
 * Copyright (C) 2011 Michael Brown <mbrown@fensystems.co.uk>.
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

/* Initial temporary stack size */
#define EXE_STACK_SIZE 0x400

/* Temporary decompression area (avoid DOS high memory area) */
#define EXE_DECOMPRESS_ADDRESS 0x110000

/* Fields within the Program Segment Prefix */
#define PSP_CMDLINE_LEN 0x80
#define PSP_CMDLINE_START 0x81

	.text
	.arch i386
	.org 0
	.code16
	.section ".prefix", "awx", @progbits

signature:
	/* "MZ" signature */
	.ascii	"MZ"

last_block:
	/* Number of bytes in last block that are really used */
	.word	0

blocks:
	/* Number of 512-byte blocks */
	.word	0
	.section ".zinfo.fixup", "a", @progbits /* Compressor fixups */
	.ascii	"ADDW"
	.long	blocks
	.long	512
	.long	0
	.previous

num_reloc:
	/* Number of relocation entries stored after the header */
	.word	0

header_pgh:
	/* Number of paragraphs in the header */
	.word	( ( _exe_start - signature ) / 16 )

min_bss_pgh:
	/* Minimum number of paragraphs of additional (BSS) memory */
	.word	( EXE_STACK_SIZE / 16 )

max_bss_pgh:
	/* Maximum number of paragraphs of additional (BSS) memory */
	.word	( EXE_STACK_SIZE / 16 )

init_ss:
	/* Initial stack segment (relative to start of executable) */
	.word	-( ( _exe_start - signature ) / 16 )
	.section ".zinfo.fixup", "a", @progbits /* Compressor fixups */
	.ascii	"ADDW"
	.long	init_ss
	.long	16
	.long	0
	.previous

init_sp:
	/* Initial stack pointer */
	.word	EXE_STACK_SIZE

checksum:
	/* Checksum (ignored) */
	.word	0

init_ip:
	/* Initial instruction pointer */
	.word	_exe_start

init_cs:
	/* Initial code segment (relative to start of executable) */
	.word	-( ( _exe_start - signature ) / 16 )

reloc_table:
	/* Relocation table offset */
	.word	0

overlay:
	/* Overlay number */
	.word	0

	.align 16, 0

	.globl	_exe_start
_exe_start:
	/* Install iPXE.  Use a fixed temporary decompression area to
	 * avoid trashing the DOS high memory area.
	 */
	call	alloc_basemem
	xorl	%esi, %esi
	movl	$EXE_DECOMPRESS_ADDRESS, %edi
	orl	$0xffffffff, %ebp	/* Allow arbitrary relocation */
	call	install_prealloc

	/* Set up real-mode stack */
	movw	%bx, %ss
	movw	$_estack16, %sp

	/* Jump to .text16 segment */
	pushw	%ax
	pushw	$1f
	lret
	.section ".text16", "awx", @progbits
1:
	/* Terminate command line with a NUL */
	movzbw	PSP_CMDLINE_LEN, %si
	movb	$0, PSP_CMDLINE_START(%si)

	/* Calculate command line physical address */
	xorl	%esi, %esi
	movw	%ds, %si
	shll	$4, %esi
	addl	$PSP_CMDLINE_START, %esi

	/* Set up %ds for access to .data16 */
	movw	%bx, %ds

	/* Record command line address */
	movl	%esi, cmdline_phys

	/* Run iPXE */
	pushl	$main
	pushw	%cs
	call	prot_call
	popl	%ecx /* discard */

	/* Uninstall iPXE */
	call	uninstall

	/* Exit back to DOS.  This is very unlikely to work */
	movw	$0x4c00, %ax
	int	$0x21
