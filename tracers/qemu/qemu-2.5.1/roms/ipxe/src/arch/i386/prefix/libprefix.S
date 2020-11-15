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

/* Image compression enabled */
#define COMPRESS 1

/* Protected mode flag */
#define CR0_PE 1

/* Allow for DBG()-style messages within libprefix */
#ifdef NDEBUG
	.macro	progress message
	.endm
#else
	.macro	progress message
	pushfl
	pushw	%ds
	pushw	%si
	pushw	%di
	pushw	%cs
	popw	%ds
	xorw	%di, %di
	movw	$progress_\@, %si
	call	print_message
	popw	%di
	popw	%si
	popw	%ds
	popfl
	.section ".prefix.data", "aw", @progbits
progress_\@:
	.asciz	"\message"
	.size	progress_\@, . - progress_\@
	.previous
	.endm
#endif

/*****************************************************************************
 * Utility function: print character (with LF -> LF,CR translation)
 *
 * Parameters:
 *   %al : character to print
 *   %ds:di : output buffer (or %di=0 to print to console)
 * Returns:
 *   %ds:di : next character in output buffer (if applicable)
 *****************************************************************************
 */
	.section ".prefix.lib", "awx", @progbits
	.code16
	.globl	print_character
print_character:
	/* Preserve registers */
	pushw	%ax
	pushw	%bx
	pushw	%bp
	/* If %di is non-zero, write character to buffer and exit */
	testw	%di, %di
	jz	1f
	movb	%al, %ds:(%di)
	incw	%di
	jmp	3f
1:	/* Print character */
	movw	$0x0007, %bx		/* page 0, attribute 7 (normal) */
	movb	$0x0e, %ah		/* write char, tty mode */
	cmpb	$0x0a, %al		/* '\n'? */
	jne	2f
	int	$0x10
	movb	$0x0d, %al
2:	int	$0x10
	/* Restore registers and return */
3:	popw	%bp
	popw	%bx
	popw	%ax
	ret
	.size	print_character, . - print_character

/*****************************************************************************
 * Utility function: print space
 *
 * Parameters:
 *   %ds:di : output buffer (or %di=0 to print to console)
 * Returns:
 *   %ds:di : next character in output buffer (if applicable)
 *****************************************************************************
 */
	.section ".prefix.lib", "awx", @progbits
	.code16
	.globl	print_space
print_space:
	/* Preserve registers */
	pushw	%ax
	/* Print space */
	movb	$( ' ' ), %al
	call	print_character
	/* Restore registers and return */
	popw	%ax
	ret
	.size	print_space, . - print_space

/*****************************************************************************
 * Utility function: print a NUL-terminated string
 *
 * Parameters:
 *   %ds:si : string to print
 *   %ds:di : output buffer (or %di=0 to print to console)
 * Returns:
 *   %ds:si : character after terminating NUL
 *   %ds:di : next character in output buffer (if applicable)
 *****************************************************************************
 */
	.section ".prefix.lib", "awx", @progbits
	.code16
	.globl	print_message
print_message:
	/* Preserve registers */
	pushw	%ax
	/* Print string */
1: 	lodsb
	testb	%al, %al
	je	2f
	call	print_character
	jmp	1b
2:	/* Restore registers and return */
	popw	%ax
	ret
	.size	print_message, . - print_message

/*****************************************************************************
 * Utility functions: print hex digit/byte/word/dword
 *
 * Parameters:
 *   %al (low nibble) : digit to print
 *   %al : byte to print
 *   %ax : word to print
 *   %eax : dword to print
 *   %ds:di : output buffer (or %di=0 to print to console)
 * Returns:
 *   %ds:di : next character in output buffer (if applicable)
 *****************************************************************************
 */
	.section ".prefix.lib", "awx", @progbits
	.code16
	.globl	print_hex_dword
print_hex_dword:
	rorl	$16, %eax
	call	print_hex_word
	rorl	$16, %eax
	/* Fall through */
	.size	print_hex_dword, . - print_hex_dword
	.globl	print_hex_word
print_hex_word:
	xchgb	%al, %ah
	call	print_hex_byte
	xchgb	%al, %ah
	/* Fall through */
	.size	print_hex_word, . - print_hex_word
	.globl	print_hex_byte
print_hex_byte:
	rorb	$4, %al
	call	print_hex_nibble
	rorb	$4, %al
	/* Fall through */
	.size	print_hex_byte, . - print_hex_byte
	.globl	print_hex_nibble
print_hex_nibble:
	/* Preserve registers */
	pushw	%ax
	/* Print digit (technique by Norbert Juffa <norbert.juffa@amd.com> */
	andb	$0x0f, %al
	cmpb	$10, %al
	sbbb	$0x69, %al
	das
	call	print_character
	/* Restore registers and return */
	popw	%ax
	ret
	.size	print_hex_nibble, . - print_hex_nibble

/*****************************************************************************
 * Utility function: print PCI bus:dev.fn
 *
 * Parameters:
 *   %ax : PCI bus:dev.fn to print
 *   %ds:di : output buffer (or %di=0 to print to console)
 * Returns:
 *   %ds:di : next character in output buffer (if applicable)
 *****************************************************************************
 */
	.section ".prefix.lib", "awx", @progbits
	.code16
	.globl	print_pci_busdevfn
print_pci_busdevfn:
	/* Preserve registers */
	pushw	%ax
	/* Print bus */
	xchgb	%al, %ah
	call	print_hex_byte
	/* Print ":" */
	movb	$( ':' ), %al
	call	print_character
	/* Print device */
	movb	%ah, %al
	shrb	$3, %al
	call	print_hex_byte
	/* Print "." */
	movb	$( '.' ), %al
	call	print_character
	/* Print function */
	movb	%ah, %al
	andb	$0x07, %al
	call	print_hex_nibble
	/* Restore registers and return */
	popw	%ax
	ret
	.size	print_pci_busdevfn, . - print_pci_busdevfn

/*****************************************************************************
 * Utility function: clear current line
 *
 * Parameters:
 *   %ds:di : output buffer (or %di=0 to print to console)
 * Returns:
 *   %ds:di : next character in output buffer (if applicable)
 *****************************************************************************
 */
	.section ".prefix.lib", "awx", @progbits
	.code16
	.globl	print_kill_line
print_kill_line:
	/* Preserve registers */
	pushw	%ax
	pushw	%cx
	/* Print CR */
	movb	$( '\r' ), %al
	call	print_character
	/* Print 79 spaces */
	movw	$79, %cx
1:	call	print_space
	loop	1b
	/* Print CR */
	call	print_character
	/* Restore registers and return */
	popw	%cx
	popw	%ax
	ret
	.size	print_kill_line, . - print_kill_line

/****************************************************************************
 * copy_bytes
 *
 * Copy bytes
 *
 * Parameters:
 *   %ds:esi : source address
 *   %es:edi : destination address
 *   %ecx : length
 * Returns:
 *   %ds:esi : next source address
 *   %es:edi : next destination address
 * Corrupts:
 *   None
 ****************************************************************************
 */
	.section ".prefix.lib", "awx", @progbits
	.code16
copy_bytes:
	pushl	%ecx
	rep addr32 movsb
	popl	%ecx
	ret
	.size	copy_bytes, . - copy_bytes

/****************************************************************************
 * zero_bytes
 *
 * Zero bytes
 *
 * Parameters:
 *   %es:edi : destination address
 *   %ecx : length
 * Returns:
 *   %es:edi : next destination address
 * Corrupts:
 *   None
 ****************************************************************************
 */
	.section ".prefix.lib", "awx", @progbits
	.code16
zero_bytes:
	pushl	%ecx
	pushw	%ax
	xorw	%ax, %ax
	rep addr32 stosb
	popw	%ax
	popl	%ecx
	ret
	.size	zero_bytes, . - zero_bytes

/****************************************************************************
 * process_bytes
 *
 * Call memcpy()-like function
 *
 * Parameters:
 *   %esi : source physical address
 *   %edi : destination physical address
 *   %ecx : length
 *   %bx : memcpy()-like function to call, passing parameters:
 *	     %ds:esi : source address
 *	     %es:edi : destination address
 *	     %ecx : length
 *         and returning:
 *	     %ds:esi : next source address
 *	     %es:edi : next destination address
 * Returns:
 *   %esi : next source physical address
 *   %edi : next destination physical address
 * Corrupts:
 *   None
 ****************************************************************************
 */
	.section ".prefix.lib", "awx", @progbits
	.code16
process_bytes:

#ifndef KEEP_IT_REAL

	/* Preserve registers */
	pushl	%eax
	pushl	%ebp

	/* Construct GDT on stack (since .prefix may not be writable) */
	.equ	PM_DS, 0x18	/* Flat data segment */
	pushl	$0x00cf9300
	pushl	$0x0000ffff
	.equ	PM_SS, 0x10	/* Stack segment based at %ss:0000 */
	pushl	$0x008f0930
	pushw	%ss
	pushw	$0xffff
	.equ	PM_CS, 0x08	/* Code segment based at %cs:0000 */
	pushl	$0x008f09b0
	pushw	%cs
	pushw	$0xffff
	pushl	$0		/* Base and length */
	pushw	%ss
	pushw	$0x1f
	movzwl	%sp, %ebp
	shll	$4, 0x02(%bp)
	addl	%ebp, 0x02(%bp)
	shll	$4, 0x0a(%bp)
	shll	$4, 0x12(%bp)
	subw	$8, %sp
	sgdt	-8(%bp)

	/* Switch to protected mode */
	pushw	%gs
	pushw	%fs
	pushw	%es
	pushw	%ds
	pushw	%ss
	pushw	%cs
	pushw	$2f
	cli
	data32 lgdt (%bp)
	movl	%cr0, %eax
	orb	$CR0_PE, %al
	movl	%eax, %cr0
	ljmp	$PM_CS, $1f
1:	movw	$PM_SS, %ax
	movw	%ax, %ss
	movw	$PM_DS, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs

#ifdef NDEBUG
	/* Call memcpy()-like function */
	call	*%bx
#endif

	/* Return to (flat) real mode */
	movl	%cr0, %eax
	andb	$0!CR0_PE, %al
	movl	%eax, %cr0
	lret
2:	/* lret will ljmp to here */
	popw	%ss
	popw	%ds
	popw	%es
	popw	%fs
	popw	%gs

#ifndef NDEBUG
	/* Call memcpy()-like function in flat real mode (to allow for
	 * debug output via INT 10).
	 */
	pushw	%ds
	pushw	%es
	xorw	%ax, %ax
	movw	%ax, %ds
	movw	%ax, %es
	call	*%bx
	popw	%es
	popw	%ds
#endif

	/* Restore GDT */
	data32 lgdt -8(%bp)
	addw	$( 8 /* saved GDT */ + ( PM_DS + 8 ) /* GDT on stack */ ), %sp

	/* Restore registers and return */
	popl	%ebp
	popl	%eax
	ret

#else /* KEEP_IT_REAL */

	/* Preserve registers */
	pushl	%eax
	pushw	%ds
	pushw	%es
	
	/* Convert %esi and %edi to %ds:esi and %es:edi */
	shrl	$4, %esi
	movw	%si, %ds
	xorw	%si, %si
	shll	$4, %esi
	shrl	$4, %edi
	movw	%di, %es
	xorw	%di, %di
	shll	$4, %edi

	/* Call memcpy()-like function */
	call	*%bx

	/* Convert %ds:esi and %es:edi back to physical addresses */
	xorl	%eax, %eax
	movw    %ds, %ax
	shll	$4, %eax
	addl	%eax, %esi
	xorl	%eax, %eax
	movw    %es, %ax
	shll	$4, %eax
	addl	%eax, %edi

	/* Restore registers and return */
	popw	%es
	popw	%ds
	popl	%eax
	ret

#endif /* KEEP_IT_REAL */

	.size	process_bytes, . - process_bytes

/****************************************************************************
 * install_block
 *
 * Install block to specified address
 *
 * Parameters:
 *   %esi : source physical address (must be a multiple of 16)
 *   %edi : destination physical address (must be a multiple of 16)
 *   %ecx : length of (decompressed) data
 *   %edx : total length of block (including any uninitialised data portion)
 * Returns:
 *   %esi : next source physical address (will be a multiple of 16)
 *   %edi : next destination physical address (will be a multiple of 16)
 * Corrupts:
 *   none
 ****************************************************************************
 */
	.section ".prefix.lib", "awx", @progbits
	.code16
install_block:
	/* Preserve registers */
	pushl	%ecx
	pushw	%bx

	/* Decompress (or copy) source to destination */
#if COMPRESS
	movw	$decompress16, %bx
#else
	movw	$copy_bytes, %bx
#endif
	call	process_bytes

	/* Zero .bss portion */
	negl	%ecx
	addl	%edx, %ecx
	movw	$zero_bytes, %bx
	call	process_bytes

	/* Round up %esi and %edi to start of next blocks */
	addl	$0xf, %esi
	andl	$~0xf, %esi
	addl	$0xf, %edi
	andl	$~0xf, %edi

	/* Restore registers and return */
	popw	%bx
	popl	%ecx
	ret
	.size install_block, . - install_block

/****************************************************************************
 * alloc_basemem
 *
 * Allocate space for .text16 and .data16 from top of base memory.
 * Memory is allocated using the BIOS free base memory counter at
 * 0x40:13.
 *
 * Parameters: 
 *   none
 * Returns:
 *   %ax : .text16 segment address
 *   %bx : .data16 segment address
 * Corrupts:
 *   none
 ****************************************************************************
 */
	.section ".prefix.lib", "awx", @progbits
	.code16
	.globl	alloc_basemem
alloc_basemem:
	/* Preserve registers */
	pushw	%fs

	/* FBMS => %ax as segment address */
	pushw	$0x40
	popw	%fs
	movw	%fs:0x13, %ax
	shlw	$6, %ax

	/* Calculate .data16 segment address */
	subw	$_data16_memsz_pgh, %ax
	pushw	%ax

	/* Calculate .text16 segment address.  Round down to ensure
	 * low bits are zero, to speed up mode transitions under KVM.
	 */
	subw	$_text16_memsz_pgh, %ax
	andb	$~0x03, %al
	pushw	%ax

	/* Update FBMS */
	shrw	$6, %ax
	movw	%ax, %fs:0x13

	/* Retrieve .text16 and .data16 segment addresses */
	popw	%ax
	popw	%bx

	/* Restore registers and return */
	popw	%fs
	ret
	.size alloc_basemem, . - alloc_basemem

/****************************************************************************
 * free_basemem
 *
 * Free space allocated with alloc_basemem.
 *
 * Parameters:
 *   none (.text16 segment address is implicit in %cs)
 * Returns:
 *   %ax : 0 if successfully freed
 * Corrupts:
 *   none
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
	.code16
	.globl	free_basemem
free_basemem:
	/* Preserve registers */
	pushw	%fs
	pushw	%ax

	/* Check FBMS counter */
	movw	%cs, %ax
	shrw	$6, %ax
	pushw	$0x40
	popw	%fs
	cmpw	%ax, %fs:0x13
	jne	1f

	/* Check hooked interrupt count */
	cmpw	$0, %cs:hooked_bios_interrupts
	jne	1f

	/* OK to free memory */
	movw	%cs, %ax
	addw	$_text16_memsz_pgh, %ax
	addw	$_data16_memsz_pgh, %ax
	shrw	$6, %ax
	movw	%ax, %fs:0x13
	xorw	%ax, %ax

1:	/* Restore registers and return */
	popw	%ax
	popw	%fs
	ret
	.size free_basemem, . - free_basemem

	.section ".text16.data", "aw", @progbits
	.globl	hooked_bios_interrupts
hooked_bios_interrupts:
	.word	0
	.size	hooked_bios_interrupts, . - hooked_bios_interrupts

/****************************************************************************
 * install
 *
 * Install all text and data segments.
 *
 * Parameters:
 *   none
 * Returns:
 *   %ax  : .text16 segment address
 *   %bx  : .data16 segment address
 * Corrupts:
 *   none
 ****************************************************************************
 */
	.section ".prefix.lib", "awx", @progbits
	.code16
	.globl install
install:
	progress "install:\n"
	/* Preserve registers */
	pushl	%esi
	pushl	%edi
	pushl	%ebp
	/* Allocate space for .text16 and .data16 */
	call	alloc_basemem
	/* Image source = %cs:0000 */
	xorl	%esi, %esi
	/* Image destination = default */
	xorl	%edi, %edi
	/* Allow arbitrary relocation */
	orl	$0xffffffff, %ebp
	/* Install text and data segments */
	call	install_prealloc
	/* Restore registers and return */
	popl	%ebp
	popl	%edi
	popl	%esi
	ret
	.size install, . - install

/****************************************************************************
 * install_prealloc
 *
 * Install all text and data segments.
 *
 * Parameters:
 *   %ax  : .text16 segment address
 *   %bx  : .data16 segment address
 *   %esi : Image source physical address (or zero for %cs:0000)
 *   %edi : Decompression temporary area physical address (or zero for default)
 *   %ebp : Maximum end address for relocation
 *          - 0xffffffff for no maximum
 *          - 0x00000000 to inhibit use of INT 15,e820 and INT 15,e801
 * Corrupts:
 *   none
 ****************************************************************************
 */
	.section ".prefix.lib", "awx", @progbits
	.code16
	.globl install_prealloc
install_prealloc:
	progress "install_prealloc:\n"
	/* Save registers on external stack */
	pushal
	pushw	%ds
	pushw	%es
	cld			/* Sanity: clear the direction flag asap */

	/* Switch to temporary stack in .bss16 */
	pushw	%ss
	popw	%ds
	movl	%esp, %ecx
	movw	%bx, %ss
	movl	$_data16_memsz, %esp
	pushw	%ds
	pushl	%ecx

	/* Set up %ds for (read-only) access to .prefix */
	pushw	%cs
	popw	%ds

	/* Save decompression temporary area physical address */
	pushl	%edi

	/* Install .text16.early and calculate %ecx as offset to next block */
	progress "  .text16.early\n"
	pushl	%esi
	xorl	%esi, %esi
	movw	%cs, %si
	shll	$4, %esi
	pushl	%esi			/* Save original %cs:0000 */
	addl	$_text16_early_lma, %esi
	movzwl	%ax, %edi
	shll	$4, %edi
	movl	$_text16_early_filesz, %ecx
	movl	$_text16_early_memsz, %edx
	call	install_block		/* .text16.early */
	popl	%ecx			/* Calculate offset to next block */
	subl	%esi, %ecx
	negl	%ecx
	popl	%esi

#ifndef KEEP_IT_REAL

	/* Access high memory by enabling the A20 gate.  (We will
	 * already have 4GB segment limits as a result of calling
	 * install_block.)
	 */
	progress "  access_highmem\n"
	pushw	%cs
	pushw	$1f
	pushw	%ax
	pushw	$access_highmem
	lret
1:	/* Die if we could not access high memory */
	jnc	3f
	movw	$a20_death_message, %si
	xorw	%di, %di
	call	print_message
2:	jmp	2b
	.section ".prefix.data", "aw", @progbits
a20_death_message:
	.asciz	"\nHigh memory inaccessible - cannot continue\n"
	.size	a20_death_message, . - a20_death_message
	.previous
3:
#endif

	/* Open payload (which may not yet be in memory) */
	progress "  open_payload\n"
	pushw	%cs
	pushw	$1f
	pushw	%ax
	pushw	$open_payload
	lret
1:	/* Die if we could not access the payload */
	jnc	3f
	xorw	%di, %di
	movl	%esi, %eax
	call	print_hex_dword
	call	print_space
	movl	%ecx, %eax
	call	print_hex_dword
	movw	$payload_death_message, %si
	call	print_message
2:	/* Halt system */
	cli
	hlt
	jmp	2b
	.section ".prefix.data", "aw", @progbits
payload_death_message:
	.asciz	"\nPayload inaccessible - cannot continue\n"
	.size	payload_death_message, . - payload_death_message
	.previous
3:

	/* Calculate physical address of payload (i.e. first source) */
	testl	%esi, %esi
	jnz	1f
	movw	%cs, %si
	shll	$4, %esi
1:	addl	%ecx, %esi

	/* Install .text16.late and .data16 */
	progress "  .text16.late\n"
	movl	$_text16_late_filesz, %ecx
	movl	$_text16_late_memsz, %edx
	call	install_block		/* .text16.late */
	progress "  .data16\n"
	movzwl	%bx, %edi
	shll	$4, %edi
	movl	$_data16_filesz, %ecx
	movl	$_data16_filesz, %edx	/* do not zero our temporary stack */
	call	install_block		/* .data16 */

	/* Set up %ds for access to .data16 */
	movw	%bx, %ds

	/* Restore decompression temporary area physical address */
	popl	%edi

#ifndef KEEP_IT_REAL

	/* Find a suitable decompression temporary area, if none specified */
	pushl	%eax
	testl	%edi, %edi
	jnz	1f
	/* Use INT 15,88 to find the highest available address via INT
	 * 15,88.  This limits us to around 64MB, which should avoid
	 * all of the POST-time memory map failure modes.
	 */
	movb	$0x88, %ah
	int	$0x15
	movw	%ax, %di
	addl	$0x400, %edi
	subl	$_textdata_memsz_kb, %edi
	shll	$10, %edi
	/* Sanity check: if we have ended up below 1MB, use 1MB */
	cmpl	$0x100000, %edi
	jae	1f
	movl	$0x100000, %edi
1:	popl	%eax

	/* Install .text and .data to temporary area in high memory,
	 * prior to reading the E820 memory map and relocating
	 * properly.
	 */
	progress "  .textdata\n"
	pushl	%edi
	movl	$_textdata_filesz, %ecx
	movl	$_textdata_memsz, %edx
	call	install_block
	popl	%edi

#endif /* KEEP_IT_REAL */

	/* Switch back to original stack and zero .bss16 */
	addr32 lss %ss:(%esp), %esp
	pushl	%edi
	pushw	%es
	movw	%bx, %es
	movl	$_data16_filesz, %edi
	movl	$_data16_memsz, %ecx
	subl	%edi, %ecx
	call	zero_bytes
	popw	%es
	popl	%edi

#ifndef KEEP_IT_REAL

	/* Initialise librm at current location */
	progress "  init_librm\n"
	movw	%ax, (init_librm_vector+2)
	lcall	*init_librm_vector

	/* Inhibit INT 15,e820 and INT 15,e801 if applicable */
	testl	%ebp, %ebp
	jnz	1f
	incb	memmap_post
	decl	%ebp
1:
	/* Call relocate() to determine target address for relocation.
	 * relocate() will return with %esi, %edi and %ecx set up
	 * ready for the copy to the new location.
	 */
	progress "  relocate\n"
	movw	%ax, (prot_call_vector+2)
	pushl	$relocate
	lcall	*prot_call_vector
	popl	%edx /* discard */

	/* Copy code to new location */
	progress "  copy\n"
	pushl	%edi
	pushw	%bx
	movw	$copy_bytes, %bx
	call	process_bytes
	popw	%bx
	popl	%edi

	/* Initialise librm at new location */
	progress "  init_librm\n"
	lcall	*init_librm_vector

#else /* KEEP_IT_REAL */

	/* Initialise libkir */
	movw	%ax, (init_libkir_vector+2)
	lcall	*init_libkir_vector

#endif /* KEEP_IT_REAL */

	/* Close access to payload */
	progress "  close_payload\n"
	movw	%ax, (close_payload_vector+2)
	lcall	*close_payload_vector

	/* Restore registers */
	popw	%es
	popw	%ds
	popal
	ret
	.size install_prealloc, . - install_prealloc

	/* Vectors for far calls to .text16 functions.  Must be in
	 * .data16, since .prefix may not be writable.
	 */
	.section ".data16", "aw", @progbits
#ifdef KEEP_IT_REAL
init_libkir_vector:
	.word init_libkir
	.word 0
	.size init_libkir_vector, . - init_libkir_vector
#else
init_librm_vector:
	.word init_librm
	.word 0
	.size init_librm_vector, . - init_librm_vector
prot_call_vector:
	.word prot_call
	.word 0
	.size prot_call_vector, . - prot_call_vector
#endif
close_payload_vector:
	.word close_payload
	.word 0
	.size close_payload_vector, . - close_payload_vector

	/* Dummy routines to open and close payload */
	.section ".text16.early.data", "aw", @progbits
	.weak	open_payload
	.weak	close_payload
open_payload:
close_payload:
	clc
	lret
	.size	open_payload, . - open_payload
	.size	close_payload, . - close_payload

/****************************************************************************
 * uninstall
 *
 * Uninstall all text and data segments.
 *
 * Parameters:
 *   none (.text16 segment address is implicit in %cs)
 * Returns:
 *   none
 * Corrupts:
 *   none
 ****************************************************************************
 */
	.section ".text16", "ax", @progbits
	.code16
	.globl uninstall
uninstall:
	call	free_basemem
	ret
	.size uninstall, . - uninstall



	/* File split information for the compressor */
#if COMPRESS
#define PACK_OR_COPY	"PACK"
#else
#define PACK_OR_COPY	"COPY"
#endif
	.section ".zinfo", "a", @progbits
	.ascii	"COPY"
	.long	_prefix_lma
	.long	_prefix_filesz
	.long	_max_align
	.ascii	PACK_OR_COPY
	.long	_text16_early_lma
	.long	_text16_early_filesz
	.long	_max_align
	.ascii	"PAYL"
	.long	0
	.long	0
	.long	_payload_align
	.ascii	"COPY"
	.long	_pprefix_lma
	.long	_pprefix_filesz
	.long	_max_align
	.ascii	PACK_OR_COPY
	.long	_text16_late_lma
	.long	_text16_late_filesz
	.long	_max_align
	.ascii	PACK_OR_COPY
	.long	_data16_lma
	.long	_data16_filesz
	.long	_max_align
	.ascii	PACK_OR_COPY
	.long	_textdata_lma
	.long	_textdata_filesz
	.long	_max_align

	.weak	_payload_align
	.equ	_payload_align, 1
