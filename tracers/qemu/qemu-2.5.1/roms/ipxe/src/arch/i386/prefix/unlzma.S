/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/****************************************************************************
 *
 * This file provides the decompress() and decompress16() functions
 * which can be called in order to decompress an LZMA-compressed
 * image.  The code is modelled on the public-domain "XZ Embedded"
 * implementation as used by the Linux kernel.  Symbol names are
 * chosen to match the XZ Embedded implementation where possible, for
 * ease of reference.
 *
 * This code is optimised for size rather than speed, since the amount
 * of data to be decompressed is trivially small by modern standards.
 *
 * The same basic assembly code is used to compile both decompress()
 * and decompress16().
 *
 * Note that these functions require large amounts of stack space.
 *
 ****************************************************************************
 */

	.text
	.arch i586
	.section ".prefix.lib", "ax", @progbits

#ifdef CODE16
#define ADDR16
#define ADDR32 addr32
#define decompress decompress16
	.code16
#else /* CODE16 */
#define ADDR16 addr16
#define ADDR32
	.code32
#endif /* CODE16 */

/****************************************************************************
 * Debugging
 ****************************************************************************
 *
 * This code will usually run in 16-bit protected mode, in which case
 * only the 0xe9 debug port (present on some virtual machines) can be
 * used.
 *
 * To debug on real hardware, build with DEBUG=libprefix.  This will
 * cause this code to be called in flat real mode, and so DEBUG_INT10
 * may be used.
 */

/* Enable debugging via 0xe9 debug port */
#define DEBUG_E9 0

/* Enable debugging via BIOS INT 10 (works only when in flat real mode) */
#define DEBUG_INT10 0

#if ( DEBUG_E9 || DEBUG_INT10 )
	.macro	print_character, reg
	pushfl
	pushw	%ax
	pushw	%bx
	pushw	%bp
	movb 	\reg, %al
	movw	$0x0007, %bx
	movb	$0x0e, %ah
#if DEBUG_E9
	outb	%al, $0xe9
#endif
#if DEBUG_INT10
	cmpb	$('\n'), %al
	jne	L\@
	int	$0x10
	movb	$('\r'), %al
L\@:	int	$0x10
#endif
	popw	%bp
	popw	%bx
	popw	%ax
	popfl
	.endm

	.macro	print_hex_nibble
	pushfl
	pushw	%ax
	cmpb	$10, %al
	sbb	$0x69, %al
	das
	print_character %al
	popw	%ax
	popfl
	.endm

	.macro	print_hex_byte, reg
	pushfl
	pushw	%ax
	movb	\reg, %al
	pushw	%ax
	shrb	$4, %al
	print_hex_nibble
	popw	%ax
	andb	$0x0f, %al
	print_hex_nibble
	popw	%ax
	popfl
	.endm

	.macro	print_hex_word, reg
	pushw	%ax
	movw	\reg, %ax
	print_hex_byte %ah
	print_hex_byte %al
	popw	%ax
	.endm

	.macro	print_hex_dword, reg
	pushl	%eax
	movl	\reg, %eax
	rorl	$16, %eax
	print_hex_word %ax
	rorl	$16, %eax
	print_hex_word %ax
	popl	%eax
	.endm
#else
	.macro	print_character, char
	.endm
	.macro	print_hex_byte, reg
	.endm
	.macro	print_hex_word, reg
	.endm
	.macro	print_hex_dword, reg
	.endm
#endif

/****************************************************************************
 * LZMA parameters and data structures
 ****************************************************************************
 */

/* LZMA decompressor states (as used in XZ Embedded) */
#define STATE_LIT_LIT 0x00
#define STATE_MATCH_LIT_LIT 0x01
#define STATE_REP_LIT_LIT 0x02
#define STATE_SHORTREP_LIT_LIT 0x03
#define STATE_MATCH_LIT 0x04
#define STATE_REP_LIT 0x05
#define STATE_SHORTREP_LIT 0x06
#define STATE_LIT_MATCH 0x07
#define STATE_LIT_LONGREP 0x08
#define STATE_LIT_SHORTREP 0x09
#define STATE_NONLIT_MATCH 0x0a
#define STATE_NONLIT_REP 0x0b

/* LZMA maximum decompressor state in which most recent symbol was a literal */
#define STATE_LIT_MAX 0x06

/* LZMA number of literal context bits ("lc=" parameter) */
#define LZMA_LC 2

	.struct	0
lzma_len_dec:
choice:		.word	0
choice2:	.word	0
low:		.rept	( 1 << 3 )
		.word	0
		.endr
mid:		.rept	( 1 << 3 )
		.word	0
		.endr
high:		.rept	( 1 << 8 )
		.word	0
		.endr
	.equ	sizeof__lzma_len_dec, . - lzma_len_dec
	.previous

	.struct	0
lzma_dec:
out_start:	.long	0
rc_code:	.long	0
rc_range:	.long	0
len:		.word	0
reps:
rep0:		.long	0
rep1:		.long	0
rep2:		.long	0
rep3:		.long	0
probs:
is_match:	.word	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
is_rep:		.word	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
is_rep0:	.word	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
is_rep1:	.word	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
is_rep2:	.word	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
is_rep0_long:	.word	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
dist_slot:	.rept	( 4 * ( 1 << 6 ) )
		.word	0
		.endr
dist_special:	.rept	( ( 1 << ( 14 / 2 ) ) - 14 )
		.word	0
		.endr
dist_align:	.rept	( 1 << 4 )
		.word	0
		.endr
match_len_dec:	.space	sizeof__lzma_len_dec
rep_len_dec:	.space	sizeof__lzma_len_dec
literal:	.rept	( ( 1 << LZMA_LC ) * 0x300 )
		.word	0
		.endr
	.align	4
	.equ	sizeof__lzma_dec, . - lzma_dec
	.previous

	/* Some binutils versions seem not to handle .struct/.previous */
	.section ".prefix.lib", "ax", @progbits

/*****************************************************************************
 * Normalise range encoder
 *
 * Parameters:
 *   %ss:%ebp : LZMA parameter block
 *   %ds:%esi : compressed input data pointer
 * Returns:
 *   %ds:%esi : compressed input data pointer (possibly updated)
 *   %eax : current range
 *****************************************************************************
 */
rc_normalise:
	/* Check if rc_range is less than 1<<24 */
	testb	$0xff, (rc_range+3)(%ebp)
	jnz	1f
	/* If it is, shift in a new byte from the compressed input data */
	shll	$8, rc_range(%ebp)
	shll	$8, rc_code(%ebp)
	ADDR32 lodsb
	movb	%al, (rc_code+0)(%ebp)
1:	/* Return current range */
	movl	rc_range(%ebp), %eax
	ret
	.size	rc_normalise, . - rc_normalise

/*****************************************************************************
 * Decode single range-encoded bit using a probability estimate
 *
 * Parameters:
 *   %ss:%ebp : LZMA parameter block
 *   %ds:%esi : compressed input data pointer
 *   %ebx : probability estimate pointer (offset from %ebp)
 * Returns:
 *   %ds:%esi : compressed input data pointer (possibly updated)
 *   CF : decoded bit
 *   ZF : inverse of decoded bit
 * Corrupts:
 *   none
 *****************************************************************************
 */
rc_bit:
	/* Preserve registers */
	pushl	%eax
	pushl	%edx
	/* Perform normalisation */
	call	rc_normalise
	/* Calculate bound in %eax and probability estimate in %dx */
	shrl	$11, %eax
	movzwl	(%ebp,%ebx), %edx
	mul	%edx /* will zero %edx */
	movw	(%ebp,%ebx), %dx
	/* Compare code against bound */
	cmpl	%eax, rc_code(%ebp)
	jae	2f
1:	/* Code is less than bound */
	movl	%eax, rc_range(%ebp)
	negw	%dx
	addw	$(1<<11), %dx
	shrw	$5, %dx
	addw	%dx, (%ebp,%ebx)
	xorw	%ax, %ax	/* Clear CF, set ZF */
	jmp	99f
2:	/* Code is greater than or equal to bound */
	subl	%eax, rc_range(%ebp)
	subl	%eax, rc_code(%ebp)
	shrw	$5, %dx
	subw	%dx, (%ebp,%ebx)
	incw	%dx		/* Clear ZF (%dx is 11-bit; can never wrap) */
	stc			/* Set CF */
99:	/* Restore registers and return */
	popl	%edx
	popl	%eax
	ret
	.size	rc_bit, . - rc_bit

/*****************************************************************************
 * Decode MSB-first bittree
 *
 * Parameters:
 *   %ss:%ebp : LZMA parameter block
 *   %ds:%esi : compressed input data pointer
 *   %ebx : probability estimate set pointer (offset from %ebp)
 *   %cx : number of bits to decode
 * Returns:
 *   %ds:%esi : compressed input data pointer (possibly updated)
 *   %eax : decoded bittree
 * Corrupts:
 *   none
 *****************************************************************************
 */
rc_bittree:
	/* Preserve registers */
	pushl	%edi
	pushw	%cx
	movl	%ebx, %edi
	/* Initialise registers */
	movl	$1, %eax
1:	/* Decode bit */
	leaw	(%edi,%eax,2), %bx	/* high word always zero anyway */
	call	rc_bit
	rclw	%ax
	ADDR16 loop 1b
	/* Restore registers, clear unwanted high bit of result, and return */
	movl	%edi, %ebx
	popw	%cx
	popl	%edi
	btrw	%cx, %ax
	ret
	.size	rc_bittree, . - rc_bittree

/*****************************************************************************
 * Decode LSB-first bittree
 *
 * Parameters:
 *   %ss:%ebp : LZMA parameter block
 *   %ds:%esi : compressed input data pointer
 *   %ebx : probability estimate set pointer (offset from %ebp)
 *   %cx : number of bits to decode
 * Returns:
 *   %ds:%esi : compressed input data pointer (possibly updated)
 *   %eax : decoded bittree
 * Corrupts:
 *   none
 *****************************************************************************
 */
rc_bittree_reverse:
	/* Preserve registers */
	pushw	%cx
	/* Decode bittree */
	call	rc_bittree
1:	/* Reverse result */
	rcrb	%al
	rclb	%ah
	ADDR16 loop 1b
	shrw	$8, %ax
	/* Restore registers and return */
	popw	%cx
	ret
	.size	rc_bittree_reverse, . - rc_bittree_reverse

/*****************************************************************************
 * Decode MSB-first bittree with optional match byte
 *
 * Parameters:
 *   %ss:%ebp : LZMA parameter block
 *   %ds:%esi : compressed input data pointer
 *   %ebx : probability estimate set pointer (offset from %ebp)
 *   %cl : match byte
 *   %ch : 1 to use match byte, 0 to ignore match byte
 * Returns:
 *   %ds:%esi : compressed input data pointer (possibly updated)
 *   %eax : decoded bittree
 * Corrupts:
 *   none
 *****************************************************************************
 */
rc_bittree_match:
	/* Preserve registers */
	pushl	%edi
	pushw	%cx
	pushw	%dx
	movl	%ebx, %edi
	/* Initialise registers */
	movl	$1, %eax
1:	/* Decode bit */
	rolb	$1, %cl
	movw	%cx, %dx
	andb	%dh, %dl		/* match_bit in %dl */
	movw	%dx, %bx
	addb	%bl, %bh
	xorb	%bl, %bl
	addw	%ax, %bx		/* offset + match_bit + symbol */
	leaw	(%edi,%ebx,2), %bx	/* high word always zero anyway */
	call	rc_bit
	rclw	%ax
	movb	%al, %dh
	notb	%dh
	xorb	%dh, %dl
	andb	%dl, %ch		/* offset &= ( match_bit ^ bit ) */
	testb	%ah, %ah
	jz	1b
	/* Restore registers, clear unwanted high bit of result, and return */
	movl	%edi, %ebx
	popw	%dx
	popw	%cx
	popl	%edi
	xorb	%ah, %ah
	ret
	.size	rc_bittree_match, . - rc_bittree_match

/*****************************************************************************
 * Decode direct bits (no probability estimates)
 *
 * Parameters:
 *   %ss:%ebp : LZMA parameter block
 *   %ds:%esi : compressed input data pointer
 *   %cx : number of bits to decode
 * Returns:
 *   %ds:%esi : compressed input data pointer (possibly updated)
 *   %eax : decoded bits
 * Corrupts:
 *   none
 *****************************************************************************
 */
rc_direct:
	/* Preserve registers */
	pushl	%ebx
	pushw	%cx
	pushl	%edx
	/* Initialise registers */
	xorl	%edx, %edx
1:	/* Perform normalisation */
	call	rc_normalise
	/* Decode bit */
	shrl	$1, %eax
	movl	%eax, rc_range(%ebp)
	movl	rc_code(%ebp), %ebx
	subl	%eax, %ebx
	js	2f
	movl	%ebx, rc_code(%ebp)
2:	rcll	%ebx
	rcll	%edx
	xorb	$1, %dl
	ADDR16 loop 1b
	/* Restore registers and return */
	movl	%edx, %eax
	popl	%edx
	popw	%cx
	popl	%ebx
	ret
	.size	rc_direct, . - rc_direct

/*****************************************************************************
 * Decode an LZMA literal
 *
 * Parameters:
 *   %ss:%ebp : LZMA parameter block
 *   %ds:%esi : compressed input data pointer
 *   %es:%edi : uncompressed output data pointer
 *   %edx : LZMA state
 * Returns:
 *   %ds:%esi : compressed input data pointer (possibly updated)
 *   %es:%edi : uncompressed output data pointer (updated)
 *   %edx : LZMA state
 *   CF : end of payload marker found (always zero)
 * Corrupts:
 *   %eax
 *   %ebx
 *   %ecx
 *****************************************************************************
 *
 * Literals are coded as an eight-bit tree, using a match byte if the
 * previous symbol was not a literal.
 *
 */
lzma_literal:
	/* Get most recent output byte, if available */
	xorl	%ebx, %ebx
	cmpl	%edi, out_start(%ebp)
	je	1f
	movb	%es:-1(%edi), %bh
1:	/* Locate probability estimate set */
	shrb	$( 8 - LZMA_LC ), %bh
	shlb	$1, %bh
	leaw	literal(%ebx,%ebx,2), %bx
	/* Get match byte, if applicable */
	xorw	%cx, %cx
	cmpb	$STATE_LIT_MAX, %dl
	jbe	1f
	movl	rep0(%ebp), %eax
	notl	%eax
	movb	%es:(%edi,%eax), %cl
	movb	$1, %ch
1:	/* Decode bittree */
	call	rc_bittree_match
	/* Store output byte */
	ADDR32 stosb
	print_hex_byte %al
	print_character $(' ')
	/* Update LZMA state */
	subb	$3, %dl
	jns	1f
	xorb	%dl, %dl
1:	cmpb	$7, %dl
	jb	1f
	subb	$3, %dl
1:	/* Clear CF and return */
	clc
	ret
	.size	lzma_literal, . - lzma_literal

/*****************************************************************************
 * Decode an LZMA length
 *
 * Parameters:
 *   %ss:%ebp : LZMA parameter block
 *   %ds:%esi : compressed input data pointer
 *   %ebx : length parameter pointer (offset from %ebp)
 * Returns:
 *   %ds:%esi : compressed input data pointer (possibly updated)
 * Corrupts:
 *   %ebx
 *****************************************************************************
 *
 * Lengths are encoded as:
 *
 *   "0" + 3 bits    : lengths 2-9 ("low")
 *   "10" + 3 bits   : lengths 10-17 ("mid")
 *   "11" + 8 bits   : lengths 18-273 ("high")
 */
lzma_len:
	/* Preserve registers */
	pushl	%eax
	pushl	%ecx
	pushl	%edi
	movl	%ebx, %edi
	/* Start by assuming three bits and a base length of 2 */
	movw	$3, %cx
	movw	$2, len(%ebp)
	/* Check low-length choice bit */
	leal	choice(%edi), %ebx
	call	rc_bit
	leal	low(%edi), %ebx
	jz	1f
	/* Check high-length choice bit */
	leal	choice2(%edi), %ebx
	call	rc_bit
	leal	mid(%edi), %ebx
	movb	$10, len(%ebp)
	jz	1f
	leal	high(%edi), %ebx
	movb	$8, %cl
	movb	$18, len(%ebp)
1:	/* Get encoded length */
	call	rc_bittree
	addw	%ax, len(%ebp)
	/* Restore registers and return */
	movl	%edi, %ebx
	popl	%edi
	popl	%ecx
	popl	%eax
	ret
	.size	lzma_len, . - lzma_len

/*****************************************************************************
 * Copy (possibly repeated) matched data
 *
 * Parameters:
 *   %ss:%ebp : LZMA parameter block
 *   %ds:%esi : compressed input data pointer
 *   %es:%edi : uncompressed output data pointer
 *   %cl : repeated match distance index (for repeated matches)
 *   %eax : match distance (for non-repeated matches)
 * Returns:
 *   %ds:%esi : compressed input data pointer (possibly updated)
 *   %es:%edi : uncompressed output data pointer
 *   CF : match distance is out of range
 * Corrupts:
 *   %eax
 *   %ebx
 *   %ecx
 *****************************************************************************
 */
match:	/* Update repeated match list */
	print_character $('[')
	movl	$3, %ecx
	jmp	1f
match_rep:
	print_character $('[')
	print_character $('R')
	print_hex_byte %cl
	print_character $('=')
	movzbl	%cl, %ecx
	movl	reps(%ebp,%ecx,4), %eax
	jcxz	2f
1:	movl	(reps-4)(%ebp,%ecx,4), %ebx
	movl	%ebx, reps(%ebp,%ecx,4)
	loop	1b
	movl	%eax, rep0(%ebp)
2:	/* Preserve registers */
	pushl	%esi
	/* Get stored match length */
	movzwl	len(%ebp), %ecx
	print_hex_dword	%eax
	print_character $('+')
	print_hex_word %cx
	print_character $(']')
	print_character $(' ')
	/* Abort with CF set if match distance is out of range */
	movl	out_start(%ebp), %esi
	negl	%esi
	leal	-1(%edi,%esi), %esi
	cmpl	%eax, %esi
	jc	99f
	/* Perform copy */
	notl	%eax
	leal	(%edi,%eax), %esi
	ADDR32 es rep movsb
99:	/* Restore registers and return */
	popl	%esi
	ret
	.size	match, . - match

/*****************************************************************************
 * Decode an LZMA match
 *
 * Parameters:
 *   %ss:%ebp : LZMA parameter block
 *   %ds:%esi : compressed input data pointer
 *   %es:%edi : uncompressed output data pointer
 *   %edx : LZMA state
 * Returns:
 *   %ds:%esi : compressed input data pointer (possibly updated)
 *   %es:%edi : uncompressed output data pointer
 *   %edx : LZMA state
 *   CF : end of payload marker found
 * Corrupts:
 *   %eax
 *   %ebx
 *   %ecx
 *****************************************************************************
 *
 * Matches are encoded as an LZMA length followed by a 6-bit "distance
 * slot" code, 0-26 fixed-probability bits, and 0-5 context encoded
 * bits.
 */
lzma_match:
	/* Preserve registers */
	pushl	%edi
	/* Update LZMA state */
	cmpb	$STATE_LIT_MAX, %dl
	movb	$STATE_LIT_MATCH, %dl
	jbe	1f
	movb	$STATE_NONLIT_MATCH, %dl
1:	/* Decode length */
	movl	$match_len_dec, %ebx
	call	lzma_len
	/* Decode distance slot */
	movw	len(%ebp), %bx
	subw	$2, %bx
	cmpw	$4, %bx
	jb	1f
	movw	$3, %bx
1:	shlw	$7, %bx
	addw	$dist_slot, %bx
	movw	$6, %cx
	call	rc_bittree
	/* Distance slots 0-3 are literal distances */
	cmpb	$4, %al
	jb	99f
	/* Determine initial bits: 10/11 for even/odd distance codes */
	movl	%eax, %edi
	andw	$1, %di
	orw	$2, %di
	/* Determine number of context-encoded bits */
	movw	%ax, %cx
	shrb	$1, %cl
	decb	%cl
	/* Select context to be used in absence of fixed-probability bits */
	movl	%edi, %ebx
	shlw	%cl, %bx
	subw	%ax, %bx
	leaw	(dist_special-2)(%ebx,%ebx), %bx
	/* Decode fixed-probability bits, if any */
	cmpb	$6, %cl
	jb	1f
	subb	$4, %cl
	shll	%cl, %edi
	call	rc_direct
	orl	%eax, %edi
	/* Select context to be used in presence of fixed-probability bits */
	movb	$4, %cl
	movl	$dist_align, %ebx
1:	/* Decode context-encoded bits */
	shll	%cl, %edi
	call	rc_bittree_reverse
	orl	%edi, %eax
99:	/* Restore registers and tail-call */
	popl	%edi
	jmp	match
	.size	lzma_match, . - lzma_match

/*****************************************************************************
 * Decode an LZMA repeated match
 *
 * Parameters:
 *   %ss:%ebp : LZMA parameter block
 *   %ds:%esi : compressed input data pointer
 *   %es:%edi : uncompressed output data pointer
 *   %edx : LZMA state
 * Returns:
 *   %ds:%esi : compressed input data pointer (possibly updated)
 *   %es:%edi : uncompressed output data pointer
 *   %edx : LZMA state
 *   CF : end of payload marker found
 * Corrupts:
 *   %eax
 *   %ebx
 *   %ecx
 *****************************************************************************
 *
 * Repeated matches are encoded as:
 *
 *   "00"	 : shortrep0 (implicit length 1)
 *   "01" + len  : longrep0
 *   "10" + len  : longrep1
 *   "110" + len : longrep2
 *   "111" + len : longrep3
 */
lzma_rep_match:
	/* Initially assume longrep0 */
	movw	$(STATE_LIT_LONGREP << 8), %cx
	/* Get is_rep0 bit */
	leal	is_rep0(,%edx,2), %ebx
	call	rc_bit
	jnz	1f
	/* Get is_rep0_long bit */
	leal	is_rep0_long(,%edx,2), %ebx
	call	rc_bit
	jnz	98f
	movw	$1, len(%ebp)
	movb	$STATE_LIT_SHORTREP, %ch
	jmp	99f
1:	/* Get is_rep1 bit */
	incb	%cl
	leal	is_rep1(,%edx,2), %ebx
	call	rc_bit
	jz	98f
	/* Get is_rep2 bit */
	incb	%cl
	leal	is_rep2(,%edx,2), %ebx
	call	rc_bit
	adcb	$0, %cl
98:	/* Decode length */
	movl	$rep_len_dec, %ebx
	call	lzma_len
99:	/* Update LZMA state */
	cmpb	$STATE_LIT_MAX, %dl
	movb	%ch, %dl
	jbe	1f
	movb	$STATE_NONLIT_REP, %dl
1:	/* Tail call */
	jmp	match_rep
	.size	lzma_match, . - lzma_match

/*****************************************************************************
 * Decode one LZMA symbol
 *
 * Parameters:
 *   %ss:%ebp : LZMA parameter block
 *   %ds:%esi : compressed input data pointer
 *   %es:%edi : uncompressed output data pointer
 *   %edx : LZMA state
 * Returns:
 *   %ds:%esi : compressed input data pointer (possibly updated)
 *   %es:%edi : uncompressed output data pointer (updated)
 *   %edx : LZMA state
 *   CF : end of payload marker found
 * Corrupts:
 *   %eax
 *   %ebx
 *   %ecx
 *****************************************************************************
 */
lzma_decode:
	/* Get is_match bit */
	leal	is_match(,%edx,2), %ebx
	call	rc_bit
	jz	lzma_literal
	/* Get is_rep bit */
	leal	is_rep(,%edx,2), %ebx
	call	rc_bit
	jz	lzma_match
	jmp	lzma_rep_match
	.size	lzma_decode, . - lzma_decode

/****************************************************************************
 * Undo effect of branch-call-jump (BCJ) filter
 *
 * Parameters:
 *   %es:%esi : start of uncompressed output data (note %es)
 *   %es:%edi : end of uncompressed output data
 * Returns:
 * Corrupts:
 *   %eax
 *   %ebx
 *   %ecx
 *   %edx
 *   %esi
 *****************************************************************************
 */
bcj_filter:
	/* Store (negative) start of data in %edx */
	movl	%esi, %edx
	negl	%edx
	/* Calculate limit in %ecx */
	leal	-5(%edi,%edx), %ecx
1:	/* Calculate offset in %ebx */
	leal	(%esi,%edx), %ebx
	/* Check for end of data */
	cmpl	%ecx, %ebx
	ja	99f
	/* Check for an opcode which would be followed by a rel32 address */
	ADDR32 es lodsb
	andb	$0xfe, %al
	cmpb	$0xe8, %al
	jne	1b
	/* Get current jump target value in %eax */
	ADDR32 es lodsl
	/* Convert absolute addresses in the range [0,limit) back to
	 * relative addresses in the range [-offset,limit-offset).
	 */
	cmpl	%ecx, %eax
	jae	2f
	subl	%ebx,%es:-4(%esi)
2:	/* Convert negative numbers in the range [-offset,0) back to
	 * positive numbers in the range [limit-offset,limit).
	 */
	notl	%eax	/* Range is now [0,offset) */
	cmpl	%ebx, %eax
	jae	1b
	addl	%ecx,%es:-4(%esi)
	jmp	1b
99:	/* Return */
	ret
	.size	bcj_filter, . - bcj_filter

/****************************************************************************
 * decompress (real-mode or 16/32-bit protected-mode near call)
 *
 * Decompress data
 *
 * Parameters (passed via registers):
 *   %ds:%esi : Start of compressed input data
 *   %es:%edi : Start of output buffer
 * Returns:
 *   %ds:%esi - End of compressed input data
 *   %es:%edi - End of decompressed output data
 *   All other registers are preserved
 *
 * NOTE: It would be possible to build a smaller version of the
 * decompression code for -DKEEP_IT_REAL by using 16-bit registers
 * where possible.
 ****************************************************************************
 */
	.globl	decompress
decompress:
	/* Preserve registers */
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	pushl	%ebp
	/* Allocate parameter block */
	subl	$sizeof__lzma_dec, %esp
	movl	%esp, %ebp
	/* Zero parameter block and set all probabilities to 0.5 */
	pushl	%edi
	pushw	%es
	pushw	%ss
	popw	%es
	movl	%ebp, %edi
	xorl	%eax, %eax
	movl	$( sizeof__lzma_dec / 4 ), %ecx
	ADDR32 rep stosl
	leal	probs(%ebp), %edi
	movw	$( ( 1 << 11 ) / 2 ), %ax
	movl	$( ( sizeof__lzma_dec - probs ) / 2 ), %ecx
	ADDR32 rep stosw
	popw	%es
	popl	%edi
	/* Initialise remaining parameters */
	movl	%edi, out_start(%ebp)
	print_character $('\n')
	ADDR32 lodsb	/* discard initial byte */
	print_hex_byte %al
	ADDR32 lodsl
	bswapl	%eax
	print_hex_dword %eax
	print_character $('\n')
	movl	%eax, rc_code(%ebp)
	decl	rc_range(%ebp)
	movl	$STATE_LIT_LIT, %edx
1:	/* Decompress until we reach end of buffer */
	call	lzma_decode
	jnc	1b
	call	rc_normalise
	print_character $('\n')
	/* Undo BCJ filter */
	pushl	%esi
	movl	out_start(%ebp), %esi
	call	bcj_filter
	popl	%esi
	/* Restore registers and return */
	addl	$sizeof__lzma_dec, %esp
	popl	%ebp
	popl	%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	ret

	/* Specify minimum amount of stack space required */
	.globl	_min_decompress_stack
	.equ	_min_decompress_stack, ( sizeof__lzma_dec + 512 /* margin */ )
