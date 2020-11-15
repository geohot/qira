FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

#define BOOT_SEG	0x07c0
#define EXEC_SEG	0x0100
#define STACK_SEG 	0x0200
#define STACK_SIZE	0x2000
	
	.text
	.arch i386
	.section ".prefix", "awx", @progbits
	.code16

/*
 * Find active partition
 *
 * Parameters:
 *   %dl	: BIOS drive number
 *   %bp	: Active partition handler routine
 */
find_active_partition:
	/* Set up stack at STACK_SEG:STACK_SIZE */
	movw	$STACK_SEG, %ax
	movw	%ax, %ss
	movw	$STACK_SIZE, %sp

	/* Relocate self to EXEC_SEG */
	pushw	$BOOT_SEG
	popw	%ds
	pushw	$EXEC_SEG
	popw	%es
	xorw	%si, %si
	xorw	%di, %di
	movw	$0x200, %cx
	rep movsb
	ljmp	$EXEC_SEG, $1f
1:	pushw	%ds
	popw	%es
	pushw	%cs
	popw	%ds

	/* Check for LBA extensions */
	movb	$0x41, %ah
	movw	$0x55aa, %bx
	stc
	int	$0x13
	jc	1f
	cmpw	$0xaa55, %bx
	jne	1f
	movw	$read_lba, read_sectors
1:	
	/* Read and process root partition table */
	xorb	%dh, %dh
	movw	$0x0001, %cx
	xorl	%esi, %esi
	xorl	%edi, %edi
	call	process_table

	/* Print failure message */
	movw	$10f, %si
	jmp	boot_error
10:	.asciz	"Could not locate active partition\r\n"

/*
 * Print failure message and boot next device
 *
 * Parameters:
 *   %si	: Failure string
 */
boot_error:
	cld
	movw	$0x0007, %bx
	movb	$0x0e, %ah
1:	lodsb
	testb	%al, %al
	je	99f
	int	$0x10
	jmp	1b
99:	/* Boot next device */
	int	$0x18

/*
 * Process partition table
 *
 * Parameters:
 *   %dl	: BIOS drive number
 *   %dh	: Head
 *   %cl	: Sector (bits 0-5), high two bits of cylinder (bits 6-7)
 *   %ch	: Low eight bits of cylinder
 *   %esi:%edi	: LBA address
 *   %bp	: Active partition handler routine
 *
 * Returns:
 *   CF set on error
 */
process_table:
	pushal
	call	read_boot_sector
	jc	99f
	movw	$446, %bx
1:	call	process_partition
	addw	$16, %bx
	cmpw	$510, %bx
	jne	1b
99:	popal
	ret

/*
 * Process partition
 *
 * Parameters:
 *   %dl	: BIOS drive number
 *   %dh	: Head
 *   %cl	: Sector (bits 0-5), high two bits of cylinder (bits 6-7)
 *   %ch	: Low eight bits of cylinder
 *   %esi:%edi	: LBA address
 *   %bx	: Offset within partition table
 *   %bp	: Active partition handler routine
 */
process_partition:
	pushal
	/* Load C/H/S values from partition entry */
	movb	%es:1(%bx), %dh
	movw	%es:2(%bx), %cx
	/* Update LBA address from partition entry */
	addl	%es:8(%bx), %edi
	adcl	$0, %esi
	/* Check active flag */
	testb	$0x80, %es:(%bx)
	jz	1f
	call	read_boot_sector
	jc	99f
	jmp	*%bp
1:	/* Check for extended partition */
	movb	%es:4(%bx), %al
	cmpb	$0x05, %al
	je	2f
	cmpb	$0x0f, %al
	je	2f
	cmpb	$0x85, %al
	jne	99f
2:	call	process_table
99:	popal
	/* Reload original partition table */
	call	read_boot_sector
	ret

/*
 * Read single sector to %es:0000 and verify 0x55aa signature
 *
 * Parameters:
 *   %dl	: BIOS drive number
 *   %dh	: Head
 *   %cl	: Sector (bits 0-5), high two bits of cylinder (bits 6-7)
 *   %ch	: Low eight bits of cylinder
 *   %esi:%edi	: LBA address
 *
 * Returns:
 *   CF set on error
 */
read_boot_sector:
	pushw	%ax
	movw	$1, %ax
	call	*read_sectors
	jc	99f
	cmpw	$0xaa55, %es:(510)
	je	99f
	stc	
99:	popw	%ax
	ret
	
/*
 * Read sectors to %es:0000
 *
 * Parameters:
 *   %dl	: BIOS drive number
 *   %dh	: Head
 *   %cl	: Sector (bits 0-5), high two bits of cylinder (bits 6-7)
 *   %ch	: Low eight bits of cylinder
 *   %esi:%edi	: LBA address
 *   %ax	: Number of sectors (max 127)
 *
 * Returns:
 *   CF set on error
 */
read_sectors:	.word	read_chs

read_chs:
	/* Read sectors using C/H/S address */
	pushal
	xorw	%bx, %bx
	movb	$0x02, %ah
	stc
	int	$0x13
	sti
	popal
	ret

read_lba:
	/* Read sectors using LBA address */
	pushal
	movw	%ax, (lba_desc + 2)
	pushw	%es
	popw	(lba_desc + 6)
	movl	%edi, (lba_desc + 8)
	movl	%esi, (lba_desc + 12)
	movw	$lba_desc, %si
	movb	$0x42, %ah
	int	$0x13
	popal
	ret

lba_desc:
	.byte	0x10
	.byte	0
	.word	1
	.word	0x0000
	.word	0x0000
	.long	0, 0
