FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

#define BZI_LOAD_HIGH_ADDR 0x100000

	.text
	.arch i386
	.code16
	.section ".prefix", "ax", @progbits
	.globl	_lkrn_start
_lkrn_start:

/*****************************************************************************
 *
 * Kernel header
 *
 * We place our prefix (i.e. our .prefix and .text16.early sections)
 * within the bzImage real-mode portion which gets loaded at
 * 1000:0000, and our payload (i.e. everything else) within the
 * bzImage protected-mode portion which gets loaded at 0x100000
 * upwards.
 *
 */

	.org	0x1f1
setup_sects:
	.byte	-1 /* Allow for initial "boot sector" */
	.section ".zinfo.fixup", "a", @progbits	/* Compressor fixups */
	.ascii	"ADHL"
	.long	setup_sects
	.long	512
	.long	0
	.previous
root_flags:
	.word	0
syssize:
	.long	0
	.section ".zinfo.fixup", "a", @progbits	/* Compressor fixups */
	.ascii	"ADPL"
	.long	syssize
	.long	16
	.long	0
	.previous
ram_size:
	.word	0
vid_mode:
	.word	0
root_dev:
	.word	0
boot_flag:
	.word	0xaa55
jump:
	/* Manually specify a two-byte jmp instruction here rather
	 * than leaving it up to the assembler.
	 */
	.byte	0xeb, ( setup - header )
header:
	.byte	'H', 'd', 'r', 'S'
version:
	.word	0x0207 /* 2.07 */
realmode_swtch:
	.long	0
start_sys:
	.word	0
kernel_version:
	.word	version_string - 0x200
type_of_loader:
	.byte	0
loadflags:
	.byte	0x01 /* LOADED_HIGH */
setup_move_size:
	.word	0
code32_start:
	.long	0
ramdisk_image:
	.long	0
ramdisk_size:
	.long	0
bootsect_kludge:
	.long	0
heap_end_ptr:
	.word	0
ext_loader_ver:
	.byte	0
ext_loader_type:
	.byte	0
cmd_line_ptr:
	.long	0
initrd_addr_max:
	.long	0xffffffff
kernel_alignment:
	.long	0
relocatable_kernel:
	.byte	0
min_alignment:
	.byte	0
xloadflags:
	.word	0
cmdline_size:
	.long	0x7ff
hardware_subarch:
	.long	0
hardware_subarch_data:
	.byte	0, 0, 0, 0, 0, 0, 0, 0

version_string:
	.asciz	VERSION

/*****************************************************************************
 *
 * Setup code
 *
 */

setup:
	/* Fix up code segment */
	pushw	%ds
	pushw	$1f
	lret
1:
	/* Set up stack just below 0x7c00 and clear direction flag */
	xorw	%ax, %ax
	movw	%ax, %ss
	movw	$0x7c00, %sp
	cld

	/* Retrieve command-line pointer */
	movl	cmd_line_ptr, %edx
	testl	%edx, %edx
	jz	no_cmd_line

	/* Set up %es:%di to point to command line */
	movl	%edx, %edi
	andl	$0xf, %edi
	rorl	$4, %edx
	movw	%dx, %es

	/* Find length of command line */
	pushw	%di
	movw	$0xffff, %cx
	repnz scasb
	notw	%cx
	popw	%si

	/* Make space for command line on stack */
	movw	%sp, %di
	subw	%cx, %di
	andw	$~0xf, %di
	movw	%di, %sp

	/* Copy command line to stack */
	pushw	%ds
	pushw	%es
	popw	%ds
	pushw	%ss
	popw	%es
	rep movsb
	popw	%ds

	/* Store new command-line pointer */
	movzwl	%sp, %edx
no_cmd_line:

	/* Calculate maximum relocation address */
	movl	ramdisk_image, %ebp
	testl	%ebp, %ebp
	jnz	1f
	orl	$0xffffffff, %ebp /* Allow arbitrary relocation if no initrd */
1:
	/* Install iPXE */
	call	alloc_basemem
	xorl	%esi, %esi
	xorl	%edi, %edi
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
	/* Retrieve initrd pointer and size */
	movl	ramdisk_image, %ebp
	movl	ramdisk_size, %ecx

	/* Set up %ds for access to .data16 */
	movw	%bx, %ds

	/* Store command-line pointer */
	movl	%edx, cmdline_phys

	/* Store initrd pointer and size */
	movl	%ebp, initrd_phys
	movl	%ecx, initrd_len

	/* Run iPXE */
	pushl	$main
	pushw	%cs
	call	prot_call
	popl	%ecx /* discard */

	/* Uninstall iPXE */
	call	uninstall

	/* Boot next device */
	int $0x18

/*****************************************************************************
 *
 * Open payload (called by libprefix)
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

	/* Our payload will always end up at BZI_LOAD_HIGH_ADDR */
	movl	$BZI_LOAD_HIGH_ADDR, %esi
	xorl	%ecx, %ecx
	lret

	/* Payload must be aligned to a whole number of setup sectors */
	.globl	_payload_align
	.equ	_payload_align, 512
