/* At entry, the processor is in 16 bit real mode and the code is being
 * executed from an address it was not linked to. Code must be pic and
 * 32 bit sensitive until things are fixed up.
 *
 * Also be very careful as the stack is at the rear end of the interrupt
 * table so using a noticeable amount of stack space is a no-no.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

#include <config/general.h>
#include <config/branding.h>

#define PNP_SIGNATURE ( '$' + ( 'P' << 8 ) + ( 'n' << 16 ) + ( 'P' << 24 ) )
#define PMM_SIGNATURE ( '$' + ( 'P' << 8 ) + ( 'M' << 16 ) + ( 'M' << 24 ) )
#define PCI_SIGNATURE ( 'P' + ( 'C' << 8 ) + ( 'I' << 16 ) + ( ' ' << 24 ) )
#define STACK_MAGIC ( 'L' + ( 'R' << 8 ) + ( 'E' << 16 ) + ( 'T' << 24 ) )
#define PMM_ALLOCATE 0x0000
#define PMM_FIND 0x0001
#define PMM_HANDLE_BASE ( ( ( 'F' - 'A' + 1 ) << 26 ) + \
			  ( ( 'E' - 'A' + 1 ) << 21 ) + \
			  ( ( 'N' - 'A' + 1 ) << 16 ) )
#define PMM_HANDLE_BASE_IMAGE_SOURCE \
	( PMM_HANDLE_BASE | 0x00001000 )
#define PMM_HANDLE_BASE_DECOMPRESS_TO \
	( PMM_HANDLE_BASE | 0x00002000 )
#define PCI_FUNC_MASK 0x07

/* ROM banner timeout, converted to a number of (18Hz) timer ticks. */
#define ROM_BANNER_TIMEOUT_TICKS ( ( 18 * ROM_BANNER_TIMEOUT ) / 10 )

/* Allow payload to be excluded from ROM size
 */
#if ROMPREFIX_EXCLUDE_PAYLOAD
#define	ZINFO_TYPE_ADxB "ADHB"
#define	ZINFO_TYPE_ADxW "ADHW"
#else
#define	ZINFO_TYPE_ADxB "ADDB"
#define	ZINFO_TYPE_ADxW "ADDW"
#endif

/* Allow ROM to be marked as containing multiple images
 */
#if ROMPREFIX_MORE_IMAGES
#define INDICATOR 0x00
#else
#define INDICATOR 0x80
#endif

/* Default to building a PCI ROM if no bus type is specified
 */
#ifndef BUSTYPE
#define BUSTYPE "PCIR"
#endif

	.text
	.code16
	.arch i386
	.section ".prefix", "ax", @progbits
	.globl	_rom_start
_rom_start:
	
	.org	0x00
romheader:
	.word	0xAA55			/* BIOS extension signature */
romheader_size:	.byte 0			/* Size in 512-byte blocks */
	jmp	init			/* Initialisation vector */
checksum:
	.byte	0
	.org	0x10
	.word	ipxeheader
	.org	0x16
	.word	undiheader
.ifeqs	BUSTYPE, "PCIR"
	.org	0x18
	.word	pciheader
.endif
	.org	0x1a
	.word	pnpheader
	.size romheader, . - romheader

	.section ".zinfo.fixup", "a", @progbits	/* Compressor fixups */
	.ascii	ZINFO_TYPE_ADxB
	.long	romheader_size
	.long	512
	.long	0
	.previous

.ifeqs	BUSTYPE, "PCIR"
pciheader:
	.ascii	"PCIR"			/* Signature */
	.word	pci_vendor_id		/* Vendor identification */ 
	.word	pci_device_id		/* Device identification */
	.word	( pci_devlist - pciheader ) /* Device list pointer */
	.word	pciheader_len		/* PCI data structure length */
	.byte	0x03			/* PCI data structure revision */
	.byte	0x02, 0x00, 0x00	/* Class code */
pciheader_image_length:
	.word	0			/* Image length */
	.word	0x0001			/* Revision level */
	.byte	0x00			/* Code type */
	.byte	INDICATOR		/* Last image indicator */
pciheader_runtime_length:
	.word	0			/* Maximum run-time image length */
	.word	0x0000			/* Configuration utility code header */
	.word	0x0000			/* DMTF CLP entry point */
	.equ pciheader_len, . - pciheader
	.size pciheader, . - pciheader

	/* PCI additional device list (filled in by linker) */
	.section ".pci_devlist.00000000", "a", @progbits
pci_devlist:
	.previous
	.section ".pci_devlist.ffffffff", "a", @progbits
pci_devlist_end:
	.short	0x0000 /* List terminator */
	.previous
	/* Ensure that terminator is always present */
	.reloc pciheader, RELOC_TYPE_NONE, pci_devlist_end

	.section ".zinfo.fixup", "a", @progbits	/* Compressor fixups */
	.ascii	ZINFO_TYPE_ADxW
	.long	pciheader_image_length
	.long	512
	.long	0
	.ascii	ZINFO_TYPE_ADxW
	.long	pciheader_runtime_length
	.long	512
	.long	0
	.previous
.endif	/* PCIR */

	/* PnP doesn't require any particular alignment, but IBM
	 * BIOSes will scan on 16-byte boundaries rather than using
	 * the offset stored at 0x1a
	 */
	.align	16
pnpheader:
	.ascii	"$PnP"			/* Signature */
	.byte	0x01			/* Structure revision */
	.byte	( pnpheader_len	/ 16 )	/* Length (in 16 byte increments) */
	.word	0x0000			/* Offset of next header */
	.byte	0x00			/* Reserved */
	.byte	0x00			/* Checksum */
	.long	0x00000000		/* Device identifier */
	.word	mfgstr			/* Manufacturer string */
	.word	prodstr			/* Product name */
	.byte	0x02			/* Device base type code */
	.byte	0x00			/* Device sub-type code */
	.byte	0x00			/* Device interface type code */
	.byte	0xf4			/* Device indicator */
	.word	0x0000			/* Boot connection vector */
	.word	0x0000			/* Disconnect vector */
	.word	bev_entry		/* Boot execution vector */
	.word	0x0000			/* Reserved */
	.word	0x0000			/* Static resource information vector*/
	.equ pnpheader_len, . - pnpheader
	.size pnpheader, . - pnpheader

/* Manufacturer string */
mfgstr:
	.asciz	"http://ipxe.org"
	.size mfgstr, . - mfgstr

/* Product string
 *
 * Defaults to PRODUCT_SHORT_NAME.  If the ROM image is writable at
 * initialisation time, it will be filled in to include the PCI
 * bus:dev.fn number of the card as well.
 */
prodstr:
	.ascii	PRODUCT_SHORT_NAME
.ifeqs	BUSTYPE, "PCIR"
prodstr_separator:
	.byte	0
	.ascii	"(PCI "
prodstr_pci_id:
	.ascii	"xx:xx.x)"		/* Filled in by init code */
.endif	/* PCIR */
	.byte	0
	.size prodstr, . - prodstr

	.globl	undiheader	
	.weak	undiloader
undiheader:
	.ascii	"UNDI"			/* Signature */
	.byte	undiheader_len		/* Length of structure */
	.byte	0			/* Checksum */
	.byte	0			/* Structure revision */
	.byte	0,1,2			/* PXE version: 2.1.0 */
	.word	undiloader		/* Offset to loader routine */
	.word	_data16_memsz		/* Stack segment size */
	.word	_data16_memsz		/* Data segment size */
	.word	_text16_memsz		/* Code segment size */
	.ascii	BUSTYPE			/* Bus type */
	.equ undiheader_len, . - undiheader
	.size undiheader, . - undiheader

ipxeheader:
	.ascii	"iPXE"			/* Signature */
	.byte	ipxeheader_len		/* Length of structure */
	.byte	0			/* Checksum */
shrunk_rom_size:
	.byte	0			/* Shrunk size (in 512-byte blocks) */
	.byte	0			/* Reserved */
build_id:
	.long	_build_id		/* Randomly-generated build ID */
	.equ ipxeheader_len, . - ipxeheader
	.size ipxeheader, . - ipxeheader

	.section ".zinfo.fixup", "a", @progbits	/* Compressor fixups */
	.ascii	"ADHB"
	.long	shrunk_rom_size
	.long	512
	.long	0
	.previous

/* Initialisation (called once during POST)
 *
 * Determine whether or not this is a PnP system via a signature
 * check.  If it is PnP, return to the PnP BIOS indicating that we are
 * a boot-capable device; the BIOS will call our boot execution vector
 * if it wants to boot us.  If it is not PnP, hook INT 19.
 */
init:
	/* Preserve registers, clear direction flag, set %ds=%cs */
	pushaw
	pushw	%ds
	pushw	%es
	pushw	%fs
	pushw	%gs
	cld
	pushw	%cs
	popw	%ds

	/* Print message as early as possible */
	movw	$init_message, %si
	xorw	%di, %di
	call	print_message

	/* Store PCI 3.0 runtime segment address for later use, if
	 * applicable.
	 */
.ifeqs	BUSTYPE, "PCIR"
	movw	%bx, %gs
.endif

	/* Store PCI bus:dev.fn address, print PCI bus:dev.fn, and add
	 * PCI bus:dev.fn to product name string, if applicable.
	 */
.ifeqs	BUSTYPE, "PCIR"
	xorw	%di, %di
	call	print_space
	movw	%ax, init_pci_busdevfn
	call	print_pci_busdevfn
	movw	$prodstr_pci_id, %di
	call	print_pci_busdevfn
	movb	$( ' ' ), prodstr_separator
.endif

	/* Print segment address */
	xorw	%di, %di
	call	print_space
	movw	%cs, %ax
	call	print_hex_word

	/* Check for PCI BIOS version, if applicable */
.ifeqs	BUSTYPE, "PCIR"
	pushl	%ebx
	pushl	%edx
	pushl	%edi
	stc
	movw	$0xb101, %ax
	int	$0x1a
	jc	no_pci3
	cmpl	$PCI_SIGNATURE, %edx
	jne	no_pci3
	testb	%ah, %ah
	jnz	no_pci3
	movw	$init_message_pci, %si
	xorw	%di, %di
	call	print_message
	movb	%bh, %al
	call	print_hex_nibble
	movb	$( '.' ), %al
	call	print_character
	movb	%bl, %al
	call	print_hex_byte
	cmpb	$3, %bh
	jb	no_pci3
	/* PCI >=3.0: leave %gs as-is if sane */
	movw	%gs, %ax
	cmpw	$0xa000, %ax	/* Insane if %gs < 0xa000 */
	jb	pci3_insane
	movw	%cs, %bx	/* Sane if %cs == %gs */
	cmpw	%bx, %ax
	je	1f
	movzbw	romheader_size, %cx /* Sane if %cs+len <= %gs */
	shlw	$5, %cx
	addw	%cx, %bx
	cmpw	%bx, %ax
	jae	1f
	movw	%cs, %bx	/* Sane if %gs+len <= %cs */
	addw	%cx, %ax
	cmpw	%bx, %ax
	jbe	1f
pci3_insane: /* PCI 3.0 with insane %gs value: print error and ignore %gs */
	movb	$( '!' ), %al
	call	print_character
	movw	%gs, %ax
	call	print_hex_word
no_pci3:
	/* PCI <3.0: set %gs (runtime segment) = %cs (init-time segment) */
	pushw	%cs
	popw	%gs
1:	popl	%edi
	popl	%edx
	popl	%ebx
.endif	/* PCIR */

	/* Check for PnP BIOS.  Although %es:di should point to the
	 * PnP BIOS signature on entry, some BIOSes fail to do this.
	 */
	movw	$( 0xf000 - 1 ), %bx
pnp_scan:
	incw	%bx
	jz	no_pnp
	movw	%bx, %es
	cmpl	$PNP_SIGNATURE, %es:0
	jne	pnp_scan
	xorw	%dx, %dx
	xorw	%si, %si
	movzbw	%es:5, %cx
1:	es lodsb
	addb	%al, %dl
	loop	1b
	jnz	pnp_scan
	/* Is PnP: print PnP message */
	movw	$init_message_pnp, %si
	xorw	%di, %di
	call	print_message
	jmp	pnp_done
no_pnp:	/* Not PnP-compliant - hook INT 19 */
#ifdef NONPNP_HOOK_INT19
	movw	$init_message_int19, %si
	xorw	%di, %di
	call	print_message
	xorw	%ax, %ax
	movw	%ax, %es
	pushl	%es:( 0x19 * 4 )
	popl	orig_int19
	pushw	%gs /* %gs contains runtime %cs */
	pushw	$int19_entry
	popl	%es:( 0x19 * 4 )
#endif /* NONPNP_HOOK_INT19 */
pnp_done:

	/* Check for PMM */
	movw	$( 0xe000 - 1 ), %bx
pmm_scan:
	incw	%bx
	jz	no_pmm
	movw	%bx, %es
	cmpl	$PMM_SIGNATURE, %es:0
	jne	pmm_scan
	xorw	%dx, %dx
	xorw	%si, %si
	movzbw	%es:5, %cx
1:	es lodsb
	addb	%al, %dl
	loop	1b
	jnz	pmm_scan
	/* PMM found: print PMM message */
	movw	$init_message_pmm, %si
	xorw	%di, %di
	call	print_message
	/* We have PMM and so a 1kB stack: preserve whole registers */
	pushal
	/* Allocate image source PMM block.  Round up the size to the
	 * nearest 4kB (8 512-byte sectors) to work around AMI BIOS bugs.
	 */
	movzbl	romheader_size, %ecx
	addw	extra_size, %cx
	addw	$0x0007, %cx	/* Round up to multiple of 8 512-byte sectors */
	andw	$0xfff8, %cx
	shll	$5, %ecx
	movl	$PMM_HANDLE_BASE_IMAGE_SOURCE, %ebx
	movw	$get_pmm_image_source, %bp
	call	get_pmm
	movl	%esi, image_source
	jz	1f
	/* Copy ROM to image source PMM block */
	pushw	%es
	xorw	%ax, %ax
	movw	%ax, %es
	movl	%esi, %edi
	xorl	%esi, %esi
	movzbl	romheader_size, %ecx
	shll	$7, %ecx
	addr32 rep movsl	/* PMM presence implies flat real mode */
	popw	%es
	/* Shrink ROM */
	movb	shrunk_rom_size, %al
	movb	%al, romheader_size
1:	/* Allocate decompression PMM block.  Round up the size to the
	 * nearest 128kB and use the size within the PMM handle; this
	 * allows the same decompression area to be shared between
	 * multiple iPXE ROMs even with differing build IDs
	 */
	movl	$_textdata_memsz_pgh, %ecx
	addl	$0x00001fff, %ecx
	andl	$0xffffe000, %ecx
	movl	%ecx, %ebx
	shrw	$12, %bx
	orl	$PMM_HANDLE_BASE_DECOMPRESS_TO, %ebx
	movw	$get_pmm_decompress_to, %bp
	call	get_pmm
	movl	%esi, decompress_to
	/* Restore registers */
	popal
no_pmm:

	/* Update checksum */
	xorw	%bx, %bx
	xorw	%si, %si
	movzbw	romheader_size, %cx
	shlw	$9, %cx
1:	lodsb
	addb	%al, %bl
	loop	1b
	subb	%bl, checksum

	/* Copy self to option ROM space, if applicable.  Required for
	 * PCI3.0, which loads us to a temporary location in low
	 * memory.  Will be a no-op for lower PCI versions.
	 */
.ifeqs	BUSTYPE, "PCIR"
	xorw	%di, %di
	call	print_space
	movw	%gs, %ax
	call	print_hex_word
	movzbw	romheader_size, %cx
	shlw	$9, %cx
	movw	%ax, %es
	xorw	%si, %si
	xorw	%di, %di
	cs rep	movsb
.endif

	/* Skip prompt if this is not the first PCI function, if applicable */
.ifeqs	BUSTYPE, "PCIR"
	testb	$PCI_FUNC_MASK, init_pci_busdevfn
	jnz	no_shell
.endif
	/* Prompt for POST-time shell */
	movw	$init_message_prompt, %si
	xorw	%di, %di
	call	print_message
	movw	$prodstr, %si
	call	print_message
	movw	$init_message_dots, %si
	call	print_message
	/* Wait for Ctrl-B */
	movw	$0xff02, %bx
	call	wait_for_key
	/* Clear prompt */
	pushf
	xorw	%di, %di
	call	print_kill_line
	movw	$init_message_done, %si
	call	print_message
	popf
	jnz	no_shell
	/* Ctrl-B was pressed: invoke iPXE.  The keypress will be
	 * picked up by the initial shell prompt, and we will drop
	 * into a shell.
	 */
	xorl	%ebp, %ebp	/* Inhibit use of INT 15,e820 and INT 15,e801 */
	pushw	%cs
	call	exec
no_shell:
	movb	$( '\n' ), %al
	xorw	%di, %di
	call	print_character

	/* Restore registers */
	popw	%gs
	popw	%fs
	popw	%es
	popw	%ds
	popaw

	/* Indicate boot capability to PnP BIOS, if present */
	movw	$0x20, %ax
	lret
	.size init, . - init

/* Attempt to find or allocate PMM block
 *
 * Parameters:
 *  %ecx : size of block to allocate, in paragraphs
 *  %ebx : PMM handle base
 *  %bp : routine to check acceptability of found blocks
 *  %es:0000 : PMM structure
 * Returns:
 *  %ebx : PMM handle
 *  %esi : allocated block address, or zero (with ZF set) if allocation failed
 */
get_pmm:
	/* Preserve registers */
	pushl	%eax
	pushw	%di
	movw	$( ' ' ), %di
get_pmm_find:
	/* Try to find existing block */
	pushl	%ebx		/* PMM handle */
	pushw	$PMM_FIND
	lcall	*%es:7
	addw	$6, %sp
	pushw	%dx
	pushw	%ax
	popl	%esi
	/* Treat 0xffffffff (not supported) as 0x00000000 (not found) */
	incl	%esi
	jz	get_pmm_allocate
	decl	%esi
	jz	get_pmm_allocate
	/* Block found - check acceptability */
	call	*%bp
	jnc	get_pmm_done
	/* Block not acceptable - increment handle and retry */
	incl	%ebx
	jmp	get_pmm_find
get_pmm_allocate:
	/* Block not found - try to allocate new block */
	pushw	$0x0002		/* Extended memory */
	pushl	%ebx		/* PMM handle */
	pushl	%ecx		/* Length */
	pushw	$PMM_ALLOCATE
	lcall	*%es:7
	addw	$12, %sp
	pushw	%dx
	pushw	%ax
	popl	%esi
	movw	$( '+' ), %di	/* Indicate allocation attempt */
get_pmm_done:
	/* Print block address */
	movw	%di, %ax
	xorw	%di, %di
	call	print_character
	movl	%esi, %eax
	call	print_hex_dword
	/* Treat 0xffffffff (not supported) as 0x00000000 (allocation
	 * failed), and set ZF to indicate a zero result.
	 */
	incl	%esi
	jz	1f
	decl	%esi
1:	/* Restore registers and return */
	popw	%di
	popl	%eax
	ret
	.size	get_pmm, . - get_pmm

	/* Check acceptability of image source block */
get_pmm_image_source:
	pushw	%es
	xorw	%ax, %ax
	movw	%ax, %es
	movl	build_id, %eax
	addr32 cmpl %es:build_id(%esi), %eax
	je	1f
	stc
1:	popw	%es
	ret
	.size	get_pmm_image_source, . - get_pmm_image_source

	/* Check acceptability of decompression block */
get_pmm_decompress_to:
	clc
	ret
	.size	get_pmm_decompress_to, . - get_pmm_decompress_to

/*
 * Note to hardware vendors:
 *
 * If you wish to brand this boot ROM, please do so by defining the
 * strings PRODUCT_NAME and PRODUCT_SHORT_NAME in config/branding.h.
 *
 * While nothing in the GPL prevents you from removing all references
 * to iPXE or http://ipxe.org, we prefer you not to do so.
 *
 * If you have an OEM-mandated branding requirement that cannot be
 * satisfied simply by defining PRODUCT_NAME and PRODUCT_SHORT_NAME,
 * please contact us.
 *
 * [ Including an ASCII NUL in PRODUCT_NAME is considered to be
 *   bypassing the spirit of this request! ]
 */
init_message:
	.ascii	"\n"
	.ascii	PRODUCT_NAME
	.ascii	"\n"
	.ascii	PRODUCT_SHORT_NAME
	.ascii	" ("
	.ascii	PRODUCT_URI
	.asciz	")"
	.size	init_message, . - init_message
.ifeqs	BUSTYPE, "PCIR"
init_message_pci:
	.asciz	" PCI"
	.size	init_message_pci, . - init_message_pci
.endif	/* PCIR */
init_message_pnp:
	.asciz	" PnP"
	.size	init_message_pnp, . - init_message_pnp
init_message_pmm:
	.asciz	" PMM"
	.size	init_message_pmm, . - init_message_pmm
init_message_int19:
	.asciz	" INT19"
	.size	init_message_int19, . - init_message_int19
init_message_prompt:
	.asciz	"\nPress Ctrl-B to configure "
	.size	init_message_prompt, . - init_message_prompt
init_message_dots:
	.asciz	"..."
	.size	init_message_dots, . - init_message_dots
init_message_done:
	.asciz	"\n\n"
	.size	init_message_done, . - init_message_done

/* PCI bus:dev.fn
 *
 */
.ifeqs	BUSTYPE, "PCIR"
init_pci_busdevfn:
	.word	0
	.size	init_pci_busdevfn, . - init_pci_busdevfn
.endif	/* PCIR */

/* Image source area
 *
 * May be either zero (indicating to use option ROM space as source),
 * or within a PMM-allocated block.
 */
	.globl	image_source
image_source:
	.long	0
	.size	image_source, . - image_source

/* Additional image source size (in 512-byte sectors)
 *
 */
extra_size:
	.word	0
	.size	extra_size, . - extra_size

/* Temporary decompression area
 *
 * May be either zero (indicating to use default decompression area in
 * high memory), or within a PMM-allocated block.
 */
	.globl	decompress_to
decompress_to:
	.long	0
	.size	decompress_to, . - decompress_to

/* Boot Execution Vector entry point
 *
 * Called by the PnP BIOS when it wants to boot us.
 */
bev_entry:
	orl	$0xffffffff, %ebp	/* Allow arbitrary relocation */
	pushw	%cs
	call	exec
	lret
	.size	bev_entry, . - bev_entry

/* INT19 entry point
 *
 * Called via the hooked INT 19 if we detected a non-PnP BIOS.  We
 * attempt to return via the original INT 19 vector (if we were able
 * to store it).
 */
int19_entry:
	pushw	%cs
	popw	%ds
	/* Prompt user to press B to boot */
	movw	$int19_message_prompt, %si
	xorw	%di, %di
	call	print_message
	movw	$prodstr, %si
	call	print_message
	movw	$int19_message_dots, %si
	call	print_message
	movw	$0xdf4e, %bx
	call	wait_for_key
	pushf
	xorw	%di, %di
	call	print_kill_line
	movw	$int19_message_done, %si
	call	print_message
	popf
	jz	1f
	/* Leave keypress in buffer and start iPXE.  The keypress will
	 * cause the usual initial Ctrl-B prompt to be skipped.
	 */
	orl	$0xffffffff, %ebp	/* Allow arbitrary relocation */
	pushw	%cs
	call	exec
1:	/* Try to call original INT 19 vector */
	movl	%cs:orig_int19, %eax
	testl	%eax, %eax
	je	2f
	ljmp	*%cs:orig_int19
2:	/* No chained vector: issue INT 18 as a last resort */
	int	$0x18
	.size	int19_entry, . - int19_entry
orig_int19:
	.long	0
	.size	orig_int19, . - orig_int19

int19_message_prompt:
	.asciz	"Press N to skip booting from "
	.size	int19_message_prompt, . - int19_message_prompt
int19_message_dots:
	.asciz	"..."
	.size	int19_message_dots, . - int19_message_dots
int19_message_done:
	.asciz	"\n\n"
	.size	int19_message_done, . - int19_message_done
	
/* Execute as a boot device
 *
 */
exec:	/* Set %ds = %cs */
	pushw	%cs
	popw	%ds

	/* Print message as soon as possible */
	movw	$prodstr, %si
	xorw	%di, %di
	call	print_message
	movw	$exec_message_pre_install, %si
	call	print_message

	/* Store magic word on BIOS stack and remember BIOS %ss:sp */
	pushl	$STACK_MAGIC
	movw	%ss, %cx
	movw	%sp, %dx

	/* Obtain a reasonably-sized temporary stack */
	xorw	%bx, %bx
	movw	%bx, %ss
	movw	$0x7c00, %sp

	/* Install iPXE */
	call	alloc_basemem
	movl	image_source, %esi
	movl	decompress_to, %edi
	call	install_prealloc

	/* Print message indicating successful installation */
	movw	$exec_message_post_install, %si
	xorw	%di, %di
	call	print_message

	/* Set up real-mode stack */
	movw	%bx, %ss
	movw	$_estack16, %sp

	/* Jump to .text16 segment */
	pushw	%ax
	pushw	$1f
	lret
	.section ".text16", "awx", @progbits
1:
	/* Retrieve PCI bus:dev.fn, if applicable */
.ifeqs	BUSTYPE, "PCIR"
	movw	init_pci_busdevfn, %ax
.endif

	/* Set up %ds for access to .data16 */
	movw	%bx, %ds

	/* Store PCI bus:dev.fn, if applicable */
.ifeqs	BUSTYPE, "PCIR"
#ifdef AUTOBOOT_ROM_FILTER
	movw	%ax, autoboot_busdevfn
#endif /* AUTOBOOT_ROM_FILTER */
.endif

	/* Call main() */
	pushl	$main
	pushw	%cs
	call	prot_call
	popl	%eax /* discard */

	/* Set up flat real mode for return to BIOS */
	call	flatten_real_mode

	/* Uninstall iPXE */
	call	uninstall

	/* Restore BIOS stack */
	movw	%cx, %ss
	movw	%dx, %sp

	/* Check magic word on BIOS stack */
	popl	%eax
	cmpl	$STACK_MAGIC, %eax
	jne	1f
	/* BIOS stack OK: return to caller */
	lret
1:	/* BIOS stack corrupt: use INT 18 */
	int	$0x18
	.previous

exec_message_pre_install:
	.asciz	" starting execution..."
	.size exec_message_pre_install, . - exec_message_pre_install
exec_message_post_install:
	.asciz	"ok\n"
	.size exec_message_post_install, . - exec_message_post_install

/* Wait for key press specified by %bl (masked by %bh)
 *
 * Used by init and INT19 code when prompting user.  If the specified
 * key is pressed, it is left in the keyboard buffer.
 *
 * Returns with ZF set iff specified key is pressed.
 */
wait_for_key:
	/* Preserve registers */
	pushw	%cx
	pushw	%ax
1:	/* Empty the keyboard buffer before waiting for input */
	movb	$0x01, %ah
	int	$0x16
	jz	2f
	xorw	%ax, %ax
	int	$0x16
	jmp	1b
2:	/* Wait for a key press */
	movw	$ROM_BANNER_TIMEOUT_TICKS, %cx
3:	decw	%cx
	js	99f		/* Exit with ZF clear */
	/* Wait for timer tick to be updated */
	call	wait_for_tick
	/* Check to see if a key was pressed */
	movb	$0x01, %ah
	int	$0x16
	jz	3b
	/* Check to see if key was the specified key */
	andb	%bh, %al
	cmpb	%al, %bl
	je	99f		/* Exit with ZF set */
	/* Not the specified key: remove from buffer and stop waiting */
	pushfw
	xorw	%ax, %ax
	int	$0x16
	popfw			/* Exit with ZF clear */
99:	/* Restore registers and return */
	popw	%ax
	popw	%cx
	ret
	.size wait_for_key, . - wait_for_key

/* Wait for timer tick
 *
 * Used by wait_for_key
 */
wait_for_tick:
	pushl	%eax
	pushw	%fs
	movw	$0x40, %ax
	movw	%ax, %fs
	movl	%fs:(0x6c), %eax
1:	pushf
	sti
	hlt
	popf
	cmpl	%fs:(0x6c), %eax
	je	1b
	popw	%fs
	popl	%eax
	ret
	.size wait_for_tick, . - wait_for_tick

/* Drag in objects via _rom_start */
REQUIRING_SYMBOL ( _rom_start )

/* Drag in ROM configuration */
REQUIRE_OBJECT ( config_romprefix )
