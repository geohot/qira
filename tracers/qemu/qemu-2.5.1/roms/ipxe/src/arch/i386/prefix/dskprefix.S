/* NOTE: this boot sector contains instructions that need at least an 80186.
 * Yes, as86 has a bug somewhere in the valid instruction set checks.
 *
 */

/*	floppyload.S Copyright (C) 1991, 1992 Linus Torvalds
 *	modified by Drew Eckhardt
 *	modified by Bruce Evans (bde)
 *
 * floppyprefix.S is loaded at 0x0000:0x7c00 by the bios-startup routines.
 *
 * It then loads the system at SYSSEG<<4, using BIOS interrupts.
 *
 * The loader has been made as simple as possible, and continuous read errors
 * will result in a unbreakable loop. Reboot by hand. It loads pretty fast by
 * getting whole tracks at a time whenever possible.
 */

FILE_LICENCE ( GPL2_ONLY )

.equ	BOOTSEG, 0x07C0			/* original address of boot-sector */

.equ	SYSSEG, 0x1000			/* system loaded at SYSSEG<<4 */

	.org	0
	.arch i386
	.text
	.section ".prefix", "ax", @progbits
	.code16
	.globl	_dsk_start
_dsk_start:

	jmp	$BOOTSEG, $go		/* reload cs:ip to match relocation addr */
go: 
	movw	$0x2000-12, %di		/* 0x2000 is arbitrary value >= length */
					/* of bootsect + room for stack + 12 for */
					/* saved disk parm block */

	movw	$BOOTSEG, %ax
	movw	%ax,%ds
	movw	%ax,%es
	movw	%ax,%ss			/* put stack at BOOTSEG:0x4000-12. */
	movw	%di,%sp

/* Many BIOS's default disk parameter tables will not recognize multi-sector
 * reads beyond the maximum sector number specified in the default diskette
 * parameter tables - this may mean 7 sectors in some cases.
 *
 * Since single sector reads are slow and out of the question, we must take care
 * of this by creating new parameter tables (for the first disk) in RAM.  We
 * will set the maximum sector count to 36 - the most we will encounter on an
 * ED 2.88.  High doesn't hurt.	Low does.
 *
 * Segments are as follows: ds=es=ss=cs - BOOTSEG
 */

	xorw	%cx,%cx
	movw	%cx,%es			/* access segment 0 */
	movw	$0x78, %bx		/* 0:bx is parameter table address */
	pushw	%ds			/* save ds */
/* 0:bx is parameter table address */
	ldsw	%es:(%bx),%si		/* loads ds and si */

	movw	%ax,%es			/* ax is BOOTSECT (loaded above) */
	movb	$6, %cl			/* copy 12 bytes */
	cld
	pushw	%di			/* keep a copy for later */
	rep
	movsw				/* ds:si is source, es:di is dest */
	popw	%di

	movb	$36,%es:4(%di)

	movw	%cx,%ds			/* access segment 0 */
	xchgw	%di,(%bx)
	movw	%es,%si
	xchgw	%si,2(%bx)
	popw	%ds			/* restore ds */
	movw	%di, dpoff		/* save old parameters */
	movw	%si, dpseg		/* to restore just before finishing */
	pushw	%ds
	popw	%es			/* reload es */

/* Note that es is already set up.  Also cx is 0 from rep movsw above. */

	xorb	%ah,%ah			/* reset FDC */
	xorb	%dl,%dl
	int	$0x13

/* Get disk drive parameters, specifically number of sectors/track.
 *
 * It seems that there is no BIOS call to get the number of sectors.  Guess
 * 36 sectors if sector 36 can be read, 18 sectors if sector 18 can be read,
 * 15 if sector 15 can be read.	Otherwise guess 9.
 */

	movw	$disksizes, %si		/* table of sizes to try */

probe_loop: 
	lodsb
	cbtw				/* extend to word */
	movw	%ax, sectors
	cmpw	$disksizes+4, %si
	jae	got_sectors		/* if all else fails, try 9 */
	xchgw	%cx,%ax			/* cx = track and sector */
	xorw	%dx,%dx			/* drive 0, head 0 */
	movw	$0x0200, %bx		/* address after boot sector */
					/*   (512 bytes from origin, es = cs) */
	movw	$0x0201, %ax		/* service 2, 1 sector */
	int	$0x13
	jc	probe_loop		/* try next value */

got_sectors: 
	movw	$msg1end-msg1, %cx
	movw	$msg1, %si
	call	print_str

/* ok, we've written the Loading... message, now we want to load the system */

	movw	$SYSSEG, %ax
	movw	%ax,%es			/* segment of SYSSEG<<4 */
	pushw	%es
	call	read_it

/* This turns off the floppy drive motor, so that we enter the kernel in a
 * known state, and don't have to worry about it later.
 */
	movw	$0x3f2, %dx
	xorb	%al,%al
	outb	%al,%dx

	call	print_nl
	pop	%es			/* = SYSSEG */

/* Restore original disk parameters */
	movw	$0x78, %bx
	movw	dpoff, %di
	movw	dpseg, %si
	xorw	%ax,%ax
	movw	%ax,%ds
	movw	%di,(%bx)
	movw	%si,2(%bx)

	/* Everything now loaded.  %es = SYSSEG, so %es:0000 points to
	 * start of loaded image.
	 */

	/* Jump to loaded copy */
	ljmp	$SYSSEG, $start_runtime

endseg:	.word SYSSEG
	.section ".zinfo.fixup", "a", @progbits	/* Compressor fixups */
	.ascii	"ADDW"
	.long	endseg
	.long	16
	.long	0
	.previous

/* This routine loads the system at address SYSSEG<<4, making sure no 64kB
 * boundaries are crossed. We try to load it as fast as possible, loading whole
 * tracks whenever we can.
 *
 * in:	es - starting address segment (normally SYSSEG)
 */
read_it: 
	movw	$0,sread		/* load whole image including prefix */
	movw	%es,%ax
	testw	$0x0fff, %ax
die:	jne	die			/* es must be at 64kB boundary */
	xorw	%bx,%bx			/* bx is starting address within segment */
rp_read: 
	movw	%es,%ax
	movw	%bx,%dx
	movb	$4, %cl
	shrw	%cl,%dx			/* bx is always divisible by 16 */
	addw	%dx,%ax
	cmpw	endseg, %ax	/* have we loaded all yet? */
	jb	ok1_read
	ret
ok1_read: 
	movw	sectors, %ax
	subw	sread, %ax
	movw	%ax,%cx
	shlw	$9, %cx
	addw	%bx,%cx
	jnc	ok2_read
	je	ok2_read
	xorw	%ax,%ax
	subw	%bx,%ax
	shrw	$9, %ax
ok2_read: 
	call	read_track
	movw	%ax,%cx
	addw	sread, %ax
	cmpw	sectors, %ax
	jne	ok3_read
	movw	$1, %ax
	subw	head, %ax
	jne	ok4_read
	incw	track
ok4_read: 
	movw	%ax, head
	xorw	%ax,%ax
ok3_read: 
	movw	%ax, sread
	shlw	$9, %cx
	addw	%cx,%bx
	jnc	rp_read
	movw	%es,%ax
	addb	$0x10, %ah
	movw	%ax,%es
	xorw	%bx,%bx
	jmp	rp_read

read_track: 
	pusha
	pushw	%ax
	pushw	%bx
	pushw	%bp			/* just in case the BIOS is buggy */
	movw	$0x0e2e, %ax		/* 0x2e = . */
	movw	$0x0007, %bx
	int	$0x10
	popw	%bp
	popw	%bx
	popw	%ax

	movw	track, %dx
	movw	sread, %cx
	incw	%cx
	movb	%dl,%ch
	movw	head, %dx
	movb	%dl,%dh
	andw	$0x0100, %dx
	movb	$2, %ah

	pushw	%dx			/* save for error dump */
	pushw	%cx
	pushw	%bx
	pushw	%ax

	int	$0x13
	jc	bad_rt
	addw	$8, %sp
	popa
	ret

bad_rt: pushw	%ax			/* save error code */
	call	print_all		/* ah = error, al = read */

	xorb	%ah,%ah
	xorb	%dl,%dl
	int	$0x13

	addw	$10, %sp
	popa
	jmp	read_track

/* print_all is for debugging purposes.	It will print out all of the registers.
 * The assumption is that this is called from a routine, with a stack frame like
 *	dx
 *	cx
 *	bx
 *	ax
 *	error
 *	ret <- sp
 */

print_all: 
	call	print_nl		/* nl for readability */
	movw	$5, %cx			/* error code + 4 registers */
	movw	%sp,%bp

print_loop: 
	pushw	%cx			/* save count left */

	cmpb	$5, %cl
	jae	no_reg			/* see if register name is needed */

	movw	$0x0007, %bx		/* page 0, attribute 7 (normal) */
	movw	$0xe05+0x41-1, %ax
	subb	%cl,%al
	int	$0x10

	movb	$0x58, %al		/* 'X' */
	int	$0x10

	movb	$0x3A, %al		/* ':' */
	int	$0x10

no_reg: 
	addw	$2, %bp			/* next register */
	call	print_hex		/* print it */
	movb	$0x20, %al		/* print a space */
	int	$0x10
	popw	%cx
	loop	print_loop
	call	print_nl		/* nl for readability */
	ret

print_str: 
	movw	$0x0007, %bx		/* page 0, attribute 7 (normal) */
	movb	$0x0e, %ah		/* write char, tty mode */
prloop: 
	lodsb
	int	$0x10
	loop	prloop
	ret

print_nl: 
	movw	$0x0007, %bx		/* page 0, attribute 7 (normal) */
	movw	$0xe0d, %ax		/* CR */
	int	$0x10
	movb	$0xa, %al		/* LF */
	int	$0x10
	ret

/* print_hex prints the word pointed to by ss:bp in hexadecimal. */

print_hex: 
	movw	(%bp),%dx		/* load word into dx */
	movb	$4, %cl
	movb	$0x0e, %ah		/* write char, tty mode */
	movw	$0x0007, %bx		/* page 0, attribute 7 (normal) */
	call	print_digit
	call	print_digit
	call	print_digit
/* fall through */
print_digit: 
	rol	%cl,%dx			/* rotate so that lowest 4 bits are used */
	movb	$0x0f, %al		/* mask for nybble */
	andb	%dl,%al
	addb	$0x90, %al		/* convert al to ascii hex (four instructions) */
	daa
	adcb	$0x40, %al
	daa
	int	$0x10
	ret

sread:	.word 0				/* sectors read of current track */
head:	.word 0				/* current head */
track:	.word 0				/* current track */

sectors: 
	.word 0

dpseg:	.word 0
dpoff:	.word 0

disksizes: 
	.byte 36,18,15,9

msg1: 
	.ascii "Loading ROM image"
msg1end: 

	.org 510, 0
	.word 0xAA55

start_runtime:
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

