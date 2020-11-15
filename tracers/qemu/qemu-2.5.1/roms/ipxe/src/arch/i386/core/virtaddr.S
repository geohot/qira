/*
 * Functions to support the virtual addressing method of relocation
 * that Etherboot uses.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )

#include "librm.h"
		
	.arch i386
	.text
	.code32
	
/****************************************************************************
 * _virt_to_phys (virtual addressing)
 *
 * Switch from virtual to flat physical addresses.  %esp is adjusted
 * to a physical value.  Segment registers are set to flat physical
 * selectors.  All other registers are preserved.  Flags are
 * preserved.
 *
 * Parameters: none
 * Returns: none
 ****************************************************************************
 */
	.globl _virt_to_phys
_virt_to_phys:
	/* Preserve registers and flags */
	pushfl
	pushl	%eax
	pushl	%ebp

	/* Change return address to a physical address */
	movl	virt_offset, %ebp
	addl	%ebp, 12(%esp)

	/* Switch to physical code segment */
	cli
	pushl	$PHYSICAL_CS
	leal	1f(%ebp), %eax
	pushl	%eax
	lret
1:
	/* Reload other segment registers and adjust %esp */
	movl	$PHYSICAL_DS, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs
	movl	%eax, %ss
	addl	%ebp, %esp

	/* Restore registers and flags, and return */
	popl	%ebp
	popl	%eax
	popfl
	ret

/****************************************************************************
 * _phys_to_virt (flat physical addressing)
 *
 * Switch from flat physical to virtual addresses.  %esp is adjusted
 * to a virtual value.  Segment registers are set to virtual
 * selectors.  All other registers are preserved.  Flags are
 * preserved.
 *
 * Parameters: none
 * Returns: none
 ****************************************************************************
 */
	.globl _phys_to_virt
_phys_to_virt:
	/* Preserve registers and flags */
	pushfl
	pushl	%eax
	pushl	%ebp

	/* Switch to virtual code segment */
	cli
	ljmp	$VIRTUAL_CS, $1f
1:
	/* Reload data segment registers */
	movl	$VIRTUAL_DS, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs

	/* Reload stack segment and adjust %esp */
	movl	virt_offset, %ebp
	movl	%eax, %ss
	subl	%ebp, %esp

	/* Change the return address to a virtual address */
	subl	%ebp, 12(%esp)

	/* Restore registers and flags, and return */
	popl	%ebp
	popl	%eax
	popfl
	ret

/****************************************************************************
 * _intr_to_virt (virtual code segment, virtual or physical stack segment)
 *
 * Switch from virtual code segment with either a virtual or physical
 * stack segment to using virtual addressing.  %esp is adjusted if
 * necessary to a virtual value.  Segment registers are set to virtual
 * selectors.  All other registers are preserved.  Flags are
 * preserved.
 *
 * Parameters: none
 * Returns: none
 ****************************************************************************
 */
	.globl _intr_to_virt
_intr_to_virt:
	/* Preserve registers and flags */
	pushfl
	pushl	%eax
	pushl	%ebp

	/* Check whether stack segment is physical or virtual */
	movl	%ss, %eax
	cmpw	$VIRTUAL_DS, %ax
	movl	$VIRTUAL_DS, %eax

	/* Reload data segment registers */
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs

	/* Reload stack segment and adjust %esp if necessary */
	je	1f
	movl	virt_offset, %ebp
	movl	%eax, %ss
	subl	%ebp, %esp
1:
	/* Restore registers and flags, and return */
	popl	%ebp
	popl	%eax
	popfl
	ret
