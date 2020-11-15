/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * @file
 *
 * x86 bootsector image format
 *
 */

#include <errno.h>
#include <realmode.h>
#include <biosint.h>
#include <bootsector.h>
#include <ipxe/console.h>

/** Vector for storing original INT 18 handler
 *
 * We do not chain to this vector, so there is no need to place it in
 * .text16.
 */
static struct segoff int18_vector;

/** Vector for storing original INT 19 handler
 *
 * We do not chain to this vector, so there is no need to place it in
 * .text16.
 */
static struct segoff int19_vector;

/** Restart point for INT 18 or 19 */
extern void bootsector_exec_fail ( void );

/**
 * Jump to preloaded bootsector
 *
 * @v segment		Real-mode segment
 * @v offset		Real-mode offset
 * @v drive		Drive number to pass to boot sector
 * @ret rc		Return status code
 */
int call_bootsector ( unsigned int segment, unsigned int offset,
		      unsigned int drive ) {
	int discard_b, discard_D, discard_d;

	/* Reset console, since boot sector will probably use it */
	console_reset();

	DBG ( "Booting from boot sector at %04x:%04x\n", segment, offset );

	/* Hook INTs 18 and 19 to capture failure paths */
	hook_bios_interrupt ( 0x18, ( unsigned int ) bootsector_exec_fail,
			      &int18_vector );
	hook_bios_interrupt ( 0x19, ( unsigned int ) bootsector_exec_fail,
			      &int19_vector );

	/* Boot the loaded sector
	 *
	 * We assume that the boot sector may completely destroy our
	 * real-mode stack, so we preserve everything we need in
	 * static storage.
	 */
	__asm__ __volatile__ ( REAL_CODE ( /* Save return address off-stack */
					   "popw %%cs:saved_retaddr\n\t"
					   /* Save stack pointer */
					   "movw %%ss, %%ax\n\t"
					   "movw %%ax, %%cs:saved_ss\n\t"
					   "movw %%sp, %%cs:saved_sp\n\t"
					   /* Save frame pointer (gcc bug) */
					   "movl %%ebp, %%cs:saved_ebp\n\t"
					   /* Prepare jump to boot sector */
					   "pushw %%bx\n\t"
					   "pushw %%di\n\t"
					   /* Clear all registers */
					   "xorl %%eax, %%eax\n\t"
					   "xorl %%ebx, %%ebx\n\t"
					   "xorl %%ecx, %%ecx\n\t"
					   /* %edx contains drive number */
					   "xorl %%esi, %%esi\n\t"
					   "xorl %%edi, %%edi\n\t"
					   "xorl %%ebp, %%ebp\n\t"
					   "movw %%ax, %%ds\n\t"
					   "movw %%ax, %%es\n\t"
					   "movw %%ax, %%fs\n\t"
					   "movw %%ax, %%gs\n\t"
					   /* Jump to boot sector */
					   "sti\n\t"
					   "lret\n\t"
					   /* Preserved variables */
					   "\nsaved_ebp: .long 0\n\t"
					   "\nsaved_ss: .word 0\n\t"
					   "\nsaved_sp: .word 0\n\t"
					   "\nsaved_retaddr: .word 0\n\t"
					   /* Boot failure return point */
					   "\nbootsector_exec_fail:\n\t"
					   /* Restore frame pointer (gcc bug) */
					   "movl %%cs:saved_ebp, %%ebp\n\t"
					   /* Restore stack pointer */
					   "movw %%cs:saved_ss, %%ax\n\t"
					   "movw %%ax, %%ss\n\t"
					   "movw %%cs:saved_sp, %%sp\n\t"
					   /* Return via saved address */
					   "jmp *%%cs:saved_retaddr\n\t" )
			       : "=b" ( discard_b ), "=D" ( discard_D ),
			         "=d" ( discard_d )
			       : "b" ( segment ), "D" ( offset ),
			         "d" ( drive )
			       : "eax", "ecx", "esi" );

	DBG ( "Booted disk returned via INT 18 or 19\n" );

	/* Unhook INTs 18 and 19 */
	unhook_bios_interrupt ( 0x18, ( unsigned int ) bootsector_exec_fail,
				&int18_vector );
	unhook_bios_interrupt ( 0x19, ( unsigned int ) bootsector_exec_fail,
				&int19_vector );
	
	return -ECANCELED;
}
