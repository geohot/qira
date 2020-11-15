/*
 * Copyright (C) 2008 Daniel Verkamp <daniel@drv.nu>.
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
 */

/**
 * @file SYSLINUX COM32 helpers
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <realmode.h>
#include <comboot.h>
#include <assert.h>
#include <ipxe/uaccess.h>

static com32sys_t __bss16 ( com32_regs );
#define com32_regs __use_data16 ( com32_regs )

static uint8_t __bss16 ( com32_int_vector );
#define com32_int_vector __use_data16 ( com32_int_vector )

static uint32_t __bss16 ( com32_farcall_proc );
#define com32_farcall_proc __use_data16 ( com32_farcall_proc )

uint16_t __bss16 ( com32_saved_sp );

/**
 * Interrupt call helper
 */
void __asmcall com32_intcall ( uint8_t interrupt, physaddr_t inregs_phys, physaddr_t outregs_phys ) {

	memcpy_user ( virt_to_user( &com32_regs ), 0,
	              phys_to_user ( inregs_phys ), 0,
	              sizeof(com32sys_t) );

	com32_int_vector = interrupt;

	__asm__ __volatile__ (
		REAL_CODE ( /* Save all registers */
		            "pushal\n\t"
		            "pushw %%ds\n\t"
		            "pushw %%es\n\t"
		            "pushw %%fs\n\t"
		            "pushw %%gs\n\t"
		            /* Mask off unsafe flags */
		            "movl (com32_regs + 40), %%eax\n\t"
		            "andl $0x200cd7, %%eax\n\t"
		            "movl %%eax, (com32_regs + 40)\n\t"
		            /* Load com32_regs into the actual registers */
		            "movw %%sp, %%ss:(com32_saved_sp)\n\t"
		            "movw $com32_regs, %%sp\n\t"
		            "popw %%gs\n\t"
		            "popw %%fs\n\t"
		            "popw %%es\n\t"
		            "popw %%ds\n\t"
		            "popal\n\t"
		            "popfl\n\t"
		            "movw %%ss:(com32_saved_sp), %%sp\n\t"
		            /* patch INT instruction */
		            "pushw %%ax\n\t"
		            "movb %%ss:(com32_int_vector), %%al\n\t"
		            "movb %%al, %%cs:(com32_intcall_instr + 1)\n\t" 
		            /* perform a jump to avoid problems with cache
		             * consistency in self-modifying code on some CPUs (486)
		             */
		            "jmp 1f\n"
		            "1:\n\t"
		            "popw %%ax\n\t"
		            "com32_intcall_instr:\n\t"
		            /* INT instruction to be patched */
		            "int $0xFF\n\t"
		            /* Copy regs back to com32_regs */
		            "movw %%sp, %%ss:(com32_saved_sp)\n\t"
		            "movw $(com32_regs + 44), %%sp\n\t"
		            "pushfl\n\t"
		            "pushal\n\t"
		            "pushw %%ds\n\t"
		            "pushw %%es\n\t"
		            "pushw %%fs\n\t"
		            "pushw %%gs\n\t"
		            "movw %%ss:(com32_saved_sp), %%sp\n\t"
		            /* Restore registers */
		            "popw %%gs\n\t"
		            "popw %%fs\n\t"
		            "popw %%es\n\t"
		            "popw %%ds\n\t"
		            "popal\n\t")
		            : : );

	if ( outregs_phys ) {
		memcpy_user ( phys_to_user ( outregs_phys ), 0,
		              virt_to_user( &com32_regs ), 0, 
		              sizeof(com32sys_t) );
	}
}

/**
 * Farcall helper
 */
void __asmcall com32_farcall ( uint32_t proc, physaddr_t inregs_phys, physaddr_t outregs_phys ) {

	memcpy_user ( virt_to_user( &com32_regs ), 0,
	              phys_to_user ( inregs_phys ), 0,
	              sizeof(com32sys_t) );

	com32_farcall_proc = proc;

	__asm__ __volatile__ (
		REAL_CODE ( /* Save all registers */
		            "pushal\n\t"
		            "pushw %%ds\n\t"
		            "pushw %%es\n\t"
		            "pushw %%fs\n\t"
		            "pushw %%gs\n\t"
		            /* Mask off unsafe flags */
		            "movl (com32_regs + 40), %%eax\n\t"
		            "andl $0x200cd7, %%eax\n\t"
		            "movl %%eax, (com32_regs + 40)\n\t"
		            /* Load com32_regs into the actual registers */
		            "movw %%sp, %%ss:(com32_saved_sp)\n\t"
		            "movw $com32_regs, %%sp\n\t"
		            "popw %%gs\n\t"
		            "popw %%fs\n\t"
		            "popw %%es\n\t"
		            "popw %%ds\n\t"
		            "popal\n\t"
		            "popfl\n\t"
		            "movw %%ss:(com32_saved_sp), %%sp\n\t"
		            /* Call procedure */
		            "lcall *%%ss:(com32_farcall_proc)\n\t"
		            /* Copy regs back to com32_regs */
		            "movw %%sp, %%ss:(com32_saved_sp)\n\t"
		            "movw $(com32_regs + 44), %%sp\n\t"
		            "pushfl\n\t"
		            "pushal\n\t"
		            "pushw %%ds\n\t"
		            "pushw %%es\n\t"
		            "pushw %%fs\n\t"
		            "pushw %%gs\n\t"
		            "movw %%ss:(com32_saved_sp), %%sp\n\t"
		            /* Restore registers */
		            "popw %%gs\n\t"
		            "popw %%fs\n\t"
		            "popw %%es\n\t"
		            "popw %%ds\n\t"
		            "popal\n\t")
		            : : );

	if ( outregs_phys ) {
		memcpy_user ( phys_to_user ( outregs_phys ), 0,
		              virt_to_user( &com32_regs ), 0, 
		              sizeof(com32sys_t) );
	}
}

/**
 * CDECL farcall helper
 */
int __asmcall com32_cfarcall ( uint32_t proc, physaddr_t stack, size_t stacksz ) {
	int32_t eax;

	copy_user_to_rm_stack ( phys_to_user ( stack ), stacksz );
	com32_farcall_proc = proc;

	__asm__ __volatile__ (
		REAL_CODE ( "lcall *%%ss:(com32_farcall_proc)\n\t" )
		: "=a" (eax)
		: 
		: "ecx", "edx" );

	remove_user_from_rm_stack ( 0, stacksz );

	return eax;
}
