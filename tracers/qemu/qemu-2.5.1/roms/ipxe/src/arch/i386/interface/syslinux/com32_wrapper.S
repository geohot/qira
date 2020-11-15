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

FILE_LICENCE ( GPL2_OR_LATER )

	.text
	.arch i386
	.code32

	.globl com32_farcall_wrapper
com32_farcall_wrapper:

	movl $com32_farcall, %eax
	jmp com32_wrapper


	.globl com32_cfarcall_wrapper
com32_cfarcall_wrapper:

	movl $com32_cfarcall, %eax
	jmp com32_wrapper


	.globl com32_intcall_wrapper
com32_intcall_wrapper:

	movl $com32_intcall, %eax
	/*jmp com32_wrapper*/ /* fall through */

com32_wrapper:
	cli

	/* Switch to internal virtual address space */
	call _phys_to_virt

	mov %eax, (com32_helper_function)

	/* Save external COM32 stack pointer */
	movl %esp, (com32_external_esp)

	/* Copy arguments to caller-save registers */
	movl 12(%esp), %eax
	movl 8(%esp), %ecx
	movl 4(%esp), %edx

	/* Switch to internal stack */
	movl (com32_internal_esp), %esp

	/* Copy arguments to internal stack */
	pushl %eax
	pushl %ecx
	pushl %edx

	call *(com32_helper_function)

	/* Clean up stack */
	addl $12, %esp

	/* Save internal stack pointer and restore external stack pointer */
	movl %esp, (com32_internal_esp)
	movl (com32_external_esp), %esp

	/* Switch to external flat physical address space */
	call _virt_to_phys

	sti
	ret


	.data

/* Internal iPXE virtual address space %esp */
.globl com32_internal_esp
.lcomm com32_internal_esp, 4

/* External flat physical address space %esp */
.globl com32_external_esp
.lcomm com32_external_esp, 4

/* Function pointer of helper to call */
.lcomm com32_helper_function, 4
