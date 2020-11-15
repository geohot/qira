// Rom layout and bios assembler to C interface.
//
// Copyright (C) 2009-2013  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.


#include "asm-offsets.h" // BREGS_*
#include "config.h" // CONFIG_*
#include "entryfuncs.S" // ENTRY_*


/****************************************************************
 * Rom Header
 ****************************************************************/

        .section .rom.header
        .code16
        .global _rom_header, _rom_header_size, _rom_header_checksum
_rom_header:
        .word 0xaa55
_rom_header_size:
        .byte 0
_rom_header_entry:
        jmp _optionrom_entry
_rom_header_checksum:
        .byte 0
_rom_header_other:
        .space 17
_rom_header_pcidata:
#if CONFIG_VGA_PCI == 1
        .word rom_pci_data
#else
        .word 0
#endif
_rom_header_pnpdata:
        .word 0
_rom_header_other2:
        .word 0
_rom_header_signature:
        .asciz "IBM"


/****************************************************************
 * Entry points
 ****************************************************************/

        // This macro implements a call while avoiding instructions
        // that old versions of x86emu have problems with.
        .macro VGA_CALLL cfunc
#if CONFIG_VGA_FIXUP_ASM
        pushw %ax
        callw \cfunc
#else
        calll \cfunc
#endif
        .endm

        // This macro is the same as ENTRY_ARG except VGA_CALLL is used.
        .macro ENTRY_ARG_VGA cfunc
        cli
        cld
        PUSHBREGS
        movw %ss, %ax           // Move %ss to %ds
        movw %ax, %ds
        movl %esp, %ebx         // Backup %esp, then zero high bits
        movzwl %sp, %esp
        movl %esp, %eax         // First arg is pointer to struct bregs
        VGA_CALLL \cfunc
        movl %ebx, %esp         // Restore %esp (including high bits)
        POPBREGS
        .endm

        DECLFUNC entry_104f05
entry_104f05:
        ENTRY_ARG_VGA vbe_104f05
        lretw

        DECLFUNC _optionrom_entry
_optionrom_entry:
        ENTRY_ARG_VGA vga_post
        lretw

        DECLFUNC entry_10
entry_10:
        ENTRY_ARG_VGA handle_10
        iretw

        // Entry point using extra stack
        DECLFUNC entry_10_extrastack
entry_10_extrastack:
        cli
        cld
        pushw %ds               // Set %ds:%eax to space on ExtraStack
        pushl %eax
        movw %cs:ExtraStackSeg, %ds
        movl $(CONFIG_VGA_EXTRA_STACK_SIZE-PUSHBREGS_size-16), %eax
        SAVEBREGS_POP_DSEAX     // Save registers on extra stack
        movl %esp, PUSHBREGS_size+8(%eax)
        movw %ss, PUSHBREGS_size+12(%eax)
        popl BREGS_code(%eax)
        popw BREGS_flags(%eax)

        movw %ds, %dx           // Setup %ss/%esp and call function
        movw %dx, %ss
        movl %eax, %esp
        VGA_CALLL handle_10

        movl %esp, %eax         // Restore registers and return
        movw PUSHBREGS_size+12(%eax), %ss
        movl PUSHBREGS_size+8(%eax), %esp
        popl %edx
        popw %dx
        pushw BREGS_flags(%eax)
        pushl BREGS_code(%eax)
        RESTOREBREGS_DSEAX
        iretw

        // Timer irq handling
        DECLFUNC entry_timer_hook
entry_timer_hook:
        ENTRY handle_timer_hook
        ljmpw *%cs:Timer_Hook_Resume

        // Timer irq handling on extra stack
        DECLFUNC entry_timer_hook_extrastack
entry_timer_hook_extrastack:
        cli
        cld
        pushw %ds               // Set %ds:%eax to space on ExtraStack
        pushl %eax
        movw %cs:ExtraStackSeg, %ds
        movl $(CONFIG_VGA_EXTRA_STACK_SIZE-PUSHBREGS_size-8), %eax
        SAVEBREGS_POP_DSEAX
        movl %esp, PUSHBREGS_size(%eax)
        movw %ss, PUSHBREGS_size+4(%eax)

        movw %ds, %dx           // Setup %ss/%esp and call function
        movw %dx, %ss
        movl %eax, %esp
        calll handle_timer_hook

        movl %esp, %eax         // Restore registers and return
        movw PUSHBREGS_size+4(%eax), %ss
        movl PUSHBREGS_size(%eax), %esp
        RESTOREBREGS_DSEAX
        ljmpw *%cs:Timer_Hook_Resume
