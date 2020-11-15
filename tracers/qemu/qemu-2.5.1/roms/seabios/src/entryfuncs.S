// Macros for entering C code
//
// Copyright (C) 2008-2014  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.


/****************************************************************
 * Macros for save and restore of 'struct bregs' registers
 ****************************************************************/

#define PUSHBREGS_size 32

        // Save registers (matches struct bregs) to stack
        .macro PUSHBREGS
        pushl %eax
        pushl %ecx
        pushl %edx
        pushl %ebx
        pushl %ebp
        pushl %esi
        pushl %edi
        pushw %es
        pushw %ds
        .endm

        // Restore registers (from struct bregs) from stack
        .macro POPBREGS
        popw %ds
        popw %es
        popl %edi
        popl %esi
        popl %ebp
        popl %ebx
        popl %edx
        popl %ecx
        popl %eax
        .endm

        // Save registers to struct bregs at %ds:%eax.  The caller
        // should "pushw %ds ; pushl %eax" prior to calling - this macro
        // will pop them off.
        .macro SAVEBREGS_POP_DSEAX
        popl BREGS_eax(%eax)
        popw BREGS_ds(%eax)
        movl %edi, BREGS_edi(%eax)
        movl %esi, BREGS_esi(%eax)
        movl %ebp, BREGS_ebp(%eax)
        movl %ebx, BREGS_ebx(%eax)
        movl %edx, BREGS_edx(%eax)
        movl %ecx, BREGS_ecx(%eax)
        movw %es, BREGS_es(%eax)
        .endm

        // Restore registers from struct bregs at %ds:%eax
        .macro RESTOREBREGS_DSEAX
        movl BREGS_edi(%eax), %edi
        movl BREGS_esi(%eax), %esi
        movl BREGS_ebp(%eax), %ebp
        movl BREGS_ebx(%eax), %ebx
        movl BREGS_edx(%eax), %edx
        movl BREGS_ecx(%eax), %ecx
        movw BREGS_es(%eax), %es
        pushl BREGS_eax(%eax)
        movw BREGS_ds(%eax), %ds
        popl %eax
        .endm


/****************************************************************
 * Entry macros
 ****************************************************************/

        // Call a C function - this does the minimal work necessary to
        // call into C.  It sets up %ds, backs up %es, and backs up
        // those registers that are call clobbered by the C compiler.
        .macro ENTRY cfunc
        cli         // In case something far-calls instead of using "int"
        cld
        pushl %eax              // Save registers clobbered by C code
        pushl %ecx
        pushl %edx
        pushw %es
        pushw %ds
        movw %ss, %ax           // Move %ss to %ds
        movw %ax, %ds
        pushl %esp              // Backup %esp, then clear high bits
        movzwl %sp, %esp
        calll \cfunc
        popl %esp               // Restore %esp (including high bits)
        popw %ds                // Restore registers saved above
        popw %es
        popl %edx
        popl %ecx
        popl %eax
        .endm

        // Call a C function with current register list as an
        // argument.  This backs up the registers and sets %eax
        // to point to the backup.  On return, the registers are
        // restored from the structure.
        .macro ENTRY_ARG cfunc
        cli
        cld
        PUSHBREGS
        movw %ss, %ax           // Move %ss to %ds
        movw %ax, %ds
        movl %esp, %ebx         // Backup %esp, then zero high bits
        movzwl %sp, %esp
        movl %esp, %eax         // First arg is pointer to struct bregs
        calll \cfunc
        movl %ebx, %esp         // Restore %esp (including high bits)
        POPBREGS
        .endm

        // As above, but get calling function from stack.
        .macro ENTRY_ARG_ST
        cli
        cld
        pushl %ecx
        pushl %edx
        pushl %ebx
        pushl %ebp
        pushl %esi
        pushl %edi
        pushw %es
        pushw %ds
        movw %ss, %cx           // Move %ss to %ds
        movw %cx, %ds
        movl %esp, %ebx         // Backup %esp, then zero high bits
        movzwl %sp, %esp
        movl 28(%esp), %ecx     // Get calling function
        movl %eax, 28(%esp)     // Save %eax
        movl %esp, %eax         // First arg is pointer to struct bregs
        calll *%ecx
        movl %ebx, %esp         // Restore %esp (including high bits)
        POPBREGS
        .endm

        // Same as ENTRY_ARG, but don't mangle %esp
        .macro ENTRY_ARG_ESP cfunc
        cli
        cld
        PUSHBREGS
        movw %ss, %ax           // Move %ss to %ds
        movw %ax, %ds
        movl %esp, %eax         // First arg is pointer to struct bregs
        calll \cfunc
        POPBREGS
        .endm

        // Reset stack, transition to 32bit mode, and call a C function.
        .macro ENTRY_INTO32 cfunc
        xorw %dx, %dx
        movw %dx, %ss
        movl $ BUILD_STACK_ADDR , %esp
        movl $ \cfunc , %edx
        jmp transition32
        .endm

        // Declare a function
        .macro DECLFUNC func
        .section .text.asm.\func
        .global \func
        .endm
