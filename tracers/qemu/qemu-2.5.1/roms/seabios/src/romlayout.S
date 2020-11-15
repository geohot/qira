// Rom layout and bios assembler to C interface.
//
// Copyright (C) 2008-2012  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2002  MandrakeSoft S.A.
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "asm-offsets.h" // BREGS_*
#include "config.h" // CONFIG_*
#include "entryfuncs.S" // ENTRY_*
#include "hw/rtc.h" // CMOS_RESET_CODE
#include "x86.h" // CR0_*

        .code16


/****************************************************************
 * 16bit / 32bit call trampolines
 ****************************************************************/

// Place CPU into 32bit mode from 16bit mode.
// %edx = return location (in 32bit mode)
// Clobbers: ecx, flags, segment registers, cr0, idt/gdt
        DECLFUNC transition32
transition32_nmi_off:
        // transition32 when NMI and A20 are already initialized
        movl %eax, %ecx
        jmp 1f
transition32:
        movl %eax, %ecx

        // Disable irqs (and clear direction flag)
        cli
        cld

        // Disable nmi
        movl $CMOS_RESET_CODE|NMI_DISABLE_BIT, %eax
        outb %al, $PORT_CMOS_INDEX
        inb $PORT_CMOS_DATA, %al

        // enable a20
        inb $PORT_A20, %al
        orb $A20_ENABLE_BIT, %al
        outb %al, $PORT_A20

        // Set segment descriptors
1:      lidtw %cs:pmode_IDT_info
        lgdtw %cs:rombios32_gdt_48

        // Enable protected mode
        movl %cr0, %eax
        orl $CR0_PE, %eax
        movl %eax, %cr0

        // start 32bit protected mode code
        ljmpl $SEG32_MODE32_CS, $(BUILD_BIOS_ADDR + 2f)

        .code32
        // init data segments
2:      movl $SEG32_MODE32_DS, %eax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %ss
        movw %ax, %fs
        movw %ax, %gs

        movl %ecx, %eax
        jmpl *%edx
        .code16

// Place CPU into 16bit mode from 32bit mode.
// %edx = return location (in 16bit mode)
// Clobbers: ecx, flags, segment registers, cr0, idt/gdt
        DECLFUNC transition16
        .global transition16big
        .code32
transition16:
        movl %eax, %ecx

        // restore data segment limits to 0xffff
        movl $SEG32_MODE16_DS, %eax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %ss
        movw %ax, %fs
        movw %ax, %gs

#if CONFIG_DISABLE_A20
        // disable a20
        inb $PORT_A20, %al
        andb $~A20_ENABLE_BIT, %al
        outb %al, $PORT_A20
#endif

        // Jump to 16bit mode
        ljmpw $SEG32_MODE16_CS, $1f

transition16big:
        movl %eax, %ecx

        movl $SEG32_MODE16BIG_DS, %eax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %ss
        movw %ax, %fs
        movw %ax, %gs

        ljmpw $SEG32_MODE16BIG_CS, $1f

        .code16
1:
        // Disable protected mode
        movl %cr0, %eax
        andl $~CR0_PE, %eax
        movl %eax, %cr0

        // far jump to flush CPU queue after transition to real mode
        ljmpw $SEG_BIOS, $2f

2:
        // restore IDT to normal real-mode defaults
        lidtw %cs:rmode_IDT_info

        // Clear segment registers
        xorw %ax, %ax
        movw %ax, %fs
        movw %ax, %gs
        movw %ax, %es
        movw %ax, %ds
        movw %ax, %ss  // Assume stack is in segment 0

        movl %ecx, %eax
        jmpl *%edx


/****************************************************************
 * External calling trampolines
 ****************************************************************/

// Far call a 16bit function from 16bit mode with a specified cpu register state
// %eax = address of struct bregs, %edx = segment of struct bregs
// Clobbers: %e[bc]x, %e[ds]i, flags
        DECLFUNC __farcall16
__farcall16:
        // Save %edx/%eax, %ebp
        pushl %ebp
        pushl %eax
        pushl %edx

        // Setup for iretw call
        movl %edx, %ds
        pushw %cs
        pushw $1f                       // return point
        pushw BREGS_flags(%eax)         // flags
        pushl BREGS_code(%eax)          // CS:IP

        // Load calling registers and invoke call
        RESTOREBREGS_DSEAX
        iretw                           // XXX - just do a lcalll
1:
        // Store flags, es, eax
        pushfw
        cli
        cld
        pushw %ds
        pushl %eax
        movw 0x08(%esp), %ds
        movl 0x0c(%esp), %eax
        SAVEBREGS_POP_DSEAX
        popw BREGS_flags(%eax)
        movw %ss, %cx
        movw %cx, %ds                   // Restore %ds == %ss

        // Remove %edx/%eax, restore %ebp
        popl %edx
        popl %eax
        popl %ebp

        retl

// IRQ trampolines
        .macro IRQ_TRAMPOLINE num
        DECLFUNC irq_trampoline_0x\num
        irq_trampoline_0x\num :
        int $0x\num
        lretw
        .endm

        IRQ_TRAMPOLINE 02
        IRQ_TRAMPOLINE 10
        IRQ_TRAMPOLINE 13
        IRQ_TRAMPOLINE 15
        IRQ_TRAMPOLINE 16
        IRQ_TRAMPOLINE 18
        IRQ_TRAMPOLINE 19
        IRQ_TRAMPOLINE 1c
        IRQ_TRAMPOLINE 4a


/****************************************************************
 * Misc. entry points.
 ****************************************************************/

// Entry point for QEMU smi interrupts.
        DECLFUNC entry_smi
entry_smi:
        // Transition to 32bit mode.
        movl $1f + BUILD_BIOS_ADDR, %edx
        jmp transition32_nmi_off
        .code32
1:      movl $BUILD_SMM_ADDR + 0x8000, %esp
        calll _cfunc32flat_handle_smi - BUILD_BIOS_ADDR
        rsm
        .code16

// Entry point for QEMU smp sipi interrupts.
        DECLFUNC entry_smp
entry_smp:
        // Transition to 32bit mode.
        cli
        cld
        movl $2f + BUILD_BIOS_ADDR, %edx
        jmp transition32_nmi_off
        .code32
        // Acquire lock and take ownership of shared stack
1:      rep ; nop
2:      lock btsl $0, SMPLock
        jc 1b
        movl SMPStack, %esp
        // Call handle_smp
        calll _cfunc32flat_handle_smp - BUILD_BIOS_ADDR
        // Release lock and halt processor.
        movl $0, SMPLock
3:      hlt
        jmp 3b
        .code16

// Resume (and reboot) entry point - called from entry_post
        DECLFUNC entry_resume
entry_resume:
        // Disable interrupts
        cli
        cld
        // Use the ExtraStack in low mem.
        movl $_zonelow_seg, %eax
        movw %ax, %ds
        movw %ax, %ss
        movl $ExtraStack + BUILD_EXTRA_STACK_SIZE, %esp
        // Call handler.
        jmp handle_resume

// PMM entry point
        DECLFUNC entry_pmm
entry_pmm:
        pushl %esp              // Backup %esp, then clear high bits
        movzwl %sp, %esp
        pushfl                  // Save registers clobbered by C code
        cli
        cld
        PUSHBREGS
        movl %ss, %ecx          // Move %ss to %ds
        movw %cx, %ds
        shll $4, %ecx
        movl $_cfunc32flat_handle_pmm, %eax // Setup: call32(handle_pmm, args, -1)
        leal PUSHBREGS_size+12(%esp, %ecx), %edx // %edx points to start of args
        movl $-1, %ecx
        calll call32
        movw %ax, BREGS_eax(%esp)       // Modify %ax:%dx to return %eax
        shrl $16, %eax
        movw %ax, BREGS_edx(%esp)
        POPBREGS
        popfl
        popl %esp
        lretw

// PnP entry points
        DECLFUNC entry_pnp_real
        .global entry_pnp_prot
entry_pnp_prot:
        pushl %esp
        jmp 1f
entry_pnp_real:
        pushl %esp              // Backup %esp, then clear high bits
        movzwl %sp, %esp
1:
        pushfl                  // Save registers clobbered by C code
        cli
        cld
        PUSHBREGS
        movw %ss, %cx           // Move %ss to %ds
        movw %cx, %ds
        leal PUSHBREGS_size+12(%esp), %eax  // %eax points to start of u16 args
        calll handle_pnp
        movw %ax, BREGS_eax(%esp)   // Modify %eax to return %ax
        POPBREGS
        popfl
        popl %esp
        lretw

// APM entry points
        DECLFUNC entry_apm16
entry_apm16:
        pushfw          // save flags
        pushl %eax      // dummy
        ENTRY_ARG handle_apm
        addw $4, %sp    // pop dummy
        popfw           // restore flags
        lretw

        DECLFUNC entry_apm32
        .code32
entry_apm32:
        pushfl
        pushl %gs
        pushl %cs               // Move second descriptor after %cs to %gs
        addl $16, (%esp)
        popl %gs
        ENTRY_ARG_ESP _cfunc32seg_handle_apm
        popl %gs
        popfl
        lretl
        .code16

// PCI-BIOS entry points
        DECLFUNC entry_pcibios32
        .code32
entry_pcibios32:
        pushfl
        pushl %gs               // Backup %gs and set %gs=%ds
        pushl %ds
        popl %gs
        ENTRY_ARG_ESP _cfunc32seg_handle_pcibios
        popl %gs
        popfl
        lretl
        .code16

        DECLFUNC entry_pcibios16
entry_pcibios16:
        ENTRY_ARG handle_pcibios
        iretw

// int 1589 entry point
        DECLFUNC entry_1589
entry_1589:
        ENTRY_ARG handle_1589
        iretw

// BIOS32 support
        DECLFUNC entry_bios32
        .code32
entry_bios32:
        pushfl
#if CONFIG_PCIBIOS
        // Check for PCI-BIOS request
        cmpl $0x49435024, %eax // $PCI
        jne 1f
        movl $BUILD_BIOS_ADDR, %ebx
        movl $BUILD_BIOS_SIZE, %ecx
        movl $entry_pcibios32, %edx
        xorb %al, %al
        jmp 2f
#endif
        // Unknown request
1:      movb $0x80, %al
        // Return to caller
2:      popfl
        lretl
        .code16

// 32bit elf entry point
        DECLFUNC entry_elf
        .code32
entry_elf:
        cli
        cld
        lidtl (BUILD_BIOS_ADDR + pmode_IDT_info)
        lgdtl (BUILD_BIOS_ADDR + rombios32_gdt_48)
        movl $SEG32_MODE32_DS, %eax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %fs
        movw %ax, %gs
        movw %ax, %ss
        movl $BUILD_STACK_ADDR, %esp
        ljmpl $SEG32_MODE32_CS, $_cfunc32flat_handle_post
        .code16

// UEFI Compatibility Support Module (CSM) entry point
        DECLFUNC entry_csm
entry_csm:
        // Backup register state
        pushfw
        cli
        cld
        pushl %eax                      // dummy
        PUSHBREGS

        // Backup stack location and convert to a "flat pointer"
        movl %ss, %eax
        movw %ax, BREGS_code+2(%esp)    // Store %ss in bregs->code.seg
        shll $4, %eax
        addl %esp, %eax

        // Change to BUILD_STACK_ADDR stack and call handle_csm(bregs)
        ENTRY_INTO32 _cfunc32flat_handle_csm

        DECLFUNC __csm_return
        .code32
__csm_return:
        movl $1f, %edx
        jmp transition16big
        .code16

        // Switch back to original stack
1:      movzwl BREGS_code+2(%eax), %edx
        movl %edx, %ecx
        shll $4, %ecx
        subl %ecx, %eax
        movl %edx, %ss
        movl %eax, %esp

        // Restore register state and return.
        POPBREGS
        addw $4, %sp                    // pop dummy
        popfw
        lretw


/****************************************************************
 * Interrupt entry points
 ****************************************************************/

        // Main entry point for hardware interrupts handled on extra stack
        DECLFUNC irqentry_extrastack
irqentry_extrastack:
        cli
        cld
        pushw %ds               // Set %ds:%eax to space on ExtraStack
        pushl %eax
        movl $_zonelow_seg, %eax
        movl %eax, %ds
        movl StackPos, %eax
        subl $PUSHBREGS_size+8, %eax
        SAVEBREGS_POP_DSEAX
        popl %ecx
        movl %esp, PUSHBREGS_size(%eax)
        movw %ss, PUSHBREGS_size+4(%eax)

        movw %ds, %dx           // Setup %ss/%esp and call function
        movw %dx, %ss
        movl %eax, %esp
        calll *%ecx

        movl %esp, %eax         // Restore registers and return
        movw PUSHBREGS_size+4(%eax), %ss
        movl PUSHBREGS_size(%eax), %esp
        RESTOREBREGS_DSEAX
        iretw

        // Main entry point for software interrupts handled on extra stack
        DECLFUNC irqentry_arg_extrastack
irqentry_arg_extrastack:
        cli
        cld
        pushw %ds               // Set %ds:%eax to space on ExtraStack
        pushl %eax
        movl $_zonelow_seg, %eax
        movl %eax, %ds
        movl StackPos, %eax
        subl $PUSHBREGS_size+16, %eax
        SAVEBREGS_POP_DSEAX     // Save registers on extra stack
        popl %ecx
        movl %esp, PUSHBREGS_size+8(%eax)
        movw %ss, PUSHBREGS_size+12(%eax)
        popl BREGS_code(%eax)
        popw BREGS_flags(%eax)

        movw %ds, %dx           // Setup %ss/%esp and call function
        movw %dx, %ss
        movl %eax, %esp
        calll *%ecx

        movl %esp, %eax         // Restore registers and return
        movw PUSHBREGS_size+12(%eax), %ss
        movl PUSHBREGS_size+8(%eax), %esp
        popl %edx
        popw %dx
        pushw BREGS_flags(%eax)
        pushl BREGS_code(%eax)
        RESTOREBREGS_DSEAX
        iretw

        // Main entry point for software interrupts (using caller's stack)
        DECLFUNC irqentry_arg
irqentry_arg:
        ENTRY_ARG_ST
        iretw

        // Helper macros for hardware interrupt declaration
        .macro IRQ_ENTRY num
        .global entry_\num
        entry_\num :
        pushl $ handle_\num
        jmp irqentry_extrastack
        .endm

        .macro DECL_IRQ_ENTRY num
        DECLFUNC entry_\num
        IRQ_ENTRY \num
        .endm

        // Helper macros for software interrupt declaration
        .macro IRQ_ENTRY_ARG num
        .global entry_\num
        entry_\num :
        pushl $ handle_\num
#if CONFIG_ENTRY_EXTRASTACK
        jmp irqentry_arg_extrastack
#else
        jmp irqentry_arg
#endif
        .endm

        .macro DECL_IRQ_ENTRY_ARG num
        DECLFUNC entry_\num
        IRQ_ENTRY_ARG \num
        .endm

        // Various entry points (that don't require a fixed location).
        DECL_IRQ_ENTRY_ARG 13
        DECL_IRQ_ENTRY 76
        DECL_IRQ_ENTRY 70
        DECL_IRQ_ENTRY 74
        DECL_IRQ_ENTRY 75
        DECL_IRQ_ENTRY hwpic1
        DECL_IRQ_ENTRY hwpic2

        // int 18/19 are special - they reset stack and call into 32bit mode.
        DECLFUNC entry_19
entry_19:
        ENTRY_INTO32 _cfunc32flat_handle_19

        DECLFUNC entry_18
entry_18:
        ENTRY_INTO32 _cfunc32flat_handle_18


/****************************************************************
 * Fixed position entry points
 ****************************************************************/

        // Specify a location in the fixed part of bios area.
        .macro ORG addr
        .section .fixedaddr.\addr
        .endm

        ORG 0xe05b
entry_post:
        cmpl $0, %cs:HaveRunPost                // Check for resume/reboot
        jnz entry_resume
        ENTRY_INTO32 _cfunc32flat_handle_post   // Normal entry point

        ORG 0xe2c3
        IRQ_ENTRY 02

        ORG 0xe3fe
        .global entry_13_official
entry_13_official:
        jmp entry_13

        // 0xe401 - OldFDPT in misc.c

        ORG 0xe6f2
        .global entry_19_official
entry_19_official:
        jmp entry_19

        // 0xe6f5 - BIOS_CONFIG_TABLE in misc.c

        // 0xe729 - BaudTable in misc.c

        ORG 0xe739
        IRQ_ENTRY_ARG 14

        ORG 0xe82e
        IRQ_ENTRY_ARG 16

        ORG 0xe987
        IRQ_ENTRY 09

        ORG 0xec59
        IRQ_ENTRY_ARG 40

        ORG 0xef57
        IRQ_ENTRY 0e

        // 0xefc7 - diskette_param_table in misc.c

        ORG 0xefd2
        IRQ_ENTRY_ARG 17

        ORG 0xf045
entry_10_0x0f:
        // XXX - INT 10 Functions 0-Fh Entry Point
        iretw

        ORG 0xf065
        IRQ_ENTRY_ARG 10

        // 0xf0a4 - VideoParams in misc.c

        ORG 0xf841
        IRQ_ENTRY_ARG 12

        ORG 0xf84d
        IRQ_ENTRY_ARG 11

        ORG 0xf859
        .global entry_15_official
entry_15_official:
        cmpb $0x89, %ah
        je entry_1589           // 1589 calls return in protected mode
        IRQ_ENTRY_ARG 15

        // 0xfa6e - vgafont8 in font.c

        ORG 0xfe6e
        .global entry_1a_official
entry_1a_official:
        cmpb $0xb1, %ah
        je entry_pcibios16      // PCIBIOS calls can be in protected mode
        IRQ_ENTRY_ARG 1a

        ORG 0xfea5
        IRQ_ENTRY 08

        // 0xfef3 - InitVectors in misc.c

        ORG 0xff53
        .global entry_iret_official
entry_iret_official:
        iretw

        ORG 0xff54
        IRQ_ENTRY_ARG 05

        ORG 0xfff0 // Power-up Entry Point
        .global reset_vector
reset_vector:
        ljmpw $SEG_BIOS, $entry_post

        // 0xfff5 - BiosDate in misc.c

        // 0xfffe - BiosModelId in misc.c

        // 0xffff - BiosChecksum in misc.c

        .end
