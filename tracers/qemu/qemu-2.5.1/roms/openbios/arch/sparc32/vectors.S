/*
 * <vectors.S>
 *
 * Sparc V9 Trap Table(s) with SpitFire/Cheetah extensions.
 *
 *   Copyright (C) 1996, 2001 David S. Miller (davem@caip.rutgers.edu)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2 as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *   MA  02110-1301, USA.
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 */

#define __ASSEMBLY
#include "psr.h"
#include "asm/asi.h"
#define SER_ADDR5  0x71100004
#define SER_ADDR10 0xf1100004

        .section ".text.vectors", "ax"
        .align 4 /* Should be 16384, but alignment is handled by the ldscript */
/* Sparc32 trap table */
        .globl trap_table, t_zero, t_wovf, t_wunf, __divide_error
trap_table:

#define WINDOW_SPILL \
        rd %psr, %l0; rd %wim, %l3; b spill_window_entry; nop;

#define WINDOW_FILL \
        rd %psr, %l0; rd %wim, %l3; b fill_window_entry; nop;

#define TRAP_DFAULT(lvl) \
        rd %psr, %l0; rd %wim, %l3; b handle_dfault; mov lvl, %l7;

#define BTRAP(lvl) ba bug; mov lvl, %g1; nop; nop;
#define BTRAPS(x) BTRAP(x) BTRAP(x+1) BTRAP(x+2) BTRAP(x+3) BTRAP(x+4) BTRAP(x+5) BTRAP(x+6) BTRAP(x+7)
#define TRAP_ENTRY_INTERRUPT(int_level) \
        sethi %hi(irq_entry ## int_level), %l7; \
        or %l7, %lo(irq_entry ## int_level), %l7; \
        jmp %l7; \
         nop

t_zero:         b entry; nop; nop; nop;
                BTRAP(0x1) BTRAP(0x2) BTRAP(0x3) BTRAP(0x4)
t_wovf:         WINDOW_SPILL                        /* Window Overflow               */
t_wunf:         WINDOW_FILL                         /* Window Underflow              */
                BTRAP(0x7)
                BTRAP(0x8)
                TRAP_DFAULT(0x9)
                BTRAP(0xa) BTRAP(0xb) BTRAP(0xc) BTRAP(0xd) BTRAP(0xe) BTRAP(0xf)
#if 0
                BAD_TRAP(0x10)
t_irq1:         TRAP_ENTRY_INTERRUPT(1)             /* IRQ Software/SBUS Level 1     */
t_irq2:         TRAP_ENTRY_INTERRUPT(2)             /* IRQ SBUS Level 2              */
t_irq3:         TRAP_ENTRY_INTERRUPT(3)             /* IRQ SCSI/DMA/SBUS Level 3     */
t_irq4:         TRAP_ENTRY_INTERRUPT(4)             /* IRQ Software Level 4          */
t_irq5:         TRAP_ENTRY_INTERRUPT(5)             /* IRQ SBUS/Ethernet Level 5     */
t_irq6:         TRAP_ENTRY_INTERRUPT(6)             /* IRQ Software Level 6          */
t_irq7:         TRAP_ENTRY_INTERRUPT(7)             /* IRQ Video/SBUS Level 5        */
t_irq8:         TRAP_ENTRY_INTERRUPT(8)             /* IRQ SBUS Level 6              */
t_irq9:         TRAP_ENTRY_INTERRUPT(9)             /* IRQ SBUS Level 7              */
t_irq10:        TRAP_ENTRY_INTERRUPT(10)            /* IRQ Timer #1 (one we use)     */
t_irq11:        TRAP_ENTRY_INTERRUPT(11)            /* IRQ Floppy Intr.              */
t_irq12:        TRAP_ENTRY_INTERRUPT(12)            /* IRQ Zilog serial chip         */
t_irq13:        TRAP_ENTRY_INTERRUPT(13)            /* IRQ Audio Intr.               */
t_irq14:        TRAP_ENTRY_INTERRUPT(14)            /* IRQ Timer #2                  */
t_nmi:          BAD_TRAP(0x1f)                      /* Level 15 (NMI)                */
#else
                BTRAPS(0x10)
                BTRAP(0x18) BTRAP(0x19)
t_irq10:        TRAP_ENTRY_INTERRUPT(10)            /* IRQ Timer #1 (one we use)     */
                BTRAP(0x1b) BTRAP(0x1c) BTRAP(0x1d)
t_irq14:        TRAP_ENTRY_INTERRUPT(14)            /* IRQ Timer #2                  */
                BTRAP(0x1f)
#endif
                BTRAPS(0x20)
                BTRAP(0x28)
                TRAP_DFAULT(0x29)
                BTRAP(0x2a) BTRAP(0x2b) BTRAP(0x2c) BTRAP(0x2d) BTRAP(0x2e) BTRAP(0x2f)
                BTRAPS(0x30) BTRAPS(0x38)
                BTRAPS(0x40) BTRAPS(0x48)
                BTRAPS(0x50) BTRAPS(0x58)
                BTRAPS(0x60) BTRAPS(0x68)
                BTRAPS(0x70) BTRAPS(0x78)
                BTRAPS(0x80) BTRAPS(0x88)
                BTRAPS(0x90) BTRAPS(0x98)
                BTRAPS(0xa0) BTRAPS(0xa8)
                BTRAPS(0xb0) BTRAPS(0xb8)
                BTRAPS(0xc0) BTRAPS(0xc8)
                BTRAPS(0xd0) BTRAPS(0xd8)
                BTRAPS(0xe0) BTRAPS(0xe8)
                BTRAPS(0xf0) BTRAPS(0xf8)

        .section ".text", "ax"
        .align 4
__divide_error:
bug:
        /* Dump the exception and its context */
        ! Set up CPU state
        rd      %psr, %g2
        andn    %g2, PSR_ET, %g2
        wr      %g2, %psr
        ! Disable mmu, re-enable boot mode
        set     _start, %g3
        set     dump_exception, %g2
        sub     %g2, %g3, %g3
        set     3 << 13, %g2
        jmp    %g3
         sta    %g2, [%g0] ASI_M_MMUREGS

outstr:
        /* void outstr (unsigned long port5, unsigned long port10,
         * const unsigned char *str);
         * Writes a string on an IO port.
         */
1:      lduba    [%o2] ASI_M_KERNELTXT, %o3
        cmp     %o3, 0
        be      2f
         nop
        stba    %o3, [%o0] ASI_M_BYPASS
        stba    %o3, [%o1] ASI_M_CTL
        b       1b
         inc    %o2
2:      retl
         nop

outhex:
        /* void outhex (unsigned long port5, unsigned long port10,
         * uint32_t value);
         * Dumps a 32 bits hex number on serial port
         */
        mov     %o2, %o4
        set     28, %o3
        srl     %o4, %o3, %o2
1:      and     %o2, 0xf, %o2
        cmp     %o2, 9
        bgt     2f
         nop
        b       3f
         add    %o2, '0', %o2
2:      add     %o2, 'a' - 10, %o2
3:      stba    %o2, [%o0] ASI_M_BYPASS
        stba    %o2, [%o1] ASI_M_CTL
        subcc   %o3, 4, %o3
        bge     1b
         srl    %o4, %o3, %o2
        retl
         nop

        /* void dump_exception ();
         *
         * Dump a message when catching an exception
         */
dump_exception:
        set     SER_ADDR5 + 2, %o0
        set     SER_ADDR10 + 2, %o1
        set     (_BUG_message_0), %o2
        call    outstr
         nop

        call    outhex
         mov    %g1, %o2

        set     (_BUG_message_1), %o2
        call    outstr
         nop

        call    outhex
         mov    %l1, %o2

        set     (_BUG_message_2), %o2
        call    outstr
         nop

        call    outhex
         mov    %l2, %o2

        set     (_BUG_message_3), %o2
        call    outstr
         nop
_forever:
        /* Loop forever */
        b       _forever                                  ;
         nop

irq_entry10:
        sethi   %hi(counter_regs), %l7
        ld      [%l7 + %lo(counter_regs)], %l7
        sethi   0x10000, %l6
        ld      [%l7 + %l6], %g0
        jmp     %l1
         rett   %l2

irq_entry14:
        sethi   %hi(counter_regs), %l7
        ld      [%l7 + %lo(counter_regs)], %l7
        ld      [%l7], %g0
        sethi   %hi(obp_ticks), %l7
        ld      [%l7 + %lo(obp_ticks)], %l7
        ld      [%l7], %l6
        add     %l6, 10, %l6
        st      %l6, [%l7]
        jmp     %l1
         rett  %l2

/* Register window handlers */
#include "wof.S"
#include "wuf.S"

/* Data fault handler */
        .data
        .align  4
        .global ignore_dfault

ignore_dfault:
        .word   0

        .text
        .align  4

handle_dfault:
        /* If ignore_dfault is 0, fall through to normal exception handler */
        sethi   %hi(ignore_dfault), %l4
        ld      [%l4 + %lo(ignore_dfault)], %l4
        tst     %l4
        bz,a    bug
         mov    %l7, %g1

        /* Otherwise skip the faulting instruction and return */
        jmp     %l2
         rett   %l2 + 4


        .section .rodata
_BUG_message_0:
        .string "Unhandled Exception 0x"
_BUG_message_1:
        .string "\r\nPC = 0x"
_BUG_message_2:
        .string " NPC = 0x"
_BUG_message_3:
        .string "\r\nStopping execution\r\n"
