/* 
 *   <vectors.S>
 *      
 *   Second stage boot-loader and exception vectors for Open Hack'Ware.
 *   
 *   Copyright (C) 2004-2005 Jocelyn Mayer (l_indien@magic.fr)
 *   
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define ASSEMBLY_CODE
#include "bios.h"

.section .text
.align 2

.globl _start
_start:
        /* Entry point */
        li      r0, 0                                     ;
_turn_off_mmu:
        /* Be sure MMU is off and we are in 32 bits mode (for PPC64) */
        lis     r11, _hw_init@h                           ;
        ori     r11, r11, _hw_init@l                      ;
        mtspr   26, r11                                   ;
        mtspr   27, r0                                    ;
        rfi                                               ;
_hw_init:
        /* May need more hw init here */
_load_bios:
        /* Load the full BIOS into RAM */
        lis     r12, bios_base@h                          ;
        ori     r12, r12, bios_base@l                     ;
        lmw     r29, 0(r12)                               ;
        /* Set up the C stack */
        addis   r1, r29, 0x0040                           ;
        clrrwi  r1, r1, 19                                ;
        stw     r1, -16(r1)                               ;
        stwu    r0, -4(r1)                                ;
        stwu    r0, -4(r1)                                ;
        stwu    r0, -4(r1)                                ;
        stwu    r0, -4(r1)                                ;
        /* Skip frame pointer */        
        stwu    r0, -8(r1)                                ;
        stwu    r0, -4(r1)                                ;
        stwu    r0, -4(r1)                                ;
        /* Start copying */
        mtctr   r30                                       ;
        subi    r12, r3, 4                                ;
        subi    r13, r29, 4                               ;
_bios_copy_loop:
        lwzu    r14, 4(r12)                               ;
        stwu    r14, 4(r13)                               ;
        bdnz    _bios_copy_loop                           ;
        /* Synchronize the whole execution context */
        /* Also enable FPU */
        ori     r0, r0, (1 << 13)                         ;
        mtspr   26, r29                                   ;
        mtspr   27, r0                                    ;
        rfi                                               ;
        /* If we ever return, stop */
        bl      bug                                       ;

.org 0x0080
.section .text
.align 2
bug:
        /* Dump the exception and its context */
        mflr    r3                                        ;
        mfspr   r4, SRR0                                  ;
        mfspr   r5, SRR1                                  ;
        mfspr   r6, DAR                                   ;
        mfspr   r7, DSISR                                 ;
        /* Turn MMU off */
        lis     r0, _bug_no_mmu@h                         ;
        ori     r0, r0, _bug_no_mmu@l                     ;
        mtspr   26, r0                                    ;
        li      r0, 0                                     ;
        mtspr   27, r0                                    ;
        rfi                                               ;
_bug_no_mmu:
        bl      dump_exception                            ;
_forever:
        /* Loop forever */
        b       _forever                                  ;

skip_exception:
        /* Skip external interrupts and decrementer exception */
        /* BEWARE: be sure not to modify any register */
        stw     r11, save_area@l(0)                       ;
        mfspr   r11, 27                                   ;
        clrlwi  r11, r11, 16                              ;
        mtspr   27, r11                                   ;
        lwz     r11, save_area@l(0)                       ;
        rfi                                               ;

#define EXCP_BUG(entry)                                     \
.org 0x##entry                                            ; \
.section .text                                            ; \
.align 2                                                  ; \
excp_##entry:                                             ; \
        bl bug

#define EXCP_SKIP(entry)                                    \
.org 0x##entry                                            ; \
.section .text                                            ; \
.align 2                                                  ; \
excp_##entry##:                                           ; \
        b skip_exception

        /* Exception vectors */
        /* Reset exception */
.org 0x0100
excp_0100:
        ba 0xfffffffc

        /* Machine check exception */
        EXCP_BUG(0200)                                    ;

        /* DSI exception */
        EXCP_BUG(0300)                                    ;

        /* ISI exception */
        EXCP_BUG(0400)                                    ;

        /* External interrupt: skip it */
        EXCP_SKIP(0500)                                   ;

        /* Alignment exception */
        EXCP_BUG(0600)                                    ;

        /* Program exception */
        EXCP_BUG(0700)                                    ;

        /* No floating point exception */
        EXCP_BUG(0800)                                    ;

        /* Decrementer exception: skip it */
        EXCP_SKIP(0900)                                   ;

        /* Reserved A exception */
        EXCP_BUG(0A00)                                    ;

        /* Reserved B exception */
        EXCP_BUG(0B00)                                    ;

        /* System call exception */
        EXCP_BUG(0C00)                                    ;

        /* Trace exception */
        EXCP_BUG(0D00)                                    ;

        /* Floating point assist exception */
        EXCP_BUG(0E00)                                    ;

        /* Performance monitor exception */
        EXCP_BUG(0F00)                                    ;

        /* Instruction TLB miss exception */
        EXCP_BUG(1000)                                    ;

        /* Data TLB miss for store exception */
        EXCP_BUG(1100)                                    ;

        /* Data TLB miss for load exception */
        EXCP_BUG(1200)                                    ;

        /* Instruction address breakpoint exception */
        EXCP_BUG(1300)                                    ;

        /* System management interrupt exception */
        EXCP_BUG(1400)                                    ;

        /* Thermal management exception */
        EXCP_BUG(1500)                                    ;

        /* Unknown exceptions */
        EXCP_BUG(1600)                                    ;

        EXCP_BUG(1700)                                    ;

        EXCP_BUG(1800)                                    ;

        EXCP_BUG(1900)                                    ;

        EXCP_BUG(1A00)                                    ;

        EXCP_BUG(1B00)                                    ;

        EXCP_BUG(1C00)                                    ;

        EXCP_BUG(1D00)                                    ;

        EXCP_BUG(1E00)                                    ;

        EXCP_BUG(1F00)                                    ;
        /* End of exception vectors list */

.org 0x2000
.section .text
.align 2
helpers_start:

outb:
        /* void outb (uint32_t port, uint32_t data);
         * Writes a single character on an IO port.
         * Used for serial console.
         */
        stb     r4, 0(r3)                                 ;
        eieio                                             ;
        blr                                               ;

outstr:
        /* void outstr (uint32_t port, const unsigned char *str);
         * Writes a string on an IO port.
         */
        mflr    r20                                       ;
        subi    r11, r4, 1                                ;
        
_outstr_next:
        lbzu    r4, 1(r11)                                ;
        cmpi    0, r4, 0                                  ;
        beq     _outstr_done                              ;
        bl      outb                                      ;
        b       _outstr_next                              ;
_outstr_done:
        mtlr    r20                                       ;
        blr                                               ;

outdigit:
        /* void outdigit (uint32_t port, uint32_t digit);
         * Dumps a single digit on serial port.
         */
        mflr    r20                                       ;
        addi    r4, r4, '0'                               ;
        bl      outb                                      ;
        mtlr    r20                                       ;
        blr                                               ;

outhex:
        /* void outhex (uint32_t port, uint32_t value);
         * Dumps a 32 bits hex number on serial port
         */
        mflr    r21
        li      r11, 8                                    ;
        mtctr   r11                                       ;
        mr      r11, r4                                   ;
_outhex_next:
        rlwinm  r11, r11, 4, 0, 31                        ;
        clrlwi  r4, r11, 28                               ;
        cmpi    0, r4, 9                                  ;
        bgt     _outhex_xdigit                            ;
        bl      outdigit                                  ;
        bdnz    _outhex_next                              ;
        b       _outhex_done                              ;
_outhex_xdigit:
        addi    r4, r4, 'a' - 10                          ;
        bl      outb                                      ;
        bdnz    _outhex_next                              ;
_outhex_done:
        mtlr    r21                                       ;
        blr                                               ;

        /* void dump_exception (uint32_t lr, uint32_t srr0, uint32_t srr1,
         *                      uint32_t dar, uint32_t dsisr);
         * Dump a message when catching an exception
         */
dump_exception:
        /* Save call parameters */
        mflr    r19                                       ;
        mr      r22, r3                                   ;
        mr      r23, r4                                   ;
        mr      r24, r5                                   ;
        mr      r25, r6                                   ;
        mr      r26, r7                                   ;
        lis     r11, registers_area@h                     ;
        ori     r11, r11, registers_area@l                ;
        lmw     r27, 0(r11)                               ;
        /* Now, serial IO port is in r27,
         * message table start is in r28,
         * first exception message offset is in r29,
         * and last known exception number is in r30
         */
        /* Print error prompt message */
        mr      r3, r27                                   ;
        lwzu    r4, 4(r28)                                ;
        bl      outstr                                    ;
        /* Find message corresponding to the caught exception */
        srwi    r12, r22, 8                               ;
        cmp     0, r12, r30                               ;
        ble     _dump_excp_msg                            ;
        subi    r12, r30, 1                               ;
_dump_excp_msg:
        rlwinm  r12, r12, 2, 0, 31                        ;
        /* Dump execption message */
        mr      r3, r27                                   ;
        lwzx    r4, r12, r29                              ;
        bl      outstr                                    ;
        /* Complete exception message */
        mr      r3, r27                                   ;
        lwzu    r4, 4(r28)                                ;
        bl      outstr                                    ;
        /* Dump nip */
        mr      r3, r27                                   ;
        lwzu    r4, 4(r28)                                ;
        bl      outstr                                    ;
        mr      r3, r27                                   ;
        mr      r4, r23                                   ;
        bl      outhex                                    ;
        /* dump msr */
        mr      r3, r27                                   ;
        lwzu    r4, 4(r28)                                ;
        bl      outstr                                    ;
        mr      r3, r27                                   ;
        mr      r4, r24                                   ;
        bl      outhex                                    ;
        /* dump dar */
        mr      r3, r27                                   ;
        lwzu    r4, 4(r28)                                ;
        bl      outstr                                    ;
        mr      r3, r27                                   ;
        mr      r4, r25                                   ;
        bl      outhex                                    ;
        /* dump dsisr */
        mr      r3, r27                                   ;
        lwzu    r4, 4(r28)                                ;
        bl      outstr                                    ;
        mr      r3, r27                                   ;
        mr      r4, r26                                   ;
        bl      outhex                                    ;
        /* All done, dump last message and return */
        mr      r3, r27                                   ;
        lwzu    r4, 4(r28)                                ;
        bl      outstr                                    ;
        mtlr    r19                                       ;
        blr                                               ;

.section .rodata
.align 2
_BUG_message_0:
        .string "ERROR: BUG caught...\n"
_BUG_message_1:
        .string " exception"
_BUG_message_2:
        .string "\nnip=0x"
_BUG_message_3:
        .string " msr=0x"
_BUG_message_4:
        .string " dar=0x"
_BUG_message_5:
        .string " dsisr=0x"
_BUG_message_6:
        .string "\nStopping execution\n"

_excp_message_0x00:
        .string "BIOS execution"
_excp_message_0x01:
        .string "Reset"
_excp_message_0x02:
        .string "Machine check"
_excp_message_0x03:
        .string "Data memory access"
_excp_message_0x04:
        .string "Instruction fetch"
_excp_message_0x05:
        .string "External"
_excp_message_0x06:
        .string "Alignment"
_excp_message_0x07:
        .string "Program"
_excp_message_0x08:
        .string "No floating point"
_excp_message_0x09:
        .string "Decrementer"
_excp_message_0x0a:
        .string "Reserved A"
_excp_message_0x0b:
        .string "Reserved B"
_excp_message_0x0c:
        .string "System call"
_excp_message_0x0d:
        .string "Trace"
_excp_message_0x0e:
        .string "Floating point assist"
_excp_message_0x0f:
        .string "Performance monitor"
_excp_message_0x10:
        .string "Instruction TLB miss"
_excp_message_0x11:
        .string "Data TLB miss for store"
_excp_message_0x12:
        .string "Data TLB miss for load"
_excp_message_0x13:
        .string "Instruction address breakpoint"
_excp_message_0x14:
        .string "System management"
_excp_message_0x15:
        .string "Thermal management"
_excp_message_0x16:
        .string "Unknown"
_messages_table:
        .long _BUG_message_0
        .long _BUG_message_1
        .long _BUG_message_2
        .long _BUG_message_3
        .long _BUG_message_4
        .long _BUG_message_5
        .long _BUG_message_6
_excp_messages_table:
        .long _excp_message_0x00
        .long _excp_message_0x01
        .long _excp_message_0x02
        .long _excp_message_0x03
        .long _excp_message_0x04
        .long _excp_message_0x05
        .long _excp_message_0x06
        .long _excp_message_0x07
        .long _excp_message_0x08
        .long _excp_message_0x09
        .long _excp_message_0x0a
        .long _excp_message_0x0b
        .long _excp_message_0x0c
        .long _excp_message_0x0d
        .long _excp_message_0x0e
        .long _excp_message_0x0f
        .long _excp_message_0x10
        .long _excp_message_0x11
        .long _excp_message_0x12
        .long _excp_message_0x13
        .long _excp_message_0x14
        .long _excp_message_0x15
        .long _excp_message_0x16
_last_excp_message:

bios_base:
        .long BIOS_BASE
bios_size:
        .long BIOS_SIZE / 4
_dummy_0:
        .long 0x00000000

registers_area: /* To be loaded in register when an exception is caught */
_serial_IO:      /* r27 */
        .long 0x800003F8
_messages_start: /* r28 */
        .long _messages_table - 4
_excp_messages:  /* r29 */
        .long _excp_messages_table
_max_excp:       /* r30 */
        .long (_last_excp_message - _excp_messages_table) / 4
_dummy_1:        /* r31: dummy */
        .long 0x00000000
        
.section .data
.align 2
save_area: /* Area for r11 save when an exception is skipped */
        .long 0x00000000
