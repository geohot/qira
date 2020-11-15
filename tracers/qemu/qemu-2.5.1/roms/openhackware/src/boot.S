/* 
 *	<boot.S>
 *	
 *     First stage BIOS loader for Open Hack'Ware.
 *   
 *   Copyright (C) 2004-2005 Jocelyn Mayer (l_indien@magic.fr)
 *   
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *   
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
/*
 * setup one RAM bank then
 * relocate the one page BIOS second stage into RAM.
 *
 * We consider that we know nothing about the CPU state
 * at the time we enter this code.
 *
 */

#define ASSEMBLY_CODE
#include "bios.h"

.section .rom, "ax"
.align 2
_boot_start:
        /* Minimal setup */
        li    r0, 0                                          ;
        /* r11 is _boot_start address */
        mflr    r11                                          ;
        addi    r11, r11, (_boot_start - _start - 4)         ;
        /* Disable MMU and interruptions */
        addi    r12, r11, (_boot_no_mmu - _boot_start)       ;
        mtspr   SRR0, r12                                    ;
        mfmsr   r12                                          ;
        lis     r13, 0x0004                                  ;
        ori     r13, r13, 0xEF71                             ;
        andc    r15, r12, r13                                ;
        mtspr   SRR1, r12                                    ;
        rfi                                                  ;
_boot_no_mmu:
        /* TODO: initialize physical RAM (we need at least one page)
         * before doing anything else.
         * This may be machine dependent code.
         */
_boot_copy:
        /* Copy the second stage bootloader into RAM
         * We may need a tiny driver if we need to boot from special device
         * (ie disc-on-chip, ...)
         */
        lis    r12, (VECTORS_SIZE / 4)@h                     ;
        ori    r12, r12, (VECTORS_SIZE / 4)@l                ;
        mtctr  r12                                           ;
        clrrwi r12, r11, BIOS_IMAGE_BITS                     ;
        addis  r3, r12, VECTORS_SIZE@h                       ;
        addi   r3, r3, VECTORS_SIZE@l                        ;
        subi   r12, r12, 4                                   ;
        lis    r13, VECTORS_BASE@h                           ;
        ori    r13, r13, VECTORS_BASE@l                      ;
        mtlr   r13                                           ;
        subi   r13, r13, 4                                   ;
_boot_copy_loop:
        lwzu   r14, 4(r12)                                   ;
        stwu   r14, 4(r13)                                   ;
        bdnz   _boot_copy_loop                               ;
        /* Synchronize the whole execution context */
        addi    r12, r11, (_boot_sync - _boot_start)         ;
        mtspr   SRR0, r12                                    ;
        mfmsr   r12                                          ;
        mtspr   SRR1, r12                                    ;
        rfi                                                  ;
_boot_sync:
        /* All done, jump into the loaded code */
        blrl                                                 ;
        /* If we ever return, reboot */
        b _start                                             ;

.space BOOT_SIZE - 4 - (. - _boot_start), 0xFF
/* Reset entry point */
        . = 0x1FC
_start:
        bl _boot_start                                       ;
