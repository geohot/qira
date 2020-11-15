/* 
 *	<start.S>
 *	
 *     BIOS start code for Open Hack'Ware.
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

.section .start, "ax"
.align 2

.globl _start
_start:
        /* Save our stack pointer */
        lis    r11, saved_params@h                           ;
        ori    r11, r11, saved_params@l                      ;
        stw    r1, 0(r11)                                    ;
        /* Fill space from _bss_start to _ram_start with zeroes */
        lis    r11, _bss_start@h                             ;
        ori    r11, r11, _bss_start@l                        ;
        lis    r12, _ram_start@h                             ;
        ori    r12, r12, _ram_start@l                        ;
        subf   r12, r11, r12                                 ;
        srawi  r12, r12, 2                                   ;
        cmpi   0, r12, 0                                     ;
        beq    _bss_done                                     ;
        mtctr  r12                                           ;
        subi   r11, r11, 4                                   ;
        li     r12, 0                                        ;
_bss_loop:
        stwu   r12, 4(r11)                                   ;
        bdnz   _bss_loop                                     ;
_bss_done:
        /* Now, we have a real C environment: call main */
        bl     main                                          ;
        /* If we return, stop */
.globl bug
bug:
        li     r0, 0x80                                      ;
        mtlr   r0                                            ;
        blr                                                  ;
_return_loop:
        b      _return_loop                                  ;

.section .data
.align 2
saved_params:
        .long 0x00000000 /* OF stack     */
        .long 0x00000000 /* client stack */
        .long 0x00000000 /* client link  */
        
.section .text
.align 2

.globl transfer_handler
transfer_handler:
        /* Build a new stack room and launch loaded image
         * void transfer_handler (void *residual, void *load_addr,
         *                        void *OF_entry, void *bootinfos,
         *                        void *cmdline, void *unused,
         *                        void *nip, void *stack_base);
         */
        mfmsr  r0                                            ;
        mtspr  SRR1, r0                                      ;
        mtspr  SRR0, r9                                      ;
        li     r0, 0                                         ;
        mr     r1, r10                                       ;
        stw    r1, -16(r1)                                   ;
        stwu   r0, -4(r1)                                    ;
        stwu   r0, -4(r1)                                    ;
        stwu   r0, -4(r1)                                    ;
        stwu   r0, -4(r1)                                    ;
        /* Skip frame pointer */        
        stwu   r0, -8(r1)                                    ;
        stwu   r0, -4(r1)                                    ;
        stwu   r0, -4(r1)                                    ;
        rfi                                                  ;
        /* Should never return, but who knows... */
        bl     bug                                           ;

.globl  OF_entry
OF_entry:
        /* Save the stack pointer and get our own one */
        lis    r11, saved_params@h                           ;
        ori    r11, r11, saved_params@l                      ;
        mflr   r12                                           ;
        stw    r12, 8(r11)                                   ;
        stw    r1, 4(r11)                                    ;
        lwz    r1, 0(r11)                                    ;
        bl     OF_client_entry                               ;
        lis    r11, saved_params@h                           ;
        ori    r11, r11, saved_params@l                      ;
        lwz    r12, 8(r11)                                   ;
        mtlr   r12                                           ;
        lwz    r1, 4(r11)                                    ;
        blr                                                  ;
        
        /* PPC helpers */
.globl mfmsr
mfmsr:
        /* uint32_t mfmsr (void); */
        mfmsr  r3                                            ;
        blr                                                  ;
.globl mtmsr
mtmsr:
        /* void mtmsr (uint32_t msr); */
        lis    r0, _mtmsr_rfi@h                              ;
        ori    r0, r0, _mtmsr_rfi@l                          ;
        mtspr  26, r0                                        ;
        mtspr  27, r3                                        ;
        rfi                                                  ;
_mtmsr_rfi:
        blr                                                  ;
.globl MMU_on
MMU_on:
        /* void MMU_on (void); */
        stwu   r1, -16(r1)                                   ;
        mflr   r0                                            ;
        stw    r0, 20(r1)                                    ;
        mfmsr  r3                                            ;
        ori    r3, r3, 0x30                                  ;
        bl     mtmsr                                         ;
        lwz    r0, 20(r1)                                    ;
        mtlr   r0                                            ;
        addi   r1, r1, 16                                    ;
        blr                                                  ;
        
.globl MMU_off
MMU_off:
        /* void MMU_off (void); */
        stwu   r1, -16(r1)                                   ;
        mflr   r0                                            ;
        stw    r0, 20(r1)                                    ;
        mfmsr  r3                                            ;
        andi.  r3, r3, 0xFFCF                                ;
        bl     mtmsr                                         ;
        lwz    r0, 20(r1)                                    ;
        mtlr   r0                                            ;
        addi   r1, r1, 16                                    ;
        blr                                                  ;
        
.globl mfpvr
mfpvr:
        /* uint32_t mfpvr (void); */
        mfpvr  r3                                            ;
        blr                                                  ;

.globl mftb
mftb:
        /* void mftb (uint32_t *tb); */
        stwu   r1, -16(r1)                                   ;
        stw    r11, 12(r1)                                   ;
        stw    r12,  8(r1)                                   ;
        /* No need to save lr */
_tb_loop:
        mftbu  r11                                           ;
        mftb   r12                                           ;
        mftbu  r0                                            ;
        cmpw   r0, r11                                       ;
        bne    _tb_loop                                      ;
        stw    r11,  0(r3)                                   ;
        stw    r12,  4(r3)                                   ;
        lwz    r12,  8(r1)                                   ;
        lwz    r11, 12(r1)                                   ;
        addi   r1, r1, 16                                    ;
        blr                                                  ;      

        /* IO helpers */
.globl inb
inb:
        /* uint32_t inb (uint16_t port); */
        stwu   r1, -16(r1)                                   ;
        stw    r11, 12(r1)                                   ;
        lis    r11, isa_io_base@h                            ;
        ori    r11, r11, isa_io_base@l                       ;
        lwz    r11, 0(r11)                                   ;
        add    r3, r3, r11                                   ;
        lbz    r3, 0(r3)                                     ;
        eieio                                                ;
        lwz    r11, 12(r1)                                   ;
        addi   r1, r1, 16                                    ;
        blr                                                  ;

.globl outb
outb:
        /* void outb (uint16_t port, uint32_t val); */
        stwu   r1, -16(r1)                                   ;
        stw    r11, 12(r1)                                   ;
        lis    r11, isa_io_base@h                            ;
        ori    r11, r11, isa_io_base@l                       ;
        lwz    r11, 0(r11)                                   ;
        add    r3, r3, r11                                   ;
        eieio                                                ;
        stb    r4, 0(r3)                                     ;
        lwz    r11, 12(r1)                                   ;
        addi   r1, r1, 16                                    ;
        blr                                                  ;

.globl inw
inw:
        /* uint32_t inw (uint16_t port); */
        stwu   r1, -16(r1)                                   ;
        stw    r11, 12(r1)                                   ;
        lis    r11, isa_io_base@h                            ;
        ori    r11, r11, isa_io_base@l                       ;
        lwz    r11, 0(r11)                                   ;
        add    r3, r3, r11                                   ;
        lhbrx  r3, 0, r3                                     ;
        eieio                                                ;
        lwz    r11, 12(r1)                                   ;
        addi   r1, r1, 16                                    ;
        blr                                                  ;

.globl outw
outw:
        /* void outw (uint16_t port, uint32_t val); */
        stwu   r1, -16(r1)                                   ;
        stw    r11, 12(r1)                                   ;
        lis    r11, isa_io_base@h                            ;
        ori    r11, r11, isa_io_base@l                       ;
        lwz    r11, 0(r11)                                   ;
        add    r3, r3, r11                                   ;
        eieio                                                ;
        sthbrx r4, 0, r3                                     ;
        lwz    r11, 12(r1)                                   ;
        addi   r1, r1, 16                                    ;
        blr                                                  ;

.globl inl
inl:
        /* uint32_t inl (uint16_t port); */
        stwu   r1, -16(r1)                                   ;
        stw    r11, 12(r1)                                   ;
        lis    r11, isa_io_base@h                            ;
        ori    r11, r11, isa_io_base@l                       ;
        lwz    r11, 0(r11)                                   ;
        add    r3, r3, r11                                   ;
        lwbrx  r3, 0, r3                                     ;
        eieio                                                ;
        lwz    r11, 12(r1)                                   ;
        addi   r1, r1, 16                                    ;
        blr                                                  ;

.globl outl
outl:
        /* void outl (uint16_t port, uint32_t val); */
        stwu   r1, -16(r1)                                   ;
        stw    r11, 12(r1)                                   ;
        lis    r11, isa_io_base@h                            ;
        ori    r11, r11, isa_io_base@l                       ;
        lwz    r11, 0(r11)                                   ;
        add    r3, r3, r11                                   ;
        eieio                                                ;
        stwbrx r4, 0, r3                                     ;
        lwz    r11, 12(r1)                                   ;
        addi   r1, r1, 16                                    ;
        blr                                                  ;

.globl eieio
eieio:
        eieio                                                ;
        blr                                                  ;
        
        /* Misc helpers */
.globl ldswap16
ldswap16:
        /* uint16_t ldswap16 (uint16_t *addr); */
        lhbrx  r3, 0, r3                                     ;
        blr                                                  ;

.globl stswap16
stswap16:
        /* void stswap16 (void *addr, uint16_t val); */
        sthbrx r4, 0, r3                                     ;
        blr                                                  ;

.globl ldswap32
ldswap32:
        /* uint32_t ldswap32 (uint32_t *addr); */
        lwbrx  r3, 0, r3                                     ;
        blr                                                  ;

.globl stswap32
stswap32:
        /* void stswap32 (void *addr, uint32_t val); */
        stwbrx r4, 0, r3                                     ;
        blr                                                  ;

.globl mul64
mul64:
        /* void mul64 (uint32_t *ret, uint32_t a, uint32_t b); */
        mulhwu r0, r4, r5                                    ;
        stw    r0, 0(r3)                                     ;
        mullw  r0, r4, r5                                    ;
        stw    r0, 4(r3)                                     ;
        blr                                                  ;

.globl add64
add64:
        /* void add64 (uint32_t *ret, uint32_t *a, uint32_t *b); */
        stwu   r1, -16(r1)                                   ;
        stw    r11, 12(r1)                                   ;
        stw    r12,  8(r1)                                   ;
        lwz    r11,  4(r4)                                   ;
        lwz    r12,  4(r5)                                   ;
        addc   r0, r11, r12                                  ;
        stw    r0,   4(r3)                                   ;
        lwz    r11,  0(r4)                                   ;
        lwz    r12,  0(r5)                                   ;
        adde   r0, r11, r12                                  ;
        stw    r0,   0(r3)                                   ;
        lwz    r12,  8(r1)                                   ;
        lwz    r11,  4(r1)                                   ;
        addi   r1, r1, 16                                    ;
        blr                                                  ;

.globl setjmp
setjmp:
        /* int setjmp (jmp_buf env); */
        /* save gprs */
        stmw   r0, 0(r3)                                     ;
        /* save lr, ctr, xer and ccr */
        mflr   r0                                            ;
        stw    r0, 0x80(r3)                                  ;
        mfctr  r0                                            ;
        stw    r0, 0x84(r3)                                  ;
        mfxer  r0                                            ;
        stw    r0, 0x88(r3)                                  ;
        mfcr   r0                                            ;
        stw    r0, 0x8C(r3)                                  ;
        /* return 0 */
        li     r3, 0                                         ;
        blr                                                  ;

.globl longjmp
longjmp:
        /* void longjmp (jmp_buf env, int val); */
        /* Let's pretend env is our stack */
        mr     r1, r3                                        ;
        /* Be sure we won't return 0 */
        cmpi   0, r4, 0                                      ;
        bne    _longjmp_cont                                 ;
        addi   r4, r4, 1                                     ;
_longjmp_cont:
        /* Store return value in jmp_buf */
        stw    r4, 0x0C(r1)                                  ;
        /* restore lr, ctr, xer and ccr */
        lwz    r0, 0x80(r1)                                  ;
        mtlr   r0                                            ;
        lwz    r0, 0x84(r1)                                  ;
        mtctr  r0                                            ;
        lwz    r0, 0x88(r1)                                  ;
        mtxer  r0                                            ;
        lwz    r0, 0x8C(r1)                                  ;
        mtcr   r0                                            ;
        /* Restore r2 to r31 */
        lmw    r2, 0x08(r1)                                  ;
        /* Restore r0 (could forget it...) */
        lwz    r0, 0x00(r1)                                  ;
        /* Restore stack */
        lwz    r1, 0x04(r1)                                  ;
        /* Return */
        blr                                                  ;
