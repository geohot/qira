/**
 ** Standalone startup code for Linux PROM emulator.
 ** Copyright 1999 Pete A. Zaitcev
 ** This code is licensed under GNU General Public License.
 **/
/*
 * $Id: head.S,v 1.12 2002/07/23 05:47:09 zaitcev Exp $
 */

#define __ASSEMBLY
#include "psr.h"
#include "asm/asi.h"
#include "asm/crs.h"
#define NO_QEMU_PROTOS
#define NO_OPENBIOS_PROTOS
#include "arch/common/fw_cfg.h"

#define CFG_ADDR 0x00000510
#define CFG_ASI  0x2d

#define PHYS_JJ_INTR0	0x71E00000  /* CPU0 interrupt control registers */

#define PHYS_SS10_INTR0 	0xf1400000

#define PHYS_SS2_INTR0 	0xf5000000
#define SER_ADDR2       0xf1000004

#define PHYS_SS1000_SBI         0x02800000
#define SER_ADDR1000            0x00200004

#define WRITE_PAUSE    nop; nop; nop; /* Have to do this after %wim/%psr chg */

        .globl	entry, _entry

	.section ".text", "ax"
	.align	8

        /* Memory map:
	 *
	 * Top +-------------------------+
	 *     | SMP CPU table           |
	 *     | s + 0x1f00 ... 0x1f0f   |
	 *     | s + 0x1f0c valid        |
	 *     | s + 0x1f08 entry        |
	 *     | s + 0x1f04 ctxtbl       |
	 *     | s + 0x1f00 ctx          |
	 *     +-------------------------+
	 *     | Bootstrap               |
	 *     | MMU L3 tables 8 * 0x100 |
	 *     | s + 0xa00 ... 0x11ff    |
	 *     +-------------------------+
	 *     | Bootstrap               |
	 *     | MMU L2 tables 2 * 0x100 |
	 *     | s + 0x800 ... 0x9ff     |
	 *     +-------------------------+
	 *     | Bootstrap               |
	 *     | MMU L1 table 0x400      |
	 *     | s + 0x400 ... 0x7ff     |
	 *     +-------------------------+
	 *     | Bootstrap               |
	 *     | MMU L0/ctx table 0x400  |
	 *     | s + 0x000 ... 0x3ff     |
	 *     +-------------------------+
	 *     |                         |
	 *     | ROM into RAM            |
	 *     |                         |
	 *     +-------------------------+
	 *     :                         :
	 * Bottom
	 */

/*
 * Entry point
 * We start execution from here.
 */
_entry:
entry:
        /* Switch to our main context.
         * Main context is statically defined in C.
         */

        ! Check signature "QEMU"
        set     CFG_ADDR, %g5
        mov     FW_CFG_SIGNATURE, %g2
        stha    %g2, [%g5] CFG_ASI
        add     %g5, 2, %g5
        lduba   [%g5] CFG_ASI, %g2
        cmp     %g2, 'Q'
        bne     bad_conf
         nop
        lduba   [%g5] CFG_ASI, %g2
        cmp     %g2, 'E'
        bne     bad_conf
         nop
        lduba   [%g5] CFG_ASI, %g2
        cmp     %g2, 'M'
        bne     bad_conf
         nop
        lduba   [%g5] CFG_ASI, %g2
        cmp     %g2, 'U'
        bne     bad_conf
         nop

        ! Get memory size from configuration device
        ! NB: little endian format
        mov     FW_CFG_RAM_SIZE, %g2
        sub     %g5, 2, %g5
        stha    %g2, [%g5] CFG_ASI
        add     %g5, 2, %g5
        lduba   [%g5] CFG_ASI, %g4

        lduba   [%g5] CFG_ASI, %g3
        sll     %g3, 8, %g3
        or      %g3, %g4, %g4

        lduba   [%g5] CFG_ASI, %g3
        sll     %g3, 16, %g3
        or      %g3, %g4, %g4

        lduba   [%g5] CFG_ASI, %g3
        sll     %g3, 24, %g3
        or      %g3, %g4, %g1
        ! %g1 contains end of memory

        ! Get kernel address from configuration device
        ! NB: little endian format
        mov     FW_CFG_KERNEL_ADDR, %g2
        sub     %g5, 2, %g5
        stha    %g2, [%g5] CFG_ASI
        add     %g5, 2, %g5
        lduba   [%g5] CFG_ASI, %g4

        lduba   [%g5] CFG_ASI, %g3
        sll     %g3, 8, %g3
        or      %g3, %g4, %g4

        lduba   [%g5] CFG_ASI, %g3
        sll     %g3, 16, %g3
        or      %g3, %g4, %g4

        lduba   [%g5] CFG_ASI, %g3
        sll     %g3, 24, %g3
        or      %g3, %g4, %g4

        ! If kernel address is set, don't clear from base of RAM in order to
        ! leave the kernel image intact
        mov     0, %g6
        cmp     %g4, 0
        beq     clear_mem
         nop

        ! Start from 16M
        set     0x1000000, %g6

clear_mem:
        sta     %g0, [%g6] ASI_M_BYPASS
        add     %g6, 0x4, %g6
        cmp     %g6, %g1
        bl      clear_mem
         nop

clear_done:
        ! Start of private memory in %g6
        set     0x2000, %g3
        sub     %g1, %g3, %g6

        ! Check if this is the boot CPU and skip SMP table check if yes
        ! XXX: not all CPUs should have MXCC
        set     0x1c00f00, %g2
        ldda    [%g2] ASI_CONTROL, %g2
        srl     %g3, 24, %g7
        sub     %g7, 8, %g7
        tst     %g7
        bz      skip_table
         nop

        ! Calculate SMP table location
	set	0x1f0c, %g2
        add     %g6, %g2, %g2                 ! valid?
        lda     [%g2] ASI_M_BYPASS, %g7
        sta     %g0, [%g2] ASI_M_BYPASS

skip_table:
        ! Get machine ID from configuration device
        mov     FW_CFG_MACHINE_ID, %g2
        sub     %g5, 2, %g5
        stha    %g2, [%g5] CFG_ASI
        add     %g5, 2, %g5
        lduba   [%g5] CFG_ASI, %g4

        lduba   [%g5] CFG_ASI, %g3
        sll     %g3, 8, %g3
        or      %g3, %g4, %g4
        mov     %g4, %y

        cmp     %g4, 96
        bgeu    ss1000
         cmp    %g4, 64
        bgeu    ss10
         cmp    %g4, 32
        blu     ss2
         nop

        ! Ok, this is SS-5

        tst     %g7
        bz      first_cpu
         nop

        ! Clear softints used for SMP CPU startup
        set     PHYS_JJ_INTR0 + 0x04, %g1
        sll     %g2, 12, %g2
        add     %g1, %g2, %g2
        set     0xffffffff, %g1
        sta     %g1, [%g2] ASI_M_BYPASS         ! clear softints
        add     %g2, 4, %g2
        sta     %g0, [%g2] ASI_M_BYPASS         ! clear softints

load_ctx:
        ! SMP init, jump to user specified address
	set	0x1f04, %g5
        add     %g6, %g5, %g5                 ! ctxtbl
        lda     [%g5] ASI_M_BYPASS, %g2
        sta     %g0, [%g5] ASI_M_BYPASS
        set     AC_M_CTPR, %g1
        sta     %g2, [%g1] ASI_M_MMUREGS        ! set ctx table ptr
	set	0x1f00, %g5
        add     %g6, %g5, %g5                 ! ctx
        lda     [%g5] ASI_M_BYPASS, %g2
        sta     %g0, [%g5] ASI_M_BYPASS
        set     AC_M_CXR, %g1
        sta     %g2, [%g1] ASI_M_MMUREGS        ! set context
	set	0x1f08, %g5
        add     %g6, %g5, %g5                 ! entry
        lda     [%g5] ASI_M_BYPASS, %g2
        sta     %g0, [%g5] ASI_M_BYPASS
        set     1, %g1
        jmp     %g2                             ! jump to kernel
         sta    %g1, [%g0] ASI_M_MMUREGS        ! enable mmu

ss10:
        ! Ok, this is SS-10 or SS-600MP
        tst     %g7
        bz      first_cpu
         nop

        ! Clear softints used for SMP CPU startup
        set     PHYS_SS10_INTR0 + 0x04, %g1
        sll     %g2, 12, %g2
        add     %g1, %g2, %g2
        set     0xffffffff, %g1
        sta     %g1, [%g2] ASI_M_CTL            ! clear softints
        add     %g2, 4, %g2
        b       load_ctx
         sta    %g0, [%g2] ASI_M_CTL            ! clear softints

ss2:
        ! Ok, this is SS-2
        set     ss2_error, %o2
        b       ss2_ss1000_halt
         nop

ss1000:
        ! Ok, this is SS-1000 or SS-2000
        set     ss1000_error, %o2
        b       ss2_ss1000_halt
         nop

first_cpu:
        /* Create temporary page tables and map the ROM area to end of
	RAM. This will be done properly in iommu.c later. */
        ! Calculate start of page tables etc. to %g6
        set     0x2000, %g4
        sub     %g1, %g4, %g6                   ! start of private memory

        mov     %g6, %g2                        ! ctx table at s+0x0
        add	%g2, 0x400, %g3			! l1 table at s+0x400
        srl	%g3, 0x4, %g3
        or	%g3, 0x1, %g3
        sta	%g3, [%g2] ASI_M_BYPASS
        add	%g2, 0x400, %g2			! s+0x400
        add	%g2, 0x400, %g3			! l2 table for ram (00xxxxxx) at s+0x800
        srl	%g3, 0x4, %g3
        or	%g3, 0x1, %g3
        sta	%g3, [%g2] ASI_M_BYPASS
        add	%g2, 0x500, %g3			! l2 table for rom (ffxxxxxx) at s+0x900
        add	%g2, 0x3fc, %g2			! s+0x7fc
        srl	%g3, 0x4, %g3
        or	%g3, 0x1, %g3
        sta	%g3, [%g2] ASI_M_BYPASS
        add	%g2, 0x4, %g2			! s+0x800
#if 0
        set     0x40, %g6
        set	((7 << 2) | 2), %g3		! 7 = U: --- S: RWX (main memory)
1:      sta	%g3, [%g2] ASI_M_BYPASS
        add     %g2, 4, %g2
        deccc   %g6
        bne     1b
         nop
#else
        add     %g2, 0x100, %g2
#endif
                                                ! s+0x900
        add	%g2, 0xa00 - 0x900, %g3		! l3 table for rom at s+0xa00
        add	%g2, 0x0d0, %g2			! s+0x9d0
        srl	%g3, 0x4, %g3
        or	%g3, 0x1, %g3
        sta	%g3, [%g2] ASI_M_BYPASS
        add	%g2, 4, %g2			! s+0x9d4
        add	%g2, 0xb00 - 0x9d4, %g3		! 2nd l3 table for rom at s+0xb00
        srl	%g3, 0x4, %g3
        or	%g3, 0x1, %g3
        sta	%g3, [%g2] ASI_M_BYPASS
        add	%g2, 4, %g2			! s+0x9d8
        add	%g2, 0xc00 - 0x9d8, %g3		! 3rd l3 table for rom at s+0xc00
        srl	%g3, 0x4, %g3
        or	%g3, 0x1, %g3
        sta	%g3, [%g2] ASI_M_BYPASS
        add	%g2, 4, %g2			! s+0x9dc
        add	%g2, 0xd00 - 0x9dc, %g3		! 4th l3 table for rom at s+0xd00
        srl	%g3, 0x4, %g3
        or	%g3, 0x1, %g3
        sta	%g3, [%g2] ASI_M_BYPASS
        add	%g2, 4, %g2			! s+0x9e0
        add	%g2, 0xe00 - 0x9e0, %g3		! 5th l3 table for rom at s+0xe00
        srl	%g3, 0x4, %g3
        or	%g3, 0x1, %g3
        sta	%g3, [%g2] ASI_M_BYPASS
        add	%g2, 4, %g2			! s+0x9e4
        add	%g2, 0xf00 - 0x9e4, %g3		! 6th l3 table for rom at s+0xf00
        srl	%g3, 0x4, %g3
        or	%g3, 0x1, %g3
        sta	%g3, [%g2] ASI_M_BYPASS
        add	%g2, 4, %g2			! s+0x9e8
        add	%g2, 0x1000 - 0x9e8, %g3	! 7th l3 table for rom at s+0x1000
        srl	%g3, 0x4, %g3
        or	%g3, 0x1, %g3
        sta	%g3, [%g2] ASI_M_BYPASS
        add	%g2, 4, %g2			! s+0x9ec
        add	%g2, 0x1100 - 0x9ec, %g3	! 8th l3 table for rom at s+0x1100
        srl	%g3, 0x4, %g3
        or	%g3, 0x1, %g3
        sta	%g3, [%g2] ASI_M_BYPASS
      add	%g2, 0xa00-0x9ec, %g2		! s+0xa00

        /* Use end of ram for code, rodata, data, and bss
	sections. SunOS wants to write to trap table... */
        set	_end, %g6
        set	_start, %g4
        sub     %g6, %g4, %g6
        sub     %g1, %g6, %g3
        set	0x1000, %g5
        sub     %g3, %g5, %g3
        sub     %g3, %g5, %g3                   ! start of ROM copy
        mov     %g3, %g7                        ! save in %g7
        srl     %g6, 12, %g6                    ! # of all pages
1:      srl	%g3, 0x4, %g4
        or	%g4, ((7 << 2) | 2), %g4        ! 7 = U: --- S: RWX
        sta	%g4, [%g2] ASI_M_BYPASS
        add	%g2, 4, %g2
        add	%g3, %g5, %g3
        deccc	%g6
        bne	1b
         nop

        mov	%g1, %g6                        ! %g6 = memory size

        /* Copy the code, rodata and data sections from ROM. */
        sub     %g7, 4, %g3
        set	_start - 4, %g4                 ! First address of TEXT - 4
        set	_bss, %g5                       ! Last address of DATA
        ba	2f
         nop
1:
        lda     [%g4] ASI_M_KERNELTXT, %g1
        sta	%g1, [%g3] ASI_M_BYPASS
2:
        cmp     %g4, %g5
        add     %g3, 0x4, %g3
        bl      1b
         add    %g4, 0x4, %g4

        set     0x2000, %g3
        sub     %g6, %g3, %g7                   ! ctx table at s+0x0
        set     AC_M_CTPR, %g2
        srl     %g7, 4, %g7
        sta     %g7, [%g2] ASI_M_MMUREGS	! set ctx table ptr
        set     AC_M_CXR, %g2
        sta     %g0, [%g2] ASI_M_MMUREGS	! context 0
        set     highmem, %g2
        set	1, %g1
        jmp     %g2
         sta    %g1, [%g0] ASI_M_MMUREGS	! enable mmu
highmem:
        /*
         * The code which enables traps is a simplified version of
         * kernel head.S.
         *
         * We know number of windows as 8 so we do not calculate them.
         * The deadwood is here for any case.
         */

        /* Turn on Supervisor, EnableFloating, and all the PIL bits.
         * Also puts us in register window zero with traps off.
         */
        set	(PSR_PS | PSR_S | PSR_PIL | PSR_EF), %g2
        wr	%g2, 0x0, %psr
        WRITE_PAUSE

        /* Zero out our BSS section. */
        set	_bss - 4, %o0           ! First address of BSS
        set	_estack - 4, %o1        ! Last address of BSS
        ba	2f
         nop
1:
        st	%g0, [%o0]
2:
        subcc	%o0, %o1, %g0
        bl	1b
         add	%o0, 0x4, %o0

        set     trap_table, %g1
        wr      %g1, 0x0, %tbr

        set     qemu_mem_size, %g1
        st      %g6, [%g1]

        set     _end, %o0                       ! Store va->pa conversion factor
        set     _start, %o2
        sub     %o0, %o2, %o0
        sub     %g6, %o0, %o0
        set     0x2000, %o1
        sub     %o0, %o1, %o0                   ! start of ROM copy
        sub     %o2, %o0, %o0                   ! start of ROM copy
        set     va_shift, %g1
        st      %o0, [%g1]

        set     qemu_machine_type, %g1
        mov     %y, %g2
        st      %g2, [%g1]

        /* Compute NWINDOWS and stash it away. Now uses %wim trick explained
         * in the V8 manual. Ok, this method seems to work, Sparc is cool...
         * No, it doesn't work, have to play the save/readCWP/restore trick.
         */

        wr      %g0, 0x0, %wim                  ! so we do not get a trap
        WRITE_PAUSE

        save

        rd      %psr, %g3

        restore

        and     %g3, 0x1f, %g3
        add     %g3, 0x1, %g3

        mov     2, %g1
        wr      %g1, 0x0, %wim                  ! make window 1 invalid
        WRITE_PAUSE

        cmp     %g3, 0x7
        bne     1f
         nop

        /* Adjust our window handling routines to
         * do things correctly on 7 window Sparcs.
         */
#define PATCH_INSN(src, dest) \
        set     src, %g5; \
        set     dest, %g2; \
        ld      [%g5], %g4; \
        st      %g4, [%g2];

        /* Patch for window spills... */
        PATCH_INSN(spnwin_patch1_7win, spnwin_patch1)
        PATCH_INSN(spnwin_patch2_7win, spnwin_patch2)

        /* Patch for window fills... */
        PATCH_INSN(fnwin_patch1_7win, fnwin_patch1)
        PATCH_INSN(fnwin_patch2_7win, fnwin_patch2)

1:
        /* Finally, turn on traps so that we can call c-code. */
        rd	%psr, %g3
        wr	%g3, 0x0, %psr
        WRITE_PAUSE

        wr	%g3, PSR_ET, %psr
        WRITE_PAUSE

        set     0, %fp
        call    __switch_context_nosave
         nop

        /* We get here when the main context switches back to
         * the boot context.
         * Return to previous bootloader.
         */
        ret
         nop

ss2_ss1000_halt:
        set     SER_ADDR2, %o0
        set     SER_ADDR1000, %o1
        mov     0x05, %o3 /* Reg 5, TXCTRL2 */
        stba    %o3, [%o0] ASI_M_BYPASS
        stba    %o3, [%o1] ASI_M_CTL
        mov     0x68, %o3 /* 8 bits, Tx enabled */
        stba    %o3, [%o0] ASI_M_BYPASS
        stba    %o3, [%o1] ASI_M_CTL
        add     %o0, 2, %o0
        add     %o1, 2, %o1

1:      lduba   [%o2] ASI_M_KERNELTXT, %o3
        cmp     %o3, 0
        be      2f
         nop
        stba    %o3, [%o0] ASI_M_BYPASS
        stba    %o3, [%o1] ASI_M_CTL
        b       1b
         inc    %o2
bad_conf:
2:      b       2b
         nop

        .section .rodata
ss2_error:
        .string "Sun4c machines are not supported by OpenBIOS yet, freezing\r\n"
ss1000_error:
        .string "Sun4d machines are not supported by OpenBIOS yet, freezing\r\n"
