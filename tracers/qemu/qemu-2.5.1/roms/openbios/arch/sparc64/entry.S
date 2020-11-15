/**
 ** Standalone startup code for Linux PROM emulator.
 ** Copyright 1999 Pete A. Zaitcev
 ** This code is licensed under GNU General Public License.
 **/
/*
 * $Id: head.S,v 1.12 2002/07/23 05:47:09 zaitcev Exp $
 */

#define __ASSEMBLY__
#include <asm/asi.h>
#include "pstate.h"
#include "lsu.h"
#define NO_QEMU_PROTOS
#define NO_OPENBIOS_PROTOS
#include "arch/common/fw_cfg.h"

#define PROM_ADDR 0x1fff0000000
#define CFG_ADDR  0x1fe02000510
#define HZ        1 * 1000 * 1000
#define TICK_INT_DIS 0x8000000000000000

        .globl	entry, _entry

	.section ".text", "ax"
	.align	8
        .register %g2, #scratch
        .register %g3, #scratch
        .register %g6, #scratch
        .register %g7, #scratch

/*
 * Entry point
 * We start execution from here.
 */
_entry:
entry:
        ! Set up CPU state
        wrpr    %g0, PSTATE_PRIV, %pstate
        wr      %g0, 0, %fprs
        wrpr    %g0, 0x0, %tl

        ! Extract NWINDOWS from %ver
        rdpr    %ver, %g1
        and     %g1, 0xf, %g1
        dec     %g1
        wrpr    %g1, 0, %cleanwin
        wrpr    %g1, 0, %cansave
        wrpr    %g0, 0, %canrestore
        wrpr    %g0, 0, %otherwin
        wrpr    %g0, 0, %wstate
        ! disable timer now
        setx    TICK_INT_DIS, %g2, %g1
        wr      %g1, 0, %tick_cmpr

        ! Disable I/D MMUs and caches
        stxa    %g0, [%g0] ASI_LSU_CONTROL

        ! Check signature "QEMU"
        setx    CFG_ADDR, %g2, %g5
        mov     FW_CFG_SIGNATURE, %g2
        stha    %g2, [%g5] ASI_PHYS_BYPASS_EC_E_L
        inc     %g5
        lduba   [%g5] ASI_PHYS_BYPASS_EC_E, %g2
        cmp     %g2, 'Q'
        bne     bad_conf
         nop
        lduba   [%g5] ASI_PHYS_BYPASS_EC_E, %g2
        cmp     %g2, 'E'
        bne     bad_conf
         nop
        lduba   [%g5] ASI_PHYS_BYPASS_EC_E, %g2
        cmp     %g2, 'M'
        bne     bad_conf
         nop
        lduba   [%g5] ASI_PHYS_BYPASS_EC_E, %g2
        cmp     %g2, 'U'
        bne     bad_conf
         nop

        ! Clear ITLB
        mov     6 << 3, %g1
        stxa    %g0, [%g1] ASI_IMMU
        stxa    %g0, [%g1] ASI_DMMU
        mov     63 << 3, %g1
1:      stxa    %g0, [%g1] ASI_ITLB_DATA_ACCESS
        subcc   %g1, 1 << 3, %g1
        bpos    1b
         nop

        ! Clear DTLB
        mov     63 << 3, %g1
1:      stxa    %g0, [%g1] ASI_DTLB_DATA_ACCESS
        subcc   %g1, 1 << 3, %g1
        bpos    1b
         nop

        ! Get memory size from configuration device
        ! NB: little endian format
        mov     FW_CFG_RAM_SIZE, %g2
        dec     %g5
        stha    %g2, [%g5] ASI_PHYS_BYPASS_EC_E_L
        inc     %g5
        lduba   [%g5] ASI_PHYS_BYPASS_EC_E, %g4

        lduba   [%g5] ASI_PHYS_BYPASS_EC_E, %g3
        sllx    %g3, 8, %g3
        or      %g3, %g4, %g4

        lduba   [%g5] ASI_PHYS_BYPASS_EC_E, %g3
        sllx    %g3, 16, %g3
        or      %g3, %g4, %g4

        lduba   [%g5] ASI_PHYS_BYPASS_EC_E, %g3
        sllx    %g3, 24, %g3
        or      %g3, %g4, %g4

        lduba   [%g5] ASI_PHYS_BYPASS_EC_E, %g3
        sllx    %g3, 32, %g3
        or      %g3, %g4, %g4

        lduba   [%g5] ASI_PHYS_BYPASS_EC_E, %g3
        sllx    %g3, 40, %g3
        or      %g3, %g4, %g4

        lduba   [%g5] ASI_PHYS_BYPASS_EC_E, %g3
        sllx    %g3, 48, %g3
        or      %g3, %g4, %g4

        lduba   [%g5] ASI_PHYS_BYPASS_EC_E, %g3
        sllx    %g3, 56, %g3
        or      %g3, %g4, %g1
        ! %g1 contains end of memory

        setx    _end, %g7, %g3
        set     0x7ffff, %g2
        add     %g3, %g2, %g3
        andn    %g3, %g2, %g3
        setx    _data, %g7, %g2
        sub     %g3, %g2, %g2
        sub	%g1, %g2, %g2			! %g2 = start of private memory
        mov     %g2, %l0

	! setup .data & .bss
        setx    _data, %g7, %g4
        sub     %g3, %g4, %g5
        srlx    %g5, 19, %g6			! %g6 = # of 512k .bss pages
	set	0xc0000000, %g3
	sllx	%g3, 32, %g3
	or	%g3, 0x76, %g3
	! valid, 512k, locked, cacheable(I/E/C), priv, writable
	set	48, %g7
1:	stxa	%g4, [%g7] ASI_DMMU		! vaddr = _data + N * 0x80000, ctx=0
	or	%g2, %g3, %g5
	! paddr = start_mem + N * 0x80000
	stxa	%g5, [%g0] ASI_DTLB_DATA_IN
	set	0x80000, %g5
	add	%g2, %g5, %g2
	add	%g4, %g5, %g4
	deccc	%g6
	bne	1b
	 nop

	! setup .rodata, also make .text readable
	setx	_data, %g7, %g5
	setx	_start, %g7, %g4
        sub     %g5, %g4, %g5
	srlx    %g5, 19, %g6			! %g6 = # of 512k .rodata pages
	set	48, %g7
	set	0x80000, %g5
        setx    PROM_ADDR, %l1, %l2
1:      stxa	%g4, [%g7] ASI_DMMU		! vaddr = _rodata, ctx=0
	set	0xc0000000, %g3
	sllx	%g3, 32, %g3
	or	%g3, 0x74, %g3
	or	%l2, %g3, %g3
	! valid, 512k, locked, cacheable(I/E/C), priv
	! paddr = _rodata + N * 0x10000
	stxa	%g3, [%g0] ASI_DTLB_DATA_IN
	add	%g4, %g5, %g4
	deccc	%g6
	bne	1b
	 add	%l2, %g5, %l2

	membar	#Sync

	setx	_start, %g7, %g4
	setx	_rodata, %g7, %g5
        sub     %g5, %g4, %g5
	set 0x7ffff, %g7
	add %g5, %g7, %g5					! round to 512k
        srlx    %g5, 19, %g6			! %g6 = # of 512k .text pages
	set	0x80000, %g5
	set	48, %g7
        setx    PROM_ADDR, %l1, %l2
1:      stxa	%g4, [%g7] ASI_IMMU		! vaddr = _start, ctx=0
	set	0xc0000000, %g3
	sllx	%g3, 32, %g3
	or	%g3, 0x74, %g3
	or	%l2, %g3, %g3
	! valid, 512k, locked, cacheable(I/E/C), priv
	! paddr = _start + N * 0x80000
	stxa	%g3, [%g0] ASI_ITLB_DATA_IN
	add	%g4, %g5, %g4
	deccc	%g6
	bne	1b
	 add	%l2, %g5, %l2

	flush	%g4

	mov	%g1, %g3

	set     8, %g2
	sta     %g0, [%g2] ASI_DMMU		! set primary ctx=0

	! Enable I/D MMUs and caches
        setx    lowmem, %g2, %g1
	set	LSU_CONTROL_DM|LSU_CONTROL_IM|LSU_CONTROL_DC|LSU_CONTROL_IC, %g2
        jmp     %g1
         stxa	%g2, [%g0] ASI_LSU_CONTROL

lowmem:
        /* Copy the DATA section from ROM. */
        setx	_data - 8, %o7, %o0             ! First address of DATA
        setx	_bss, %o7, %o1                  ! Last address of DATA
        setx    _start, %o7, %o2
        sub     %o0, %o2, %o2                   ! _data - _start
        setx    PROM_ADDR, %o7, %o3
        add     %o3, %o2, %o2                   ! PROM_ADDR + (_data - _start)
        ba	2f
         nop
1:
        ldxa    [%o2] ASI_PHYS_BYPASS_EC_E, %g1
        stx	%g1, [%o0]
2:
        add	%o2, 0x8, %o2
        subcc	%o0, %o1, %g0
        bl	1b
         add	%o0, 0x8, %o0

        /* Zero out our BSS section. */
        setx    _bss - 8, %o7, %o0              ! First address of BSS
        setx    _end - 8, %o7, %o1                  ! Last address of BSS
        ba	2f
         nop
1:
        stx     %g0, [%o0]
2:
        subcc	%o0, %o1, %g0
        bl	1b
         add	%o0, 0x8, %o0

        setx    trap_table, %g2, %g1
        wrpr    %g1, %tba

        setx    qemu_mem_size, %g7, %g1
        stx     %g3, [%g1]

        setx    _data, %g7, %g1                 ! Store va->pa conversion factor
        sub     %g1, %l0, %g2
        setx    va_shift, %g7, %g1
        stx     %g2, [%g1]

        /* Finally, turn on traps so that we can call c-code. */
	wrpr    %g0, (PSTATE_PRIV|PSTATE_PEF|PSTATE_IE), %pstate

        ! 100 Hz timer
        setx    TICK_INT_DIS, %g2, %g1
        rd      %tick, %g2
        andn    %g2, %g1, %g2
        set     HZ, %g1
        add     %g1, %g2, %g1
        wr      %g1, 0, %tick_cmpr

        /* Switch to our main context.
         * Main context is statically defined in C.
         */

        call    __switch_context_nosave
         nop

        /* We get here when the main context switches back to
         * the boot context.
         */
bad_conf:
        b       bad_conf
         nop
