#define __ASSEMBLY
#include "psr.h"
#include "asm/asi.h"
#define ASI_BP ASI_M_BYPASS
#define REGWIN_SZ   0x40

	.globl	__switch_context, __switch_context_nosave, __exit_context, halt

	.text
	.align	4

#define STACKFRAME_SZ     0x60

/* These are just handy. */
#define _SV	save	%sp, -STACKFRAME_SZ, %sp
#define _RS     restore

#define FLUSH_ALL_KERNEL_WINDOWS \
	_SV; _SV; _SV; _SV; _SV; _SV; _SV; \
	_RS; _RS; _RS; _RS; _RS; _RS; _RS;

/*
 * Switch execution context
 * This saves registers in the stack, then
 * switches the stack, and restores everything from the new stack.
 * This function takes no argument. New stack pointer is
 * taken from global variable __context, and old stack pointer
 * is also saved to __context. This way we can just jump to
 * this routine to get back to the original context.
 */

__switch_context:
        FLUSH_ALL_KERNEL_WINDOWS
	/* Save everything in stack */
        st      %fp, [%fp + 120 -144]
        add     %fp, -144, %fp
        st      %g1, [%fp + 4]
        st      %g2, [%fp + 8]
        st      %g3, [%fp + 12]
        st      %g4, [%fp + 16]
        st      %g5, [%fp + 20]
        st      %g6, [%fp + 24]
        st      %g7, [%fp + 28]

        st      %o0, [%fp + 32]
        st      %o1, [%fp + 36]
        st      %o2, [%fp + 40]
        st      %o3, [%fp + 44]
        st      %o4, [%fp + 48]
        st      %o5, [%fp + 52]
        st      %sp, [%fp + 56]
        st      %o7, [%fp + 60]

        st      %l0, [%fp + 64]
        st      %l1, [%fp + 68]
        st      %l2, [%fp + 72]
        st      %l3, [%fp + 76]
        st      %l4, [%fp + 80]
        st      %l5, [%fp + 84]
        st      %l6, [%fp + 88]
        st      %l7, [%fp + 92]

        st      %i0, [%fp + 96]
        st      %i1, [%fp + 100]
        st      %i2, [%fp + 104]
        st      %i3, [%fp + 108]
        st      %i4, [%fp + 112]
        st      %i5, [%fp + 116]
        st      %i7, [%fp + 124]

        /* ctx->return_address:  Return to caller */
        st      %o7, [%fp + 128]

	/* Interrupts are not allowed... */

	/* Turn on Supervisor, EnableFloating, and all the PIL bits.
	 * Also puts us in register window zero with traps off.
	 */
#if 0
	set	(PSR_PS | PSR_S | PSR_PIL | PSR_EF), %g2
	wr	%g2, 0x0, %psr
#endif
        set     __context, %g1
        /* Swap ctx pointer with %fp and jump*/
        ba     __set_context
         swap      [%g1], %fp
__switch_context_nosave:
        set     __context, %g1
        /* load %fp from ctx pointer */
        ld      [%g1], %fp
__set_context:
	/* Load all registers */
        /* offset 0: %g0, no need to load */
        ld      [%fp + 4], %g1
        ld      [%fp + 8], %g2
        ld      [%fp + 12], %g3
        ld      [%fp + 16], %g4
        ld      [%fp + 20], %g5
        ld      [%fp + 24], %g6
        ld      [%fp + 28], %g7

        /* offset 32: %o0, loaded from ctx->param */
        ld      [%fp + 36], %o1
        ld      [%fp + 40], %o2
        ld      [%fp + 44], %o3
        ld      [%fp + 48], %o4
        ld      [%fp + 52], %o5
        ld      [%fp + 56], %sp
        /* offset 60: %o7, loaded from ctx->return_addr */

        ld      [%fp + 64], %l0
        ld      [%fp + 68], %l1
        ld      [%fp + 72], %l2
        ld      [%fp + 76], %l3
        ld      [%fp + 80], %l4
        ld      [%fp + 84], %l5
        ld      [%fp + 88], %l6
        ld      [%fp + 92], %l7

        ld      [%fp + 96], %i0
        ld      [%fp + 100], %i1
        ld      [%fp + 104], %i2
        ld      [%fp + 108], %i3
        ld      [%fp + 112], %i4
        ld      [%fp + 116], %i5
        ld      [%fp + 124], %i7

        /* ctx->return_addr */
        ld      [%fp + 136], %o7

        /* ctx->param */
        ld      [%fp + 140], %o0

        /* ctx->pc, save %g1 to %y and load to %g1 */
        mov     %g1, %y
        ld      [%fp + 128], %g1
        /* %fp last */
        ld      [%fp + 120], %fp
        /* Finally, get the new %pc from %g1 and restore %g1*/
        jmp     %g1
         mov    %y, %g1

        FLUSH_ALL_KERNEL_WINDOWS
__exit_context:
	/* Get back to the original context */
	call	__switch_context
	 nop

	/* We get here if the other context attempt to switch to this
	 * dead context. This should not happen. */

halt:
	b	halt
	 nop
