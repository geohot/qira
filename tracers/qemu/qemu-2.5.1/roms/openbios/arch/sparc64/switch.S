#include "pstate.h"
#include <asm/asi.h>
#define ASI_BP ASI_M_BYPASS
#define REGWIN_SZ   0x40

	.globl	__switch_context, __switch_context_nosave, __exit_context, halt

	.text
	.align	4
        .register %g2, #scratch
        .register %g3, #scratch
        .register %g6, #scratch
        .register %g7, #scratch

/*
 * Switch execution context
 * This saves registers in the stack, then
 * switches the stack, and restores everything from the new stack.
 * This function takes no argument. New stack pointer is
 * taken from global variable __context, and old stack pointer
 * is also saved to __context. This way we can just jump to
 * this routine to get back to the original context.
 */

/* XXX: totally bogus for sparc, need to save and restore all windows */
__switch_context:

	/* make sure caller's windows are on caller's stack */
	flushw;

	/* Save everything in current stack */

	setx	__context, %g2, %g1
        stx     %g3, [%g1 + 24]
        stx     %g4, [%g1 + 32]
        stx     %g5, [%g1 + 40]
        stx     %g6, [%g1 + 48]
        stx     %g7, [%g1 + 56]

        stx     %o0, [%g1 + 64]
        stx     %o1, [%g1 + 72]
        stx     %o2, [%g1 + 80]
        stx     %o3, [%g1 + 88]
        stx     %o4, [%g1 + 96]
        stx     %o5, [%g1 + 104]
        stx     %o6, [%g1 + 112]
        stx     %o7, [%g1 + 120]

        stx     %l0, [%g1 + 128]
        stx     %l1, [%g1 + 136]
        stx     %l2, [%g1 + 144]
        stx     %l3, [%g1 + 152]
        stx     %l4, [%g1 + 160]
        stx     %l5, [%g1 + 168]
        stx     %l6, [%g1 + 176]
        stx     %l7, [%g1 + 184]

        stx     %i0, [%g1 + 192]
        stx     %i1, [%g1 + 200]
        stx     %i2, [%g1 + 208]
        stx     %i3, [%g1 + 216]
        stx     %i4, [%g1 + 224]
        stx     %i5, [%g1 + 232]
        stx     %i6, [%g1 + 240]
        stx     %i7, [%g1 + 248]

__switch_context_nosave:
	/* Interrupts are not allowed... */
	/* make sure caller's windows are on caller's stack */
	flushw
	/* Load all registers
	 */
	setx	__context, %g2, %g1
        ldx     [%g1], %g1
        ldx     [%g1 + 16], %g2
        ldx     [%g1 + 24], %g3
        ldx     [%g1 + 32], %g4
        ldx     [%g1 + 40], %g5
        ldx     [%g1 + 48], %g6
        ldx     [%g1 + 56], %g7

        ldx     [%g1 + 64], %o0
        ldx     [%g1 + 72], %o1
        ldx     [%g1 + 80], %o2
        ldx     [%g1 + 88], %o3
        ldx     [%g1 + 96], %o4
        ldx     [%g1 + 104], %o5
        ldx     [%g1 + 112], %o6
        ldx     [%g1 + 120], %o7

        ldx     [%g1 + 128], %l0
        ldx     [%g1 + 136], %l1
        ldx     [%g1 + 144], %l2
        ldx     [%g1 + 152], %l3
        ldx     [%g1 + 160], %l4
        ldx     [%g1 + 168], %l5
        ldx     [%g1 + 176], %l6
        ldx     [%g1 + 184], %l7

        ldx     [%g1 + 192], %i0
        ldx     [%g1 + 200], %i1
        ldx     [%g1 + 208], %i2
        ldx     [%g1 + 216], %i3
        ldx     [%g1 + 224], %i4
        ldx     [%g1 + 232], %i5
        ldx     [%g1 + 240], %i6
        ldx     [%g1 + 248], %i7

        ldx     [%g1 + 256], %g1
       	/* Finally, load new %pc */
        jmp     %g1
         clr    %g1

__exit_context:
	/* Get back to the original context */
	call	__switch_context
	 nop

	/* We get here if the other context attempt to switch to this
	 * dead context. This should not happen. */

halt:
	b	halt
	 nop
