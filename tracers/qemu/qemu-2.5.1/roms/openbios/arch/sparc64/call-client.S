	.globl	sparc64_of_client_interface, client_tba


/*
 * SAVE_WINDOW_STATE and RESTORE_WINDOW_STATE are used to ensure
 * that the CPU window state is preserved across CIF calls. This is
 * to workaround a *BSD restriction that window fill/spill traps must
 * be minimised during trap table takeover, and likely emulates the
 * behaviour of OBP.
 */

#define SAVE_WINDOW_STATE(type) \
	setx	client_window, %g6, %g1; \
	rdpr	%cwp, %g7; \
	stx	%g7, [%g1]; \
	rdpr	%cansave, %g7; \
	stx	%g7, [%g1 + 0x8]; \
	rdpr	%canrestore, %g7; \
	stx	%g7, [%g1 + 0x10]; \
	rdpr	%otherwin, %g7; \
	stx	%g7, [%g1 + 0x18]; \
	rdpr	%wstate, %g7; \
	stx	%g7, [%g1 + 0x20]; \
	rdpr	%cleanwin, %g7; \
	stx	%g7, [%g1 + 0x28]; \
	\
	stx	%o0, [%g1 + 0x30]; \
	stx	%o1, [%g1 + 0x38]; \
	stx	%o2, [%g1 + 0x40]; \
	stx	%o3, [%g1 + 0x48]; \
	stx	%o4, [%g1 + 0x50]; \
	stx	%o5, [%g1 + 0x58]; \
	stx	%o6, [%g1 + 0x60]; \
	stx	%o7, [%g1 + 0x68]; \
	\
	rdpr	%pstate, %g7; \
	stx	%g7, [%g1 + 0x70]; \
	rd	%y, %g7; \
	stx	%g7, [%g1 + 0x78]; \
	rd	%fprs, %g7; \
	stx	%g7, [%g1 + 0x80]; \
	\
	/* Now iterate through all of the windows saving all l and i registers */ \
	add	%g1, 0x90, %g5; \
	\
	/* Get the number of windows in %g6 */ \
	rdpr	%ver, %g6; \
	and	%g6, 0xf, %g6; \
	inc	%g6; \
	\
save_cpu_window_##type: \
	deccc	%g6; \
	wrpr	%g6, %cwp; \
	stx	%l0, [%g5]; \
	stx	%l1, [%g5 + 0x8]; \
	stx	%l2, [%g5 + 0x10]; \
	stx	%l3, [%g5 + 0x18]; \
	stx	%l4, [%g5 + 0x20]; \
	stx	%l5, [%g5 + 0x28]; \
	stx	%l6, [%g5 + 0x30]; \
	stx	%l7, [%g5 + 0x38]; \
	stx	%i0, [%g5 + 0x40]; \
	stx	%i1, [%g5 + 0x48]; \
	stx	%i2, [%g5 + 0x50]; \
	stx	%i3, [%g5 + 0x58]; \
	stx	%i4, [%g5 + 0x60]; \
	stx	%i5, [%g5 + 0x68]; \
	stx	%i6, [%g5 + 0x70]; \
	stx	%i7, [%g5 + 0x78]; \
	bne	save_cpu_window_##type; \
	 add	%g5, 0x80, %g5; \
	\
	/* For 8 windows with 16 registers to save in the window, memory required \
	is 16*8*8 = 0x400 bytes */ \
	\
	/* Now we should be in window 0 so update the other window registers */ \
	rdpr	%ver, %g6; \
	and	%g6, 0xf, %g6; \
	dec	%g6; \
	wrpr	%g6, %cansave; \
	\
	wrpr	%g0, %cleanwin; \
	wrpr	%g0, %canrestore; \
	wrpr	%g0, %otherwin;


#define RESTORE_WINDOW_STATE(type) \
	setx	client_window, %g6, %g1; \
	\
	/* Get the number of windows in %g6 */ \
	rdpr	%ver, %g6; \
	and	%g6, 0xf, %g6; \
	inc	%g6; \
	\
	/* Now iterate through all of the windows restoring all l and i registers */ \
	add	%g1, 0x90, %g5; \
	\
restore_cpu_window_##type: \
	deccc	%g6; \
	wrpr	%g6, %cwp; \
	ldx	[%g5], %l0; \
	ldx	[%g5 + 0x8], %l1; \
	ldx	[%g5 + 0x10], %l2; \
	ldx	[%g5 + 0x18], %l3; \
	ldx	[%g5 + 0x20], %l4; \
	ldx	[%g5 + 0x28], %l5; \
	ldx	[%g5 + 0x30], %l6; \
	ldx	[%g5 + 0x38], %l7; \
	ldx	[%g5 + 0x40], %i0; \
	ldx	[%g5 + 0x48], %i1; \
	ldx	[%g5 + 0x50], %i2; \
	ldx	[%g5 + 0x58], %i3; \
	ldx	[%g5 + 0x60], %i4; \
	ldx	[%g5 + 0x68], %i5; \
	ldx	[%g5 + 0x70], %i6; \
	ldx	[%g5 + 0x78], %i7; \
	bne	restore_cpu_window_##type; \
	 add	%g5, 0x80, %g5; \
	\
	/* Restore the window registers to their original value */ \
	ldx	[%g1], %g7; \
	wrpr	%g7, %cwp; \
	ldx	[%g1 + 0x8], %g7; \
	wrpr	%g7, %cansave; \
	ldx	[%g1 + 0x10], %g7; \
	wrpr	%g7, %canrestore; \
	ldx	[%g1 + 0x18], %g7; \
	wrpr	%g7, %otherwin; \
	ldx	[%g1 + 0x20], %g7; \
	wrpr	%g7, %wstate; \
	ldx	[%g1 + 0x28], %g7; \
	wrpr	%g7, %cleanwin; \
	\
	ldx	[%g1 + 0x30], %o0; \
	ldx	[%g1 + 0x38], %o1; \
	ldx	[%g1 + 0x40], %o2; \
	ldx	[%g1 + 0x48], %o3; \
	ldx	[%g1 + 0x50], %o4; \
	ldx	[%g1 + 0x58], %o5; \
	ldx	[%g1 + 0x60], %o6; \
	ldx	[%g1 + 0x68], %o7; \
	\
	ldx	[%g1 + 0x70], %g7; \
	wrpr	%g7, %pstate; \
	ldx	[%g1 + 0x78], %g7; \
	wr	%g7, 0, %y; \
	ldx	[%g1 + 0x80], %g7; \
	wr	%g7, 0, %fprs


	.data
	.align	8

	.skip	16384
openbios_stack:

client_stack:
	.xword	0
client_tba:
	.xword	0
client_window:
	.skip	2048


	.text
	.align	4
        .register %g2, #scratch
        .register %g3, #scratch
        .register %g6, #scratch
        .register %g7, #scratch
/*
	make some more space on stack since linux kernel only provides 128 bytes
	without memory to spill registers (used by gcc in -O0 mode)
*/

sparc64_of_client_interface:

	/* Save globals on callers stack */
	add	%sp, -56, %sp

	stx	%g1, [%sp + 2047 + 0]
	stx	%g2, [%sp + 2047 + 8]
	stx	%g3, [%sp + 2047 + 16]
	stx	%g4, [%sp + 2047 + 24]
	stx	%g5, [%sp + 2047 + 32]
	stx	%g6, [%sp + 2047 + 40]
	stx	%g7, [%sp + 2047 + 48]

	/* Save client trap table */
	setx	client_tba, %g6, %g7
	rdpr	%tba, %g6
	stx	%g6, [%g7]

	/* Save existing stack */
	setx	client_stack, %g6, %g7
	stx	%sp, [%g7]

	/* Save windows */
	SAVE_WINDOW_STATE(cif)

	/* Move to OpenBIOS stack */
	setx	openbios_stack - 2047 - 192, %g6, %g7
	mov	%g7, %sp

	/* Call client inteface */
	call of_client_interface
	 ldx	[%g1 + 0x30], %o0

	setx	client_window, %g6, %g1
	stx	%o0, [%g1 + 0x30]

	/* Restore windows */
	RESTORE_WINDOW_STATE(cif)

	/* Restore stack */
	setx	client_stack, %g6, %g7
	ldx	[%g7], %sp

	/* Restore client trap table */
	setx	client_tba, %g6, %g7
	ldx	[%g7], %g6
	wrpr	%g6, %tba

	/* Restore globals */
	ldx	[%sp + 2047 + 0], %g1
	ldx	[%sp + 2047 + 8], %g2
	ldx	[%sp + 2047 + 16], %g3
	ldx	[%sp + 2047 + 24], %g4
	ldx	[%sp + 2047 + 32], %g5
	ldx	[%sp + 2047 + 40], %g6
	ldx	[%sp + 2047 + 48], %g7

	add	%sp, 56, %sp

	jmp	%o7+8
	 nop
