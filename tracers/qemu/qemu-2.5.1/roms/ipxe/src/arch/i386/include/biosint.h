#ifndef BIOSINT_H
#define BIOSINT_H

/**
 * @file BIOS interrupts
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <realmode.h>

struct segoff;

/**
 * Hooked interrupt count
 *
 * At exit, after unhooking all possible interrupts, this counter
 * should be examined.  If it is non-zero, it means that we failed to
 * unhook at least one interrupt vector, and so must not free up the
 * memory we are using.  (Note that this also implies that we should
 * re-hook INT 15 in order to hide ourselves from the memory map).
 */
extern uint16_t __text16 ( hooked_bios_interrupts );
#define hooked_bios_interrupts __use_text16 ( hooked_bios_interrupts )

extern void hook_bios_interrupt ( unsigned int interrupt, unsigned int handler,
				  struct segoff *chain_vector );
extern int unhook_bios_interrupt ( unsigned int interrupt,
				   unsigned int handler,
				   struct segoff *chain_vector );

#endif /* BIOSINT_H */
