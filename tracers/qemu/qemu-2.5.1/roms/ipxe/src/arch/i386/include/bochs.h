#ifndef BOCHS_H
#define BOCHS_H

/** @file
 *
 * bochs breakpoints
 *
 * This file defines @c bochsbp, the magic breakpoint instruction that
 * is incredibly useful when debugging under bochs.  This file should
 * never be included in production code.
 *
 * Use the pseudo-instruction @c bochsbp in assembly code, or the
 * bochsbp() function in C code.
 *
 */

#ifdef ASSEMBLY

/* Breakpoint for when debugging under bochs */
#define bochsbp xchgw %bx, %bx
#define BOCHSBP bochsbp

#else /* ASSEMBLY */

/** Breakpoint for when debugging under bochs */
static inline void bochsbp ( void ) {
	__asm__ __volatile__ ( "xchgw %bx, %bx" );
}

#endif /* ASSEMBLY */

#warning "bochs.h should not be included into production code"

#endif /* BOCHS_H */
