#ifndef _SETJMP_H
#define _SETJMP_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

/** A jump buffer */
typedef struct {
	/** Saved return address */
	uint64_t retaddr;
	/** Saved stack pointer */
	uint64_t stack;
	/** Saved %rbx */
	uint64_t rbx;
	/** Saved %rbp */
	uint64_t rbp;
	/** Saved %r12 */
	uint64_t r12;
	/** Saved %r13 */
	uint64_t r13;
	/** Saved %r14 */
	uint64_t r14;
	/** Saved %r15 */
	uint64_t r15;
} jmp_buf[1];

extern int __asmcall __attribute__ (( returns_twice ))
setjmp ( jmp_buf env );

extern void __asmcall __attribute__ (( noreturn ))
longjmp ( jmp_buf env, int val );

#endif /* _SETJMP_H */
