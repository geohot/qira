#ifndef _SETJMP_H
#define _SETJMP_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <realmode.h>

/** A jump buffer */
typedef struct {
	/** Saved return address */
	uint32_t retaddr;
	/** Saved stack pointer */
	uint32_t stack;
	/** Saved %ebx */
	uint32_t ebx;
	/** Saved %esi */
	uint32_t esi;
	/** Saved %edi */
	uint32_t edi;
	/** Saved %ebp */
	uint32_t ebp;
} jmp_buf[1];

/** A real-mode-extended jump buffer */
typedef struct {
	/** Jump buffer */
	jmp_buf env;
	/** Real-mode stack pointer */
	segoff_t rm_stack;
} rmjmp_buf[1];

extern int __asmcall __attribute__ (( returns_twice ))
setjmp ( jmp_buf env );

extern void __asmcall __attribute__ (( noreturn ))
longjmp ( jmp_buf env, int val );

#define rmsetjmp( _env ) ( {					\
	(_env)->rm_stack.segment = rm_ss;			\
	(_env)->rm_stack.offset = rm_sp;			\
	setjmp ( (_env)->env ); } )				\

#define rmlongjmp( _env, _val ) do {				\
	rm_ss = (_env)->rm_stack.segment;			\
	rm_sp = (_env)->rm_stack.offset;			\
	longjmp ( (_env)->env, (_val) );			\
	} while ( 0 )

#endif /* _SETJMP_H */
