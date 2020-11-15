#ifndef _ASSERT_H
#define _ASSERT_H

/** @file
 *
 * Assertions
 *
 * This file provides two assertion macros: assert() (for run-time
 * assertions) and linker_assert() (for link-time assertions).
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef NDEBUG
#define ASSERTING 0
#else
#define ASSERTING 1
#endif

extern unsigned int assertion_failures;

#define ASSERTED ( ASSERTING && ( assertion_failures != 0 ) )

/** printf() for assertions
 *
 * This function exists so that the assert() macro can expand to
 * printf() calls without dragging the printf() prototype into scope.
 *
 * As far as the compiler is concerned, assert_printf() and printf() are
 * completely unrelated calls; it's only at the assembly stage that
 * references to the assert_printf symbol are collapsed into references
 * to the printf symbol.
 */
extern int __attribute__ (( format ( printf, 1, 2 ) )) 
assert_printf ( const char *fmt, ... ) asm ( "printf" );

/**
 * Assert a condition at run-time.
 *
 * If the condition is not true, a debug message will be printed.
 * Assertions only take effect in debug-enabled builds (see DBG()).
 *
 * @todo Make an assertion failure abort the program
 *
 */
#define assert( condition ) 						     \
	do { 								     \
		if ( ASSERTING && ! (condition) ) { 			     \
			assertion_failures++;				     \
			assert_printf ( "assert(%s) failed at %s line %d\n", \
					#condition, __FILE__, __LINE__ );    \
		} 							     \
	} while ( 0 )

/**
 * Assert a condition at link-time.
 *
 * If the condition is not true, the link will fail with an unresolved
 * symbol (error_symbol).
 *
 * This macro is iPXE-specific.  Do not use this macro in code
 * intended to be portable.
 *
 */
#define linker_assert( condition, error_symbol )	\
        if ( ! (condition) ) {				\
                extern void error_symbol ( void );	\
                error_symbol();				\
        }

#endif /* _ASSERT_H */
