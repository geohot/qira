#ifndef REALMODE_H
#define REALMODE_H

#include <stdint.h>
#include <registers.h>
#include <ipxe/uaccess.h>

/*
 * Data structures and type definitions
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/*
 * Declaration of variables in .data16
 *
 * To place a variable in the .data16 segment, declare it using the
 * pattern:
 *
 *   int __data16 ( foo );
 *   #define foo __use_data16 ( foo );
 *
 *   extern uint32_t __data16 ( bar );
 *   #define bar __use_data16 ( bar );
 *
 *   static long __data16 ( baz ) = 0xff000000UL;
 *   #define baz __use_data16 ( baz );
 *
 * i.e. take a normal declaration, add __data16() around the variable
 * name, and add a line saying "#define <name> __use_data16 ( <name> )
 *
 * You can then access them just like any other variable, for example
 *
 *   int x = foo + bar;
 *
 * This magic is achieved at a cost of only around 7 extra bytes per
 * group of accesses to .data16 variables.  When using KEEP_IT_REAL,
 * there is no extra cost.
 *
 * You should place variables in .data16 when they need to be accessed
 * by real-mode code.  Real-mode assembly (e.g. as created by
 * REAL_CODE()) can access these variables via the usual data segment.
 * You can therefore write something like
 *
 *   static uint16_t __data16 ( foo );
 *   #define foo __use_data16 ( foo )
 *
 *   int bar ( void ) {
 *     __asm__ __volatile__ ( REAL_CODE ( "int $0xff\n\t"
 *                                        "movw %ax, foo" )
 *                            : : );
 *     return foo;
 *   }
 *
 * Variables may also be placed in .text16 using __text16 and
 * __use_text16.  Some variables (e.g. chained interrupt vectors) fit
 * most naturally in .text16; most should be in .data16.
 *
 * If you have only a pointer to a magic symbol within .data16 or
 * .text16, rather than the symbol itself, you can attempt to extract
 * the underlying symbol name using __from_data16() or
 * __from_text16().  This is not for the faint-hearted; check the
 * assembler output to make sure that it's doing the right thing.
 */

/**
 * Convert segment:offset address to user buffer
 *
 * @v segment		Real-mode segment
 * @v offset		Real-mode offset
 * @ret buffer		User buffer
 */
static inline __always_inline userptr_t
real_to_user ( unsigned int segment, unsigned int offset ) {
	return ( phys_to_user ( ( segment << 4 ) + offset ) );
}

/**
 * Copy data to base memory
 *
 * @v dest_seg		Destination segment
 * @v dest_off		Destination offset
 * @v src		Source
 * @v len		Length
 */
static inline __always_inline void
copy_to_real ( unsigned int dest_seg, unsigned int dest_off,
	       void *src, size_t n ) {
	copy_to_user ( real_to_user ( dest_seg, dest_off ), 0, src, n );
}

/**
 * Copy data to base memory
 *
 * @v dest		Destination
 * @v src_seg		Source segment
 * @v src_off		Source offset
 * @v len		Length
 */
static inline __always_inline void
copy_from_real ( void *dest, unsigned int src_seg,
		 unsigned int src_off, size_t n ) {
	copy_from_user ( dest, real_to_user ( src_seg, src_off ), 0, n );
}

/**
 * Write a single variable to base memory
 *
 * @v var		Variable to write
 * @v dest_seg		Destination segment
 * @v dest_off		Destination offset
 */
#define put_real( var, dest_seg, dest_off ) \
	copy_to_real ( (dest_seg), (dest_off), &(var), sizeof (var) )

/**
 * Read a single variable from base memory
 *
 * @v var		Variable to read
 * @v src_seg		Source segment
 * @v src_off		Source offset
 */
#define get_real( var, src_seg, src_off ) \
	copy_from_real ( &(var), (src_seg), (src_off), sizeof (var) )

/*
 * REAL_CODE ( asm_code_str )
 *
 * This can be used in inline assembly to create a fragment of code
 * that will execute in real mode.  For example: to write a character
 * to the BIOS console using INT 10, you would do something like:
 *
 *     __asm__ __volatile__ ( REAL_CODE ( "int $0x16" )
 *			      : "=a" ( character ) : "a" ( 0x0000 ) );
 *
 */

#endif /* REALMODE_H */
