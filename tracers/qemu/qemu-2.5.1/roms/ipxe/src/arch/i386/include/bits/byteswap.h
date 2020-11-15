#ifndef _BITS_BYTESWAP_H
#define _BITS_BYTESWAP_H

/** @file
 *
 * Byte-order swapping functions
 *
 */

#include <stdint.h>

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

static inline __attribute__ (( always_inline, const )) uint16_t
__bswap_variable_16 ( uint16_t x ) {
	__asm__ ( "xchgb %b0,%h0" : "=q" ( x ) : "0" ( x ) );
	return x;
}

static inline __attribute__ (( always_inline )) void
__bswap_16s ( uint16_t *x ) {
	__asm__ ( "rorw $8, %0" : "+m" ( *x ) );
}

static inline __attribute__ (( always_inline, const )) uint32_t
__bswap_variable_32 ( uint32_t x ) {
	__asm__ ( "bswapl %0" : "=r" ( x ) : "0" ( x ) );
	return x;
}

static inline __attribute__ (( always_inline )) void
__bswap_32s ( uint32_t *x ) {
	__asm__ ( "bswapl %0" : "=r" ( *x ) : "0" ( *x ) );
}

static inline __attribute__ (( always_inline, const )) uint64_t
__bswap_variable_64 ( uint64_t x ) {
	uint32_t in_high = ( x >> 32 );
	uint32_t in_low = ( x & 0xffffffffUL );
	uint32_t out_high;
	uint32_t out_low;

	__asm__ ( "bswapl %0\n\t"
		  "bswapl %1\n\t"
		  "xchgl %0,%1\n\t"
		  : "=r" ( out_high ), "=r" ( out_low )
		  : "0" ( in_high ), "1" ( in_low ) );

	return ( ( ( ( uint64_t ) out_high ) << 32 ) |
		 ( ( uint64_t ) out_low ) );
}

static inline __attribute__ (( always_inline )) void
__bswap_64s ( uint64_t *x ) {
	struct {
		uint32_t __attribute__ (( may_alias )) low;
		uint32_t __attribute__ (( may_alias )) high;
	} __attribute__ (( may_alias )) *dwords = ( ( void * ) x );
	uint32_t discard;

	__asm__ ( "movl %0,%2\n\t"
		  "bswapl %2\n\t"
		  "xchgl %2,%1\n\t"
		  "bswapl %2\n\t"
		  "movl %2,%0\n\t"
		  : "+m" ( dwords->low ), "+m" ( dwords->high ),
		    "=r" ( discard ) );
}

#endif /* _BITS_BYTESWAP_H */
