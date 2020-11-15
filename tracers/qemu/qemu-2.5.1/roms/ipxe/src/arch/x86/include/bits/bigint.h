#ifndef _BITS_BIGINT_H
#define _BITS_BIGINT_H

/** @file
 *
 * Big integer support
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <string.h>

/** Element of a big integer */
typedef uint32_t bigint_element_t;

/**
 * Initialise big integer
 *
 * @v value0		Element 0 of big integer to initialise
 * @v size		Number of elements
 * @v data		Raw data
 * @v len		Length of raw data
 */
static inline __attribute__ (( always_inline )) void
bigint_init_raw ( uint32_t *value0, unsigned int size,
		  const void *data, size_t len ) {
	long pad_len = ( sizeof ( bigint_t ( size ) ) - len );
	void *discard_D;
	long discard_c;

	/* Copy raw data in reverse order, padding with zeros */
	__asm__ __volatile__ ( "\n1:\n\t"
			       "movb -1(%2,%1), %%al\n\t"
			       "stosb\n\t"
			       "loop 1b\n\t"
			       "xorl %%eax, %%eax\n\t"
			       "mov %3, %1\n\t"
			       "rep stosb\n\t"
			       : "=&D" ( discard_D ), "=&c" ( discard_c )
			       : "r" ( data ), "g" ( pad_len ), "0" ( value0 ),
				 "1" ( len )
			       : "eax" );
}

/**
 * Add big integers
 *
 * @v addend0		Element 0 of big integer to add
 * @v value0		Element 0 of big integer to be added to
 * @v size		Number of elements
 */
static inline __attribute__ (( always_inline )) void
bigint_add_raw ( const uint32_t *addend0, uint32_t *value0,
		 unsigned int size ) {
	long index;
	void *discard_S;
	long discard_c;

	__asm__ __volatile__ ( "xor %0, %0\n\t" /* Zero %0 and clear CF */
			       "\n1:\n\t"
			       "lodsl\n\t"
			       "adcl %%eax, (%3,%0,4)\n\t"
			       "inc %0\n\t" /* Does not affect CF */
			       "loop 1b\n\t"
			       : "=&r" ( index ), "=&S" ( discard_S ),
				 "=&c" ( discard_c )
			       : "r" ( value0 ), "1" ( addend0 ), "2" ( size )
			       : "eax" );
}

/**
 * Subtract big integers
 *
 * @v subtrahend0	Element 0 of big integer to subtract
 * @v value0		Element 0 of big integer to be subtracted from
 * @v size		Number of elements
 */
static inline __attribute__ (( always_inline )) void
bigint_subtract_raw ( const uint32_t *subtrahend0, uint32_t *value0,
		      unsigned int size ) {
	long index;
	void *discard_S;
	long discard_c;

	__asm__ __volatile__ ( "xor %0, %0\n\t" /* Zero %0 and clear CF */
			       "\n1:\n\t"
			       "lodsl\n\t"
			       "sbbl %%eax, (%3,%0,4)\n\t"
			       "inc %0\n\t" /* Does not affect CF */
			       "loop 1b\n\t"
			       : "=&r" ( index ), "=&S" ( discard_S ),
				 "=&c" ( discard_c )
			       : "r" ( value0 ), "1" ( subtrahend0 ),
				 "2" ( size )
			       : "eax" );
}

/**
 * Rotate big integer left
 *
 * @v value0		Element 0 of big integer
 * @v size		Number of elements
 */
static inline __attribute__ (( always_inline )) void
bigint_rol_raw ( uint32_t *value0, unsigned int size ) {
	long index;
	long discard_c;

	__asm__ __volatile__ ( "xor %0, %0\n\t" /* Zero %0 and clear CF */
			       "\n1:\n\t"
			       "rcll $1, (%2,%0,4)\n\t"
			       "inc %0\n\t" /* Does not affect CF */
			       "loop 1b\n\t"
			       : "=&r" ( index ), "=&c" ( discard_c )
			       : "r" ( value0 ), "1" ( size ) );
}

/**
 * Rotate big integer right
 *
 * @v value0		Element 0 of big integer
 * @v size		Number of elements
 */
static inline __attribute__ (( always_inline )) void
bigint_ror_raw ( uint32_t *value0, unsigned int size ) {
	long discard_c;

	__asm__ __volatile__ ( "clc\n\t"
			       "\n1:\n\t"
			       "rcrl $1, -4(%1,%0,4)\n\t"
			       "loop 1b\n\t"
			       : "=&c" ( discard_c )
			       : "r" ( value0 ), "0" ( size ) );
}

/**
 * Test if big integer is equal to zero
 *
 * @v value0		Element 0 of big integer
 * @v size		Number of elements
 * @ret is_zero		Big integer is equal to zero
 */
static inline __attribute__ (( always_inline, pure )) int
bigint_is_zero_raw ( const uint32_t *value0, unsigned int size ) {
	void *discard_D;
	long discard_c;
	int result;

	__asm__ __volatile__ ( "xor %0, %0\n\t" /* Set ZF */
			       "repe scasl\n\t"
			       "sete %b0\n\t"
			       : "=&a" ( result ), "=&D" ( discard_D ),
				 "=&c" ( discard_c )
			       : "1" ( value0 ), "2" ( size ) );
	return result;
}

/**
 * Compare big integers
 *
 * @v value0		Element 0 of big integer
 * @v reference0	Element 0 of reference big integer
 * @v size		Number of elements
 * @ret geq		Big integer is greater than or equal to the reference
 */
static inline __attribute__ (( always_inline, pure )) int
bigint_is_geq_raw ( const uint32_t *value0, const uint32_t *reference0,
		    unsigned int size ) {
	const bigint_t ( size ) __attribute__ (( may_alias )) *value =
		( ( const void * ) value0 );
	const bigint_t ( size ) __attribute__ (( may_alias )) *reference =
		( ( const void * ) reference0 );
	void *discard_S;
	void *discard_D;
	long discard_c;
	int result;

	__asm__ __volatile__ ( "std\n\t"
			       "\n1:\n\t"
			       "lodsl\n\t"
			       "scasl\n\t"
			       "loope 1b\n\t"
			       "setae %b0\n\t"
			       "cld\n\t"
			       : "=q" ( result ), "=&S" ( discard_S ),
				 "=&D" ( discard_D ), "=&c" ( discard_c )
			       : "0" ( 0 ), "1" ( &value->element[ size - 1 ] ),
				 "2" ( &reference->element[ size - 1 ] ),
				 "3" ( size )
			       : "eax" );
	return result;
}

/**
 * Test if bit is set in big integer
 *
 * @v value0		Element 0 of big integer
 * @v size		Number of elements
 * @v bit		Bit to test
 * @ret is_set		Bit is set
 */
static inline __attribute__ (( always_inline )) int
bigint_bit_is_set_raw ( const uint32_t *value0, unsigned int size,
			unsigned int bit ) {
	const bigint_t ( size ) __attribute__ (( may_alias )) *value =
		( ( const void * ) value0 );
	unsigned int index = ( bit / ( 8 * sizeof ( value->element[0] ) ) );
	unsigned int subindex = ( bit % ( 8 * sizeof ( value->element[0] ) ) );

	return ( value->element[index] & ( 1 << subindex ) );
}

/**
 * Find highest bit set in big integer
 *
 * @v value0		Element 0 of big integer
 * @v size		Number of elements
 * @ret max_bit		Highest bit set + 1 (or 0 if no bits set)
 */
static inline __attribute__ (( always_inline )) int
bigint_max_set_bit_raw ( const uint32_t *value0, unsigned int size ) {
	long discard_c;
	int result;

	__asm__ __volatile__ ( "\n1:\n\t"
			       "bsrl -4(%2,%1,4), %0\n\t"
			       "loopz 1b\n\t"
			       "rol %1\n\t" /* Does not affect ZF */
			       "rol %1\n\t"
			       "leal 1(%k0,%k1,8), %k0\n\t"
			       "jnz 2f\n\t"
			       "xor %0, %0\n\t"
			       "\n2:\n\t"
			       : "=&r" ( result ), "=&c" ( discard_c )
			       : "r" ( value0 ), "1" ( size ) );
	return result;
}

/**
 * Grow big integer
 *
 * @v source0		Element 0 of source big integer
 * @v source_size	Number of elements in source big integer
 * @v dest0		Element 0 of destination big integer
 * @v dest_size		Number of elements in destination big integer
 */
static inline __attribute__ (( always_inline )) void
bigint_grow_raw ( const uint32_t *source0, unsigned int source_size,
		  uint32_t *dest0, unsigned int dest_size ) {
	long pad_size = ( dest_size - source_size );
	void *discard_D;
	void *discard_S;
	long discard_c;

	__asm__ __volatile__ ( "rep movsl\n\t"
			       "xorl %%eax, %%eax\n\t"
			       "mov %3, %2\n\t"
			       "rep stosl\n\t"
			       : "=&D" ( discard_D ), "=&S" ( discard_S ),
				 "=&c" ( discard_c )
			       : "g" ( pad_size ), "0" ( dest0 ),
				 "1" ( source0 ), "2" ( source_size )
			       : "eax" );
}

/**
 * Shrink big integer
 *
 * @v source0		Element 0 of source big integer
 * @v source_size	Number of elements in source big integer
 * @v dest0		Element 0 of destination big integer
 * @v dest_size		Number of elements in destination big integer
 */
static inline __attribute__ (( always_inline )) void
bigint_shrink_raw ( const uint32_t *source0, unsigned int source_size __unused,
		    uint32_t *dest0, unsigned int dest_size ) {
	void *discard_D;
	void *discard_S;
	long discard_c;

	__asm__ __volatile__ ( "rep movsl\n\t"
			       : "=&D" ( discard_D ), "=&S" ( discard_S ),
				 "=&c" ( discard_c )
			       : "0" ( dest0 ), "1" ( source0 ),
				 "2" ( dest_size )
			       : "eax" );
}

/**
 * Finalise big integer
 *
 * @v value0		Element 0 of big integer to finalise
 * @v size		Number of elements
 * @v out		Output buffer
 * @v len		Length of output buffer
 */
static inline __attribute__ (( always_inline )) void
bigint_done_raw ( const uint32_t *value0, unsigned int size __unused,
		  void *out, size_t len ) {
	void *discard_D;
	long discard_c;

	/* Copy raw data in reverse order */
	__asm__ __volatile__ ( "\n1:\n\t"
			       "movb -1(%2,%1), %%al\n\t"
			       "stosb\n\t"
			       "loop 1b\n\t"
			       : "=&D" ( discard_D ), "=&c" ( discard_c )
			       : "r" ( value0 ), "0" ( out ), "1" ( len )
			       : "eax" );
}

extern void bigint_multiply_raw ( const uint32_t *multiplicand0,
				  const uint32_t *multiplier0,
				  uint32_t *value0, unsigned int size );

#endif /* _BITS_BIGINT_H */
