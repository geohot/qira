#ifndef _BITS_STRINGS_H
#define _BITS_STRINGS_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Find first (i.e. least significant) set bit
 *
 * @v value		Value
 * @ret lsb		Least significant bit set in value (LSB=1), or zero
 */
static inline __attribute__ (( always_inline )) int __ffsl ( long value ) {
	long lsb_minus_one;

	/* If the input value is zero, the BSF instruction returns
	 * ZF=0 and leaves an undefined value in the output register.
	 * Perform this check in C rather than asm so that it can be
	 * omitted in cases where the compiler is able to prove that
	 * the input is non-zero.
	 */
	if ( value ) {
		__asm__ ( "bsfl %1, %0"
			  : "=r" ( lsb_minus_one )
			  : "rm" ( value ) );
		return ( lsb_minus_one + 1 );
	} else {
		return 0;
	}
}

/**
 * Find first (i.e. least significant) set bit
 *
 * @v value		Value
 * @ret lsb		Least significant bit set in value (LSB=1), or zero
 */
static inline __attribute__ (( always_inline )) int __ffsll ( long long value ){
	unsigned long high = ( value >> 32 );
	unsigned long low = ( value >> 0 );

	if ( low ) {
		return ( __ffsl ( low ) );
	} else if ( high ) {
		return ( 32 + __ffsl ( high ) );
	} else {
		return 0;
	}
}

/**
 * Find last (i.e. most significant) set bit
 *
 * @v value		Value
 * @ret msb		Most significant bit set in value (LSB=1), or zero
 */
static inline __attribute__ (( always_inline )) int __flsl ( long value ) {
	long msb_minus_one;

	/* If the input value is zero, the BSR instruction returns
	 * ZF=0 and leaves an undefined value in the output register.
	 * Perform this check in C rather than asm so that it can be
	 * omitted in cases where the compiler is able to prove that
	 * the input is non-zero.
	 */
	if ( value ) {
		__asm__ ( "bsrl %1, %0"
			  : "=r" ( msb_minus_one )
			  : "rm" ( value ) );
		return ( msb_minus_one + 1 );
	} else {
		return 0;
	}
}

/**
 * Find last (i.e. most significant) set bit
 *
 * @v value		Value
 * @ret msb		Most significant bit set in value (LSB=1), or zero
 */
static inline __attribute__ (( always_inline )) int __flsll ( long long value ){
	unsigned long high = ( value >> 32 );
	unsigned long low = ( value >> 0 );

	if ( high ) {
		return ( 32 + __flsl ( high ) );
	} else if ( low ) {
		return ( __flsl ( low ) );
	} else {
		return 0;
	}
}

#endif /* _BITS_STRINGS_H */
