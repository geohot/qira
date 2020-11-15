#ifndef _STRINGS_H
#define _STRINGS_H

/** @file
 *
 * String functions
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <string.h>
#include <bits/strings.h>

/**
 * Find first (i.e. least significant) set bit
 *
 * @v x			Value
 * @ret lsb		Least significant bit set in value (LSB=1), or zero
 */
static inline __attribute__ (( always_inline )) int
__constant_ffsll ( unsigned long long x ) {
	int r = 0;

	if ( ! ( x & 0x00000000ffffffffULL ) ) {
		x >>= 32;
		r += 32;
	}
	if ( ! ( x & 0x0000ffffUL ) ) {
		x >>= 16;
		r += 16;
	}
	if ( ! ( x & 0x00ff ) ) {
		x >>= 8;
		r += 8;
	}
	if ( ! ( x & 0x0f ) ) {
		x >>= 4;
		r += 4;
	}
	if ( ! ( x & 0x3 ) ) {
		x >>= 2;
		r += 2;
	}
	if ( ! ( x & 0x1 ) ) {
		x >>= 1;
		r += 1;
	}
	return ( x ? ( r + 1 ) : 0 );
}

/**
 * Find first (i.e. least significant) set bit
 *
 * @v x			Value
 * @ret lsb		Least significant bit set in value (LSB=1), or zero
 */
static inline __attribute__ (( always_inline )) int
__constant_ffsl ( unsigned long x ) {
	return __constant_ffsll ( x );
}

/**
 * Find last (i.e. most significant) set bit
 *
 * @v x			Value
 * @ret msb		Most significant bit set in value (LSB=1), or zero
 */
static inline __attribute__ (( always_inline )) int
__constant_flsll ( unsigned long long x ) {
	int r = 0;

	if ( x & 0xffffffff00000000ULL ) {
		x >>= 32;
		r += 32;
	}
	if ( x & 0xffff0000UL ) {
		x >>= 16;
		r += 16;
	}
	if ( x & 0xff00 ) {
		x >>= 8;
		r += 8;
	}
	if ( x & 0xf0 ) {
		x >>= 4;
		r += 4;
	}
	if ( x & 0xc ) {
		x >>= 2;
		r += 2;
	}
	if ( x & 0x2 ) {
		x >>= 1;
		r += 1;
	}
	return ( x ? ( r + 1 ) : 0 );
}

/**
 * Find last (i.e. most significant) set bit
 *
 * @v x			Value
 * @ret msb		Most significant bit set in value (LSB=1), or zero
 */
static inline __attribute__ (( always_inline )) int
__constant_flsl ( unsigned long x ) {
	return __constant_flsll ( x );
}

int __ffsll ( long long x );
int __ffsl ( long x );
int __flsll ( long long x );
int __flsl ( long x );

/**
 * Find first (i.e. least significant) set bit
 *
 * @v x			Value
 * @ret lsb		Least significant bit set in value (LSB=1), or zero
 */
#define ffsll( x ) \
	( __builtin_constant_p ( x ) ? __constant_ffsll ( x ) : __ffsll ( x ) )

/**
 * Find first (i.e. least significant) set bit
 *
 * @v x			Value
 * @ret lsb		Least significant bit set in value (LSB=1), or zero
 */
#define ffsl( x ) \
	( __builtin_constant_p ( x ) ? __constant_ffsl ( x ) : __ffsl ( x ) )

/**
 * Find first (i.e. least significant) set bit
 *
 * @v x			Value
 * @ret lsb		Least significant bit set in value (LSB=1), or zero
 */
#define ffs( x ) ffsl ( x )

/**
 * Find last (i.e. most significant) set bit
 *
 * @v x			Value
 * @ret msb		Most significant bit set in value (LSB=1), or zero
 */
#define flsll( x ) \
	( __builtin_constant_p ( x ) ? __constant_flsll ( x ) : __flsll ( x ) )

/**
 * Find last (i.e. most significant) set bit
 *
 * @v x			Value
 * @ret msb		Most significant bit set in value (LSB=1), or zero
 */
#define flsl( x ) \
	( __builtin_constant_p ( x ) ? __constant_flsl ( x ) : __flsl ( x ) )

/**
 * Find last (i.e. most significant) set bit
 *
 * @v x			Value
 * @ret msb		Most significant bit set in value (LSB=1), or zero
 */
#define fls( x ) flsl ( x )

/**
 * Copy memory
 *
 * @v src		Source
 * @v dest		Destination
 * @v len		Length
 */
static inline __attribute__ (( always_inline )) void
bcopy ( const void *src, void *dest, size_t len ) {
	memmove ( dest, src, len );
}

/**
 * Zero memory
 *
 * @v dest		Destination
 * @v len		Length
 */
static inline __attribute__ (( always_inline )) void
bzero ( void *dest, size_t len ) {
	memset ( dest, 0, len );
}

int __pure strcasecmp ( const char *first, const char *second ) __nonnull;

#endif /* _STRINGS_H */
