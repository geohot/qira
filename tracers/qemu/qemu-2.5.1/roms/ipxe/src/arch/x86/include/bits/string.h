#ifndef X86_BITS_STRING_H
#define X86_BITS_STRING_H

/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * Optimised string operations
 *
 */

extern void * __memcpy ( void *dest, const void *src, size_t len );
extern void * __memcpy_reverse ( void *dest, const void *src, size_t len );

/**
 * Copy memory area (where length is a compile-time constant)
 *
 * @v dest		Destination address
 * @v src		Source address
 * @v len		Length
 * @ret dest		Destination address
 */
static inline __attribute__ (( always_inline )) void *
__constant_memcpy ( void *dest, const void *src, size_t len ) {
	union {
		uint32_t u32[2];
		uint16_t u16[4];
		uint8_t  u8[8];
	} __attribute__ (( __may_alias__ )) *dest_u = dest;
	const union {
		uint32_t u32[2];
		uint16_t u16[4];
		uint8_t  u8[8];
	} __attribute__ (( __may_alias__ )) *src_u = src;
	const void *esi;
	void *edi;

	switch ( len ) {
	case 0 : /* 0 bytes */
		return dest;
	/*
	 * Single-register moves; these are always better than a
	 * string operation.  We can clobber an arbitrary two
	 * registers (data, source, dest can re-use source register)
	 * instead of being restricted to esi and edi.  There's also a
	 * much greater potential for optimising with nearby code.
	 *
	 */
	case 1 : /* 4 bytes */
		dest_u->u8[0]  = src_u->u8[0];
		return dest;
	case 2 : /* 6 bytes */
		dest_u->u16[0] = src_u->u16[0];
		return dest;
	case 4 : /* 4 bytes */
		dest_u->u32[0] = src_u->u32[0];
		return dest;
	/*
	 * Double-register moves; these are probably still a win.
	 *
	 */
	case 3 : /* 12 bytes */
		dest_u->u16[0] = src_u->u16[0];
		dest_u->u8[2]  = src_u->u8[2];
		return dest;
	case 5 : /* 10 bytes */
		dest_u->u32[0] = src_u->u32[0];
		dest_u->u8[4]  = src_u->u8[4];
		return dest;
	case 6 : /* 12 bytes */
		dest_u->u32[0] = src_u->u32[0];
		dest_u->u16[2] = src_u->u16[2];
		return dest;
	case 8 : /* 10 bytes */
		dest_u->u32[0] = src_u->u32[0];
		dest_u->u32[1] = src_u->u32[1];
		return dest;
	}

	/* Even if we have to load up esi and edi ready for a string
	 * operation, we can sometimes save space by using multiple
	 * single-byte "movs" operations instead of loading up ecx and
	 * using "rep movsb".
	 *
	 * "load ecx, rep movsb" is 7 bytes, plus an average of 1 byte
	 * to allow for saving/restoring ecx 50% of the time.
	 *
	 * "movsl" and "movsb" are 1 byte each, "movsw" is two bytes.
	 * (In 16-bit mode, "movsl" is 2 bytes and "movsw" is 1 byte,
	 * but "movsl" moves twice as much data, so it balances out).
	 *
	 * The cutoff point therefore occurs around 26 bytes; the byte
	 * requirements for each method are:
	 *
	 * len		   16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
	 * #bytes (ecx)	    8  8  8  8  8  8  8  8  8  8  8  8  8  8  8  8
	 * #bytes (no ecx)  4  5  6  7  5  6  7  8  6  7  8  9  7  8  9 10
	 */

	esi = src;
	edi = dest;
	
	if ( len >= 26 )
		return __memcpy ( dest, src, len );
	
	if ( len >= 6*4 )
		__asm__ __volatile__ ( "movsl" : "=&D" ( edi ), "=&S" ( esi )
				       : "0" ( edi ), "1" ( esi ) : "memory" );
	if ( len >= 5*4 )
		__asm__ __volatile__ ( "movsl" : "=&D" ( edi ), "=&S" ( esi )
				       : "0" ( edi ), "1" ( esi ) : "memory" );
	if ( len >= 4*4 )
		__asm__ __volatile__ ( "movsl" : "=&D" ( edi ), "=&S" ( esi )
				       : "0" ( edi ), "1" ( esi ) : "memory" );
	if ( len >= 3*4 )
		__asm__ __volatile__ ( "movsl" : "=&D" ( edi ), "=&S" ( esi )
				       : "0" ( edi ), "1" ( esi ) : "memory" );
	if ( len >= 2*4 )
		__asm__ __volatile__ ( "movsl" : "=&D" ( edi ), "=&S" ( esi )
				       : "0" ( edi ), "1" ( esi ) : "memory" );
	if ( len >= 1*4 )
		__asm__ __volatile__ ( "movsl" : "=&D" ( edi ), "=&S" ( esi )
				       : "0" ( edi ), "1" ( esi ) : "memory" );
	if ( ( len % 4 ) >= 2 )
		__asm__ __volatile__ ( "movsw" : "=&D" ( edi ), "=&S" ( esi )
				       : "0" ( edi ), "1" ( esi ) : "memory" );
	if ( ( len % 2 ) >= 1 )
		__asm__ __volatile__ ( "movsb" : "=&D" ( edi ), "=&S" ( esi )
				       : "0" ( edi ), "1" ( esi ) : "memory" );

	return dest;
}

/**
 * Copy memory area
 *
 * @v dest		Destination address
 * @v src		Source address
 * @v len		Length
 * @ret dest		Destination address
 */
static inline __attribute__ (( always_inline )) void *
memcpy ( void *dest, const void *src, size_t len ) {
	if ( __builtin_constant_p ( len ) ) {
		return __constant_memcpy ( dest, src, len );
	} else {
		return __memcpy ( dest, src, len );
	}
}

extern void * __memmove ( void *dest, const void *src, size_t len );

/**
 * Copy (possibly overlapping) memory area
 *
 * @v dest		Destination address
 * @v src		Source address
 * @v len		Length
 * @ret dest		Destination address
 */
static inline __attribute__ (( always_inline )) void *
memmove ( void *dest, const void *src, size_t len ) {
	ssize_t offset = ( dest - src );

	if ( __builtin_constant_p ( offset ) ) {
		if ( offset <= 0 ) {
			return memcpy ( dest, src, len );
		} else {
			return __memcpy_reverse ( dest, src, len );
		}
	} else {
		return __memmove ( dest, src, len );
	}
}

/**
 * Fill memory region
 *
 * @v dest		Destination address
 * @v fill		Fill pattern
 * @v len		Length
 * @ret dest		Destination address
 */
static inline __attribute__ (( always_inline )) void *
__memset ( void *dest, int fill, size_t len ) {
	void *discard_D;
	size_t discard_c;

	__asm__ __volatile__ ( "rep stosb"
			       : "=&D" ( discard_D ), "=&c" ( discard_c )
			       : "0" ( dest ), "1" ( len ), "a" ( fill )
			       : "memory" );
	return dest;
}

/**
 * Fill memory region with zero (where length is a compile-time constant)
 *
 * @v dest		Destination address
 * @v len		Length
 * @ret dest		Destination address
 */
static inline __attribute__ (( always_inline )) void *
__constant_memset_zero ( void *dest, size_t len ) {
	union {
		uint32_t u32[2];
		uint16_t u16[4];
		uint8_t  u8[8];
	} __attribute__ (( __may_alias__ )) *dest_u = dest;
	void *edi;
	uint32_t eax;

	switch ( len ) {
	case 0 : /* 0 bytes */
		return dest;

	/* Single-register moves.  Almost certainly better than a
	 * string operation.  We can avoid clobbering any registers,
	 * we can reuse a zero that happens to already be in a
	 * register, and we can optimise away the code entirely if the
	 * memset() is used to clear a region which then gets
	 * immediately overwritten.
	 */
	case 1 : /* 3 bytes */
		dest_u->u8[0] = 0;
		return dest;
	case 2: /* 5 bytes */
		dest_u->u16[0] = 0;
		return dest;
	case 4: /* 6 bytes */
		dest_u->u32[0] = 0;
		return dest;

	/* Double-register moves.  Very probably better than a string
	 * operation.
	 */
	case 3 : /* 9 bytes */
		dest_u->u16[0] = 0;
		dest_u->u8[2]  = 0;
		return dest;
	case 5 : /* 10 bytes */
		dest_u->u32[0] = 0;
		dest_u->u8[4]  = 0;
		return dest;
	case 6 : /* 12 bytes */
		dest_u->u32[0] = 0;
		dest_u->u16[2] = 0;
		return dest;
	case 8 : /* 13 bytes */
		dest_u->u32[0] = 0;
		dest_u->u32[1] = 0;
		return dest;
	}

	/* As with memcpy(), we can potentially save space by using
	 * multiple single-byte "stos" instructions instead of loading
	 * up ecx and using "rep stosb".
	 *
	 * "load ecx, rep movsb" is 7 bytes, plus an average of 1 byte
	 * to allow for saving/restoring ecx 50% of the time.
	 *
	 * "stosl" and "stosb" are 1 byte each, "stosw" is two bytes.
	 *
	 * The calculations are therefore the same as for memcpy(),
	 * giving a cutoff point of around 26 bytes.
	 */

	edi = dest;
	eax = 0;

	if ( len >= 26 )
		return __memset ( dest, 0, len );

	if ( len >= 6*4 )
		__asm__ __volatile__ ( "stosl" : "=&D" ( edi ), "=&a" ( eax )
				       : "0" ( edi ), "1" ( eax ) : "memory" );
	if ( len >= 5*4 )
		__asm__ __volatile__ ( "stosl" : "=&D" ( edi ), "=&a" ( eax )
				       : "0" ( edi ), "1" ( eax ) : "memory" );
	if ( len >= 4*4 )
		__asm__ __volatile__ ( "stosl" : "=&D" ( edi ), "=&a" ( eax )
				       : "0" ( edi ), "1" ( eax ) : "memory" );
	if ( len >= 3*4 )
		__asm__ __volatile__ ( "stosl" : "=&D" ( edi ), "=&a" ( eax )
				       : "0" ( edi ), "1" ( eax ) : "memory" );
	if ( len >= 2*4 )
		__asm__ __volatile__ ( "stosl" : "=&D" ( edi ), "=&a" ( eax )
				       : "0" ( edi ), "1" ( eax ) : "memory" );
	if ( len >= 1*4 )
		__asm__ __volatile__ ( "stosl" : "=&D" ( edi ), "=&a" ( eax )
				       : "0" ( edi ), "1" ( eax ) : "memory" );
	if ( ( len % 4 ) >= 2 )
		__asm__ __volatile__ ( "stosw" : "=&D" ( edi ), "=&a" ( eax )
				       : "0" ( edi ), "1" ( eax ) : "memory" );
	if ( ( len % 2 ) >= 1 )
		__asm__ __volatile__ ( "stosb" : "=&D" ( edi ), "=&a" ( eax )
				       : "0" ( edi ), "1" ( eax ) : "memory" );

	return dest;
}

/**
 * Fill memory region
 *
 * @v dest		Destination address
 * @v fill		Fill pattern
 * @v len		Length
 * @ret dest		Destination address
 */
static inline __attribute__ (( always_inline )) void *
memset ( void *dest, int fill, size_t len ) {

	if ( __builtin_constant_p ( fill ) && ( fill == 0 ) &&
	     __builtin_constant_p ( len ) ) {
		return __constant_memset_zero ( dest, len );
	} else {
		return __memset ( dest, fill, len );
	}
}

#endif /* X86_BITS_STRING_H */
