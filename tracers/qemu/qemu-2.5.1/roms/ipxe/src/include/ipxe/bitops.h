#ifndef _IPXE_BITOPS_H
#define _IPXE_BITOPS_H

/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
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

/**
 * @file
 *
 * Bit operations
 *
 */

#include <stdint.h>
#include <byteswap.h>

/* Endianness selection.
 *
 * This is a property of the NIC, not a property of the host CPU.
 */
#ifdef BITOPS_LITTLE_ENDIAN
#define cpu_to_BIT64	cpu_to_le64
#define cpu_to_BIT32	cpu_to_le32
#define BIT64_to_cpu	le64_to_cpu
#define BIT32_to_cpu	le32_to_cpu
#endif
#ifdef BITOPS_BIG_ENDIAN
#define cpu_to_BIT64	cpu_to_be64
#define cpu_to_BIT32	cpu_to_be32
#define BIT64_to_cpu	be64_to_cpu
#define BIT32_to_cpu	be32_to_cpu
#endif

/** Datatype used to represent a bit in the pseudo-structures */
typedef unsigned char pseudo_bit_t;

/**
 * Wrapper structure for pseudo_bit_t structures
 *
 * This structure provides a wrapper around pseudo_bit_t structures.
 * It has the correct size, and also encapsulates type information
 * about the underlying pseudo_bit_t-based structure, which allows the
 * BIT_FILL() etc. macros to work without requiring explicit type
 * information.
 */
#define PSEUDO_BIT_STRUCT( _structure )					      \
	union {								      \
		uint8_t bytes[ sizeof ( _structure ) / 8 ];		      \
		uint32_t dwords[ sizeof ( _structure ) / 32 ];		      \
		uint64_t qwords[ sizeof ( _structure ) / 64 ];		      \
		_structure *dummy[0];					      \
	} __attribute__ (( packed )) u

/** Get pseudo_bit_t structure type from wrapper structure pointer */
#define PSEUDO_BIT_STRUCT_TYPE( _ptr )					      \
	typeof ( *((_ptr)->u.dummy[0]) )

/** Bit offset of a field within a pseudo_bit_t structure */
#define BIT_OFFSET( _ptr, _field )					      \
	offsetof ( PSEUDO_BIT_STRUCT_TYPE ( _ptr ), _field )

/** Bit width of a field within a pseudo_bit_t structure */
#define BIT_WIDTH( _ptr, _field )					      \
	sizeof ( ( ( PSEUDO_BIT_STRUCT_TYPE ( _ptr ) * ) NULL )->_field )

/** Qword offset of a field within a pseudo_bit_t structure */
#define QWORD_OFFSET( _ptr, _field )					      \
	( BIT_OFFSET ( _ptr, _field ) / 64 )

/** Qword bit offset of a field within a pseudo_bit_t structure */
#define QWORD_BIT_OFFSET( _ptr, _index, _field )			      \
	( BIT_OFFSET ( _ptr, _field ) - ( 64 * (_index) ) )

/** Bit mask for a field within a pseudo_bit_t structure */
#define BIT_MASK( _ptr, _field )					      \
	( ( ~( ( uint64_t ) 0 ) ) >>					      \
	  ( 64 - BIT_WIDTH ( _ptr, _field ) ) )

/*
 * Assemble native-endian qword from named fields and values
 *
 */

#define BIT_ASSEMBLE_1( _ptr, _index, _field, _value )			      \
	( ( ( uint64_t) (_value) ) <<					      \
	  QWORD_BIT_OFFSET ( _ptr, _index, _field ) )

#define BIT_ASSEMBLE_2( _ptr, _index, _field, _value, ... )		      \
	( BIT_ASSEMBLE_1 ( _ptr, _index, _field, _value ) |		      \
	  BIT_ASSEMBLE_1 ( _ptr, _index, __VA_ARGS__ ) )

#define BIT_ASSEMBLE_3( _ptr, _index, _field, _value, ... )		      \
	( BIT_ASSEMBLE_1 ( _ptr, _index, _field, _value ) |		      \
	  BIT_ASSEMBLE_2 ( _ptr, _index, __VA_ARGS__ ) )

#define BIT_ASSEMBLE_4( _ptr, _index, _field, _value, ... )		      \
	( BIT_ASSEMBLE_1 ( _ptr, _index, _field, _value ) |		      \
	  BIT_ASSEMBLE_3 ( _ptr, _index, __VA_ARGS__ ) )

#define BIT_ASSEMBLE_5( _ptr, _index, _field, _value, ... )		      \
	( BIT_ASSEMBLE_1 ( _ptr, _index, _field, _value ) |		      \
	  BIT_ASSEMBLE_4 ( _ptr, _index, __VA_ARGS__ ) )

#define BIT_ASSEMBLE_6( _ptr, _index, _field, _value, ... )		      \
	( BIT_ASSEMBLE_1 ( _ptr, _index, _field, _value ) |		      \
	  BIT_ASSEMBLE_5 ( _ptr, _index, __VA_ARGS__ ) )

#define BIT_ASSEMBLE_7( _ptr, _index, _field, _value, ... )		      \
	( BIT_ASSEMBLE_1 ( _ptr, _index, _field, _value ) |		      \
	  BIT_ASSEMBLE_6 ( _ptr, _index, __VA_ARGS__ ) )

/*
 * Build native-endian (positive) qword bitmasks from named fields
 *
 */

#define BIT_MASK_1( _ptr, _index, _field )				      \
	( BIT_MASK ( _ptr, _field ) <<					      \
	  QWORD_BIT_OFFSET ( _ptr, _index, _field ) )

#define BIT_MASK_2( _ptr, _index, _field, ... )				      \
	( BIT_MASK_1 ( _ptr, _index, _field ) |				      \
	  BIT_MASK_1 ( _ptr, _index, __VA_ARGS__ ) )

#define BIT_MASK_3( _ptr, _index, _field, ... )				      \
	( BIT_MASK_1 ( _ptr, _index, _field ) |				      \
	  BIT_MASK_2 ( _ptr, _index, __VA_ARGS__ ) )

#define BIT_MASK_4( _ptr, _index, _field, ... )				      \
	( BIT_MASK_1 ( _ptr, _index, _field ) |				      \
	  BIT_MASK_3 ( _ptr, _index, __VA_ARGS__ ) )

#define BIT_MASK_5( _ptr, _index, _field, ... )				      \
	( BIT_MASK_1 ( _ptr, _index, _field ) |				      \
	  BIT_MASK_4 ( _ptr, _index, __VA_ARGS__ ) )

#define BIT_MASK_6( _ptr, _index, _field, ... )				      \
	( BIT_MASK_1 ( _ptr, _index, _field ) |				      \
	  BIT_MASK_5 ( _ptr, _index, __VA_ARGS__ ) )

#define BIT_MASK_7( _ptr, _index, _field, ... )				      \
	( BIT_MASK_1 ( _ptr, _index, _field ) |				      \
	  BIT_MASK_6 ( _ptr, _index, __VA_ARGS__ ) )

/*
 * Populate little-endian qwords from named fields and values
 *
 */

#define BIT_FILL( _ptr, _index, _assembled ) do {			      \
		uint64_t *__ptr = &(_ptr)->u.qwords[(_index)];		      \
		uint64_t __assembled = (_assembled);			      \
		*__ptr = cpu_to_BIT64 ( __assembled );			      \
	} while ( 0 )

#define BIT_FILL_1( _ptr, _field1, ... )				      \
	BIT_FILL ( _ptr, QWORD_OFFSET ( _ptr, _field1 ),		      \
		   BIT_ASSEMBLE_1 ( _ptr, QWORD_OFFSET ( _ptr, _field1 ),     \
				    _field1, __VA_ARGS__ ) )

#define BIT_FILL_2( _ptr, _field1, ... )				      \
	BIT_FILL ( _ptr, QWORD_OFFSET ( _ptr, _field1 ),		      \
		   BIT_ASSEMBLE_2 ( _ptr, QWORD_OFFSET ( _ptr, _field1 ),     \
				    _field1, __VA_ARGS__ ) )

#define BIT_FILL_3( _ptr, _field1, ... )				      \
	BIT_FILL ( _ptr, QWORD_OFFSET ( _ptr, _field1 ),		      \
		   BIT_ASSEMBLE_3 ( _ptr, QWORD_OFFSET ( _ptr, _field1 ),     \
				    _field1, __VA_ARGS__ ) )

#define BIT_FILL_4( _ptr, _field1, ... )				      \
	BIT_FILL ( _ptr, QWORD_OFFSET ( _ptr, _field1 ),		      \
		   BIT_ASSEMBLE_4 ( _ptr, QWORD_OFFSET ( _ptr, _field1 ),     \
				    _field1, __VA_ARGS__ ) )

#define BIT_FILL_5( _ptr, _field1, ... )				      \
	BIT_FILL ( _ptr, QWORD_OFFSET ( _ptr, _field1 ),		      \
		   BIT_ASSEMBLE_5 ( _ptr, QWORD_OFFSET ( _ptr, _field1 ),     \
				    _field1, __VA_ARGS__ ) )

#define BIT_FILL_6( _ptr, _field1, ... )				      \
	BIT_FILL ( _ptr, QWORD_OFFSET ( _ptr, _field1 ),		      \
		   BIT_ASSEMBLE_6 ( _ptr, QWORD_OFFSET ( _ptr, _field1 ),     \
				    _field1, __VA_ARGS__ ) )

/** Extract value of named field */
#define BIT_GET64( _ptr, _field )					      \
	( {								      \
		unsigned int __index = QWORD_OFFSET ( _ptr, _field );	      \
		uint64_t *__ptr = &(_ptr)->u.qwords[__index];		      \
		uint64_t __value = BIT64_to_cpu ( *__ptr );		      \
		__value >>=						      \
		    QWORD_BIT_OFFSET ( _ptr, __index, _field );		      \
		__value &= BIT_MASK ( _ptr, _field );			      \
		__value;						      \
	} )

/** Extract value of named field (for fields up to the size of a long) */
#define BIT_GET( _ptr, _field )						      \
	( ( unsigned long ) BIT_GET64 ( _ptr, _field ) )

#define BIT_SET( _ptr, _field, _value ) do {				      \
		unsigned int __index = QWORD_OFFSET ( _ptr, _field );	      \
		uint64_t *__ptr = &(_ptr)->u.qwords[__index];		      \
		unsigned int __shift =					      \
			QWORD_BIT_OFFSET ( _ptr, __index, _field );	      \
		uint64_t __value = (_value);				      \
		*__ptr &= cpu_to_BIT64 ( ~( BIT_MASK ( _ptr, _field ) <<      \
					    __shift ) );		      \
		*__ptr |= cpu_to_BIT64 ( __value << __shift );		      \
	} while ( 0 )

#endif /* _IPXE_BITOPS_H */
