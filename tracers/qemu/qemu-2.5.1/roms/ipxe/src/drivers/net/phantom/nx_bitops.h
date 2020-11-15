#ifndef _NX_BITOPS_H
#define _NX_BITOPS_H

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
 * NetXen bit operations
 *
 */

/** Datatype used to represent a bit in the pseudo-structures */
typedef unsigned char pseudo_bit_t;

/**
 * Wrapper structure for pseudo_bit_t structures
 *
 * This structure provides a wrapper around pseudo_bit_t structures.
 * It has the correct size, and also encapsulates type information
 * about the underlying pseudo_bit_t-based structure, which allows the
 * NX_FILL etc. macros to work without requiring explicit type
 * information.
 */
#define NX_PSEUDO_BIT_STRUCT( _structure )				     \
	union {								     \
		uint8_t bytes[ sizeof ( _structure ) / 8 ];		     \
		uint64_t qwords[ sizeof ( _structure ) / 64 ];		     \
		_structure *dummy[0];					     \
	} u;

/** Get pseudo_bit_t structure type from wrapper structure pointer */
#define NX_PSEUDO_STRUCT( _ptr )					     \
	typeof ( *((_ptr)->u.dummy[0]) )

/** Bit offset of a field within a pseudo_bit_t structure */
#define NX_BIT_OFFSET( _ptr, _field )					     \
	offsetof ( NX_PSEUDO_STRUCT ( _ptr ), _field )

/** Bit width of a field within a pseudo_bit_t structure */
#define NX_BIT_WIDTH( _ptr, _field )					     \
	sizeof ( ( ( NX_PSEUDO_STRUCT ( _ptr ) * ) NULL )->_field )

/** Qword offset of a field within a pseudo_bit_t structure */
#define NX_QWORD_OFFSET( _ptr, _field )					     \
	( NX_BIT_OFFSET ( _ptr, _field ) / 64 )

/** Qword bit offset of a field within a pseudo_bit_t structure
 *
 * Yes, using mod-64 would work, but would lose the check for the
 * error of specifying a mismatched field name and qword index.
 */
#define NX_QWORD_BIT_OFFSET( _ptr, _index, _field )			     \
	( NX_BIT_OFFSET ( _ptr, _field ) - ( 64 * (_index) ) )

/** Bit mask for a field within a pseudo_bit_t structure */
#define NX_BIT_MASK( _ptr, _field )					     \
	( ( ~( ( uint64_t ) 0 ) ) >>					     \
	  ( 64 - NX_BIT_WIDTH ( _ptr, _field ) ) )

/*
 * Assemble native-endian qword from named fields and values
 *
 */

#define NX_ASSEMBLE_1( _ptr, _index, _field, _value )			     \
	( ( ( uint64_t) (_value) ) <<					     \
	  NX_QWORD_BIT_OFFSET ( _ptr, _index, _field ) )

#define NX_ASSEMBLE_2( _ptr, _index, _field, _value, ... )		     \
	( NX_ASSEMBLE_1 ( _ptr, _index, _field, _value ) |		     \
	  NX_ASSEMBLE_1 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_ASSEMBLE_3( _ptr, _index, _field, _value, ... )		     \
	( NX_ASSEMBLE_1 ( _ptr, _index, _field, _value ) |		     \
	  NX_ASSEMBLE_2 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_ASSEMBLE_4( _ptr, _index, _field, _value, ... )		     \
	( NX_ASSEMBLE_1 ( _ptr, _index, _field, _value ) |		     \
	  NX_ASSEMBLE_3 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_ASSEMBLE_5( _ptr, _index, _field, _value, ... )		     \
	( NX_ASSEMBLE_1 ( _ptr, _index, _field, _value ) |		     \
	  NX_ASSEMBLE_4 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_ASSEMBLE_6( _ptr, _index, _field, _value, ... )		     \
	( NX_ASSEMBLE_1 ( _ptr, _index, _field, _value ) |		     \
	  NX_ASSEMBLE_5 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_ASSEMBLE_7( _ptr, _index, _field, _value, ... )		     \
	( NX_ASSEMBLE_1 ( _ptr, _index, _field, _value ) |		     \
	  NX_ASSEMBLE_6 ( _ptr, _index, __VA_ARGS__ ) )

/*
 * Build native-endian (positive) qword bitmasks from named fields
 *
 */

#define NX_MASK_1( _ptr, _index, _field )			     \
	( NX_BIT_MASK ( _ptr, _field ) <<			     \
	  NX_QWORD_BIT_OFFSET ( _ptr, _index, _field ) )

#define NX_MASK_2( _ptr, _index, _field, ... )			     \
	( NX_MASK_1 ( _ptr, _index, _field ) |			     \
	  NX_MASK_1 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_MASK_3( _ptr, _index, _field, ... )			     \
	( NX_MASK_1 ( _ptr, _index, _field ) |			     \
	  NX_MASK_2 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_MASK_4( _ptr, _index, _field, ... )			     \
	( NX_MASK_1 ( _ptr, _index, _field ) |			     \
	  NX_MASK_3 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_MASK_5( _ptr, _index, _field, ... )			     \
	( NX_MASK_1 ( _ptr, _index, _field ) |			     \
	  NX_MASK_4 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_MASK_6( _ptr, _index, _field, ... )			     \
	( NX_MASK_1 ( _ptr, _index, _field ) |			     \
	  NX_MASK_5 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_MASK_7( _ptr, _index, _field, ... )			     \
	( NX_MASK_1 ( _ptr, _index, _field ) |			     \
	  NX_MASK_6 ( _ptr, _index, __VA_ARGS__ ) )

/*
 * Populate big-endian qwords from named fields and values
 *
 */

#define NX_FILL( _ptr, _index, _assembled )				     \
	do {								     \
		uint64_t *__ptr = &(_ptr)->u.qwords[(_index)];		     \
		uint64_t __assembled = (_assembled);			     \
		*__ptr = cpu_to_le64 ( __assembled );			     \
	} while ( 0 )

#define NX_FILL_1( _ptr, _index, ... )					     \
	NX_FILL ( _ptr, _index, NX_ASSEMBLE_1 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_FILL_2( _ptr, _index, ... )					     \
	NX_FILL ( _ptr, _index, NX_ASSEMBLE_2 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_FILL_3( _ptr, _index, ... )					     \
	NX_FILL ( _ptr, _index, NX_ASSEMBLE_3 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_FILL_4( _ptr, _index, ... )					     \
	NX_FILL ( _ptr, _index, NX_ASSEMBLE_4 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_FILL_5( _ptr, _index, ... )					     \
	NX_FILL ( _ptr, _index, NX_ASSEMBLE_5 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_FILL_6( _ptr, _index, ... )					     \
	NX_FILL ( _ptr, _index, NX_ASSEMBLE_6 ( _ptr, _index, __VA_ARGS__ ) )

#define NX_FILL_7( _ptr, _index, ... )					     \
	NX_FILL ( _ptr, _index, NX_ASSEMBLE_7 ( _ptr, _index, __VA_ARGS__ ) )

/** Extract value of named field */
#define NX_GET64( _ptr, _field )					     \
	( {								     \
		unsigned int __index = NX_QWORD_OFFSET ( _ptr, _field );     \
		uint64_t *__ptr = &(_ptr)->u.qwords[__index];		     \
		uint64_t __value = le64_to_cpu ( *__ptr );		     \
		__value >>=						     \
		    NX_QWORD_BIT_OFFSET ( _ptr, __index, _field );	     \
		__value &= NX_BIT_MASK ( _ptr, _field );		     \
		__value;						     \
	} )

/** Extract value of named field (for fields up to the size of a long) */
#define NX_GET( _ptr, _field )						     \
	( ( unsigned long ) NX_GET64 ( _ptr, _field ) )

#endif /* _NX_BITOPS_H */
