/**************************************************************************
 *
 * GPL net driver for Level 5 Etherfabric network cards
 *
 * Written by Michael Brown <mbrown@fensystems.co.uk>
 *
 * Copyright Fen Systems Ltd. 2005
 * Copyright Level 5 Networks Inc. 2005
 *
 * This software may be used and distributed according to the terms of
 * the GNU General Public License (GPL), incorporated herein by
 * reference.  Drivers based on or derived from this code fall under
 * the GPL and must retain the authorship, copyright and license
 * notice.  This file is not a complete program and may only be used
 * when the entire operating system is licensed under the GPL.
 *
 **************************************************************************
 */

FILE_LICENCE ( GPL_ANY );

#ifndef EFAB_BITFIELD_H
#define EFAB_BITFIELD_H

/** @file
 *
 * Etherfabric bitfield access
 *
 * Etherfabric NICs make extensive use of bitfields up to 128 bits
 * wide.  Since there is no native 128-bit datatype on most systems,
 * and since 64-bit datatypes are inefficient on 32-bit systems and
 * vice versa, we wrap accesses in a way that uses the most efficient
 * datatype.
 *
 * The NICs are PCI devices and therefore little-endian.  Since most
 * of the quantities that we deal with are DMAed to/from host memory,
 * we define our datatypes (efab_oword_t, efab_qword_t and
 * efab_dword_t) to be little-endian.
 *
 * In the less common case of using PIO for individual register
 * writes, we construct the little-endian datatype in host memory and
 * then use non-swapping equivalents of writel/writeq, rather than
 * constructing a native-endian datatype and relying on the implicit
 * byte-swapping done by writel/writeq.  (We use a similar strategy
 * for register reads.)
 */

/** Dummy field low bit number */
#define EFAB_DUMMY_FIELD_LBN 0
/** Dummy field width */
#define EFAB_DUMMY_FIELD_WIDTH 0
/** Dword 0 low bit number */
#define EFAB_DWORD_0_LBN 0
/** Dword 0 width */
#define EFAB_DWORD_0_WIDTH 32
/** Dword 1 low bit number */
#define EFAB_DWORD_1_LBN 32
/** Dword 1 width */
#define EFAB_DWORD_1_WIDTH 32
/** Dword 2 low bit number */
#define EFAB_DWORD_2_LBN 64
/** Dword 2 width */
#define EFAB_DWORD_2_WIDTH 32
/** Dword 3 low bit number */
#define EFAB_DWORD_3_LBN 96
/** Dword 3 width */
#define EFAB_DWORD_3_WIDTH 32

/** Specified attribute (e.g. LBN) of the specified field */
#define EFAB_VAL(field,attribute) field ## _ ## attribute
/** Low bit number of the specified field */
#define EFAB_LOW_BIT( field ) EFAB_VAL ( field, LBN )
/** Bit width of the specified field */
#define EFAB_WIDTH( field ) EFAB_VAL ( field, WIDTH )
/** High bit number of the specified field */
#define EFAB_HIGH_BIT(field) ( EFAB_LOW_BIT(field) + EFAB_WIDTH(field) - 1 )
/** Mask equal in width to the specified field.
 *
 * For example, a field with width 5 would have a mask of 0x1f.
 *
 * The maximum width mask that can be generated is 64 bits.
 */
#define EFAB_MASK64( field )						\
	( EFAB_WIDTH(field) == 64 ? ~( ( uint64_t ) 0 ) :		\
	  ( ( ( ( ( uint64_t ) 1 ) << EFAB_WIDTH(field) ) ) - 1 ) )

/** Mask equal in width to the specified field.
 *
 * For example, a field with width 5 would have a mask of 0x1f.
 *
 * The maximum width mask that can be generated is 32 bits.  Use
 * EFAB_MASK64 for higher width fields.
 */
#define EFAB_MASK32( field )						\
	( EFAB_WIDTH(field) == 32 ? ~( ( uint32_t ) 0 ) :		\
	  ( ( ( ( ( uint32_t ) 1 ) << EFAB_WIDTH(field) ) ) - 1 ) )

/** A doubleword (i.e. 4 byte) datatype
 *
 * This datatype is defined to be little-endian.
 */
typedef union efab_dword {
	uint32_t u32[1];
	uint32_t opaque; /* For bitwise operations between two efab_dwords */
} efab_dword_t;

/** A quadword (i.e. 8 byte) datatype
 *
 * This datatype is defined to be little-endian.
 */
typedef union efab_qword {
	uint64_t u64[1];
	uint32_t u32[2];
	efab_dword_t dword[2];
} efab_qword_t;

/**
 * An octword (eight-word, i.e. 16 byte) datatype
 *
 * This datatype is defined to be little-endian.
 */
typedef union efab_oword {
	uint64_t u64[2];
	efab_qword_t qword[2];
	uint32_t u32[4];
	efab_dword_t dword[4];
} efab_oword_t;

/** Format string for printing an efab_dword_t */
#define EFAB_DWORD_FMT "%08x"

/** Format string for printing an efab_qword_t */
#define EFAB_QWORD_FMT "%08x:%08x"

/** Format string for printing an efab_oword_t */
#define EFAB_OWORD_FMT "%08x:%08x:%08x:%08x"

/** printk parameters for printing an efab_dword_t */
#define EFAB_DWORD_VAL(dword)					\
	( ( unsigned int ) le32_to_cpu ( (dword).u32[0] ) )

/** printk parameters for printing an efab_qword_t */
#define EFAB_QWORD_VAL(qword)					\
	( ( unsigned int ) le32_to_cpu ( (qword).u32[1] ) ),	\
	( ( unsigned int ) le32_to_cpu ( (qword).u32[0] ) )

/** printk parameters for printing an efab_oword_t */
#define EFAB_OWORD_VAL(oword)					\
	( ( unsigned int ) le32_to_cpu ( (oword).u32[3] ) ),	\
	( ( unsigned int ) le32_to_cpu ( (oword).u32[2] ) ),	\
	( ( unsigned int ) le32_to_cpu ( (oword).u32[1] ) ),	\
	( ( unsigned int ) le32_to_cpu ( (oword).u32[0] ) )

/**
 * Extract bit field portion [low,high) from the native-endian element
 * which contains bits [min,max).
 *
 * For example, suppose "element" represents the high 32 bits of a
 * 64-bit value, and we wish to extract the bits belonging to the bit
 * field occupying bits 28-45 of this 64-bit value.
 *
 * Then EFAB_EXTRACT ( element, 32, 63, 28, 45 ) would give
 *
 *   ( element ) << 4
 *
 * The result will contain the relevant bits filled in in the range
 * [0,high-low), with garbage in bits [high-low+1,...).
 */
#define EFAB_EXTRACT_NATIVE( native_element, min ,max ,low ,high )	\
	( ( ( low > max ) || ( high < min ) ) ? 0 :			\
	  ( ( low > min ) ?						\
	    ( (native_element) >> ( low - min ) ) :			\
	    ( (native_element) << ( min - low ) ) ) )

/**
 * Extract bit field portion [low,high) from the 64-bit little-endian
 * element which contains bits [min,max)
 */
#define EFAB_EXTRACT64( element, min, max, low, high )			\
	EFAB_EXTRACT_NATIVE ( le64_to_cpu(element), min, max, low, high )

/**
 * Extract bit field portion [low,high) from the 32-bit little-endian
 * element which contains bits [min,max)
 */
#define EFAB_EXTRACT32( element, min, max, low, high )			\
	EFAB_EXTRACT_NATIVE ( le32_to_cpu(element), min, max, low, high )

#define EFAB_EXTRACT_OWORD64( oword, low, high )			\
	( EFAB_EXTRACT64 ( (oword).u64[0],   0,  63, low, high ) |	\
	  EFAB_EXTRACT64 ( (oword).u64[1],  64, 127, low, high ) )

#define EFAB_EXTRACT_QWORD64( qword, low, high )			\
	( EFAB_EXTRACT64 ( (qword).u64[0],   0,  63, low, high ) )

#define EFAB_EXTRACT_OWORD32( oword, low, high )			\
	( EFAB_EXTRACT32 ( (oword).u32[0],   0,  31, low, high ) |	\
	  EFAB_EXTRACT32 ( (oword).u32[1],  32,  63, low, high ) |	\
	  EFAB_EXTRACT32 ( (oword).u32[2],  64,  95, low, high ) |	\
	  EFAB_EXTRACT32 ( (oword).u32[3],  96, 127, low, high ) )

#define EFAB_EXTRACT_QWORD32( qword, low, high )			\
	( EFAB_EXTRACT32 ( (qword).u32[0],   0,  31, low, high ) |	\
	  EFAB_EXTRACT32 ( (qword).u32[1],  32,  63, low, high ) )

#define EFAB_EXTRACT_DWORD( dword, low, high )				\
	( EFAB_EXTRACT32 ( (dword).u32[0],   0,  31, low, high ) )

#define EFAB_OWORD_FIELD64( oword, field )				\
	( EFAB_EXTRACT_OWORD64 ( oword, EFAB_LOW_BIT ( field ),		\
				 EFAB_HIGH_BIT ( field ) ) &		\
	  EFAB_MASK64 ( field ) )

#define EFAB_QWORD_FIELD64( qword, field )				\
	( EFAB_EXTRACT_QWORD64 ( qword, EFAB_LOW_BIT ( field ),		\
				 EFAB_HIGH_BIT ( field ) ) &		\
	  EFAB_MASK64 ( field ) )

#define EFAB_OWORD_FIELD32( oword, field )				\
	( EFAB_EXTRACT_OWORD32 ( oword, EFAB_LOW_BIT ( field ),		\
				 EFAB_HIGH_BIT ( field ) ) &		\
	  EFAB_MASK32 ( field ) )

#define EFAB_QWORD_FIELD32( qword, field )				\
	( EFAB_EXTRACT_QWORD32 ( qword, EFAB_LOW_BIT ( field ),		\
				 EFAB_HIGH_BIT ( field ) ) &		\
	  EFAB_MASK32 ( field ) )

#define EFAB_DWORD_FIELD( dword, field )				\
	( EFAB_EXTRACT_DWORD ( dword, EFAB_LOW_BIT ( field ),		\
			       EFAB_HIGH_BIT ( field ) ) &		\
	  EFAB_MASK32 ( field ) )

#define EFAB_OWORD_IS_ZERO64( oword )					\
	( ! ( (oword).u64[0] || (oword).u64[1] ) )

#define EFAB_QWORD_IS_ZERO64( qword )					\
	( ! ( (qword).u64[0] ) )

#define EFAB_OWORD_IS_ZERO32( oword )					\
	( ! ( (oword).u32[0] || (oword).u32[1] ||			\
	      (oword).u32[2] || (oword).u32[3] ) )

#define EFAB_QWORD_IS_ZERO32( qword )					\
	( ! ( (qword).u32[0] || (qword).u32[1] ) )

#define EFAB_DWORD_IS_ZERO( dword )					\
	( ! ( (dword).u32[0] ) )

#define EFAB_OWORD_IS_ALL_ONES64( oword )				\
	( ( (oword).u64[0] & (oword).u64[1] ) == ~( ( uint64_t ) 0 ) )

#define EFAB_QWORD_IS_ALL_ONES64( qword )				\
	( (qword).u64[0] == ~( ( uint64_t ) 0 ) )

#define EFAB_OWORD_IS_ALL_ONES32( oword )				\
	( ( (oword).u32[0] & (oword).u32[1] &				\
	    (oword).u32[2] & (oword).u32[3] ) == ~( ( uint32_t ) 0 ) )

#define EFAB_QWORD_IS_ALL_ONES32( qword )				\
	( ( (qword).u32[0] & (qword).u32[1] ) == ~( ( uint32_t ) 0 ) )

#define EFAB_DWORD_IS_ALL_ONES( dword )					\
	( (dword).u32[0] == ~( ( uint32_t ) 0 ) )

#if ( BITS_PER_LONG == 64 )
#define EFAB_OWORD_FIELD	EFAB_OWORD_FIELD64
#define EFAB_QWORD_FIELD	EFAB_QWORD_FIELD64
#define EFAB_OWORD_IS_ZERO	EFAB_OWORD_IS_ZERO64
#define EFAB_QWORD_IS_ZERO	EFAB_QWORD_IS_ZERO64
#define EFAB_OWORD_IS_ALL_ONES	EFAB_OWORD_IS_ALL_ONES64
#define EFAB_QWORD_IS_ALL_ONES	EFAB_QWORD_IS_ALL_ONES64
#else
#define EFAB_OWORD_FIELD	EFAB_OWORD_FIELD32
#define EFAB_QWORD_FIELD	EFAB_QWORD_FIELD32
#define EFAB_OWORD_IS_ZERO	EFAB_OWORD_IS_ZERO32
#define EFAB_QWORD_IS_ZERO	EFAB_QWORD_IS_ZERO32
#define EFAB_OWORD_IS_ALL_ONES	EFAB_OWORD_IS_ALL_ONES32
#define EFAB_QWORD_IS_ALL_ONES	EFAB_QWORD_IS_ALL_ONES32
#endif

/**
 * Construct bit field portion
 *
 * Creates the portion of the bit field [low,high) that lies within
 * the range [min,max).
 */
#define EFAB_INSERT_NATIVE64( min, max, low, high, value )	\
	( ( ( low > max ) || ( high < min ) ) ? 0 :		\
	  ( ( low > min ) ?					\
	    ( ( ( uint64_t ) (value) ) << ( low - min ) ) :	\
	    ( ( ( uint64_t ) (value) ) >> ( min - low ) ) ) )

#define EFAB_INSERT_NATIVE32( min, max, low, high, value )	\
	( ( ( low > max ) || ( high < min ) ) ? 0 :		\
	  ( ( low > min ) ?					\
	    ( ( ( uint32_t ) (value) ) << ( low - min ) ) :	\
	    ( ( ( uint32_t ) (value) ) >> ( min - low ) ) ) )

#define EFAB_INSERT_NATIVE( min, max, low, high, value )	\
	( ( ( ( max - min ) >= 32 ) ||				\
	    ( ( high - low ) >= 32 ) )	 			\
	  ? EFAB_INSERT_NATIVE64 ( min, max, low, high, value )	\
	  : EFAB_INSERT_NATIVE32 ( min, max, low, high, value ) )

/**
 * Construct bit field portion
 *
 * Creates the portion of the named bit field that lies within the
 * range [min,max).
 */
#define EFAB_INSERT_FIELD_NATIVE( min, max, field, value )	\
	EFAB_INSERT_NATIVE ( min, max, EFAB_LOW_BIT ( field ),	\
			     EFAB_HIGH_BIT ( field ), value )

/**
 * Construct bit field
 *
 * Creates the portion of the named bit fields that lie within the
 * range [min,max).
 */
#define EFAB_INSERT_FIELDS_NATIVE( min, max,				\
				   field1, value1,			\
				   field2, value2,			\
				   field3, value3,			\
				   field4, value4,			\
				   field5, value5,			\
				   field6, value6,			\
				   field7, value7,			\
				   field8, value8,			\
				   field9, value9,			\
				   field10, value10 )			\
	( EFAB_INSERT_FIELD_NATIVE ( min, max, field1, value1 ) |	\
	  EFAB_INSERT_FIELD_NATIVE ( min, max, field2, value2 ) |	\
	  EFAB_INSERT_FIELD_NATIVE ( min, max, field3, value3 ) |	\
	  EFAB_INSERT_FIELD_NATIVE ( min, max, field4, value4 ) |	\
	  EFAB_INSERT_FIELD_NATIVE ( min, max, field5, value5 ) |	\
	  EFAB_INSERT_FIELD_NATIVE ( min, max, field6, value6 ) |	\
	  EFAB_INSERT_FIELD_NATIVE ( min, max, field7, value7 ) |	\
	  EFAB_INSERT_FIELD_NATIVE ( min, max, field8, value8 ) |	\
	  EFAB_INSERT_FIELD_NATIVE ( min, max, field9, value9 ) |	\
	  EFAB_INSERT_FIELD_NATIVE ( min, max, field10, value10 ) )

#define EFAB_INSERT_FIELDS64( ... )					\
	cpu_to_le64 ( EFAB_INSERT_FIELDS_NATIVE ( __VA_ARGS__ ) )

#define EFAB_INSERT_FIELDS32( ... )					\
	cpu_to_le32 ( EFAB_INSERT_FIELDS_NATIVE ( __VA_ARGS__ ) )

#define EFAB_POPULATE_OWORD64( oword, ... ) do {			\
	(oword).u64[0] = EFAB_INSERT_FIELDS64 (   0,  63, __VA_ARGS__ );\
	(oword).u64[1] = EFAB_INSERT_FIELDS64 (  64, 127, __VA_ARGS__ );\
	} while ( 0 )

#define EFAB_POPULATE_QWORD64( qword, ... ) do {			\
	(qword).u64[0] = EFAB_INSERT_FIELDS64 (   0,  63, __VA_ARGS__ );\
	} while ( 0 )

#define EFAB_POPULATE_OWORD32( oword, ... ) do {			\
	(oword).u32[0] = EFAB_INSERT_FIELDS32 (   0,  31, __VA_ARGS__ );\
	(oword).u32[1] = EFAB_INSERT_FIELDS32 (  32,  63, __VA_ARGS__ );\
	(oword).u32[2] = EFAB_INSERT_FIELDS32 (  64,  95, __VA_ARGS__ );\
	(oword).u32[3] = EFAB_INSERT_FIELDS32 (  96, 127, __VA_ARGS__ );\
	} while ( 0 )

#define EFAB_POPULATE_QWORD32( qword, ... ) do {			\
	(qword).u32[0] = EFAB_INSERT_FIELDS32 (   0,  31, __VA_ARGS__ );\
	(qword).u32[1] = EFAB_INSERT_FIELDS32 (  32,  63, __VA_ARGS__ );\
	} while ( 0 )

#define EFAB_POPULATE_DWORD( dword, ... ) do {				\
	(dword).u32[0] = EFAB_INSERT_FIELDS32 (   0,  31, __VA_ARGS__ );\
	} while ( 0 )

#if ( BITS_PER_LONG == 64 )
#define EFAB_POPULATE_OWORD EFAB_POPULATE_OWORD64
#define EFAB_POPULATE_QWORD EFAB_POPULATE_QWORD64
#else
#define EFAB_POPULATE_OWORD EFAB_POPULATE_OWORD32
#define EFAB_POPULATE_QWORD EFAB_POPULATE_QWORD32
#endif

/* Populate an octword field with various numbers of arguments */
#define EFAB_POPULATE_OWORD_10 EFAB_POPULATE_OWORD
#define EFAB_POPULATE_OWORD_9( oword, ... ) \
	EFAB_POPULATE_OWORD_10 ( oword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_OWORD_8( oword, ... ) \
	EFAB_POPULATE_OWORD_9 ( oword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_OWORD_7( oword, ... ) \
	EFAB_POPULATE_OWORD_8 ( oword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_OWORD_6( oword, ... ) \
	EFAB_POPULATE_OWORD_7 ( oword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_OWORD_5( oword, ... ) \
	EFAB_POPULATE_OWORD_6 ( oword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_OWORD_4( oword, ... ) \
	EFAB_POPULATE_OWORD_5 ( oword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_OWORD_3( oword, ... ) \
	EFAB_POPULATE_OWORD_4 ( oword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_OWORD_2( oword, ... ) \
	EFAB_POPULATE_OWORD_3 ( oword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_OWORD_1( oword, ... ) \
	EFAB_POPULATE_OWORD_2 ( oword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_ZERO_OWORD( oword ) \
	EFAB_POPULATE_OWORD_1 ( oword, EFAB_DUMMY_FIELD, 0 )
#define EFAB_SET_OWORD( oword ) \
	EFAB_POPULATE_OWORD_4 ( oword, \
				EFAB_DWORD_0, 0xffffffff, \
				EFAB_DWORD_1, 0xffffffff, \
				EFAB_DWORD_2, 0xffffffff, \
				EFAB_DWORD_3, 0xffffffff )

/* Populate a quadword field with various numbers of arguments */
#define EFAB_POPULATE_QWORD_10 EFAB_POPULATE_QWORD
#define EFAB_POPULATE_QWORD_9( qword, ... ) \
	EFAB_POPULATE_QWORD_10 ( qword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_QWORD_8( qword, ... ) \
	EFAB_POPULATE_QWORD_9 ( qword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_QWORD_7( qword, ... ) \
	EFAB_POPULATE_QWORD_8 ( qword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_QWORD_6( qword, ... ) \
	EFAB_POPULATE_QWORD_7 ( qword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_QWORD_5( qword, ... ) \
	EFAB_POPULATE_QWORD_6 ( qword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_QWORD_4( qword, ... ) \
	EFAB_POPULATE_QWORD_5 ( qword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_QWORD_3( qword, ... ) \
	EFAB_POPULATE_QWORD_4 ( qword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_QWORD_2( qword, ... ) \
	EFAB_POPULATE_QWORD_3 ( qword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_QWORD_1( qword, ... ) \
	EFAB_POPULATE_QWORD_2 ( qword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_ZERO_QWORD( qword ) \
	EFAB_POPULATE_QWORD_1 ( qword, EFAB_DUMMY_FIELD, 0 )
#define EFAB_SET_QWORD( qword ) \
	EFAB_POPULATE_QWORD_2 ( qword, \
				EFAB_DWORD_0, 0xffffffff, \
				EFAB_DWORD_1, 0xffffffff )

/* Populate a dword field with various numbers of arguments */
#define EFAB_POPULATE_DWORD_10 EFAB_POPULATE_DWORD
#define EFAB_POPULATE_DWORD_9( dword, ... ) \
	EFAB_POPULATE_DWORD_10 ( dword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_DWORD_8( dword, ... ) \
	EFAB_POPULATE_DWORD_9 ( dword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_DWORD_7( dword, ... ) \
	EFAB_POPULATE_DWORD_8 ( dword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_DWORD_6( dword, ... ) \
	EFAB_POPULATE_DWORD_7 ( dword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_DWORD_5( dword, ... ) \
	EFAB_POPULATE_DWORD_6 ( dword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_DWORD_4( dword, ... ) \
	EFAB_POPULATE_DWORD_5 ( dword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_DWORD_3( dword, ... ) \
	EFAB_POPULATE_DWORD_4 ( dword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_DWORD_2( dword, ... ) \
	EFAB_POPULATE_DWORD_3 ( dword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_POPULATE_DWORD_1( dword, ... ) \
	EFAB_POPULATE_DWORD_2 ( dword, EFAB_DUMMY_FIELD, 0, __VA_ARGS__ )
#define EFAB_ZERO_DWORD( dword ) \
	EFAB_POPULATE_DWORD_1 ( dword, EFAB_DUMMY_FIELD, 0 )
#define EFAB_SET_DWORD( dword ) \
	EFAB_POPULATE_DWORD_1 ( dword, EFAB_DWORD_0, 0xffffffff )

/*
 * Modify a named field within an already-populated structure.  Used
 * for read-modify-write operations.
 *
 */

#define EFAB_INSERT_FIELD64( ... )					\
	cpu_to_le64 ( EFAB_INSERT_FIELD_NATIVE ( __VA_ARGS__ ) )

#define EFAB_INSERT_FIELD32( ... )					\
	cpu_to_le32 ( EFAB_INSERT_FIELD_NATIVE ( __VA_ARGS__ ) )

#define EFAB_INPLACE_MASK64( min, max, field )				\
	EFAB_INSERT_FIELD64 ( min, max, field, EFAB_MASK64 ( field ) )

#define EFAB_INPLACE_MASK32( min, max, field )				\
	EFAB_INSERT_FIELD32 ( min, max, field, EFAB_MASK32 ( field ) )

#define EFAB_SET_OWORD_FIELD64( oword, field, value ) do {		      \
	(oword).u64[0] = ( ( (oword).u64[0] 				      \
			     & ~EFAB_INPLACE_MASK64 (  0,  63, field ) )      \
			   | EFAB_INSERT_FIELD64 (  0,  63, field, value ) ); \
	(oword).u64[1] = ( ( (oword).u64[1] 				      \
			     & ~EFAB_INPLACE_MASK64 ( 64, 127, field ) )      \
			   | EFAB_INSERT_FIELD64 ( 64, 127, field, value ) ); \
	} while ( 0 )

#define EFAB_SET_QWORD_FIELD64( qword, field, value ) do {		      \
	(qword).u64[0] = ( ( (qword).u64[0] 				      \
			     & ~EFAB_INPLACE_MASK64 (  0,  63, field ) )      \
			   | EFAB_INSERT_FIELD64 (  0,  63, field, value ) ); \
	} while ( 0 )

#define EFAB_SET_OWORD_FIELD32( oword, field, value ) do {		      \
	(oword).u32[0] = ( ( (oword).u32[0] 				      \
			     & ~EFAB_INPLACE_MASK32 (  0,  31, field ) )      \
			   | EFAB_INSERT_FIELD32 (  0,  31, field, value ) ); \
	(oword).u32[1] = ( ( (oword).u32[1] 				      \
			     & ~EFAB_INPLACE_MASK32 ( 32,  63, field ) )      \
			   | EFAB_INSERT_FIELD32 ( 32,  63, field, value ) ); \
	(oword).u32[2] = ( ( (oword).u32[2] 				      \
			     & ~EFAB_INPLACE_MASK32 ( 64,  95, field ) )      \
			   | EFAB_INSERT_FIELD32 ( 64,  95, field, value ) ); \
	(oword).u32[3] = ( ( (oword).u32[3] 				      \
			     & ~EFAB_INPLACE_MASK32 ( 96, 127, field ) )      \
			   | EFAB_INSERT_FIELD32 ( 96, 127, field, value ) ); \
	} while ( 0 )

#define EFAB_SET_QWORD_FIELD32( qword, field, value ) do {		      \
	(qword).u32[0] = ( ( (qword).u32[0] 				      \
			     & ~EFAB_INPLACE_MASK32 (  0,  31, field ) )      \
			   | EFAB_INSERT_FIELD32 (  0,  31, field, value ) ); \
	(qword).u32[1] = ( ( (qword).u32[1] 				      \
			     & ~EFAB_INPLACE_MASK32 ( 32,  63, field ) )      \
			   | EFAB_INSERT_FIELD32 ( 32,  63, field, value ) ); \
	} while ( 0 )

#define EFAB_SET_DWORD_FIELD( dword, field, value ) do {		      \
	(dword).u32[0] = ( ( (dword).u32[0] 				      \
			     & ~EFAB_INPLACE_MASK32 (  0,  31, field ) )      \
			   | EFAB_INSERT_FIELD32 (  0,  31, field, value ) ); \
	} while ( 0 )

#if ( BITS_PER_LONG == 64 )
#define EFAB_SET_OWORD_FIELD EFAB_SET_OWORD_FIELD64
#define EFAB_SET_QWORD_FIELD EFAB_SET_QWORD_FIELD64
#else
#define EFAB_SET_OWORD_FIELD EFAB_SET_OWORD_FIELD32
#define EFAB_SET_QWORD_FIELD EFAB_SET_QWORD_FIELD32
#endif

/* Used to avoid compiler warnings about shift range exceeding width
 * of the data types when dma_addr_t is only 32 bits wide.
 */
#define DMA_ADDR_T_WIDTH	( 8 * sizeof ( dma_addr_t ) )
#define EFAB_DMA_TYPE_WIDTH( width ) \
	( ( (width) < DMA_ADDR_T_WIDTH ) ? (width) : DMA_ADDR_T_WIDTH )
#define EFAB_DMA_MAX_MASK ( ( DMA_ADDR_T_WIDTH == 64 ) ? \
			    ~( ( uint64_t ) 0 ) : ~( ( uint32_t ) 0 ) )
#define EFAB_DMA_MASK(mask) ( (mask) & EFAB_DMA_MAX_MASK )

#endif /* EFAB_BITFIELD_H */

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
