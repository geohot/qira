/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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
 * memcpy() self-tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ipxe/test.h>
#include <ipxe/profile.h>

/** Number of sample iterations for profiling */
#define PROFILE_COUNT 16

/* Provide global functions to allow inspection of generated code */

void memcpy_0 ( void *dest, void *src ) { memcpy ( dest, src, 0 ); }
void memcpy_1 ( void *dest, void *src ) { memcpy ( dest, src, 1 ); }
void memcpy_2 ( void *dest, void *src ) { memcpy ( dest, src, 2 ); }
void memcpy_3 ( void *dest, void *src ) { memcpy ( dest, src, 3 ); }
void memcpy_4 ( void *dest, void *src ) { memcpy ( dest, src, 4 ); }
void memcpy_5 ( void *dest, void *src ) { memcpy ( dest, src, 5 ); }
void memcpy_6 ( void *dest, void *src ) { memcpy ( dest, src, 6 ); }
void memcpy_7 ( void *dest, void *src ) { memcpy ( dest, src, 7 ); }
void memcpy_8 ( void *dest, void *src ) { memcpy ( dest, src, 8 ); }
void memcpy_9 ( void *dest, void *src ) { memcpy ( dest, src, 9 ); }
void memcpy_10 ( void *dest, void *src ) { memcpy ( dest, src, 10 ); }
void memcpy_11 ( void *dest, void *src ) { memcpy ( dest, src, 11 ); }
void memcpy_12 ( void *dest, void *src ) { memcpy ( dest, src, 12 ); }
void memcpy_13 ( void *dest, void *src ) { memcpy ( dest, src, 13 ); }
void memcpy_14 ( void *dest, void *src ) { memcpy ( dest, src, 14 ); }
void memcpy_15 ( void *dest, void *src ) { memcpy ( dest, src, 15 ); }
void memcpy_16 ( void *dest, void *src ) { memcpy ( dest, src, 16 ); }
void memcpy_17 ( void *dest, void *src ) { memcpy ( dest, src, 17 ); }
void memcpy_18 ( void *dest, void *src ) { memcpy ( dest, src, 18 ); }
void memcpy_19 ( void *dest, void *src ) { memcpy ( dest, src, 19 ); }
void memcpy_20 ( void *dest, void *src ) { memcpy ( dest, src, 20 ); }
void memcpy_21 ( void *dest, void *src ) { memcpy ( dest, src, 21 ); }
void memcpy_22 ( void *dest, void *src ) { memcpy ( dest, src, 22 ); }
void memcpy_23 ( void *dest, void *src ) { memcpy ( dest, src, 23 ); }
void memcpy_24 ( void *dest, void *src ) { memcpy ( dest, src, 24 ); }
void memcpy_25 ( void *dest, void *src ) { memcpy ( dest, src, 25 ); }
void memcpy_26 ( void *dest, void *src ) { memcpy ( dest, src, 26 ); }
void memcpy_27 ( void *dest, void *src ) { memcpy ( dest, src, 27 ); }
void memcpy_28 ( void *dest, void *src ) { memcpy ( dest, src, 28 ); }
void memcpy_29 ( void *dest, void *src ) { memcpy ( dest, src, 29 ); }
void memcpy_30 ( void *dest, void *src ) { memcpy ( dest, src, 30 ); }
void memcpy_31 ( void *dest, void *src ) { memcpy ( dest, src, 31 ); }

/**
 * Force a call to the variable-length implementation of memcpy()
 *
 * @v dest		Destination address
 * @v src		Source address
 * @v len		Length of data
 * @ret dest		Destination address
 */
__attribute__ (( noinline )) void * memcpy_var ( void *dest, const void *src,
						 size_t len ) {
	return memcpy ( dest, src, len );
}

/**
 * Perform a constant-length memcpy() test
 *
 * ...			Data to copy
 */
#define MEMCPY_TEST_CONSTANT( ... ) do {				\
		static const uint8_t src[] = { __VA_ARGS__ };		\
		uint8_t dest_const[ 1 + sizeof ( src ) + 1 ];		\
		uint8_t dest_var[ 1 + sizeof ( src ) + 1 ];		\
									\
		dest_const[0] = 0x33;					\
		dest_const[ sizeof ( dest_const ) - 1 ] = 0x44;		\
		memcpy ( ( dest_const + 1 ), src,			\
			 ( sizeof ( dest_const ) - 2 ) );		\
		ok ( dest_const[0] == 0x33 );				\
		ok ( dest_const[ sizeof ( dest_const ) - 1 ] == 0x44 );	\
		ok ( memcmp ( ( dest_const + 1 ), src,			\
			      ( sizeof ( dest_const ) - 2 ) ) == 0 );	\
									\
		dest_var[0] = 0x55;					\
		dest_var[ sizeof ( dest_var ) - 1 ] = 0x66;		\
		memcpy_var ( ( dest_var + 1 ), src,			\
			     ( sizeof ( dest_var ) - 2 ) );		\
		ok ( dest_var[0] == 0x55 );				\
		ok ( dest_var[ sizeof ( dest_var ) - 1 ] == 0x66 );	\
		ok ( memcmp ( ( dest_var + 1 ), src,			\
			      ( sizeof ( dest_var ) - 2 ) ) == 0 );	\
	} while ( 0 )

/**
 * Test memcpy() speed
 *
 * @v dest_offset	Destination alignment offset
 * @v src_offset	Source alignment offset
 * @v len		Length of data to copy
 */
static void memcpy_test_speed ( unsigned int dest_offset,
				unsigned int src_offset, size_t len ) {
	struct profiler profiler;
	uint8_t *dest;
	uint8_t *src;
	unsigned int i;

	/* Allocate blocks */
	dest = malloc ( len + dest_offset );
	assert ( dest != NULL );
	src = malloc ( len + src_offset );
	assert ( src != NULL );

	/* Generate random source data */
	for ( i = 0 ; i < len ; i++ )
		src[ src_offset + i ] = random();

	/* Check correctness of copied data */
	memcpy ( ( dest + dest_offset ), ( src + src_offset ), len );
	ok ( memcmp ( ( dest + dest_offset ), ( src + src_offset ),
		      len ) == 0 );

	/* Profile memcpy() */
	memset ( &profiler, 0, sizeof ( profiler ) );
	for ( i = 0 ; i < PROFILE_COUNT ; i++ ) {
		profile_start ( &profiler );
		memcpy ( ( dest + dest_offset ), ( src + src_offset ), len );
		profile_stop ( &profiler );
	}

	/* Free blocks */
	free ( dest );
	free ( src );

	DBG ( "MEMCPY copied %zd bytes (+%d => +%d) in %ld +/- %ld ticks\n",
	      len, src_offset, dest_offset, profile_mean ( &profiler ),
	      profile_stddev ( &profiler ) );
}

/**
 * Perform memcpy() self-tests
 *
 */
static void memcpy_test_exec ( void ) {
	unsigned int dest_offset;
	unsigned int src_offset;

	/* Constant-length tests */
	MEMCPY_TEST_CONSTANT ( );
	MEMCPY_TEST_CONSTANT ( 0x86 );
	MEMCPY_TEST_CONSTANT ( 0x8c, 0xd3 );
	MEMCPY_TEST_CONSTANT ( 0x4e, 0x08, 0xed );
	MEMCPY_TEST_CONSTANT ( 0xcc, 0x61, 0x8f, 0x70 );
	MEMCPY_TEST_CONSTANT ( 0x6d, 0x28, 0xe0, 0x9e, 0x6d );
	MEMCPY_TEST_CONSTANT ( 0x7d, 0x13, 0x4f, 0xef, 0x17, 0xb3 );
	MEMCPY_TEST_CONSTANT ( 0x38, 0xa7, 0xd4, 0x8d, 0x44, 0x01, 0xfd );
	MEMCPY_TEST_CONSTANT ( 0x45, 0x9f, 0xf4, 0xf9, 0xf3, 0x0f, 0x99, 0x43 );
	MEMCPY_TEST_CONSTANT ( 0x69, 0x8c, 0xf6, 0x12, 0x79, 0x70, 0xd8, 0x1e,
			       0x9d );
	MEMCPY_TEST_CONSTANT ( 0xbe, 0x53, 0xb4, 0xb7, 0xdd, 0xe6, 0x35, 0x10,
			       0x3c, 0xe7 );
	MEMCPY_TEST_CONSTANT ( 0xaf, 0x41, 0x8a, 0x88, 0xb1, 0x4e, 0x52, 0xd4,
			       0xe6, 0xc3, 0x76 );
	MEMCPY_TEST_CONSTANT ( 0xdf, 0x43, 0xe4, 0x5d, 0xad, 0x17, 0x35, 0x38,
			       0x1a, 0x1d, 0x57, 0x58 );
	MEMCPY_TEST_CONSTANT ( 0x20, 0x52, 0x83, 0x92, 0xb9, 0x85, 0xa4, 0x06,
			       0x94, 0xe0, 0x3d, 0x57, 0xd4 );
	MEMCPY_TEST_CONSTANT ( 0xf1, 0x67, 0x31, 0x9e, 0x32, 0x98, 0x27, 0xe9,
			       0x8e, 0x62, 0xb4, 0x82, 0x7e, 0x02 );
	MEMCPY_TEST_CONSTANT ( 0x93, 0xc1, 0x55, 0xe3, 0x60, 0xce, 0xac, 0x1e,
			       0xae, 0x9d, 0xca, 0xec, 0x92, 0xb3, 0x38 );
	MEMCPY_TEST_CONSTANT ( 0xb3, 0xc1, 0xfa, 0xe7, 0x8a, 0x1c, 0xe4, 0xce,
			       0x85, 0xe6, 0x3c, 0xab, 0x1c, 0xa2, 0xaf, 0x7a );
	MEMCPY_TEST_CONSTANT ( 0x9b, 0x6e, 0x1c, 0x48, 0x82, 0xd3, 0x6e, 0x58,
			       0xa7, 0xb0, 0xe6, 0xea, 0x6d, 0xee, 0xc8, 0xf8,
			       0xaf );
	MEMCPY_TEST_CONSTANT ( 0x86, 0x6d, 0xb0, 0xf5, 0xf2, 0xc9, 0xcd, 0xfe,
			       0xfb, 0x38, 0x67, 0xbc, 0x51, 0x9d, 0x25, 0xbc,
			       0x09, 0x88 );
	MEMCPY_TEST_CONSTANT ( 0x58, 0xa4, 0x96, 0x9e, 0x98, 0x36, 0xdb, 0xae,
			       0x8a, 0x08, 0x7c, 0x64, 0xf9, 0xfb, 0x25, 0xb4,
			       0x8e, 0xf3, 0xed );
	MEMCPY_TEST_CONSTANT ( 0xc6, 0x3b, 0x84, 0x3c, 0x76, 0x24, 0x8e, 0x42,
			       0x11, 0x1f, 0x09, 0x2e, 0x24, 0xbb, 0x67, 0x71,
			       0x3a, 0xca, 0x60, 0xdd );
	MEMCPY_TEST_CONSTANT ( 0x8e, 0x2d, 0xa9, 0x58, 0x87, 0xe2, 0xac, 0x4b,
			       0xc8, 0xbf, 0xa2, 0x4e, 0xee, 0x3a, 0xa6, 0x71,
			       0x76, 0xee, 0x42, 0x05, 0x6e );
	MEMCPY_TEST_CONSTANT ( 0x8a, 0xda, 0xdf, 0x7b, 0x55, 0x41, 0x8c, 0xcd,
			       0x42, 0x40, 0x18, 0xe2, 0x60, 0xc4, 0x7d, 0x64,
			       0x00, 0xd5, 0xef, 0xa1, 0x7b, 0x31 );
	MEMCPY_TEST_CONSTANT ( 0xd9, 0x25, 0xcb, 0xbb, 0x9c, 0x1d, 0xdd, 0xcd,
			       0xde, 0x96, 0xd9, 0x74, 0x13, 0x95, 0xfe, 0x68,
			       0x0b, 0x3d, 0x30, 0x8d, 0x0c, 0x1e, 0x6d );
	MEMCPY_TEST_CONSTANT ( 0x2d, 0x0d, 0x02, 0x33, 0xd6, 0xbe, 0x6c, 0xa6,
			       0x0a, 0xab, 0xe5, 0xda, 0xe2, 0xab, 0x78, 0x3c,
			       0xd3, 0xdd, 0xea, 0xfa, 0x1a, 0xe4, 0xf4, 0xb3 );
	MEMCPY_TEST_CONSTANT ( 0x6a, 0x34, 0x39, 0xea, 0x29, 0x5f, 0xa6, 0x18,
			       0xc1, 0x53, 0x39, 0x78, 0xdb, 0x40, 0xf2, 0x98,
			       0x78, 0xcf, 0xee, 0xfd, 0xcd, 0xf8, 0x56, 0xf8,
			       0x30 );
	MEMCPY_TEST_CONSTANT ( 0xe4, 0xe5, 0x5a, 0x8d, 0xcf, 0x04, 0x29, 0x7c,
			       0xa7, 0xd8, 0x43, 0xbf, 0x0b, 0xbf, 0xe7, 0x68,
			       0xf7, 0x8c, 0x81, 0xf9, 0x3f, 0xad, 0xa4, 0x40,
			       0x38, 0x82 );
	MEMCPY_TEST_CONSTANT ( 0x71, 0xcd, 0x3d, 0x26, 0xde, 0x11, 0x23, 0xd5,
			       0x42, 0x6e, 0x63, 0x72, 0x53, 0xfc, 0x28, 0x06,
			       0x4b, 0xe0, 0x2c, 0x07, 0x6b, 0xe8, 0xd9, 0x5f,
			       0xf8, 0x74, 0xed );
	MEMCPY_TEST_CONSTANT ( 0x05, 0xb2, 0xae, 0x81, 0x91, 0xc9, 0xa2, 0x5f,
			       0xa9, 0x1b, 0x25, 0x7f, 0x32, 0x0c, 0x04, 0x00,
			       0xf1, 0x46, 0xab, 0x77, 0x1e, 0x12, 0x27, 0xe7,
			       0xf6, 0x1e, 0x0c, 0x29 );
	MEMCPY_TEST_CONSTANT ( 0x0e, 0xca, 0xa5, 0x56, 0x3d, 0x99, 0x99, 0xf9,
			       0x6e, 0xdd, 0x93, 0x98, 0xec, 0x8b, 0x5c, 0x71,
			       0x0c, 0xb0, 0xe6, 0x12, 0xf2, 0x10, 0x1a, 0xbe,
			       0x4a, 0xe0, 0xe3, 0x00, 0xf8 );
	MEMCPY_TEST_CONSTANT ( 0x40, 0xa8, 0x28, 0x5b, 0x12, 0x0d, 0x80, 0x8e,
			       0x8a, 0xd9, 0x92, 0x7a, 0x6e, 0x48, 0x8d, 0x14,
			       0x4b, 0xc6, 0xce, 0x21, 0x2f, 0x0e, 0x47, 0xbd,
			       0xf1, 0xca, 0x0e, 0x1f, 0x65, 0xc4 );
	MEMCPY_TEST_CONSTANT ( 0x84, 0x83, 0x44, 0xe8, 0x1c, 0xbf, 0x23, 0x05,
			       0xdf, 0xed, 0x3b, 0xb7, 0x0b, 0x4a, 0x05, 0xec,
			       0xb7, 0x6f, 0x1c, 0xfe, 0x05, 0x05, 0x4e, 0xd1,
			       0x50, 0x88, 0x81, 0x87, 0x68, 0xf6, 0x66 );
	MEMCPY_TEST_CONSTANT ( 0x0d, 0x1d, 0xcf, 0x3e, 0x7c, 0xf8, 0x12, 0x1b,
			       0x96, 0x7f, 0xff, 0x27, 0xca, 0xfe, 0xd3, 0x8b,
			       0x10, 0xb9, 0x5d, 0x05, 0xad, 0x50, 0xed, 0x35,
			       0x32, 0x9c, 0xe6, 0x3b, 0x73, 0xe0, 0x7d );

	/* Speed tests */
	memcpy_test_speed ( 0, 0, 64 );
	memcpy_test_speed ( 0, 0, 128 );
	memcpy_test_speed ( 0, 0, 256 );
	for ( dest_offset = 0 ; dest_offset < 4 ; dest_offset++ ) {
		for ( src_offset = 0 ; src_offset < 4 ; src_offset++ ) {
			memcpy_test_speed ( dest_offset, src_offset, 4096 );
		}
	}
}

/** memcpy() self-test */
struct self_test memcpy_test __self_test = {
	.name = "memcpy",
	.exec = memcpy_test_exec,
};
