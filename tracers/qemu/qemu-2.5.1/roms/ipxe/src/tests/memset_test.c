/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
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
 * memset() self-tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <string.h>
#include <ipxe/test.h>

/* Provide global functions to allow inspection of generated code */

void memset_zero_0 ( void *dest ) { memset ( dest, 0, 0 ); }
void memset_zero_1 ( void *dest ) { memset ( dest, 0, 1 ); }
void memset_zero_2 ( void *dest ) { memset ( dest, 0, 2 ); }
void memset_zero_3 ( void *dest ) { memset ( dest, 0, 3 ); }
void memset_zero_4 ( void *dest ) { memset ( dest, 0, 4 ); }
void memset_zero_5 ( void *dest ) { memset ( dest, 0, 5 ); }
void memset_zero_6 ( void *dest ) { memset ( dest, 0, 6 ); }
void memset_zero_7 ( void *dest ) { memset ( dest, 0, 7 ); }
void memset_zero_8 ( void *dest ) { memset ( dest, 0, 8 ); }
void memset_zero_9 ( void *dest ) { memset ( dest, 0, 9 ); }
void memset_zero_10 ( void *dest ) { memset ( dest, 0, 10 ); }
void memset_zero_11 ( void *dest ) { memset ( dest, 0, 11 ); }
void memset_zero_12 ( void *dest ) { memset ( dest, 0, 12 ); }
void memset_zero_13 ( void *dest ) { memset ( dest, 0, 13 ); }
void memset_zero_14 ( void *dest ) { memset ( dest, 0, 14 ); }
void memset_zero_15 ( void *dest ) { memset ( dest, 0, 15 ); }
void memset_zero_16 ( void *dest ) { memset ( dest, 0, 16 ); }
void memset_zero_17 ( void *dest ) { memset ( dest, 0, 17 ); }
void memset_zero_18 ( void *dest ) { memset ( dest, 0, 18 ); }
void memset_zero_19 ( void *dest ) { memset ( dest, 0, 19 ); }
void memset_zero_20 ( void *dest ) { memset ( dest, 0, 20 ); }
void memset_zero_21 ( void *dest ) { memset ( dest, 0, 21 ); }
void memset_zero_22 ( void *dest ) { memset ( dest, 0, 22 ); }
void memset_zero_23 ( void *dest ) { memset ( dest, 0, 23 ); }
void memset_zero_24 ( void *dest ) { memset ( dest, 0, 24 ); }
void memset_zero_25 ( void *dest ) { memset ( dest, 0, 25 ); }
void memset_zero_26 ( void *dest ) { memset ( dest, 0, 26 ); }
void memset_zero_27 ( void *dest ) { memset ( dest, 0, 27 ); }
void memset_zero_28 ( void *dest ) { memset ( dest, 0, 28 ); }
void memset_zero_29 ( void *dest ) { memset ( dest, 0, 29 ); }
void memset_zero_30 ( void *dest ) { memset ( dest, 0, 30 ); }
void memset_zero_31 ( void *dest ) { memset ( dest, 0, 31 ); }

/**
 * Force a call to the variable-length implementation of memset()
 *
 * @v dest		Destination address
 * @v fill		Fill pattern
 * @v len		Length of data
 * @ret dest		Destination address
 */
__attribute__ (( noinline )) void * memset_var ( void *dest, unsigned int fill,
						 size_t len ) {
	return memset ( dest, fill, len );
}

/**
 * Perform a constant-length memset() test
 *
 * @v len		Length of data
 */
#define MEMSET_TEST_CONSTANT( len ) do {				\
		uint8_t dest_const[ 1 + len + 1 ];			\
		uint8_t dest_var[ 1 + len + 1 ];			\
		static uint8_t zero[len];				\
		unsigned int i;						\
									\
		for ( i = 0 ; i < sizeof ( dest_const ) ; i++ )		\
			dest_const[i] = 0xaa;				\
		memset ( ( dest_const + 1 ), 0, len );			\
		ok ( dest_const[0] == 0xaa );				\
		ok ( dest_const[ sizeof ( dest_const ) - 1 ] == 0xaa );	\
		ok ( memcmp ( ( dest_const + 1 ), zero, len ) == 0 );	\
									\
		for ( i = 0 ; i < sizeof ( dest_var ) ; i++ )		\
			dest_var[i] = 0xbb;				\
		memset_var ( ( dest_var + 1 ), 0, len );		\
		ok ( dest_var[0] == 0xbb );				\
		ok ( dest_var[ sizeof ( dest_var ) - 1 ] == 0xbb );	\
		ok ( memcmp ( ( dest_var + 1 ), zero, len ) == 0 );	\
	} while ( 0 )

/**
 * Perform memset() self-tests
 *
 */
static void memset_test_exec ( void ) {

	/* Constant-length tests */
	MEMSET_TEST_CONSTANT ( 0 );
	MEMSET_TEST_CONSTANT ( 1 );
	MEMSET_TEST_CONSTANT ( 2 );
	MEMSET_TEST_CONSTANT ( 3 );
	MEMSET_TEST_CONSTANT ( 4 );
	MEMSET_TEST_CONSTANT ( 5 );
	MEMSET_TEST_CONSTANT ( 6 );
	MEMSET_TEST_CONSTANT ( 7 );
	MEMSET_TEST_CONSTANT ( 8 );
	MEMSET_TEST_CONSTANT ( 9 );
	MEMSET_TEST_CONSTANT ( 10 );
	MEMSET_TEST_CONSTANT ( 11 );
	MEMSET_TEST_CONSTANT ( 12 );
	MEMSET_TEST_CONSTANT ( 13 );
	MEMSET_TEST_CONSTANT ( 14 );
	MEMSET_TEST_CONSTANT ( 15 );
	MEMSET_TEST_CONSTANT ( 16 );
	MEMSET_TEST_CONSTANT ( 17 );
	MEMSET_TEST_CONSTANT ( 18 );
	MEMSET_TEST_CONSTANT ( 19 );
	MEMSET_TEST_CONSTANT ( 20 );
	MEMSET_TEST_CONSTANT ( 21 );
	MEMSET_TEST_CONSTANT ( 22 );
	MEMSET_TEST_CONSTANT ( 23 );
	MEMSET_TEST_CONSTANT ( 24 );
	MEMSET_TEST_CONSTANT ( 25 );
	MEMSET_TEST_CONSTANT ( 26 );
	MEMSET_TEST_CONSTANT ( 27 );
	MEMSET_TEST_CONSTANT ( 28 );
	MEMSET_TEST_CONSTANT ( 29 );
	MEMSET_TEST_CONSTANT ( 30 );
	MEMSET_TEST_CONSTANT ( 31 );
}

/** memset() self-test */
struct self_test memset_test __self_test = {
	.name = "memset",
	.exec = memset_test_exec,
};
