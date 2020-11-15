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
 * TCP/IP self-tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ipxe/test.h>
#include <ipxe/profile.h>
#include <ipxe/tcpip.h>

/** Number of sample iterations for profiling */
#define PROFILE_COUNT 16

/** A TCP/IP fixed-data test */
struct tcpip_test {
	/** Data */
	const void *data;
	/** Length of data */
	size_t len;
};

/** A TCP/IP pseudorandom-data test */
struct tcpip_random_test {
	/** Seed */
	unsigned int seed;
	/** Length of data */
	size_t len;
	/** Alignment offset */
	size_t offset;
};

/** Define inline data */
#define DATA(...) { __VA_ARGS__ }

/** Define a TCP/IP fixed-data test */
#define TCPIP_TEST( name, DATA )					\
	static const uint8_t __attribute__ (( aligned ( 16 ) ))		\
		name ## _data[] = DATA;					\
	static struct tcpip_test name = {				\
		.data = name ## _data,					\
		.len = sizeof ( name ## _data ),			\
	}

/** Define a TCP/IP pseudorandom-data test */
#define TCPIP_RANDOM_TEST( name, SEED, LEN, OFFSET )			\
	static struct tcpip_random_test name = {			\
		.seed = SEED,						\
		.len = LEN,						\
		.offset = OFFSET,					\
	}

/** Buffer for pseudorandom-data tests */
static uint8_t __attribute__ (( aligned ( 16 ) ))
	tcpip_data[ 4096 + 7 /* offset */ ];

/** Empty data */
TCPIP_TEST ( empty, DATA() );

/** Single byte */
TCPIP_TEST ( one_byte, DATA ( 0xeb ) );

/** Double byte */
TCPIP_TEST ( two_bytes, DATA ( 0xba, 0xbe ) );

/** Final wrap-around carry (big-endian) */
TCPIP_TEST ( final_carry_big,
	     DATA ( 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ) );

/** Final wrap-around carry (little-endian) */
TCPIP_TEST ( final_carry_little,
	     DATA ( 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00 ) );

/** Random data (aligned) */
TCPIP_RANDOM_TEST ( random_aligned, 0x12345678UL, 4096, 0 );

/** Random data (unaligned, +1) */
TCPIP_RANDOM_TEST ( random_unaligned_1, 0x12345678UL, 4096, 1 );

/** Random data (unaligned, +2) */
TCPIP_RANDOM_TEST ( random_unaligned_2, 0x12345678UL, 4096, 2 );

/** Random data (aligned, truncated) */
TCPIP_RANDOM_TEST ( random_aligned_truncated, 0x12345678UL, 4095, 0 );

/** Random data (unaligned start and finish) */
TCPIP_RANDOM_TEST ( partial, 0xcafebabe, 121, 5 );

/**
 * Calculate TCP/IP checksum
 *
 * @v data		Data to sum
 * @v len		Length of data
 * @ret cksum		Checksum
 *
 * This is a reference implementation taken from RFC1071 (and modified
 * to fix compilation without warnings under gcc).
 */
static uint16_t rfc_tcpip_chksum ( const void *data, size_t len ) {
	unsigned long sum = 0;

        while ( len > 1 )  {
		sum += *( ( uint16_t * ) data );
		data += 2;
		len -= 2;
	}

	if ( len > 0 )
		sum += *( ( uint8_t * ) data );

	while ( sum >> 16 )
		sum = ( ( sum & 0xffff ) + ( sum >> 16 ) );

	return ~sum;
}

/**
 * Report TCP/IP fixed-data test result
 *
 * @v test		TCP/IP test
 * @v file		Test code file
 * @v line		Test code line
 */
static void tcpip_okx ( struct tcpip_test *test, const char *file,
			unsigned int line ) {
	uint16_t expected;
	uint16_t generic_sum;
	uint16_t sum;

	/* Verify generic_tcpip_continue_chksum() result */
	expected = rfc_tcpip_chksum ( test->data, test->len );
	generic_sum = generic_tcpip_continue_chksum ( TCPIP_EMPTY_CSUM,
						      test->data, test->len );
	okx ( generic_sum == expected, file, line );

	/* Verify optimised tcpip_continue_chksum() result */
	sum = tcpip_continue_chksum ( TCPIP_EMPTY_CSUM, test->data, test->len );
	okx ( sum == expected, file, line );
}
#define tcpip_ok( test ) tcpip_okx ( test, __FILE__, __LINE__ )

/**
 * Report TCP/IP pseudorandom-data test result
 *
 * @v test		TCP/IP test
 * @v file		Test code file
 * @v line		Test code line
 */
static void tcpip_random_okx ( struct tcpip_random_test *test,
			       const char *file, unsigned int line ) {
	uint8_t *data = ( tcpip_data + test->offset );
	struct profiler profiler;
	uint16_t expected;
	uint16_t generic_sum;
	uint16_t sum;
	unsigned int i;

	/* Sanity check */
	assert ( ( test->len + test->offset ) <= sizeof ( tcpip_data ) );

	/* Generate random data */
	srandom ( test->seed );
	for ( i = 0 ; i < test->len ; i++ )
		data[i] = random();

	/* Verify generic_tcpip_continue_chksum() result */
	expected = rfc_tcpip_chksum ( data, test->len );
	generic_sum = generic_tcpip_continue_chksum ( TCPIP_EMPTY_CSUM,
						      data, test->len );
	okx ( generic_sum == expected, file, line );

	/* Verify optimised tcpip_continue_chksum() result */
	sum = tcpip_continue_chksum ( TCPIP_EMPTY_CSUM, data, test->len );
	okx ( sum == expected, file, line );

	/* Profile optimised calculation */
	memset ( &profiler, 0, sizeof ( profiler ) );
	for ( i = 0 ; i < PROFILE_COUNT ; i++ ) {
		profile_start ( &profiler );
		sum = tcpip_continue_chksum ( TCPIP_EMPTY_CSUM, data,
					      test->len );
		profile_stop ( &profiler );
	}
	DBG ( "TCPIP checksummed %zd bytes (+%zd) in %ld +/- %ld ticks\n",
	      test->len, test->offset, profile_mean ( &profiler ),
	      profile_stddev ( &profiler ) );
}
#define tcpip_random_ok( test ) tcpip_random_okx ( test, __FILE__, __LINE__ )

/**
 * Perform TCP/IP self-tests
 *
 */
static void tcpip_test_exec ( void ) {

	tcpip_ok ( &empty );
	tcpip_ok ( &one_byte );
	tcpip_ok ( &two_bytes );
	tcpip_ok ( &final_carry_big );
	tcpip_ok ( &final_carry_little );
	tcpip_random_ok ( &random_aligned );
	tcpip_random_ok ( &random_unaligned_1 );
	tcpip_random_ok ( &random_unaligned_2 );
	tcpip_random_ok ( &random_aligned_truncated );
	tcpip_random_ok ( &partial );
}

/** TCP/IP self-test */
struct self_test tcpip_test __self_test = {
	.name = "tcpip",
	.exec = tcpip_test_exec,
};
