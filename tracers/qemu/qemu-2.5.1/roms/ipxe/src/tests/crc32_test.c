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
 * CRC32 tests
 *
 *
 * Test vectors generated using Perl's Digest::CRC:
 *
 *    use Digest::CRC qw ( crc );
 *
 *    printf "%#08x", crc ( $data, 32, $seed, 0, 1, 0x04c11db7, 1 );
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stdint.h>
#include <ipxe/crc32.h>
#include <ipxe/test.h>

/** Define inline data */
#define DATA(...) { __VA_ARGS__ }

/** A CRC32 test */
struct crc32_test {
	/** Test data */
	const void *data;
	/** Length of test data */
	size_t len;
	/** Seed */
	uint32_t seed;
	/** Expected CRC32 */
	uint32_t crc32;
};

/**
 * Define a CRC32 test
 *
 * @v name		Test name
 * @v DATA		Test data
 * @v SEED		Seed
 * @v CRC32		Expected CRC32
 * @ret test		CRC32 test
 */
#define CRC32_TEST( name, DATA, SEED, CRC32 )				\
	static const uint8_t name ## _data[] = DATA;			\
	static struct crc32_test name = {				\
		.data = name ## _data,					\
		.len = sizeof ( name ## _data ),			\
		.seed = SEED,						\
		.crc32 = CRC32,						\
	};

/**
 * Report a CRC32 test result
 *
 * @v test		CRC32 test
 */
#define crc32_ok( test ) do {						\
	uint32_t crc32;							\
	crc32 = crc32_le ( (test)->seed, (test)->data, (test)->len );	\
	ok ( crc32 == (test)->crc32 );					\
	} while ( 0 )

/* CRC32 tests */
CRC32_TEST ( empty_test,
	     DATA ( ),
	     0x12345678UL, 0x12345678UL );
CRC32_TEST ( hw_test,
	     DATA ( 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' ),
	     0xffffffffUL, 0xf2b5ee7aUL );
CRC32_TEST ( hw_split_part1_test,
	     DATA ( 'h', 'e', 'l', 'l', 'o' ),
	     0xffffffffUL, 0xc9ef5979UL );
CRC32_TEST ( hw_split_part2_test,
	     DATA ( ' ', 'w', 'o', 'r', 'l', 'd' ),
	     0xc9ef5979UL, 0xf2b5ee7aUL );

/**
 * Perform CRC32 self-tests
 *
 */
static void crc32_test_exec ( void ) {

	crc32_ok ( &empty_test );
	crc32_ok ( &hw_test );
	crc32_ok ( &hw_split_part1_test );
	crc32_ok ( &hw_split_part2_test );
}

/** CRC32 self-test */
struct self_test crc32_test __self_test = {
	.name = "crc32",
	.exec = crc32_test_exec,
};
