/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
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
 * Byte-order swapping test functions
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stdint.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/test.h>

/* Provide global functions to allow inspection of generated assembly code */

uint16_t test_bswap16 ( uint16_t x ) {
	return __bswap_16 ( x );
}

uint32_t test_bswap32 ( uint32_t x ) {
	return __bswap_32 ( x );
}

uint64_t test_bswap64 ( uint64_t x ) {
	return __bswap_64 ( x );
}

void test_bswap16s ( uint16_t *x ) {
	__bswap_16s ( x );
}

void test_bswap32s ( uint32_t *x ) {
	__bswap_32s ( x );
}

void test_bswap64s ( uint64_t *x ) {
	__bswap_64s ( x );
}

/**
 * Perform byte-order swapping
 *
 */
static void byteswap_test_exec ( void ) {
	uint16_t test16;
	uint32_t test32;
	uint64_t test64;

	ok ( test_bswap16 ( 0x1234 ) == 0x3412 );
	ok ( test_bswap32 ( 0x12345678UL ) == 0x78563412UL );
	ok ( test_bswap64 ( 0x123456789abcdef0ULL ) == 0xf0debc9a78563412ULL );

	test16 = 0xabcd;
	test_bswap16s ( &test16 );
	ok ( test16 == 0xcdab );

	test32 = 0xabcdef01UL;
	test_bswap32s ( &test32 );
	ok ( test32 == 0x01efcdabUL );

	test64 = 0xabcdef0123456789ULL;
	test_bswap64s ( &test64 );
	ok ( test64 == 0x8967452301efcdabULL );
}

/** Byte-order swapping self-test */
struct self_test byteswap_test __self_test = {
	.name = "byteswap",
	.exec = byteswap_test_exec,
};
