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
 * Base16 tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stdint.h>
#include <string.h>
#include <ipxe/base16.h>
#include <ipxe/test.h>

/** A Base16 test */
struct base16_test {
	/** Raw data */
	const void *data;
	/** Length of raw data */
	size_t len;
	/** Base16-encoded data */
	const char *encoded;
};

/** Define inline data */
#define DATA(...) { __VA_ARGS__ }

/** Define a base16 test */
#define BASE16( name, DATA, ENCODED )					\
	static const uint8_t name ## _data[] = DATA;			\
	static struct base16_test name = {				\
		.data = name ## _data,					\
		.len = sizeof ( name ## _data ),			\
		.encoded = ENCODED,					\
	}

/** Empty data test */
BASE16 ( empty_test, DATA(), "" );

/** "Hello world" test */
BASE16 ( hw_test,
	 DATA ( 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' ),
	 "48656c6c6f20776f726c64" );

/** Random data test */
BASE16 ( random_test,
	 DATA ( 0x8b, 0x1a, 0xa2, 0x6c, 0xa9, 0x38, 0x43, 0xb8, 0x81, 0xf8,
		0x30, 0x44, 0xb2, 0x32, 0x6e, 0x82, 0xfe, 0x0f, 0x84, 0x91 ),
	 "8b1aa26ca93843b881f83044b2326e82fe0f8491" );

/**
 * Report a base16 encoding test result
 *
 * @v test		Base16 test
 * @v file		Test code file
 * @v line		Test code line
 */
static void base16_encode_okx ( struct base16_test *test, const char *file,
				unsigned int line ) {
	size_t len = base16_encoded_len ( test->len );
	char buf[ len + 1 /* NUL */ ];
	size_t check_len;

	okx ( len == strlen ( test->encoded ), file, line );
	check_len = base16_encode ( test->data, test->len, buf, sizeof ( buf ));
	okx ( check_len == len, file, line );
	okx ( strcmp ( test->encoded, buf ) == 0, file, line );
}
#define base16_encode_ok( test ) base16_encode_okx ( test, __FILE__, __LINE__ )

/**
 * Report a base16 decoding test result
 *
 * @v test		Base16 test
 * @v file		Test code file
 * @v line		Test code line
 */
static void base16_decode_okx ( struct base16_test *test, const char *file,
				unsigned int line ) {
	size_t max_len = base16_decoded_max_len ( test->encoded );
	uint8_t buf[max_len];
	int len;

	len = base16_decode ( test->encoded, buf, sizeof ( buf ) );
	okx ( len >= 0, file, line );
	okx ( ( size_t ) len <= max_len, file, line );
	okx ( ( size_t ) len == test->len, file, line );
	okx ( memcmp ( test->data, buf, len ) == 0, file, line );
}
#define base16_decode_ok( test ) base16_decode_okx ( test, __FILE__, __LINE__ )

/**
 * Perform Base16 self-tests
 *
 */
static void base16_test_exec ( void ) {

	base16_encode_ok ( &empty_test );
	base16_decode_ok ( &empty_test );

	base16_encode_ok ( &hw_test );
	base16_decode_ok ( &hw_test );

	base16_encode_ok ( &random_test );
	base16_decode_ok ( &random_test );
}

/** Base16 self-test */
struct self_test base16_test __self_test = {
	.name = "base16",
	.exec = base16_test_exec,
};
