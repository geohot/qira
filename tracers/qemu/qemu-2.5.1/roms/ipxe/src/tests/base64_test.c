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
 * Base64 tests
 *
 * Test vectors generated using "base64 -w 0"
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stdint.h>
#include <string.h>
#include <ipxe/base64.h>
#include <ipxe/test.h>

/** A Base64 test */
struct base64_test {
	/** Raw data */
	const void *data;
	/** Length of raw data */
	size_t len;
	/** Base64-encoded data */
	const char *encoded;
};

/** Define inline data */
#define DATA(...) { __VA_ARGS__ }

/** Define a base64 test */
#define BASE64( name, DATA, ENCODED )					\
	static const uint8_t name ## _data[] = DATA;			\
	static struct base64_test name = {				\
		.data = name ## _data,					\
		.len = sizeof ( name ## _data ),			\
		.encoded = ENCODED,					\
	}

/** Empty data test */
BASE64 ( empty_test, DATA(), "" );

/** "Hello world" test */
BASE64 ( hw_test,
	 DATA ( 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' ),
	 "SGVsbG8gd29ybGQ=" );

/** Random data test */
BASE64 ( random_test,
	 DATA ( 0x36, 0x03, 0x84, 0xdc, 0x4e, 0x03, 0x46, 0xa0, 0xb5, 0x2d,
		0x03, 0x6e, 0xd0, 0x56, 0xed, 0xa0, 0x37, 0x02, 0xac, 0xc6,
		0x65, 0xd1 ),
	 "NgOE3E4DRqC1LQNu0FbtoDcCrMZl0Q==" );

/**
 * Report a base64 encoding test result
 *
 * @v test		Base64 test
 * @v file		Test code file
 * @v line		Test code line
 */
static void base64_encode_okx ( struct base64_test *test, const char *file,
				unsigned int line ) {
	size_t len = base64_encoded_len ( test->len );
	char buf[ len + 1 /* NUL */ ];
	size_t check_len;

	okx ( len == strlen ( test->encoded ), file, line );
	check_len = base64_encode ( test->data, test->len, buf, sizeof ( buf ));
	okx ( check_len == len, file, line );
	okx ( strcmp ( test->encoded, buf ) == 0, file, line );
}
#define base64_encode_ok( test ) base64_encode_okx ( test, __FILE__, __LINE__ )

/**
 * Report a base64 decoding test result
 *
 * @v test		Base64 test
 * @v file		Test code file
 * @v line		Test code line
 */
static void base64_decode_okx ( struct base64_test *test, const char *file,
				unsigned int line ) {
	size_t max_len = base64_decoded_max_len ( test->encoded );
	uint8_t buf[max_len];
	int len;

	len = base64_decode ( test->encoded, buf, sizeof ( buf ) );
	okx ( len >= 0, file, line );
	okx ( ( size_t ) len <= max_len, file, line );
	okx ( ( size_t ) len == test->len, file, line );
	okx ( memcmp ( test->data, buf, len ) == 0, file, line );
}
#define base64_decode_ok( test ) base64_decode_okx ( test, __FILE__, __LINE__ )

/**
 * Perform Base64 self-tests
 *
 */
static void base64_test_exec ( void ) {

	base64_encode_ok ( &empty_test );
	base64_decode_ok ( &empty_test );

	base64_encode_ok ( &hw_test );
	base64_decode_ok ( &hw_test );

	base64_encode_ok ( &random_test );
	base64_decode_ok ( &random_test );
}

/** Base64 self-test */
struct self_test base64_test __self_test = {
	.name = "base64",
	.exec = base64_test_exec,
};
