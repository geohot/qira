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
 * IPv4 tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include <ipxe/in.h>
#include <ipxe/test.h>

/** Define inline IPv4 address */
#define IPV4(a,b,c,d) \
	htonl ( ( (a) << 24 ) | ( (b) << 16 ) | ( (c) << 8 ) | (d) )

/**
 * Report an inet_ntoa() test result
 *
 * @v addr		IPv4 address
 * @v text		Expected textual representation
 * @v file		Test code file
 * @v line		Test code line
 */
static void inet_ntoa_okx ( uint32_t addr, const char *text, const char *file,
			    unsigned int line ) {
	struct in_addr in = { .s_addr = addr };
	char *actual;

	/* Format address */
	actual = inet_ntoa ( in );
	DBG ( "inet_ntoa ( %d.%d.%d.%d ) = %s\n",
	      ( ( ntohl ( addr ) >> 24 ) & 0xff ),
	      ( ( ntohl ( addr ) >> 16 ) & 0xff ),
	      ( ( ntohl ( addr ) >> 8 ) & 0xff ),
	      ( ( ntohl ( addr ) >> 0 ) & 0xff ), actual );
	okx ( strcmp ( actual, text ) == 0, file, line );
}
#define inet_ntoa_ok( addr, text ) \
	inet_ntoa_okx ( addr, text, __FILE__, __LINE__ )

/**
 * Report an inet_aton() test result
 *
 * @v text		Textual representation
 * @v addr		Expected IPv4 address
 * @v file		Test code file
 * @v line		Test code line
 */
static void inet_aton_okx ( const char *text, uint32_t addr, const char *file,
			    unsigned int line ) {
	struct in_addr actual;

	/* Parse address */
	okx ( inet_aton ( text, &actual ) != 0, file, line );
	DBG ( "inet_aton ( \"%s\" ) = %s\n", text, inet_ntoa ( actual ) );
	okx ( actual.s_addr == addr, file, line );
};
#define inet_aton_ok( text, addr ) \
	inet_aton_okx ( text, addr, __FILE__, __LINE__ )

/**
 * Report an inet_aton() failure test result
 *
 * @v text		Textual representation
 * @v file		Test code file
 * @v line		Test code line
 */
static void inet_aton_fail_okx ( const char *text, const char *file,
				 unsigned int line ) {
	struct in_addr actual;

	/* Attempt to parse address */
	okx ( inet_aton ( text, &actual ) == 0, file, line );
}
#define inet_aton_fail_ok( text ) \
	inet_aton_fail_okx ( text, __FILE__, __LINE__ )

/**
 * Perform IPv4 self-tests
 *
 */
static void ipv4_test_exec ( void ) {

	/* Address testing macros */
	ok (   IN_IS_CLASSA ( IPV4 ( 10, 0, 0, 1 ) ) );
	ok ( ! IN_IS_CLASSB ( IPV4 ( 10, 0, 0, 1 ) ) );
	ok ( ! IN_IS_CLASSC ( IPV4 ( 10, 0, 0, 1 ) ) );
	ok ( ! IN_IS_CLASSA ( IPV4 ( 172, 16, 0, 1 ) ) );
	ok (   IN_IS_CLASSB ( IPV4 ( 172, 16, 0, 1 ) ) );
	ok ( ! IN_IS_CLASSC ( IPV4 ( 172, 16, 0, 1 ) ) );
	ok ( ! IN_IS_CLASSA ( IPV4 ( 192, 168, 0, 1 ) ) );
	ok ( ! IN_IS_CLASSB ( IPV4 ( 192, 168, 0, 1 ) ) );
	ok (   IN_IS_CLASSC ( IPV4 ( 192, 168, 0, 1 ) ) );
	ok ( ! IN_IS_MULTICAST ( IPV4 ( 127, 0, 0, 1 ) ) );
	ok ( ! IN_IS_MULTICAST ( IPV4 ( 8, 8, 8, 8 ) ) );
	ok ( ! IN_IS_MULTICAST ( IPV4 ( 0, 0, 0, 0 ) ) );
	ok ( ! IN_IS_MULTICAST ( IPV4 ( 223, 0, 0, 1 ) ) );
	ok ( ! IN_IS_MULTICAST ( IPV4 ( 240, 0, 0, 1 ) ) );
	ok (   IN_IS_MULTICAST ( IPV4 ( 224, 0, 0, 1 ) ) );
	ok (   IN_IS_MULTICAST ( IPV4 ( 231, 89, 0, 2 ) ) );
	ok (   IN_IS_MULTICAST ( IPV4 ( 239, 6, 1, 17 ) ) );

	/* inet_ntoa() tests */
	inet_ntoa_ok ( IPV4 ( 127, 0, 0, 1 ), "127.0.0.1" );
	inet_ntoa_ok ( IPV4 ( 0, 0, 0, 0 ), "0.0.0.0" );
	inet_ntoa_ok ( IPV4 ( 255, 255, 255, 255 ), "255.255.255.255" );
	inet_ntoa_ok ( IPV4 ( 212, 13, 204, 60 ), "212.13.204.60" );

	/* inet_aton() tests */
	inet_aton_ok ( "212.13.204.60", IPV4 ( 212, 13, 204, 60 ) );
	inet_aton_ok ( "127.0.0.1", IPV4 ( 127, 0, 0, 1 ) );

	/* inet_aton() failure tests */
	inet_aton_fail_ok ( "256.0.0.1" ); /* Byte out of range */
	inet_aton_fail_ok ( "212.13.204.60.1" ); /* Too long */
	inet_aton_fail_ok ( "127.0.0" ); /* Too short */
	inet_aton_fail_ok ( "1.2.3.a" ); /* Invalid characters */
	inet_aton_fail_ok ( "127.0..1" ); /* Missing bytes */
}

/** IPv4 self-test */
struct self_test ipv4_test __self_test = {
	.name = "ipv4",
	.exec = ipv4_test_exec,
};
