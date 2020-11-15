/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
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
 * IPv6 tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include <ipxe/ipv6.h>
#include <ipxe/test.h>

/** Define inline IPv6 address */
#define IPV6(...) { __VA_ARGS__ }

/** The unspecified IPv6 address */
static const struct in6_addr sample_unspecified = {
	.s6_addr = IPV6 ( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ),
};

/** A sample link-local IPv6 address */
static const struct in6_addr sample_link_local = {
	.s6_addr = IPV6 ( 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			  0x00, 0x00, 0x69, 0xff, 0xfe, 0x50, 0x58, 0x45 ),
};

/** A sample global IPv6 address */
static const struct in6_addr sample_global = {
	.s6_addr = IPV6 ( 0x20, 0x01, 0x0b, 0xa8, 0x00, 0x00, 0x01, 0xd4,
			  0x00, 0x00, 0x00, 0x00, 0x69, 0x50, 0x58, 0x45 ),
};

/** A sample multicast IPv6 address */
static const struct in6_addr sample_multicast = {
	.s6_addr = IPV6 ( 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ),
};

/**
 * Report an inet6_ntoa() test result
 *
 * @v addr		IPv6 address
 * @v text		Expected textual representation
 */
#define inet6_ntoa_ok( addr, text ) do {				\
	static const struct in6_addr in = {				\
		.s6_addr = addr,					\
	};								\
	static const char expected[] = text;				\
	char *actual;							\
									\
	actual = inet6_ntoa ( &in );					\
	DBG ( "inet6_ntoa ( %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x ) "	\
	      "= %s\n", ntohs ( in.s6_addr16[0] ),			\
	      ntohs ( in.s6_addr16[1] ), ntohs ( in.s6_addr16[2] ),	\
	      ntohs ( in.s6_addr16[3] ), ntohs ( in.s6_addr16[4] ),	\
	      ntohs ( in.s6_addr16[5] ), ntohs ( in.s6_addr16[6] ),	\
	      ntohs ( in.s6_addr16[7] ), actual );			\
	ok ( strcmp ( actual, expected ) == 0 );			\
	} while ( 0 )

/**
 * Report an inet6_aton() test result
 *
 * @v text		Textual representation
 * @v addr		Expected IPv6 address
 */
#define inet6_aton_ok( text, addr ) do {				\
	static const char string[] = text;				\
	static const struct in6_addr expected = {			\
		.s6_addr = addr,					\
	};								\
	struct in6_addr actual;						\
									\
	ok ( inet6_aton ( string, &actual ) == 0 );			\
	DBG ( "inet6_aton ( \"%s\" ) = %s\n", string,			\
	      inet6_ntoa ( &actual ) );					\
	ok ( memcmp ( &actual, &expected, sizeof ( actual ) ) == 0 );	\
	} while ( 0 )

/**
 * Report an inet6_aton() failure test result
 *
 * @v text		Textual representation
 */
#define inet6_aton_fail_ok( text ) do {					\
	static const char string[] = text;				\
	struct in6_addr dummy;						\
									\
	ok ( inet6_aton ( string, &dummy ) != 0 );			\
	} while ( 0 )

/**
 * Perform IPv6 self-tests
 *
 */
static void ipv6_test_exec ( void ) {

	/* Address testing macros */
	ok (   IN6_IS_ADDR_UNSPECIFIED ( &sample_unspecified ) );
	ok ( ! IN6_IS_ADDR_UNSPECIFIED ( &sample_link_local ) );
	ok ( ! IN6_IS_ADDR_UNSPECIFIED ( &sample_global ) );
	ok ( ! IN6_IS_ADDR_UNSPECIFIED ( &sample_multicast ) );
	ok ( ! IN6_IS_ADDR_MULTICAST ( &sample_unspecified ) );
	ok ( ! IN6_IS_ADDR_MULTICAST ( &sample_link_local ) );
	ok ( ! IN6_IS_ADDR_MULTICAST ( &sample_global ) );
	ok (   IN6_IS_ADDR_MULTICAST ( &sample_multicast ) );
	ok ( ! IN6_IS_ADDR_LINKLOCAL ( &sample_unspecified ) );
	ok (   IN6_IS_ADDR_LINKLOCAL ( &sample_link_local ) );
	ok ( ! IN6_IS_ADDR_LINKLOCAL ( &sample_global ) );
	ok ( ! IN6_IS_ADDR_LINKLOCAL ( &sample_multicast ) );

	/* inet6_ntoa() tests */
	inet6_ntoa_ok ( IPV6 ( 0x20, 0x01, 0x0b, 0xa8, 0x00, 0x00, 0x01, 0xd4,
			       0x00, 0x00, 0x00, 0x00, 0x69, 0x50, 0x58, 0x45 ),
			"2001:ba8:0:1d4::6950:5845" );
	/* No zeros */
	inet6_ntoa_ok ( IPV6 ( 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01,
			       0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01 ),
			"2001:db8:1:1:1:1:1:1" );
	/* Run of zeros */
	inet6_ntoa_ok ( IPV6 ( 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ),
			"2001:db8::1" );
	/* No "::" for single zero */
	inet6_ntoa_ok ( IPV6 ( 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01,
			       0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01 ),
			"2001:db8:0:1:1:1:1:1" );
	/* Use "::" for longest run of zeros */
	inet6_ntoa_ok ( IPV6 ( 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ),
			"2001:0:0:1::1" );
	/* Use "::" for leftmost equal-length run of zeros */
	inet6_ntoa_ok ( IPV6 ( 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ),
			"2001:db8::1:0:0:1" );
	/* Trailing run of zeros */
	inet6_ntoa_ok ( IPV6 ( 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ),
			"fe80::" );
	/* Leading run of zeros */
	inet6_ntoa_ok ( IPV6 ( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ),
			"::1" );
	/* All zeros */
	inet6_ntoa_ok ( IPV6 ( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ),
			"::" );
	/* Maximum length */
	inet6_ntoa_ok ( IPV6 ( 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff ),
			"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" );

	/* inet6_aton() tests */
	inet6_aton_ok ( "2001:ba8:0:1d4::6950:5845",
			IPV6 ( 0x20, 0x01, 0x0b, 0xa8, 0x00, 0x00, 0x01, 0xd4,
			       0x00, 0x00, 0x00, 0x00, 0x69, 0x50, 0x58, 0x45));
	/* No zeros */
	inet6_aton_ok ( "2001:db8:1:1:1:1:1:1",
			IPV6 ( 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01,
			       0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01));
	/* All intervening zeros */
	inet6_aton_ok ( "fe80::1",
			IPV6 ( 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01));
	/* Trailing run of zeros */
	inet6_aton_ok ( "fe80::",
			IPV6 ( 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));
	/* Leading run of zeros */
	inet6_aton_ok ( "::1",
			IPV6 ( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01));
	/* All zeros */
	inet6_aton_ok ( "::",
			IPV6 ( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));

	/* inet6_aton() failure tests */
	inet6_aton_fail_ok ( "20012:ba8:0:1d4::6950:5845" );
	inet6_aton_fail_ok ( "200z:ba8:0:1d4::6950:5845" );
	inet6_aton_fail_ok ( "2001.ba8:0:1d4::6950:5845" );
	inet6_aton_fail_ok ( "2001:db8:1:1:1:1:1" );
	inet6_aton_fail_ok ( "2001:db8:1:1:1:1:1:1:2" );
	inet6_aton_fail_ok ( "2001:db8::1::2" );
	inet6_aton_fail_ok ( "2001:ba8:0:1d4:::6950:5845" );
	inet6_aton_fail_ok ( ":::" );
}

/** IPv6 self-test */
struct self_test ipv6_test __self_test = {
	.name = "ipv6",
	.exec = ipv6_test_exec,
};
