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
 * vsprintf() self-tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <string.h>
#include <stdio.h>
#include <ipxe/test.h>

/**
 * Report an snprintf() test result
 *
 */
#define snprintf_ok( len, result, format, ... ) do {			\
	char actual[ (len) ];						\
	const char expected[] = result;					\
	size_t actual_len;						\
									\
	actual_len = snprintf ( actual, sizeof ( actual ),		\
				format, ##__VA_ARGS__ );		\
	ok ( actual_len >= strlen ( result ) );				\
	ok ( strcmp ( actual, expected ) == 0 );			\
	if ( strcmp ( actual, expected ) != 0 ) {			\
		DBG ( "SNPRINTF expected \"%s\", got \"%s\"\n",		\
		      expected, actual );				\
	}								\
	} while ( 0 )

/**
 * Perform vsprintf() self-tests
 *
 */
static void vsprintf_test_exec ( void ) {

	/* Constant string */
	snprintf_ok ( 16, "Testing", "Testing" );

	/* Constant string, truncated to fit */
	snprintf_ok ( 5, "Test", "Testing" );

	/* Basic format specifiers */
	snprintf_ok ( 16, "%", "%%" );
	snprintf_ok ( 16, "ABC", "%c%c%c", 'A', 'B', 'C' );
	snprintf_ok ( 16, "abc", "%lc%lc%lc", L'a', L'b', L'c' );
	snprintf_ok ( 16, "Hello world", "%s %s", "Hello", "world" );
	snprintf_ok ( 16, "Goodbye world", "%ls %s", L"Goodbye", "world" );
	snprintf_ok ( 16, "0x1234abcd", "%p", ( ( void * ) 0x1234abcd ) );
	snprintf_ok ( 16, "0xa723", "%#x", 0xa723 );
	snprintf_ok ( 16, "a723", "%x", 0xa723 );
	snprintf_ok ( 16, "0x0000a723", "%#08x", 0xa723 );
	snprintf_ok ( 16, "00A723", "%06X", 0xa723 );
	snprintf_ok ( 16, "9876abcd", "%lx", 0x9876abcdUL );
	snprintf_ok ( 16, "1234 5678", "%04llx %04llx", 0x1234ULL, 0x5678ULL );
	snprintf_ok ( 16, "123", "%d", 123 );
	snprintf_ok ( 16, "456", "%i", 456 );
	snprintf_ok ( 16, " 99", "%3d", 99 );
	snprintf_ok ( 16, "099", "%03d", 99 );
	snprintf_ok ( 16, "-72", "%d", -72 );
	snprintf_ok ( 16, " -72", "%4d", -72 );
	snprintf_ok ( 16, "-072", "%04d", -72 );
	snprintf_ok ( 16, "4", "%zd", sizeof ( uint32_t ) );
	snprintf_ok ( 16, "123456789", "%d", 123456789 );

	/* Realistic combinations */
	snprintf_ok ( 64, "DBG 0x1234 thingy at 0x0003f0c0+0x5c\n",
		      "DBG %p %s at %#08lx+%#zx\n", ( ( void * ) 0x1234 ),
		      "thingy", 0x3f0c0UL, ( ( size_t ) 0x5c ) );
	snprintf_ok ( 64, "PCI 00:1f.3", "PCI %02x:%02x.%x", 0x00, 0x1f, 0x03 );
	snprintf_ok ( 64, "Region [1000000,3f000000)", "Region [%llx,%llx)",
		      0x1000000ULL, 0x3f000000ULL );
}

/** vsprintf() self-test */
struct self_test vsprintf_test __self_test = {
	.name = "vsprintf",
	.exec = vsprintf_test_exec,
};
