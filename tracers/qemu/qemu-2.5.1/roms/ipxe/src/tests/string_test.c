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
 * String self-tests
 *
 * memcpy() tests are handled separately
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ipxe/string.h>
#include <ipxe/test.h>

/**
 * Perform string self-tests
 *
 */
static void string_test_exec ( void ) {

	/* Test strlen() */
	ok ( strlen ( "" ) == 0 );
	ok ( strlen ( "Hello" ) == 5 );
	ok ( strlen ( "Hello world!" ) == 12 );
	ok ( strlen ( "Hello\0world!" ) == 5 );

	/* Test strnlen() */
	ok ( strnlen ( "", 0 ) == 0 );
	ok ( strnlen ( "", 10 ) == 0 );
	ok ( strnlen ( "Hello", 0 ) == 0 );
	ok ( strnlen ( "Hello", 3 ) == 3 );
	ok ( strnlen ( "Hello", 5 ) == 5 );
	ok ( strnlen ( "Hello", 16 ) == 5 );
	ok ( strnlen ( "Hello world!", 5 ) == 5 );
	ok ( strnlen ( "Hello world!", 11 ) == 11 );
	ok ( strnlen ( "Hello world!", 16 ) == 12 );

	/* Test strchr() */
	ok ( strchr ( "", 'a' ) == NULL );
	ok ( *(strchr ( "Testing", 'e' )) == 'e' );
	ok ( *(strchr ( "Testing", 'g' )) == 'g' );
	ok ( strchr ( "Testing", 'x' ) == NULL );

	/* Test strrchr() */
	ok ( strrchr ( "", 'a' ) == NULL );
	ok ( *(strrchr ( "Haystack", 'a' )) == 'a' );
	ok ( *(strrchr ( "Haystack", 'k' )) == 'k' );
	ok ( strrchr ( "Haystack", 'x' ) == NULL );

	/* Test memchr() */
	ok ( memchr ( "", '\0', 0 ) == NULL );
	ok ( *((uint8_t *)memchr ( "post\0null", 'l', 9 )) == 'l' );
	ok ( *((uint8_t *)memchr ( "post\0null", '\0', 9 )) == '\0' );
	ok ( memchr ( "thingy", 'z', 6 ) == NULL );

	/* Test strcmp() */
	ok ( strcmp ( "", "" ) == 0 );
	ok ( strcmp ( "Hello", "Hello" ) == 0 );
	ok ( strcmp ( "Hello", "hello" ) != 0 );
	ok ( strcmp ( "Hello", "Hello world!" ) != 0 );
	ok ( strcmp ( "Hello world!", "Hello" ) != 0 );

	/* Test strncmp() */
	ok ( strncmp ( "", "", 0 ) == 0 );
	ok ( strncmp ( "", "", 15 ) == 0 );
	ok ( strncmp ( "Goodbye", "Goodbye", 16 ) == 0 );
	ok ( strncmp ( "Goodbye", "Hello", 16 ) != 0 );
	ok ( strncmp ( "Goodbye", "Goodbye world", 32 ) != 0 );
	ok ( strncmp ( "Goodbye", "Goodbye world", 7 ) == 0 );

	/* Test strcasecmp() */
	ok ( strcasecmp ( "", "" ) == 0 );
	ok ( strcasecmp ( "Uncle Jack", "Uncle jack" ) == 0 );
	ok ( strcasecmp ( "Uncle Jack", "Uncle" ) != 0 );
	ok ( strcasecmp ( "Uncle", "Uncle Jack" ) != 0 );
	ok ( strcasecmp ( "not", "equal" ) != 0 );

	/* Test memcmp() */
	ok ( memcmp ( "", "", 0 ) == 0 );
	ok ( memcmp ( "Foo", "Foo", 3 ) == 0 );
	ok ( memcmp ( "Foo", "Bar", 3 ) != 0 );

	/* Test strstr() */
	{
		const char haystack[] = "find me!";
		char *found;

		found = strstr ( haystack, "find" );
		ok ( found == &haystack[0] );
		found = strstr ( haystack, "me" );
		ok ( found == &haystack[5] );
		found = strstr ( haystack, "me." );
		ok ( found == NULL );
	}

	/* Test memset() */
	{
		static uint8_t test[7] = { '>', 1, 1, 1, 1, 1, '<' };
		static const uint8_t expected[7] = { '>', 0, 0, 0, 0, 0, '<' };
		memset ( ( test + 1 ), 0, ( sizeof ( test ) - 2 ) );
		ok ( memcmp ( test, expected, sizeof ( test ) ) == 0 );
	}
	{
		static uint8_t test[4] = { '>', 0, 0, '<' };
		static const uint8_t expected[4] = { '>', 0xeb, 0xeb, '<' };
		memset ( ( test + 1 ), 0xeb, ( sizeof ( test ) - 2 ) );
		ok ( memcmp ( test, expected, sizeof ( test ) ) == 0 );
	}

	/* Test memmove() */
	{
		static uint8_t test[11] =
			{ '>', 1, 2, 3, 4, 5, 6, 7, 8, 9, '<' };
		static const uint8_t expected[11] =
			{ '>', 3, 4, 5, 6, 7, 8, 7, 8, 9, '<' };
		memmove ( ( test + 1 ), ( test + 3 ), 6 );
		ok ( memcmp ( test, expected, sizeof ( test ) ) == 0 );
	}
	{
		static uint8_t test[12] =
			{ '>', 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, '<' };
		static const uint8_t expected[12] =
			{ '>', 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, '<' };
		memmove ( ( test + 6 ), ( test + 1 ), 5 );
		ok ( memcmp ( test, expected, sizeof ( test ) ) == 0 );
	}

	/* Test memswap() */
	{
		static uint8_t test[8] =
			{ '>', 1, 2, 3, 7, 8, 9, '<' };
		static const uint8_t expected[8] =
			{ '>', 7, 8, 9, 1, 2, 3, '<' };
		memswap ( ( test + 1 ), ( test + 4 ), 3 );
		ok ( memcmp ( test, expected, sizeof ( test ) ) == 0 );
	}

	/* Test strdup() */
	{
		const char *orig = "testing testing";
		char *dup = strdup ( orig );
		ok ( dup != NULL );
		ok ( dup != orig );
		ok ( strcmp ( dup, orig ) == 0 );
		free ( dup );
	}

	/* Test strndup() */
	{
		const char *normal = "testing testing";
		const char unterminated[6] = { 'h', 'e', 'l', 'l', 'o', '!' };
		char *dup;
		dup = strndup ( normal, 32 );
		ok ( dup != NULL );
		ok ( dup != normal );
		ok ( strcmp ( dup, normal ) == 0 );
		free ( dup );
		dup = strndup ( normal, 4 );
		ok ( dup != NULL );
		ok ( strcmp ( dup, "test" ) == 0 );
		free ( dup );
		dup = strndup ( unterminated, 5 );
		ok ( dup != NULL );
		ok ( strcmp ( dup, "hello" ) == 0 );
		free ( dup );
	}

	/* Test strcpy() */
	{
		const char longer[7] = "copyme";
		const char shorter[3] = "hi";
		char dest[7];
		char *copy;

		copy = strcpy ( dest, longer );
		ok ( copy == dest );
		ok ( memcmp ( dest, longer, 7 ) == 0 );
		copy = strcpy ( dest, shorter );
		ok ( copy == dest );
		ok ( memcmp ( dest, shorter, 3 ) == 0 );
		ok ( memcmp ( ( dest + 3 ), ( longer + 3 ), 4 ) == 0 );
	}

	/* Test strncpy() */
	{
		const char src[5] = "copy";
		const char orig[8] = { 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x' };
		const char zero[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
		char dest[8];
		char *copy;

		memcpy ( dest, orig, sizeof ( dest ) );
		copy = strncpy ( dest, src, 5 );
		ok ( copy == dest );
		ok ( memcmp ( dest, src, 5 ) == 0 );
		ok ( memcmp ( dest + 5, orig + 5, 3 ) == 0 );
		memcpy ( dest, orig, sizeof ( dest ) );
		copy = strncpy ( dest, src, 4 );
		ok ( copy == dest );
		ok ( memcmp ( dest, src, 4 ) == 0 );
		ok ( memcmp ( dest + 4, orig + 4, 4 ) == 0 );
		memcpy ( dest, orig, sizeof ( dest ) );
		copy = strncpy ( dest, src, 8 );
		ok ( copy == dest );
		ok ( memcmp ( dest, src, 5 ) == 0 );
		ok ( memcmp ( dest + 5, zero + 5, 3 ) == 0 );
		memcpy ( dest, orig, sizeof ( dest ) );
		copy = strncpy ( dest, "", 8 );
		ok ( copy == dest );
		ok ( memcmp ( dest, zero, 8 ) == 0 );
	}

	/* Test strcat() */
	{
		char buf[16] = "append";
		char *dest;

		dest = strcat ( buf, " this" );
		ok ( dest == buf );
		ok ( strcmp ( buf, "append this" ) == 0 );
	}

	/* Test digit_value() */
	{
		unsigned int i;
		char buf[2];
		for ( i = 0 ; i < 16 ; i++ ) {
			snprintf ( buf, sizeof ( buf ), "%x", i );
			ok ( digit_value ( buf[0] ) == i );
			snprintf ( buf, sizeof ( buf ), "%X", i );
			ok ( digit_value ( buf[0] ) == i );
		}
		ok ( digit_value ( 0 ) >= 16 );
		ok ( digit_value ( 9 ) >= 16 );
		ok ( digit_value ( '0' - 1 ) >= 16 );
		ok ( digit_value ( '9' + 1 ) >= 16 );
		ok ( digit_value ( 'A' - 1 ) >= 16 );
		ok ( digit_value ( 'F' + 1 ) >= 16 );
		ok ( digit_value ( 'a' - 1 ) >= 16 );
		ok ( digit_value ( 'f' + 1 ) >= 16 );
	}

	/* Test strtoul() */
	ok ( strtoul ( "12345", NULL, 0 ) == 12345UL );
	ok ( strtoul ( "  741", NULL, 10 ) == 741UL );
	ok ( strtoul ( " 555a", NULL, 0 ) == 555UL );
	ok ( strtoul ( " 555a", NULL, 16 ) == 0x555aUL );
	ok ( strtoul ( "-12", NULL, 0 ) == -12UL );
	ok ( strtoul ( "+3", NULL, 0 ) == 3UL );
	ok ( strtoul ( "721", NULL, 0 ) == 721UL );
	ok ( strtoul ( "721", NULL, 8 ) == 0721UL );
	ok ( strtoul ( "0721", NULL, 0 ) == 0721UL );
	ok ( strtoul ( "", NULL, 0 ) == 0UL );
	ok ( strtoul ( "\t0xcAfe", NULL, 0 ) == 0xcafeUL );
	ok ( strtoul ( "0xffffffff", NULL, 0 ) == 0xffffffffUL );
	{
		static const char string[] = "123aHa.world";
		char *endp;
		ok ( strtoul ( string, &endp, 0 ) == 123UL );
		ok ( endp == &string[3] );
		ok ( strtoul ( string, &endp, 16 ) == 0x123aUL );
		ok ( endp == &string[4] );
		ok ( strtoul ( string, &endp, 26 ) ==
		     ( ( ( ( ( 1 * 26 + 2 ) * 26 + 3 ) * 26 + 10 ) * 26
			 + 17 ) * 26 + 10 ) );
		ok ( endp == &string[6] );
	}
}

/** String self-test */
struct self_test string_test __self_test = {
	.name = "string",
	.exec = string_test_exec,
};
