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
 * Line buffer self-tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <string.h>
#include <assert.h>
#include <ipxe/linebuf.h>
#include <ipxe/test.h>

/** Define inline raw data */
#define DATA(...) { __VA_ARGS__ }

/** Define inline lines */
#define LINES(...) { __VA_ARGS__ }

/** A line buffer test */
struct linebuf_test {
	/** Raw data */
	const void *data;
	/** Length of raw data */
	size_t len;
	/** Expected sequence of lines */
	const char **lines;
	/** Number of expected lines */
	unsigned int count;
};

/** Line buffer test expected failure indicator */
static const char linebuf_failure[1];

/**
 * Define a line buffer test
 *
 * @v name		Test name
 * @v DATA		Raw data
 * @v LINES		Expected sequence of lines
 * @ret test		Line buffer test
 */
#define LINEBUF_TEST( name, DATA, LINES )				\
	static const char name ## _data[] = DATA;			\
	static const char * name ## _lines[] = LINES;			\
	static struct linebuf_test name = {				\
		.data = name ## _data,					\
		.len = ( sizeof ( name ## _data ) - 1 /* NUL */ ),	\
		.lines = name ## _lines,				\
		.count = ( sizeof ( name ## _lines ) /			\
			   sizeof ( name ## _lines[0] ) ),		\
	}

/** Simple line buffer test */
LINEBUF_TEST ( simple,
	       ( "HTTP/1.1 200 OK\r\n"
		 "Content-Length: 123\r\n"
		 "Content-Type: text/plain\r\n"
		 "\r\n" ),
	       LINES ( "HTTP/1.1 200 OK",
		       "Content-Length: 123",
		       "Content-Type: text/plain",
		       "" ) );

/** Mixed line terminators */
LINEBUF_TEST ( mixed,
	       ( "LF only\n" "CRLF\r\n" "\n" "\n" "\r\n" "\r\n" "CR only\r" ),
	       LINES ( "LF only", "CRLF", "", "", "", "",
		       NULL /* \r should not be treated as a terminator */ ) );

/** Split consumption: part 1 */
LINEBUF_TEST ( split_1,
	       ( "This line was" ),
	       LINES ( NULL ) );

/** Split consumption: part 2 */
LINEBUF_TEST ( split_2,
	       ( " split across" ),
	       LINES ( NULL ) );

/** Split consumption: part 3 */
LINEBUF_TEST ( split_3,
	       ( " multiple calls\r\nand so was this one\r" ),
	       LINES ( "This line was split across multiple calls", NULL ) );

/** Split consumption: part 4 */
LINEBUF_TEST ( split_4,
	       ( "\nbut not this one\r\n" ),
	       LINES ( "and so was this one", "but not this one" ) );

/** Split consumption: part 5 */
LINEBUF_TEST ( split_5,
	       ( "" ),
	       LINES ( NULL ) );

/** Split consumption: part 6 */
LINEBUF_TEST ( split_6,
	       ( "This line came after a zero-length call\r\n" ),
	       LINES ( "This line came after a zero-length call" ) );

/** Embedded NULs */
LINEBUF_TEST ( embedded_nuls,
	       ( "This\r\ntest\r\nincludes\r\n\r\nsome\0binary\0data\r\n" ),
	       LINES ( "This", "test", "includes", "", linebuf_failure ) );

/**
 * Report line buffer initialisation test result
 *
 * @v linebuf		Line buffer
 * @v file		Test code file
 * @v line		Test code line
 */
static void linebuf_init_okx ( struct line_buffer *linebuf,
				const char *file, unsigned int line ) {

	/* Initialise line buffer */
	memset ( linebuf, 0, sizeof ( *linebuf ) );
	okx ( buffered_line ( linebuf ) == NULL, file, line );
}
#define linebuf_init_ok( linebuf ) \
	linebuf_init_okx ( linebuf, __FILE__, __LINE__ )

/**
 * Report line buffer consumption test result
 *
 * @v test		Line buffer test
 * @v linebuf		Line buffer
 * @v file		Test code file
 * @v line		Test code line
 */
static void linebuf_consume_okx ( struct linebuf_test *test,
				  struct line_buffer *linebuf,
				  const char *file, unsigned int line ) {
	const char *data = test->data;
	size_t remaining = test->len;
	int len;
	unsigned int i;
	const char *expected;
	char *actual;
	int rc;

	DBGC ( test, "LINEBUF %p:\n", test );
	DBGC_HDA ( test, 0, data, remaining );

	/* Consume data one line at a time */
	for ( i = 0 ; i < test->count ; i++ ) {

		/* Add data to line buffer */
		len = line_buffer ( linebuf, data, remaining );

		/* Get buffered line, if any */
		actual = buffered_line ( linebuf );
		if ( len < 0 ) {
			rc = len;
			DBGC ( test, "LINEBUF %p %s\n", test, strerror ( rc ) );
		} else if ( actual != NULL ) {
			DBGC ( test, "LINEBUF %p \"%s\" (consumed %d)\n",
			       test, actual, len );
		} else {
			DBGC ( test, "LINEBUF %p unterminated (consumed %d)\n",
			       test, len );
		}

		/* Check for success/failure */
		expected = test->lines[i];
		if ( expected == linebuf_failure ) {
			rc = len;
			okx ( rc < 0, file, line );
			okx ( remaining > 0, file, line );
			return;
		}
		okx ( len >= 0, file, line );
		okx ( ( ( size_t ) len ) <= remaining, file, line );

		/* Check expected result */
		if ( expected == NULL ) {
			okx ( actual == NULL, file, line );
		} else {
			okx ( actual != NULL, file, line );
			okx ( strcmp ( actual, expected ) == 0, file, line );
		}

		/* Consume data */
		data += len;
		remaining -= len;
	}

	/* Check that all data was consumed */
	okx ( remaining == 0, file, line );
}
#define linebuf_consume_ok( test, linebuf ) \
	linebuf_consume_okx ( test, linebuf, __FILE__, __LINE__ )

/**
 * Report line buffer accumulation test result
 *
 * @v test		Line buffer test
 * @v linebuf		Line buffer
 * @v file		Test code file
 * @v line		Test code line
 */
static void linebuf_accumulated_okx ( struct linebuf_test *test,
				      struct line_buffer *linebuf,
				      const char *file, unsigned int line ) {
	const char *actual;
	const char *expected;
	unsigned int i;

	/* Check each accumulated line */
	actual = linebuf->data;
	for ( i = 0 ; i < test->count ; i++ ) {

		/* Check accumulated line */
		okx ( actual != NULL, file, line );
		okx ( actual >= linebuf->data, file, line );
		expected = test->lines[i];
		if ( ( expected == NULL ) || ( expected == linebuf_failure ) )
			return;
		okx ( strcmp ( actual, expected ) == 0, file, line );

		/* Move to next line */
		actual += ( strlen ( actual ) + 1 /* NUL */ );
		okx ( actual <= ( linebuf->data + linebuf->len ), file, line );
	}
}
#define linebuf_accumulated_ok( test, linebuf ) \
	linebuf_accumulated_okx ( test, linebuf, __FILE__, __LINE__ )

/**
 * Report line buffer emptying test result
 *
 * @v linebuf		Line buffer
 * @v file		Test code file
 * @v line		Test code line
 */
static void linebuf_empty_okx ( struct line_buffer *linebuf,
				const char *file, unsigned int line ) {

	/* Empty line buffer */
	empty_line_buffer ( linebuf );
	okx ( buffered_line ( linebuf ) == NULL, file, line );
}
#define linebuf_empty_ok( linebuf ) \
	linebuf_empty_okx ( linebuf, __FILE__, __LINE__ )

/**
 * Report line buffer combined test result
 *
 * @v test		Line buffer test
 * @v file		Test code file
 * @v line		Test code line
 */
static void linebuf_okx ( struct linebuf_test *test, const char *file,
			  unsigned int line ) {
	struct line_buffer linebuf;

	linebuf_init_okx ( &linebuf, file, line );
	linebuf_consume_okx ( test, &linebuf, file, line );
	linebuf_accumulated_okx ( test, &linebuf, file, line );
	linebuf_empty_okx ( &linebuf, file, line );
}
#define linebuf_ok( test ) \
	linebuf_okx ( test, __FILE__, __LINE__ )

/**
 * Perform line buffer self-tests
 *
 */
static void linebuf_test_exec ( void ) {
	struct line_buffer linebuf;

	/* Basic tests */
	linebuf_ok ( &simple );
	linebuf_ok ( &mixed );

	/* Split consumption test */
	linebuf_init_ok ( &linebuf );
	linebuf_consume_ok ( &split_1, &linebuf );
	linebuf_consume_ok ( &split_2, &linebuf );
	linebuf_consume_ok ( &split_3, &linebuf );
	linebuf_consume_ok ( &split_4, &linebuf );
	linebuf_consume_ok ( &split_5, &linebuf );
	linebuf_consume_ok ( &split_6, &linebuf );
	linebuf_empty_ok ( &linebuf );

	/* Embedded NULs */
	linebuf_ok ( &embedded_nuls );
}

/** Line buffer self-test */
struct self_test linebuf_test __self_test = {
	.name = "linebuf",
	.exec = linebuf_test_exec,
};
