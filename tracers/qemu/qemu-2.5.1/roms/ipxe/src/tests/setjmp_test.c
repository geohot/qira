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
 * setjmp()/longjmp() tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stddef.h>
#include <assert.h>
#include <setjmp.h>
#include <ipxe/test.h>

/** A setjmp()/longjmp() test */
struct setjmp_test {
	/** Jump buffer */
	jmp_buf env;
	/** Expected value */
	int expected;
	/** Test code file */
	const char *file;
	/** Test code line */
	unsigned int line;
};

/** Expected jump */
static struct setjmp_test *jumped;

/**
 * Report a setjmp() test result
 *
 * @v test		setjmp()/longjmp() test
 *
 * This has to be implemented as a macro since if it were a function
 * then the context saved by setjmp() would be invalidated when the
 * function returned.
 */
#define setjmp_ok( test ) do {						\
	int value;							\
	/* Sanity check */						\
	assert ( jumped == NULL );					\
	/* Initialise test */						\
	(test)->expected = 0;						\
	(test)->file = __FILE__;					\
	(test)->line = __LINE__;					\
	/* Perform setjmp() */						\
	value = setjmp ( (test)->env );					\
	/* Report setjmp()/longjmp() result */				\
	setjmp_return_ok ( (test), value );				\
	} while ( 0 )

/**
 * Report a setjmp()/longjmp() test result
 *
 * @v test		setjmp()/longjmp() test
 * @v value		Value returned from setjmp()
 *
 * This function ends up reporting results from either setjmp() or
 * longjmp() tests (since calls to longjmp() will return via the
 * corresponding setjmp()).  It therefore uses the test code file and
 * line stored in the test structure, which will represent the line
 * from which either setjmp() or longjmp() was called.
 */
static void setjmp_return_ok ( struct setjmp_test *test, int value ) {

	/* Determine whether this was reached via setjmp() or longjmp() */
	if ( value == 0 ) {
		/* This is the initial call to setjmp() */
		okx ( test->expected == 0, test->file, test->line );
		okx ( jumped == NULL, test->file, test->line );
	} else {
		/* This is reached via a call to longjmp() */
		okx ( value == test->expected, test->file, test->line );
		okx ( jumped == test, test->file, test->line );
	}

	/* Clear expected jump */
	jumped = NULL;
}

/**
 * Report a longjmp() test result
 *
 * @v test		setjmp()/longjmp() test
 * @v file		Test code file
 * @v line		Test code line
 */
static void longjmp_okx ( struct setjmp_test *test, int value,
			  const char *file, unsigned int line ) {

	/* Record expected value.  A zero passed to longjmp() should
	 * result in setjmp() returning a value of one.
	 */
	test->expected = ( value ? value : 1 );

	/* Record test code file and line */
	test->file = file;
	test->line = line;

	/* Record expected jump */
	jumped = test;

	/* Perform longjmp().  Should return via setjmp_okx() */
	longjmp ( test->env, value );

	/* longjmp() should never return */
	assert ( 0 );
}
#define longjmp_ok( test, value ) \
	longjmp_okx ( test, value, __FILE__, __LINE__ )

/**
 * Perform setjmp()/longjmp() self-tests
 *
 */
static void setjmp_test_exec ( void ) {
	static struct setjmp_test alpha;
	static struct setjmp_test beta;
	static int iteration;

	/* This is one of the very few situations in which the
	 * "for-case" pattern is justified.
	 */
	for ( iteration = 0 ; iteration < 10 ; iteration++ ) {
		DBGC ( jumped, "SETJMP test iteration %d\n", iteration );
		switch ( iteration ) {
		case 0: setjmp_ok ( &alpha ); break;
		case 1: setjmp_ok ( &beta ); break;
		case 2:	longjmp_ok ( &alpha, 0 );
		case 3: longjmp_ok ( &alpha, 1 );
		case 4: longjmp_ok ( &alpha, 2 );
		case 5: longjmp_ok ( &beta, 17 );
		case 6: longjmp_ok ( &beta, 29 );
		case 7: longjmp_ok ( &alpha, -1 );
		case 8: longjmp_ok ( &beta, 0 );
		case 9: longjmp_ok ( &beta, 42 );
		}
	}
}

/** setjmp()/longjmp() self-test */
struct self_test setjmp_test __self_test = {
	.name = "setjmp",
	.exec = setjmp_test_exec,
};
