/*
 * Copyright (C) 2011 Michael Brown <mbrown@fensystems.co.uk>.
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
 * Self-test infrastructure
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/test.h>
#include <ipxe/init.h>
#include <ipxe/image.h>
#include <usr/profstat.h>

/** Current self-test set */
static struct self_test *current_tests;

/**
 * Report test result
 *
 * @v success		Test succeeded
 * @v file		Test code file
 * @v line		Test code line
 * @v test		Test code
 */
void test_ok ( int success, const char *file, unsigned int line,
	       const char *test ) {

	/* Sanity check */
	assert ( current_tests != NULL );

	/* Increment test counter */
	current_tests->total++;

	/* Report failure if applicable */
	if ( ! success ) {
		current_tests->failures++;
		printf ( "FAILURE: \"%s\" test failed at %s line %d: ( %s )\n",
			 current_tests->name, file, line, test );
	}
}

/**
 * Run self-test set
 *
 */
static void run_tests ( struct self_test *tests ) {
	unsigned int old_assertion_failures = assertion_failures;

	/* Sanity check */
	assert ( current_tests == NULL );

	/* Record current test set */
	current_tests = tests;

	/* Run tests */
	tests->exec();

	/* Clear current test set */
	current_tests = NULL;

	/* Record number of assertion failures */
	tests->assertion_failures =
		( assertion_failures - old_assertion_failures );

	/* Print test set summary */
	if ( tests->failures || tests->assertion_failures ) {
		printf ( "FAILURE: \"%s\" %d of %d tests failed",
			 tests->name, tests->failures, tests->total );
		if ( tests->assertion_failures ) {
			printf ( " with %d assertion failures",
				 tests->assertion_failures );
		}
		printf ( "\n" );
	} else {
		printf ( "OK: \"%s\" %d tests passed\n",
			 tests->name, tests->total );
	}
}

/**
 * Run all self-tests
 *
 * @ret rc		Return status code
 */
static int run_all_tests ( void ) {
	struct self_test *tests;
	unsigned int failures = 0;
	unsigned int assertions = 0;
	unsigned int total = 0;

	/* Run all compiled-in self-tests */
	printf ( "Starting self-tests\n" );
	for_each_table_entry ( tests, SELF_TESTS )
		run_tests ( tests );

	/* Print overall summary */
	for_each_table_entry ( tests, SELF_TESTS ) {
		total += tests->total;
		failures += tests->failures;
		assertions += tests->assertion_failures;
	}
	if ( failures || assertions ) {
		printf ( "FAILURE: %d of %d tests failed",
			 failures, total );
		if ( assertions ) {
			printf ( " with %d assertion failures", assertions );
		}
		printf ( "\n" );
		return -EINPROGRESS;
	} else {
		printf ( "OK: all %d tests passed\n", total );
		profstat();
		return 0;
	}
}

static int test_image_probe ( struct image *image __unused ) {
	return -ENOTTY;
}

static int test_image_exec ( struct image *image __unused ) {
	return run_all_tests();
}

static struct image_type test_image_type = {
	.name = "self-tests",
	.probe = test_image_probe,
	.exec = test_image_exec,
};

static struct image test_image = {
	.refcnt = REF_INIT ( ref_no_free ),
	.name = "<TESTS>",
	.type = &test_image_type,
};

static void test_init ( void ) {
	int rc;

	/* Register self-tests image */
	if ( ( rc = register_image ( &test_image ) ) != 0 ) {
		DBG ( "Could not register self-test image: %s\n",
		      strerror ( rc ) );
		/* No way to report failure */
		return;
	}
}

/** Self-test initialisation function */
struct init_fn test_init_fn __init_fn ( INIT_EARLY ) = {
	.initialise = test_init,
};
