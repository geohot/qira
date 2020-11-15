/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
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
 * Profiling self-tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <string.h>
#include <assert.h>
#include <ipxe/test.h>
#include <ipxe/profile.h>

/** A profiling test */
struct profile_test {
	/** Sample values */
	const unsigned long *samples;
	/** Number of samples */
	unsigned int count;
	/** Expected mean sample value */
	unsigned long mean;
	/** Expected standard deviation */
	unsigned long stddev;
};

/** Define inline data */
#define DATA(...) { __VA_ARGS__ }

/** Define a profiling test */
#define PROFILE_TEST( name, MEAN, STDDEV, SAMPLES )			\
	static const unsigned long name ## _samples[] = SAMPLES;	\
	static struct profile_test name = {				\
		.samples = name ## _samples,				\
		.count = ( sizeof ( name ## _samples ) /		\
			   sizeof ( name ## _samples [0] ) ),		\
		.mean = MEAN,						\
		.stddev = STDDEV,					\
	}

/** Empty data set */
PROFILE_TEST ( empty, 0, 0, DATA() );

/** Single-element data set (zero) */
PROFILE_TEST ( zero, 0, 0, DATA ( 0 ) );

/** Single-element data set (non-zero) */
PROFILE_TEST ( single, 42, 0, DATA ( 42 ) );

/** Multiple identical element data set */
PROFILE_TEST ( identical, 69, 0, DATA ( 69, 69, 69, 69, 69, 69, 69 ) );

/** Small element data set */
PROFILE_TEST ( small, 5, 2, DATA ( 3, 5, 9, 4, 3, 2, 5, 7 ) );

/** Random data set */
PROFILE_TEST ( random, 70198, 394,
	       DATA ( 69772, 70068, 70769, 69653, 70663, 71078, 70101, 70341,
		      70215, 69600, 70020, 70456, 70421, 69972, 70267, 69999,
		      69972 ) );

/** Large-valued random data set */
PROFILE_TEST ( large, 93533894UL, 25538UL,
	       DATA ( 93510333UL, 93561169UL, 93492361UL, 93528647UL,
		      93557566UL, 93503465UL, 93540126UL, 93549020UL,
		      93502307UL, 93527320UL, 93537152UL, 93540125UL,
		      93550773UL, 93586731UL, 93521312UL ) );

/**
 * Report a profiling test result
 *
 * @v test		Profiling test
 * @v file		Test code file
 * @v line		Test code line
 */
static void profile_okx ( struct profile_test *test, const char *file,
			  unsigned int line ) {
	struct profiler profiler;
	unsigned long mean;
	unsigned long stddev;
	unsigned int i;

	/* Initialise profiler */
	memset ( &profiler, 0, sizeof ( profiler ) );

	/* Record sample values */
	for ( i = 0 ; i < test->count ; i++ )
		profile_update ( &profiler, test->samples[i] );

	/* Check resulting statistics */
	mean = profile_mean ( &profiler );
	stddev = profile_stddev ( &profiler );
	DBGC ( test, "PROFILE calculated mean %ld stddev %ld\n", mean, stddev );
	okx ( mean == test->mean, file, line );
	okx ( stddev == test->stddev, file, line );
}
#define profile_ok( test ) profile_okx ( test, __FILE__, __LINE__ )

/**
 * Perform profiling self-tests
 *
 */
static void profile_test_exec ( void ) {

	/* Perform profiling tests */
	profile_ok ( &empty );
	profile_ok ( &zero );
	profile_ok ( &single );
	profile_ok ( &identical );
	profile_ok ( &small );
	profile_ok ( &random );
	profile_ok ( &large );
}

/** Profiling self-test */
struct self_test profile_test __self_test = {
	.name = "profile",
	.exec = profile_test_exec,
};
