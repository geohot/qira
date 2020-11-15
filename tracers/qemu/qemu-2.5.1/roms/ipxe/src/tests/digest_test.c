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
 * Digest self-tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stdlib.h>
#include <string.h>
#include <ipxe/crypto.h>
#include <ipxe/profile.h>
#include "digest_test.h"

/** Maximum number of digest test fragments */
#define NUM_DIGEST_TEST_FRAG 8

/** A digest test fragment list */
struct digest_test_fragments {
	/** Fragment lengths */
	size_t len[NUM_DIGEST_TEST_FRAG];
};

/** Digest test fragment lists */
static struct digest_test_fragments digest_test_fragments[] = {
	{ { 0, -1UL, } },
	{ { 1, 1, 1, 1, 1, 1, 1, 1 } },
	{ { 2, 0, 23, 4, 6, 1, 0 } },
};

/** Number of sample iterations for profiling */
#define PROFILE_COUNT 16

/**
 * Report a digest fragmented test result
 *
 * @v test		Digest test
 * @v fragments		Fragment list
 * @v file		Test code file
 * @v line		Test code line
 */
void digest_frag_okx ( struct digest_test *test,
		       struct digest_test_fragments *fragments,
		       const char *file, unsigned int line ) {
	struct digest_algorithm *digest = test->digest;
	uint8_t ctx[digest->ctxsize];
	uint8_t out[digest->digestsize];
	const void *data = test->data;
	size_t len = test->len;
	size_t frag_len = 0;
	unsigned int i;

	/* Sanity check */
	okx ( test->expected_len == sizeof ( out ), file, line );

	/* Initialise digest */
	digest_init ( digest, ctx );

	/* Update digest fragment-by-fragment */
	for ( i = 0 ; len && ( i < ( sizeof ( fragments->len ) /
				     sizeof ( fragments->len[0] ) ) ) ; i++ ) {
		if ( fragments )
			frag_len = fragments->len[i];
		if ( ( frag_len == 0 ) || ( frag_len < len ) )
			frag_len = len;
		digest_update ( digest, ctx, data, frag_len );
		data += frag_len;
		len -= frag_len;
	}

	/* Finalise digest */
	digest_final ( digest, ctx, out );

	/* Compare against expected output */
	okx ( memcmp ( test->expected, out, sizeof ( out ) ) == 0, file, line );
}

/**
 * Report a digest test result
 *
 * @v test		Digest test
 * @v file		Test code file
 * @v line		Test code line
 */
void digest_okx ( struct digest_test *test, const char *file,
		  unsigned int line ) {
	unsigned int i;

	/* Test with a single pass */
	digest_frag_okx ( test, NULL, file, line );

	/* Test with fragment lists */
	for ( i = 0 ; i < ( sizeof ( digest_test_fragments ) /
			    sizeof ( digest_test_fragments[0] ) ) ; i++ ) {
		digest_frag_okx ( test, &digest_test_fragments[i], file, line );
	}
}

/**
 * Calculate digest algorithm cost
 *
 * @v digest		Digest algorithm
 * @ret cost		Cost (in cycles per byte)
 */
unsigned long digest_cost ( struct digest_algorithm *digest ) {
	static uint8_t random[8192]; /* Too large for stack */
	uint8_t ctx[digest->ctxsize];
	uint8_t out[digest->digestsize];
	struct profiler profiler;
	unsigned long cost;
	unsigned int i;

	/* Fill buffer with pseudo-random data */
	srand ( 0x1234568 );
	for ( i = 0 ; i < sizeof ( random ) ; i++ )
		random[i] = rand();

	/* Profile digest calculation */
	memset ( &profiler, 0, sizeof ( profiler ) );
	for ( i = 0 ; i < PROFILE_COUNT ; i++ ) {
		profile_start ( &profiler );
		digest_init ( digest, ctx );
		digest_update ( digest, ctx, random, sizeof ( random ) );
		digest_final ( digest, ctx, out );
		profile_stop ( &profiler );
	}

	/* Round to nearest whole number of cycles per byte */
	cost = ( ( profile_mean ( &profiler ) + ( sizeof ( random ) / 2 ) ) /
		 sizeof ( random ) );

	return cost;
}
