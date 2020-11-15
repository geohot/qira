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
 * Entropy source
 *
 * This algorithm is designed to comply with ANS X9.82 Part 4 (April
 * 2011 Draft) Section 13.3.  This standard is unfortunately not
 * freely available.
 */

#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <ipxe/crypto.h>
#include <ipxe/hash_df.h>
#include <ipxe/entropy.h>

/* Disambiguate the various error causes */
#define EPIPE_REPETITION_COUNT_TEST \
	__einfo_error ( EINFO_EPIPE_REPETITION_COUNT_TEST )
#define EINFO_EPIPE_REPETITION_COUNT_TEST \
	__einfo_uniqify ( EINFO_EPIPE, 0x01, "Repetition count test failed" )
#define EPIPE_ADAPTIVE_PROPORTION_TEST \
	__einfo_error ( EINFO_EPIPE_ADAPTIVE_PROPORTION_TEST )
#define EINFO_EPIPE_ADAPTIVE_PROPORTION_TEST \
	__einfo_uniqify ( EINFO_EPIPE, 0x02, "Adaptive proportion test failed" )

/**
 * Calculate cutoff value for the repetition count test
 *
 * @ret cutoff		Cutoff value
 *
 * This is the cutoff value for the Repetition Count Test defined in
 * ANS X9.82 Part 2 (October 2011 Draft) Section 8.5.2.1.2.
 */
static inline __attribute__ (( always_inline )) unsigned int
repetition_count_cutoff ( void ) {
	double max_repetitions;
	unsigned int cutoff;

	/* The cutoff formula for the repetition test is:
	 *
	 *   C = ( 1 + ( -log2(W) / H_min ) )
	 *
	 * where W is set at 2^(-30) (in ANS X9.82 Part 2 (October
	 * 2011 Draft) Section 8.5.2.1.3.1).
	 */
	max_repetitions = ( 1 + ( 30 / min_entropy_per_sample() ) );

	/* Round up to a whole number of repetitions.  We don't have
	 * the ceil() function available, so do the rounding by hand.
	 */
	cutoff = max_repetitions;
	if ( cutoff < max_repetitions )
		cutoff++;
	linker_assert ( ( cutoff >= max_repetitions ), rounding_error );

	/* Floating-point operations are not allowed in iPXE since we
	 * never set up a suitable environment.  Abort the build
	 * unless the calculated number of repetitions is a
	 * compile-time constant.
	 */
	linker_assert ( __builtin_constant_p ( cutoff ),
			repetition_count_cutoff_not_constant );

	return cutoff;
}

/**
 * Perform repetition count test
 *
 * @v sample		Noise sample
 * @ret rc		Return status code
 *
 * This is the Repetition Count Test defined in ANS X9.82 Part 2
 * (October 2011 Draft) Section 8.5.2.1.2.
 */
static int repetition_count_test ( noise_sample_t sample ) {
	static noise_sample_t most_recent_sample;
	static unsigned int repetition_count = 0;

	/* A = the most recently seen sample value
	 * B = the number of times that value A has been seen in a row
	 * C = the cutoff value above which the repetition test should fail
	 */

	/* 1.  For each new sample processed:
	 *
	 * (Note that the test for "repetition_count > 0" ensures that
	 * the initial value of most_recent_sample is treated as being
	 * undefined.)
	 */
	if ( ( sample == most_recent_sample ) && ( repetition_count > 0 ) ) {

		/* a) If the new sample = A, then B is incremented by one. */
		repetition_count++;

		/*    i.  If B >= C, then an error condition is raised
		 *        due to a failure of the test
		 */
		if ( repetition_count >= repetition_count_cutoff() )
			return -EPIPE_REPETITION_COUNT_TEST;

	} else {

		/* b) Else:
		 *    i.  A = new sample
		 */
		most_recent_sample = sample;

		/*    ii. B = 1 */
		repetition_count = 1;
	}

	return 0;
}

/**
 * Window size for the adaptive proportion test
 *
 * ANS X9.82 Part 2 (October 2011 Draft) Section 8.5.2.1.3.1.1 allows
 * five possible window sizes: 16, 64, 256, 4096 and 65536.
 *
 * We expect to generate relatively few (<256) entropy samples during
 * a typical iPXE run; the use of a large window size would mean that
 * the test would never complete a single cycle.  We use a window size
 * of 64, which is the smallest window size that permits values of
 * H_min down to one bit per sample.
 */
#define ADAPTIVE_PROPORTION_WINDOW_SIZE 64

/**
 * Combine adaptive proportion test window size and min-entropy
 *
 * @v n			N (window size)
 * @v h			H (min-entropy)
 * @ret n_h		(N,H) combined value
 */
#define APC_N_H( n, h ) ( ( (n) << 8 ) | (h) )

/**
 * Define a row of the adaptive proportion cutoff table
 *
 * @v h			H (min-entropy)
 * @v c16		Cutoff for N=16
 * @v c64		Cutoff for N=64
 * @v c256		Cutoff for N=256
 * @v c4096		Cutoff for N=4096
 * @v c65536		Cutoff for N=65536
 */
#define APC_TABLE_ROW( h, c16, c64, c256, c4096, c65536)	   \
	case APC_N_H ( 16, h ) :	return c16;		   \
	case APC_N_H ( 64, h ) :	return c64;   		   \
	case APC_N_H ( 256, h ) :	return c256;		   \
	case APC_N_H ( 4096, h ) :	return c4096;		   \
	case APC_N_H ( 65536, h ) :	return c65536;

/** Value used to represent "N/A" in adaptive proportion cutoff table */
#define APC_NA 0

/**
 * Look up value in adaptive proportion test cutoff table
 *
 * @v n			N (window size)
 * @v h			H (min-entropy)
 * @ret cutoff		Cutoff
 *
 * This is the table of cutoff values defined in ANS X9.82 Part 2
 * (October 2011 Draft) Section 8.5.2.1.3.1.2.
 */
static inline __attribute__ (( always_inline )) unsigned int
adaptive_proportion_cutoff_lookup ( unsigned int n, unsigned int h ) {
	switch ( APC_N_H ( n, h ) ) {
		APC_TABLE_ROW (  1, APC_NA,     51,    168,   2240,  33537 );
		APC_TABLE_ROW (  2, APC_NA,     35,    100,   1193,  17053 );
		APC_TABLE_ROW (  3,     10,     24,     61,    643,   8705 );
		APC_TABLE_ROW (  4,      8,     16,     38,    354,   4473 );
		APC_TABLE_ROW (  5,      6,     12,     25,    200,   2321 );
		APC_TABLE_ROW (  6,      5,      9,     17,    117,   1220 );
		APC_TABLE_ROW (  7,      4,      7,     15,     71,    653 );
		APC_TABLE_ROW (  8,      4,      5,      9,     45,    358 );
		APC_TABLE_ROW (  9,      3,      4,      7,     30,    202 );
		APC_TABLE_ROW ( 10,      3,      4,      5,     21,    118 );
		APC_TABLE_ROW ( 11,      2,      3,      4,     15,     71 );
		APC_TABLE_ROW ( 12,      2,      3,      4,     11,     45 );
		APC_TABLE_ROW ( 13,      2,      2,      3,      9,     30 );
		APC_TABLE_ROW ( 14,      2,      2,      3,      7,     21 );
		APC_TABLE_ROW ( 15,      1,      2,      2,      6,     15 );
		APC_TABLE_ROW ( 16,      1,      2,      2,      5,     11 );
		APC_TABLE_ROW ( 17,      1,      1,      2,      4,      9 );
		APC_TABLE_ROW ( 18,      1,      1,      2,      4,      7 );
		APC_TABLE_ROW ( 19,      1,      1,      1,      3,      6 );
		APC_TABLE_ROW ( 20,      1,      1,      1,      3,      5 );
	default:
		return APC_NA;
	}
}

/**
 * Calculate cutoff value for the adaptive proportion test
 *
 * @ret cutoff		Cutoff value
 *
 * This is the cutoff value for the Adaptive Proportion Test defined
 * in ANS X9.82 Part 2 (October 2011 Draft) Section 8.5.2.1.3.1.2.
 */
static inline __attribute__ (( always_inline )) unsigned int
adaptive_proportion_cutoff ( void ) {
	unsigned int h;
	unsigned int n;
	unsigned int cutoff;

	/* Look up cutoff value in cutoff table */
	n = ADAPTIVE_PROPORTION_WINDOW_SIZE;
	h = min_entropy_per_sample();
	cutoff = adaptive_proportion_cutoff_lookup ( n, h );

	/* Fail unless cutoff value is a build-time constant */
	linker_assert ( __builtin_constant_p ( cutoff ),
			adaptive_proportion_cutoff_not_constant );

	/* Fail if cutoff value is N/A */
	linker_assert ( ( cutoff != APC_NA ),
			adaptive_proportion_cutoff_not_applicable );

	return cutoff;
}

/**
 * Perform adaptive proportion test
 *
 * @v sample		Noise sample
 * @ret rc		Return status code
 *
 * This is the Adaptive Proportion Test for the Most Common Value
 * defined in ANS X9.82 Part 2 (October 2011 Draft) Section 8.5.2.1.3.
 */
static int adaptive_proportion_test ( noise_sample_t sample ) {
	static noise_sample_t current_counted_sample;
	static unsigned int sample_count = ADAPTIVE_PROPORTION_WINDOW_SIZE;
	static unsigned int repetition_count;

	/* A = the sample value currently being counted
	 * B = the number of samples examined in this run of the test so far
	 * N = the total number of samples that must be observed in
	 *     one run of the test, also known as the "window size" of
	 *     the test
	 * B = the current number of times that S (sic) has been seen
	 *     in the W (sic) samples examined so far
	 * C = the cutoff value above which the repetition test should fail
	 * W = the probability of a false positive: 2^-30
	 */

	/* 1.  The entropy source draws the current sample from the
	 *     noise source.
	 *
	 * (Nothing to do; we already have the current sample.)
	 */

	/* 2.  If S = N, then a new run of the test begins: */
	if ( sample_count == ADAPTIVE_PROPORTION_WINDOW_SIZE ) {

		/* a.  A = the current sample */
		current_counted_sample = sample;

		/* b.  S = 0 */
		sample_count = 0;

		/* c. B = 0 */
		repetition_count = 0;

	} else {

		/* Else: (the test is already running)
		 * a.  S = S + 1
		 */
		sample_count++;

		/* b.  If A = the current sample, then: */
		if ( sample == current_counted_sample ) {

			/* i.   B = B + 1 */
			repetition_count++;

			/* ii.  If S (sic) > C then raise an error
			 *      condition, because the test has
			 *      detected a failure
			 */
			if ( repetition_count > adaptive_proportion_cutoff() )
				return -EPIPE_ADAPTIVE_PROPORTION_TEST;

		}
	}

	return 0;
}

/**
 * Get entropy sample
 *
 * @ret entropy		Entropy sample
 * @ret rc		Return status code
 *
 * This is the GetEntropy function defined in ANS X9.82 Part 2
 * (October 2011 Draft) Section 6.5.1.
 */
static int get_entropy ( entropy_sample_t *entropy ) {
	static int rc = 0;
	noise_sample_t noise;

	/* Any failure is permanent */
	if ( rc != 0 )
		return rc;

	/* Get noise sample */
	if ( ( rc = get_noise ( &noise ) ) != 0 )
		return rc;

	/* Perform Repetition Count Test and Adaptive Proportion Test
	 * as mandated by ANS X9.82 Part 2 (October 2011 Draft)
	 * Section 8.5.2.1.1.
	 */
	if ( ( rc = repetition_count_test ( noise ) ) != 0 )
		return rc;
	if ( ( rc = adaptive_proportion_test ( noise ) ) != 0 )
		return rc;

	/* We do not use any optional conditioning component */
	*entropy = noise;

	return 0;
}

/**
 * Calculate number of samples required for startup tests
 *
 * @ret num_samples	Number of samples required
 *
 * ANS X9.82 Part 2 (October 2011 Draft) Section 8.5.2.1.5 requires
 * that at least one full cycle of the continuous tests must be
 * performed at start-up.
 */
static inline __attribute__ (( always_inline )) unsigned int
startup_test_count ( void ) {
	unsigned int num_samples;

	/* At least max(N,C) samples shall be generated by the noise
	 * source for start-up testing.
	 */
	num_samples = repetition_count_cutoff();
	if ( num_samples < adaptive_proportion_cutoff() )
		num_samples = adaptive_proportion_cutoff();
	linker_assert ( __builtin_constant_p ( num_samples ),
			startup_test_count_not_constant );

	return num_samples;
}

/**
 * Create next nonce value
 *
 * @ret nonce		Nonce
 *
 * This is the MakeNextNonce function defined in ANS X9.82 Part 4
 * (April 2011 Draft) Section 13.3.4.2.
 */
static uint32_t make_next_nonce ( void ) {
	static uint32_t nonce;

	/* The simplest implementation of a nonce uses a large counter */
	nonce++;

	return nonce;
}

/**
 * Obtain entropy input temporary buffer
 *
 * @v num_samples	Number of entropy samples
 * @v tmp		Temporary buffer
 * @v tmp_len		Length of temporary buffer
 * @ret rc		Return status code
 *
 * This is (part of) the implementation of the Get_entropy_input
 * function (using an entropy source as the source of entropy input
 * and condensing each entropy source output after each GetEntropy
 * call) as defined in ANS X9.82 Part 4 (April 2011 Draft) Section
 * 13.3.4.2.
 *
 * To minimise code size, the number of samples required is calculated
 * at compilation time.
 */
int get_entropy_input_tmp ( unsigned int num_samples, uint8_t *tmp,
			    size_t tmp_len ) {
	static unsigned int startup_tested = 0;
	struct {
		uint32_t nonce;
		entropy_sample_t sample;
	} __attribute__ (( packed )) data;;
	uint8_t df_buf[tmp_len];
	unsigned int i;
	int rc;

	/* Enable entropy gathering */
	if ( ( rc = entropy_enable() ) != 0 )
		return rc;

	/* Perform mandatory startup tests, if not yet performed */
	for ( ; startup_tested < startup_test_count() ; startup_tested++ ) {
		if ( ( rc = get_entropy ( &data.sample ) ) != 0 )
			goto err_get_entropy;
	}

	/* 3.  entropy_total = 0
	 *
	 * (Nothing to do; the number of entropy samples required has
	 * already been precalculated.)
	 */

	/* 4.  tmp = a fixed n-bit value, such as 0^n */
	memset ( tmp, 0, tmp_len );

	/* 5.  While ( entropy_total < min_entropy ) */
	while ( num_samples-- ) {
		/* 5.1.  ( status, entropy_bitstring, assessed_entropy )
		 *       = GetEntropy()
		 * 5.2.  If status indicates an error, return ( status, Null )
		 */
		if ( ( rc = get_entropy ( &data.sample ) ) != 0 )
			goto err_get_entropy;

		/* 5.3.  nonce = MakeNextNonce() */
		data.nonce = make_next_nonce();

		/* 5.4.  tmp = tmp XOR
		 *             df ( ( nonce || entropy_bitstring ), n )
		 */
		hash_df ( &entropy_hash_df_algorithm, &data, sizeof ( data ),
			  df_buf, sizeof ( df_buf ) );
		for ( i = 0 ; i < tmp_len ; i++ )
			tmp[i] ^= df_buf[i];

		/* 5.5.  entropy_total = entropy_total + assessed_entropy
		 *
		 * (Nothing to do; the number of entropy samples
		 * required has already been precalculated.)
		 */
	}

	/* Disable entropy gathering */
	entropy_disable();

	return 0;

 err_get_entropy:
	entropy_disable();
	return rc;
}
