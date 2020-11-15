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

#include <stdint.h>
#include <stdio.h>
#include <strings.h>
#include <assert.h>
#include <ipxe/isqrt.h>
#include <ipxe/profile.h>

/** @file
 *
 * Profiling
 *
 * The profiler computes basic statistics (mean, variance, and
 * standard deviation) for the samples which it records.  Note that
 * these statistics need not be completely accurate; it is sufficient
 * to give a rough approximation.
 *
 * The algorithm for updating the mean and variance estimators is from
 * The Art of Computer Programming (via Wikipedia), with adjustments
 * to avoid the use of floating-point instructions.
 */

/** Accumulated time excluded from profiling */
unsigned long profile_excluded;

/**
 * Format a hex fraction (for debugging)
 *
 * @v value		Value
 * @v shift		Bit shift
 * @ret string		Formatted hex fraction
 */
static const char * profile_hex_fraction ( signed long long value,
					   unsigned int shift ) {
	static char buf[23] = "-"; /* -0xXXXXXXXXXXXXXXXX.XX + NUL */
	unsigned long long int_part;
	uint8_t frac_part;
	char *ptr;

	if ( value < 0 ) {
		value = -value;
		ptr = &buf[0];
	} else {
		ptr = &buf[1];
	}
	int_part = ( value >> shift );
	frac_part = ( value >> ( shift - ( 8 * sizeof ( frac_part ) ) ) );
	snprintf ( &buf[1], ( sizeof ( buf ) - 1  ), "%#llx.%02x",
		   int_part, frac_part );
	return ptr;
}

/**
 * Calculate bit shift for mean sample value
 *
 * @v profiler		Profiler
 * @ret shift		Bit shift
 */
static inline unsigned int profile_mean_shift ( struct profiler *profiler ) {

	return ( ( ( 8 * sizeof ( profiler->mean ) ) - 1 ) /* MSB */
		 - 1 /* Leave sign bit unused */
		 - profiler->mean_msb );
}

/**
 * Calculate bit shift for accumulated variance value
 *
 * @v profiler		Profiler
 * @ret shift		Bit shift
 */
static inline unsigned int profile_accvar_shift ( struct profiler *profiler ) {

	return ( ( ( 8 * sizeof ( profiler->accvar ) ) - 1 ) /* MSB */
		 - 1 /* Leave top bit unused */
		 - profiler->accvar_msb );
}

/**
 * Update profiler with a new sample
 *
 * @v profiler		Profiler
 * @v sample		Sample value
 */
void profile_update ( struct profiler *profiler, unsigned long sample ) {
	unsigned int sample_msb;
	unsigned int mean_shift;
	unsigned int delta_shift;
	signed long pre_delta;
	signed long post_delta;
	signed long long accvar_delta;
	unsigned int accvar_delta_shift;
	unsigned int accvar_delta_msb;
	unsigned int accvar_shift;

	/* Our scaling logic assumes that sample values never overflow
	 * a signed long (i.e. that the high bit is always zero).
	 */
	assert ( ( ( signed ) sample ) >= 0 );

	/* Update sample count */
	profiler->count++;

	/* Adjust mean sample value scale if necessary.  Skip if
	 * sample is zero (in which case flsl(sample)-1 would
	 * underflow): in the case of a zero sample we have no need to
	 * adjust the scale anyway.
	 */
	if ( sample ) {
		sample_msb = ( flsl ( sample ) - 1 );
		if ( profiler->mean_msb < sample_msb ) {
			profiler->mean >>= ( sample_msb - profiler->mean_msb );
			profiler->mean_msb = sample_msb;
		}
	}

	/* Scale sample to internal units */
	mean_shift = profile_mean_shift ( profiler );
	sample <<= mean_shift;

	/* Update mean */
	pre_delta = ( sample - profiler->mean );
	profiler->mean += ( pre_delta / ( ( signed ) profiler->count ) );
	post_delta = ( sample - profiler->mean );
	delta_shift = mean_shift;
	DBGC ( profiler, "PROFILER %p sample %#lx mean %s", profiler,
	       ( sample >> mean_shift ),
		profile_hex_fraction ( profiler->mean, mean_shift ) );
	DBGC ( profiler, " pre %s",
	       profile_hex_fraction ( pre_delta, delta_shift ) );
	DBGC ( profiler, " post %s\n",
	       profile_hex_fraction ( post_delta, delta_shift ) );

	/* Scale both deltas to fit in half of an unsigned long long
	 * to avoid potential overflow on multiplication.  Note that
	 * shifting a signed quantity is "implementation-defined"
	 * behaviour in the C standard, but gcc documents that it will
	 * always perform sign extension.
	 */
	if ( sizeof ( pre_delta ) > ( sizeof ( accvar_delta ) / 2 ) ) {
		unsigned int shift = ( 8 * ( sizeof ( pre_delta ) -
					     ( sizeof ( accvar_delta ) / 2 ) ));
		pre_delta >>= shift;
		post_delta >>= shift;
		delta_shift -= shift;
	}

	/* Update variance, if applicable.  Skip if either delta is
	 * zero (in which case flsl(delta)-1 would underflow): in the
	 * case of a zero delta there is no change to the accumulated
	 * variance anyway.
	 */
	if ( pre_delta && post_delta ) {

		/* Calculate variance delta */
		accvar_delta = ( ( ( signed long long ) pre_delta ) *
				 ( ( signed long long ) post_delta ) );
		accvar_delta_shift = ( 2 * delta_shift );
		assert ( accvar_delta > 0 );

		/* Calculate variance delta MSB, using flsl() on each
		 * delta individually to provide an upper bound rather
		 * than requiring the existence of flsll().
		 */
		accvar_delta_msb = ( flsll ( accvar_delta ) - 1 );
		if ( accvar_delta_msb > accvar_delta_shift ) {
			accvar_delta_msb -= accvar_delta_shift;
		} else {
			accvar_delta_msb = 0;
		}

		/* Adjust scales as necessary */
		if ( profiler->accvar_msb < accvar_delta_msb ) {
			/* Rescale accumulated variance */
			profiler->accvar >>= ( accvar_delta_msb -
					       profiler->accvar_msb );
			profiler->accvar_msb = accvar_delta_msb;
		} else {
			/* Rescale variance delta */
			accvar_delta >>= ( profiler->accvar_msb -
					   accvar_delta_msb );
			accvar_delta_shift -= ( profiler->accvar_msb -
						accvar_delta_msb );
		}

		/* Scale delta to internal units */
		accvar_shift = profile_accvar_shift ( profiler );
		accvar_delta <<= ( accvar_shift - accvar_delta_shift );

		/* Accumulate variance */
		profiler->accvar += accvar_delta;

		/* Adjust scale if necessary */
		if ( profiler->accvar &
		     ( 1ULL << ( ( 8 * sizeof ( profiler->accvar ) ) - 1 ) ) ) {
			profiler->accvar >>= 1;
			profiler->accvar_msb++;
			accvar_delta >>= 1;
			accvar_shift--;
		}

		DBGC ( profiler, "PROFILER %p accvar %s", profiler,
		       profile_hex_fraction ( profiler->accvar, accvar_shift ));
		DBGC ( profiler, " delta %s\n",
		       profile_hex_fraction ( accvar_delta, accvar_shift ) );
	}
}

/**
 * Get mean sample value
 *
 * @v profiler		Profiler
 * @ret mean		Mean sample value
 */
unsigned long profile_mean ( struct profiler *profiler ) {
	unsigned int mean_shift = profile_mean_shift ( profiler );

	/* Round to nearest and scale down to original units */
	return ( ( profiler->mean + ( 1UL << ( mean_shift - 1 ) ) )
		 >> mean_shift );
}

/**
 * Get sample variance
 *
 * @v profiler		Profiler
 * @ret variance	Sample variance
 */
unsigned long profile_variance ( struct profiler *profiler ) {
	unsigned int accvar_shift = profile_accvar_shift ( profiler );

	/* Variance is zero if fewer than two samples exist (avoiding
	 * division by zero error).
	 */
	if ( profiler->count < 2 )
		return 0;

	/* Calculate variance, round to nearest, and scale to original units */
	return ( ( ( profiler->accvar / ( profiler->count - 1 ) )
		   + ( 1ULL << ( accvar_shift - 1 ) ) ) >> accvar_shift );
}

/**
 * Get sample standard deviation
 *
 * @v profiler		Profiler
 * @ret stddev		Sample standard deviation
 */
unsigned long profile_stddev ( struct profiler *profiler ) {

	return isqrt ( profile_variance ( profiler ) );
}
