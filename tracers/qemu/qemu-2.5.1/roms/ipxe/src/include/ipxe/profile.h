#ifndef _IPXE_PROFILE_H
#define _IPXE_PROFILE_H

/** @file
 *
 * Profiling
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <bits/profile.h>
#include <ipxe/tables.h>

#ifdef NDEBUG
#define PROFILING 0
#else
#define PROFILING 1
#endif

/**
 * A data structure for storing profiling information
 */
struct profiler {
	/** Name */
	const char *name;
	/** Start timestamp */
	unsigned long started;
	/** Stop timestamp */
	unsigned long stopped;
	/** Number of samples */
	unsigned int count;
	/** Mean sample value (scaled) */
	unsigned long mean;
	/** Mean sample value MSB
	 *
	 * This is the highest bit set in the raw (unscaled) value
	 * (i.e. one less than would be returned by flsl(raw_mean)).
	 */
	unsigned int mean_msb;
	/** Accumulated variance (scaled) */
	unsigned long long accvar;
	/** Accumulated variance MSB
	 *
	 * This is the highest bit set in the raw (unscaled) value
	 * (i.e. one less than would be returned by flsll(raw_accvar)).
	 */
	unsigned int accvar_msb;
};

/** Profiler table */
#define PROFILERS __table ( struct profiler, "profilers" )

/** Declare a profiler */
#if PROFILING
#define __profiler __table_entry ( PROFILERS, 01 )
#else
#define __profiler
#endif

extern unsigned long profile_excluded;

extern void profile_update ( struct profiler *profiler, unsigned long sample );
extern unsigned long profile_mean ( struct profiler *profiler );
extern unsigned long profile_variance ( struct profiler *profiler );
extern unsigned long profile_stddev ( struct profiler *profiler );

/**
 * Get start time
 *
 * @v profiler		Profiler
 * @ret started		Start time
 */
static inline __attribute__ (( always_inline )) unsigned long
profile_started ( struct profiler *profiler ) {

	/* If profiling is active then return start time */
	if ( PROFILING ) {
		return ( profiler->started + profile_excluded );
	} else {
		return 0;
	}
}

/**
 * Get stop time
 *
 * @v profiler		Profiler
 * @ret stopped		Stop time
 */
static inline __attribute__ (( always_inline )) unsigned long
profile_stopped ( struct profiler *profiler ) {

	/* If profiling is active then return start time */
	if ( PROFILING ) {
		return ( profiler->stopped + profile_excluded );
	} else {
		return 0;
	}
}

/**
 * Get elapsed time
 *
 * @v profiler		Profiler
 * @ret elapsed		Elapsed time
 */
static inline __attribute__ (( always_inline )) unsigned long
profile_elapsed ( struct profiler *profiler ) {

	/* If profiling is active then return elapsed time */
	if ( PROFILING ) {
		return ( profile_stopped ( profiler ) -
			 profile_started ( profiler ) );
	} else {
		return 0;
	}
}

/**
 * Start profiling
 *
 * @v profiler		Profiler
 * @v started		Start timestamp
 */
static inline __attribute__ (( always_inline )) void
profile_start_at ( struct profiler *profiler, unsigned long started ) {

	/* If profiling is active then record start timestamp */
	if ( PROFILING )
		profiler->started = ( started - profile_excluded );
}

/**
 * Stop profiling
 *
 * @v profiler		Profiler
 * @v stopped		Stop timestamp
 */
static inline __attribute__ (( always_inline )) void
profile_stop_at ( struct profiler *profiler, unsigned long stopped ) {

	/* If profiling is active then record end timestamp and update stats */
	if ( PROFILING ) {
		profiler->stopped = ( stopped - profile_excluded );
		profile_update ( profiler, profile_elapsed ( profiler ) );
	}
}

/**
 * Start profiling
 *
 * @v profiler		Profiler
 */
static inline __attribute__ (( always_inline )) void
profile_start ( struct profiler *profiler ) {

	/* If profiling is active then record start timestamp */
	if ( PROFILING )
		profile_start_at ( profiler, profile_timestamp() );
}

/**
 * Stop profiling
 *
 * @v profiler		Profiler
 */
static inline __attribute__ (( always_inline )) void
profile_stop ( struct profiler *profiler ) {

	/* If profiling is active then record end timestamp and update stats */
	if ( PROFILING )
		profile_stop_at ( profiler, profile_timestamp() );
}

/**
 * Exclude time from other ongoing profiling results
 *
 * @v profiler		Profiler
 */
static inline __attribute__ (( always_inline )) void
profile_exclude ( struct profiler *profiler ) {

	/* If profiling is active then update accumulated excluded time */
	if ( PROFILING )
		profile_excluded += profile_elapsed ( profiler );
}

/**
 * Record profiling sample in custom units
 *
 * @v profiler		Profiler
 * @v sample		Profiling sample
 */
static inline __attribute__ (( always_inline )) void
profile_custom ( struct profiler *profiler, unsigned long sample ) {

	/* If profiling is active then update stats */
	if ( PROFILING )
		profile_update ( profiler, sample );
}

#endif /* _IPXE_PROFILE_H */
