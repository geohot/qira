#ifndef _TIME_H
#define _TIME_H

/** @file
 *
 * Date and time
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <sys/time.h>
#include <ipxe/time.h>

/** Broken-down time */
struct tm {
	/** Seconds [0,60] */
	int tm_sec;
	/** Minutes [0,59] */
	int tm_min;
	/** Hour [0,23] */
	int tm_hour;
	/** Day of month [1,31] */
	int tm_mday;
	/** Month of year [0,11] */
	int tm_mon;
	/** Years since 1900 */
	int tm_year;
	/** Day of week [0,6] (Sunday=0) */
	int tm_wday;
	/** Day of year [0,365] */
	int tm_yday;
	/** Daylight savings flag */
	int tm_isdst;
};

/**
 * Get current time in seconds since the Epoch
 *
 * @v t			Time to fill in, or NULL
 * @ret time		Current time
 */
static inline time_t time ( time_t *t ) {
	time_t now;

	now = time_now();
	if ( t )
		*t = now;
	return now;
}

extern time_t mktime ( struct tm *tm );

#endif /* _TIME_H */
