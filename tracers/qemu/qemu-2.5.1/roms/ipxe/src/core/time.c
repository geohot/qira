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

#include <time.h>

/** @file
 *
 * Date and time
 *
 * POSIX:2008 section 4.15 defines "seconds since the Epoch" as an
 * abstract measure approximating the number of seconds that have
 * elapsed since the Epoch, excluding leap seconds.  The formula given
 * is
 *
 *    tm_sec + tm_min*60 + tm_hour*3600 + tm_yday*86400 +
 *    (tm_year-70)*31536000 + ((tm_year-69)/4)*86400 -
 *    ((tm_year-1)/100)*86400 + ((tm_year+299)/400)*86400
 *
 * This calculation assumes that leap years occur in each year that is
 * either divisible by 4 but not divisible by 100, or is divisible by
 * 400.
 */

/** Days of week (for debugging) */
static const char *weekdays[] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

/**
 * Determine whether or not year is a leap year
 *
 * @v tm_year		Years since 1900
 * @v is_leap_year	Year is a leap year
 */
static int is_leap_year ( int tm_year ) {
	int leap_year = 0;

	if ( ( tm_year % 4 ) == 0 )
		leap_year = 1;
	if ( ( tm_year % 100 ) == 0 )
		leap_year = 0;
	if ( ( tm_year % 400 ) == 100 )
		leap_year = 1;

	return leap_year;
}

/**
 * Calculate number of leap years since 1900
 *
 * @v tm_year		Years since 1900
 * @v num_leap_years	Number of leap years
 */
static int leap_years_to_end ( int tm_year ) {
	int leap_years = 0;

	leap_years += ( tm_year / 4 );
	leap_years -= ( tm_year / 100 );
	leap_years += ( ( tm_year + 300 ) / 400 );

	return leap_years;
}

/**
 * Calculate day of week
 *
 * @v tm_year		Years since 1900
 * @v tm_mon		Month of year [0,11]
 * @v tm_day		Day of month [1,31]
 */
static int day_of_week ( int tm_year, int tm_mon, int tm_mday ) {
	static const uint8_t offset[12] =
		{ 1, 4, 3, 6, 1, 4, 6, 2, 5, 0, 3, 5 };
	int pseudo_year = tm_year;

	if ( tm_mon < 2 )
		pseudo_year--;
	return ( ( pseudo_year + leap_years_to_end ( pseudo_year ) +
		   offset[tm_mon] + tm_mday ) % 7 );
}

/** Days from start of year until start of months (in non-leap years) */
static const uint16_t days_to_month_start[] =
	{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

/**
 * Calculate seconds since the Epoch
 *
 * @v tm		Broken-down time
 * @ret time		Seconds since the Epoch
 */
time_t mktime ( struct tm *tm ) {
	int days_since_epoch;
	int seconds_since_day;
	time_t seconds;

	/* Calculate day of year */
	tm->tm_yday = ( ( tm->tm_mday - 1 ) +
			days_to_month_start[ tm->tm_mon ] );
	if ( ( tm->tm_mon >= 2 ) && is_leap_year ( tm->tm_year ) )
		tm->tm_yday++;

	/* Calculate day of week */
	tm->tm_wday = day_of_week ( tm->tm_year, tm->tm_mon, tm->tm_mday );

	/* Calculate seconds since the Epoch */
	days_since_epoch = ( tm->tm_yday + ( 365 * tm->tm_year ) - 25567 +
			     leap_years_to_end ( tm->tm_year - 1 ) );
	seconds_since_day =
		( ( ( ( tm->tm_hour * 60 ) + tm->tm_min ) * 60 ) + tm->tm_sec );
	seconds = ( ( ( ( time_t ) days_since_epoch ) * ( ( time_t ) 86400 ) ) +
		    seconds_since_day );

	DBGC ( &weekdays, "TIME %04d-%02d-%02d %02d:%02d:%02d => %lld (%s, "
	       "day %d)\n", ( tm->tm_year + 1900 ), ( tm->tm_mon + 1 ),
	       tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, seconds,
	       weekdays[ tm->tm_wday ], tm->tm_yday );

	return seconds;
}
