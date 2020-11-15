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
 * RTC-based time source
 *
 */

#include <stdint.h>
#include <time.h>
#include <rtc.h>
#include <ipxe/time.h>

/**
 * Read RTC register
 *
 * @v address		Register address
 * @ret data		Data
 */
static unsigned int rtc_readb ( int address ) {
	outb ( address, CMOS_ADDRESS );
	return inb ( CMOS_DATA );
}

/**
 * Check if RTC update is in progress
 *
 * @ret is_busy		RTC update is in progress
 */
static int rtc_is_busy ( void ) {
	return ( rtc_readb ( RTC_STATUS_A ) & RTC_STATUS_A_UPDATE_IN_PROGRESS );
}

/**
 * Read RTC BCD register
 *
 * @v address		Register address
 * @ret value		Value
 */
static unsigned int rtc_readb_bcd ( int address ) {
	unsigned int bcd;

	bcd = rtc_readb ( address );
	return ( bcd - ( 6 * ( bcd >> 4 ) ) );
}

/**
 * Read RTC time
 *
 * @ret time		Time, in seconds
 */
static time_t rtc_read_time ( void ) {
	unsigned int status_b;
	int is_binary;
	int is_24hour;
	unsigned int ( * read_component ) ( int address );
	struct tm tm;
	int is_pm;
	unsigned int hour;
	time_t time;

	/* Wait for any in-progress update to complete */
	while ( rtc_is_busy() ) {}

	/* Determine RTC mode */
	status_b = rtc_readb ( RTC_STATUS_B );
	is_binary = ( status_b & RTC_STATUS_B_BINARY );
	is_24hour = ( status_b & RTC_STATUS_B_24_HOUR );
	read_component = ( is_binary ? rtc_readb : rtc_readb_bcd );

	/* Read time values */
	tm.tm_sec = read_component ( RTC_SEC );
	tm.tm_min = read_component ( RTC_MIN );
	hour = read_component ( RTC_HOUR );
	if ( ! is_24hour ) {
		is_pm = ( hour >= 80 );
		hour = ( ( ( ( hour & 0x7f ) % 80 ) % 12 ) +
			 ( is_pm ? 12 : 0 ) );
	}
	tm.tm_hour = hour;
	tm.tm_mday = read_component ( RTC_MDAY );
	tm.tm_mon = ( read_component ( RTC_MON ) - 1 );
	tm.tm_year = ( read_component ( RTC_YEAR ) +
		       100 /* Assume we are in the 21st century, since
			    * this code was written in 2012 */ );

	DBGC ( RTC_STATUS_A, "RTCTIME is %04d-%02d-%02d %02d:%02d:%02d "
	       "(%s,%d-hour)\n", ( tm.tm_year + 1900 ), ( tm.tm_mon + 1 ),
	       tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
	       ( is_binary ? "binary" : "BCD" ), ( is_24hour ? 24 : 12 ) );

	/* Convert to seconds since the Epoch */
	time = mktime ( &tm );

	return time;
}

/**
 * Get current time in seconds
 *
 * @ret time		Time, in seconds
 */
static time_t rtc_now ( void ) {
	time_t time = 0;
	time_t last_time;

	/* Read time until we get two matching values in a row, in
	 * case we end up reading a corrupted value in the middle of
	 * an update.
	 */
	do {
		last_time = time;
		time = rtc_read_time();
	} while ( time != last_time );

	return time;
}

PROVIDE_TIME ( rtc, time_now, rtc_now );
