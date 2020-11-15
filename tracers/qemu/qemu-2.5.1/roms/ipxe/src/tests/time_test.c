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
 * Date and time self-tests
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <time.h>
#include <ipxe/test.h>

/** A mktime() test */
struct mktime_test {
	/** Broken-down time */
	struct tm tm;
	/** Day of the week */
	int wday;
	/** Day of the year */
	int yday;
	/** Seconds since the Epoch */
	time_t time;
};

/**
 * Define a mktime() test
 *
 * @v name		Test name
 * @v SEC		Seconds [0,60]
 * @v MIN		Minutes [0,59]
 * @v HOUR		Hour [0,23]
 * @v MDAY		Day of month [1,31]
 * @v MON		Month of year [0,11]
 * @v YEAR		Years since 1900
 * @v WDAY		Day of week [0,6] (Sunday=0)
 * @v YDAY		Day of year [0,365]
 * @v ISDST		Daylight savings flag (ignored)
 * @v TIME		Seconds since the Epoch
 * @ret test		mktime() test
 *
 * This macro is designed to make it easy to generate test vectors in
 * Perl using
 *
 *    print join ", ", gmtime ( $time ), $time."ULL";
 *
 */
#define MKTIME_TEST( name, SEC, MIN, HOUR, MDAY, MON, YEAR, WDAY,	\
		     YDAY, ISDST, TIME )				\
	static struct mktime_test name = {				\
		.tm = {							\
			.tm_sec = SEC,					\
			.tm_min = MIN,					\
			.tm_hour = HOUR,				\
			.tm_mday = MDAY,				\
			.tm_mon = MON,					\
			.tm_year = YEAR,				\
			.tm_isdst = ISDST,				\
		},							\
		.wday = WDAY,						\
		.yday = YDAY,						\
		.time = TIME,						\
	}

/**
 * Report mktime() test result
 *
 * @v test		mktime() test
 */
#define mktime_ok( test ) do {						\
	time_t time = mktime ( &(test)->tm );				\
	ok ( time == (test)->time );					\
	ok ( (test)->tm.tm_wday == (test)->wday );			\
	ok ( (test)->tm.tm_yday == (test)->yday );			\
	} while ( 0 )

/* Start of the Epoch */
MKTIME_TEST ( mktime_epoch, 00, 00, 00, 01, 00, 70, 4, 0, 0, 0 );

/* Birth of iPXE as a new project */
MKTIME_TEST ( mktime_ipxe, 01, 15, 20, 19, 03, 110, 1, 108, 0, 1271708101ULL );

/* Random test vectors generated using Perl's gmtime() */
MKTIME_TEST ( mktime_0, 4, 17, 20, 1, 0, 150, 6, 0, 0, 2524681024ULL );
MKTIME_TEST ( mktime_1, 22, 47, 21, 27, 11, 77, 2, 360, 0, 252107242ULL );
MKTIME_TEST ( mktime_2, 26, 10, 0, 7, 2, 196, 3, 66, 0, 3981917426ULL );
MKTIME_TEST ( mktime_3, 44, 44, 23, 15, 9, 261, 4, 287, 0, 6052319084ULL );
MKTIME_TEST ( mktime_4, 3, 22, 18, 8, 9, 296, 6, 281, 0, 7156232523ULL );
MKTIME_TEST ( mktime_5, 27, 26, 16, 18, 11, 338, 2, 351, 0, 8487649587ULL );
MKTIME_TEST ( mktime_6, 31, 36, 22, 3, 3, 293, 3, 92, 0, 7045310191ULL );
MKTIME_TEST ( mktime_7, 2, 0, 6, 25, 5, 289, 4, 175, 0, 6926191202ULL );
MKTIME_TEST ( mktime_8, 43, 50, 1, 8, 0, 210, 3, 7, 0, 4418589043ULL );
MKTIME_TEST ( mktime_9, 48, 14, 20, 23, 3, 86, 3, 112, 0, 514671288ULL );
MKTIME_TEST ( mktime_10, 4, 43, 5, 29, 11, 173, 5, 362, 0, 3281751784ULL );
MKTIME_TEST ( mktime_11, 47, 26, 21, 12, 7, 177, 4, 223, 0, 3396029207ULL );
MKTIME_TEST ( mktime_12, 18, 55, 20, 26, 11, 88, 1, 360, 0, 599172918ULL );
MKTIME_TEST ( mktime_13, 8, 32, 13, 15, 7, 314, 1, 226, 0, 7719456728ULL );
MKTIME_TEST ( mktime_14, 0, 16, 11, 20, 6, 138, 2, 200, 0, 2163237360ULL );
MKTIME_TEST ( mktime_15, 48, 0, 9, 31, 2, 202, 5, 89, 0, 4173238848ULL );
MKTIME_TEST ( mktime_16, 51, 55, 0, 15, 1, 323, 6, 45, 0, 7987769751ULL );
MKTIME_TEST ( mktime_17, 36, 10, 7, 11, 5, 301, 4, 161, 0, 7303590636ULL );
MKTIME_TEST ( mktime_18, 22, 39, 11, 21, 9, 233, 3, 293, 0, 5169181162ULL );
MKTIME_TEST ( mktime_19, 48, 29, 8, 31, 7, 207, 3, 242, 0, 4344222588ULL );
MKTIME_TEST ( mktime_20, 4, 53, 22, 8, 8, 165, 2, 250, 0, 3019675984ULL );
MKTIME_TEST ( mktime_21, 14, 16, 8, 10, 5, 298, 0, 160, 0, 7208900174ULL );
MKTIME_TEST ( mktime_22, 10, 35, 3, 12, 3, 188, 1, 102, 0, 3732579310ULL );
MKTIME_TEST ( mktime_23, 47, 12, 18, 22, 2, 103, 6, 80, 0, 1048356767ULL );
MKTIME_TEST ( mktime_24, 23, 29, 17, 23, 10, 201, 3, 326, 0, 4162210163ULL );
MKTIME_TEST ( mktime_25, 58, 35, 23, 24, 3, 111, 0, 113, 0, 1303688158ULL );
MKTIME_TEST ( mktime_26, 34, 56, 15, 24, 11, 154, 4, 357, 0, 2681740594ULL );
MKTIME_TEST ( mktime_27, 7, 11, 22, 28, 1, 243, 4, 58, 0, 5464447867ULL );
MKTIME_TEST ( mktime_28, 25, 45, 23, 29, 11, 90, 6, 362, 0, 662514325ULL );
MKTIME_TEST ( mktime_29, 31, 20, 12, 24, 1, 146, 6, 54, 0, 2403087631ULL );
MKTIME_TEST ( mktime_30, 49, 7, 18, 16, 10, 271, 6, 319, 0, 6370596469ULL );
MKTIME_TEST ( mktime_31, 31, 55, 2, 25, 5, 141, 2, 175, 0, 2255741731ULL );

/**
 * Perform date and time self-tests
 *
 */
static void time_test_exec ( void ) {

	mktime_ok ( &mktime_epoch );
	mktime_ok ( &mktime_ipxe );
	mktime_ok ( &mktime_0 );
	mktime_ok ( &mktime_1 );
	mktime_ok ( &mktime_2 );
	mktime_ok ( &mktime_3 );
	mktime_ok ( &mktime_4 );
	mktime_ok ( &mktime_5 );
	mktime_ok ( &mktime_6 );
	mktime_ok ( &mktime_7 );
	mktime_ok ( &mktime_8 );
	mktime_ok ( &mktime_9 );
	mktime_ok ( &mktime_10 );
	mktime_ok ( &mktime_11 );
	mktime_ok ( &mktime_12 );
	mktime_ok ( &mktime_13 );
	mktime_ok ( &mktime_14 );
	mktime_ok ( &mktime_15 );
	mktime_ok ( &mktime_16 );
	mktime_ok ( &mktime_17 );
	mktime_ok ( &mktime_18 );
	mktime_ok ( &mktime_19 );
	mktime_ok ( &mktime_20 );
	mktime_ok ( &mktime_21 );
	mktime_ok ( &mktime_22 );
	mktime_ok ( &mktime_23 );
	mktime_ok ( &mktime_24 );
	mktime_ok ( &mktime_25 );
	mktime_ok ( &mktime_26 );
	mktime_ok ( &mktime_27 );
	mktime_ok ( &mktime_28 );
	mktime_ok ( &mktime_29 );
	mktime_ok ( &mktime_30 );
	mktime_ok ( &mktime_31 );
}

/** Date and time self-test */
struct self_test time_test __self_test = {
	.name = "time",
	.exec = time_test_exec,
};
