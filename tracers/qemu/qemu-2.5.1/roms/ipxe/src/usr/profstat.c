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

#include <stdio.h>
#include <ipxe/profile.h>
#include <usr/profstat.h>

/** @file
 *
 * Profiling
 *
 */

/**
 * Print profiling statistics
 *
 */
void profstat ( void ) {
	struct profiler *profiler;

	for_each_table_entry ( profiler, PROFILERS ) {
		printf ( "%s: %ld +/- %ld ticks (%d samples)\n",
			 profiler->name, profile_mean ( profiler ),
			 profile_stddev ( profiler ), profiler->count );
	}
}
