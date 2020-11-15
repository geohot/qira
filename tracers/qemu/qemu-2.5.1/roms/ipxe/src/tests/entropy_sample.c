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
 * Entropy sampling
 *
 */

#include <stdio.h>
#include <ipxe/entropy.h>
#include <ipxe/test.h>

/** Total number of test samples */
#define SAMPLE_COUNT 65536

/** Number of samples per block */
#define SAMPLE_BLOCKSIZE 256

/**
 * Generate entropy samples for external testing
 *
 */
static void entropy_sample_test_exec ( void ) {
	static noise_sample_t samples[SAMPLE_BLOCKSIZE];
	unsigned int i;
	unsigned int j;
	int rc;

	/* Collect and print blocks of samples */
	for ( i = 0 ; i < ( SAMPLE_COUNT / SAMPLE_BLOCKSIZE ) ; i++ ) {

		/* Collect one block of samples */
		rc = entropy_enable();
		ok ( rc == 0 );
		for ( j = 0 ; j < SAMPLE_BLOCKSIZE ; j++ ) {
			rc = get_noise ( &samples[j] );
			ok ( rc == 0 );
		}
		entropy_disable();

		/* Print out sample values */
		for ( j = 0 ; j < SAMPLE_BLOCKSIZE ; j++ ) {
			printf ( "SAMPLE %d %d\n", ( i * SAMPLE_BLOCKSIZE + j ),
				 samples[j] );
		}
	}
}

/** Entropy sampling self-test */
struct self_test entropy_sample_test __self_test = {
	.name = "entropy_sample",
	.exec = entropy_sample_test_exec,
};
