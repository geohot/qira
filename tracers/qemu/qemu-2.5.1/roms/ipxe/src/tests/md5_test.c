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
 * MD5 tests
 *
 * Test inputs borrowed from NIST SHA-1 tests, with results calculated
 * using md5sum.
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <ipxe/md5.h>
#include <ipxe/test.h>
#include "digest_test.h"

/* Empty test vector (digest obtained from "md5sum /dev/null") */
DIGEST_TEST ( md5_empty, &md5_algorithm, DIGEST_EMPTY,
	      DIGEST ( 0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9,
		       0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e ) );

/* NIST test vector "abc" (digest obtained from "md5sum <data>") */
DIGEST_TEST ( md5_nist_abc, &md5_algorithm, DIGEST_NIST_ABC,
	      DIGEST ( 0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6,
		       0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72 ) );

/* NIST test vector "abc...opq" (digest obtained from "md5sum <data>") */
DIGEST_TEST ( md5_nist_abc_opq, &md5_algorithm, DIGEST_NIST_ABC_OPQ,
	      DIGEST ( 0x82, 0x15, 0xef, 0x07, 0x96, 0xa2, 0x0b, 0xca, 0xaa,
		       0xe1, 0x16, 0xd3, 0x87, 0x6c, 0x66, 0x4a ) );

/**
 * Perform MD5 self-test
 *
 */
static void md5_test_exec ( void ) {

	/* Correctness tests */
	digest_ok ( &md5_empty );
	digest_ok ( &md5_nist_abc );
	digest_ok ( &md5_nist_abc_opq );

	/* Speed tests */
	DBG ( "MD5 required %ld cycles per byte\n",
	      digest_cost ( &md5_algorithm ) );
}

/** MD5 self-test */
struct self_test md5_test __self_test = {
	.name = "md5",
	.exec = md5_test_exec,
};
