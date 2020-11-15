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
 * SHA-1 tests
 *
 * NIST test vectors are taken from
 *
 *  http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA1.pdf
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <ipxe/sha1.h>
#include <ipxe/test.h>
#include "digest_test.h"

/* Empty test vector (digest obtained from "sha1sum /dev/null") */
DIGEST_TEST ( sha1_empty, &sha1_algorithm, DIGEST_EMPTY,
	      DIGEST ( 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32,
		       0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8,
		       0x07, 0x09 ) );

/* NIST test vector "abc" */
DIGEST_TEST ( sha1_nist_abc, &sha1_algorithm, DIGEST_NIST_ABC,
	      DIGEST ( 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba,
		       0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0,
		       0xd8, 0x9d ) );

/* NIST test vector "abc...opq" */
DIGEST_TEST ( sha1_nist_abc_opq, &sha1_algorithm, DIGEST_NIST_ABC_OPQ,
	      DIGEST ( 0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba,
		       0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46,
		       0x70, 0xf1 ) );

/**
 * Perform SHA-1 self-test
 *
 */
static void sha1_test_exec ( void ) {

	/* Correctness tests */
	digest_ok ( &sha1_empty );
	digest_ok ( &sha1_nist_abc );
	digest_ok ( &sha1_nist_abc_opq );

	/* Speed tests */
	DBG ( "SHA1 required %ld cycles per byte\n",
	      digest_cost ( &sha1_algorithm ) );
}

/** SHA-1 self-test */
struct self_test sha1_test __self_test = {
	.name = "sha1",
	.exec = sha1_test_exec,
};
