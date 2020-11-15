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
 * SHA-256 family tests
 *
 * NIST test vectors are taken from
 *
 *  http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA256.pdf
 *  http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA224.pdf
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <ipxe/sha256.h>
#include <ipxe/test.h>
#include "digest_test.h"

/* Empty test vector (digest obtained from "sha256sum /dev/null") */
DIGEST_TEST ( sha256_empty, &sha256_algorithm, DIGEST_EMPTY,
	      DIGEST ( 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a,
		       0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae,
		       0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99,
		       0x1b, 0x78, 0x52, 0xb8, 0x55 ) );

/* NIST test vector "abc" */
DIGEST_TEST ( sha256_nist_abc, &sha256_algorithm, DIGEST_NIST_ABC,
	      DIGEST ( 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41,
		       0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03,
		       0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff,
		       0x61, 0xf2, 0x00, 0x15, 0xad ) );

/* NIST test vector "abc...opq" */
DIGEST_TEST ( sha256_nist_abc_opq, &sha256_algorithm, DIGEST_NIST_ABC_OPQ,
	      DIGEST ( 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5,
		       0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c,
		       0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed,
		       0xd4, 0x19, 0xdb, 0x06, 0xc1 ) );

/* Empty test vector (digest obtained from "sha224sum /dev/null") */
DIGEST_TEST ( sha224_empty, &sha224_algorithm, DIGEST_EMPTY,
	      DIGEST ( 0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47,
		       0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4, 0x15, 0xa2,
		       0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4,
		       0x2f ) );

/* NIST test vector "abc" */
DIGEST_TEST ( sha224_nist_abc, &sha224_algorithm, DIGEST_NIST_ABC,
	      DIGEST ( 0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86,
		       0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3, 0x2a, 0xad,
		       0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d,
		       0xa7 ) );

/* NIST test vector "abc...opq" */
DIGEST_TEST ( sha224_nist_abc_opq, &sha224_algorithm, DIGEST_NIST_ABC_OPQ,
	      DIGEST ( 0x75, 0x38, 0x8b, 0x16, 0x51, 0x27, 0x76, 0xcc, 0x5d,
		       0xba, 0x5d, 0xa1, 0xfd, 0x89, 0x01, 0x50, 0xb0, 0xc6,
		       0x45, 0x5c, 0xb4, 0xf5, 0x8b, 0x19, 0x52, 0x52, 0x25,
		       0x25 ) );

/**
 * Perform SHA-256 family self-test
 *
 */
static void sha256_test_exec ( void ) {

	/* Correctness tests */
	digest_ok ( &sha256_empty );
	digest_ok ( &sha256_nist_abc );
	digest_ok ( &sha256_nist_abc_opq );
	digest_ok ( &sha224_empty );
	digest_ok ( &sha224_nist_abc );
	digest_ok ( &sha224_nist_abc_opq );

	/* Speed tests */
	DBG ( "SHA256 required %ld cycles per byte\n",
	      digest_cost ( &sha256_algorithm ) );
	DBG ( "SHA224 required %ld cycles per byte\n",
	      digest_cost ( &sha224_algorithm ) );
}

/** SHA-256 family self-test */
struct self_test sha256_test __self_test = {
	.name = "sha256",
	.exec = sha256_test_exec,
};
