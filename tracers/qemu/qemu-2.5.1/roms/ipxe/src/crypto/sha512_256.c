/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
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
 * SHA-512/256 algorithm
 *
 */

#include <stdint.h>
#include <byteswap.h>
#include <ipxe/crypto.h>
#include <ipxe/asn1.h>
#include <ipxe/sha512.h>

/** SHA-512/256 initial digest values */
static const struct sha512_digest sha512_256_init_digest = {
	.h = {
		cpu_to_be64 ( 0x22312194fc2bf72cULL ),
		cpu_to_be64 ( 0x9f555fa3c84c64c2ULL ),
		cpu_to_be64 ( 0x2393b86b6f53b151ULL ),
		cpu_to_be64 ( 0x963877195940eabdULL ),
		cpu_to_be64 ( 0x96283ee2a88effe3ULL ),
		cpu_to_be64 ( 0xbe5e1e2553863992ULL ),
		cpu_to_be64 ( 0x2b0199fc2c85b8aaULL ),
		cpu_to_be64 ( 0x0eb72ddc81c52ca2ULL ),
	},
};

/**
 * Initialise SHA-512/256 algorithm
 *
 * @v ctx		SHA-512/256 context
 */
static void sha512_256_init ( void *ctx ) {
	struct sha512_context *context = ctx;

	sha512_family_init ( context, &sha512_256_init_digest,
			     SHA512_256_DIGEST_SIZE );
}

/** SHA-512/256 algorithm */
struct digest_algorithm sha512_256_algorithm = {
	.name		= "sha512/256",
	.ctxsize	= sizeof ( struct sha512_context ),
	.blocksize	= sizeof ( union sha512_block ),
	.digestsize	= SHA512_256_DIGEST_SIZE,
	.init		= sha512_256_init,
	.update		= sha512_update,
	.final		= sha512_final,
};

/** "sha512_256" object identifier */
static uint8_t oid_sha512_256[] = { ASN1_OID_SHA512_256 };

/** "sha512_256" OID-identified algorithm */
struct asn1_algorithm oid_sha512_256_algorithm __asn1_algorithm = {
	.name = "sha512/256",
	.digest = &sha512_256_algorithm,
	.oid = ASN1_OID_CURSOR ( oid_sha512_256 ),
};
