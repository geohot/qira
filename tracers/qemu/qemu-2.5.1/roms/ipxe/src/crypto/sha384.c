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
 * SHA-384 algorithm
 *
 */

#include <stdint.h>
#include <byteswap.h>
#include <ipxe/crypto.h>
#include <ipxe/asn1.h>
#include <ipxe/sha512.h>

/** SHA-384 initial digest values */
static const struct sha512_digest sha384_init_digest = {
	.h = {
		cpu_to_be64 ( 0xcbbb9d5dc1059ed8ULL ),
		cpu_to_be64 ( 0x629a292a367cd507ULL ),
		cpu_to_be64 ( 0x9159015a3070dd17ULL ),
		cpu_to_be64 ( 0x152fecd8f70e5939ULL ),
		cpu_to_be64 ( 0x67332667ffc00b31ULL ),
		cpu_to_be64 ( 0x8eb44a8768581511ULL ),
		cpu_to_be64 ( 0xdb0c2e0d64f98fa7ULL ),
		cpu_to_be64 ( 0x47b5481dbefa4fa4ULL ),
	},
};

/**
 * Initialise SHA-384 algorithm
 *
 * @v ctx		SHA-384 context
 */
static void sha384_init ( void *ctx ) {
	struct sha512_context *context = ctx;

	sha512_family_init ( context, &sha384_init_digest, SHA384_DIGEST_SIZE );
}

/** SHA-384 algorithm */
struct digest_algorithm sha384_algorithm = {
	.name		= "sha384",
	.ctxsize	= sizeof ( struct sha512_context ),
	.blocksize	= sizeof ( union sha512_block ),
	.digestsize	= SHA384_DIGEST_SIZE,
	.init		= sha384_init,
	.update		= sha512_update,
	.final		= sha512_final,
};

/** "sha384" object identifier */
static uint8_t oid_sha384[] = { ASN1_OID_SHA384 };

/** "sha384" OID-identified algorithm */
struct asn1_algorithm oid_sha384_algorithm __asn1_algorithm = {
	.name = "sha384",
	.digest = &sha384_algorithm,
	.oid = ASN1_OID_CURSOR ( oid_sha384 ),
};
