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
 * SHA-224 algorithm
 *
 */

#include <stdint.h>
#include <byteswap.h>
#include <ipxe/crypto.h>
#include <ipxe/asn1.h>
#include <ipxe/sha256.h>

/** SHA-224 initial digest values */
static const struct sha256_digest sha224_init_digest = {
	.h = {
		cpu_to_be32 ( 0xc1059ed8 ),
		cpu_to_be32 ( 0x367cd507 ),
		cpu_to_be32 ( 0x3070dd17 ),
		cpu_to_be32 ( 0xf70e5939 ),
		cpu_to_be32 ( 0xffc00b31 ),
		cpu_to_be32 ( 0x68581511 ),
		cpu_to_be32 ( 0x64f98fa7 ),
		cpu_to_be32 ( 0xbefa4fa4 ),
	},
};

/**
 * Initialise SHA-224 algorithm
 *
 * @v ctx		SHA-224 context
 */
static void sha224_init ( void *ctx ) {
	struct sha256_context *context = ctx;

	sha256_family_init ( context, &sha224_init_digest, SHA224_DIGEST_SIZE );
}

/** SHA-224 algorithm */
struct digest_algorithm sha224_algorithm = {
	.name		= "sha224",
	.ctxsize	= sizeof ( struct sha256_context ),
	.blocksize	= sizeof ( union sha256_block ),
	.digestsize	= SHA224_DIGEST_SIZE,
	.init		= sha224_init,
	.update		= sha256_update,
	.final		= sha256_final,
};

/** "sha224" object identifier */
static uint8_t oid_sha224[] = { ASN1_OID_SHA224 };

/** "sha224" OID-identified algorithm */
struct asn1_algorithm oid_sha224_algorithm __asn1_algorithm = {
	.name = "sha224",
	.digest = &sha224_algorithm,
	.oid = ASN1_OID_CURSOR ( oid_sha224 ),
};
