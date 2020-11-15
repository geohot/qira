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
 * SHA-512/224 algorithm
 *
 */

#include <stdint.h>
#include <byteswap.h>
#include <ipxe/crypto.h>
#include <ipxe/asn1.h>
#include <ipxe/sha512.h>

/** SHA-512/224 initial digest values */
static const struct sha512_digest sha512_224_init_digest = {
	.h = {
		cpu_to_be64 ( 0x8c3d37c819544da2ULL ),
		cpu_to_be64 ( 0x73e1996689dcd4d6ULL ),
		cpu_to_be64 ( 0x1dfab7ae32ff9c82ULL ),
		cpu_to_be64 ( 0x679dd514582f9fcfULL ),
		cpu_to_be64 ( 0x0f6d2b697bd44da8ULL ),
		cpu_to_be64 ( 0x77e36f7304c48942ULL ),
		cpu_to_be64 ( 0x3f9d85a86a1d36c8ULL ),
		cpu_to_be64 ( 0x1112e6ad91d692a1ULL ),
	},
};

/**
 * Initialise SHA-512/224 algorithm
 *
 * @v ctx		SHA-512/224 context
 */
static void sha512_224_init ( void *ctx ) {
	struct sha512_context *context = ctx;

	sha512_family_init ( context, &sha512_224_init_digest,
			     SHA512_224_DIGEST_SIZE );
}

/** SHA-512/224 algorithm */
struct digest_algorithm sha512_224_algorithm = {
	.name		= "sha512/224",
	.ctxsize	= sizeof ( struct sha512_context ),
	.blocksize	= sizeof ( union sha512_block ),
	.digestsize	= SHA512_224_DIGEST_SIZE,
	.init		= sha512_224_init,
	.update		= sha512_update,
	.final		= sha512_final,
};

/** "sha512_224" object identifier */
static uint8_t oid_sha512_224[] = { ASN1_OID_SHA512_224 };

/** "sha512_224" OID-identified algorithm */
struct asn1_algorithm oid_sha512_224_algorithm __asn1_algorithm = {
	.name = "sha512/224",
	.digest = &sha512_224_algorithm,
	.oid = ASN1_OID_CURSOR ( oid_sha512_224 ),
};
