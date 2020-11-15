/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

#include <ipxe/rsa.h>
#include <ipxe/sha512.h>
#include <ipxe/asn1.h>
#include <ipxe/tls.h>

/** "sha384WithRSAEncryption" object identifier */
static uint8_t oid_sha384_with_rsa_encryption[] =
	{ ASN1_OID_SHA384WITHRSAENCRYPTION };

/** "sha384WithRSAEncryption" OID-identified algorithm */
struct asn1_algorithm sha384_with_rsa_encryption_algorithm __asn1_algorithm = {
	.name = "sha384WithRSAEncryption",
	.pubkey = &rsa_algorithm,
	.digest = &sha384_algorithm,
	.oid = ASN1_OID_CURSOR ( oid_sha384_with_rsa_encryption ),
};

/** SHA-384 digestInfo prefix */
static const uint8_t rsa_sha384_prefix_data[] =
	{ RSA_DIGESTINFO_PREFIX ( SHA384_DIGEST_SIZE, ASN1_OID_SHA384 ) };

/** SHA-384 digestInfo prefix */
struct rsa_digestinfo_prefix rsa_sha384_prefix __rsa_digestinfo_prefix = {
	.digest = &sha384_algorithm,
	.data = rsa_sha384_prefix_data,
	.len = sizeof ( rsa_sha384_prefix_data ),
};

/** RSA with SHA-384 signature hash algorithm */
struct tls_signature_hash_algorithm tls_rsa_sha384 __tls_sig_hash_algorithm = {
	.code = {
		.signature = TLS_RSA_ALGORITHM,
		.hash = TLS_SHA384_ALGORITHM,
	},
	.pubkey = &rsa_algorithm,
	.digest = &sha384_algorithm,
};
