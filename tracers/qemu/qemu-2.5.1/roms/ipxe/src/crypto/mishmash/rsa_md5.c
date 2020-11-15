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
#include <ipxe/md5.h>
#include <ipxe/asn1.h>

/** "md5WithRSAEncryption" object identifier */
static uint8_t oid_md5_with_rsa_encryption[] =
	{ ASN1_OID_MD5WITHRSAENCRYPTION };

/** "md5WithRSAEncryption" OID-identified algorithm */
struct asn1_algorithm md5_with_rsa_encryption_algorithm __asn1_algorithm = {
	.name = "md5WithRSAEncryption",
	.pubkey = &rsa_algorithm,
	.digest = &md5_algorithm,
	.oid = ASN1_OID_CURSOR ( oid_md5_with_rsa_encryption ),
};

/** MD5 digestInfo prefix */
static const uint8_t rsa_md5_prefix_data[] =
	{ RSA_DIGESTINFO_PREFIX ( MD5_DIGEST_SIZE, ASN1_OID_MD5 ) };

/** MD5 digestInfo prefix */
struct rsa_digestinfo_prefix rsa_md5_prefix __rsa_digestinfo_prefix = {
	.digest = &md5_algorithm,
	.data = rsa_md5_prefix_data,
	.len = sizeof ( rsa_md5_prefix_data ),
};
