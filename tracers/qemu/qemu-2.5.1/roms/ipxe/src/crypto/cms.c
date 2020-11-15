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
 * Cryptographic Message Syntax (PKCS #7)
 *
 * The format of CMS messages is defined in RFC 5652.
 *
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <ipxe/asn1.h>
#include <ipxe/x509.h>
#include <ipxe/malloc.h>
#include <ipxe/uaccess.h>
#include <ipxe/cms.h>

/* Disambiguate the various error causes */
#define EACCES_NON_SIGNING \
	__einfo_error ( EINFO_EACCES_NON_SIGNING )
#define EINFO_EACCES_NON_SIGNING \
	__einfo_uniqify ( EINFO_EACCES, 0x01, "Not a signing certificate" )
#define EACCES_NON_CODE_SIGNING \
	__einfo_error ( EINFO_EACCES_NON_CODE_SIGNING )
#define EINFO_EACCES_NON_CODE_SIGNING \
	__einfo_uniqify ( EINFO_EACCES, 0x02, "Not a code-signing certificate" )
#define EACCES_WRONG_NAME \
	__einfo_error ( EINFO_EACCES_WRONG_NAME )
#define EINFO_EACCES_WRONG_NAME \
	__einfo_uniqify ( EINFO_EACCES, 0x04, "Incorrect certificate name" )
#define EACCES_NO_SIGNATURES \
	__einfo_error ( EINFO_EACCES_NO_SIGNATURES )
#define EINFO_EACCES_NO_SIGNATURES \
	__einfo_uniqify ( EINFO_EACCES, 0x05, "No signatures present" )
#define EINVAL_DIGEST \
	__einfo_error ( EINFO_EINVAL_DIGEST )
#define EINFO_EINVAL_DIGEST \
	__einfo_uniqify ( EINFO_EINVAL, 0x01, "Not a digest algorithm" )
#define EINVAL_PUBKEY \
	__einfo_error ( EINFO_EINVAL_PUBKEY )
#define EINFO_EINVAL_PUBKEY \
	__einfo_uniqify ( EINFO_EINVAL, 0x02, "Not a public-key algorithm" )
#define ENOTSUP_SIGNEDDATA \
	__einfo_error ( EINFO_ENOTSUP_SIGNEDDATA )
#define EINFO_ENOTSUP_SIGNEDDATA \
	__einfo_uniqify ( EINFO_ENOTSUP, 0x01, "Not a digital signature" )

/** "pkcs7-signedData" object identifier */
static uint8_t oid_signeddata[] = { ASN1_OID_SIGNEDDATA };

/** "pkcs7-signedData" object identifier cursor */
static struct asn1_cursor oid_signeddata_cursor =
	ASN1_OID_CURSOR ( oid_signeddata );

/**
 * Parse CMS signature content type
 *
 * @v sig		CMS signature
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int cms_parse_content_type ( struct cms_signature *sig,
				    const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;

	/* Enter contentType */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_OID );

	/* Check OID is pkcs7-signedData */
	if ( asn1_compare ( &cursor, &oid_signeddata_cursor ) != 0 ) {
		DBGC ( sig, "CMS %p does not contain signedData:\n", sig );
		DBGC_HDA ( sig, 0, raw->data, raw->len );
		return -ENOTSUP_SIGNEDDATA;
	}

	DBGC ( sig, "CMS %p contains signedData\n", sig );
	return 0;
}

/**
 * Parse CMS signature certificate list
 *
 * @v sig		CMS signature
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int cms_parse_certificates ( struct cms_signature *sig,
				    const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	struct x509_certificate *cert;
	int rc;

	/* Enter certificates */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_EXPLICIT_TAG ( 0 ) );

	/* Add each certificate */
	while ( cursor.len ) {

		/* Add certificate to chain */
		if ( ( rc = x509_append_raw ( sig->certificates, cursor.data,
					      cursor.len ) ) != 0 ) {
			DBGC ( sig, "CMS %p could not append certificate: %s\n",
			       sig, strerror ( rc) );
			DBGC_HDA ( sig, 0, cursor.data, cursor.len );
			return rc;
		}
		cert = x509_last ( sig->certificates );
		DBGC ( sig, "CMS %p found certificate %s\n",
		       sig, x509_name ( cert ) );

		/* Move to next certificate */
		asn1_skip_any ( &cursor );
	}

	return 0;
}

/**
 * Identify CMS signature certificate by issuer and serial number
 *
 * @v sig		CMS signature
 * @v issuer		Issuer
 * @v serial		Serial number
 * @ret cert		X.509 certificate, or NULL if not found
 */
static struct x509_certificate *
cms_find_issuer_serial ( struct cms_signature *sig,
			 const struct asn1_cursor *issuer,
			 const struct asn1_cursor *serial ) {
	struct x509_link *link;
	struct x509_certificate *cert;

	/* Scan through certificate list */
	list_for_each_entry ( link, &sig->certificates->links, list ) {

		/* Check issuer and serial number */
		cert = link->cert;
		if ( ( asn1_compare ( issuer, &cert->issuer.raw ) == 0 ) &&
		     ( asn1_compare ( serial, &cert->serial.raw ) == 0 ) )
			return cert;
	}

	return NULL;
}

/**
 * Parse CMS signature signer identifier
 *
 * @v sig		CMS signature
 * @v info		Signer information to fill in
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int cms_parse_signer_identifier ( struct cms_signature *sig,
					 struct cms_signer_info *info,
					 const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	struct asn1_cursor serial;
	struct asn1_cursor issuer;
	struct x509_certificate *cert;
	int rc;

	/* Enter issuerAndSerialNumber */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Identify issuer */
	memcpy ( &issuer, &cursor, sizeof ( issuer ) );
	if ( ( rc = asn1_shrink ( &issuer, ASN1_SEQUENCE ) ) != 0 ) {
		DBGC ( sig, "CMS %p/%p could not locate issuer: %s\n",
		       sig, info, strerror ( rc ) );
		DBGC_HDA ( sig, 0, raw->data, raw->len );
		return rc;
	}
	DBGC ( sig, "CMS %p/%p issuer is:\n", sig, info );
	DBGC_HDA ( sig, 0, issuer.data, issuer.len );
	asn1_skip_any ( &cursor );

	/* Identify serialNumber */
	memcpy ( &serial, &cursor, sizeof ( serial ) );
	if ( ( rc = asn1_shrink ( &serial, ASN1_INTEGER ) ) != 0 ) {
		DBGC ( sig, "CMS %p/%p could not locate serialNumber: %s\n",
		       sig, info, strerror ( rc ) );
		DBGC_HDA ( sig, 0, raw->data, raw->len );
		return rc;
	}
	DBGC ( sig, "CMS %p/%p serial number is:\n", sig, info );
	DBGC_HDA ( sig, 0, serial.data, serial.len );

	/* Identify certificate */
	cert = cms_find_issuer_serial ( sig, &issuer, &serial );
	if ( ! cert ) {
		DBGC ( sig, "CMS %p/%p could not identify signer's "
		       "certificate\n", sig, info );
		return -ENOENT;
	}

	/* Append certificate to chain */
	if ( ( rc = x509_append ( info->chain, cert ) ) != 0 ) {
		DBGC ( sig, "CMS %p/%p could not append certificate: %s\n",
		       sig, info, strerror ( rc ) );
		return rc;
	}

	/* Append remaining certificates to chain */
	if ( ( rc = x509_auto_append ( info->chain,
				       sig->certificates ) ) != 0 ) {
		DBGC ( sig, "CMS %p/%p could not append certificates: %s\n",
		       sig, info, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Parse CMS signature digest algorithm
 *
 * @v sig		CMS signature
 * @v info		Signer information to fill in
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int cms_parse_digest_algorithm ( struct cms_signature *sig,
					struct cms_signer_info *info,
					const struct asn1_cursor *raw ) {
	struct asn1_algorithm *algorithm;
	int rc;

	/* Identify algorithm */
	if ( ( rc = asn1_digest_algorithm ( raw, &algorithm ) ) != 0 ) {
		DBGC ( sig, "CMS %p/%p could not identify digest algorithm: "
		       "%s\n", sig, info, strerror ( rc ) );
		DBGC_HDA ( sig, 0, raw->data, raw->len );
		return rc;
	}

	/* Record digest algorithm */
	info->digest = algorithm->digest;
	DBGC ( sig, "CMS %p/%p digest algorithm is %s\n",
	       sig, info, algorithm->name );

	return 0;
}

/**
 * Parse CMS signature algorithm
 *
 * @v sig		CMS signature
 * @v info		Signer information to fill in
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int cms_parse_signature_algorithm ( struct cms_signature *sig,
					   struct cms_signer_info *info,
					   const struct asn1_cursor *raw ) {
	struct asn1_algorithm *algorithm;
	int rc;

	/* Identify algorithm */
	if ( ( rc = asn1_pubkey_algorithm ( raw, &algorithm ) ) != 0 ) {
		DBGC ( sig, "CMS %p/%p could not identify public-key "
		       "algorithm: %s\n", sig, info, strerror ( rc ) );
		DBGC_HDA ( sig, 0, raw->data, raw->len );
		return rc;
	}

	/* Record signature algorithm */
	info->pubkey = algorithm->pubkey;
	DBGC ( sig, "CMS %p/%p public-key algorithm is %s\n",
	       sig, info, algorithm->name );

	return 0;
}

/**
 * Parse CMS signature value
 *
 * @v sig		CMS signature
 * @v info		Signer information to fill in
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int cms_parse_signature_value ( struct cms_signature *sig,
				       struct cms_signer_info *info,
				       const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	int rc;

	/* Enter signature */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	if ( ( rc = asn1_enter ( &cursor, ASN1_OCTET_STRING ) ) != 0 ) {
		DBGC ( sig, "CMS %p/%p could not locate signature:\n",
		       sig, info );
		DBGC_HDA ( sig, 0, raw->data, raw->len );
		return rc;
	}

	/* Record signature */
	info->signature_len = cursor.len;
	info->signature = malloc ( info->signature_len );
	if ( ! info->signature )
		return -ENOMEM;
	memcpy ( info->signature, cursor.data, info->signature_len );
	DBGC ( sig, "CMS %p/%p signature value is:\n", sig, info );
	DBGC_HDA ( sig, 0, info->signature, info->signature_len );

	return 0;
}

/**
 * Parse CMS signature signer information
 *
 * @v sig		CMS signature
 * @v info		Signer information to fill in
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int cms_parse_signer_info ( struct cms_signature *sig,
				   struct cms_signer_info *info,
				   const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	int rc;

	/* Enter signerInfo */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Skip version */
	asn1_skip ( &cursor, ASN1_INTEGER );

	/* Parse sid */
	if ( ( rc = cms_parse_signer_identifier ( sig, info, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Parse digestAlgorithm */
	if ( ( rc = cms_parse_digest_algorithm ( sig, info, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Skip signedAttrs, if present */
	asn1_skip_if_exists ( &cursor, ASN1_EXPLICIT_TAG ( 0 ) );

	/* Parse signatureAlgorithm */
	if ( ( rc = cms_parse_signature_algorithm ( sig, info, &cursor ) ) != 0)
		return rc;
	asn1_skip_any ( &cursor );

	/* Parse signature */
	if ( ( rc = cms_parse_signature_value ( sig, info, &cursor ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Parse CMS signature from ASN.1 data
 *
 * @v sig		CMS signature
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int cms_parse ( struct cms_signature *sig,
		       const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	struct cms_signer_info *info;
	int rc;

	/* Enter contentInfo */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Parse contentType */

	if ( ( rc = cms_parse_content_type ( sig, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Enter content */
	asn1_enter ( &cursor, ASN1_EXPLICIT_TAG ( 0 ) );

	/* Enter signedData */
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Skip version */
	asn1_skip ( &cursor, ASN1_INTEGER );

	/* Skip digestAlgorithms */
	asn1_skip ( &cursor, ASN1_SET );

	/* Skip encapContentInfo */
	asn1_skip ( &cursor, ASN1_SEQUENCE );

	/* Parse certificates */
	if ( ( rc = cms_parse_certificates ( sig, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Skip crls, if present */
	asn1_skip_if_exists ( &cursor, ASN1_EXPLICIT_TAG ( 1 ) );

	/* Enter signerInfos */
	asn1_enter ( &cursor, ASN1_SET );

	/* Add each signerInfo.  Errors are handled by ensuring that
	 * cms_put() will always be able to free any allocated memory.
	 */
	while ( cursor.len ) {

		/* Allocate signer information block */
		info = zalloc ( sizeof ( *info ) );
		if ( ! info )
			return -ENOMEM;
		list_add ( &info->list, &sig->info );

		/* Allocate certificate chain */
		info->chain = x509_alloc_chain();
		if ( ! info->chain )
			return -ENOMEM;

		/* Parse signerInfo */
		if ( ( rc = cms_parse_signer_info ( sig, info,
						    &cursor ) ) != 0 )
			return rc;
		asn1_skip_any ( &cursor );
	}

	return 0;
}

/**
 * Free CMS signature
 *
 * @v refcnt		Reference count
 */
static void cms_free ( struct refcnt *refcnt ) {
	struct cms_signature *sig =
		container_of ( refcnt, struct cms_signature, refcnt );
	struct cms_signer_info *info;
	struct cms_signer_info *tmp;

	list_for_each_entry_safe ( info, tmp, &sig->info, list ) {
		list_del ( &info->list );
		x509_chain_put ( info->chain );
		free ( info->signature );
		free ( info );
	}
	x509_chain_put ( sig->certificates );
	free ( sig );
}

/**
 * Create CMS signature
 *
 * @v data		Raw signature data
 * @v len		Length of raw data
 * @ret sig		CMS signature
 * @ret rc		Return status code
 *
 * On success, the caller holds a reference to the CMS signature, and
 * is responsible for ultimately calling cms_put().
 */
int cms_signature ( const void *data, size_t len, struct cms_signature **sig ) {
	struct asn1_cursor cursor;
	int rc;

	/* Allocate and initialise signature */
	*sig = zalloc ( sizeof ( **sig ) );
	if ( ! *sig ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	ref_init ( &(*sig)->refcnt, cms_free );
	INIT_LIST_HEAD ( &(*sig)->info );

	/* Allocate certificate list */
	(*sig)->certificates = x509_alloc_chain();
	if ( ! (*sig)->certificates ) {
		rc = -ENOMEM;
		goto err_alloc_chain;
	}

	/* Initialise cursor */
	cursor.data = data;
	cursor.len = len;
	asn1_shrink_any ( &cursor );

	/* Parse signature */
	if ( ( rc = cms_parse ( *sig, &cursor ) ) != 0 )
		goto err_parse;

	return 0;

 err_parse:
 err_alloc_chain:
	cms_put ( *sig );
 err_alloc:
	return rc;
}

/**
 * Calculate digest of CMS-signed data
 *
 * @v sig		CMS signature
 * @v info		Signer information
 * @v data		Signed data
 * @v len		Length of signed data
 * @v out		Digest output
 */
static void cms_digest ( struct cms_signature *sig,
			 struct cms_signer_info *info,
			 userptr_t data, size_t len, void *out ) {
	struct digest_algorithm *digest = info->digest;
	uint8_t ctx[ digest->ctxsize ];
	uint8_t block[ digest->blocksize ];
	size_t offset = 0;
	size_t frag_len;

	/* Initialise digest */
	digest_init ( digest, ctx );

	/* Process data one block at a time */
	while ( len ) {
		frag_len = len;
		if ( frag_len > sizeof ( block ) )
			frag_len = sizeof ( block );
		copy_from_user ( block, data, offset, frag_len );
		digest_update ( digest, ctx, block, frag_len );
		offset += frag_len;
		len -= frag_len;
	}

	/* Finalise digest */
	digest_final ( digest, ctx, out );

	DBGC ( sig, "CMS %p/%p digest value:\n", sig, info );
	DBGC_HDA ( sig, 0, out, digest->digestsize );
}

/**
 * Verify digest of CMS-signed data
 *
 * @v sig		CMS signature
 * @v info		Signer information
 * @v cert		Corresponding certificate
 * @v data		Signed data
 * @v len		Length of signed data
 * @ret rc		Return status code
 */
static int cms_verify_digest ( struct cms_signature *sig,
			       struct cms_signer_info *info,
			       struct x509_certificate *cert,
			       userptr_t data, size_t len ) {
	struct digest_algorithm *digest = info->digest;
	struct pubkey_algorithm *pubkey = info->pubkey;
	struct x509_public_key *public_key = &cert->subject.public_key;
	uint8_t digest_out[ digest->digestsize ];
	uint8_t ctx[ pubkey->ctxsize ];
	int rc;

	/* Generate digest */
	cms_digest ( sig, info, data, len, digest_out );

	/* Initialise public-key algorithm */
	if ( ( rc = pubkey_init ( pubkey, ctx, public_key->raw.data,
				  public_key->raw.len ) ) != 0 ) {
		DBGC ( sig, "CMS %p/%p could not initialise public key: %s\n",
		       sig, info, strerror ( rc ) );
		goto err_init;
	}

	/* Verify digest */
	if ( ( rc = pubkey_verify ( pubkey, ctx, digest, digest_out,
				    info->signature,
				    info->signature_len ) ) != 0 ) {
		DBGC ( sig, "CMS %p/%p signature verification failed: %s\n",
		       sig, info, strerror ( rc ) );
		goto err_verify;
	}

 err_verify:
	pubkey_final ( pubkey, ctx );
 err_init:
	return rc;
}

/**
 * Verify CMS signature signer information
 *
 * @v sig		CMS signature
 * @v info		Signer information
 * @v data		Signed data
 * @v len		Length of signed data
 * @v time		Time at which to validate certificates
 * @v store		Certificate store, or NULL to use default
 * @v root		Root certificate list, or NULL to use default
 * @ret rc		Return status code
 */
static int cms_verify_signer_info ( struct cms_signature *sig,
				    struct cms_signer_info *info,
				    userptr_t data, size_t len,
				    time_t time, struct x509_chain *store,
				    struct x509_root *root ) {
	struct x509_certificate *cert;
	int rc;

	/* Validate certificate chain */
	if ( ( rc = x509_validate_chain ( info->chain, time, store,
					  root ) ) != 0 ) {
		DBGC ( sig, "CMS %p/%p could not validate chain: %s\n",
		       sig, info, strerror ( rc ) );
		return rc;
	}

	/* Extract code-signing certificate */
	cert = x509_first ( info->chain );
	assert ( cert != NULL );

	/* Check that certificate can create digital signatures */
	if ( ! ( cert->extensions.usage.bits & X509_DIGITAL_SIGNATURE ) ) {
		DBGC ( sig, "CMS %p/%p certificate cannot create signatures\n",
		       sig, info );
		return -EACCES_NON_SIGNING;
	}

	/* Check that certificate can sign code */
	if ( ! ( cert->extensions.ext_usage.bits & X509_CODE_SIGNING ) ) {
		DBGC ( sig, "CMS %p/%p certificate is not code-signing\n",
		       sig, info );
		return -EACCES_NON_CODE_SIGNING;
	}

	/* Verify digest */
	if ( ( rc = cms_verify_digest ( sig, info, cert, data, len ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Verify CMS signature
 *
 * @v sig		CMS signature
 * @v data		Signed data
 * @v len		Length of signed data
 * @v name		Required common name, or NULL to check all signatures
 * @v time		Time at which to validate certificates
 * @v store		Certificate store, or NULL to use default
 * @v root		Root certificate list, or NULL to use default
 * @ret rc		Return status code
 */
int cms_verify ( struct cms_signature *sig, userptr_t data, size_t len,
		 const char *name, time_t time, struct x509_chain *store,
		 struct x509_root *root ) {
	struct cms_signer_info *info;
	struct x509_certificate *cert;
	int count = 0;
	int rc;

	/* Verify using all signerInfos */
	list_for_each_entry ( info, &sig->info, list ) {
		cert = x509_first ( info->chain );
		if ( name && ( x509_check_name ( cert, name ) != 0 ) )
			continue;
		if ( ( rc = cms_verify_signer_info ( sig, info, data, len, time,
						     store, root ) ) != 0 )
			return rc;
		count++;
	}

	/* Check that we have verified at least one signature */
	if ( count == 0 ) {
		if ( name ) {
			DBGC ( sig, "CMS %p had no signatures matching name "
			       "%s\n", sig, name );
			return -EACCES_WRONG_NAME;
		} else {
			DBGC ( sig, "CMS %p had no signatures\n", sig );
			return -EACCES_NO_SIGNATURES;
		}
	}

	return 0;
}
