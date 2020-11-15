/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
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
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ipxe/asn1.h>
#include <ipxe/x509.h>
#include <ipxe/sha1.h>
#include <ipxe/base64.h>
#include <ipxe/uri.h>
#include <ipxe/ocsp.h>
#include <config/crypto.h>

/** @file
 *
 * Online Certificate Status Protocol
 *
 */

/* Disambiguate the various error causes */
#define EACCES_CERT_STATUS						\
	__einfo_error ( EINFO_EACCES_CERT_STATUS )
#define EINFO_EACCES_CERT_STATUS					\
	__einfo_uniqify ( EINFO_EACCES, 0x01,				\
			  "Certificate status not good" )
#define EACCES_CERT_MISMATCH						\
	__einfo_error ( EINFO_EACCES_CERT_MISMATCH )
#define EINFO_EACCES_CERT_MISMATCH					\
	__einfo_uniqify ( EINFO_EACCES, 0x02,				\
			  "Certificate ID mismatch" )
#define EACCES_NON_OCSP_SIGNING						\
	__einfo_error ( EINFO_EACCES_NON_OCSP_SIGNING )
#define EINFO_EACCES_NON_OCSP_SIGNING					\
	__einfo_uniqify ( EINFO_EACCES, 0x03,				\
			  "Not an OCSP signing certificate" )
#define EACCES_STALE							\
	__einfo_error ( EINFO_EACCES_STALE )
#define EINFO_EACCES_STALE						\
	__einfo_uniqify ( EINFO_EACCES, 0x04,				\
			  "Stale (or premature) OCSP repsonse" )
#define EACCES_NO_RESPONDER						\
	__einfo_error ( EINFO_EACCES_NO_RESPONDER )
#define EINFO_EACCES_NO_RESPONDER					\
	__einfo_uniqify ( EINFO_EACCES, 0x05,				\
			  "Missing OCSP responder certificate" )
#define ENOTSUP_RESPONSE_TYPE						\
	__einfo_error ( EINFO_ENOTSUP_RESPONSE_TYPE )
#define EINFO_ENOTSUP_RESPONSE_TYPE					\
	__einfo_uniqify ( EINFO_ENOTSUP, 0x01,				\
			  "Unsupported OCSP response type" )
#define ENOTSUP_RESPONDER_ID						\
	__einfo_error ( EINFO_ENOTSUP_RESPONDER_ID )
#define EINFO_ENOTSUP_RESPONDER_ID					\
	__einfo_uniqify ( EINFO_ENOTSUP, 0x02,				\
			  "Unsupported OCSP responder ID" )
#define EPROTO_MALFORMED_REQUEST					\
	__einfo_error ( EINFO_EPROTO_MALFORMED_REQUEST )
#define EINFO_EPROTO_MALFORMED_REQUEST					\
	__einfo_uniqify ( EINFO_EPROTO, OCSP_STATUS_MALFORMED_REQUEST,	\
			  "Illegal confirmation request" )
#define EPROTO_INTERNAL_ERROR						\
	__einfo_error ( EINFO_EPROTO_INTERNAL_ERROR )
#define EINFO_EPROTO_INTERNAL_ERROR					\
	__einfo_uniqify ( EINFO_EPROTO, OCSP_STATUS_INTERNAL_ERROR,	\
			  "Internal error in issuer" )
#define EPROTO_TRY_LATER						\
	__einfo_error ( EINFO_EPROTO_TRY_LATER )
#define EINFO_EPROTO_TRY_LATER						\
	__einfo_uniqify ( EINFO_EPROTO, OCSP_STATUS_TRY_LATER,		\
			  "Try again later" )
#define EPROTO_SIG_REQUIRED						\
	__einfo_error ( EINFO_EPROTO_SIG_REQUIRED )
#define EINFO_EPROTO_SIG_REQUIRED					\
	__einfo_uniqify ( EINFO_EPROTO, OCSP_STATUS_SIG_REQUIRED,	\
			  "Must sign the request" )
#define EPROTO_UNAUTHORIZED						\
	__einfo_error ( EINFO_EPROTO_UNAUTHORIZED )
#define EINFO_EPROTO_UNAUTHORIZED					\
	__einfo_uniqify ( EINFO_EPROTO, OCSP_STATUS_UNAUTHORIZED,	\
			  "Request unauthorized" )
#define EPROTO_STATUS( status )						\
	EUNIQ ( EINFO_EPROTO, (status), EPROTO_MALFORMED_REQUEST,	\
		EPROTO_INTERNAL_ERROR, EPROTO_TRY_LATER,		\
		EPROTO_SIG_REQUIRED, EPROTO_UNAUTHORIZED )

/** OCSP digest algorithm */
#define ocsp_digest_algorithm sha1_algorithm

/** OCSP digest algorithm identifier */
static const uint8_t ocsp_algorithm_id[] =
	{ OCSP_ALGORITHM_IDENTIFIER ( ASN1_OID_SHA1 ) };

/** OCSP basic response type */
static const uint8_t oid_basic_response_type[] = { ASN1_OID_OCSP_BASIC };

/** OCSP basic response type cursor */
static struct asn1_cursor oid_basic_response_type_cursor =
	ASN1_OID_CURSOR ( oid_basic_response_type );

/**
 * Free OCSP check
 *
 * @v refcnt		Reference count
 */
static void ocsp_free ( struct refcnt *refcnt ) {
	struct ocsp_check *ocsp =
		container_of ( refcnt, struct ocsp_check, refcnt );

	x509_put ( ocsp->cert );
	x509_put ( ocsp->issuer );
	free ( ocsp->uri_string );
	free ( ocsp->request.builder.data );
	free ( ocsp->response.data );
	x509_put ( ocsp->response.signer );
	free ( ocsp );
}

/**
 * Build OCSP request
 *
 * @v ocsp		OCSP check
 * @ret rc		Return status code
 */
static int ocsp_request ( struct ocsp_check *ocsp ) {
	struct digest_algorithm *digest = &ocsp_digest_algorithm;
	struct asn1_builder *builder = &ocsp->request.builder;
	struct asn1_cursor *cert_id = &ocsp->request.cert_id;
	uint8_t digest_ctx[digest->ctxsize];
	uint8_t name_digest[digest->digestsize];
	uint8_t pubkey_digest[digest->digestsize];
	int rc;

	/* Generate digests */
	digest_init ( digest, digest_ctx );
	digest_update ( digest, digest_ctx, ocsp->cert->issuer.raw.data,
			ocsp->cert->issuer.raw.len );
	digest_final ( digest, digest_ctx, name_digest );
	digest_init ( digest, digest_ctx );
	digest_update ( digest, digest_ctx,
			ocsp->issuer->subject.public_key.raw_bits.data,
			ocsp->issuer->subject.public_key.raw_bits.len );
	digest_final ( digest, digest_ctx, pubkey_digest );

	/* Construct request */
	if ( ( rc = ( asn1_prepend_raw ( builder, ocsp->cert->serial.raw.data,
					 ocsp->cert->serial.raw.len ),
		      asn1_prepend ( builder, ASN1_OCTET_STRING,
				     pubkey_digest, sizeof ( pubkey_digest ) ),
		      asn1_prepend ( builder, ASN1_OCTET_STRING,
				     name_digest, sizeof ( name_digest ) ),
		      asn1_prepend ( builder, ASN1_SEQUENCE,
				     ocsp_algorithm_id,
				     sizeof ( ocsp_algorithm_id ) ),
		      asn1_wrap ( builder, ASN1_SEQUENCE ),
		      asn1_wrap ( builder, ASN1_SEQUENCE ),
		      asn1_wrap ( builder, ASN1_SEQUENCE ),
		      asn1_wrap ( builder, ASN1_SEQUENCE ),
		      asn1_wrap ( builder, ASN1_SEQUENCE ) ) ) != 0 ) {
		DBGC ( ocsp, "OCSP %p \"%s\" could not build request: %s\n",
		       ocsp, x509_name ( ocsp->cert ), strerror ( rc ) );
		return rc;
	}
	DBGC2 ( ocsp, "OCSP %p \"%s\" request is:\n",
		ocsp, x509_name ( ocsp->cert ) );
	DBGC2_HDA ( ocsp, 0, builder->data, builder->len );

	/* Parse certificate ID for comparison with response */
	cert_id->data = builder->data;
	cert_id->len = builder->len;
	if ( ( rc = ( asn1_enter ( cert_id, ASN1_SEQUENCE ),
		      asn1_enter ( cert_id, ASN1_SEQUENCE ),
		      asn1_enter ( cert_id, ASN1_SEQUENCE ),
		      asn1_enter ( cert_id, ASN1_SEQUENCE ) ) ) != 0 ) {
		DBGC ( ocsp, "OCSP %p \"%s\" could not locate certID: %s\n",
		       ocsp, x509_name ( ocsp->cert ), strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Build OCSP URI string
 *
 * @v ocsp		OCSP check
 * @ret rc		Return status code
 */
static int ocsp_uri_string ( struct ocsp_check *ocsp ) {
	struct x509_ocsp_responder *responder =
		&ocsp->cert->extensions.auth_info.ocsp;
	struct uri path_uri;
	char *path_base64_string;
	char *path_uri_string;
	size_t path_len;
	size_t len;
	int rc;

	/* Sanity check */
	if ( ! responder->uri.len ) {
		DBGC ( ocsp, "OCSP %p \"%s\" has no OCSP URI\n",
		       ocsp, x509_name ( ocsp->cert ) );
		rc = -ENOTTY;
		goto err_no_uri;
	}

	/* Base64-encode the request as the URI path */
	path_len = ( base64_encoded_len ( ocsp->request.builder.len )
		     + 1 /* NUL */ );
	path_base64_string = malloc ( path_len );
	if ( ! path_base64_string ) {
		rc = -ENOMEM;
		goto err_path_base64;
	}
	base64_encode ( ocsp->request.builder.data, ocsp->request.builder.len,
			path_base64_string, path_len );

	/* URI-encode the Base64-encoded request */
	memset ( &path_uri, 0, sizeof ( path_uri ) );
	path_uri.path = path_base64_string;
	path_uri_string = format_uri_alloc ( &path_uri );
	if ( ! path_uri_string ) {
		rc = -ENOMEM;
		goto err_path_uri;
	}

	/* Construct URI string */
	len = ( responder->uri.len + strlen ( path_uri_string ) + 1 /* NUL */ );
	ocsp->uri_string = zalloc ( len );
	if ( ! ocsp->uri_string ) {
		rc = -ENOMEM;
		goto err_ocsp_uri;
	}
	memcpy ( ocsp->uri_string, responder->uri.data, responder->uri.len );
	strcpy ( &ocsp->uri_string[responder->uri.len], path_uri_string );
	DBGC2 ( ocsp, "OCSP %p \"%s\" URI is %s\n",
		ocsp, x509_name ( ocsp->cert ), ocsp->uri_string );

	/* Success */
	rc = 0;

 err_ocsp_uri:
	free ( path_uri_string );
 err_path_uri:
	free ( path_base64_string );
 err_path_base64:
 err_no_uri:
	return rc;
}

/**
 * Create OCSP check
 *
 * @v cert		Certificate to check
 * @v issuer		Issuing certificate
 * @ret ocsp		OCSP check
 * @ret rc		Return status code
 */
int ocsp_check ( struct x509_certificate *cert,
		 struct x509_certificate *issuer,
		 struct ocsp_check **ocsp ) {
	int rc;

	/* Sanity checks */
	assert ( cert != NULL );
	assert ( issuer != NULL );
	assert ( issuer->valid );

	/* Allocate and initialise check */
	*ocsp = zalloc ( sizeof ( **ocsp ) );
	if ( ! *ocsp ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	ref_init ( &(*ocsp)->refcnt, ocsp_free );
	(*ocsp)->cert = x509_get ( cert );
	(*ocsp)->issuer = x509_get ( issuer );

	/* Build request */
	if ( ( rc = ocsp_request ( *ocsp ) ) != 0 )
		goto err_request;

	/* Build URI string */
	if ( ( rc = ocsp_uri_string ( *ocsp ) ) != 0 )
		goto err_uri_string;

	return 0;

 err_uri_string:
 err_request:
	ocsp_put ( *ocsp );
 err_alloc:
	*ocsp = NULL;
	return rc;
}

/**
 * Parse OCSP response status
 *
 * @v ocsp		OCSP check
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int ocsp_parse_response_status ( struct ocsp_check *ocsp,
					const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	uint8_t status;
	int rc;

	/* Enter responseStatus */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	if ( ( rc = asn1_enter ( &cursor, ASN1_ENUMERATED ) ) != 0 ) {
		DBGC ( ocsp, "OCSP %p \"%s\" could not locate responseStatus: "
		       "%s\n", ocsp, x509_name ( ocsp->cert ), strerror ( rc ));
		return rc;
	}

	/* Extract response status */
	if ( cursor.len != sizeof ( status ) ) {
		DBGC ( ocsp, "OCSP %p \"%s\" invalid status:\n",
		       ocsp, x509_name ( ocsp->cert ) );
		DBGC_HDA ( ocsp, 0, cursor.data, cursor.len );
		return -EINVAL;
	}
	memcpy ( &status, cursor.data, sizeof ( status ) );

	/* Check response status */
	if ( status != OCSP_STATUS_SUCCESSFUL ) {
		DBGC ( ocsp, "OCSP %p \"%s\" response status %d\n",
		       ocsp, x509_name ( ocsp->cert ), status );
		return EPROTO_STATUS ( status );
	}

	return 0;
}

/**
 * Parse OCSP response type
 *
 * @v ocsp		OCSP check
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int ocsp_parse_response_type ( struct ocsp_check *ocsp,
				      const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;

	/* Enter responseType */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_OID );

	/* Check responseType is "basic" */
	if ( asn1_compare ( &oid_basic_response_type_cursor, &cursor ) != 0 ) {
		DBGC ( ocsp, "OCSP %p \"%s\" response type not supported:\n",
		       ocsp, x509_name ( ocsp->cert ) );
		DBGC_HDA ( ocsp, 0, cursor.data, cursor.len );
		return -ENOTSUP_RESPONSE_TYPE;
	}

	return 0;
}

/**
 * Compare responder's certificate name
 *
 * @v ocsp		OCSP check
 * @v cert		Certificate
 * @ret difference	Difference as returned by memcmp()
 */
static int ocsp_compare_responder_name ( struct ocsp_check *ocsp,
					 struct x509_certificate *cert ) {
	struct ocsp_responder *responder = &ocsp->response.responder;

	/* Compare responder ID with certificate's subject */
	return asn1_compare ( &responder->id, &cert->subject.raw );
}

/**
 * Compare responder's certificate public key hash
 *
 * @v ocsp		OCSP check
 * @v cert		Certificate
 * @ret difference	Difference as returned by memcmp()
 */
static int ocsp_compare_responder_key_hash ( struct ocsp_check *ocsp,
					     struct x509_certificate *cert ) {
	struct ocsp_responder *responder = &ocsp->response.responder;
	struct asn1_cursor key_hash;
	uint8_t ctx[SHA1_CTX_SIZE];
	uint8_t digest[SHA1_DIGEST_SIZE];
	int difference;

	/* Enter responder key hash */
	memcpy ( &key_hash, &responder->id, sizeof ( key_hash ) );
	asn1_enter ( &key_hash, ASN1_OCTET_STRING );

	/* Sanity check */
	difference = ( sizeof ( digest ) - key_hash.len );
	if ( difference )
		return difference;

	/* Generate SHA1 hash of certificate's public key */
	digest_init ( &sha1_algorithm, ctx );
	digest_update ( &sha1_algorithm, ctx,
			cert->subject.public_key.raw_bits.data,
			cert->subject.public_key.raw_bits.len );
	digest_final ( &sha1_algorithm, ctx, digest );

	/* Compare responder key hash with hash of certificate's public key */
	return memcmp ( digest, key_hash.data, sizeof ( digest ) );
}

/**
 * Parse OCSP responder ID
 *
 * @v ocsp		OCSP check
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int ocsp_parse_responder_id ( struct ocsp_check *ocsp,
				     const struct asn1_cursor *raw ) {
	struct ocsp_responder *responder = &ocsp->response.responder;
	struct asn1_cursor *responder_id = &responder->id;
	unsigned int type;

	/* Enter responder ID */
	memcpy ( responder_id, raw, sizeof ( *responder_id ) );
	type = asn1_type ( responder_id );
	asn1_enter_any ( responder_id );

	/* Identify responder ID type */
	switch ( type ) {
	case ASN1_EXPLICIT_TAG ( 1 ) :
		DBGC2 ( ocsp, "OCSP %p \"%s\" responder identified by name\n",
			ocsp, x509_name ( ocsp->cert ) );
		responder->compare = ocsp_compare_responder_name;
		return 0;
	case ASN1_EXPLICIT_TAG ( 2 ) :
		DBGC2 ( ocsp, "OCSP %p \"%s\" responder identified by key "
			"hash\n", ocsp, x509_name ( ocsp->cert ) );
		responder->compare = ocsp_compare_responder_key_hash;
		return 0;
	default:
		DBGC ( ocsp, "OCSP %p \"%s\" unsupported responder ID type "
		       "%d\n", ocsp, x509_name ( ocsp->cert ), type );
		return -ENOTSUP_RESPONDER_ID;
	}
}

/**
 * Parse OCSP certificate ID
 *
 * @v ocsp		OCSP check
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int ocsp_parse_cert_id ( struct ocsp_check *ocsp,
				const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;

	/* Check certID matches request */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_shrink_any ( &cursor );
	if ( asn1_compare ( &cursor, &ocsp->request.cert_id ) != 0 ) {
		DBGC ( ocsp, "OCSP %p \"%s\" certID mismatch:\n",
		       ocsp, x509_name ( ocsp->cert ) );
		DBGC_HDA ( ocsp, 0, ocsp->request.cert_id.data,
			   ocsp->request.cert_id.len );
		DBGC_HDA ( ocsp, 0, cursor.data, cursor.len );
		return -EACCES_CERT_MISMATCH;
	}

	return 0;
}

/**
 * Parse OCSP responses
 *
 * @v ocsp		OCSP check
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int ocsp_parse_responses ( struct ocsp_check *ocsp,
				  const struct asn1_cursor *raw ) {
	struct ocsp_response *response = &ocsp->response;
	struct asn1_cursor cursor;
	int rc;

	/* Enter responses */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Enter first singleResponse */
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Parse certID */
	if ( ( rc = ocsp_parse_cert_id ( ocsp, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Check certStatus */
	if ( asn1_type ( &cursor ) != ASN1_IMPLICIT_TAG ( 0 ) ) {
		DBGC ( ocsp, "OCSP %p \"%s\" non-good certStatus:\n",
		       ocsp, x509_name ( ocsp->cert ) );
		DBGC_HDA ( ocsp, 0, cursor.data, cursor.len );
		return -EACCES_CERT_STATUS;
	}
	asn1_skip_any ( &cursor );

	/* Parse thisUpdate */
	if ( ( rc = asn1_generalized_time ( &cursor,
					    &response->this_update ) ) != 0 ) {
		DBGC ( ocsp, "OCSP %p \"%s\" could not parse thisUpdate: %s\n",
		       ocsp, x509_name ( ocsp->cert ), strerror ( rc ) );
		return rc;
	}
	DBGC2 ( ocsp, "OCSP %p \"%s\" this update was at time %lld\n",
		ocsp, x509_name ( ocsp->cert ), response->this_update );
	asn1_skip_any ( &cursor );

	/* Parse nextUpdate, if present */
	if ( asn1_type ( &cursor ) == ASN1_EXPLICIT_TAG ( 0 ) ) {
		asn1_enter ( &cursor, ASN1_EXPLICIT_TAG ( 0 ) );
		if ( ( rc = asn1_generalized_time ( &cursor,
					     &response->next_update ) ) != 0 ) {
			DBGC ( ocsp, "OCSP %p \"%s\" could not parse "
			       "nextUpdate: %s\n", ocsp,
			       x509_name ( ocsp->cert ), strerror ( rc ) );
			return rc;
		}
		DBGC2 ( ocsp, "OCSP %p \"%s\" next update is at time %lld\n",
			ocsp, x509_name ( ocsp->cert ), response->next_update );
	} else {
		/* If no nextUpdate is present, this indicates that
		 * "newer revocation information is available all the
		 * time".  Actually, this indicates that there is no
		 * point to performing the OCSP check, since an
		 * attacker could replay the response at any future
		 * time and it would still be valid.
		 */
		DBGC ( ocsp, "OCSP %p \"%s\" responder is a moron\n",
		       ocsp, x509_name ( ocsp->cert ) );
		response->next_update = time ( NULL );
	}

	return 0;
}

/**
 * Parse OCSP response data
 *
 * @v ocsp		OCSP check
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int ocsp_parse_tbs_response_data ( struct ocsp_check *ocsp,
					  const struct asn1_cursor *raw ) {
	struct ocsp_response *response = &ocsp->response;
	struct asn1_cursor cursor;
	int rc;

	/* Record raw tbsResponseData */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_shrink_any ( &cursor );
	memcpy ( &response->tbs, &cursor, sizeof ( response->tbs ) );

	/* Enter tbsResponseData */
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Skip version, if present */
	asn1_skip_if_exists ( &cursor, ASN1_EXPLICIT_TAG ( 0 ) );

	/* Parse responderID */
	if ( ( rc = ocsp_parse_responder_id ( ocsp, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Skip producedAt */
	asn1_skip_any ( &cursor );

	/* Parse responses */
	if ( ( rc = ocsp_parse_responses ( ocsp, &cursor ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Parse OCSP certificates
 *
 * @v ocsp		OCSP check
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int ocsp_parse_certs ( struct ocsp_check *ocsp,
			      const struct asn1_cursor *raw ) {
	struct ocsp_response *response = &ocsp->response;
	struct asn1_cursor cursor;
	struct x509_certificate *cert;
	int rc;

	/* Enter certs */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_EXPLICIT_TAG ( 0 ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Parse certificate, if present.  The data structure permits
	 * multiple certificates, but the protocol requires that the
	 * OCSP signing certificate must either be the issuer itself,
	 * or must be directly issued by the issuer (see RFC2560
	 * section 4.2.2.2 "Authorized Responders").  We therefore
	 * need to identify only the single certificate matching the
	 * Responder ID.
	 */
	while ( cursor.len ) {

		/* Parse certificate */
		if ( ( rc = x509_certificate ( cursor.data, cursor.len,
					       &cert ) ) != 0 ) {
			DBGC ( ocsp, "OCSP %p \"%s\" could not parse "
			       "certificate: %s\n", ocsp,
			       x509_name ( ocsp->cert ), strerror ( rc ) );
			DBGC_HDA ( ocsp, 0, cursor.data, cursor.len );
			return rc;
		}

		/* Use if this certificate matches the responder ID */
		if ( response->responder.compare ( ocsp, cert ) == 0 ) {
			response->signer = cert;
			DBGC2 ( ocsp, "OCSP %p \"%s\" response is signed by ",
				ocsp, x509_name ( ocsp->cert ) );
			DBGC2 ( ocsp, "\"%s\"\n",
				x509_name ( response->signer ) );
			return 0;
		}

		/* Otherwise, discard this certificate */
		x509_put ( cert );
		asn1_skip_any ( &cursor );
	}

	DBGC ( ocsp, "OCSP %p \"%s\" missing responder certificate\n",
	       ocsp, x509_name ( ocsp->cert ) );
	return -EACCES_NO_RESPONDER;
}

/**
 * Parse OCSP basic response
 *
 * @v ocsp		OCSP check
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int ocsp_parse_basic_response ( struct ocsp_check *ocsp,
				       const struct asn1_cursor *raw ) {
	struct ocsp_response *response = &ocsp->response;
	struct asn1_algorithm **algorithm = &response->algorithm;
	struct asn1_bit_string *signature = &response->signature;
	struct asn1_cursor cursor;
	int rc;

	/* Enter BasicOCSPResponse */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Parse tbsResponseData */
	if ( ( rc = ocsp_parse_tbs_response_data ( ocsp, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Parse signatureAlgorithm */
	if ( ( rc = asn1_signature_algorithm ( &cursor, algorithm ) ) != 0 ) {
		DBGC ( ocsp, "OCSP %p \"%s\" cannot parse signature "
		       "algorithm: %s\n",
		       ocsp, x509_name ( ocsp->cert ), strerror ( rc ) );
		return rc;
	}
	DBGC2 ( ocsp, "OCSP %p \"%s\" signature algorithm is %s\n",
		ocsp, x509_name ( ocsp->cert ), (*algorithm)->name );
	asn1_skip_any ( &cursor );

	/* Parse signature */
	if ( ( rc = asn1_integral_bit_string ( &cursor, signature ) ) != 0 ) {
		DBGC ( ocsp, "OCSP %p \"%s\" cannot parse signature: %s\n",
		       ocsp, x509_name ( ocsp->cert ), strerror ( rc ) );
		return rc;
	}
	asn1_skip_any ( &cursor );

	/* Parse certs, if present */
	if ( ( asn1_type ( &cursor ) == ASN1_EXPLICIT_TAG ( 0 ) ) &&
	     ( ( rc = ocsp_parse_certs ( ocsp, &cursor ) ) != 0 ) )
		return rc;

	return 0;
}

/**
 * Parse OCSP response bytes
 *
 * @v ocsp		OCSP check
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int ocsp_parse_response_bytes ( struct ocsp_check *ocsp,
				       const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	int rc;

	/* Enter responseBytes */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_EXPLICIT_TAG ( 0 ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Parse responseType */
	if ( ( rc = ocsp_parse_response_type ( ocsp, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Enter response */
	asn1_enter ( &cursor, ASN1_OCTET_STRING );

	/* Parse response */
	if ( ( rc = ocsp_parse_basic_response ( ocsp, &cursor ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Parse OCSP response
 *
 * @v ocsp		OCSP check
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int ocsp_parse_response ( struct ocsp_check *ocsp,
				 const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	int rc;

	/* Enter OCSPResponse */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Parse responseStatus */
	if ( ( rc = ocsp_parse_response_status ( ocsp, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Parse responseBytes */
	if ( ( rc = ocsp_parse_response_bytes ( ocsp, &cursor ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Receive OCSP response
 *
 * @v ocsp		OCSP check
 * @v data		Response data
 * @v len		Length of response data
 * @ret rc		Return status code
 */
int ocsp_response ( struct ocsp_check *ocsp, const void *data, size_t len ) {
	struct ocsp_response *response = &ocsp->response;
	struct asn1_cursor cursor;
	int rc;

	/* Duplicate data */
	x509_put ( response->signer );
	response->signer = NULL;
	free ( response->data );
	response->data = malloc ( len );
	if ( ! response->data )
		return -ENOMEM;
	memcpy ( response->data, data, len );
	cursor.data = response->data;
	cursor.len = len;

	/* Parse response */
	if ( ( rc = ocsp_parse_response ( ocsp, &cursor ) ) != 0 )
		return rc;

	return 0;
}

/**
 * OCSP dummy root certificate store
 *
 * OCSP validation uses no root certificates, since it takes place
 * only when there already exists a validated issuer certificate.
 */
static struct x509_root ocsp_root = {
	.digest = &ocsp_digest_algorithm,
	.count = 0,
	.fingerprints = NULL,
};

/**
 * Check OCSP response signature
 *
 * @v ocsp		OCSP check
 * @v signer		Signing certificate
 * @ret rc		Return status code
 */
static int ocsp_check_signature ( struct ocsp_check *ocsp,
				  struct x509_certificate *signer ) {
	struct ocsp_response *response = &ocsp->response;
	struct digest_algorithm *digest = response->algorithm->digest;
	struct pubkey_algorithm *pubkey = response->algorithm->pubkey;
	struct x509_public_key *public_key = &signer->subject.public_key;
	uint8_t digest_ctx[ digest->ctxsize ];
	uint8_t digest_out[ digest->digestsize ];
	uint8_t pubkey_ctx[ pubkey->ctxsize ];
	int rc;

	/* Generate digest */
	digest_init ( digest, digest_ctx );
	digest_update ( digest, digest_ctx, response->tbs.data,
			response->tbs.len );
	digest_final ( digest, digest_ctx, digest_out );

	/* Initialise public-key algorithm */
	if ( ( rc = pubkey_init ( pubkey, pubkey_ctx, public_key->raw.data,
				  public_key->raw.len ) ) != 0 ) {
		DBGC ( ocsp, "OCSP %p \"%s\" could not initialise public key: "
		       "%s\n", ocsp, x509_name ( ocsp->cert ), strerror ( rc ));
		goto err_init;
	}

	/* Verify digest */
	if ( ( rc = pubkey_verify ( pubkey, pubkey_ctx, digest, digest_out,
				    response->signature.data,
				    response->signature.len ) ) != 0 ) {
		DBGC ( ocsp, "OCSP %p \"%s\" signature verification failed: "
		       "%s\n", ocsp, x509_name ( ocsp->cert ), strerror ( rc ));
		goto err_verify;
	}

	DBGC2 ( ocsp, "OCSP %p \"%s\" signature is correct\n",
		ocsp, x509_name ( ocsp->cert ) );

 err_verify:
	pubkey_final ( pubkey, pubkey_ctx );
 err_init:
	return rc;
}

/**
 * Validate OCSP response
 *
 * @v ocsp		OCSP check
 * @v time		Time at which to validate response
 * @ret rc		Return status code
 */
int ocsp_validate ( struct ocsp_check *ocsp, time_t time ) {
	struct ocsp_response *response = &ocsp->response;
	struct x509_certificate *signer;
	int rc;

	/* Sanity checks */
	assert ( response->data != NULL );

	/* The response may include a signer certificate; if this is
	 * not present then the response must have been signed
	 * directly by the issuer.
	 */
	signer = ( response->signer ? response->signer : ocsp->issuer );

	/* Validate signer, if applicable.  If the signer is not the
	 * issuer, then it must be signed directly by the issuer.
	 */
	if ( signer != ocsp->issuer ) {
		/* Forcibly invalidate the signer, since we need to
		 * ensure that it was signed by our issuer (and not
		 * some other issuer).  This prevents a sub-CA's OCSP
		 * certificate from fraudulently signing OCSP
		 * responses from the parent CA.
		 */
		x509_invalidate ( signer );
		if ( ( rc = x509_validate ( signer, ocsp->issuer, time,
					    &ocsp_root ) ) != 0 ) {
			DBGC ( ocsp, "OCSP %p \"%s\" could not validate ",
			       ocsp, x509_name ( ocsp->cert ) );
			DBGC ( ocsp, "signer \"%s\": %s\n",
			       x509_name ( signer ), strerror ( rc ) );
			return rc;
		}

		/* If signer is not the issuer, then it must have the
		 * extendedKeyUsage id-kp-OCSPSigning.
		 */
		if ( ! ( signer->extensions.ext_usage.bits &
			 X509_OCSP_SIGNING ) ) {
			DBGC ( ocsp, "OCSP %p \"%s\" ",
			       ocsp, x509_name ( ocsp->cert ) );
			DBGC ( ocsp, "signer \"%s\" is not an OCSP-signing "
			       "certificate\n", x509_name ( signer ) );
			return -EACCES_NON_OCSP_SIGNING;
		}
	}

	/* Check OCSP response signature */
	if ( ( rc = ocsp_check_signature ( ocsp, signer ) ) != 0 )
		return rc;

	/* Check OCSP response is valid at the specified time
	 * (allowing for some margin of error).
	 */
	if ( response->this_update > ( time + TIMESTAMP_ERROR_MARGIN ) ) {
		DBGC ( ocsp, "OCSP %p \"%s\" response is not yet valid (at "
		       "time %lld)\n", ocsp, x509_name ( ocsp->cert ), time );
		return -EACCES_STALE;
	}
	if ( response->next_update < ( time - TIMESTAMP_ERROR_MARGIN ) ) {
		DBGC ( ocsp, "OCSP %p \"%s\" response is stale (at time "
		       "%lld)\n", ocsp, x509_name ( ocsp->cert ), time );
		return -EACCES_STALE;
	}
	DBGC2 ( ocsp, "OCSP %p \"%s\" response is valid (at time %lld)\n",
		ocsp, x509_name ( ocsp->cert ), time );

	/* Mark certificate as passing OCSP verification */
	ocsp->cert->extensions.auth_info.ocsp.good = 1;

	/* Validate certificate against issuer */
	if ( ( rc = x509_validate ( ocsp->cert, ocsp->issuer, time,
				    &ocsp_root ) ) != 0 ) {
		DBGC ( ocsp, "OCSP %p \"%s\" could not validate certificate: "
		       "%s\n", ocsp, x509_name ( ocsp->cert ), strerror ( rc ));
		return rc;
	}
	DBGC ( ocsp, "OCSP %p \"%s\" successfully validated ",
	       ocsp, x509_name ( ocsp->cert ) );
	DBGC ( ocsp, "using \"%s\"\n", x509_name ( signer ) );

	return 0;
}
