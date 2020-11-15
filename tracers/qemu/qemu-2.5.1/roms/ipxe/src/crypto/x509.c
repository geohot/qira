/*
 * Copyright (C) 2007 Michael Brown <mbrown@fensystems.co.uk>.
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/list.h>
#include <ipxe/base16.h>
#include <ipxe/asn1.h>
#include <ipxe/crypto.h>
#include <ipxe/md5.h>
#include <ipxe/sha1.h>
#include <ipxe/sha256.h>
#include <ipxe/rsa.h>
#include <ipxe/rootcert.h>
#include <ipxe/certstore.h>
#include <ipxe/socket.h>
#include <ipxe/in.h>
#include <ipxe/x509.h>
#include <config/crypto.h>

/** @file
 *
 * X.509 certificates
 *
 * The structure of X.509v3 certificates is documented in RFC 5280
 * section 4.1.
 */

/* Disambiguate the various error causes */
#define ENOTSUP_ALGORITHM \
	__einfo_error ( EINFO_ENOTSUP_ALGORITHM )
#define EINFO_ENOTSUP_ALGORITHM \
	__einfo_uniqify ( EINFO_ENOTSUP, 0x01, "Unsupported algorithm" )
#define ENOTSUP_EXTENSION \
	__einfo_error ( EINFO_ENOTSUP_EXTENSION )
#define EINFO_ENOTSUP_EXTENSION \
	__einfo_uniqify ( EINFO_ENOTSUP, 0x02, "Unsupported extension" )
#define EINVAL_ALGORITHM \
	__einfo_error ( EINFO_EINVAL_ALGORITHM )
#define EINFO_EINVAL_ALGORITHM \
	__einfo_uniqify ( EINFO_EINVAL, 0x01, "Invalid algorithm type" )
#define EINVAL_ALGORITHM_MISMATCH \
	__einfo_error ( EINFO_EINVAL_ALGORITHM_MISMATCH )
#define EINFO_EINVAL_ALGORITHM_MISMATCH \
	__einfo_uniqify ( EINFO_EINVAL, 0x04, "Signature algorithm mismatch" )
#define EINVAL_PATH_LEN \
	__einfo_error ( EINFO_EINVAL_PATH_LEN )
#define EINFO_EINVAL_PATH_LEN \
	__einfo_uniqify ( EINFO_EINVAL, 0x05, "Invalid pathLenConstraint" )
#define EINVAL_VERSION \
	__einfo_error ( EINFO_EINVAL_VERSION )
#define EINFO_EINVAL_VERSION \
	__einfo_uniqify ( EINFO_EINVAL, 0x06, "Invalid version" )
#define EACCES_WRONG_ISSUER \
	__einfo_error ( EINFO_EACCES_WRONG_ISSUER )
#define EINFO_EACCES_WRONG_ISSUER \
	__einfo_uniqify ( EINFO_EACCES, 0x01, "Wrong issuer" )
#define EACCES_NOT_CA \
	__einfo_error ( EINFO_EACCES_NOT_CA )
#define EINFO_EACCES_NOT_CA \
	__einfo_uniqify ( EINFO_EACCES, 0x02, "Not a CA certificate" )
#define EACCES_KEY_USAGE \
	__einfo_error ( EINFO_EACCES_KEY_USAGE )
#define EINFO_EACCES_KEY_USAGE \
	__einfo_uniqify ( EINFO_EACCES, 0x03, "Incorrect key usage" )
#define EACCES_EXPIRED \
	__einfo_error ( EINFO_EACCES_EXPIRED )
#define EINFO_EACCES_EXPIRED \
	__einfo_uniqify ( EINFO_EACCES, 0x04, "Expired (or not yet valid)" )
#define EACCES_PATH_LEN \
	__einfo_error ( EINFO_EACCES_PATH_LEN )
#define EINFO_EACCES_PATH_LEN \
	__einfo_uniqify ( EINFO_EACCES, 0x05, "Maximum path length exceeded" )
#define EACCES_UNTRUSTED \
	__einfo_error ( EINFO_EACCES_UNTRUSTED )
#define EINFO_EACCES_UNTRUSTED \
	__einfo_uniqify ( EINFO_EACCES, 0x06, "Untrusted root certificate" )
#define EACCES_OUT_OF_ORDER \
	__einfo_error ( EINFO_EACCES_OUT_OF_ORDER )
#define EINFO_EACCES_OUT_OF_ORDER \
	__einfo_uniqify ( EINFO_EACCES, 0x07, "Validation out of order" )
#define EACCES_EMPTY \
	__einfo_error ( EINFO_EACCES_EMPTY )
#define EINFO_EACCES_EMPTY \
	__einfo_uniqify ( EINFO_EACCES, 0x08, "Empty certificate chain" )
#define EACCES_OCSP_REQUIRED \
	__einfo_error ( EINFO_EACCES_OCSP_REQUIRED )
#define EINFO_EACCES_OCSP_REQUIRED \
	__einfo_uniqify ( EINFO_EACCES, 0x09, "OCSP check required" )
#define EACCES_WRONG_NAME \
	__einfo_error ( EINFO_EACCES_WRONG_NAME )
#define EINFO_EACCES_WRONG_NAME \
	__einfo_uniqify ( EINFO_EACCES, 0x0a, "Incorrect certificate name" )
#define EACCES_USELESS \
	__einfo_error ( EINFO_EACCES_USELESS )
#define EINFO_EACCES_USELESS \
	__einfo_uniqify ( EINFO_EACCES, 0x0b, "No usable certificates" )

/**
 * Get X.509 certificate name (for debugging)
 *
 * @v cert		X.509 certificate
 * @ret name		Name (for debugging)
 */
const char * x509_name ( struct x509_certificate *cert ) {
	struct asn1_cursor *common_name = &cert->subject.common_name;
	struct digest_algorithm *digest = &sha1_algorithm;
	static char buf[64];
	uint8_t fingerprint[ digest->digestsize ];
	size_t len;

	len = common_name->len;
	if ( len ) {
		/* Certificate has a commonName: use that */
		if ( len > ( sizeof ( buf ) - 1 /* NUL */ ) )
			len = ( sizeof ( buf ) - 1 /* NUL */ );
		memcpy ( buf, common_name->data, len );
		buf[len] = '\0';
	} else {
		/* Certificate has no commonName: use SHA-1 fingerprint */
		x509_fingerprint ( cert, digest, fingerprint );
		base16_encode ( fingerprint, sizeof ( fingerprint ),
				buf, sizeof ( buf ) );
	}
	return buf;
}

/** "commonName" object identifier */
static uint8_t oid_common_name[] = { ASN1_OID_COMMON_NAME };

/** "commonName" object identifier cursor */
static struct asn1_cursor oid_common_name_cursor =
	ASN1_OID_CURSOR ( oid_common_name );

/**
 * Parse X.509 certificate version
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_version ( struct x509_certificate *cert,
				const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	int version;
	int rc;

	/* Enter version */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_EXPLICIT_TAG ( 0 ) );

	/* Parse integer */
	if ( ( rc = asn1_integer ( &cursor, &version ) ) != 0 ) {
		DBGC ( cert, "X509 %p cannot parse version: %s\n",
		       cert, strerror ( rc ) );
		DBGC_HDA ( cert, 0, raw->data, raw->len );
		return rc;
	}

	/* Sanity check */
	if ( version < 0 ) {
		DBGC ( cert, "X509 %p invalid version %d\n", cert, version );
		DBGC_HDA ( cert, 0, raw->data, raw->len );
		return -EINVAL_VERSION;
	}

	/* Record version */
	cert->version = version;
	DBGC2 ( cert, "X509 %p is a version %d certificate\n",
		cert, ( cert->version + 1 ) );

	return 0;
}

/**
 * Parse X.509 certificate serial number
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_serial ( struct x509_certificate *cert,
			       const struct asn1_cursor *raw ) {
	struct x509_serial *serial = &cert->serial;
	int rc;

	/* Record raw serial number */
	memcpy ( &serial->raw, raw, sizeof ( serial->raw ) );
	if ( ( rc = asn1_shrink ( &serial->raw, ASN1_INTEGER ) ) != 0 ) {
		DBGC ( cert, "X509 %p cannot shrink serialNumber: %s\n",
		       cert, strerror ( rc ) );
		return rc;
	}
	DBGC2 ( cert, "X509 %p issuer is:\n", cert );
	DBGC2_HDA ( cert, 0, serial->raw.data, serial->raw.len );

	return 0;
}

/**
 * Parse X.509 certificate issuer
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_issuer ( struct x509_certificate *cert,
			       const struct asn1_cursor *raw ) {
	struct x509_issuer *issuer = &cert->issuer;
	int rc;

	/* Record raw issuer */
	memcpy ( &issuer->raw, raw, sizeof ( issuer->raw ) );
	if ( ( rc = asn1_shrink ( &issuer->raw, ASN1_SEQUENCE ) ) != 0 ) {
		DBGC ( cert, "X509 %p cannot shrink issuer: %s\n",
		       cert, strerror ( rc ) );
		return rc;
	}
	DBGC2 ( cert, "X509 %p issuer is:\n", cert );
	DBGC2_HDA ( cert, 0, issuer->raw.data, issuer->raw.len );

	return 0;
}

/**
 * Parse X.509 certificate validity
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_validity ( struct x509_certificate *cert,
				 const struct asn1_cursor *raw ) {
	struct x509_validity *validity = &cert->validity;
	struct x509_time *not_before = &validity->not_before;
	struct x509_time *not_after = &validity->not_after;
	struct asn1_cursor cursor;
	int rc;

	/* Enter validity */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Parse notBefore */
	if ( ( rc = asn1_generalized_time ( &cursor,
					    &not_before->time ) ) != 0 ) {
		DBGC ( cert, "X509 %p cannot parse notBefore: %s\n",
		       cert, strerror ( rc ) );
		return rc;
	}
	DBGC2 ( cert, "X509 %p valid from time %lld\n",
		cert, not_before->time );
	asn1_skip_any ( &cursor );

	/* Parse notAfter */
	if ( ( rc = asn1_generalized_time ( &cursor,
					    &not_after->time ) ) != 0 ) {
		DBGC ( cert, "X509 %p cannot parse notAfter: %s\n",
		       cert, strerror ( rc ) );
		return rc;
	}
	DBGC2 ( cert, "X509 %p valid until time %lld\n",
		cert, not_after->time );

	return 0;
}

/**
 * Parse X.509 certificate common name
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_common_name ( struct x509_certificate *cert,
				    const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	struct asn1_cursor oid_cursor;
	struct asn1_cursor name_cursor;
	int rc;

	/* Enter name */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Scan through name list */
	for ( ; cursor.len ; asn1_skip_any ( &cursor ) ) {

		/* Check for "commonName" OID */
		memcpy ( &oid_cursor, &cursor, sizeof ( oid_cursor ) );
		asn1_enter ( &oid_cursor, ASN1_SET );
		asn1_enter ( &oid_cursor, ASN1_SEQUENCE );
		memcpy ( &name_cursor, &oid_cursor, sizeof ( name_cursor ) );
		asn1_enter ( &oid_cursor, ASN1_OID );
		if ( asn1_compare ( &oid_common_name_cursor, &oid_cursor ) != 0)
			continue;
		asn1_skip_any ( &name_cursor );
		if ( ( rc = asn1_enter_any ( &name_cursor ) ) != 0 ) {
			DBGC ( cert, "X509 %p cannot locate name:\n", cert );
			DBGC_HDA ( cert, 0, raw->data, raw->len );
			return rc;
		}

		/* Record common name */
		memcpy ( &cert->subject.common_name, &name_cursor,
			 sizeof ( cert->subject.common_name ) );

		return 0;
	}

	/* Certificates may not have a commonName */
	DBGC2 ( cert, "X509 %p no commonName found:\n", cert );
	return 0;
}

/**
 * Parse X.509 certificate subject
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_subject ( struct x509_certificate *cert,
				const struct asn1_cursor *raw ) {
	struct x509_subject *subject = &cert->subject;
	int rc;

	/* Record raw subject */
	memcpy ( &subject->raw, raw, sizeof ( subject->raw ) );
	asn1_shrink_any ( &subject->raw );
	DBGC2 ( cert, "X509 %p subject is:\n", cert );
	DBGC2_HDA ( cert, 0, subject->raw.data, subject->raw.len );

	/* Parse common name */
	if ( ( rc = x509_parse_common_name ( cert, raw ) ) != 0 )
		return rc;
	DBGC2 ( cert, "X509 %p common name is \"%s\":\n", cert,
		x509_name ( cert ) );

	return 0;
}

/**
 * Parse X.509 certificate public key information
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_public_key ( struct x509_certificate *cert,
				   const struct asn1_cursor *raw ) {
	struct x509_public_key *public_key = &cert->subject.public_key;
	struct asn1_algorithm **algorithm = &public_key->algorithm;
	struct asn1_bit_string *raw_bits = &public_key->raw_bits;
	struct asn1_cursor cursor;
	int rc;

	/* Record raw subjectPublicKeyInfo */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_shrink_any ( &cursor );
	memcpy ( &public_key->raw, &cursor, sizeof ( public_key->raw ) );
	DBGC2 ( cert, "X509 %p public key is:\n", cert );
	DBGC2_HDA ( cert, 0, public_key->raw.data, public_key->raw.len );

	/* Enter subjectPublicKeyInfo */
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Parse algorithm */
	if ( ( rc = asn1_pubkey_algorithm ( &cursor, algorithm ) ) != 0 ) {
		DBGC ( cert, "X509 %p could not parse public key algorithm: "
		       "%s\n", cert, strerror ( rc ) );
		return rc;
	}
	DBGC2 ( cert, "X509 %p public key algorithm is %s\n",
		cert, (*algorithm)->name );
	asn1_skip_any ( &cursor );

	/* Parse bit string */
	if ( ( rc = asn1_bit_string ( &cursor, raw_bits ) ) != 0 ) {
		DBGC ( cert, "X509 %p could not parse public key bits: %s\n",
		       cert, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Parse X.509 certificate basic constraints
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_basic_constraints ( struct x509_certificate *cert,
					  const struct asn1_cursor *raw ) {
	struct x509_basic_constraints *basic = &cert->extensions.basic;
	struct asn1_cursor cursor;
	int ca = 0;
	int path_len;
	int rc;

	/* Enter basicConstraints */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Parse "cA", if present */
	if ( asn1_type ( &cursor ) == ASN1_BOOLEAN ) {
		ca = asn1_boolean ( &cursor );
		if ( ca < 0 ) {
			rc = ca;
			DBGC ( cert, "X509 %p cannot parse cA: %s\n",
			       cert, strerror ( rc ) );
			DBGC_HDA ( cert, 0, raw->data, raw->len );
			return rc;
		}
		asn1_skip_any ( &cursor );
	}
	basic->ca = ca;
	DBGC2 ( cert, "X509 %p is %sa CA certificate\n",
		cert, ( basic->ca ? "" : "not " ) );

	/* Ignore everything else unless "cA" is true */
	if ( ! ca )
		return 0;

	/* Parse "pathLenConstraint", if present and applicable */
	basic->path_len = X509_PATH_LEN_UNLIMITED;
	if ( asn1_type ( &cursor ) == ASN1_INTEGER ) {
		if ( ( rc = asn1_integer ( &cursor, &path_len ) ) != 0 ) {
			DBGC ( cert, "X509 %p cannot parse pathLenConstraint: "
			       "%s\n", cert, strerror ( rc ) );
			DBGC_HDA ( cert, 0, raw->data, raw->len );
			return rc;
		}
		if ( path_len < 0 ) {
			DBGC ( cert, "X509 %p invalid pathLenConstraint %d\n",
			       cert, path_len );
			DBGC_HDA ( cert, 0, raw->data, raw->len );
			return -EINVAL;
		}
		basic->path_len = path_len;
		DBGC2 ( cert, "X509 %p path length constraint is %d\n",
			cert, basic->path_len );
	}

	return 0;
}

/**
 * Parse X.509 certificate key usage
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_key_usage ( struct x509_certificate *cert,
				  const struct asn1_cursor *raw ) {
	struct x509_key_usage *usage = &cert->extensions.usage;
	struct asn1_bit_string bit_string;
	const uint8_t *bytes;
	size_t len;
	unsigned int i;
	int rc;

	/* Mark extension as present */
	usage->present = 1;

	/* Parse bit string */
	if ( ( rc = asn1_bit_string ( raw, &bit_string ) ) != 0 ) {
		DBGC ( cert, "X509 %p could not parse key usage: %s\n",
		       cert, strerror ( rc ) );
		return rc;
	}

	/* Parse key usage bits */
	bytes = bit_string.data;
	len = bit_string.len;
	if ( len > sizeof ( usage->bits ) )
		len = sizeof ( usage->bits );
	for ( i = 0 ; i < len ; i++ ) {
		usage->bits |= ( *(bytes++) << ( 8 * i ) );
	}
	DBGC2 ( cert, "X509 %p key usage is %08x\n", cert, usage->bits );

	return 0;
}

/** "id-kp-codeSigning" object identifier */
static uint8_t oid_code_signing[] = { ASN1_OID_CODESIGNING };

/** "id-kp-OCSPSigning" object identifier */
static uint8_t oid_ocsp_signing[] = { ASN1_OID_OCSPSIGNING };

/** Supported key purposes */
static struct x509_key_purpose x509_key_purposes[] = {
	{
		.name = "codeSigning",
		.bits = X509_CODE_SIGNING,
		.oid = ASN1_OID_CURSOR ( oid_code_signing ),
	},
	{
		.name = "ocspSigning",
		.bits = X509_OCSP_SIGNING,
		.oid = ASN1_OID_CURSOR ( oid_ocsp_signing ),
	},
};

/**
 * Parse X.509 certificate key purpose identifier
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_key_purpose ( struct x509_certificate *cert,
				    const struct asn1_cursor *raw ) {
	struct x509_extended_key_usage *ext_usage = &cert->extensions.ext_usage;
	struct x509_key_purpose *purpose;
	struct asn1_cursor cursor;
	unsigned int i;
	int rc;

	/* Enter keyPurposeId */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	if ( ( rc = asn1_enter ( &cursor, ASN1_OID ) ) != 0 ) {
		DBGC ( cert, "X509 %p invalid keyPurposeId:\n", cert );
		DBGC_HDA ( cert, 0, raw->data, raw->len );
		return rc;
	}

	/* Identify key purpose */
	for ( i = 0 ; i < ( sizeof ( x509_key_purposes ) /
			    sizeof ( x509_key_purposes[0] ) ) ; i++ ) {
		purpose = &x509_key_purposes[i];
		if ( asn1_compare ( &cursor, &purpose->oid ) == 0 ) {
			DBGC2 ( cert, "X509 %p has key purpose %s\n",
				cert, purpose->name );
			ext_usage->bits |= purpose->bits;
			return 0;
		}
	}

	/* Ignore unrecognised key purposes */
	return 0;
}

/**
 * Parse X.509 certificate extended key usage
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_extended_key_usage ( struct x509_certificate *cert,
					   const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	int rc;

	/* Enter extKeyUsage */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Parse each extended key usage in turn */
	while ( cursor.len ) {
		if ( ( rc = x509_parse_key_purpose ( cert, &cursor ) ) != 0 )
			return rc;
		asn1_skip_any ( &cursor );
	}

	return 0;
}

/**
 * Parse X.509 certificate OCSP access method
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_ocsp ( struct x509_certificate *cert,
			     const struct asn1_cursor *raw ) {
	struct x509_ocsp_responder *ocsp = &cert->extensions.auth_info.ocsp;
	struct asn1_cursor *uri = &ocsp->uri;
	int rc;

	/* Enter accessLocation */
	memcpy ( uri, raw, sizeof ( *uri ) );
	if ( ( rc = asn1_enter ( uri, X509_GENERAL_NAME_URI ) ) != 0 ) {
		DBGC ( cert, "X509 %p OCSP does not contain "
		       "uniformResourceIdentifier:\n", cert );
		DBGC_HDA ( cert, 0, raw->data, raw->len );
		return rc;
	}
	DBGC2 ( cert, "X509 %p OCSP URI is:\n", cert );
	DBGC2_HDA ( cert, 0, uri->data, uri->len );

	return 0;
}

/** "id-ad-ocsp" object identifier */
static uint8_t oid_ad_ocsp[] = { ASN1_OID_OCSP };

/** Supported access methods */
static struct x509_access_method x509_access_methods[] = {
	{
		.name = "OCSP",
		.oid = ASN1_OID_CURSOR ( oid_ad_ocsp ),
		.parse = x509_parse_ocsp,
	},
};

/**
 * Identify X.509 access method by OID
 *
 * @v oid		OID
 * @ret method		Access method, or NULL
 */
static struct x509_access_method *
x509_find_access_method ( const struct asn1_cursor *oid ) {
	struct x509_access_method *method;
	unsigned int i;

	for ( i = 0 ; i < ( sizeof ( x509_access_methods ) /
			    sizeof ( x509_access_methods[0] ) ) ; i++ ) {
		method = &x509_access_methods[i];
		if ( asn1_compare ( &method->oid, oid ) == 0 )
			return method;
	}

	return NULL;
}

/**
 * Parse X.509 certificate access description
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_access_description ( struct x509_certificate *cert,
					   const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	struct asn1_cursor subcursor;
	struct x509_access_method *method;
	int rc;

	/* Enter keyPurposeId */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Try to identify access method */
	memcpy ( &subcursor, &cursor, sizeof ( subcursor ) );
	asn1_enter ( &subcursor, ASN1_OID );
	method = x509_find_access_method ( &subcursor );
	asn1_skip_any ( &cursor );
	DBGC2 ( cert, "X509 %p found access method %s\n",
		cert, ( method ? method->name : "<unknown>" ) );

	/* Parse access location, if applicable */
	if ( method && ( ( rc = method->parse ( cert, &cursor ) ) != 0 ) )
		return rc;

	return 0;
}

/**
 * Parse X.509 certificate authority information access
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_authority_info_access ( struct x509_certificate *cert,
					      const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	int rc;

	/* Enter authorityInfoAccess */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Parse each access description in turn */
	while ( cursor.len ) {
		if ( ( rc = x509_parse_access_description ( cert,
							    &cursor ) ) != 0 )
			return rc;
		asn1_skip_any ( &cursor );
	}

	return 0;
}

/**
 * Parse X.509 certificate subject alternative name
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_subject_alt_name ( struct x509_certificate *cert,
					 const struct asn1_cursor *raw ) {
	struct x509_subject_alt_name *alt_name = &cert->extensions.alt_name;
	struct asn1_cursor *names = &alt_name->names;
	int rc;

	/* Enter subjectAltName */
	memcpy ( names, raw, sizeof ( *names ) );
	if ( ( rc = asn1_enter ( names, ASN1_SEQUENCE ) ) != 0 ) {
		DBGC ( cert, "X509 %p invalid subjectAltName: %s\n",
		       cert, strerror ( rc ) );
		DBGC_HDA ( cert, 0, raw->data, raw->len );
		return rc;
	}
	DBGC2 ( cert, "X509 %p has subjectAltName:\n", cert );
	DBGC2_HDA ( cert, 0, names->data, names->len );

	return 0;
}

/** "id-ce-basicConstraints" object identifier */
static uint8_t oid_ce_basic_constraints[] =
	{ ASN1_OID_BASICCONSTRAINTS };

/** "id-ce-keyUsage" object identifier */
static uint8_t oid_ce_key_usage[] =
	{ ASN1_OID_KEYUSAGE };

/** "id-ce-extKeyUsage" object identifier */
static uint8_t oid_ce_ext_key_usage[] =
	{ ASN1_OID_EXTKEYUSAGE };

/** "id-pe-authorityInfoAccess" object identifier */
static uint8_t oid_pe_authority_info_access[] =
	{ ASN1_OID_AUTHORITYINFOACCESS };

/** "id-ce-subjectAltName" object identifier */
static uint8_t oid_ce_subject_alt_name[] =
	{ ASN1_OID_SUBJECTALTNAME };

/** Supported certificate extensions */
static struct x509_extension x509_extensions[] = {
	{
		.name = "basicConstraints",
		.oid = ASN1_OID_CURSOR ( oid_ce_basic_constraints ),
		.parse = x509_parse_basic_constraints,
	},
	{
		.name = "keyUsage",
		.oid = ASN1_OID_CURSOR ( oid_ce_key_usage ),
		.parse = x509_parse_key_usage,
	},
	{
		.name = "extKeyUsage",
		.oid = ASN1_OID_CURSOR ( oid_ce_ext_key_usage ),
		.parse = x509_parse_extended_key_usage,
	},
	{
		.name = "authorityInfoAccess",
		.oid = ASN1_OID_CURSOR ( oid_pe_authority_info_access ),
		.parse = x509_parse_authority_info_access,
	},
	{
		.name = "subjectAltName",
		.oid = ASN1_OID_CURSOR ( oid_ce_subject_alt_name ),
		.parse = x509_parse_subject_alt_name,
	},
};

/**
 * Identify X.509 extension by OID
 *
 * @v oid		OID
 * @ret extension	Extension, or NULL
 */
static struct x509_extension *
x509_find_extension ( const struct asn1_cursor *oid ) {
	struct x509_extension *extension;
	unsigned int i;

	for ( i = 0 ; i < ( sizeof ( x509_extensions ) /
			    sizeof ( x509_extensions[0] ) ) ; i++ ) {
		extension = &x509_extensions[i];
		if ( asn1_compare ( &extension->oid, oid ) == 0 )
			return extension;
	}

	return NULL;
}

/**
 * Parse X.509 certificate extension
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_extension ( struct x509_certificate *cert,
				  const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	struct asn1_cursor subcursor;
	struct x509_extension *extension;
	int is_critical = 0;
	int rc;

	/* Enter extension */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Try to identify extension */
	memcpy ( &subcursor, &cursor, sizeof ( subcursor ) );
	asn1_enter ( &subcursor, ASN1_OID );
	extension = x509_find_extension ( &subcursor );
	asn1_skip_any ( &cursor );
	DBGC2 ( cert, "X509 %p found extension %s\n",
		cert, ( extension ? extension->name : "<unknown>" ) );

	/* Identify criticality */
	if ( asn1_type ( &cursor ) == ASN1_BOOLEAN ) {
		is_critical = asn1_boolean ( &cursor );
		if ( is_critical < 0 ) {
			rc = is_critical;
			DBGC ( cert, "X509 %p cannot parse extension "
			       "criticality: %s\n", cert, strerror ( rc ) );
			DBGC_HDA ( cert, 0, raw->data, raw->len );
			return rc;
		}
		asn1_skip_any ( &cursor );
	}

	/* Handle unknown extensions */
	if ( ! extension ) {
		if ( is_critical ) {
			/* Fail if we cannot handle a critical extension */
			DBGC ( cert, "X509 %p cannot handle critical "
			       "extension:\n", cert );
			DBGC_HDA ( cert, 0, raw->data, raw->len );
			return -ENOTSUP_EXTENSION;
		} else {
			/* Ignore unknown non-critical extensions */
			return 0;
		}
	};

	/* Extract extnValue */
	if ( ( rc = asn1_enter ( &cursor, ASN1_OCTET_STRING ) ) != 0 ) {
		DBGC ( cert, "X509 %p extension missing extnValue:\n", cert );
		DBGC_HDA ( cert, 0, raw->data, raw->len );
		return rc;
	}

	/* Parse extension */
	if ( ( rc = extension->parse ( cert, &cursor ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Parse X.509 certificate extensions, if present
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_extensions ( struct x509_certificate *cert,
				   const struct asn1_cursor *raw ) {
	struct asn1_cursor cursor;
	int rc;

	/* Enter extensions, if present */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_EXPLICIT_TAG ( 3 ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Parse each extension in turn */
	while ( cursor.len ) {
		if ( ( rc = x509_parse_extension ( cert, &cursor ) ) != 0 )
			return rc;
		asn1_skip_any ( &cursor );
	}

	return 0;
}

/**
 * Parse X.509 certificate tbsCertificate
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int x509_parse_tbscertificate ( struct x509_certificate *cert,
				       const struct asn1_cursor *raw ) {
	struct asn1_algorithm **algorithm = &cert->signature_algorithm;
	struct asn1_cursor cursor;
	int rc;

	/* Record raw tbsCertificate */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_shrink_any ( &cursor );
	memcpy ( &cert->tbs, &cursor, sizeof ( cert->tbs ) );

	/* Enter tbsCertificate */
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Parse version, if present */
	if ( asn1_type ( &cursor ) == ASN1_EXPLICIT_TAG ( 0 ) ) {
		if ( ( rc = x509_parse_version ( cert, &cursor ) ) != 0 )
			return rc;
		asn1_skip_any ( &cursor );
	}

	/* Parse serialNumber */
	if ( ( rc = x509_parse_serial ( cert, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Parse signature */
	if ( ( rc = asn1_signature_algorithm ( &cursor, algorithm ) ) != 0 ) {
		DBGC ( cert, "X509 %p could not parse signature algorithm: "
		       "%s\n", cert, strerror ( rc ) );
		return rc;
	}
	DBGC2 ( cert, "X509 %p tbsCertificate signature algorithm is %s\n",
		cert, (*algorithm)->name );
	asn1_skip_any ( &cursor );

	/* Parse issuer */
	if ( ( rc = x509_parse_issuer ( cert, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Parse validity */
	if ( ( rc = x509_parse_validity ( cert, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Parse subject */
	if ( ( rc = x509_parse_subject ( cert, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Parse subjectPublicKeyInfo */
	if ( ( rc = x509_parse_public_key ( cert, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Parse extensions, if present */
	if ( ( rc = x509_parse_extensions ( cert, &cursor ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Parse X.509 certificate from ASN.1 data
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
int x509_parse ( struct x509_certificate *cert,
		 const struct asn1_cursor *raw ) {
	struct x509_signature *signature = &cert->signature;
	struct asn1_algorithm **signature_algorithm = &signature->algorithm;
	struct asn1_bit_string *signature_value = &signature->value;
	struct asn1_cursor cursor;
	int rc;

	/* Record raw certificate */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	memcpy ( &cert->raw, &cursor, sizeof ( cert->raw ) );

	/* Enter certificate */
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Parse tbsCertificate */
	if ( ( rc = x509_parse_tbscertificate ( cert, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Parse signatureAlgorithm */
	if ( ( rc = asn1_signature_algorithm ( &cursor,
					       signature_algorithm ) ) != 0 ) {
		DBGC ( cert, "X509 %p could not parse signature algorithm: "
		       "%s\n", cert, strerror ( rc ) );
		return rc;
	}
	DBGC2 ( cert, "X509 %p signatureAlgorithm is %s\n",
		cert, (*signature_algorithm)->name );
	asn1_skip_any ( &cursor );

	/* Parse signatureValue */
	if ( ( rc = asn1_integral_bit_string ( &cursor,
					       signature_value ) ) != 0 ) {
		DBGC ( cert, "X509 %p could not parse signature value: %s\n",
		       cert, strerror ( rc ) );
		return rc;
	}
	DBGC2 ( cert, "X509 %p signatureValue is:\n", cert );
	DBGC2_HDA ( cert, 0, signature_value->data, signature_value->len );

	/* Check that algorithm in tbsCertificate matches algorithm in
	 * signature
	 */
	if ( signature->algorithm != (*signature_algorithm) ) {
		DBGC ( cert, "X509 %p signature algorithm %s does not match "
		       "signatureAlgorithm %s\n",
		       cert, signature->algorithm->name,
		       (*signature_algorithm)->name );
		return -EINVAL_ALGORITHM_MISMATCH;
	}

	return 0;
}

/**
 * Create X.509 certificate
 *
 * @v data		Raw certificate data
 * @v len		Length of raw data
 * @ret cert		X.509 certificate
 * @ret rc		Return status code
 *
 * On success, the caller holds a reference to the X.509 certificate,
 * and is responsible for ultimately calling x509_put().
 */
int x509_certificate ( const void *data, size_t len,
		       struct x509_certificate **cert ) {
	struct asn1_cursor cursor;
	void *raw;
	int rc;

	/* Initialise cursor */
	cursor.data = data;
	cursor.len = len;
	asn1_shrink_any ( &cursor );

	/* Return stored certificate, if present */
	if ( ( *cert = certstore_find ( &cursor ) ) != NULL ) {

		/* Add caller's reference */
		x509_get ( *cert );
		return 0;
	}

	/* Allocate and initialise certificate */
	*cert = zalloc ( sizeof ( **cert ) + cursor.len );
	if ( ! *cert )
		return -ENOMEM;
	ref_init ( &(*cert)->refcnt, NULL );
	raw = ( *cert + 1 );

	/* Copy raw data */
	memcpy ( raw, cursor.data, cursor.len );
	cursor.data = raw;

	/* Parse certificate */
	if ( ( rc = x509_parse ( *cert, &cursor ) ) != 0 ) {
		x509_put ( *cert );
		*cert = NULL;
		return rc;
	}

	/* Add certificate to store */
	certstore_add ( *cert );

	return 0;
}

/**
 * Check X.509 certificate signature
 *
 * @v cert		X.509 certificate
 * @v public_key	X.509 public key
 * @ret rc		Return status code
 */
static int x509_check_signature ( struct x509_certificate *cert,
				  struct x509_public_key *public_key ) {
	struct x509_signature *signature = &cert->signature;
	struct asn1_algorithm *algorithm = signature->algorithm;
	struct digest_algorithm *digest = algorithm->digest;
	struct pubkey_algorithm *pubkey = algorithm->pubkey;
	uint8_t digest_ctx[ digest->ctxsize ];
	uint8_t digest_out[ digest->digestsize ];
	uint8_t pubkey_ctx[ pubkey->ctxsize ];
	int rc;

	/* Sanity check */
	assert ( cert->signature_algorithm == cert->signature.algorithm );

	/* Calculate certificate digest */
	digest_init ( digest, digest_ctx );
	digest_update ( digest, digest_ctx, cert->tbs.data, cert->tbs.len );
	digest_final ( digest, digest_ctx, digest_out );
	DBGC2 ( cert, "X509 %p \"%s\" digest:\n", cert, x509_name ( cert ) );
	DBGC2_HDA ( cert, 0, digest_out, sizeof ( digest_out ) );

	/* Check that signature public key algorithm matches signer */
	if ( public_key->algorithm->pubkey != pubkey ) {
		DBGC ( cert, "X509 %p \"%s\" signature algorithm %s does not "
		       "match signer's algorithm %s\n",
		       cert, x509_name ( cert ), algorithm->name,
		       public_key->algorithm->name );
		rc = -EINVAL_ALGORITHM_MISMATCH;
		goto err_mismatch;
	}

	/* Verify signature using signer's public key */
	if ( ( rc = pubkey_init ( pubkey, pubkey_ctx, public_key->raw.data,
				  public_key->raw.len ) ) != 0 ) {
		DBGC ( cert, "X509 %p \"%s\" cannot initialise public key: "
		       "%s\n", cert, x509_name ( cert ), strerror ( rc ) );
		goto err_pubkey_init;
	}
	if ( ( rc = pubkey_verify ( pubkey, pubkey_ctx, digest, digest_out,
				    signature->value.data,
				    signature->value.len ) ) != 0 ) {
		DBGC ( cert, "X509 %p \"%s\" signature verification failed: "
		       "%s\n", cert, x509_name ( cert ), strerror ( rc ) );
		goto err_pubkey_verify;
	}

	/* Success */
	rc = 0;

 err_pubkey_verify:
	pubkey_final ( pubkey, pubkey_ctx );
 err_pubkey_init:
 err_mismatch:
	return rc;
}

/**
 * Check X.509 certificate against issuer certificate
 *
 * @v cert		X.509 certificate
 * @v issuer		X.509 issuer certificate
 * @ret rc		Return status code
 */
int x509_check_issuer ( struct x509_certificate *cert,
			struct x509_certificate *issuer ) {
	struct x509_public_key *public_key = &issuer->subject.public_key;
	int rc;

	/* Check issuer.  In theory, this should be a full X.500 DN
	 * comparison, which would require support for a plethora of
	 * abominations such as TeletexString (which allows the
	 * character set to be changed mid-string using escape codes).
	 * In practice, we assume that anyone who deliberately changes
	 * the encoding of the issuer DN is probably a masochist who
	 * will rather enjoy the process of figuring out exactly why
	 * their certificate doesn't work.
	 *
	 * See http://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt
	 * for some enjoyable ranting on this subject.
	 */
	if ( asn1_compare ( &cert->issuer.raw, &issuer->subject.raw ) != 0 ) {
		DBGC ( cert, "X509 %p \"%s\" issuer does not match ",
		       cert, x509_name ( cert ) );
		DBGC ( cert, "X509 %p \"%s\" subject\n",
		       issuer, x509_name ( issuer ) );
		DBGC_HDA ( cert, 0, cert->issuer.raw.data,
			   cert->issuer.raw.len );
		DBGC_HDA ( issuer, 0, issuer->subject.raw.data,
			   issuer->subject.raw.len );
		return -EACCES_WRONG_ISSUER;
	}

	/* Check that issuer is allowed to sign certificates */
	if ( ! issuer->extensions.basic.ca ) {
		DBGC ( issuer, "X509 %p \"%s\" cannot sign ",
		       issuer, x509_name ( issuer ) );
		DBGC ( issuer, "X509 %p \"%s\": not a CA certificate\n",
		       cert, x509_name ( cert ) );
		return -EACCES_NOT_CA;
	}
	if ( issuer->extensions.usage.present &&
	     ( ! ( issuer->extensions.usage.bits & X509_KEY_CERT_SIGN ) ) ) {
		DBGC ( issuer, "X509 %p \"%s\" cannot sign ",
		       issuer, x509_name ( issuer ) );
		DBGC ( issuer, "X509 %p \"%s\": no keyCertSign usage\n",
		       cert, x509_name ( cert ) );
		return -EACCES_KEY_USAGE;
	}

	/* Check signature */
	if ( ( rc = x509_check_signature ( cert, public_key ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Calculate X.509 certificate fingerprint
 *
 * @v cert		X.509 certificate
 * @v digest		Digest algorithm
 * @v fingerprint	Fingerprint buffer
 */
void x509_fingerprint ( struct x509_certificate *cert,
			struct digest_algorithm *digest,
			void *fingerprint ) {
	uint8_t ctx[ digest->ctxsize ];

	/* Calculate fingerprint */
	digest_init ( digest, ctx );
	digest_update ( digest, ctx, cert->raw.data, cert->raw.len );
	digest_final ( digest, ctx, fingerprint );
}

/**
 * Check X.509 root certificate
 *
 * @v cert		X.509 certificate
 * @v root		X.509 root certificate list
 * @ret rc		Return status code
 */
int x509_check_root ( struct x509_certificate *cert, struct x509_root *root ) {
	struct digest_algorithm *digest = root->digest;
	uint8_t fingerprint[ digest->digestsize ];
	const uint8_t *root_fingerprint = root->fingerprints;
	unsigned int i;

	/* Calculate certificate fingerprint */
	x509_fingerprint ( cert, digest, fingerprint );

	/* Check fingerprint against all root certificates */
	for ( i = 0 ; i < root->count ; i++ ) {
		if ( memcmp ( fingerprint, root_fingerprint,
			      sizeof ( fingerprint ) ) == 0 ) {
			DBGC ( cert, "X509 %p \"%s\" is a root certificate\n",
			       cert, x509_name ( cert ) );
			return 0;
		}
		root_fingerprint += sizeof ( fingerprint );
	}

	DBGC2 ( cert, "X509 %p \"%s\" is not a root certificate\n",
		cert, x509_name ( cert ) );
	return -ENOENT;
}

/**
 * Check X.509 certificate validity period
 *
 * @v cert		X.509 certificate
 * @v time		Time at which to check certificate
 * @ret rc		Return status code
 */
int x509_check_time ( struct x509_certificate *cert, time_t time ) {
	struct x509_validity *validity = &cert->validity;

	/* Check validity period */
	if ( validity->not_before.time > ( time + TIMESTAMP_ERROR_MARGIN ) ) {
		DBGC ( cert, "X509 %p \"%s\" is not yet valid (at time %lld)\n",
		       cert, x509_name ( cert ), time );
		return -EACCES_EXPIRED;
	}
	if ( validity->not_after.time < ( time - TIMESTAMP_ERROR_MARGIN ) ) {
		DBGC ( cert, "X509 %p \"%s\" has expired (at time %lld)\n",
		       cert, x509_name ( cert ), time );
		return -EACCES_EXPIRED;
	}

	DBGC2 ( cert, "X509 %p \"%s\" is valid (at time %lld)\n",
		cert, x509_name ( cert ), time );
	return 0;
}

/**
 * Validate X.509 certificate
 *
 * @v cert		X.509 certificate
 * @v issuer		Issuing X.509 certificate (or NULL)
 * @v time		Time at which to validate certificate
 * @v root		Root certificate list, or NULL to use default
 * @ret rc		Return status code
 *
 * The issuing certificate must have already been validated.
 *
 * Validation results are cached: if a certificate has already been
 * successfully validated then @c issuer, @c time, and @c root will be
 * ignored.
 */
int x509_validate ( struct x509_certificate *cert,
		    struct x509_certificate *issuer,
		    time_t time, struct x509_root *root ) {
	unsigned int max_path_remaining;
	int rc;

	/* Use default root certificate store if none specified */
	if ( ! root )
		root = &root_certificates;

	/* Return success if certificate has already been validated */
	if ( cert->valid )
		return 0;

	/* Fail if certificate is invalid at specified time */
	if ( ( rc = x509_check_time ( cert, time ) ) != 0 )
		return rc;

	/* Succeed if certificate is a trusted root certificate */
	if ( x509_check_root ( cert, root ) == 0 ) {
		cert->valid = 1;
		cert->path_remaining = ( cert->extensions.basic.path_len + 1 );
		return 0;
	}

	/* Fail unless we have an issuer */
	if ( ! issuer ) {
		DBGC2 ( cert, "X509 %p \"%s\" has no issuer\n",
			cert, x509_name ( cert ) );
		return -EACCES_UNTRUSTED;
	}

	/* Fail unless issuer has already been validated */
	if ( ! issuer->valid ) {
		DBGC ( cert, "X509 %p \"%s\" ", cert, x509_name ( cert ) );
		DBGC ( cert, "issuer %p \"%s\" has not yet been validated\n",
		       issuer, x509_name ( issuer ) );
		return -EACCES_OUT_OF_ORDER;
	}

	/* Fail if issuing certificate cannot validate this certificate */
	if ( ( rc = x509_check_issuer ( cert, issuer ) ) != 0 )
		return rc;

	/* Fail if path length constraint is violated */
	if ( issuer->path_remaining == 0 ) {
		DBGC ( cert, "X509 %p \"%s\" ", cert, x509_name ( cert ) );
		DBGC ( cert, "issuer %p \"%s\" path length exceeded\n",
		       issuer, x509_name ( issuer ) );
		return -EACCES_PATH_LEN;
	}

	/* Fail if OCSP is required */
	if ( cert->extensions.auth_info.ocsp.uri.len &&
	     ( ! cert->extensions.auth_info.ocsp.good ) ) {
		DBGC ( cert, "X509 %p \"%s\" requires an OCSP check\n",
		       cert, x509_name ( cert ) );
		return -EACCES_OCSP_REQUIRED;
	}

	/* Calculate effective path length */
	cert->path_remaining = ( issuer->path_remaining - 1 );
	max_path_remaining = ( cert->extensions.basic.path_len + 1 );
	if ( cert->path_remaining > max_path_remaining )
		cert->path_remaining = max_path_remaining;

	/* Mark certificate as valid */
	cert->valid = 1;

	DBGC ( cert, "X509 %p \"%s\" successfully validated using ",
	       cert, x509_name ( cert ) );
	DBGC ( cert, "issuer %p \"%s\"\n", issuer, x509_name ( issuer ) );
	return 0;
}

/**
 * Check X.509 certificate alternative dNSName
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @v name		Name
 * @ret rc		Return status code
 */
static int x509_check_dnsname ( struct x509_certificate *cert,
				const struct asn1_cursor *raw,
				const char *name ) {
	const char *fullname = name;
	const char *dnsname = raw->data;
	size_t len = raw->len;

	/* Check for wildcards */
	if ( ( len >= 2 ) && ( dnsname[0] == '*' ) && ( dnsname[1] == '.' ) ) {

		/* Skip initial "*." */
		dnsname += 2;
		len -= 2;

		/* Skip initial portion of name to be tested */
		name = strchr ( name, '.' );
		if ( ! name )
			return -ENOENT;
		name++;
	}

	/* Compare names */
	if ( ! ( ( strlen ( name ) == len ) &&
		 ( memcmp ( name, dnsname, len ) == 0 ) ) )
		return -ENOENT;

	if ( name != fullname ) {
		DBGC2 ( cert, "X509 %p \"%s\" found wildcard match for "
			"\"*.%s\"\n", cert, x509_name ( cert ), name );
	}
	return 0;
}

/**
 * Check X.509 certificate alternative iPAddress
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @v name		Name
 * @ret rc		Return status code
 */
static int x509_check_ipaddress ( struct x509_certificate *cert,
				  const struct asn1_cursor *raw,
				  const char *name ) {
	struct sockaddr sa;
	sa_family_t family;
	const void *address;
	int rc;

	/* Determine address family */
	if ( raw->len == sizeof ( struct in_addr ) ) {
		struct sockaddr_in *sin = ( ( struct sockaddr_in * ) &sa );
		family = AF_INET;
		address = &sin->sin_addr;
	} else if ( raw->len == sizeof ( struct in6_addr ) ) {
		struct sockaddr_in6 *sin6 = ( ( struct sockaddr_in6 * ) &sa );
		family = AF_INET6;
		address = &sin6->sin6_addr;
	} else {
		DBGC ( cert, "X509 %p \"%s\" has iPAddress with unexpected "
		       "length %zd\n", cert, x509_name ( cert ), raw->len );
		DBGC_HDA ( cert, 0, raw->data, raw->len );
		return -EINVAL;
	}

	/* Attempt to convert name to a socket address */
	if ( ( rc = sock_aton ( name, &sa ) ) != 0 ) {
		DBGC2 ( cert, "X509 %p \"%s\" cannot parse \"%s\" as "
			"iPAddress: %s\n", cert, x509_name ( cert ), name,
			strerror ( rc ) );
		return rc;
	}
	if ( sa.sa_family != family )
		return -ENOENT;

	/* Compare addresses */
	if ( memcmp ( address, raw->data, raw->len ) != 0 )
		return -ENOENT;

	DBGC2 ( cert, "X509 %p \"%s\" found iPAddress match for \"%s\"\n",
		cert, x509_name ( cert ), sock_ntoa ( &sa ) );
	return 0;
}

/**
 * Check X.509 certificate alternative name
 *
 * @v cert		X.509 certificate
 * @v raw		ASN.1 cursor
 * @v name		Name
 * @ret rc		Return status code
 */
static int x509_check_alt_name ( struct x509_certificate *cert,
				 const struct asn1_cursor *raw,
				 const char *name ) {
	struct asn1_cursor alt_name;
	unsigned int type;

	/* Enter generalName */
	memcpy ( &alt_name, raw, sizeof ( alt_name ) );
	type = asn1_type ( &alt_name );
	asn1_enter_any ( &alt_name );

	/* Check this name */
	switch ( type ) {
	case X509_GENERAL_NAME_DNS :
		return x509_check_dnsname ( cert, &alt_name, name );
	case X509_GENERAL_NAME_IP :
		return x509_check_ipaddress ( cert, &alt_name, name );
	default:
		DBGC2 ( cert, "X509 %p \"%s\" unknown name of type %#02x:\n",
			cert, x509_name ( cert ), type );
		DBGC2_HDA ( cert, 0, alt_name.data, alt_name.len );
		return -ENOTSUP;
	}
}

/**
 * Check X.509 certificate name
 *
 * @v cert		X.509 certificate
 * @v name		Name
 * @ret rc		Return status code
 */
int x509_check_name ( struct x509_certificate *cert, const char *name ) {
	struct asn1_cursor *common_name = &cert->subject.common_name;
	struct asn1_cursor alt_name;
	int rc;

	/* Check commonName */
	if ( x509_check_dnsname ( cert, common_name, name ) == 0 ) {
		DBGC2 ( cert, "X509 %p \"%s\" commonName matches \"%s\"\n",
			cert, x509_name ( cert ), name );
		return 0;
	}

	/* Check any subjectAlternativeNames */
	memcpy ( &alt_name, &cert->extensions.alt_name.names,
		 sizeof ( alt_name ) );
	for ( ; alt_name.len ; asn1_skip_any ( &alt_name ) ) {
		if ( ( rc = x509_check_alt_name ( cert, &alt_name,
						  name ) ) == 0 ) {
			DBGC2 ( cert, "X509 %p \"%s\" subjectAltName matches "
				"\"%s\"\n", cert, x509_name ( cert ), name );
			return 0;
		}
	}

	DBGC ( cert, "X509 %p \"%s\" does not match name \"%s\"\n",
	       cert, x509_name ( cert ), name );
	return -EACCES_WRONG_NAME;
}

/**
 * Free X.509 certificate chain
 *
 * @v refcnt		Reference count
 */
static void x509_free_chain ( struct refcnt *refcnt ) {
	struct x509_chain *chain =
		container_of ( refcnt, struct x509_chain, refcnt );
	struct x509_link *link;
	struct x509_link *tmp;

	DBGC2 ( chain, "X509 chain %p freed\n", chain );

	/* Free each link in the chain */
	list_for_each_entry_safe ( link, tmp, &chain->links, list ) {
		x509_put ( link->cert );
		list_del ( &link->list );
		free ( link );
	}

	/* Free chain */
	free ( chain );
}

/**
 * Allocate X.509 certificate chain
 *
 * @ret chain		X.509 certificate chain, or NULL
 */
struct x509_chain * x509_alloc_chain ( void ) {
	struct x509_chain *chain;

	/* Allocate chain */
	chain = zalloc ( sizeof ( *chain ) );
	if ( ! chain )
		return NULL;

	/* Initialise chain */
	ref_init ( &chain->refcnt, x509_free_chain );
	INIT_LIST_HEAD ( &chain->links );

	DBGC2 ( chain, "X509 chain %p allocated\n", chain );
	return chain;
}

/**
 * Append X.509 certificate to X.509 certificate chain
 *
 * @v chain		X.509 certificate chain
 * @v cert		X.509 certificate
 * @ret rc		Return status code
 */
int x509_append ( struct x509_chain *chain, struct x509_certificate *cert ) {
	struct x509_link *link;

	/* Allocate link */
	link = zalloc ( sizeof ( *link ) );
	if ( ! link )
		return -ENOMEM;

	/* Add link to chain */
	link->cert = x509_get ( cert );
	list_add_tail ( &link->list, &chain->links );
	DBGC ( chain, "X509 chain %p added X509 %p \"%s\"\n",
	       chain, cert, x509_name ( cert ) );

	return 0;
}

/**
 * Append X.509 certificate to X.509 certificate chain
 *
 * @v chain		X.509 certificate chain
 * @v data		Raw certificate data
 * @v len		Length of raw data
 * @ret rc		Return status code
 */
int x509_append_raw ( struct x509_chain *chain, const void *data,
		      size_t len ) {
	struct x509_certificate *cert;
	int rc;

	/* Parse certificate */
	if ( ( rc = x509_certificate ( data, len, &cert ) ) != 0 )
		goto err_parse;

	/* Append certificate to chain */
	if ( ( rc = x509_append ( chain, cert ) ) != 0 )
		goto err_append;

	/* Drop reference to certificate */
	x509_put ( cert );

	return 0;

 err_append:
	x509_put ( cert );
 err_parse:
	return rc;
}

/**
 * Identify X.509 certificate by subject
 *
 * @v certs		X.509 certificate list
 * @v subject		Subject
 * @ret cert		X.509 certificate, or NULL if not found
 */
static struct x509_certificate *
x509_find_subject ( struct x509_chain *certs,
		    const struct asn1_cursor *subject ) {
	struct x509_link *link;
	struct x509_certificate *cert;

	/* Scan through certificate list */
	list_for_each_entry ( link, &certs->links, list ) {

		/* Check subject */
		cert = link->cert;
		if ( asn1_compare ( subject, &cert->subject.raw ) == 0 )
			return cert;
	}

	return NULL;
}

/**
 * Append X.509 certificates to X.509 certificate chain
 *
 * @v chain		X.509 certificate chain
 * @v certs		X.509 certificate list
 * @ret rc		Return status code
 *
 * Certificates will be automatically appended to the chain based upon
 * the subject and issuer names.
 */
int x509_auto_append ( struct x509_chain *chain, struct x509_chain *certs ) {
	struct x509_certificate *cert;
	struct x509_certificate *previous;
	int rc;

	/* Get current certificate */
	cert = x509_last ( chain );
	if ( ! cert ) {
		DBGC ( chain, "X509 chain %p has no certificates\n", chain );
		return -EACCES_EMPTY;
	}

	/* Append certificates, in order */
	while ( 1 ) {

		/* Find issuing certificate */
		previous = cert;
		cert = x509_find_subject ( certs, &cert->issuer.raw );
		if ( ! cert )
			break;
		if ( cert == previous )
			break;

		/* Append certificate to chain */
		if ( ( rc = x509_append ( chain, cert ) ) != 0 )
			return rc;
	}

	return 0;
}

/**
 * Validate X.509 certificate chain
 *
 * @v chain		X.509 certificate chain
 * @v time		Time at which to validate certificates
 * @v store		Certificate store, or NULL to use default
 * @v root		Root certificate list, or NULL to use default
 * @ret rc		Return status code
 */
int x509_validate_chain ( struct x509_chain *chain, time_t time,
			  struct x509_chain *store, struct x509_root *root ) {
	struct x509_certificate *issuer = NULL;
	struct x509_link *link;
	int rc;

	/* Use default certificate store if none specified */
	if ( ! store )
		store = &certstore;

	/* Append any applicable certificates from the certificate store */
	if ( ( rc = x509_auto_append ( chain, store ) ) != 0 )
		return rc;

	/* Find first certificate that can be validated as a
	 * standalone (i.e.  is already valid, or can be validated as
	 * a trusted root certificate).
	 */
	list_for_each_entry ( link, &chain->links, list ) {

		/* Try validating this certificate as a standalone */
		if ( ( rc = x509_validate ( link->cert, NULL, time,
					    root ) ) != 0 )
			continue;

		/* Work back up to start of chain, performing pairwise
		 * validation.
		 */
		issuer = link->cert;
		list_for_each_entry_continue_reverse ( link, &chain->links,
						       list ) {

			/* Validate this certificate against its issuer */
			if ( ( rc = x509_validate ( link->cert, issuer, time,
						    root ) ) != 0 )
				return rc;
			issuer = link->cert;
		}

		return 0;
	}

	DBGC ( chain, "X509 chain %p found no usable certificates\n", chain );
	return -EACCES_USELESS;
}

/* Drag in objects via x509_validate() */
REQUIRING_SYMBOL ( x509_validate );

/* Drag in certificate store */
REQUIRE_OBJECT ( certstore );

/* Drag in crypto configuration */
REQUIRE_OBJECT ( config_crypto );
