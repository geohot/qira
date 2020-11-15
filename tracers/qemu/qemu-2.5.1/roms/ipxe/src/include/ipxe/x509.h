#ifndef _IPXE_X509_H
#define _IPXE_X509_H

/** @file
 *
 * X.509 certificates
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <ipxe/asn1.h>
#include <ipxe/refcnt.h>
#include <ipxe/list.h>

/** An X.509 serial number */
struct x509_serial {
	/** Raw serial number */
	struct asn1_cursor raw;
};

/** An X.509 issuer */
struct x509_issuer {
	/** Raw issuer */
	struct asn1_cursor raw;
};

/** An X.509 time */
struct x509_time {
	/** Seconds since the Epoch */
	time_t time;
};

/** An X.509 certificate validity period */
struct x509_validity {
	/** Not valid before */
	struct x509_time not_before;
	/** Not valid after */
	struct x509_time not_after;
};

/** An X.509 certificate public key */
struct x509_public_key {
	/** Raw public key information */
	struct asn1_cursor raw;
	/** Public key algorithm */
	struct asn1_algorithm *algorithm;
	/** Raw public key bit string */
	struct asn1_bit_string raw_bits;
};

/** An X.509 certificate subject */
struct x509_subject {
	/** Raw subject */
	struct asn1_cursor raw;
	/** Common name */
	struct asn1_cursor common_name;
	/** Public key information */
	struct x509_public_key public_key;
};

/** An X.509 certificate signature */
struct x509_signature {
	/** Signature algorithm */
	struct asn1_algorithm *algorithm;
	/** Signature value */
	struct asn1_bit_string value;
};

/** An X.509 certificate basic constraints set */
struct x509_basic_constraints {
	/** Subject is a CA */
	int ca;
	/** Path length */
	unsigned int path_len;
};

/** Unlimited path length
 *
 * We use -2U, since this quantity represents one *fewer* than the
 * maximum number of remaining certificates in a chain.
 */
#define X509_PATH_LEN_UNLIMITED -2U

/** An X.509 certificate key usage */
struct x509_key_usage {
	/** Key usage extension is present */
	int present;
	/** Usage bits */
	unsigned int bits;
};

/** X.509 certificate key usage bits */
enum x509_key_usage_bits {
	X509_DIGITAL_SIGNATURE = 0x0080,
	X509_NON_REPUDIATION = 0x0040,
	X509_KEY_ENCIPHERMENT = 0x0020,
	X509_DATA_ENCIPHERMENT = 0x0010,
	X509_KEY_AGREEMENT = 0x0008,
	X509_KEY_CERT_SIGN = 0x0004,
	X509_CRL_SIGN = 0x0002,
	X509_ENCIPHER_ONLY = 0x0001,
	X509_DECIPHER_ONLY = 0x8000,
};

/** An X.509 certificate extended key usage */
struct x509_extended_key_usage {
	/** Usage bits */
	unsigned int bits;
};

/** X.509 certificate extended key usage bits
 *
 * Extended key usages are identified by OID; these bits are purely an
 * internal definition.
 */
enum x509_extended_key_usage_bits {
	X509_CODE_SIGNING = 0x0001,
	X509_OCSP_SIGNING = 0x0002,
};

/** X.509 certificate OCSP responder */
struct x509_ocsp_responder {
	/** URI */
	struct asn1_cursor uri;
	/** OCSP status is good */
	int good;
};

/** X.509 certificate authority information access */
struct x509_authority_info_access {
	/** OCSP responder */
	struct x509_ocsp_responder ocsp;
};

/** X.509 certificate subject alternative name */
struct x509_subject_alt_name {
	/** Names */
	struct asn1_cursor names;
};

/** X.509 certificate general name types */
enum x509_general_name_types {
	X509_GENERAL_NAME_DNS = ASN1_IMPLICIT_TAG ( 2 ),
	X509_GENERAL_NAME_URI = ASN1_IMPLICIT_TAG ( 6 ),
	X509_GENERAL_NAME_IP = ASN1_IMPLICIT_TAG ( 7 ),
};

/** An X.509 certificate extensions set */
struct x509_extensions {
	/** Basic constraints */
	struct x509_basic_constraints basic;
	/** Key usage */
	struct x509_key_usage usage;
	/** Extended key usage */
	struct x509_extended_key_usage ext_usage;
	/** Authority information access */
	struct x509_authority_info_access auth_info;
	/** Subject alternative name */
	struct x509_subject_alt_name alt_name;
};

/** A link in an X.509 certificate chain */
struct x509_link {
	/** List of links */
	struct list_head list;
	/** Certificate */
	struct x509_certificate *cert;
};

/** An X.509 certificate chain */
struct x509_chain {
	/** Reference count */
	struct refcnt refcnt;
	/** List of links */
	struct list_head links;
};

/** An X.509 certificate */
struct x509_certificate {
	/** Reference count */
	struct refcnt refcnt;

	/** Link in certificate store */
	struct x509_link store;

	/** Certificate has been validated */
	int valid;
	/** Maximum number of subsequent certificates in chain */
	unsigned int path_remaining;

	/** Raw certificate */
	struct asn1_cursor raw;
	/** Version */
	unsigned int version;
	/** Serial number */
	struct x509_serial serial;
	/** Raw tbsCertificate */
	struct asn1_cursor tbs;
	/** Signature algorithm */
	struct asn1_algorithm *signature_algorithm;
	/** Issuer */
	struct x509_issuer issuer;
	/** Validity */
	struct x509_validity validity;
	/** Subject */
	struct x509_subject subject;
	/** Signature */
	struct x509_signature signature;
	/** Extensions */
	struct x509_extensions extensions;
};

/**
 * Get reference to X.509 certificate
 *
 * @v cert		X.509 certificate
 * @ret cert		X.509 certificate
 */
static inline __attribute__ (( always_inline )) struct x509_certificate *
x509_get ( struct x509_certificate *cert ) {
	ref_get ( &cert->refcnt );
	return cert;
}

/**
 * Drop reference to X.509 certificate
 *
 * @v cert		X.509 certificate
 */
static inline __attribute__ (( always_inline )) void
x509_put ( struct x509_certificate *cert ) {
	ref_put ( &cert->refcnt );
}

/**
 * Get reference to X.509 certificate chain
 *
 * @v chain		X.509 certificate chain
 * @ret chain		X.509 certificate chain
 */
static inline __attribute__ (( always_inline )) struct x509_chain *
x509_chain_get ( struct x509_chain *chain ) {
	ref_get ( &chain->refcnt );
	return chain;
}

/**
 * Drop reference to X.509 certificate chain
 *
 * @v chain		X.509 certificate chain
 */
static inline __attribute__ (( always_inline )) void
x509_chain_put ( struct x509_chain *chain ) {
	ref_put ( &chain->refcnt );
}

/**
 * Get first certificate in X.509 certificate chain
 *
 * @v chain		X.509 certificate chain
 * @ret cert		X.509 certificate, or NULL
 */
static inline __attribute__ (( always_inline )) struct x509_certificate *
x509_first ( struct x509_chain *chain ) {
	struct x509_link *link;

	link = list_first_entry ( &chain->links, struct x509_link, list );
	return ( link ? link->cert : NULL );
}

/**
 * Get last certificate in X.509 certificate chain
 *
 * @v chain		X.509 certificate chain
 * @ret cert		X.509 certificate, or NULL
 */
static inline __attribute__ (( always_inline )) struct x509_certificate *
x509_last ( struct x509_chain *chain ) {
	struct x509_link *link;

	link = list_last_entry ( &chain->links, struct x509_link, list );
	return ( link ? link->cert : NULL );
}

/** An X.509 extension */
struct x509_extension {
	/** Name */
	const char *name;
	/** Object identifier */
	struct asn1_cursor oid;
	/** Parse extension
	 *
	 * @v cert		X.509 certificate
	 * @v raw		ASN.1 cursor
	 * @ret rc		Return status code
	 */
	int ( * parse ) ( struct x509_certificate *cert,
			  const struct asn1_cursor *raw );
};

/** An X.509 key purpose */
struct x509_key_purpose {
	/** Name */
	const char *name;
	/** Object identifier */
	struct asn1_cursor oid;
	/** Extended key usage bits */
	unsigned int bits;
};

/** An X.509 access method */
struct x509_access_method {
	/** Name */
	const char *name;
	/** Object identifier */
	struct asn1_cursor oid;
	/** Parse access method
	 *
	 * @v cert		X.509 certificate
	 * @v raw		ASN.1 cursor
	 * @ret rc		Return status code
	 */
	int ( * parse ) ( struct x509_certificate *cert,
			  const struct asn1_cursor *raw );
};

/** An X.509 root certificate store */
struct x509_root {
	/** Fingerprint digest algorithm */
	struct digest_algorithm *digest;
	/** Number of certificates */
	unsigned int count;
	/** Certificate fingerprints */
	const void *fingerprints;
};

extern const char * x509_name ( struct x509_certificate *cert );
extern int x509_parse ( struct x509_certificate *cert,
			const struct asn1_cursor *raw );
extern int x509_certificate ( const void *data, size_t len,
			      struct x509_certificate **cert );
extern int x509_validate ( struct x509_certificate *cert,
			   struct x509_certificate *issuer,
			   time_t time, struct x509_root *root );
extern int x509_check_name ( struct x509_certificate *cert, const char *name );

extern struct x509_chain * x509_alloc_chain ( void );
extern int x509_append ( struct x509_chain *chain,
			 struct x509_certificate *cert );
extern int x509_append_raw ( struct x509_chain *chain, const void *data,
			     size_t len );
extern int x509_auto_append ( struct x509_chain *chain,
			      struct x509_chain *certs );
extern int x509_validate_chain ( struct x509_chain *chain, time_t time,
				 struct x509_chain *store,
				 struct x509_root *root );

/* Functions exposed only for unit testing */
extern int x509_check_issuer ( struct x509_certificate *cert,
			       struct x509_certificate *issuer );
extern void x509_fingerprint ( struct x509_certificate *cert,
			       struct digest_algorithm *digest,
			       void *fingerprint );
extern int x509_check_root ( struct x509_certificate *cert,
			     struct x509_root *root );
extern int x509_check_time ( struct x509_certificate *cert, time_t time );

/**
 * Invalidate X.509 certificate
 *
 * @v cert		X.509 certificate
 */
static inline void x509_invalidate ( struct x509_certificate *cert ) {
	cert->valid = 0;
	cert->path_remaining = 0;
}

/**
 * Invalidate X.509 certificate chain
 *
 * @v chain		X.509 certificate chain
 */
static inline void x509_invalidate_chain ( struct x509_chain *chain ) {
	struct x509_link *link;

	list_for_each_entry ( link, &chain->links, list )
		x509_invalidate ( link->cert );
}

#endif /* _IPXE_X509_H */
