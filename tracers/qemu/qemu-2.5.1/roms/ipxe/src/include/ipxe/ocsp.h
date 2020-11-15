#ifndef _IPXE_OCSP_H
#define _IPXE_OCSP_H

/** @file
 *
 * Online Certificate Status Protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdarg.h>
#include <time.h>
#include <ipxe/asn1.h>
#include <ipxe/x509.h>
#include <ipxe/refcnt.h>

/** OCSP algorithm identifier */
#define OCSP_ALGORITHM_IDENTIFIER( ... )				\
	ASN1_OID, VA_ARG_COUNT ( __VA_ARGS__ ), __VA_ARGS__,		\
	ASN1_NULL, 0x00

/* OCSP response statuses */
#define OCSP_STATUS_SUCCESSFUL		0x00
#define OCSP_STATUS_MALFORMED_REQUEST	0x01
#define OCSP_STATUS_INTERNAL_ERROR	0x02
#define OCSP_STATUS_TRY_LATER		0x03
#define OCSP_STATUS_SIG_REQUIRED	0x05
#define OCSP_STATUS_UNAUTHORIZED	0x06

struct ocsp_check;

/** An OCSP request */
struct ocsp_request {
	/** Request builder */
	struct asn1_builder builder;
	/** Certificate ID */
	struct asn1_cursor cert_id;
};

/** An OCSP responder */
struct ocsp_responder {
	/**
	 * Check if certificate is the responder's certificate
	 *
	 * @v ocsp		OCSP check
	 * @v cert		Certificate
	 * @ret difference	Difference as returned by memcmp()
	 */
	int ( * compare ) ( struct ocsp_check *ocsp,
			    struct x509_certificate *cert );
	/** Responder ID */
	struct asn1_cursor id;
};

/** An OCSP response */
struct ocsp_response {
	/** Raw response */
	void *data;
	/** Raw tbsResponseData */
	struct asn1_cursor tbs;
	/** Responder */
	struct ocsp_responder responder;
	/** Time at which status is known to be correct */
	time_t this_update;
	/** Time at which newer status information will be available */
	time_t next_update;
	/** Signature algorithm */
	struct asn1_algorithm *algorithm;
	/** Signature value */
	struct asn1_bit_string signature;
	/** Signing certificate */
	struct x509_certificate *signer;
};

/** An OCSP check */
struct ocsp_check {
	/** Reference count */
	struct refcnt refcnt;
	/** Certificate being checked */
	struct x509_certificate *cert;
	/** Issuing certificate */
	struct x509_certificate *issuer;
	/** URI string */
	char *uri_string;
	/** Request */
	struct ocsp_request request;
	/** Response */
	struct ocsp_response response;
};

/**
 * Get reference to OCSP check
 *
 * @v ocsp		OCSP check
 * @ret ocsp		OCSP check
 */
static inline __attribute__ (( always_inline )) struct ocsp_check *
ocsp_get ( struct ocsp_check *ocsp ) {
	ref_get ( &ocsp->refcnt );
	return ocsp;
}

/**
 * Drop reference to OCSP check
 *
 * @v ocsp		OCSP check
 */
static inline __attribute__ (( always_inline )) void
ocsp_put ( struct ocsp_check *ocsp ) {
	ref_put ( &ocsp->refcnt );
}

extern int ocsp_check ( struct x509_certificate *cert,
			struct x509_certificate *issuer,
			struct ocsp_check **ocsp );
extern int ocsp_response ( struct ocsp_check *ocsp, const void *data,
			   size_t len );
extern int ocsp_validate ( struct ocsp_check *check, time_t time );

#endif /* _IPXE_OCSP_H */
