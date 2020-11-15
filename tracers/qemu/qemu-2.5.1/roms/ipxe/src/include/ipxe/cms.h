#ifndef _IPXE_CMS_H
#define _IPXE_CMS_H

/** @file
 *
 * Cryptographic Message Syntax (PKCS #7)
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <time.h>
#include <ipxe/asn1.h>
#include <ipxe/crypto.h>
#include <ipxe/x509.h>
#include <ipxe/refcnt.h>
#include <ipxe/uaccess.h>

/** CMS signer information */
struct cms_signer_info {
	/** List of signer information blocks */
	struct list_head list;

	/** Certificate chain */
	struct x509_chain *chain;

	/** Digest algorithm */
	struct digest_algorithm *digest;
	/** Public-key algorithm */
	struct pubkey_algorithm *pubkey;

	/** Signature */
	void *signature;
	/** Length of signature */
	size_t signature_len;
};

/** A CMS signature */
struct cms_signature {
	/** Reference count */
	struct refcnt refcnt;
	/** List of all certificates */
	struct x509_chain *certificates;
	/** List of signer information blocks */
	struct list_head info;
};

/**
 * Get reference to CMS signature
 *
 * @v sig		CMS signature
 * @ret sig		CMS signature
 */
static inline __attribute__ (( always_inline )) struct cms_signature *
cms_get ( struct cms_signature *sig ) {
	ref_get ( &sig->refcnt );
	return sig;
}

/**
 * Drop reference to CMS signature
 *
 * @v sig		CMS signature
 */
static inline __attribute__ (( always_inline )) void
cms_put ( struct cms_signature *sig ) {
	ref_put ( &sig->refcnt );
}

extern int cms_signature ( const void *data, size_t len,
			   struct cms_signature **sig );
extern int cms_verify ( struct cms_signature *sig, userptr_t data, size_t len,
			const char *name, time_t time, struct x509_chain *store,
			struct x509_root *root );

#endif /* _IPXE_CMS_H */
