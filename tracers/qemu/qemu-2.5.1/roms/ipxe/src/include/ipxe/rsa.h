#ifndef _IPXE_RSA_H
#define _IPXE_RSA_H

/** @file
 *
 * RSA public-key cryptography
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdarg.h>
#include <ipxe/crypto.h>
#include <ipxe/bigint.h>
#include <ipxe/asn1.h>
#include <ipxe/tables.h>

/** RSA digestAlgorithm sequence contents */
#define RSA_DIGESTALGORITHM_CONTENTS( ... )				\
	ASN1_OID, VA_ARG_COUNT ( __VA_ARGS__ ), __VA_ARGS__,		\
	ASN1_NULL, 0x00

/** RSA digestAlgorithm sequence */
#define RSA_DIGESTALGORITHM( ... )					\
	ASN1_SEQUENCE,							\
	VA_ARG_COUNT ( RSA_DIGESTALGORITHM_CONTENTS ( __VA_ARGS__ ) ),	\
	RSA_DIGESTALGORITHM_CONTENTS ( __VA_ARGS__ )

/** RSA digest prefix */
#define RSA_DIGEST_PREFIX( digest_size )				\
	ASN1_OCTET_STRING, digest_size

/** RSA digestInfo prefix */
#define RSA_DIGESTINFO_PREFIX( digest_size, ... )			\
	ASN1_SEQUENCE,							\
	( VA_ARG_COUNT ( RSA_DIGESTALGORITHM ( __VA_ARGS__ ) ) +	\
	  VA_ARG_COUNT ( RSA_DIGEST_PREFIX ( digest_size ) ) +		\
	  digest_size ),						\
	RSA_DIGESTALGORITHM ( __VA_ARGS__ ),				\
	RSA_DIGEST_PREFIX ( digest_size )

/** An RSA digestInfo prefix */
struct rsa_digestinfo_prefix {
	/** Digest algorithm */
	struct digest_algorithm *digest;
	/** Prefix */
	const void *data;
	/** Length of prefix */
	size_t len;
};

/** RSA digestInfo prefix table */
#define RSA_DIGESTINFO_PREFIXES \
	__table ( struct rsa_digestinfo_prefix, "rsa_digestinfo_prefixes" )

/** Declare an RSA digestInfo prefix */
#define __rsa_digestinfo_prefix __table_entry ( RSA_DIGESTINFO_PREFIXES, 01 )

/** An RSA context */
struct rsa_context {
	/** Allocated memory */
	void *dynamic;
	/** Modulus */
	bigint_element_t *modulus0;
	/** Modulus size */
	unsigned int size;
	/** Modulus length */
	size_t max_len;
	/** Exponent */
	bigint_element_t *exponent0;
	/** Exponent size */
	unsigned int exponent_size;
	/** Input buffer */
	bigint_element_t *input0;
	/** Output buffer */
	bigint_element_t *output0;
	/** Temporary working space for modular exponentiation */
	void *tmp;
};

extern struct pubkey_algorithm rsa_algorithm;

#endif /* _IPXE_RSA_H */
