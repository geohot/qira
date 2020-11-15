#ifndef _IPXE_HMAC_DRBG_H
#define _IPXE_HMAC_DRBG_H

/** @file
 *
 * HMAC_DRBG algorithm
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/crypto.h>

/** Declare an HMAC_DRBG algorithm
 *
 * @v hash			Underlying hash algorithm
 * @v max_security_strength	Maxmimum security strength
 * @v out_len_bits		Output block length, in bits
 * @ret hmac_drbg		HMAC_DRBG algorithm
 */
#define HMAC_DRBG( hash, max_security_strength, out_len_bits ) \
	( hash, max_security_strength, out_len_bits )

/** HMAC_DRBG using SHA-1
 *
 * The maximum security strength of HMAC_DRBG using SHA-1 is 128 bits
 * according to the list of maximum security strengths documented in
 * NIST SP 800-57 Part 1 Section 5.6.1 Table 3.
 *
 * The output block length of HMAC_DRBG using SHA-1 is 160 bits
 * according to ANS X9.82 Part 3-2007 Section 10.2.1 Table 2 (NIST SP
 * 800-90 Section 10.1 Table 2).
 */
#define HMAC_DRBG_SHA1 HMAC_DRBG ( &sha1_algorithm, 128, 160 )

/** HMAC_DRBG using SHA-224
 *
 * The maximum security strength of HMAC_DRBG using SHA-224 is 192
 * bits according to the list of maximum security strengths documented
 * in NIST SP 800-57 Part 1 Section 5.6.1 Table 3.
 *
 * The output block length of HMAC_DRBG using SHA-224 is 224 bits
 * according to ANS X9.82 Part 3-2007 Section 10.2.1 Table 2 (NIST SP
 * 800-90 Section 10.1 Table 2).
 */
#define HMAC_DRBG_SHA224 HMAC_DRBG ( &sha224_algorithm, 192, 224 )

/** HMAC_DRBG using SHA-256
 *
 * The maximum security strength of HMAC_DRBG using SHA-256 is 256
 * bits according to the list of maximum security strengths documented
 * in NIST SP 800-57 Part 1 Section 5.6.1 Table 3.
 *
 * The output block length of HMAC_DRBG using SHA-256 is 256 bits
 * according to ANS X9.82 Part 3-2007 Section 10.2.1 Table 2 (NIST SP
 * 800-90 Section 10.1 Table 2).
 */
#define HMAC_DRBG_SHA256 HMAC_DRBG ( &sha256_algorithm, 256, 256 )

/** HMAC_DRBG using SHA-384
 *
 * The maximum security strength of HMAC_DRBG using SHA-384 is 256
 * bits according to the list of maximum security strengths documented
 * in NIST SP 800-57 Part 1 Section 5.6.1 Table 3.
 *
 * The output block length of HMAC_DRBG using SHA-384 is 384 bits
 * according to ANS X9.82 Part 3-2007 Section 10.2.1 Table 2 (NIST SP
 * 800-90 Section 10.1 Table 2).
 */
#define HMAC_DRBG_SHA384 HMAC_DRBG ( &sha384_algorithm, 256, 384 )

/** HMAC_DRBG using SHA-512
 *
 * The maximum security strength of HMAC_DRBG using SHA-512 is 256
 * bits according to the list of maximum security strengths documented
 * in NIST SP 800-57 Part 1 Section 5.6.1 Table 3.
 *
 * The output block length of HMAC_DRBG using SHA-512 is 512 bits
 * according to ANS X9.82 Part 3-2007 Section 10.2.1 Table 2 (NIST SP
 * 800-90 Section 10.1 Table 2).
 */
#define HMAC_DRBG_SHA512 HMAC_DRBG ( &sha512_algorithm, 256, 512 )

/** Underlying hash algorithm
 *
 * @v hmac_drbg			HMAC_DRBG algorithm
 * @ret hash			Underlying hash algorithm
 */
#define HMAC_DRBG_HASH( hmac_drbg ) \
	HMAC_DRBG_EXTRACT_HASH hmac_drbg
#define HMAC_DRBG_EXTRACT_HASH( hash, max_security_strength, out_len_bits ) \
	hash

/** Maximum security strength
 *
 * @v hmac_drbg			HMAC_DRBG algorithm
 * @ret max_security_strength	Maxmimum security strength
 */
#define HMAC_DRBG_MAX_SECURITY_STRENGTH( hmac_drbg ) \
	HMAC_DRBG_EXTRACT_MAX_SECURITY_STRENGTH hmac_drbg
#define HMAC_DRBG_EXTRACT_MAX_SECURITY_STRENGTH( hash, max_security_strength, \
						 out_len_bits ) \
	max_security_strength

/** Output block length, in bits
 *
 * @v hmac_drbg			HMAC_DRBG algorithm
 * @ret out_len_bits		Output block length, in bits
 */
#define HMAC_DRBG_OUTLEN_BITS( hmac_drbg ) \
	HMAC_DRBG_EXTRACT_OUTLEN_BITS hmac_drbg
#define HMAC_DRBG_EXTRACT_OUTLEN_BITS( hash, max_security_strength, \
				       out_len_bits ) \
	out_len_bits

/** Output block length, in bytes
 *
 * @v hmac_drbg			HMAC_DRBG algorithm
 * @ret out_len_bytes		Output block length, in bytes
 */
#define HMAC_DRBG_OUTLEN_BYTES( hmac_drbg ) \
	( HMAC_DRBG_OUTLEN_BITS ( hmac_drbg ) / 8 )

/** Maximum output block length, in bytes
 *
 * The maximum output block length for HMAC_DRBG is 512 bits for
 * SHA-512 according to ANS X9.82 Part 3-2007 Section 10.2.1 Table 2
 * (NIST SP 800-90 Section 10.1 Table 2).
 */
#define HMAC_DRBG_MAX_OUTLEN_BYTES HMAC_DRBG_OUTLEN_BYTES ( HMAC_DRBG_SHA512 )

/** Required minimum entropy for instantiate and reseed
 *
 * @v security_strength		Security strength
 * @ret min_entropy		Required minimum entropy
 *
 * The minimum required entropy for HMAC_DRBG is equal to the security
 * strength according to ANS X9.82 Part 3-2007 Section 10.2.1 Table 2
 * (NIST SP 800-90 Section 10.1 Table 2).
 */
#define HMAC_DRBG_MIN_ENTROPY( security_strength ) (security_strength)

/** Minimum entropy input length
 *
 * @v security_strength		Security strength
 * @ret min_entropy_len_bytes	Required minimum entropy length (in bytes)
 *
 * The minimum entropy input length for HMAC_DRBG is equal to the
 * security strength according to ANS X9.82 Part 3-2007 Section 10.2.1
 * Table 2 (NIST SP 800-90 Section 10.1 Table 2).
 */
#define HMAC_DRBG_MIN_ENTROPY_LEN_BYTES( security_strength ) \
	( (security_strength) / 8 )

/** Maximum entropy input length
 *
 * The maximum entropy input length for HMAC_DRBG is 2^35 bits
 * according to ANS X9.82 Part 3-2007 Section 10.2.1 Table 2 (NIST SP
 * 800-90 Section 10.1 Table 2).
 *
 * We choose to allow up to 32 bytes.
 */
#define HMAC_DRBG_MAX_ENTROPY_LEN_BYTES 32

/** Maximum personalisation string length
 *
 * The maximum permitted personalisation string length for HMAC_DRBG
 * is 2^35 bits according to ANS X9.82 Part 3-2007 Section 10.2.1
 * Table 1 (NIST SP 800-90 Section 10.1 Table 2).
 *
 * We choose to allow up to 2^32-1 bytes (i.e. 2^35-8 bits).
 */
#define HMAC_DRBG_MAX_PERSONAL_LEN_BYTES 0xffffffffUL

/** Maximum additional input length
 *
 * The maximum permitted additional input length for HMAC_DRBG is 2^35
 * bits according to ANS X9.82 Part 3-2007 Section 10.2.1 Table 1
 * (NIST SP 800-90 Section 10.1 Table 2).
 *
 * We choose to allow up to 2^32-1 bytes (i.e. 2^35-8 bits).
 */
#define HMAC_DRBG_MAX_ADDITIONAL_LEN_BYTES 0xffffffffUL

/** Maximum length of generated pseudorandom data per request
 *
 * The maximum number of bits per request for HMAC_DRBG is 2^19 bits
 * according to ANS X9.82 Part 3-2007 Section 10.2.1 Table 1 (NIST SP
 * 800-90 Section 10.1 Table 2).
 *
 * We choose to allow up to 2^16-1 bytes (i.e. 2^19-8 bits).
 */
#define HMAC_DRBG_MAX_GENERATED_LEN_BYTES 0x0000ffffUL

/** Reseed interval
 *
 * The maximum permitted reseed interval for HMAC_DRBG is 2^48
 * according to ANS X9.82 Part 3-2007 Section 10.2.1 Table 2 (NIST SP
 * 800-90 Section 10.1 Table 2).  However, the sample implementation
 * given in ANS X9.82 Part 3-2007 Annex E.2.1 (NIST SP 800-90 Appendix
 * F.2) shows a reseed interval of 10000.
 *
 * We choose a very conservative reseed interval.
 */
#define HMAC_DRBG_RESEED_INTERVAL 1024

/**
 * HMAC_DRBG internal state
 *
 * This structure is defined by ANS X9.82 Part 3-2007 Section
 * 10.2.2.2.1 (NIST SP 800-90 Section 10.1.2.1).
 *
 * The "administrative information" portions (security_strength and
 * prediction_resistance) are design-time constants and so are not
 * present as fields in this structure.
 */
struct hmac_drbg_state {
	/** Current value
	 *
	 * "The value V of outlen bits, which is updated each time
	 * another outlen bits of output are produced"
	 */
	uint8_t value[HMAC_DRBG_MAX_OUTLEN_BYTES];
	/** Current key
	 *
	 * "The outlen-bit Key, which is updated at least once each
	 * time that the DRBG mechanism generates pseudorandom bits."
	 */
	uint8_t key[HMAC_DRBG_MAX_OUTLEN_BYTES];
	/** Reseed counter
	 *
	 * "A counter (reseed_counter) that indicates the number of
	 * requests for pseudorandom bits since instantiation or
	 * reseeding"
	 */
	unsigned int reseed_counter;
};

extern void hmac_drbg_instantiate ( struct digest_algorithm *hash,
				    struct hmac_drbg_state *state,
				    const void *entropy, size_t entropy_len,
				    const void *personal, size_t personal_len );
extern void hmac_drbg_reseed ( struct digest_algorithm *hash,
			       struct hmac_drbg_state *state,
			       const void *entropy, size_t entropy_len,
			       const void *additional, size_t additional_len );
extern int hmac_drbg_generate ( struct digest_algorithm *hash,
				struct hmac_drbg_state *state,
				const void *additional, size_t additional_len,
				void *data, size_t len );

#endif /* _IPXE_HMAC_DRBG_H */
