#ifndef _IPXE_DRBG_H
#define _IPXE_DRBG_H

/** @file
 *
 * DRBG mechanism
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/sha256.h>
#include <ipxe/hmac_drbg.h>

/** Choose HMAC_DRBG using SHA-256
 *
 * HMAC_DRBG using SHA-256 is an Approved algorithm in ANS X9.82.
 */
#define HMAC_DRBG_ALGORITHM HMAC_DRBG_SHA256

/** Maximum security strength */
#define DRBG_MAX_SECURITY_STRENGTH \
	HMAC_DRBG_MAX_SECURITY_STRENGTH ( HMAC_DRBG_ALGORITHM )

/** Security strength
 *
 * We choose to operate at a strength of 128 bits.
 */
#define DRBG_SECURITY_STRENGTH 128

/** Minimum entropy input length */
#define DRBG_MIN_ENTROPY_LEN_BYTES \
	HMAC_DRBG_MIN_ENTROPY_LEN_BYTES ( DRBG_SECURITY_STRENGTH )

/** Maximum entropy input length */
#define DRBG_MAX_ENTROPY_LEN_BYTES HMAC_DRBG_MAX_ENTROPY_LEN_BYTES

/** Maximum personalisation string length */
#define DRBG_MAX_PERSONAL_LEN_BYTES HMAC_DRBG_MAX_PERSONAL_LEN_BYTES

/** Maximum additional input length */
#define DRBG_MAX_ADDITIONAL_LEN_BYTES HMAC_DRBG_MAX_ADDITIONAL_LEN_BYTES

/** Maximum length of generated pseudorandom data per request */
#define DRBG_MAX_GENERATED_LEN_BYTES HMAC_DRBG_MAX_GENERATED_LEN_BYTES

/** A Deterministic Random Bit Generator */
struct drbg_state {
	/** Algorithm internal state */
	struct hmac_drbg_state internal;
	/** Reseed required flag */
	int reseed_required;
	/** State is valid */
	int valid;
};

/**
 * Instantiate DRBG algorithm
 *
 * @v state		Algorithm state
 * @v entropy		Entropy input
 * @v entropy_len	Length of entropy input
 * @v personal		Personalisation string
 * @v personal_len	Length of personalisation string
 *
 * This is the Instantiate_algorithm function defined in ANS X9.82
 * Part 3-2007 Section 9.2 (NIST SP 800-90 Section 9.1).
 */
static inline void drbg_instantiate_algorithm ( struct drbg_state *state,
						const void *entropy,
						size_t entropy_len,
						const void *personal,
						size_t personal_len ) {
	hmac_drbg_instantiate ( HMAC_DRBG_HASH ( HMAC_DRBG_ALGORITHM ),
				&state->internal, entropy, entropy_len,
				personal, personal_len );
}

/**
 * Reseed DRBG algorithm
 *
 * @v state		Algorithm state
 * @v entropy		Entropy input
 * @v entropy_len	Length of entropy input
 * @v additional	Additional input
 * @v additional_len	Length of additional input
 *
 * This is the Reseed_algorithm function defined in ANS X9.82
 * Part 3-2007 Section 9.3 (NIST SP 800-90 Section 9.2).
 */
static inline void drbg_reseed_algorithm ( struct drbg_state *state,
					   const void *entropy,
					   size_t entropy_len,
					   const void *additional,
					   size_t additional_len ) {
	hmac_drbg_reseed ( HMAC_DRBG_HASH ( HMAC_DRBG_ALGORITHM ),
			   &state->internal, entropy, entropy_len,
			   additional, additional_len );
}

/**
 * Generate pseudorandom bits using DRBG algorithm
 *
 * @v state		Algorithm state
 * @v additional	Additional input
 * @v additional_len	Length of additional input
 * @v data		Output buffer
 * @v len		Length of output buffer
 * @ret rc		Return status code
 *
 * This is the Generate_algorithm function defined in ANS X9.82
 * Part 3-2007 Section 9.4 (NIST SP 800-90 Section 9.3).
 *
 * Note that the only permitted error is "reseed required".
 */
static inline int drbg_generate_algorithm ( struct drbg_state *state,
					    const void *additional,
					    size_t additional_len,
					    void *data, size_t len ) {
	return hmac_drbg_generate ( HMAC_DRBG_HASH ( HMAC_DRBG_ALGORITHM ),
				    &state->internal, additional,
				    additional_len, data, len );
}

extern int drbg_instantiate ( struct drbg_state *state, const void *personal,
			      size_t personal_len );
extern int drbg_reseed ( struct drbg_state *state, const void *additional,
			 size_t additional_len );
extern int drbg_generate ( struct drbg_state *state, const void *additional,
			   size_t additional_len, int prediction_resist,
			   void *data, size_t len );
extern void drbg_uninstantiate ( struct drbg_state *state );

#endif /* _IPXE_DRBG_H */
