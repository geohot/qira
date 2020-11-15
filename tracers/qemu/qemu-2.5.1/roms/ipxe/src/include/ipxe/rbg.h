#ifndef _IPXE_RBG_H
#define _IPXE_RBG_H

/** @file
 *
 * RBG mechanism
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/drbg.h>

/** An RBG */
struct random_bit_generator {
	/** DRBG state */
	struct drbg_state state;
};

extern struct random_bit_generator rbg;

/**
 * Generate bits using RBG
 *
 * @v additional	Additional input
 * @v additional_len	Length of additional input
 * @v prediction_resist	Prediction resistance is required
 * @v data		Output buffer
 * @v len		Length of output buffer
 * @ret rc		Return status code
 *
 * This is the RBG_Generate function defined in ANS X9.82 Part 4
 * (April 2011 Draft) Section 9.1.2.2.
 */
static inline int rbg_generate ( const void *additional, size_t additional_len,
				 int prediction_resist, void *data,
				 size_t len ) {
	return drbg_generate ( &rbg.state, additional, additional_len,
			       prediction_resist, data, len );
}

#endif /* _IPXE_RBG_H */
