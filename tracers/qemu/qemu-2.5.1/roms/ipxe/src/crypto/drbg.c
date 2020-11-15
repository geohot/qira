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
 * DRBG mechanism
 *
 * This mechanism is designed to comply with ANS X9.82 Part 3-2007
 * Section 9.  This standard is not freely available, but most of the
 * text appears to be shared with NIST SP 800-90, which can be
 * downloaded from
 *
 *     http://csrc.nist.gov/publications/nistpubs/800-90/SP800-90revised_March2007.pdf
 *
 * Where possible, references are given to both documents.  In the
 * case of any disagreement, ANS X9.82 takes priority over NIST SP
 * 800-90.  (In particular, note that some algorithms that are
 * Approved by NIST SP 800-90 are not Approved by ANS X9.82.)
 */

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/entropy.h>
#include <ipxe/drbg.h>

/**
 * Instantiate DRBG
 *
 * @v state		Algorithm state to be initialised
 * @v personal		Personalisation string
 * @v personal_len	Length of personalisation string
 * @ret rc		Return status code
 *
 * This is the Instantiate_function defined in ANS X9.82 Part 3-2007
 * Section 9.2 (NIST SP 800-90 Section 9.1).
 *
 * Only a single security strength is supported, and prediction
 * resistance is always enabled.  The nonce is accounted for by
 * increasing the entropy input, as per ANS X9.82 Part 3-2007 Section
 * 8.4.2 (NIST SP 800-90 Section 8.6.7).
 */
int drbg_instantiate ( struct drbg_state *state, const void *personal,
		       size_t personal_len ) {
	unsigned int entropy_bits = ( ( 3 * DRBG_SECURITY_STRENGTH + 1 ) / 2 );
	size_t min_len = DRBG_MIN_ENTROPY_LEN_BYTES;
	size_t max_len = DRBG_MAX_ENTROPY_LEN_BYTES;
	uint8_t data[max_len];
	int len;
	int rc;

	DBGC ( state, "DRBG %p instantiate\n", state );

	/* Sanity checks */
	assert ( state != NULL );

	/* 1.  If requested_instantiation_security_strength >
	 *     highest_supported_security_strength, then return an
	 *     ERROR_FLAG
	 */
	if ( DRBG_SECURITY_STRENGTH > DRBG_MAX_SECURITY_STRENGTH ) {
		DBGC ( state, "DRBG %p cannot support security strength %d\n",
		       state, DRBG_SECURITY_STRENGTH );
		return -ENOTSUP;
	}

	/* 2.  If prediction_resistance_flag is set, and prediction
	 *     resistance is not supported, then return an ERROR_FLAG
	 *
	 * (Nothing to do since prediction resistance is always
	 * supported.)
	 */

	/* 3.  If the length of the personalization_string >
	 *     max_personalization_string_length, return an ERROR_FLAG
	 */
	if ( personal_len > DRBG_MAX_PERSONAL_LEN_BYTES ) {
		DBGC ( state, "DRBG %p personalisation string too long (%zd "
		       "bytes)\n", state, personal_len );
		return -ERANGE;
	}

	/* 4.  Set security_strength to the nearest security strength
	 *     greater than or equal to
	 *     requested_instantiation_security_strength.
	 *
	 * (Nothing to do since we support only a single security
	 * strength.)
	 */

	/* 5.  Using the security_strength, select appropriate DRBG
	 *     mechanism parameters.
	 *
	 * (Nothing to do since we support only a single security
	 * strength.)
	 */

	/* 6.  ( status, entropy_input ) = Get_entropy_input (
	 *     security_strength, min_length, max_length,
	 *     prediction_resistance_request )
	 * 7.  If an ERROR is returned in step 6, return a
	 *     CATASTROPHIC_ERROR_FLAG.
	 * 8.  Obtain a nonce.
	 */
	len = get_entropy_input ( entropy_bits, data, min_len,
				  sizeof ( data ) );
	if ( len < 0 ) {
		rc = len;
		DBGC ( state, "DRBG %p could not get entropy input: %s\n",
		       state, strerror ( rc ) );
		return rc;
	}
	assert ( len >= ( int ) min_len );
	assert ( len <= ( int ) sizeof ( data ) );

	/* 9.  initial_working_state = Instantiate_algorithm (
	 *     entropy_input, nonce, personalization_string ).
	 */
	drbg_instantiate_algorithm ( state, data, len, personal, personal_len );

	/* 10.  Get a state_handle for a currently empty state.  If an
	 *      empty internal state cannot be found, return an
	 *      ERROR_FLAG.
	 * 11.  Set the internal state indicated by state_handle to
	 *      the initial values for the internal state (i.e. set
	 *      the working_state to the values returned as
	 *      initial_working_state in step 9 and any other values
	 *      required for the working_state, and set the
	 *      administrative information to the appropriate values.
	 *
	 * (Almost nothing to do since the memory to hold the state
	 * was passed in by the caller and has already been updated
	 * in-situ.)
	 */
	state->reseed_required = 0;
	state->valid = 1;

	/* 12.  Return SUCCESS and state_handle. */
	return 0;
}

/**
 * Reseed DRBG
 *
 * @v state		Algorithm state
 * @v additional	Additional input
 * @v additional_len	Length of additional input
 * @ret rc		Return status code
 *
 * This is the Reseed_function defined in ANS X9.82 Part 3-2007
 * Section 9.3 (NIST SP 800-90 Section 9.2).
 *
 * Prediction resistance is always enabled.
 */
int drbg_reseed ( struct drbg_state *state, const void *additional,
		  size_t additional_len ) {
	unsigned int entropy_bits = DRBG_SECURITY_STRENGTH;
	size_t min_len = DRBG_MIN_ENTROPY_LEN_BYTES;
	size_t max_len = DRBG_MAX_ENTROPY_LEN_BYTES;
	uint8_t data[max_len];
	int len;
	int rc;

	DBGC ( state, "DRBG %p reseed\n", state );

	/* Sanity checks */
	assert ( state != NULL );

	/* 1.  Using state_handle, obtain the current internal state.
	 *     If state_handle indicates an invalid or empty internal
	 *     state, return an ERROR_FLAG.
	 *
	 * (Almost nothing to do since the memory holding the internal
	 * state was passed in by the caller.)
	 */
	if ( ! state->valid ) {
		DBGC ( state, "DRBG %p not valid\n", state );
		return -EINVAL;
	}

	/* 2.  If prediction_resistance_request is set, and
	 *     prediction_resistance_flag is not set, then return an
	 *     ERROR_FLAG.
	 *
	 * (Nothing to do since prediction resistance is always
	 * supported.)
	 */

	/* 3.  If the length of the additional_input >
	 *     max_additional_input_length, return an ERROR_FLAG.
	 */
	if ( additional_len > DRBG_MAX_ADDITIONAL_LEN_BYTES ) {
		DBGC ( state, "DRBG %p additional input too long (%zd bytes)\n",
		       state, additional_len );
		return -ERANGE;
	}

	/* 4.  ( status, entropy_input ) = Get_entropy_input (
	 *     security_strength, min_length, max_length,
	 *     prediction_resistance_request ).
	 *
	 * 5.  If an ERROR is returned in step 4, return a
	 *     CATASTROPHIC_ERROR_FLAG.
	 */
	len = get_entropy_input ( entropy_bits, data, min_len,
				  sizeof ( data ) );
	if ( len < 0 ) {
		rc = len;
		DBGC ( state, "DRBG %p could not get entropy input: %s\n",
		       state, strerror ( rc ) );
		return rc;
	}

	/* 6.  new_working_state = Reseed_algorithm ( working_state,
	 *     entropy_input, additional_input ).
	 */
	drbg_reseed_algorithm ( state, data, len, additional, additional_len );

	/* 7.  Replace the working_state in the internal state
	 *     indicated by state_handle with the values of
	 *     new_working_state obtained in step 6.
	 *
	 * (Nothing to do since the state has already been updated in-situ.)
	 */

	/* 8.  Return SUCCESS. */
	return 0;
}

/**
 * Generate pseudorandom bits using DRBG
 *
 * @v state		Algorithm state
 * @v additional	Additional input
 * @v additional_len	Length of additional input
 * @v prediction_resist	Prediction resistance is required
 * @v data		Output buffer
 * @v len		Length of output buffer
 * @ret rc		Return status code
 *
 * This is the Generate_function defined in ANS X9.82 Part 3-2007
 * Section 9.4 (NIST SP 800-90 Section 9.3).
 *
 * Requests must be for an integral number of bytes.  Only a single
 * security strength is supported.  Prediction resistance is supported
 * if requested.
 */
int drbg_generate ( struct drbg_state *state, const void *additional,
		    size_t additional_len, int prediction_resist,
		    void *data, size_t len ) {
	int rc;

	DBGC ( state, "DRBG %p generate\n", state );

	/* Sanity checks */
	assert ( state != NULL );
	assert ( data != NULL );

	/* 1.  Using state_handle, obtain the current internal state
	 *     for the instantiation.  If state_handle indicates an
	 *     invalid or empty internal state, then return an ERROR_FLAG.
	 *
	 * (Almost nothing to do since the memory holding the internal
	 * state was passed in by the caller.)
	 */
	if ( ! state->valid ) {
		DBGC ( state, "DRBG %p not valid\n", state );
		return -EINVAL;
	}

	/* 2.  If requested_number_of_bits >
	 *     max_number_of_bits_per_request, then return an
	 *     ERROR_FLAG.
	 */
	if ( len > DRBG_MAX_GENERATED_LEN_BYTES ) {
		DBGC ( state, "DRBG %p request too long (%zd bytes)\n",
		       state, len );
		return -ERANGE;
	}

	/* 3.  If requested_security_strength > the security_strength
	 *     indicated in the internal state, then return an
	 *     ERROR_FLAG.
	 *
	 * (Nothing to do since only a single security strength is
	 * supported.)
	 */

	/* 4.  If the length of the additional_input >
	 *     max_additional_input_length, then return an ERROR_FLAG.
	 */
	if ( additional_len > DRBG_MAX_ADDITIONAL_LEN_BYTES ) {
		DBGC ( state, "DRBG %p additional input too long (%zd bytes)\n",
		       state, additional_len );
		return -ERANGE;
	}

	/* 5.  If prediction_resistance_request is set, and
	 *     prediction_resistance_flag is not set, then return an
	 *     ERROR_FLAG.
	 *
	 * (Nothing to do since prediction resistance is always
	 * supported.)
	 */

	/* 6.  Clear the reseed_required_flag. */
	state->reseed_required = 0;

 step_7:
	/* 7.  If reseed_required_flag is set, or if
	 *     prediction_resistance_request is set, then
	 */
	if ( state->reseed_required || prediction_resist ) {

		/* 7.1  status = Reseed_function ( state_handle,
		 *      prediction_resistance_request,
		 *      additional_input )
		 * 7.2  If status indicates an ERROR, then return
		 *      status.
		 */
		if ( ( rc = drbg_reseed ( state, additional,
					  additional_len ) ) != 0 ) {
			DBGC ( state, "DRBG %p could not reseed: %s\n",
			       state, strerror ( rc ) );
			return rc;
		}

		/* 7.3  Using state_handle, obtain the new internal
		 *      state.
		 *
		 * (Nothing to do since the internal state has been
		 * updated in-situ.)
		 */

		/* 7.4  additional_input = the Null string. */
		additional = NULL;
		additional_len = 0;

		/* 7.5  Clear the reseed_required_flag. */
		state->reseed_required = 0;
	}

	/* 8.  ( status, pseudorandom_bits, new_working_state ) =
	 *     Generate_algorithm ( working_state,
	 *     requested_number_of_bits, additional_input ).
	 */
	rc = drbg_generate_algorithm ( state, additional, additional_len,
				       data, len );

	/* 9.  If status indicates that a reseed is required before
	 *     the requested bits can be generated, then
	 */
	if ( rc != 0 ) {

		/* 9.1  Set the reseed_required_flag. */
		state->reseed_required = 1;

		/* 9.2  If the prediction_resistance_flag is set, then
		 *      set the prediction_resistance_request
		 *      indication.
		 */
		prediction_resist = 1;

		/* 9.3  Go to step 7. */
		goto step_7;
	}

	/* 10.  Replace the old working_state in the internal state
	 *      indicated by state_handle with the values of
	 *      new_working_state.
	 *
	 * (Nothing to do since the working state has already been
	 * updated in-situ.)
	 */

	/* 11.  Return SUCCESS and pseudorandom_bits. */
	return 0;
}

/**
 * Uninstantiate DRBG
 *
 * @v state		Algorithm state
 *
 * This is the Uninstantiate_function defined in ANS X9.82 Part 3-2007
 * Section 9.5 (NIST SP 800-90 Section 9.4).
 */
void drbg_uninstantiate ( struct drbg_state *state ) {

	DBGC ( state, "DRBG %p uninstantiate\n", state );

	/* Sanity checks */
	assert ( state != NULL );

	/* 1.  If state_handle indicates an invalid state, then return
	 *     an ERROR_FLAG.
	 *
	 * (Nothing to do since the memory holding the internal state
	 * was passed in by the caller.)
	 */

	/* 2.  Erase the contents of the internal state indicated by
	 *     state_handle.
	 */
	memset ( state, 0, sizeof ( *state ) );

	/* 3.  Return SUCCESS. */
}
