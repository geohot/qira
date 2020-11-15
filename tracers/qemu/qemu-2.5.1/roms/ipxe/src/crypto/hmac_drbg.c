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
 * HMAC_DRBG algorithm
 *
 * This algorithm is designed to comply with ANS X9.82 Part 3-2007
 * Section 10.2.2.2.  This standard is not freely available, but most
 * of the text appears to be shared with NIST SP 800-90, which can be
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
#include <ipxe/crypto.h>
#include <ipxe/hmac.h>
#include <ipxe/hmac_drbg.h>

/**
 * Update the HMAC_DRBG key
 *
 * @v hash		Underlying hash algorithm
 * @v state		HMAC_DRBG internal state
 * @v data		Provided data
 * @v len		Length of provided data
 * @v single		Single byte used in concatenation
 *
 * This function carries out the operation
 *
 *     K = HMAC ( K, V || single || provided_data )
 *
 * as used by hmac_drbg_update()
 */
static void hmac_drbg_update_key ( struct digest_algorithm *hash,
				   struct hmac_drbg_state *state,
				   const void *data, size_t len,
				   const uint8_t single ) {
	uint8_t context[ hash->ctxsize ];
	size_t out_len = hash->digestsize;

	DBGC ( state, "HMAC_DRBG_%s %p provided data :\n", hash->name, state );
	DBGC_HDA ( state, 0, data, len );

	/* Sanity checks */
	assert ( hash != NULL );
	assert ( state != NULL );
	assert ( ( data != NULL ) || ( len == 0 ) );
	assert ( ( single == 0x00 ) || ( single == 0x01 ) );

	/* K = HMAC ( K, V || single || provided_data ) */
	hmac_init ( hash, context, state->key, &out_len );
	assert ( out_len == hash->digestsize );
	hmac_update ( hash, context, state->value, out_len );
	hmac_update ( hash, context, &single, sizeof ( single ) );
	hmac_update ( hash, context, data, len );
	hmac_final ( hash, context, state->key, &out_len, state->key );
	assert ( out_len == hash->digestsize );

	DBGC ( state, "HMAC_DRBG_%s %p K = HMAC ( K, V || %#02x || "
	       "provided_data ) :\n", hash->name, state, single );
	DBGC_HDA ( state, 0, state->key, out_len );
}

/**
 * Update the HMAC_DRBG value
 *
 * @v hash		Underlying hash algorithm
 * @v state		HMAC_DRBG internal state
 * @v data		Provided data
 * @v len		Length of provided data
 * @v single		Single byte used in concatenation
 *
 * This function carries out the operation
 *
 *     V = HMAC ( K, V )
 *
 * as used by hmac_drbg_update() and hmac_drbg_generate()
 */
static void hmac_drbg_update_value ( struct digest_algorithm *hash,
				     struct hmac_drbg_state *state ) {
	uint8_t context[ hash->ctxsize ];
	size_t out_len = hash->digestsize;

	/* Sanity checks */
	assert ( hash != NULL );
	assert ( state != NULL );

	/* V = HMAC ( K, V ) */
	hmac_init ( hash, context, state->key, &out_len );
	assert ( out_len == hash->digestsize );
	hmac_update ( hash, context, state->value, out_len );
	hmac_final ( hash, context, state->key, &out_len, state->value );
	assert ( out_len == hash->digestsize );

	DBGC ( state, "HMAC_DRBG_%s %p V = HMAC ( K, V ) :\n",
	       hash->name, state );
	DBGC_HDA ( state, 0, state->value, out_len );
}

/**
 * Update HMAC_DRBG internal state
 *
 * @v hash		Underlying hash algorithm
 * @v state		HMAC_DRBG internal state
 * @v data		Provided data
 * @v len		Length of provided data
 *
 * This is the HMAC_DRBG_Update function defined in ANS X9.82 Part
 * 3-2007 Section 10.2.2.2.2 (NIST SP 800-90 Section 10.1.2.2).
 *
 * The key and value are updated in-place within the HMAC_DRBG
 * internal state.
 */
static void hmac_drbg_update ( struct digest_algorithm *hash,
			       struct hmac_drbg_state *state,
			       const void *data, size_t len ) {

	DBGC ( state, "HMAC_DRBG_%s %p update\n", hash->name, state );

	/* Sanity checks */
	assert ( hash != NULL );
	assert ( state != NULL );
	assert ( ( data != NULL ) || ( len == 0 ) );

	/* 1.  K = HMAC ( K, V || 0x00 || provided_data ) */
	hmac_drbg_update_key ( hash, state, data, len, 0x00 );

	/* 2.  V = HMAC ( K, V ) */
	hmac_drbg_update_value ( hash, state );

	/* 3.  If ( provided_data = Null ), then return K and V */
	if ( ! len )
		return;

	/* 4.  K = HMAC ( K, V || 0x01 || provided_data ) */
	hmac_drbg_update_key ( hash, state, data, len, 0x01 );

	/* 5.  V = HMAC ( K, V ) */
	hmac_drbg_update_value ( hash, state );

	/* 6.  Return K and V */
}

/**
 * Instantiate HMAC_DRBG
 *
 * @v hash		Underlying hash algorithm
 * @v state		HMAC_DRBG internal state to be initialised
 * @v entropy		Entropy input
 * @v entropy_len	Length of entropy input
 * @v personal		Personalisation string
 * @v personal_len	Length of personalisation string
 *
 * This is the HMAC_DRBG_Instantiate_algorithm function defined in ANS
 * X9.82 Part 3-2007 Section 10.2.2.2.3 (NIST SP 800-90 Section
 * 10.1.2.3).
 *
 * The nonce must be included within the entropy input (i.e. the
 * entropy input must contain at least 3/2 * security_strength bits of
 * entropy, as per ANS X9.82 Part 3-2007 Section 8.4.2 (NIST SP 800-90
 * Section 8.6.7).
 *
 * The key, value and reseed counter are updated in-place within the
 * HMAC_DRBG internal state.
 */
void hmac_drbg_instantiate ( struct digest_algorithm *hash,
			     struct hmac_drbg_state *state,
			     const void *entropy, size_t entropy_len,
			     const void *personal, size_t personal_len ){
	size_t out_len = hash->digestsize;

	DBGC ( state, "HMAC_DRBG_%s %p instantiate\n", hash->name, state );

	/* Sanity checks */
	assert ( hash != NULL );
	assert ( state != NULL );
	assert ( entropy != NULL );
	assert ( ( personal != NULL ) || ( personal_len == 0 ) );

	/* 1.  seed_material = entropy_input || nonce ||
	 *     personalisation_string
	 */

	/* 2.  Key = 0x00 00..00 */
	memset ( state->key, 0x00, out_len );

	/* 3.  V = 0x01 01...01 */
	memset ( state->value, 0x01, out_len );

	/* 4.  ( Key, V ) = HMAC_DBRG_Update ( seed_material, Key, V )
	 * 5.  reseed_counter = 1
	 * 6.  Return V, Key and reseed_counter as the
	 *     initial_working_state
	 */
	hmac_drbg_reseed ( hash, state, entropy, entropy_len,
			   personal, personal_len );
}

/**
 * Reseed HMAC_DRBG
 *
 * @v hash		Underlying hash algorithm
 * @v state		HMAC_DRBG internal state
 * @v entropy		Entropy input
 * @v entropy_len	Length of entropy input
 * @v additional	Additional input
 * @v additional_len	Length of additional input
 *
 * This is the HMAC_DRBG_Reseed_algorithm function defined in ANS X9.82
 * Part 3-2007 Section 10.2.2.2.4 (NIST SP 800-90 Section 10.1.2.4).
 *
 * The key, value and reseed counter are updated in-place within the
 * HMAC_DRBG internal state.
 */
void hmac_drbg_reseed ( struct digest_algorithm *hash,
			struct hmac_drbg_state *state,
			const void *entropy, size_t entropy_len,
			const void *additional, size_t additional_len ) {
	uint8_t seed_material[ entropy_len + additional_len ];

	DBGC ( state, "HMAC_DRBG_%s %p (re)seed\n", hash->name, state );

	/* Sanity checks */
	assert ( hash != NULL );
	assert ( state != NULL );
	assert ( entropy != NULL );
	assert ( ( additional != NULL ) || ( additional_len == 0 ) );

	/* 1.  seed_material = entropy_input || additional_input */
	memcpy ( seed_material, entropy, entropy_len );
	memcpy ( ( seed_material + entropy_len ), additional, additional_len );
	DBGC ( state, "HMAC_DRBG_%s %p seed material :\n", hash->name, state );
	DBGC_HDA ( state, 0, seed_material, sizeof ( seed_material ) );

	/* 2.  ( Key, V ) = HMAC_DBRG_Update ( seed_material, Key, V ) */
	hmac_drbg_update ( hash, state, seed_material,
			   sizeof ( seed_material ) );

	/* 3.  reseed_counter = 1 */
	state->reseed_counter = 1;

	/* 4.  Return V, Key and reseed_counter as the new_working_state */
}

/**
 * Generate pseudorandom bits using HMAC_DRBG
 *
 * @v hash		Underlying hash algorithm
 * @v state		HMAC_DRBG internal state
 * @v additional	Additional input
 * @v additional_len	Length of additional input
 * @v data		Output buffer
 * @v len		Length of output buffer
 * @ret rc		Return status code
 *
 * This is the HMAC_DRBG_Generate_algorithm function defined in ANS X9.82
 * Part 3-2007 Section 10.2.2.2.5 (NIST SP 800-90 Section 10.1.2.5).
 *
 * Requests must be for an integral number of bytes.
 *
 * The key, value and reseed counter are updated in-place within the
 * HMAC_DRBG internal state.
 *
 * Note that the only permitted error is "reseed required".
 */
int hmac_drbg_generate ( struct digest_algorithm *hash,
			 struct hmac_drbg_state *state,
			 const void *additional, size_t additional_len,
			 void *data, size_t len ) {
	size_t out_len = hash->digestsize;
	void *orig_data = data;
	size_t orig_len = len;
	size_t frag_len;

	DBGC ( state, "HMAC_DRBG_%s %p generate\n", hash->name, state );

	/* Sanity checks */
	assert ( hash != NULL );
	assert ( state != NULL );
	assert ( data != NULL );
	assert ( ( additional != NULL ) || ( additional_len == 0 ) );

	/* 1.  If reseed_counter > reseed_interval, then return an
	 *     indication that a reseed is required
	 */
	if ( state->reseed_counter > HMAC_DRBG_RESEED_INTERVAL ) {
		DBGC ( state, "HMAC_DRBG_%s %p reseed interval exceeded\n",
		       hash->name, state );
		return -ESTALE;
	}

	/* 2.  If additional_input != Null, then
	 *     ( Key, V ) = HMAC_DRBG_Update ( additional_input, Key, V )
	 */
	if ( additional_len )
		hmac_drbg_update ( hash, state, additional, additional_len );

	/* 3.  temp = Null
	 * 4.  While ( len ( temp ) < requested_number_of_bits ) do:
	 */
	while ( len ) {

		/* 4.1  V = HMAC ( Key, V ) */
		hmac_drbg_update_value ( hash, state );

		/* 4.2.  temp = temp || V
		 * 5.    returned_bits = Leftmost requested_number_of_bits
		 *       of temp
		 */
		frag_len = len;
		if ( frag_len > out_len )
			frag_len = out_len;
		memcpy ( data, state->value, frag_len );
		data += frag_len;
		len -= frag_len;
	}

	/* 6.  ( Key, V ) = HMAC_DRBG_Update ( additional_input, Key, V ) */
	hmac_drbg_update ( hash, state, additional, additional_len );

	/* 7.  reseed_counter = reseed_counter + 1 */
	state->reseed_counter++;

	DBGC ( state, "HMAC_DRBG_%s %p generated :\n", hash->name, state );
	DBGC_HDA ( state, 0, orig_data, orig_len );

	/* 8.  Return SUCCESS, returned_bits, and the new values of
	 *     Key, V and reseed_counter as the new_working_state
	 */
	return 0;
}
