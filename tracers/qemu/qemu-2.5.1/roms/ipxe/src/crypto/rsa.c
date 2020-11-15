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

#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ipxe/asn1.h>
#include <ipxe/crypto.h>
#include <ipxe/bigint.h>
#include <ipxe/random_nz.h>
#include <ipxe/rsa.h>

/** @file
 *
 * RSA public-key cryptography
 *
 * RSA is documented in RFC 3447.
 */

/* Disambiguate the various error causes */
#define EACCES_VERIFY \
	__einfo_error ( EINFO_EACCES_VERIFY )
#define EINFO_EACCES_VERIFY \
	__einfo_uniqify ( EINFO_EACCES, 0x01, "RSA signature incorrect" )

/** "rsaEncryption" object identifier */
static uint8_t oid_rsa_encryption[] = { ASN1_OID_RSAENCRYPTION };

/** "rsaEncryption" OID-identified algorithm */
struct asn1_algorithm rsa_encryption_algorithm __asn1_algorithm = {
	.name = "rsaEncryption",
	.pubkey = &rsa_algorithm,
	.digest = NULL,
	.oid = ASN1_OID_CURSOR ( oid_rsa_encryption ),
};

/**
 * Identify RSA prefix
 *
 * @v digest		Digest algorithm
 * @ret prefix		RSA prefix, or NULL
 */
static struct rsa_digestinfo_prefix *
rsa_find_prefix ( struct digest_algorithm *digest ) {
	struct rsa_digestinfo_prefix *prefix;

	for_each_table_entry ( prefix, RSA_DIGESTINFO_PREFIXES ) {
		if ( prefix->digest == digest )
			return prefix;
	}
	return NULL;
}

/**
 * Free RSA dynamic storage
 *
 * @v context		RSA context
 */
static void rsa_free ( struct rsa_context *context ) {

	free ( context->dynamic );
	context->dynamic = NULL;
}

/**
 * Allocate RSA dynamic storage
 *
 * @v context		RSA context
 * @v modulus_len	Modulus length
 * @v exponent_len	Exponent length
 * @ret rc		Return status code
 */
static int rsa_alloc ( struct rsa_context *context, size_t modulus_len,
		       size_t exponent_len ) {
	unsigned int size = bigint_required_size ( modulus_len );
	unsigned int exponent_size = bigint_required_size ( exponent_len );
	bigint_t ( size ) *modulus;
	bigint_t ( exponent_size ) *exponent;
	size_t tmp_len = bigint_mod_exp_tmp_len ( modulus, exponent );
	struct {
		bigint_t ( size ) modulus;
		bigint_t ( exponent_size ) exponent;
		bigint_t ( size ) input;
		bigint_t ( size ) output;
		uint8_t tmp[tmp_len];
	} __attribute__ (( packed )) *dynamic;

	/* Free any existing dynamic storage */
	rsa_free ( context );

	/* Allocate dynamic storage */
	dynamic = malloc ( sizeof ( *dynamic ) );
	if ( ! dynamic )
		return -ENOMEM;

	/* Assign dynamic storage */
	context->dynamic = dynamic;
	context->modulus0 = &dynamic->modulus.element[0];
	context->size = size;
	context->max_len = modulus_len;
	context->exponent0 = &dynamic->exponent.element[0];
	context->exponent_size = exponent_size;
	context->input0 = &dynamic->input.element[0];
	context->output0 = &dynamic->output.element[0];
	context->tmp = &dynamic->tmp;

	return 0;
}

/**
 * Parse RSA integer
 *
 * @v integer		Integer to fill in
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int rsa_parse_integer ( struct asn1_cursor *integer,
			       const struct asn1_cursor *raw ) {

	/* Enter integer */
	memcpy ( integer, raw, sizeof ( *integer ) );
	asn1_enter ( integer, ASN1_INTEGER );

	/* Skip initial sign byte if applicable */
	if ( ( integer->len > 1 ) &&
	     ( *( ( uint8_t * ) integer->data ) == 0x00 ) ) {
		integer->data++;
		integer->len--;
	}

	/* Fail if cursor or integer are invalid */
	if ( ! integer->len )
		return -EINVAL;

	return 0;
}

/**
 * Parse RSA modulus and exponent
 *
 * @v modulus		Modulus to fill in
 * @v exponent		Exponent to fill in
 * @v raw		ASN.1 cursor
 * @ret rc		Return status code
 */
static int rsa_parse_mod_exp ( struct asn1_cursor *modulus,
			       struct asn1_cursor *exponent,
			       const struct asn1_cursor *raw ) {
	struct asn1_bit_string bits;
	struct asn1_cursor cursor;
	int is_private;
	int rc;

	/* Enter subjectPublicKeyInfo/RSAPrivateKey */
	memcpy ( &cursor, raw, sizeof ( cursor ) );
	asn1_enter ( &cursor, ASN1_SEQUENCE );

	/* Determine key format */
	if ( asn1_type ( &cursor ) == ASN1_INTEGER ) {

		/* Private key */
		is_private = 1;

		/* Skip version */
		asn1_skip_any ( &cursor );

	} else {

		/* Public key */
		is_private = 0;

		/* Skip algorithm */
		asn1_skip ( &cursor, ASN1_SEQUENCE );

		/* Enter subjectPublicKey */
		if ( ( rc = asn1_integral_bit_string ( &cursor, &bits ) ) != 0 )
			return rc;
		cursor.data = bits.data;
		cursor.len = bits.len;

		/* Enter RSAPublicKey */
		asn1_enter ( &cursor, ASN1_SEQUENCE );
	}

	/* Extract modulus */
	if ( ( rc = rsa_parse_integer ( modulus, &cursor ) ) != 0 )
		return rc;
	asn1_skip_any ( &cursor );

	/* Skip public exponent, if applicable */
	if ( is_private )
		asn1_skip ( &cursor, ASN1_INTEGER );

	/* Extract publicExponent/privateExponent */
	if ( ( rc = rsa_parse_integer ( exponent, &cursor ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Initialise RSA cipher
 *
 * @v ctx		RSA context
 * @v key		Key
 * @v key_len		Length of key
 * @ret rc		Return status code
 */
static int rsa_init ( void *ctx, const void *key, size_t key_len ) {
	struct rsa_context *context = ctx;
	struct asn1_cursor modulus;
	struct asn1_cursor exponent;
	struct asn1_cursor cursor;
	int rc;

	/* Initialise context */
	memset ( context, 0, sizeof ( *context ) );

	/* Initialise cursor */
	cursor.data = key;
	cursor.len = key_len;

	/* Parse modulus and exponent */
	if ( ( rc = rsa_parse_mod_exp ( &modulus, &exponent, &cursor ) ) != 0 ){
		DBGC ( context, "RSA %p invalid modulus/exponent:\n", context );
		DBGC_HDA ( context, 0, cursor.data, cursor.len );
		goto err_parse;
	}

	DBGC ( context, "RSA %p modulus:\n", context );
	DBGC_HDA ( context, 0, modulus.data, modulus.len );
	DBGC ( context, "RSA %p exponent:\n", context );
	DBGC_HDA ( context, 0, exponent.data, exponent.len );

	/* Allocate dynamic storage */
	if ( ( rc = rsa_alloc ( context, modulus.len, exponent.len ) ) != 0 )
		goto err_alloc;

	/* Construct big integers */
	bigint_init ( ( ( bigint_t ( context->size ) * ) context->modulus0 ),
		      modulus.data, modulus.len );
	bigint_init ( ( ( bigint_t ( context->exponent_size ) * )
			context->exponent0 ), exponent.data, exponent.len );

	return 0;

	rsa_free ( context );
 err_alloc:
 err_parse:
	return rc;
}

/**
 * Calculate RSA maximum output length
 *
 * @v ctx		RSA context
 * @ret max_len		Maximum output length
 */
static size_t rsa_max_len ( void *ctx ) {
	struct rsa_context *context = ctx;

	return context->max_len;
}

/**
 * Perform RSA cipher operation
 *
 * @v context		RSA context
 * @v in		Input buffer
 * @v out		Output buffer
 */
static void rsa_cipher ( struct rsa_context *context,
			 const void *in, void *out ) {
	bigint_t ( context->size ) *input = ( ( void * ) context->input0 );
	bigint_t ( context->size ) *output = ( ( void * ) context->output0 );
	bigint_t ( context->size ) *modulus = ( ( void * ) context->modulus0 );
	bigint_t ( context->exponent_size ) *exponent =
		( ( void * ) context->exponent0 );

	/* Initialise big integer */
	bigint_init ( input, in, context->max_len );

	/* Perform modular exponentiation */
	bigint_mod_exp ( input, modulus, exponent, output, context->tmp );

	/* Copy out result */
	bigint_done ( output, out, context->max_len );
}

/**
 * Encrypt using RSA
 *
 * @v ctx		RSA context
 * @v plaintext		Plaintext
 * @v plaintext_len	Length of plaintext
 * @v ciphertext	Ciphertext
 * @ret ciphertext_len	Length of ciphertext, or negative error
 */
static int rsa_encrypt ( void *ctx, const void *plaintext,
			 size_t plaintext_len, void *ciphertext ) {
	struct rsa_context *context = ctx;
	void *temp;
	uint8_t *encoded;
	size_t max_len = ( context->max_len - 11 );
	size_t random_nz_len = ( max_len - plaintext_len + 8 );
	int rc;

	/* Sanity check */
	if ( plaintext_len > max_len ) {
		DBGC ( context, "RSA %p plaintext too long (%zd bytes, max "
		       "%zd)\n", context, plaintext_len, max_len );
		return -ERANGE;
	}
	DBGC ( context, "RSA %p encrypting:\n", context );
	DBGC_HDA ( context, 0, plaintext, plaintext_len );

	/* Construct encoded message (using the big integer output
	 * buffer as temporary storage)
	 */
	temp = context->output0;
	encoded = temp;
	encoded[0] = 0x00;
	encoded[1] = 0x02;
	if ( ( rc = get_random_nz ( &encoded[2], random_nz_len ) ) != 0 ) {
		DBGC ( context, "RSA %p could not generate random data: %s\n",
		       context, strerror ( rc ) );
		return rc;
	}
	encoded[ 2 + random_nz_len ] = 0x00;
	memcpy ( &encoded[ context->max_len - plaintext_len ],
		 plaintext, plaintext_len );

	/* Encipher the encoded message */
	rsa_cipher ( context, encoded, ciphertext );
	DBGC ( context, "RSA %p encrypted:\n", context );
	DBGC_HDA ( context, 0, ciphertext, context->max_len );

	return context->max_len;
}

/**
 * Decrypt using RSA
 *
 * @v ctx		RSA context
 * @v ciphertext	Ciphertext
 * @v ciphertext_len	Ciphertext length
 * @v plaintext		Plaintext
 * @ret plaintext_len	Plaintext length, or negative error
 */
static int rsa_decrypt ( void *ctx, const void *ciphertext,
			 size_t ciphertext_len, void *plaintext ) {
	struct rsa_context *context = ctx;
	void *temp;
	uint8_t *encoded;
	uint8_t *end;
	uint8_t *zero;
	uint8_t *start;
	size_t plaintext_len;

	/* Sanity check */
	if ( ciphertext_len != context->max_len ) {
		DBGC ( context, "RSA %p ciphertext incorrect length (%zd "
		       "bytes, should be %zd)\n",
		       context, ciphertext_len, context->max_len );
		return -ERANGE;
	}
	DBGC ( context, "RSA %p decrypting:\n", context );
	DBGC_HDA ( context, 0, ciphertext, ciphertext_len );

	/* Decipher the message (using the big integer input buffer as
	 * temporary storage)
	 */
	temp = context->input0;
	encoded = temp;
	rsa_cipher ( context, ciphertext, encoded );

	/* Parse the message */
	end = ( encoded + context->max_len );
	if ( ( encoded[0] != 0x00 ) || ( encoded[1] != 0x02 ) )
		goto invalid;
	zero = memchr ( &encoded[2], 0, ( end - &encoded[2] ) );
	if ( ! zero )
		goto invalid;
	start = ( zero + 1 );
	plaintext_len = ( end - start );

	/* Copy out message */
	memcpy ( plaintext, start, plaintext_len );
	DBGC ( context, "RSA %p decrypted:\n", context );
	DBGC_HDA ( context, 0, plaintext, plaintext_len );

	return plaintext_len;

 invalid:
	DBGC ( context, "RSA %p invalid decrypted message:\n", context );
	DBGC_HDA ( context, 0, encoded, context->max_len );
	return -EINVAL;
}

/**
 * Encode RSA digest
 *
 * @v context		RSA context
 * @v digest		Digest algorithm
 * @v value		Digest value
 * @v encoded		Encoded digest
 * @ret rc		Return status code
 */
static int rsa_encode_digest ( struct rsa_context *context,
			       struct digest_algorithm *digest,
			       const void *value, void *encoded ) {
	struct rsa_digestinfo_prefix *prefix;
	size_t digest_len = digest->digestsize;
	uint8_t *temp = encoded;
	size_t digestinfo_len;
	size_t max_len;
	size_t pad_len;

	/* Identify prefix */
	prefix = rsa_find_prefix ( digest );
	if ( ! prefix ) {
		DBGC ( context, "RSA %p has no prefix for %s\n",
		       context, digest->name );
		return -ENOTSUP;
	}
	digestinfo_len = ( prefix->len + digest_len );

	/* Sanity check */
	max_len = ( context->max_len - 11 );
	if ( digestinfo_len > max_len ) {
		DBGC ( context, "RSA %p %s digestInfo too long (%zd bytes, max"
		       "%zd)\n",
		       context, digest->name, digestinfo_len, max_len );
		return -ERANGE;
	}
	DBGC ( context, "RSA %p encoding %s digest:\n",
	       context, digest->name );
	DBGC_HDA ( context, 0, value, digest_len );

	/* Construct encoded message */
	*(temp++) = 0x00;
	*(temp++) = 0x01;
	pad_len = ( max_len - digestinfo_len + 8 );
	memset ( temp, 0xff, pad_len );
	temp += pad_len;
	*(temp++) = 0x00;
	memcpy ( temp, prefix->data, prefix->len );
	temp += prefix->len;
	memcpy ( temp, value, digest_len );
	temp += digest_len;
	assert ( temp == ( encoded + context->max_len ) );
	DBGC ( context, "RSA %p encoded %s digest:\n", context, digest->name );
	DBGC_HDA ( context, 0, encoded, context->max_len );

	return 0;
}

/**
 * Sign digest value using RSA
 *
 * @v ctx		RSA context
 * @v digest		Digest algorithm
 * @v value		Digest value
 * @v signature		Signature
 * @ret signature_len	Signature length, or negative error
 */
static int rsa_sign ( void *ctx, struct digest_algorithm *digest,
		      const void *value, void *signature ) {
	struct rsa_context *context = ctx;
	void *temp;
	int rc;

	DBGC ( context, "RSA %p signing %s digest:\n", context, digest->name );
	DBGC_HDA ( context, 0, value, digest->digestsize );

	/* Encode digest (using the big integer output buffer as
	 * temporary storage)
	 */
	temp = context->output0;
	if ( ( rc = rsa_encode_digest ( context, digest, value, temp ) ) != 0 )
		return rc;

	/* Encipher the encoded digest */
	rsa_cipher ( context, temp, signature );
	DBGC ( context, "RSA %p signed %s digest:\n", context, digest->name );
	DBGC_HDA ( context, 0, signature, context->max_len );

	return context->max_len;
}

/**
 * Verify signed digest value using RSA
 *
 * @v ctx		RSA context
 * @v digest		Digest algorithm
 * @v value		Digest value
 * @v signature		Signature
 * @v signature_len	Signature length
 * @ret rc		Return status code
 */
static int rsa_verify ( void *ctx, struct digest_algorithm *digest,
			const void *value, const void *signature,
			size_t signature_len ) {
	struct rsa_context *context = ctx;
	void *temp;
	void *expected;
	void *actual;
	int rc;

	/* Sanity check */
	if ( signature_len != context->max_len ) {
		DBGC ( context, "RSA %p signature incorrect length (%zd "
		       "bytes, should be %zd)\n",
		       context, signature_len, context->max_len );
		return -ERANGE;
	}
	DBGC ( context, "RSA %p verifying %s digest:\n",
	       context, digest->name );
	DBGC_HDA ( context, 0, value, digest->digestsize );
	DBGC_HDA ( context, 0, signature, signature_len );

	/* Decipher the signature (using the big integer input buffer
	 * as temporary storage)
	 */
	temp = context->input0;
	expected = temp;
	rsa_cipher ( context, signature, expected );
	DBGC ( context, "RSA %p deciphered signature:\n", context );
	DBGC_HDA ( context, 0, expected, context->max_len );

	/* Encode digest (using the big integer output buffer as
	 * temporary storage)
	 */
	temp = context->output0;
	actual = temp;
	if ( ( rc = rsa_encode_digest ( context, digest, value, actual ) ) !=0 )
		return rc;

	/* Verify the signature */
	if ( memcmp ( actual, expected, context->max_len ) != 0 ) {
		DBGC ( context, "RSA %p signature verification failed\n",
		       context );
		return -EACCES_VERIFY;
	}

	DBGC ( context, "RSA %p signature verified successfully\n", context );
	return 0;
}

/**
 * Finalise RSA cipher
 *
 * @v ctx		RSA context
 */
static void rsa_final ( void *ctx ) {
	struct rsa_context *context = ctx;

	rsa_free ( context );
}

/**
 * Check for matching RSA public/private key pair
 *
 * @v private_key	Private key
 * @v private_key_len	Private key length
 * @v public_key	Public key
 * @v public_key_len	Public key length
 * @ret rc		Return status code
 */
static int rsa_match ( const void *private_key, size_t private_key_len,
		       const void *public_key, size_t public_key_len ) {
	struct asn1_cursor private_modulus;
	struct asn1_cursor private_exponent;
	struct asn1_cursor private_cursor;
	struct asn1_cursor public_modulus;
	struct asn1_cursor public_exponent;
	struct asn1_cursor public_cursor;
	int rc;

	/* Initialise cursors */
	private_cursor.data = private_key;
	private_cursor.len = private_key_len;
	public_cursor.data = public_key;
	public_cursor.len = public_key_len;

	/* Parse moduli and exponents */
	if ( ( rc = rsa_parse_mod_exp ( &private_modulus, &private_exponent,
					&private_cursor ) ) != 0 )
		return rc;
	if ( ( rc = rsa_parse_mod_exp ( &public_modulus, &public_exponent,
					&public_cursor ) ) != 0 )
		return rc;

	/* Compare moduli */
	if ( asn1_compare ( &private_modulus, &public_modulus ) != 0 )
		return -ENOTTY;

	return 0;
}

/** RSA public-key algorithm */
struct pubkey_algorithm rsa_algorithm = {
	.name		= "rsa",
	.ctxsize	= sizeof ( struct rsa_context ),
	.init		= rsa_init,
	.max_len	= rsa_max_len,
	.encrypt	= rsa_encrypt,
	.decrypt	= rsa_decrypt,
	.sign		= rsa_sign,
	.verify		= rsa_verify,
	.final		= rsa_final,
	.match		= rsa_match,
};
