#ifndef _PUBKEY_TEST_H
#define _PUBKEY_TEST_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/crypto.h>
#include <ipxe/test.h>

/**
 * Report public key decryption test result
 *
 * @v pubkey		Public key algorithm
 * @v key		Key
 * @v key_len		Key length
 * @v ciphertext	Ciphertext
 * @v ciphertext_len	Ciphertext length
 * @v expected		Expected plaintext
 * @v expected_len	Expected plaintext length
 */
#define pubkey_decrypt_ok( pubkey, key, key_len, ciphertext,		\
			   ciphertext_len, expected, expected_len ) do {\
	uint8_t ctx[ (pubkey)->ctxsize ];				\
									\
	ok ( pubkey_init ( (pubkey), ctx, (key), (key_len) ) == 0 );	\
	{								\
		size_t max_len = pubkey_max_len ( (pubkey), ctx );	\
		uint8_t decrypted[ max_len ];				\
		int decrypted_len;					\
									\
		decrypted_len = pubkey_decrypt ( (pubkey), ctx,		\
						 (ciphertext),		\
						 (ciphertext_len),	\
						 decrypted );		\
		ok ( decrypted_len == ( ( int ) (expected_len) ) );	\
		ok ( memcmp ( decrypted, (expected),			\
			      (expected_len) ) == 0 );			\
	}								\
	pubkey_final ( (pubkey), ctx );					\
	} while ( 0 )

/**
 * Report public key encryption and decryption test result
 *
 * @v pubkey		Public key algorithm
 * @v encrypt_key	Encryption key
 * @v encrypt_key_len	Encryption key length
 * @v decrypt_key	Decryption key
 * @v decrypt_key_len	Decryption key length
 * @v plaintext		Plaintext
 * @v plaintext_len	Plaintext length
 */
#define pubkey_encrypt_ok( pubkey, encrypt_key, encrypt_key_len,	\
			   decrypt_key, decrypt_key_len, plaintext,	\
			   plaintext_len ) do {				\
	uint8_t ctx[ (pubkey)->ctxsize ];				\
									\
	ok ( pubkey_init ( (pubkey), ctx, (encrypt_key),		\
			   (encrypt_key_len) ) == 0 );			\
	{								\
		size_t max_len = pubkey_max_len ( (pubkey), ctx );	\
		uint8_t encrypted[ max_len ];				\
		int encrypted_len;					\
									\
		encrypted_len = pubkey_encrypt ( (pubkey), ctx,		\
						 (plaintext),		\
						 (plaintext_len),	\
						 encrypted );		\
		ok ( encrypted_len >= 0 );				\
		pubkey_decrypt_ok ( (pubkey), (decrypt_key),		\
				    (decrypt_key_len), encrypted,	\
				    encrypted_len, (plaintext),		\
				    (plaintext_len) );			\
	}								\
	pubkey_final ( (pubkey), ctx );					\
	} while ( 0 )

/**
 * Report public key signature test result
 *
 * @v pubkey		Public key algorithm
 * @v key		Key
 * @v key_len		Key length
 * @v digest		Digest algorithm
 * @v plaintext		Plaintext
 * @v plaintext_len	Plaintext length
 * @v expected		Expected signature
 * @v expected_len	Expected signature length
 */
#define pubkey_sign_ok( pubkey, key, key_len, digest, plaintext,	\
			plaintext_len, expected, expected_len ) do {	\
	uint8_t ctx[ (pubkey)->ctxsize ];				\
	uint8_t digestctx[ (digest)->ctxsize ];				\
	uint8_t digestout[ (digest)->digestsize ];			\
									\
	digest_init ( (digest), digestctx );				\
	digest_update ( (digest), digestctx, (plaintext),		\
			(plaintext_len) );				\
	digest_final ( (digest), digestctx, digestout );		\
									\
	ok ( pubkey_init ( (pubkey), ctx, (key), (key_len) ) == 0 );	\
	{								\
		size_t max_len = pubkey_max_len ( (pubkey), ctx );	\
		uint8_t signature[ max_len ];				\
		int signature_len;					\
									\
		signature_len = pubkey_sign ( (pubkey), ctx, (digest),	\
					      digestout, signature );	\
		ok ( signature_len == ( ( int ) (expected_len) ) );	\
		ok ( memcmp ( signature, (expected),			\
			      (expected_len) ) == 0 );			\
	}								\
	pubkey_final ( (pubkey), ctx );					\
	} while ( 0 )

/**
 * Report public key verification test result
 *
 * @v pubkey		Public key algorithm
 * @v key		Key
 * @v key_len		Key length
 * @v digest		Digest algorithm
 * @v plaintext		Plaintext
 * @v plaintext_len	Plaintext length
 * @v signature		Signature
 * @v signature_len	Signature length
 */
#define pubkey_verify_ok( pubkey, key, key_len, digest, plaintext,	\
			  plaintext_len, signature, signature_len ) do {\
	uint8_t ctx[ (pubkey)->ctxsize ];				\
	uint8_t digestctx[ (digest)->ctxsize ];				\
	uint8_t digestout[ (digest)->digestsize ];			\
									\
	digest_init ( (digest), digestctx );				\
	digest_update ( (digest), digestctx, (plaintext),		\
			(plaintext_len) );				\
	digest_final ( (digest), digestctx, digestout );		\
									\
	ok ( pubkey_init ( (pubkey), ctx, (key), (key_len) ) == 0 );	\
	ok ( pubkey_verify ( (pubkey), ctx, (digest), digestout,	\
			     (signature), (signature_len) ) == 0 );	\
	pubkey_final ( (pubkey), ctx );					\
	} while ( 0 )

/**
 * Report public key verification test result
 *
 * @v pubkey		Public key algorithm
 * @v key		Key
 * @v key_len		Key length
 * @v digest		Digest algorithm
 * @v plaintext		Plaintext
 * @v plaintext_len	Plaintext length
 * @v signature		Signature
 * @v signature_len	Signature length
 */
#define pubkey_verify_fail_ok( pubkey, key, key_len, digest, plaintext,	\
			       plaintext_len, signature,		\
			       signature_len ) do {			\
	uint8_t ctx[ (pubkey)->ctxsize ];				\
	uint8_t digestctx[ (digest)->ctxsize ];				\
	uint8_t digestout[ (digest)->digestsize ];			\
									\
	digest_init ( (digest), digestctx );				\
	digest_update ( (digest), digestctx, (plaintext),		\
			(plaintext_len) );				\
	digest_final ( (digest), digestctx, digestout );		\
									\
	ok ( pubkey_init ( (pubkey), ctx, (key), (key_len) ) == 0 );	\
	ok ( pubkey_verify ( (pubkey), ctx, (digest), digestout,	\
			     (signature), (signature_len) ) != 0 );	\
	pubkey_final ( (pubkey), ctx );					\
	} while ( 0 )

#endif /* _PUBKEY_TEST_H */
