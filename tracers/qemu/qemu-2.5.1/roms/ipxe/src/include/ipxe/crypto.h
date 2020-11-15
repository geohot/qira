#ifndef _IPXE_CRYPTO_H
#define _IPXE_CRYPTO_H

/** @file
 *
 * Cryptographic API
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <stddef.h>

/** A message digest algorithm */
struct digest_algorithm {
	/** Algorithm name */
	const char *name;
	/** Context size */
	size_t ctxsize;
	/** Block size */
	size_t blocksize;
	/** Digest size */
	size_t digestsize;
	/** Initialise digest
	 *
	 * @v ctx		Context
	 */
	void ( * init ) ( void *ctx );
	/** Update digest with new data
	 *
	 * @v ctx		Context
	 * @v src		Data to digest
	 * @v len		Length of data
	 *
	 * @v len is not necessarily a multiple of @c blocksize.
	 */
	void ( * update ) ( void *ctx, const void *src, size_t len );
	/** Finalise digest
	 *
	 * @v ctx		Context
	 * @v out		Buffer for digest output
	 */
	void ( * final ) ( void *ctx, void *out );
};

/** A cipher algorithm */
struct cipher_algorithm {
	/** Algorithm name */
	const char *name;
	/** Context size */
	size_t ctxsize;
	/** Block size */
	size_t blocksize;
	/** Set key
	 *
	 * @v ctx		Context
	 * @v key		Key
	 * @v keylen		Key length
	 * @ret rc		Return status code
	 */
	int ( * setkey ) ( void *ctx, const void *key, size_t keylen );
	/** Set initialisation vector
	 *
	 * @v ctx		Context
	 * @v iv		Initialisation vector
	 */
	void ( * setiv ) ( void *ctx, const void *iv );
	/** Encrypt data
	 *
	 * @v ctx		Context
	 * @v src		Data to encrypt
	 * @v dst		Buffer for encrypted data
	 * @v len		Length of data
	 *
	 * @v len is guaranteed to be a multiple of @c blocksize.
	 */
	void ( * encrypt ) ( void *ctx, const void *src, void *dst,
			     size_t len );
	/** Decrypt data
	 *
	 * @v ctx		Context
	 * @v src		Data to decrypt
	 * @v dst		Buffer for decrypted data
	 * @v len		Length of data
	 *
	 * @v len is guaranteed to be a multiple of @c blocksize.
	 */
	void ( * decrypt ) ( void *ctx, const void *src, void *dst,
			     size_t len );
};

/** A public key algorithm */
struct pubkey_algorithm {
	/** Algorithm name */
	const char *name;
	/** Context size */
	size_t ctxsize;
	/** Initialise algorithm
	 *
	 * @v ctx		Context
	 * @v key		Key
	 * @v key_len		Length of key
	 * @ret rc		Return status code
	 */
	int ( * init ) ( void *ctx, const void *key, size_t key_len );
	/** Calculate maximum output length
	 *
	 * @v ctx		Context
	 * @ret max_len		Maximum output length
	 */
	size_t ( * max_len ) ( void *ctx );
	/** Encrypt
	 *
	 * @v ctx		Context
	 * @v plaintext		Plaintext
	 * @v plaintext_len	Length of plaintext
	 * @v ciphertext	Ciphertext
	 * @ret ciphertext_len	Length of ciphertext, or negative error
	 */
	int ( * encrypt ) ( void *ctx, const void *data, size_t len,
			    void *out );
	/** Decrypt
	 *
	 * @v ctx		Context
	 * @v ciphertext	Ciphertext
	 * @v ciphertext_len	Ciphertext length
	 * @v plaintext		Plaintext
	 * @ret plaintext_len	Plaintext length, or negative error
	 */
	int ( * decrypt ) ( void *ctx, const void *data, size_t len,
			    void *out );
	/** Sign digest value
	 *
	 * @v ctx		Context
	 * @v digest		Digest algorithm
	 * @v value		Digest value
	 * @v signature		Signature
	 * @ret signature_len	Signature length, or negative error
	 */
	int ( * sign ) ( void *ctx, struct digest_algorithm *digest,
			 const void *value, void *signature );
	/** Verify signed digest value
	 *
	 * @v ctx		Context
	 * @v digest		Digest algorithm
	 * @v value		Digest value
	 * @v signature		Signature
	 * @v signature_len	Signature length
	 * @ret rc		Return status code
	 */
	int ( * verify ) ( void *ctx, struct digest_algorithm *digest,
			   const void *value, const void *signature,
			   size_t signature_len );
	/** Finalise algorithm
	 *
	 * @v ctx		Context
	 */
	void ( * final ) ( void *ctx );
	/** Check that public key matches private key
	 *
	 * @v private_key	Private key
	 * @v private_key_len	Private key length
	 * @v public_key	Public key
	 * @v public_key_len	Public key length
	 * @ret rc		Return status code
	 */
	int ( * match ) ( const void *private_key, size_t private_key_len,
			  const void *public_key, size_t public_key_len );
};

static inline void digest_init ( struct digest_algorithm *digest,
				 void *ctx ) {
	digest->init ( ctx );
}

static inline void digest_update ( struct digest_algorithm *digest,
				   void *ctx, const void *data, size_t len ) {
	digest->update ( ctx, data, len );
}

static inline void digest_final ( struct digest_algorithm *digest,
				  void *ctx, void *out ) {
	digest->final ( ctx, out );
}

static inline int cipher_setkey ( struct cipher_algorithm *cipher,
				  void *ctx, const void *key, size_t keylen ) {
	return cipher->setkey ( ctx, key, keylen );
}

static inline void cipher_setiv ( struct cipher_algorithm *cipher,
				  void *ctx, const void *iv ) {
	cipher->setiv ( ctx, iv );
}

static inline void cipher_encrypt ( struct cipher_algorithm *cipher,
				    void *ctx, const void *src, void *dst,
				    size_t len ) {
	cipher->encrypt ( ctx, src, dst, len );
}
#define cipher_encrypt( cipher, ctx, src, dst, len ) do {		\
	assert ( ( (len) & ( (cipher)->blocksize - 1 ) ) == 0 );	\
	cipher_encrypt ( (cipher), (ctx), (src), (dst), (len) );	\
	} while ( 0 )

static inline void cipher_decrypt ( struct cipher_algorithm *cipher,
				    void *ctx, const void *src, void *dst,
				    size_t len ) {
	cipher->decrypt ( ctx, src, dst, len );
}
#define cipher_decrypt( cipher, ctx, src, dst, len ) do {		\
	assert ( ( (len) & ( (cipher)->blocksize - 1 ) ) == 0 );	\
	cipher_decrypt ( (cipher), (ctx), (src), (dst), (len) );	\
	} while ( 0 )

static inline int is_stream_cipher ( struct cipher_algorithm *cipher ) {
	return ( cipher->blocksize == 1 );
}

static inline int pubkey_init ( struct pubkey_algorithm *pubkey, void *ctx,
				const void *key, size_t key_len ) {
	return pubkey->init ( ctx, key, key_len );
}

static inline size_t pubkey_max_len ( struct pubkey_algorithm *pubkey,
				      void *ctx ) {
	return pubkey->max_len ( ctx );
}

static inline int pubkey_encrypt ( struct pubkey_algorithm *pubkey, void *ctx,
				   const void *data, size_t len, void *out ) {
	return pubkey->encrypt ( ctx, data, len, out );
}

static inline int pubkey_decrypt ( struct pubkey_algorithm *pubkey, void *ctx,
				   const void *data, size_t len, void *out ) {
	return pubkey->decrypt ( ctx, data, len, out );
}

static inline int pubkey_sign ( struct pubkey_algorithm *pubkey, void *ctx,
				struct digest_algorithm *digest,
				const void *value, void *signature ) {
	return pubkey->sign ( ctx, digest, value, signature );
}

static inline int pubkey_verify ( struct pubkey_algorithm *pubkey, void *ctx,
				  struct digest_algorithm *digest,
				  const void *value, const void *signature,
				  size_t signature_len ) {
	return pubkey->verify ( ctx, digest, value, signature, signature_len );
}

static inline void pubkey_final ( struct pubkey_algorithm *pubkey, void *ctx ) {
	pubkey->final ( ctx );
}

static inline int pubkey_match ( struct pubkey_algorithm *pubkey,
				 const void *private_key,
				 size_t private_key_len, const void *public_key,
				 size_t public_key_len ) {
	return pubkey->match ( private_key, private_key_len, public_key,
			       public_key_len );
}

extern struct digest_algorithm digest_null;
extern struct cipher_algorithm cipher_null;
extern struct pubkey_algorithm pubkey_null;

#endif /* _IPXE_CRYPTO_H */
