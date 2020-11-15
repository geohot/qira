#ifndef _IPXE_CBC_H
#define _IPXE_CBC_H

/** @file
 *
 * Cipher-block chaining
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/crypto.h>

/**
 * Set key
 *
 * @v ctx		Context
 * @v key		Key
 * @v keylen		Key length
 * @v raw_cipher	Underlying cipher algorithm
 * @v cbc_ctx		CBC context
 * @ret rc		Return status code
 */
static inline int cbc_setkey ( void *ctx, const void *key, size_t keylen,
			       struct cipher_algorithm *raw_cipher,
			       void *cbc_ctx __unused ) {

	return cipher_setkey ( raw_cipher, ctx, key, keylen );
}

/**
 * Set initialisation vector
 *
 * @v ctx		Context
 * @v iv		Initialisation vector
 * @v raw_cipher	Underlying cipher algorithm
 * @v cbc_ctx		CBC context
 */
static inline void cbc_setiv ( void *ctx __unused, const void *iv,
			       struct cipher_algorithm *raw_cipher,
			       void *cbc_ctx ) {
	memcpy ( cbc_ctx, iv, raw_cipher->blocksize );
}

extern void cbc_encrypt ( void *ctx, const void *src, void *dst,
			  size_t len, struct cipher_algorithm *raw_cipher,
			  void *cbc_ctx );
extern void cbc_decrypt ( void *ctx, const void *src, void *dst,
			  size_t len, struct cipher_algorithm *raw_cipher,
			  void *cbc_ctx );

/**
 * Create a cipher-block chaining mode of behaviour of an existing cipher
 *
 * @v _cbc_name		Name for the new CBC cipher
 * @v _cbc_cipher	New cipher algorithm
 * @v _raw_cipher	Underlying cipher algorithm
 * @v _raw_context	Context structure for the underlying cipher
 * @v _blocksize	Cipher block size
 */
#define CBC_CIPHER( _cbc_name, _cbc_cipher, _raw_cipher, _raw_context,	\
		    _blocksize )					\
struct _cbc_name ## _context {						\
	_raw_context raw_ctx;						\
	uint8_t cbc_ctx[_blocksize];					\
};									\
static int _cbc_name ## _setkey ( void *ctx, const void *key,		\
				  size_t keylen ) {			\
	struct _cbc_name ## _context * _cbc_name ## _ctx = ctx;		\
	return cbc_setkey ( &_cbc_name ## _ctx->raw_ctx, key, keylen,	\
			    &_raw_cipher, &_cbc_name ## _ctx->cbc_ctx );\
}									\
static void _cbc_name ## _setiv ( void *ctx, const void *iv ) {		\
	struct _cbc_name ## _context * _cbc_name ## _ctx = ctx;		\
	cbc_setiv ( &_cbc_name ## _ctx->raw_ctx, iv,			\
		    &_raw_cipher, &aes_cbc_ctx->cbc_ctx );		\
}									\
static void _cbc_name ## _encrypt ( void *ctx, const void *src,		\
				    void *dst, size_t len ) {		\
	struct _cbc_name ## _context * _cbc_name ## _ctx = ctx;		\
	cbc_encrypt ( &_cbc_name ## _ctx->raw_ctx, src, dst, len,	\
		      &_raw_cipher, &aes_cbc_ctx->cbc_ctx );		\
}									\
static void _cbc_name ## _decrypt ( void *ctx, const void *src,		\
				    void *dst, size_t len ) {		\
	struct _cbc_name ## _context * _cbc_name ## _ctx = ctx;		\
	cbc_decrypt ( &_cbc_name ## _ctx->raw_ctx, src, dst, len,	\
		      &_raw_cipher, &aes_cbc_ctx->cbc_ctx );		\
}									\
struct cipher_algorithm _cbc_cipher = {					\
	.name		= #_cbc_name,					\
	.ctxsize	= sizeof ( struct _cbc_name ## _context ),	\
	.blocksize	= _blocksize,					\
	.setkey		= _cbc_name ## _setkey,				\
	.setiv		= _cbc_name ## _setiv,				\
	.encrypt	= _cbc_name ## _encrypt,			\
	.decrypt	= _cbc_name ## _decrypt,			\
};

#endif /* _IPXE_CBC_H */
