#ifndef _IPXE_ECB_H
#define _IPXE_ECB_H

/** @file
 *
 * Electronic codebook (ECB)
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/crypto.h>

extern void ecb_encrypt ( void *ctx, const void *src, void *dst,
			  size_t len, struct cipher_algorithm *raw_cipher );
extern void ecb_decrypt ( void *ctx, const void *src, void *dst,
			  size_t len, struct cipher_algorithm *raw_cipher );

/**
 * Create a cipher-block chaining mode of behaviour of an existing cipher
 *
 * @v _ecb_name		Name for the new ECB cipher
 * @v _ecb_cipher	New cipher algorithm
 * @v _raw_cipher	Underlying cipher algorithm
 * @v _raw_context	Context structure for the underlying cipher
 * @v _blocksize	Cipher block size
 */
#define ECB_CIPHER( _ecb_name, _ecb_cipher, _raw_cipher, _raw_context,	\
		    _blocksize )					\
static int _ecb_name ## _setkey ( void *ctx, const void *key,		\
				  size_t keylen ) {			\
	return cipher_setkey ( &_raw_cipher, ctx, key, keylen );	\
}									\
static void _ecb_name ## _setiv ( void *ctx, const void *iv ) {		\
	cipher_setiv ( &_raw_cipher, ctx, iv );				\
}									\
static void _ecb_name ## _encrypt ( void *ctx, const void *src,		\
				    void *dst, size_t len ) {		\
	ecb_encrypt ( ctx, src, dst, len, &_raw_cipher );		\
}									\
static void _ecb_name ## _decrypt ( void *ctx, const void *src,		\
				    void *dst, size_t len ) {		\
	ecb_decrypt ( ctx, src, dst, len, &_raw_cipher );		\
}									\
struct cipher_algorithm _ecb_cipher = {					\
	.name		= #_ecb_name,					\
	.ctxsize	= sizeof ( _raw_context ),			\
	.blocksize	= _blocksize,					\
	.setkey		= _ecb_name ## _setkey,				\
	.setiv		= _ecb_name ## _setiv,				\
	.encrypt	= _ecb_name ## _encrypt,			\
	.decrypt	= _ecb_name ## _decrypt,			\
};

#endif /* _IPXE_ECB_H */
