#ifndef _IPXE_AES_H
#define _IPXE_AES_H

/** @file
 *
 * AES algorithm
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/crypto.h>

/** AES blocksize */
#define AES_BLOCKSIZE 16

/** Maximum number of AES rounds */
#define AES_MAX_ROUNDS 15

/** AES matrix */
union aes_matrix {
	/** Viewed as an array of bytes */
	uint8_t byte[16];
	/** Viewed as an array of four-byte columns */
	uint32_t column[4];
} __attribute__ (( packed ));

/** AES round keys */
struct aes_round_keys {
	/** Round keys */
	union aes_matrix key[AES_MAX_ROUNDS];
};

/** AES context */
struct aes_context {
	/** Encryption keys */
	struct aes_round_keys encrypt;
	/** Decryption keys */
	struct aes_round_keys decrypt;
	/** Number of rounds */
	unsigned int rounds;
};

/** AES context size */
#define AES_CTX_SIZE sizeof ( struct aes_context )

extern struct cipher_algorithm aes_algorithm;
extern struct cipher_algorithm aes_ecb_algorithm;
extern struct cipher_algorithm aes_cbc_algorithm;

int aes_wrap ( const void *kek, const void *src, void *dest, int nblk );
int aes_unwrap ( const void *kek, const void *src, void *dest, int nblk );

#endif /* _IPXE_AES_H */
