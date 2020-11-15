#ifndef _IPXE_ARC4_H
#define _IPXE_ARC4_H

FILE_LICENCE ( GPL2_OR_LATER );

struct cipher_algorithm;

#include <stdint.h>

struct arc4_ctx {
	int i, j;
	u8 state[256];
};

#define ARC4_CTX_SIZE sizeof ( struct arc4_ctx )

extern struct cipher_algorithm arc4_algorithm;

void arc4_skip ( const void *key, size_t keylen, size_t skip,
		 const void *src, void *dst, size_t msglen );

#endif /* _IPXE_ARC4_H */
