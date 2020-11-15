#ifndef _IPXE_CHAP_H
#define _IPXE_CHAP_H

/** @file
 *
 * CHAP protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/md5.h>

struct digest_algorithm;

/** A CHAP response */
struct chap_response {
	/** Digest algorithm used for the response */
	struct digest_algorithm *digest;
	/** Context used by the digest algorithm */
	uint8_t *digest_context;
	/** CHAP response */
	uint8_t *response;
	/** Length of CHAP response */
	size_t response_len;
};

extern int chap_init ( struct chap_response *chap,
		       struct digest_algorithm *digest );
extern void chap_update ( struct chap_response *chap, const void *data,
			  size_t len );
extern void chap_respond ( struct chap_response *chap );
extern void chap_finish ( struct chap_response *chap );

/**
 * Add identifier data to the CHAP challenge
 *
 * @v chap		CHAP response
 * @v identifier	CHAP identifier
 *
 * The CHAP identifier is the first byte of the CHAP challenge.  This
 * function is a notational convenience for calling chap_update() for
 * the identifier byte.
 */
static inline void chap_set_identifier ( struct chap_response *chap,
					 unsigned int identifier ) {
	uint8_t ident_byte = identifier;

	chap_update ( chap, &ident_byte, sizeof ( ident_byte ) );
}

#endif /* _IPXE_CHAP_H */
