#ifndef _IPXE_BASE16_H
#define _IPXE_BASE16_H

/** @file
 *
 * Base16 encoding
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <string.h>

/**
 * Calculate length of base16-encoded data
 *
 * @v raw_len		Raw data length
 * @ret encoded_len	Encoded string length (excluding NUL)
 */
static inline size_t base16_encoded_len ( size_t raw_len ) {
	return ( 2 * raw_len );
}

/**
 * Calculate maximum length of base16-decoded string
 *
 * @v encoded		Encoded string
 * @v max_raw_len	Maximum length of raw data
 */
static inline size_t base16_decoded_max_len ( const char *encoded ) {
	return ( ( strlen ( encoded ) + 1 ) / 2 );
}

extern size_t hex_encode ( char separator, const void *raw, size_t raw_len,
			   char *data, size_t len );
extern int hex_decode ( char separator, const char *encoded, void *data,
			size_t len );

/**
 * Base16-encode data
 *
 * @v raw		Raw data
 * @v raw_len		Length of raw data
 * @v data		Buffer
 * @v len		Length of buffer
 * @ret len		Encoded length
 */
static inline __attribute__ (( always_inline )) size_t
base16_encode ( const void *raw, size_t raw_len, char *data, size_t len ) {
	return hex_encode ( 0, raw, raw_len, data, len );
}

/**
 * Base16-decode data
 *
 * @v encoded		Encoded string
 * @v data		Buffer
 * @v len		Length of buffer
 * @ret len		Length of data, or negative error
 */
static inline __attribute__ (( always_inline )) int
base16_decode ( const char *encoded, void *data, size_t len ) {
	return hex_decode ( 0, encoded, data, len );
}

#endif /* _IPXE_BASE16_H */
