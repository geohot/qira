#ifndef _IPXE_RANDOM_NZ_H
#define _IPXE_RANDOM_NZ_H

/** @file
 *
 * HMAC_DRBG algorithm
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

extern int get_random_nz ( void *data, size_t len );

#endif /* _IPXE_RANDOM_NZ_H */
