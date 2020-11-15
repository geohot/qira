#ifndef _IPXE_NULL_NAP_H
#define _IPXE_NULL_NAP_H

/** @file
 *
 * Null CPU sleeping
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef NAP_NULL
#define NAP_PREFIX_null
#else
#define NAP_PREFIX_null __null_
#endif

static inline __always_inline void
NAP_INLINE ( null, cpu_nap ) ( void ) {
	/* Do nothing */
}

#endif /* _IPXE_NULL_NAP_H */
