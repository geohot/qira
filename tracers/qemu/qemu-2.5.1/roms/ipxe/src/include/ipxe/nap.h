#ifndef _IPXE_NAP_H
#define _IPXE_NAP_H

/** @file
 *
 * CPU sleeping
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/api.h>
#include <config/nap.h>

/**
 * Calculate static inline CPU sleeping API function name
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @ret _subsys_func	Subsystem API function
 */
#define NAP_INLINE( _subsys, _api_func ) \
	SINGLE_API_INLINE ( NAP_PREFIX_ ## _subsys, _api_func )

/**
 * Provide an CPU sleeping API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @v _func		Implementing function
 */
#define PROVIDE_NAP( _subsys, _api_func, _func ) \
	PROVIDE_SINGLE_API ( NAP_PREFIX_ ## _subsys, _api_func, _func )

/**
 * Provide a static inline CPU sleeping API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 */
#define PROVIDE_NAP_INLINE( _subsys, _api_func ) \
	PROVIDE_SINGLE_API_INLINE ( NAP_PREFIX_ ## _subsys, _api_func )

/* Include all architecture-independent I/O API headers */
#include <ipxe/null_nap.h>
#include <ipxe/linux/linux_nap.h>

/* Include all architecture-dependent I/O API headers */
#include <bits/nap.h>

/**
 * Sleep until next CPU interrupt
 *
 */
void cpu_nap ( void );

#endif /* _IPXE_NAP_H */
