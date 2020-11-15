#ifndef _IPXE_TIME_H
#define _IPXE_TIME_H

/** @file
 *
 * Time source
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <sys/time.h>
#include <ipxe/api.h>
#include <config/time.h>

/**
 * Calculate static inline time API function name
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @ret _subsys_func	Subsystem API function
 */
#define TIME_INLINE( _subsys, _api_func ) \
	SINGLE_API_INLINE ( TIME_PREFIX_ ## _subsys, _api_func )

/**
 * Provide a time API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @v _func		Implementing function
 */
#define PROVIDE_TIME( _subsys, _api_func, _func ) \
	PROVIDE_SINGLE_API ( TIME_PREFIX_ ## _subsys, _api_func, _func )

/**
 * Provide a static inline time API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 */
#define PROVIDE_TIME_INLINE( _subsys, _api_func ) \
	PROVIDE_SINGLE_API_INLINE ( TIME_PREFIX_ ## _subsys, _api_func )

/* Include all architecture-independent time API headers */
#include <ipxe/null_time.h>
#include <ipxe/efi/efi_time.h>
#include <ipxe/linux/linux_time.h>

/* Include all architecture-dependent time API headers */
#include <bits/time.h>

/**
 * Get current time in seconds
 *
 * @ret time		Time, in seconds
 */
time_t time_now ( void );

#endif /* _IPXE_TIME_H */
