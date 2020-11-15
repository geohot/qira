#ifndef _IPXE_REBOOT_H
#define _IPXE_REBOOT_H

/** @file
 *
 * iPXE reboot API
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/api.h>
#include <config/reboot.h>

/**
 * Calculate static inline reboot API function name
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @ret _subsys_func	Subsystem API function
 */
#define REBOOT_INLINE( _subsys, _api_func ) \
	SINGLE_API_INLINE ( REBOOT_PREFIX_ ## _subsys, _api_func )

/**
 * Provide an reboot API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @v _func		Implementing function
 */
#define PROVIDE_REBOOT( _subsys, _api_func, _func ) \
	PROVIDE_SINGLE_API ( REBOOT_PREFIX_ ## _subsys, _api_func, _func )

/**
 * Provide a static inline reboot API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 */
#define PROVIDE_REBOOT_INLINE( _subsys, _api_func ) \
	PROVIDE_SINGLE_API_INLINE ( REBOOT_PREFIX_ ## _subsys, _api_func )

/* Include all architecture-independent reboot API headers */
#include <ipxe/null_reboot.h>
#include <ipxe/efi/efi_reboot.h>

/* Include all architecture-dependent reboot API headers */
#include <bits/reboot.h>

/**
 * Reboot system
 *
 * @v warm		Perform a warm reboot
 */
void reboot ( int warm );

/**
 * Power off system
 *
 * @ret rc		Return status code
 *
 * This function may fail, since not all systems support being powered
 * off by software.
 */
int poweroff ( void );

#endif /* _IPXE_REBOOT_H */
