#ifndef _IPXE_SANBOOT_H
#define _IPXE_SANBOOT_H

/** @file
 *
 * iPXE sanboot API
 *
 * The sanboot API provides methods for hooking, unhooking,
 * describing, and booting from SAN devices.
 *
 * The standard methods (readl()/writel() etc.) do not strictly check
 * the type of the address parameter; this is because traditional
 * usage does not necessarily provide the correct pointer type.  For
 * example, code written for ISA devices at fixed I/O addresses (such
 * as the keyboard controller) tend to use plain integer constants for
 * the address parameter.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/api.h>
#include <config/sanboot.h>

struct uri;

/**
 * Calculate static inline sanboot API function name
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @ret _subsys_func	Subsystem API function
 */
#define SANBOOT_INLINE( _subsys, _api_func ) \
	SINGLE_API_INLINE ( SANBOOT_PREFIX_ ## _subsys, _api_func )

/**
 * Provide a sanboot API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @v _func		Implementing function
 */
#define PROVIDE_SANBOOT( _subsys, _api_func, _func ) \
	PROVIDE_SINGLE_API ( SANBOOT_PREFIX_ ## _subsys, _api_func, _func )

/**
 * Provide a static inline sanboot API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 */
#define PROVIDE_SANBOOT_INLINE( _subsys, _api_func ) \
	PROVIDE_SINGLE_API_INLINE ( SANBOOT_PREFIX_ ## _subsys, _api_func )

/* Include all architecture-independent sanboot API headers */
#include <ipxe/null_sanboot.h>

/* Include all architecture-dependent sanboot API headers */
#include <bits/sanboot.h>

/**
 * Get default SAN drive number
 *
 * @ret drive		Default drive number
 */
unsigned int san_default_drive ( void );

/**
 * Hook SAN device
 *
 * @v uri		URI
 * @v drive		Drive number
 * @ret rc		Return status code
 */
int san_hook ( struct uri *uri, unsigned int drive );

/**
 * Unhook SAN device
 *
 * @v drive		Drive number
 */
void san_unhook ( unsigned int drive );

/**
 * Attempt to boot from a SAN device
 *
 * @v drive		Drive number
 * @ret rc		Return status code
 */
int san_boot ( unsigned int drive );

/**
 * Describe SAN device for SAN-booted operating system
 *
 * @v drive		Drive number
 * @ret rc		Return status code
 */
int san_describe ( unsigned int drive );

#endif /* _IPXE_SANBOOT_H */
