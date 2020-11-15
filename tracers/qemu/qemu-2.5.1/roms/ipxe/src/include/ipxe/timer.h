#ifndef	_IPXE_TIMER_H
#define _IPXE_TIMER_H

/** @file
 *
 * iPXE timer API
 *
 * The timer API provides udelay() for fixed delays, and currticks()
 * for a monotonically increasing tick counter.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/api.h>
#include <config/timer.h>

/**
 * Calculate static inline timer API function name
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @ret _subsys_func	Subsystem API function
 */
#define TIMER_INLINE( _subsys, _api_func ) \
	SINGLE_API_INLINE ( TIMER_PREFIX_ ## _subsys, _api_func )

/**
 * Provide a timer API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @v _func		Implementing function
 */
#define PROVIDE_TIMER( _subsys, _api_func, _func ) \
	PROVIDE_SINGLE_API ( TIMER_PREFIX_ ## _subsys, _api_func, _func )

/**
 * Provide a static inline timer API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 */
#define PROVIDE_TIMER_INLINE( _subsys, _api_func ) \
	PROVIDE_SINGLE_API_INLINE ( TIMER_PREFIX_ ## _subsys, _api_func )

/* Include all architecture-independent I/O API headers */
#include <ipxe/efi/efi_timer.h>
#include <ipxe/linux/linux_timer.h>

/* Include all architecture-dependent I/O API headers */
#include <bits/timer.h>

/**
 * Delay for a fixed number of microseconds
 *
 * @v usecs		Number of microseconds for which to delay
 */
void udelay ( unsigned long usecs );

/**
 * Get current system time in ticks
 *
 * @ret ticks		Current time, in ticks
 */
unsigned long currticks ( void );

/**
 * Get number of ticks per second
 *
 * @ret ticks_per_sec	Number of ticks per second
 */
unsigned long ticks_per_sec ( void );

/** Number of ticks per second */
#define TICKS_PER_SEC ( ticks_per_sec() )

#endif /* _IPXE_TIMER_H */
