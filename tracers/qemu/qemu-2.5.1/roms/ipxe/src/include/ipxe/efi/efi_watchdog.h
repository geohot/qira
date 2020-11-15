#ifndef _IPXE_EFI_WATCHDOG_H
#define _IPXE_EFI_WATCHDOG_H

/** @file
 *
 * EFI watchdog holdoff timer
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

extern struct retry_timer efi_watchdog;

/**
 * Start EFI watchdog holdoff timer
 *
 */
static inline void efi_watchdog_start ( void ) {

	start_timer_nodelay ( &efi_watchdog );
}

/**
 * Stop EFI watchdog holdoff timer
 *
 */
static inline void efi_watchdog_stop ( void ) {

	stop_timer ( &efi_watchdog );
}

#endif /* _IPXE_EFI_WATCHDOG_H */
