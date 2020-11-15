#ifndef _IPXE_EFI_TIMER_H
#define _IPXE_EFI_TIMER_H

/** @file
 *
 * iPXE timer API for EFI
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef TIMER_EFI
#define TIMER_PREFIX_efi
#else
#define TIMER_PREFIX_efi __efi_
#endif

#endif /* _IPXE_EFI_TIMER_H */
