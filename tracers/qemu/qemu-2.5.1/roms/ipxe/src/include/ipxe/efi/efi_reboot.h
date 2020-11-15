#ifndef _IPXE_EFI_REBOOT_H
#define _IPXE_EFI_REBOOT_H

/** @file
 *
 * iPXE reboot API for EFI
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef REBOOT_EFI
#define REBOOT_PREFIX_efi
#else
#define REBOOT_PREFIX_efi __efi_
#endif

#endif /* _IPXE_EFI_REBOOT_H */
