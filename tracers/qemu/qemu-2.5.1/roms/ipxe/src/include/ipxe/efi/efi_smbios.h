#ifndef _IPXE_EFI_SMBIOS_H
#define _IPXE_EFI_SMBIOS_H

/** @file
 *
 * iPXE SMBIOS API for EFI
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef SMBIOS_EFI
#define SMBIOS_PREFIX_efi
#else
#define SMBIOS_PREFIX_efi __efi_
#endif

#endif /* _IPXE_EFI_SMBIOS_H */
