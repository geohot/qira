#ifndef _IPXE_EFI_UMALLOC_H
#define _IPXE_EFI_UMALLOC_H

/** @file
 *
 * iPXE user memory allocation API for EFI
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef UMALLOC_EFI
#define UMALLOC_PREFIX_efi
#else
#define UMALLOC_PREFIX_efi __efi_
#endif

#endif /* _IPXE_EFI_UMALLOC_H */
