#ifndef _IPXE_EFI_TIME_H
#define _IPXE_EFI_TIME_H

/** @file
 *
 * EFI time source
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

#ifdef TIME_EFI
#define TIME_PREFIX_efi
#else
#define TIME_PREFIX_efi __efi_
#endif

#endif /* _IPXE_EFI_TIME_H */
