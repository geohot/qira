#ifndef _IPXE_EFI_ENTROPY_H
#define _IPXE_EFI_ENTROPY_H

/** @file
 *
 * EFI entropy source
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

#ifdef ENTROPY_EFI
#define ENTROPY_PREFIX_efi
#else
#define ENTROPY_PREFIX_efi __efi_
#endif

/**
 * min-entropy per sample
 *
 * @ret min_entropy	min-entropy of each sample
 */
static inline __always_inline double
ENTROPY_INLINE ( efi, min_entropy_per_sample ) ( void ) {

	/* We use essentially the same mechanism as for the BIOS
	 * RTC-based entropy source, and so assume the same
	 * min-entropy per sample.
	 */
	return 1.3;
}

#endif /* _IPXE_EFI_ENTROPY_H */
