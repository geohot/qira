#ifndef _IPXE_BIOS_SANBOOT_H
#define _IPXE_BIOS_SANBOOT_H

/** @file
 *
 * Standard PC-BIOS sanboot interface
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef SANBOOT_PCBIOS
#define SANBOOT_PREFIX_pcbios
#else
#define SANBOOT_PREFIX_pcbios __pcbios_
#endif

/**
 * Get default SAN drive number
 *
 * @ret drive		Default drive number
 */
static inline __always_inline unsigned int
SANBOOT_INLINE ( pcbios, san_default_drive ) ( void ) {
	/* Default to booting from first hard disk */
	return 0x80;
}

#endif /* _IPXE_BIOS_SANBOOT_H */
