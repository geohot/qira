#ifndef _PNPBIOS_H
#define _PNPBIOS_H

/** @file
 *
 * PnP BIOS
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/* BIOS segment address */
#define BIOS_SEG 0xf000

extern int find_pnp_bios ( void );

#endif /* _PNPBIOS_H */
