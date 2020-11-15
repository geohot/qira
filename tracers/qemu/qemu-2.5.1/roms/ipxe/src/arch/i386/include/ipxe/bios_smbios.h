#ifndef _IPXE_BIOS_SMBIOS_H
#define _IPXE_BIOS_SMBIOS_H

/** @file
 *
 * Standard PC-BIOS SMBIOS interface
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef SMBIOS_PCBIOS
#define SMBIOS_PREFIX_pcbios
#else
#define SMBIOS_PREFIX_pcbios __pcbios_
#endif

#endif /* _IPXE_BIOS_SMBIOS_H */
