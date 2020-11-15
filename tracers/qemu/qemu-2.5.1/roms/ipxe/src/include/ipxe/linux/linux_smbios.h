#ifndef _IPXE_LINUX_SMBIOS_H
#define _IPXE_LINUX_SMBIOS_H

/** @file
 *
 * iPXE SMBIOS API for Linux
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef SMBIOS_LINUX
#define SMBIOS_PREFIX_linux
#else
#define SMBIOS_PREFIX_linux __linux_
#endif

#endif /* _IPXE_LINUX_SMBIOS_H */
