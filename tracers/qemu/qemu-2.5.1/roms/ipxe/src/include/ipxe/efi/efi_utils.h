#ifndef _IPXE_EFI_UTILS_H
#define _IPXE_EFI_UTILS_H

/** @file
 *
 * EFI utilities
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/DevicePath.h>

struct device;

extern EFI_DEVICE_PATH_PROTOCOL *
efi_devpath_end ( EFI_DEVICE_PATH_PROTOCOL *path );
extern int efi_locate_device ( EFI_HANDLE device, EFI_GUID *protocol,
			       EFI_HANDLE *parent );
extern int efi_child_add ( EFI_HANDLE parent, EFI_HANDLE child );
extern void efi_child_del ( EFI_HANDLE parent, EFI_HANDLE child );
extern void efi_device_info ( EFI_HANDLE device, const char *prefix,
			      struct device *dev );

#endif /* _IPXE_EFI_UTILS_H */
