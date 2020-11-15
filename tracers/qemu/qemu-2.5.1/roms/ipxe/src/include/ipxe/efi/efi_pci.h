#ifndef _IPXE_EFI_PCI_H
#define _IPXE_EFI_PCI_H

/** @file
 *
 * EFI driver interface
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/pci.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/Protocol/PciIo.h>

/* PciRootBridgeIo.h uses LShiftU64(), which isn't defined anywhere else */
static inline EFIAPI uint64_t LShiftU64 ( UINT64 value, UINTN shift ) {
	return ( value << shift );
}

extern int efipci_open ( EFI_HANDLE device, UINT32 attributes,
			 struct pci_device *pci );
extern void efipci_close ( EFI_HANDLE device );
extern int efipci_info ( EFI_HANDLE device, struct pci_device *pci );

#endif /* _IPXE_EFI_PCI_H */
