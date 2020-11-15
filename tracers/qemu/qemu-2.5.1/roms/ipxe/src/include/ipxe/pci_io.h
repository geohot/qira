#ifndef _IPXE_PCI_IO_H
#define _IPXE_PCI_IO_H

/** @file
 *
 * PCI I/O API
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/api.h>
#include <config/ioapi.h>

/**
 * Calculate static inline PCI I/O API function name
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @ret _subsys_func	Subsystem API function
 */
#define PCIAPI_INLINE( _subsys, _api_func ) \
	SINGLE_API_INLINE ( PCIAPI_PREFIX_ ## _subsys, _api_func )

/**
 * Provide a PCI I/O API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 * @v _func		Implementing function
 */
#define PROVIDE_PCIAPI( _subsys, _api_func, _func ) \
	PROVIDE_SINGLE_API ( PCIAPI_PREFIX_ ## _subsys, _api_func, _func )

/**
 * Provide a static inline PCI I/O API implementation
 *
 * @v _prefix		Subsystem prefix
 * @v _api_func		API function
 */
#define PROVIDE_PCIAPI_INLINE( _subsys, _api_func ) \
	PROVIDE_SINGLE_API_INLINE ( PCIAPI_PREFIX_ ## _subsys, _api_func )

/* Include all architecture-independent I/O API headers */
#include <ipxe/efi/efi_pci_api.h>
#include <ipxe/linux/linux_pci.h>

/* Include all architecture-dependent I/O API headers */
#include <bits/pci_io.h>

/**
 * Determine number of PCI buses within system
 *
 * @ret num_bus		Number of buses
 */
int pci_num_bus ( void );

/**
 * Read byte from PCI configuration space
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value read
 * @ret rc	Return status code
 */
int pci_read_config_byte ( struct pci_device *pci, unsigned int where,
			   uint8_t *value );

/**
 * Read 16-bit word from PCI configuration space
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value read
 * @ret rc	Return status code
 */
int pci_read_config_word ( struct pci_device *pci, unsigned int where,
			   uint16_t *value );

/**
 * Read 32-bit dword from PCI configuration space
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value read
 * @ret rc	Return status code
 */
int pci_read_config_dword ( struct pci_device *pci, unsigned int where,
			    uint32_t *value );

/**
 * Write byte to PCI configuration space
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value to be written
 * @ret rc	Return status code
 */
int pci_write_config_byte ( struct pci_device *pci, unsigned int where,
			    uint8_t value );

/**
 * Write 16-bit word to PCI configuration space
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value to be written
 * @ret rc	Return status code
 */
int pci_write_config_word ( struct pci_device *pci, unsigned int where,
			    uint16_t value );

/**
 * Write 32-bit dword to PCI configuration space
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value to be written
 * @ret rc	Return status code
 */
int pci_write_config_dword ( struct pci_device *pci, unsigned int where,
			     uint32_t value );

#endif /* _IPXE_PCI_IO_H */
