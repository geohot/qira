#ifndef _IPXE_PCIBIOS_H
#define _IPXE_PCIBIOS_H

#include <stdint.h>

/** @file
 *
 * PCI configuration space access via PCI BIOS
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef PCIAPI_PCBIOS
#define PCIAPI_PREFIX_pcbios
#else
#define PCIAPI_PREFIX_pcbios __pcbios_
#endif

struct pci_device;

#define PCIBIOS_INSTALLATION_CHECK	0xb1010000
#define PCIBIOS_READ_CONFIG_BYTE	0xb1080000
#define PCIBIOS_READ_CONFIG_WORD	0xb1090000
#define PCIBIOS_READ_CONFIG_DWORD	0xb10a0000
#define PCIBIOS_WRITE_CONFIG_BYTE	0xb10b0000
#define PCIBIOS_WRITE_CONFIG_WORD	0xb10c0000
#define PCIBIOS_WRITE_CONFIG_DWORD	0xb10d0000

extern int pcibios_read ( struct pci_device *pci, uint32_t command,
			  uint32_t *value );
extern int pcibios_write ( struct pci_device *pci, uint32_t command,
			   uint32_t value );

/**
 * Read byte from PCI configuration space via PCI BIOS
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value read
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( pcbios, pci_read_config_byte ) ( struct pci_device *pci,
						 unsigned int where,
						 uint8_t *value ) {
	uint32_t tmp;
	int rc;

	rc = pcibios_read ( pci, PCIBIOS_READ_CONFIG_BYTE | where, &tmp );
	*value = tmp;
	return rc;
}

/**
 * Read word from PCI configuration space via PCI BIOS
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value read
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( pcbios, pci_read_config_word ) ( struct pci_device *pci,
						 unsigned int where,
						 uint16_t *value ) {
	uint32_t tmp;
	int rc;

	rc = pcibios_read ( pci, PCIBIOS_READ_CONFIG_WORD | where, &tmp );
	*value = tmp;
	return rc;
}

/**
 * Read dword from PCI configuration space via PCI BIOS
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value read
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( pcbios, pci_read_config_dword ) ( struct pci_device *pci,
						  unsigned int where,
						  uint32_t *value ) {
	return pcibios_read ( pci, PCIBIOS_READ_CONFIG_DWORD | where, value );
}

/**
 * Write byte to PCI configuration space via PCI BIOS
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value to be written
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( pcbios, pci_write_config_byte ) ( struct pci_device *pci,
						  unsigned int where,
						  uint8_t value ) {
	return pcibios_write ( pci, PCIBIOS_WRITE_CONFIG_BYTE | where, value );
}

/**
 * Write word to PCI configuration space via PCI BIOS
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value to be written
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( pcbios, pci_write_config_word ) ( struct pci_device *pci,
						  unsigned int where,
						  uint16_t value ) {
	return pcibios_write ( pci, PCIBIOS_WRITE_CONFIG_WORD | where, value );
}

/**
 * Write dword to PCI configuration space via PCI BIOS
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value to be written
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( pcbios, pci_write_config_dword ) ( struct pci_device *pci,
						   unsigned int where,
						   uint32_t value ) {
	return pcibios_write ( pci, PCIBIOS_WRITE_CONFIG_DWORD | where, value);
}

#endif /* _IPXE_PCIBIOS_H */
