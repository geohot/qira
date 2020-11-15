#ifndef _IPXE_LINUX_PCI_H
#define _IPXE_LINUX_PCI_H

/** @file
 *
 * iPXE PCI API for Linux
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef PCIAPI_LINUX
#define PCIAPI_PREFIX_linux
#else
#define PCIAPI_PREFIX_linux __linux_
#endif

struct pci_device;

extern int linux_pci_read ( struct pci_device *pci, unsigned long where,
			    unsigned long *value, size_t len );
extern int linux_pci_write ( struct pci_device *pci, unsigned long where,
			     unsigned long value, size_t len );

/**
 * Read byte from PCI configuration space
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value read
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( linux, pci_read_config_byte ) ( struct pci_device *pci,
						unsigned int where,
						uint8_t *value ) {
	int rc;
	unsigned long tmp;

	rc = linux_pci_read ( pci, where, &tmp, sizeof ( *value ) );
	*value = tmp;
	return rc;
}

/**
 * Read word from PCI configuration space
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value read
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( linux, pci_read_config_word ) ( struct pci_device *pci,
						unsigned int where,
						uint16_t *value ) {
	int rc;
	unsigned long tmp;

	rc = linux_pci_read ( pci, where, &tmp, sizeof ( *value ) );
	*value = tmp;
	return rc;
}

/**
 * Read dword from PCI configuration space
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value read
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( linux, pci_read_config_dword ) ( struct pci_device *pci,
						 unsigned int where,
						 uint32_t *value ) {
	int rc;
	unsigned long tmp;

	rc = linux_pci_read ( pci, where, &tmp, sizeof ( *value ) );
	*value = tmp;
	return rc;
}

/**
 * Write byte to PCI configuration space
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value to be written
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( linux, pci_write_config_byte ) ( struct pci_device *pci,
						 unsigned int where,
						 uint8_t value ) {
	return linux_pci_write ( pci, where, value, sizeof ( value ) );
}

/**
 * Write word to PCI configuration space
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value to be written
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( linux, pci_write_config_word ) ( struct pci_device *pci,
						 unsigned int where,
						 uint16_t value ) {
	return linux_pci_write ( pci, where, value, sizeof ( value ) );
}

/**
 * Write dword to PCI configuration space
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value to be written
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( linux, pci_write_config_dword ) ( struct pci_device *pci,
						  unsigned int where,
						  uint32_t value ) {
	return linux_pci_write ( pci, where, value, sizeof ( value ) );
}

#endif /* _IPXE_LINUX_PCI_H */
