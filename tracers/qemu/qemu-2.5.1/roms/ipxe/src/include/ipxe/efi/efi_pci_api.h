#ifndef _IPXE_EFI_PCI_API_H
#define _IPXE_EFI_PCI_API_H

/** @file
 *
 * iPXE PCI I/O API for EFI
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifdef PCIAPI_EFI
#define PCIAPI_PREFIX_efi
#else
#define PCIAPI_PREFIX_efi __efi_
#endif

/* EFI PCI width codes defined by EFI spec */
#define EFIPCI_WIDTH_BYTE 0
#define EFIPCI_WIDTH_WORD 1
#define EFIPCI_WIDTH_DWORD 2

#define EFIPCI_LOCATION( _offset, _width ) \
	( (_offset) | ( (_width) << 16 ) )
#define EFIPCI_OFFSET( _location ) ( (_location) & 0xffff )
#define EFIPCI_WIDTH( _location ) ( (_location) >> 16 )

struct pci_device;

extern int efipci_read ( struct pci_device *pci, unsigned long location,
			 void *value );
extern int efipci_write ( struct pci_device *pci, unsigned long location,
			  unsigned long value );

/**
 * Determine number of PCI buses within system
 *
 * @ret num_bus		Number of buses
 */
static inline __always_inline int
PCIAPI_INLINE ( efi, pci_num_bus ) ( void ) {
	/* EFI does not want us to scan the PCI bus ourselves */
	return 0;
}

/**
 * Read byte from PCI configuration space via EFI
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value read
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( efi, pci_read_config_byte ) ( struct pci_device *pci,
					      unsigned int where,
					      uint8_t *value ) {
	*value = 0xff;
	return efipci_read ( pci,
			     EFIPCI_LOCATION ( where, EFIPCI_WIDTH_BYTE ),
			     value );
}

/**
 * Read word from PCI configuration space via EFI
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value read
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( efi, pci_read_config_word ) ( struct pci_device *pci,
					      unsigned int where,
					      uint16_t *value ) {
	*value = 0xffff;
	return efipci_read ( pci,
			     EFIPCI_LOCATION ( where, EFIPCI_WIDTH_WORD ),
			     value );
}

/**
 * Read dword from PCI configuration space via EFI
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value read
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( efi, pci_read_config_dword ) ( struct pci_device *pci,
					       unsigned int where,
					       uint32_t *value ) {
	*value = 0xffffffffUL;
	return efipci_read ( pci,
			     EFIPCI_LOCATION ( where, EFIPCI_WIDTH_DWORD ),
			     value );
}

/**
 * Write byte to PCI configuration space via EFI
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value to be written
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( efi, pci_write_config_byte ) ( struct pci_device *pci,
					       unsigned int where,
					       uint8_t value ) {
	return efipci_write ( pci,
			      EFIPCI_LOCATION ( where, EFIPCI_WIDTH_BYTE ),
			      value );
}

/**
 * Write word to PCI configuration space via EFI
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value to be written
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( efi, pci_write_config_word ) ( struct pci_device *pci,
					       unsigned int where,
					       uint16_t value ) {
	return efipci_write ( pci,
			      EFIPCI_LOCATION ( where, EFIPCI_WIDTH_WORD ),
			      value );
}

/**
 * Write dword to PCI configuration space via EFI
 *
 * @v pci	PCI device
 * @v where	Location within PCI configuration space
 * @v value	Value to be written
 * @ret rc	Return status code
 */
static inline __always_inline int
PCIAPI_INLINE ( efi, pci_write_config_dword ) ( struct pci_device *pci,
						unsigned int where,
						uint32_t value ) {
	return efipci_write ( pci,
			      EFIPCI_LOCATION ( where, EFIPCI_WIDTH_DWORD ),
			      value );
}

#endif /* _IPXE_EFI_PCI_API_H */
