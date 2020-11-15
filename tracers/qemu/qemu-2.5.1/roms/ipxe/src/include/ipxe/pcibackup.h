#ifndef _IPXE_PCIBACKUP_H
#define _IPXE_PCIBACKUP_H

/** @file
 *
 * PCI configuration space backup and restoration
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>

/** A PCI configuration space backup */
struct pci_config_backup {
	uint32_t dwords[64];
};

/** PCI configuration space backup exclusion list end marker */
#define PCI_CONFIG_BACKUP_EXCLUDE_END 0xff

/** Define a PCI configuration space backup exclusion list */
#define PCI_CONFIG_BACKUP_EXCLUDE(...) \
	{ __VA_ARGS__, PCI_CONFIG_BACKUP_EXCLUDE_END }

extern void pci_backup ( struct pci_device *pci,
			 struct pci_config_backup *backup,
			 const uint8_t *exclude );
extern void pci_restore ( struct pci_device *pci,
			  struct pci_config_backup *backup,
			  const uint8_t *exclude );

#endif /* _IPXE_PCIBACKUP_H */
