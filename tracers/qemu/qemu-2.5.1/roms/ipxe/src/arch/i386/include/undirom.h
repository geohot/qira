#ifndef _UNDIROM_H
#define _UNDIROM_H

/** @file
 *
 * UNDI expansion ROMs
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <pxe_types.h>

/** An UNDI PCI device ID */
struct undi_pci_device_id {
	/** PCI vendor ID */
	unsigned int vendor_id;
	/** PCI device ID */
	unsigned int device_id;
};

/** An UNDI device ID */
union undi_device_id {
	/** PCI device ID */
	struct undi_pci_device_id pci;
};

/** An UNDI ROM */
struct undi_rom {
	/** List of UNDI ROMs */
	struct list_head list;
	/** ROM segment address */
	unsigned int rom_segment;
	/** UNDI loader entry point */
	SEGOFF16_t loader_entry;
	/** Code segment size */
	size_t code_size;
	/** Data segment size */
	size_t data_size;
	/** Bus type
	 *
	 * Values are as used by @c PXENV_UNDI_GET_NIC_TYPE
	 */
	unsigned int bus_type;
	/** Device ID */
	union undi_device_id bus_id;
};

extern struct undi_rom * undirom_find_pci ( unsigned int vendor_id,
					    unsigned int device_id,
					    unsigned int rombase );

#endif /* _UNDIROM_H */
