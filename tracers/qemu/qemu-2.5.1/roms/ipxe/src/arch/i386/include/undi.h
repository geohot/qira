#ifndef _UNDI_H
#define _UNDI_H

/** @file
 *
 * UNDI driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifndef ASSEMBLY

#include <ipxe/device.h>
#include <pxe_types.h>

/** An UNDI device
 *
 * This structure is used by assembly code as well as C; do not alter
 * this structure without editing pxeprefix.S to match.
 */
struct undi_device {
	/** PXENV+ structure address */
	SEGOFF16_t pxenv;
	/** !PXE structure address */
	SEGOFF16_t ppxe;
	/** Entry point */
	SEGOFF16_t entry;
	/** Free base memory after load */
	UINT16_t fbms;
	/** Free base memory prior to load */
	UINT16_t restore_fbms;
	/** PCI bus:dev.fn, or @c UNDI_NO_PCI_BUSDEVFN */
	UINT16_t pci_busdevfn;
	/** ISAPnP card select number, or @c UNDI_NO_ISAPNP_CSN */
	UINT16_t isapnp_csn;
	/** ISAPnP read port, or @c UNDI_NO_ISAPNP_READ_PORT */
	UINT16_t isapnp_read_port;
	/** PCI vendor ID
	 *
	 * Filled in only for the preloaded UNDI device by pxeprefix.S
	 */
	UINT16_t pci_vendor;
	/** PCI device ID 
	 *
	 * Filled in only for the preloaded UNDI device by pxeprefix.S
	 */
	UINT16_t pci_device;
	/** Flags
	 *
	 * This is the bitwise OR of zero or more UNDI_FL_XXX
	 * constants.
	 */
	UINT16_t flags;

	/** Generic device */
	struct device dev;
	/** Driver-private data
	 *
	 * Use undi_set_drvdata() and undi_get_drvdata() to access this
	 * field.
	 */
	void *priv;
} __attribute__ (( packed ));

/**
 * Set UNDI driver-private data
 *
 * @v undi		UNDI device
 * @v priv		Private data
 */
static inline void undi_set_drvdata ( struct undi_device *undi, void *priv ) {
	undi->priv = priv;
}

/**
 * Get UNDI driver-private data
 *
 * @v undi		UNDI device
 * @ret priv		Private data
 */
static inline void * undi_get_drvdata ( struct undi_device *undi ) {
	return undi->priv;
}

#endif /* ASSEMBLY */

/** PCI bus:dev.fn field is invalid */
#define UNDI_NO_PCI_BUSDEVFN 0xffff

/** ISAPnP card select number field is invalid */
#define UNDI_NO_ISAPNP_CSN 0xffff

/** ISAPnP read port field is invalid */
#define UNDI_NO_ISAPNP_READ_PORT 0xffff

/** UNDI flag: START_UNDI has been called */
#define UNDI_FL_STARTED 0x0001

/** UNDI flag: UNDI_STARTUP and UNDI_INITIALIZE have been called */
#define UNDI_FL_INITIALIZED 0x0002

/** UNDI flag: keep stack resident */
#define UNDI_FL_KEEP_ALL 0x0004

#endif /* _UNDI_H */
