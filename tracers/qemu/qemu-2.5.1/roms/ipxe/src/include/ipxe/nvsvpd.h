#ifndef _IPXE_NVSVPD_H
#define _IPXE_NVSVPD_H

/**
 * @file
 *
 * Non-Volatile Storage using Vital Product Data
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/nvs.h>
#include <ipxe/pcivpd.h>

struct nvo_block;
struct refcnt;

/** An NVS VPD device */
struct nvs_vpd_device {
	/** NVS device */
	struct nvs_device nvs;
	/** PCI VPD device */
	struct pci_vpd vpd;
};

extern int nvs_vpd_init ( struct nvs_vpd_device *nvsvpd,
			  struct pci_device *pci );
extern void nvs_vpd_nvo_init ( struct nvs_vpd_device *nvsvpd,
			       unsigned int field, struct nvo_block *nvo,
			       struct refcnt *refcnt );

#endif /* IPXE_NVSVPD_H */
