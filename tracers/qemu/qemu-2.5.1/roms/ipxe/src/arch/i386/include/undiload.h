#ifndef _UNDILOAD_H
#define _UNDILOAD_H

/** @file
 *
 * UNDI load/unload
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

struct undi_device;
struct undi_rom;

extern int undi_load ( struct undi_device *undi, struct undi_rom *undirom );
extern int undi_unload ( struct undi_device *undi );

/**
 * Call UNDI loader to create a pixie
 *
 * @v undi		UNDI device
 * @v undirom		UNDI ROM
 * @v pci_busdevfn	PCI bus:dev.fn
 * @ret rc		Return status code
 */
static inline int undi_load_pci ( struct undi_device *undi,
				  struct undi_rom *undirom,
				  unsigned int pci_busdevfn ) {
	undi->pci_busdevfn = pci_busdevfn;
	undi->isapnp_csn = UNDI_NO_ISAPNP_CSN;
	undi->isapnp_read_port = UNDI_NO_ISAPNP_READ_PORT;
	return undi_load ( undi, undirom );
}

#endif /* _UNDILOAD_H */
