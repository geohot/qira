#ifndef _IPXE_NVO_H
#define _IPXE_NVO_H

/** @file
 *
 * Non-volatile stored options
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/dhcpopts.h>
#include <ipxe/settings.h>

struct nvs_device;
struct refcnt;

/**
 * A block of non-volatile stored options
 */
struct nvo_block {
	/** Settings block */
	struct settings settings;
	/** Underlying non-volatile storage device */
	struct nvs_device *nvs;
	/** Address within NVS device */
	unsigned int address;
	/** Length of options data */
	size_t len;
	/** Option-containing data */
	void *data;
	/**
	 * Resize non-volatile stored option block
	 *
	 * @v nvo		Non-volatile options block
	 * @v len		New size
	 * @ret rc		Return status code
	 */
	int ( * resize ) ( struct nvo_block *nvo, size_t len );
	/** DHCP options block */
	struct dhcp_options dhcpopts;
};

/** Name of non-volatile options settings block */
#define NVO_SETTINGS_NAME "nvo"

extern int nvo_applies ( struct settings *settings,
			 const struct setting *setting );
extern void nvo_init ( struct nvo_block *nvo, struct nvs_device *nvs,
		       size_t address, size_t len,
		       int ( * resize ) ( struct nvo_block *nvo, size_t len ),
		       struct refcnt *refcnt );
extern int register_nvo ( struct nvo_block *nvo, struct settings *parent );
extern void unregister_nvo ( struct nvo_block *nvo );

#endif /* _IPXE_NVO_H */
