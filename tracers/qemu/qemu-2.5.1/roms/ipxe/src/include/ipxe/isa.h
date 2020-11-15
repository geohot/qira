#ifndef	ISA_H
#define ISA_H

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>
#include <ipxe/isa_ids.h>
#include <ipxe/device.h>
#include <ipxe/tables.h>

/** An ISA device */
struct isa_device {
	/** Generic device */
	struct device dev;
	/** I/O address */
	uint16_t ioaddr;
	/** Driver for this device */
	struct isa_driver *driver;
	/** Driver-private data
	 *
	 * Use isa_set_drvdata() and isa_get_drvdata() to access
	 * this field.
	 */
	void *priv;
};

/*
 * An individual ISA device, identified by probe address
 *
 */
typedef uint16_t isa_probe_addr_t;

/** An ISA driver */
struct isa_driver {
	/** Name */
	const char *name;
	/** Probe address list */
	isa_probe_addr_t *probe_addrs;
	/** Number of entries in probe address list */
	unsigned int addr_count;
	/** Manufacturer ID to be assumed for this device */
	uint16_t vendor_id;
	/** Product ID to be assumed for this device */
	uint16_t prod_id;
	/**
	 * Probe device
	 *
	 * @v isa	ISA device
	 * @v id	Matching entry in ID table
	 * @ret rc	Return status code
	 */
	int ( * probe ) ( struct isa_device *isa );
	/**
	 * Remove device
	 *
	 * @v isa	ISA device
	 */
	void ( * remove ) ( struct isa_device *isa );
};

/** ISA driver table */
#define ISA_DRIVERS __table ( struct isa_driver, "isa_drivers" )

/** Declare an ISA driver */
#define __isa_driver __table_entry ( ISA_DRIVERS, 01 )

/**
 * Set ISA driver-private data
 *
 * @v isa		ISA device
 * @v priv		Private data
 */
static inline void isa_set_drvdata ( struct isa_device *isa, void *priv ) {
	isa->priv = priv;
}

/**
 * Get ISA driver-private data
 *
 * @v isa		ISA device
 * @ret priv		Private data
 */
static inline void * isa_get_drvdata ( struct isa_device *isa ) {
	return isa->priv;
}

/*
 * ISA_ROM is parsed by parserom.pl to generate Makefile rules and
 * files for rom-o-matic.
 *
 */
#define ISA_ROM( IMAGE, DESCRIPTION )

#endif /* ISA_H */

