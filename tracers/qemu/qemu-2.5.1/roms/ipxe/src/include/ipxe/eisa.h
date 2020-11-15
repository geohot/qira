#ifndef EISA_H
#define EISA_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/isa_ids.h>
#include <ipxe/device.h>
#include <ipxe/tables.h>

/*
 * EISA constants
 *
 */

#define EISA_MIN_SLOT (0x1)
#define EISA_MAX_SLOT (0xf)	/* Must be 2^n - 1 */
#define EISA_SLOT_BASE( n ) ( 0x1000 * (n) )

#define EISA_VENDOR_ID ( 0xc80 )
#define EISA_PROD_ID ( 0xc82 )
#define EISA_GLOBAL_CONFIG ( 0xc84 )

#define EISA_CMD_RESET ( 1 << 2 )
#define EISA_CMD_ENABLE ( 1 << 0 )

/** An EISA device ID list entry */
struct eisa_device_id {
	/** Name */
        const char *name;
	/** Manufacturer ID */
	uint16_t vendor_id;
	/** Product ID */
	uint16_t prod_id;
};

/** An EISA device */
struct eisa_device {
	/** Generic device */
	struct device dev;
	/** Slot number */
	unsigned int slot;
	/** I/O address */
	uint16_t ioaddr;
	/** Manufacturer ID */
	uint16_t vendor_id;
	/** Product ID */
	uint16_t prod_id;
	/** Driver for this device */
	struct eisa_driver *driver;
	/** Driver-private data
	 *
	 * Use eisa_set_drvdata() and eisa_get_drvdata() to access
	 * this field.
	 */
	void *priv;
};

/** An EISA driver */
struct eisa_driver {
	/** EISA ID table */
	struct eisa_device_id *ids;
	/** Number of entries in EISA ID table */
	unsigned int id_count;
	/**
	 * Probe device
	 *
	 * @v eisa	EISA device
	 * @v id	Matching entry in ID table
	 * @ret rc	Return status code
	 */
	int ( * probe ) ( struct eisa_device *eisa,
			  const struct eisa_device_id *id );
	/**
	 * Remove device
	 *
	 * @v eisa	EISA device
	 */
	void ( * remove ) ( struct eisa_device *eisa );
};

/** EISA driver table */
#define EISA_DRIVERS __table ( struct eisa_driver, "eisa_drivers" )

/** Declare an EISA driver */
#define __eisa_driver __table_entry ( EISA_DRIVERS, 01 )

extern void eisa_device_enabled ( struct eisa_device *eisa, int enabled );

/**
 * Enable EISA device
 *
 * @v eisa		EISA device
 */
static inline void enable_eisa_device ( struct eisa_device *eisa ) {
	eisa_device_enabled ( eisa, 1 );
}

/**
 * Disable EISA device
 *
 * @v eisa		EISA device
 */
static inline void disable_eisa_device ( struct eisa_device *eisa ) {
	eisa_device_enabled ( eisa, 0 );
}

/**
 * Set EISA driver-private data
 *
 * @v eisa		EISA device
 * @v priv		Private data
 */
static inline void eisa_set_drvdata ( struct eisa_device *eisa, void *priv ) {
	eisa->priv = priv;
}

/**
 * Get EISA driver-private data
 *
 * @v eisa		EISA device
 * @ret priv		Private data
 */
static inline void * eisa_get_drvdata ( struct eisa_device *eisa ) {
	return eisa->priv;
}

#endif /* EISA_H */
