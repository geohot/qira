/*
 * MCA bus driver code
 *
 * Abstracted from 3c509.c.
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#ifndef MCA_H
#define MCA_H

#include <ipxe/isa_ids.h>
#include <ipxe/device.h>
#include <ipxe/tables.h>

/*
 * MCA constants
 *
 */
#define MCA_MOTHERBOARD_SETUP_REG	0x94
#define MCA_ADAPTER_SETUP_REG		0x96
#define MCA_MAX_SLOT_NR			0x07	/* Must be 2^n - 1 */
#define MCA_POS_REG(n)			(0x100+(n))

/* Is there a standard that would define this? */
#define GENERIC_MCA_VENDOR ISA_VENDOR ( 'M', 'C', 'A' )

/** An MCA device ID list entry */
struct mca_device_id {
	/** Name */
        const char *name;
	/** Device ID */
	uint16_t id;
};

/** An MCA device */
struct mca_device {
	/** Generic device */
	struct device dev;
	/** Slot number */
	unsigned int slot;
	/** POS register values */
	unsigned char pos[8];
	/** Driver for this device */
	struct mca_driver *driver;
	/** Driver-private data
	 *
	 * Use mca_set_drvdata() and mca_get_drvdata() to access
	 * this field.
	 */
	void *priv;
};

#define MCA_ID(mca) ( ( (mca)->pos[1] << 8 ) + (mca)->pos[0] )

/** An MCA driver */
struct mca_driver {
	/** MCA ID table */
	struct mca_device_id *ids;
	/** Number of entries in MCA ID table */
	unsigned int id_count;
	/**
	 * Probe device
	 *
	 * @v mca	MCA device
	 * @v id	Matching entry in ID table
	 * @ret rc	Return status code
	 */
	int ( * probe ) ( struct mca_device *mca,
			  const struct mca_device_id *id );
	/**
	 * Remove device
	 *
	 * @v mca	MCA device
	 */
	void ( * remove ) ( struct mca_device *mca );
};

/** MCA driver table */
#define MCA_DRIVERS __table ( struct mca_driver, "mca_drivers" )

/** Declare an MCA driver */
#define __mca_driver __table_entry ( MCA_DRIVERS, 01 )

/**
 * Set MCA driver-private data
 *
 * @v mca		MCA device
 * @v priv		Private data
 */
static inline void mca_set_drvdata ( struct mca_device *mca, void *priv ) {
	mca->priv = priv;
}

/**
 * Get MCA driver-private data
 *
 * @v mca		MCA device
 * @ret priv		Private data
 */
static inline void * mca_get_drvdata ( struct mca_device *mca ) {
	return mca->priv;
}

#endif
