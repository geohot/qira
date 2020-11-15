/*
 * MCA bus driver code
 *
 * Abstracted from 3c509.c.
 *
 */

FILE_LICENCE ( BSD2 );

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ipxe/io.h>
#include <ipxe/mca.h>

static void mcabus_remove ( struct root_device *rootdev );

/**
 * Probe an MCA device
 *
 * @v mca		MCA device
 * @ret rc		Return status code
 *
 * Searches for a driver for the MCA device.  If a driver is found,
 * its probe() routine is called.
 */
static int mca_probe ( struct mca_device *mca ) {
	struct mca_driver *driver;
	struct mca_device_id *id;
	unsigned int i;
	int rc;

	DBG ( "Adding MCA slot %02x (ID %04x POS "
	      "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x)\n",
	      mca->slot, MCA_ID ( mca ),
	      mca->pos[0], mca->pos[1], mca->pos[2], mca->pos[3],
	      mca->pos[4], mca->pos[5], mca->pos[6], mca->pos[7] );

	for_each_table_entry ( driver, MCA_DRIVERS ) {
		for ( i = 0 ; i < driver->id_count ; i++ ) {
			id = &driver->ids[i];
			if ( id->id != MCA_ID ( mca ) )
				continue;
			mca->driver = driver;
			mca->dev.driver_name = id->name;
			DBG ( "...using driver %s\n", mca->dev.driver_name );
			if ( ( rc = driver->probe ( mca, id ) ) != 0 ) {
				DBG ( "......probe failed\n" );
				continue;
			}
			return 0;
		}
	}

	DBG ( "...no driver found\n" );
	return -ENOTTY;
}

/**
 * Remove an MCA device
 *
 * @v mca		MCA device
 */
static void mca_remove ( struct mca_device *mca ) {
	mca->driver->remove ( mca );
	DBG ( "Removed MCA device %02x\n", mca->slot );
}

/**
 * Probe MCA root bus
 *
 * @v rootdev		MCA bus root device
 *
 * Scans the MCA bus for devices and registers all devices it can
 * find.
 */
static int mcabus_probe ( struct root_device *rootdev ) {
	struct mca_device *mca = NULL;
	unsigned int slot;
	int seen_non_ff;
	unsigned int i;
	int rc;

	for ( slot = 0 ; slot <= MCA_MAX_SLOT_NR ; slot++ ) {
		/* Allocate struct mca_device */
		if ( ! mca )
			mca = malloc ( sizeof ( *mca ) );
		if ( ! mca ) {
			rc = -ENOMEM;
			goto err;
		}
		memset ( mca, 0, sizeof ( *mca ) );
		mca->slot = slot;

		/* Make sure motherboard setup is off */
		outb_p ( 0xff, MCA_MOTHERBOARD_SETUP_REG );

		/* Select the slot */
		outb_p ( 0x8 | ( mca->slot & 0xf ), MCA_ADAPTER_SETUP_REG );

		/* Read the POS registers */
		seen_non_ff = 0;
		for ( i = 0 ; i < ( sizeof ( mca->pos ) /
				    sizeof ( mca->pos[0] ) ) ; i++ ) {
			mca->pos[i] = inb_p ( MCA_POS_REG ( i ) );
			if ( mca->pos[i] != 0xff )
				seen_non_ff = 1;
		}
	
		/* Kill all setup modes */
		outb_p ( 0, MCA_ADAPTER_SETUP_REG );

		/* If all POS registers are 0xff, this means there's no device
		 * present
		 */
		if ( ! seen_non_ff )
			continue;

		/* Add to device hierarchy */
		snprintf ( mca->dev.name, sizeof ( mca->dev.name ),
			   "MCA%02x", slot );
		mca->dev.desc.bus_type = BUS_TYPE_MCA;
		mca->dev.desc.vendor = GENERIC_MCA_VENDOR;
		mca->dev.desc.device = MCA_ID ( mca );
		mca->dev.parent = &rootdev->dev;
		list_add ( &mca->dev.siblings, &rootdev->dev.children );
		INIT_LIST_HEAD ( &mca->dev.children );

		/* Look for a driver */
		if ( mca_probe ( mca ) == 0 ) {
			/* mcadev registered, we can drop our ref */
			mca = NULL;
		} else {
			/* Not registered; re-use struct */
			list_del ( &mca->dev.siblings );
		}
	}

	free ( mca );
	return 0;

 err:
	free ( mca );
	mcabus_remove ( rootdev );
	return rc;
}

/**
 * Remove MCA root bus
 *
 * @v rootdev		MCA bus root device
 */
static void mcabus_remove ( struct root_device *rootdev ) {
	struct mca_device *mca;
	struct mca_device *tmp;

	list_for_each_entry_safe ( mca, tmp, &rootdev->dev.children,
				   dev.siblings ) {
		mca_remove ( mca );
		list_del ( &mca->dev.siblings );
		free ( mca );
	}
}

/** MCA bus root device driver */
static struct root_driver mca_root_driver = {
	.probe = mcabus_probe,
	.remove = mcabus_remove,
};

/** MCA bus root device */
struct root_device mca_root_device __root_device = {
	.dev = { .name = "MCA" },
	.driver = &mca_root_driver,
};
