#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ipxe/io.h>
#include <unistd.h>
#include <ipxe/eisa.h>

FILE_LICENCE ( GPL2_OR_LATER );

static void eisabus_remove ( struct root_device *rootdev );

/**
 * Reset and enable/disable an EISA device
 *
 * @v eisa		EISA device
 * @v enabled		1=enable, 0=disable
 */
void eisa_device_enabled ( struct eisa_device *eisa, int enabled ) {
	/* Set reset line high for 1000 µs.  Spec says 500 µs, but
	 * this doesn't work for all cards, so we are conservative.
	 */
	outb ( EISA_CMD_RESET, eisa->ioaddr + EISA_GLOBAL_CONFIG );
	udelay ( 1000 ); /* Must wait 800 */

	/* Set reset low and write a 1 to ENABLE.  Delay again, in
	 * case the card takes a while to wake up.
	 */
	outb ( enabled ? EISA_CMD_ENABLE : 0,
	       eisa->ioaddr + EISA_GLOBAL_CONFIG );
	udelay ( 1000 ); /* Must wait 800 */

	DBG ( "EISA %s device %02x\n", ( enabled ? "enabled" : "disabled" ),
	      eisa->slot );
}

/**
 * Probe an EISA device
 *
 * @v eisa		EISA device
 * @ret rc		Return status code
 *
 * Searches for a driver for the EISA device.  If a driver is found,
 * its probe() routine is called.
 */
static int eisa_probe ( struct eisa_device *eisa ) {
	struct eisa_driver *driver;
	struct eisa_device_id *id;
	unsigned int i;
	int rc;

	DBG ( "Adding EISA device %02x (%04x:%04x (\"%s\") io %x)\n",
	      eisa->slot, eisa->vendor_id, eisa->prod_id,
	      isa_id_string ( eisa->vendor_id, eisa->prod_id ), eisa->ioaddr );

	for_each_table_entry ( driver, EISA_DRIVERS ) {
		for ( i = 0 ; i < driver->id_count ; i++ ) {
			id = &driver->ids[i];
			if ( id->vendor_id != eisa->vendor_id )
				continue;
			if ( ISA_PROD_ID ( id->prod_id ) !=
			     ISA_PROD_ID ( eisa->prod_id ) )
				continue;
			eisa->driver = driver;
			eisa->dev.driver_name = id->name;
			DBG ( "...using driver %s\n", eisa->dev.driver_name );
			if ( ( rc = driver->probe ( eisa, id ) ) != 0 ) {
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
 * Remove an EISA device
 *
 * @v eisa		EISA device
 */
static void eisa_remove ( struct eisa_device *eisa ) {
	eisa->driver->remove ( eisa );
	DBG ( "Removed EISA device %02x\n", eisa->slot );
}

/**
 * Probe EISA root bus
 *
 * @v rootdev		EISA bus root device
 *
 * Scans the EISA bus for devices and registers all devices it can
 * find.
 */
static int eisabus_probe ( struct root_device *rootdev ) {
	struct eisa_device *eisa = NULL;
	unsigned int slot;
	int rc;

	for ( slot = EISA_MIN_SLOT ; slot <= EISA_MAX_SLOT ; slot++ ) {
		/* Allocate struct eisa_device */
		if ( ! eisa )
			eisa = malloc ( sizeof ( *eisa ) );
		if ( ! eisa ) {
			rc = -ENOMEM;
			goto err;
		}
		memset ( eisa, 0, sizeof ( *eisa ) );
		eisa->slot = slot;
		eisa->ioaddr = EISA_SLOT_BASE ( eisa->slot );

		/* Test for board present */
		outb ( 0xff, eisa->ioaddr + EISA_VENDOR_ID );
		eisa->vendor_id =
			le16_to_cpu ( inw ( eisa->ioaddr + EISA_VENDOR_ID ) );
		eisa->prod_id =
			le16_to_cpu ( inw ( eisa->ioaddr + EISA_PROD_ID ) );
		if ( eisa->vendor_id & 0x80 ) {
			/* No board present */
			continue;
		}

		/* Add to device hierarchy */
		snprintf ( eisa->dev.name, sizeof ( eisa->dev.name ),
			   "EISA%02x", slot );
		eisa->dev.desc.bus_type = BUS_TYPE_EISA;
		eisa->dev.desc.vendor = eisa->vendor_id;
		eisa->dev.desc.device = eisa->prod_id;
		eisa->dev.parent = &rootdev->dev;
		list_add ( &eisa->dev.siblings, &rootdev->dev.children );
		INIT_LIST_HEAD ( &eisa->dev.children );

		/* Look for a driver */
		if ( eisa_probe ( eisa ) == 0 ) {
			/* eisadev registered, we can drop our ref */
			eisa = NULL;
		} else {
			/* Not registered; re-use struct */
			list_del ( &eisa->dev.siblings );
		}
	}

	free ( eisa );
	return 0;

 err:
	free ( eisa );
	eisabus_remove ( rootdev );
	return rc;
}

/**
 * Remove EISA root bus
 *
 * @v rootdev		EISA bus root device
 */
static void eisabus_remove ( struct root_device *rootdev ) {
	struct eisa_device *eisa;
	struct eisa_device *tmp;

	list_for_each_entry_safe ( eisa, tmp, &rootdev->dev.children,
				   dev.siblings ) {
		eisa_remove ( eisa );
		list_del ( &eisa->dev.siblings );
		free ( eisa );
	}
}

/** EISA bus root device driver */
static struct root_driver eisa_root_driver = {
	.probe = eisabus_probe,
	.remove = eisabus_remove,
};

/** EISA bus root device */
struct root_device eisa_root_device __root_device = {
	.dev = { .name = "EISA" },
	.driver = &eisa_root_driver,
};
