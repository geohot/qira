#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ipxe/io.h>
#include <ipxe/isa.h>

FILE_LICENCE ( GPL2_OR_LATER );

/*
 * isa.c implements a "classical" port-scanning method of ISA device
 * detection.  The driver must provide a list of probe addresses
 * (probe_addrs), together with a function (probe_addr) that can be
 * used to test for the physical presence of a device at any given
 * address.
 *
 * Note that this should probably be considered the "last resort" for
 * device probing.  If the card supports ISAPnP or EISA, use that
 * instead.  Some cards (e.g. the 3c509) implement a proprietary
 * ISAPnP-like mechanism.
 *
 * The ISA probe address list can be overridden by config.h; if the
 * user specifies ISA_PROBE_ADDRS then that list will be used first.
 * (If ISA_PROBE_ONLY is defined, the driver's own list will never be
 * used).
 */

/*
 * User-supplied probe address list
 *
 */
static isa_probe_addr_t isa_extra_probe_addrs[] = {
#ifdef ISA_PROBE_ADDRS
	ISA_PROBE_ADDRS
#endif
};
#define ISA_EXTRA_PROBE_ADDR_COUNT \
     ( sizeof ( isa_extra_probe_addrs ) / sizeof ( isa_extra_probe_addrs[0] ) )

#define ISA_IOIDX_MIN( driver ) ( -ISA_EXTRA_PROBE_ADDR_COUNT )
#ifdef ISA_PROBE_ONLY
#define ISA_IOIDX_MAX( driver ) ( -1 )
#else
#define ISA_IOIDX_MAX( driver ) ( (int) (driver)->addr_count - 1 )
#endif

#define ISA_IOADDR( driver, ioidx )					  \
	( ( (ioidx) >= 0 ) ?						  \
	  (driver)->probe_addrs[(ioidx)] :				  \
	  *( isa_extra_probe_addrs + (ioidx) + ISA_EXTRA_PROBE_ADDR_COUNT ) )

static void isabus_remove ( struct root_device *rootdev );

/**
 * Probe an ISA device
 *
 * @v isa		ISA device
 * @ret rc		Return status code
 */
static int isa_probe ( struct isa_device *isa ) {
	int rc;

	DBG ( "Trying ISA driver %s at I/O %04x\n",
	      isa->driver->name, isa->ioaddr );

	if ( ( rc = isa->driver->probe ( isa ) ) != 0 ) {
		DBG ( "...probe failed\n" );
		return rc;
	}

	DBG ( "...device found\n" );
	return 0;
}

/**
 * Remove an ISA device
 *
 * @v isa		ISA device
 */
static void isa_remove ( struct isa_device *isa ) {
	isa->driver->remove ( isa );
	DBG ( "Removed ISA%04x\n", isa->ioaddr );
}

/**
 * Probe ISA root bus
 *
 * @v rootdev		ISA bus root device
 *
 * Scans the ISA bus for devices and registers all devices it can
 * find.
 */
static int isabus_probe ( struct root_device *rootdev ) {
	struct isa_device *isa = NULL;
	struct isa_driver *driver;
	int ioidx;
	int rc;

	for_each_table_entry ( driver, ISA_DRIVERS ) {
		for ( ioidx = ISA_IOIDX_MIN ( driver ) ;
		      ioidx <= ISA_IOIDX_MAX ( driver ) ; ioidx++ ) {
			/* Allocate struct isa_device */
			if ( ! isa )
				isa = malloc ( sizeof ( *isa ) );
			if ( ! isa ) {
				rc = -ENOMEM;
				goto err;
			}
			memset ( isa, 0, sizeof ( *isa ) );
			isa->driver = driver;
			isa->ioaddr = ISA_IOADDR ( driver, ioidx );

			/* Add to device hierarchy */
			snprintf ( isa->dev.name, sizeof ( isa->dev.name ),
				   "ISA%04x", isa->ioaddr );
			isa->dev.driver_name = driver->name;
			isa->dev.desc.bus_type = BUS_TYPE_ISA;
			isa->dev.desc.vendor = driver->vendor_id;
			isa->dev.desc.device = driver->prod_id;
			isa->dev.parent = &rootdev->dev;
			list_add ( &isa->dev.siblings,
				   &rootdev->dev.children );
			INIT_LIST_HEAD ( &isa->dev.children );

			/* Try probing at this I/O address */
			if ( isa_probe ( isa ) == 0 ) {
				/* isadev registered, we can drop our ref */
				isa = NULL;
			} else {
				/* Not registered; re-use struct */
				list_del ( &isa->dev.siblings );
			}
		}
	}

	free ( isa );
	return 0;

 err:
	free ( isa );
	isabus_remove ( rootdev );
	return rc;
}

/**
 * Remove ISA root bus
 *
 * @v rootdev		ISA bus root device
 */
static void isabus_remove ( struct root_device *rootdev ) {
	struct isa_device *isa;
	struct isa_device *tmp;

	list_for_each_entry_safe ( isa, tmp, &rootdev->dev.children,
				   dev.siblings ) {
		isa_remove ( isa );
		list_del ( &isa->dev.siblings );
		free ( isa );
	}
}

/** ISA bus root device driver */
static struct root_driver isa_root_driver = {
	.probe = isabus_probe,
	.remove = isabus_remove,
};

/** ISA bus root device */
struct root_device isa_root_device __root_device = {
	.dev = { .name = "ISA" },
	.driver = &isa_root_driver,
};
