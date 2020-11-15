#ifndef _IPXE_DEVICE_H
#define _IPXE_DEVICE_H

/**
 * @file
 *
 * Device model
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/list.h>
#include <ipxe/tables.h>

struct interface;

/** A hardware device description */
struct device_description {
	/** Bus type
	 *
	 * This must be a BUS_TYPE_XXX constant.
	 */
	unsigned int bus_type;
	/** Location
	 *
	 * The interpretation of this field is bus-type-specific.
	 */
	unsigned int location;
	/** Vendor ID */
	unsigned int vendor;
	/** Device ID */
	unsigned int device;
	/** Device class */
	unsigned long class;
	/** I/O address */
	unsigned long ioaddr;
	/** IRQ */
	unsigned int irq;
};

/** PCI bus type */
#define BUS_TYPE_PCI 1

/** ISAPnP bus type */
#define BUS_TYPE_ISAPNP 2

/** EISA bus type */
#define BUS_TYPE_EISA 3

/** MCA bus type */
#define BUS_TYPE_MCA 4

/** ISA bus type */
#define BUS_TYPE_ISA 5

/** TAP bus type */
#define BUS_TYPE_TAP 6

/** EFI bus type */
#define BUS_TYPE_EFI 7

/** Xen bus type */
#define BUS_TYPE_XEN 8

/** Hyper-V bus type */
#define BUS_TYPE_HV 9

/** USB bus type */
#define BUS_TYPE_USB 10

/** A hardware device */
struct device {
	/** Name */
	char name[32];
	/** Driver name */
	const char *driver_name;
	/** Device description */
	struct device_description desc;
	/** Devices on the same bus */
	struct list_head siblings;
	/** Devices attached to this device */
	struct list_head children;
	/** Bus device */
	struct device *parent;
};

/**
 * A root device
 *
 * Root devices are system buses such as PCI, EISA, etc.
 *
 */
struct root_device {
	/** Device chain
	 *
	 * A root device has a NULL parent field.
	 */
	struct device dev;
	/** Root device driver */
	struct root_driver *driver;
	/** Driver-private data */
	void *priv;
};

/** A root device driver */
struct root_driver {
	/**
	 * Add root device
	 *
	 * @v rootdev	Root device
	 * @ret rc	Return status code
	 *
	 * Called from probe_devices() for all root devices in the build.
	 */
	int ( * probe ) ( struct root_device *rootdev );
	/**
	 * Remove root device
	 *
	 * @v rootdev	Root device
	 *
	 * Called from remove_device() for all successfully-probed
	 * root devices.
	 */
	void ( * remove ) ( struct root_device *rootdev );
};

/** Root device table */
#define ROOT_DEVICES __table ( struct root_device, "root_devices" )

/** Declare a root device */
#define __root_device __table_entry ( ROOT_DEVICES, 01 )

/**
 * Set root device driver-private data
 *
 * @v rootdev		Root device
 * @v priv		Private data
 */
static inline void rootdev_set_drvdata ( struct root_device *rootdev,
					 void *priv ){
	rootdev->priv = priv;
}

/**
 * Get root device driver-private data
 *
 * @v rootdev		Root device
 * @ret priv		Private data
 */
static inline void * rootdev_get_drvdata ( struct root_device *rootdev ) {
	return rootdev->priv;
}

extern int device_keep_count;

/**
 * Prevent devices from being removed on shutdown
 *
 */
static inline void devices_get ( void ) {
	device_keep_count++;
}

/**
 * Allow devices to be removed on shutdown
 *
 */
static inline void devices_put ( void ) {
	device_keep_count--;
}

extern struct device * identify_device ( struct interface *intf );
#define identify_device_TYPE( object_type ) \
	typeof ( struct device * ( object_type ) )

#endif /* _IPXE_DEVICE_H */
