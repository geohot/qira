#ifndef _IPXE_XENBUS_H
#define _IPXE_XENBUS_H

/** @file
 *
 * Xen device bus
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/device.h>
#include <ipxe/tables.h>
#include <ipxe/xen.h>
#include <xen/io/xenbus.h>

/** A Xen device */
struct xen_device {
	/** Generic iPXE device */
	struct device dev;
	/** Xen hypervisor */
	struct xen_hypervisor *xen;
	/** XenStore key */
	char *key;
	/** Backend XenStore key */
	char *backend;
	/** Backend domain ID */
	unsigned long backend_id;
	/** Driver */
	struct xen_driver *driver;
	/** Driver-private data */
	void *priv;
};

/** A Xen device driver */
struct xen_driver {
	/** Name */
	const char *name;
	/** Device type */
	const char *type;
	/** Probe device
	 *
	 * @v xendev		Xen device
	 * @ret rc		Return status code
	 */
	int ( * probe ) ( struct xen_device *xendev );
	/** Remove device
	 *
	 * @v xendev		Xen device
	 */
	void ( * remove ) ( struct xen_device *xendev );
};

/** Xen device driver table */
#define XEN_DRIVERS __table ( struct xen_driver, "xen_drivers" )

/** Declare a Xen device driver */
#define __xen_driver __table_entry ( XEN_DRIVERS, 01 )

/**
 * Set Xen device driver-private data
 *
 * @v xendev		Xen device
 * @v priv		Private data
 */
static inline void xen_set_drvdata ( struct xen_device *xendev, void *priv ) {
	xendev->priv = priv;
}

/**
 * Get Xen device driver-private data
 *
 * @v xendev		Xen device
 * @ret priv		Private data
 */
static inline void * xen_get_drvdata ( struct xen_device *xendev ) {
	return xendev->priv;
}

extern int xenbus_set_state ( struct xen_device *xendev, int state );
extern int xenbus_backend_state ( struct xen_device *xendev );
extern int xenbus_backend_wait ( struct xen_device *xendev, int state );
extern int xenbus_probe ( struct xen_hypervisor *xen, struct device *parent );
extern void xenbus_remove ( struct xen_hypervisor *xen, struct device *parent );

#endif /* _IPXE_XENBUS_H */
