/*
 * Copyright (C) 2014 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdio.h>
#include <errno.h>
#include <ipxe/malloc.h>
#include <ipxe/device.h>
#include <ipxe/timer.h>
#include <ipxe/nap.h>
#include <ipxe/xen.h>
#include <ipxe/xenstore.h>
#include <ipxe/xenbus.h>

/** @file
 *
 * Xen device bus
 *
 */

/* Disambiguate the various error causes */
#define ETIMEDOUT_UNKNOWN						\
	__einfo_error ( EINFO_ETIMEDOUT_UNKNOWN )
#define EINFO_ETIMEDOUT_UNKNOWN						\
	__einfo_uniqify ( EINFO_ETIMEDOUT, XenbusStateUnknown,		\
			  "Unknown" )
#define ETIMEDOUT_INITIALISING						\
	__einfo_error ( EINFO_ETIMEDOUT_INITIALISING )
#define EINFO_ETIMEDOUT_INITIALISING					\
	__einfo_uniqify ( EINFO_ETIMEDOUT, XenbusStateInitialising,	\
			  "Initialising" )
#define ETIMEDOUT_INITWAIT						\
	__einfo_error ( EINFO_ETIMEDOUT_INITWAIT )
#define EINFO_ETIMEDOUT_INITWAIT					\
	__einfo_uniqify ( EINFO_ETIMEDOUT, XenbusStateInitWait,		\
			  "InitWait" )
#define ETIMEDOUT_INITIALISED						\
	__einfo_error ( EINFO_ETIMEDOUT_INITIALISED )
#define EINFO_ETIMEDOUT_INITIALISED					\
	__einfo_uniqify ( EINFO_ETIMEDOUT, XenbusStateInitialised,	\
			  "Initialised" )
#define ETIMEDOUT_CONNECTED						\
	__einfo_error ( EINFO_ETIMEDOUT_CONNECTED )
#define EINFO_ETIMEDOUT_CONNECTED					\
	__einfo_uniqify ( EINFO_ETIMEDOUT, XenbusStateConnected,	\
			  "Connected" )
#define ETIMEDOUT_CLOSING						\
	__einfo_error ( EINFO_ETIMEDOUT_CLOSING )
#define EINFO_ETIMEDOUT_CLOSING						\
	__einfo_uniqify ( EINFO_ETIMEDOUT, XenbusStateClosing,		\
			  "Closing" )
#define ETIMEDOUT_CLOSED						\
	__einfo_error ( EINFO_ETIMEDOUT_CLOSED )
#define EINFO_ETIMEDOUT_CLOSED						\
	__einfo_uniqify ( EINFO_ETIMEDOUT, XenbusStateClosed,		\
			  "Closed" )
#define ETIMEDOUT_RECONFIGURING						\
	__einfo_error ( EINFO_ETIMEDOUT_RECONFIGURING )
#define EINFO_ETIMEDOUT_RECONFIGURING					\
	__einfo_uniqify ( EINFO_ETIMEDOUT, XenbusStateReconfiguring,	\
			  "Reconfiguring" )
#define ETIMEDOUT_RECONFIGURED						\
	__einfo_error ( EINFO_ETIMEDOUT_RECONFIGURED )
#define EINFO_ETIMEDOUT_RECONFIGURED					\
	__einfo_uniqify ( EINFO_ETIMEDOUT, XenbusStateReconfigured,	\
			  "Reconfigured" )
#define ETIMEDOUT_STATE( state )					\
	EUNIQ ( EINFO_ETIMEDOUT, (state), ETIMEDOUT_UNKNOWN,		\
		ETIMEDOUT_INITIALISING, ETIMEDOUT_INITWAIT,		\
		ETIMEDOUT_INITIALISED, ETIMEDOUT_CONNECTED,		\
		ETIMEDOUT_CLOSING, ETIMEDOUT_CLOSED,			\
		ETIMEDOUT_RECONFIGURING, ETIMEDOUT_RECONFIGURED )

/** Maximum time to wait for backend to reach a given state, in ticks */
#define XENBUS_BACKEND_TIMEOUT ( 5 * TICKS_PER_SEC )

/**
 * Set device state
 *
 * @v xendev		Xen device
 * @v state		New state
 * @ret rc		Return status code
 */
int xenbus_set_state ( struct xen_device *xendev, int state ) {
	int rc;

	/* Attempt to set state */
	if ( ( rc = xenstore_write_num ( xendev->xen, state, xendev->key,
					 "state", NULL ) ) != 0 ) {
		DBGC ( xendev, "XENBUS %s could not set state=\"%d\": %s\n",
		       xendev->key, state, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Get backend state
 *
 * @v xendev		Xen device
 * @ret state		Backend state, or negative error
 */
int xenbus_backend_state ( struct xen_device *xendev ) {
	unsigned long state;
	int rc;

	/* Attempt to get backend state */
	if ( ( rc = xenstore_read_num ( xendev->xen, &state, xendev->backend,
					"state", NULL ) ) != 0 ) {
		DBGC ( xendev, "XENBUS %s could not read %s/state: %s\n",
		       xendev->key, xendev->backend, strerror ( rc ) );
		return rc;
	}

	return state;
}

/**
 * Wait for backend to reach a given state
 *
 * @v xendev		Xen device
 * @v state		Desired backend state
 * @ret rc		Return status code
 */
int xenbus_backend_wait ( struct xen_device *xendev, int state ) {
	unsigned long started = currticks();
	unsigned long elapsed;
	unsigned int attempts = 0;
	int current_state;
	int rc;

	/* Wait for backend to reach this state */
	do {

		/* Get current backend state */
		current_state = xenbus_backend_state ( xendev );
		if ( current_state < 0 ) {
			rc = current_state;
			return rc;
		}
		if ( current_state == state )
			return 0;

		/* Allow time for backend to react */
		cpu_nap();

		/* XenStore is a very slow interface; any fixed delay
		 * time would be dwarfed by the XenStore access time.
		 * We therefore use wall clock to time out this
		 * operation.
		 */
		elapsed = ( currticks() - started );
		attempts++;

	} while ( elapsed < XENBUS_BACKEND_TIMEOUT );

	/* Construct status code from current backend state */
	rc = -ETIMEDOUT_STATE ( current_state );
	DBGC ( xendev, "XENBUS %s timed out after %d attempts waiting for "
	       "%s/state=\"%d\": %s\n", xendev->key, attempts, xendev->backend,
	       state, strerror ( rc ) );

	return rc;
}

/**
 * Find driver for Xen device
 *
 * @v type		Device type
 * @ret driver		Driver, or NULL
 */
static struct xen_driver * xenbus_find_driver ( const char *type ) {
	struct xen_driver *xendrv;

	for_each_table_entry ( xendrv, XEN_DRIVERS ) {
		if ( strcmp ( xendrv->type, type ) == 0 )
			return xendrv;
	}
	return NULL;
}

/**
 * Probe Xen device
 *
 * @v xen		Xen hypervisor
 * @v parent		Parent device
 * @v type		Device type
 * @v instance		Device instance
 * @ret rc		Return status code
 */
static int xenbus_probe_device ( struct xen_hypervisor *xen,
				 struct device *parent, const char *type,
				 const char *instance ) {
	struct xen_device *xendev;
	size_t key_len;
	int rc;

	/* Allocate and initialise structure */
	key_len = ( 7 /* "device/" */ + strlen ( type ) + 1 /* "/" */ +
		    strlen ( instance ) + 1 /* NUL */ );
	xendev = zalloc ( sizeof ( *xendev ) + key_len );
	if ( ! xendev ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	snprintf ( xendev->dev.name, sizeof ( xendev->dev.name ), "%s/%s",
		   type, instance );
	xendev->dev.desc.bus_type = BUS_TYPE_XEN;
	INIT_LIST_HEAD ( &xendev->dev.children );
	list_add_tail ( &xendev->dev.siblings, &parent->children );
	xendev->dev.parent = parent;
	xendev->xen = xen;
	xendev->key = ( ( void * ) ( xendev + 1 ) );
	snprintf ( xendev->key, key_len, "device/%s/%s", type, instance );

	/* Read backend key */
	if ( ( rc = xenstore_read ( xen, &xendev->backend, xendev->key,
				    "backend", NULL ) ) != 0 ) {
		DBGC ( xendev, "XENBUS %s could not read backend: %s\n",
		       xendev->key, strerror ( rc ) );
		goto err_read_backend;
	}

	/* Read backend domain ID */
	if ( ( rc = xenstore_read_num ( xen, &xendev->backend_id, xendev->key,
					"backend-id", NULL ) ) != 0 ) {
		DBGC ( xendev, "XENBUS %s could not read backend-id: %s\n",
		       xendev->key, strerror ( rc ) );
		goto err_read_backend_id;
	}
	DBGC ( xendev, "XENBUS %s backend=\"%s\" in domain %ld\n",
	       xendev->key, xendev->backend, xendev->backend_id );

	/* Look for a driver */
	xendev->driver = xenbus_find_driver ( type );
	if ( ! xendev->driver ) {
		DBGC ( xendev, "XENBUS %s has no driver\n", xendev->key );
		/* Not a fatal error */
		rc = 0;
		goto err_no_driver;
	}
	xendev->dev.driver_name = xendev->driver->name;
	DBGC ( xendev, "XENBUS %s has driver \"%s\"\n", xendev->key,
	       xendev->driver->name );

	/* Probe driver */
	if ( ( rc = xendev->driver->probe ( xendev ) ) != 0 ) {
		DBGC ( xendev, "XENBUS could not probe %s: %s\n",
		       xendev->key, strerror ( rc ) );
		goto err_probe;
	}

	return 0;

	xendev->driver->remove ( xendev );
 err_probe:
 err_no_driver:
 err_read_backend_id:
	free ( xendev->backend );
 err_read_backend:
	list_del ( &xendev->dev.siblings );
	free ( xendev );
 err_alloc:
	return rc;
}

/**
 * Remove Xen device
 *
 * @v xendev		Xen device
 */
static void xenbus_remove_device ( struct xen_device *xendev ) {

	/* Remove device */
	xendev->driver->remove ( xendev );
	free ( xendev->backend );
	list_del ( &xendev->dev.siblings );
	free ( xendev );
}

/**
 * Probe Xen devices of a given type
 *
 * @v xen		Xen hypervisor
 * @v parent		Parent device
 * @v type		Device type
 * @ret rc		Return status code
 */
static int xenbus_probe_type ( struct xen_hypervisor *xen,
			       struct device *parent, const char *type ) {
	char *children;
	char *child;
	size_t len;
	int rc;

	/* Get children of this key */
	if ( ( rc = xenstore_directory ( xen, &children, &len, "device",
					 type, NULL ) ) != 0 ) {
		DBGC ( xen, "XENBUS could not list \"%s\" devices: %s\n",
		       type, strerror ( rc ) );
		goto err_directory;
	}

	/* Probe each child */
	for ( child = children ; child < ( children + len ) ;
	      child += ( strlen ( child ) + 1 /* NUL */ ) ) {
		if ( ( rc = xenbus_probe_device ( xen, parent, type,
						  child ) ) != 0 )
			goto err_probe_device;
	}

	free ( children );
	return 0;

 err_probe_device:
	free ( children );
 err_directory:
	return rc;
}

/**
 * Probe Xen bus
 *
 * @v xen		Xen hypervisor
 * @v parent		Parent device
 * @ret rc		Return status code
 */
int xenbus_probe ( struct xen_hypervisor *xen, struct device *parent ) {
	char *types;
	char *type;
	size_t len;
	int rc;

	/* Get children of "device" key */
	if ( ( rc = xenstore_directory ( xen, &types, &len, "device",
					 NULL ) ) != 0 ) {
		DBGC ( xen, "XENBUS could not list device types: %s\n",
		       strerror ( rc ) );
		goto err_directory;
	}

	/* Probe each child type */
	for ( type = types ; type < ( types + len ) ;
	      type += ( strlen ( type ) + 1 /* NUL */ ) ) {
		if ( ( rc = xenbus_probe_type ( xen, parent, type ) ) != 0 )
			goto err_probe_type;
	}

	free ( types );
	return 0;

	xenbus_remove ( xen, parent );
 err_probe_type:
	free ( types );
 err_directory:
	return rc;
}

/**
 * Remove Xen bus
 *
 * @v xen		Xen hypervisor
 * @v parent		Parent device
 */
void xenbus_remove ( struct xen_hypervisor *xen __unused,
		     struct device *parent ) {
	struct xen_device *xendev;
	struct xen_device *tmp;

	/* Remove devices */
	list_for_each_entry_safe ( xendev, tmp, &parent->children,
				   dev.siblings ) {
		xenbus_remove_device ( xendev );
	}
}
