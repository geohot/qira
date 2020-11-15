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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/usb.h>
#include "usbhub.h"

/** @file
 *
 * USB hub driver
 *
 */

/**
 * Refill interrupt ring
 *
 * @v hubdev		Hub device
 */
static void hub_refill ( struct usb_hub_device *hubdev ) {
	int rc;

	/* Refill interrupt endpoint */
	if ( ( rc = usb_refill ( &hubdev->intr ) ) != 0 ) {
		DBGC ( hubdev, "HUB %s could not refill interrupt: %s\n",
		       hubdev->name, strerror ( rc ) );
		/* Continue attempting to refill */
		return;
	}

	/* Stop refill process */
	process_del ( &hubdev->refill );
}

/** Refill process descriptor */
static struct process_descriptor hub_refill_desc =
	PROC_DESC ( struct usb_hub_device, refill, hub_refill );

/**
 * Complete interrupt transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void hub_complete ( struct usb_endpoint *ep,
			   struct io_buffer *iobuf, int rc ) {
	struct usb_hub_device *hubdev =
		container_of ( ep, struct usb_hub_device, intr );
	struct usb_hub *hub = hubdev->hub;
	uint8_t *data = iobuf->data;
	unsigned int bits = ( 8 * iob_len ( iobuf ) );
	unsigned int i;

	/* Ignore packets cancelled when the endpoint closes */
	if ( ! ep->open )
		goto done;

	/* Ignore packets with errors */
	if ( rc != 0 ) {
		DBGC ( hubdev, "HUB %s interrupt failed: %s\n",
		       hubdev->name, strerror ( rc ) );
		DBGC_HDA ( hubdev, 0, iobuf->data, iob_len ( iobuf ) );
		goto done;
	}

	/* Report any port status changes */
	for ( i = 1 ; i <= hub->ports ; i++ ) {

		/* Sanity check */
		if ( i > bits ) {
			DBGC ( hubdev, "HUB %s underlength interrupt:\n",
			       hubdev->name );
			DBGC_HDA ( hubdev, 0, iobuf->data, iob_len ( iobuf ) );
			goto done;
		}

		/* Report port status change if applicable */
		if ( data[ i / 8 ] & ( 1 << ( i % 8 ) ) ) {
			DBGC2 ( hubdev, "HUB %s port %d status changed\n",
				hubdev->name, i );
			usb_port_changed ( usb_port ( hub, i ) );
		}
	}

 done:
	/* Start refill process */
	process_add ( &hubdev->refill );
}

/** Interrupt endpoint operations */
static struct usb_endpoint_driver_operations usb_hub_intr_operations = {
	.complete = hub_complete,
};

/**
 * Open hub
 *
 * @v hub		USB hub
 * @ret rc		Return status code
 */
static int hub_open ( struct usb_hub *hub ) {
	struct usb_hub_device *hubdev = usb_hub_get_drvdata ( hub );
	struct usb_device *usb = hubdev->usb;
	unsigned int i;
	int rc;

	/* Ensure ports are powered */
	for ( i = 1 ; i <= hub->ports ; i++ ) {
		if ( ( rc = usb_hub_set_port_feature ( usb, i,
						       USB_HUB_PORT_POWER,
						       0 ) ) != 0 ) {
			DBGC ( hubdev, "HUB %s port %d could not apply power: "
			       "%s\n", hubdev->name, i, strerror ( rc ) );
			goto err_power;
		}
	}

	/* Open interrupt endpoint */
	if ( ( rc = usb_endpoint_open ( &hubdev->intr ) ) != 0 ) {
		DBGC ( hubdev, "HUB %s could not register interrupt: %s\n",
		       hubdev->name, strerror ( rc ) );
		goto err_open;
	}

	/* Start refill process */
	process_add ( &hubdev->refill );

	/* Refill interrupt ring */
	hub_refill ( hubdev );

	return 0;

	usb_endpoint_close ( &hubdev->intr );
 err_open:
 err_power:
	return rc;
}

/**
 * Close hub
 *
 * @v hub		USB hub
 */
static void hub_close ( struct usb_hub *hub ) {
	struct usb_hub_device *hubdev = usb_hub_get_drvdata ( hub );

	/* Close interrupt endpoint */
	usb_endpoint_close ( &hubdev->intr );

	/* Stop refill process */
	process_del ( &hubdev->refill );
}

/**
 * Enable port
 *
 * @v hub		USB hub
 * @v port		USB port
 * @ret rc		Return status code
 */
static int hub_enable ( struct usb_hub *hub, struct usb_port *port ) {
	struct usb_hub_device *hubdev = usb_hub_get_drvdata ( hub );
	struct usb_device *usb = hubdev->usb;
	struct usb_hub_port_status status;
	unsigned int current;
	unsigned int i;
	int rc;

	/* Initiate reset if applicable */
	if ( ( hub->protocol < USB_PROTO_3_0 ) &&
	     ( ( rc = usb_hub_set_port_feature ( usb, port->address,
						 USB_HUB_PORT_RESET, 0 ) )!=0)){
		DBGC ( hubdev, "HUB %s port %d could not initiate reset: %s\n",
		       hubdev->name, port->address, strerror ( rc ) );
		return rc;
	}

	/* Wait for port to become enabled */
	for ( i = 0 ; i < USB_HUB_ENABLE_MAX_WAIT_MS ; i++ ) {

		/* Check for port being enabled */
		if ( ( rc = usb_hub_get_port_status ( usb, port->address,
						      &status ) ) != 0 ) {
			DBGC ( hubdev, "HUB %s port %d could not get status: "
			       "%s\n", hubdev->name, port->address,
			       strerror ( rc ) );
			return rc;
		}
		current = le16_to_cpu ( status.current );
		if ( current & ( 1 << USB_HUB_PORT_ENABLE ) )
			return 0;

		/* Delay */
		mdelay ( 1 );
	}

	DBGC ( hubdev, "HUB %s port %d timed out waiting for enable\n",
	       hubdev->name, port->address );
	return -ETIMEDOUT;
}

/**
 * Disable port
 *
 * @v hub		USB hub
 * @v port		USB port
 * @ret rc		Return status code
 */
static int hub_disable ( struct usb_hub *hub, struct usb_port *port ) {
	struct usb_hub_device *hubdev = usb_hub_get_drvdata ( hub );
	struct usb_device *usb = hubdev->usb;
	int rc;

	/* Disable port */
	if ( ( rc = usb_hub_clear_port_feature ( usb, port->address,
						 USB_HUB_PORT_ENABLE, 0 ) )!=0){
		DBGC ( hubdev, "HUB %s port %d could not disable: %s\n",
		       hubdev->name, port->address, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Clear port status change bits
 *
 * @v hubdev		USB hub device
 * @v port		Port number
 * @v changed		Port status change bits
 * @ret rc		Return status code
 */
static int hub_clear_changes ( struct usb_hub_device *hubdev,
			       unsigned int port, uint16_t changed ) {
	struct usb_device *usb = hubdev->usb;
	unsigned int bit;
	unsigned int feature;
	int rc;

	/* Clear each set bit */
	for ( bit = 0 ; bit < 16 ; bit++ ) {

		/* Skip unset bits */
		if ( ! ( changed & ( 1 << bit ) ) )
			continue;

		/* Skip unused features */
		feature = USB_HUB_C_FEATURE ( bit );
		if ( ! ( hubdev->features & ( 1 << feature ) ) )
			continue;

		/* Clear bit */
		if ( ( rc = usb_hub_clear_port_feature ( usb, port,
							 feature, 0 ) ) != 0 ) {
			DBGC ( hubdev, "HUB %s port %d could not clear feature "
			       "%d: %s\n", hubdev->name, port, feature,
			       strerror ( rc ) );
			return rc;
		}
	}

	return 0;
}

/**
 * Update port speed
 *
 * @v hub		USB hub
 * @v port		USB port
 * @ret rc		Return status code
 */
static int hub_speed ( struct usb_hub *hub, struct usb_port *port ) {
	struct usb_hub_device *hubdev = usb_hub_get_drvdata ( hub );
	struct usb_device *usb = hubdev->usb;
	struct usb_hub_port_status status;
	unsigned int current;
	unsigned int changed;
	int rc;

	/* Get port status */
	if ( ( rc = usb_hub_get_port_status ( usb, port->address,
					      &status ) ) != 0 ) {
		DBGC ( hubdev, "HUB %s port %d could not get status: %s\n",
		       hubdev->name, port->address, strerror ( rc ) );
		return rc;
	}
	current = le16_to_cpu ( status.current );
	changed = le16_to_cpu ( status.changed );
	DBGC2 ( hubdev, "HUB %s port %d status is %04x:%04x\n",
		hubdev->name, port->address, changed, current );

	/* Update port speed */
	if ( current & ( 1 << USB_HUB_PORT_CONNECTION ) ) {
		if ( hub->protocol >= USB_PROTO_3_0 ) {
			port->speed = USB_SPEED_SUPER;
		} else if ( current & ( 1 << USB_HUB_PORT_LOW_SPEED ) ) {
			port->speed = USB_SPEED_LOW;
		} else if ( current & ( 1 << USB_HUB_PORT_HIGH_SPEED ) ) {
			port->speed = USB_SPEED_HIGH;
		} else {
			port->speed = USB_SPEED_FULL;
		}
	} else {
		port->speed = USB_SPEED_NONE;
	}

	/* Record disconnections */
	port->disconnected |= ( changed & ( 1 << USB_HUB_PORT_CONNECTION ) );

	/* Clear port status change bits */
	if ( ( rc = hub_clear_changes ( hubdev, port->address, changed ) ) != 0)
		return rc;

	return 0;
}

/**
 * Clear transaction translator buffer
 *
 * @v hub		USB hub
 * @v port		USB port
 * @v ep		USB endpoint
 * @ret rc		Return status code
 */
static int hub_clear_tt ( struct usb_hub *hub, struct usb_port *port,
			  struct usb_endpoint *ep ) {
	struct usb_hub_device *hubdev = usb_hub_get_drvdata ( hub );
	struct usb_device *usb = hubdev->usb;
	int rc;

	/* Clear transaction translator buffer.  All hubs must support
	 * single-TT operation; we simplify our code by supporting
	 * only this configuration.
	 */
	if ( ( rc = usb_hub_clear_tt_buffer ( usb, ep->usb->address,
					      ep->address, ep->attributes,
					      USB_HUB_TT_SINGLE ) ) != 0 ) {
		DBGC ( hubdev, "HUB %s port %d could not clear TT buffer: %s\n",
		       hubdev->name, port->address, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/** USB hub operations */
static struct usb_hub_driver_operations hub_operations = {
	.open = hub_open,
	.close = hub_close,
	.enable = hub_enable,
	.disable = hub_disable,
	.speed = hub_speed,
	.clear_tt = hub_clear_tt,
};

/**
 * Probe USB hub
 *
 * @v func		USB function
 * @v config		Configuration descriptor
 * @ret rc		Return status code
 */
static int hub_probe ( struct usb_function *func,
		       struct usb_configuration_descriptor *config ) {
	struct usb_device *usb = func->usb;
	struct usb_bus *bus = usb->port->hub->bus;
	struct usb_hub_device *hubdev;
	struct usb_interface_descriptor *interface;
	union usb_hub_descriptor desc;
	unsigned int depth;
	unsigned int ports;
	int enhanced;
	int rc;

	/* Allocate and initialise structure */
	hubdev = zalloc ( sizeof ( *hubdev ) );
	if ( ! hubdev ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	enhanced = ( usb->port->protocol >= USB_PROTO_3_0 );
	hubdev->name = func->name;
	hubdev->usb = usb;
	hubdev->features =
		( enhanced ? USB_HUB_FEATURES_ENHANCED : USB_HUB_FEATURES );
	usb_endpoint_init ( &hubdev->intr, usb, &usb_hub_intr_operations );
	usb_refill_init ( &hubdev->intr, 0, USB_HUB_INTR_FILL );
	process_init_stopped ( &hubdev->refill, &hub_refill_desc, NULL );

	/* Locate hub interface descriptor */
	interface = usb_interface_descriptor ( config, func->interface[0], 0 );
	if ( ! interface ) {
		DBGC ( hubdev, "HUB %s has no interface descriptor\n",
		       hubdev->name );
		rc = -EINVAL;
		goto err_interface;
	}

	/* Locate interrupt endpoint descriptor */
	if ( ( rc = usb_endpoint_described ( &hubdev->intr, config, interface,
					     USB_INTERRUPT_IN, 0 ) ) != 0 ) {
		DBGC ( hubdev, "HUB %s could not describe interrupt endpoint: "
		       "%s\n", hubdev->name, strerror ( rc ) );
		goto err_endpoint;
	}

	/* Set hub depth */
	depth = usb_depth ( usb );
	if ( enhanced ) {
		if ( ( rc = usb_hub_set_hub_depth ( usb, depth ) ) != 0 ) {
			DBGC ( hubdev, "HUB %s could not set hub depth to %d: "
			       "%s\n", hubdev->name, depth, strerror ( rc ) );
			goto err_set_hub_depth;
		}
	}

	/* Get hub descriptor */
	if ( ( rc = usb_hub_get_descriptor ( usb, enhanced, &desc ) ) != 0 ) {
		DBGC ( hubdev, "HUB %s could not get hub descriptor: %s\n",
		       hubdev->name, strerror ( rc ) );
		goto err_hub_descriptor;
	}
	ports = desc.basic.ports;
	DBGC ( hubdev, "HUB %s has %d ports at depth %d%s\n", hubdev->name,
	       ports, depth, ( enhanced ? " (enhanced)" : "" ) );

	/* Allocate hub */
	hubdev->hub = alloc_usb_hub ( bus, usb, ports, &hub_operations );
	if ( ! hubdev->hub ) {
		rc = -ENOMEM;
		goto err_alloc_hub;
	}
	usb_hub_set_drvdata ( hubdev->hub, hubdev );

	/* Register hub */
	if ( ( rc = register_usb_hub ( hubdev->hub ) ) != 0 ) {
		DBGC ( hubdev, "HUB %s could not register: %s\n",
		       hubdev->name, strerror ( rc ) );
		goto err_register_hub;
	}

	usb_func_set_drvdata ( func, hubdev );
	return 0;

	unregister_usb_hub ( hubdev->hub );
 err_register_hub:
	free_usb_hub ( hubdev->hub );
 err_alloc_hub:
 err_hub_descriptor:
 err_set_hub_depth:
 err_endpoint:
 err_interface:
	free ( hubdev );
 err_alloc:
	return rc;
}

/**
 * Remove USB hub
 *
 * @v func		USB function
 * @ret rc		Return status code
 */
static void hub_remove ( struct usb_function *func ) {
	struct usb_hub_device *hubdev = usb_func_get_drvdata ( func );
	struct usb_hub *hub = hubdev->hub;
	struct usb_device *usb = hubdev->usb;
	struct usb_port *port;
	unsigned int i;

	/* If hub has been unplugged, mark all ports as unplugged */
	if ( usb->port->speed == USB_SPEED_NONE ) {
		for ( i = 1 ; i <= hub->ports ; i++ ) {
			port = usb_port ( hub, i );
			port->speed = USB_SPEED_NONE;
		}
	}

	/* Unregister hub */
	unregister_usb_hub ( hubdev->hub );
	assert ( ! process_running ( &hubdev->refill ) );

	/* Free hub */
	free_usb_hub ( hubdev->hub );

	/* Free hub device */
	free ( hubdev );
}

/** USB hub device IDs */
static struct usb_device_id hub_ids[] = {
	{
		.name = "hub-1",
		.vendor = USB_ANY_ID,
		.product = USB_ANY_ID,
		.class = {
			.class = USB_CLASS_HUB,
			.subclass = 0,
			.protocol = 0,
		},
	},
	{
		.name = "hub-2",
		.vendor = USB_ANY_ID,
		.product = USB_ANY_ID,
		.class = {
			.class = USB_CLASS_HUB,
			.subclass = 0,
			.protocol = 1,
		},
	},
};

/** USB hub driver */
struct usb_driver usb_hub_driver __usb_driver = {
	.ids = hub_ids,
	.id_count = ( sizeof ( hub_ids ) / sizeof ( hub_ids[0] ) ),
	.probe = hub_probe,
	.remove = hub_remove,
};
