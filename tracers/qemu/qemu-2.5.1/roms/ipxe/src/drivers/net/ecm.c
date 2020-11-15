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

#include <stdint.h>
#include <errno.h>
#include <ipxe/netdevice.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/base16.h>
#include <ipxe/profile.h>
#include <ipxe/usb.h>
#include "ecm.h"

/** @file
 *
 * CDC-ECM USB Ethernet driver
 *
 */

/** Interrupt completion profiler */
static struct profiler ecm_intr_profiler __profiler =
	{ .name = "ecm.intr" };

/** Bulk IN completion profiler */
static struct profiler ecm_in_profiler __profiler =
	{ .name = "ecm.in" };

/** Bulk OUT profiler */
static struct profiler ecm_out_profiler __profiler =
	{ .name = "ecm.out" };

/******************************************************************************
 *
 * Ethernet functional descriptor
 *
 ******************************************************************************
 */

/**
 * Locate Ethernet functional descriptor
 *
 * @v config		Configuration descriptor
 * @v interface		Interface descriptor
 * @ret desc		Descriptor, or NULL if not found
 */
struct ecm_ethernet_descriptor *
ecm_ethernet_descriptor ( struct usb_configuration_descriptor *config,
			  struct usb_interface_descriptor *interface ) {
	struct ecm_ethernet_descriptor *desc;

	for_each_interface_descriptor ( desc, config, interface ) {
		if ( ( desc->header.type == USB_CS_INTERFACE_DESCRIPTOR ) &&
		     ( desc->subtype == CDC_SUBTYPE_ETHERNET ) )
			return desc;
	}
	return NULL;
}

/**
 * Get hardware MAC address
 *
 * @v usb		USB device
 * @v desc		Ethernet functional descriptor
 * @v hw_addr		Hardware address to fill in
 * @ret rc		Return status code
 */
int ecm_fetch_mac ( struct usb_device *usb,
		    struct ecm_ethernet_descriptor *desc, uint8_t *hw_addr ) {
	char buf[ base16_encoded_len ( ETH_ALEN ) + 1 /* NUL */ ];
	int len;
	int rc;

	/* Fetch MAC address string */
	len = usb_get_string_descriptor ( usb, desc->mac, 0, buf,
					  sizeof ( buf ) );
	if ( len < 0 ) {
		rc = len;
		return rc;
	}

	/* Sanity check */
	if ( len != ( ( int ) ( sizeof ( buf ) - 1 /* NUL */ ) ) )
		return -EINVAL;

	/* Decode MAC address */
	len = base16_decode ( buf, hw_addr, ETH_ALEN );
	if ( len < 0 ) {
		rc = len;
		return rc;
	}

	return 0;
}

/******************************************************************************
 *
 * CDC-ECM communications interface
 *
 ******************************************************************************
 */

/**
 * Complete interrupt transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void ecm_intr_complete ( struct usb_endpoint *ep,
				struct io_buffer *iobuf, int rc ) {
	struct ecm_device *ecm = container_of ( ep, struct ecm_device,
						usbnet.intr );
	struct net_device *netdev = ecm->netdev;
	struct usb_setup_packet *message;
	size_t len = iob_len ( iobuf );

	/* Profile completions */
	profile_start ( &ecm_intr_profiler );

	/* Ignore packets cancelled when the endpoint closes */
	if ( ! ep->open )
		goto ignore;

	/* Drop packets with errors */
	if ( rc != 0 ) {
		DBGC ( ecm, "ECM %p interrupt failed: %s\n",
		       ecm, strerror ( rc ) );
		DBGC_HDA ( ecm, 0, iobuf->data, iob_len ( iobuf ) );
		goto error;
	}

	/* Extract message header */
	if ( len < sizeof ( *message ) ) {
		DBGC ( ecm, "ECM %p underlength interrupt:\n", ecm );
		DBGC_HDA ( ecm, 0, iobuf->data, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto error;
	}
	message = iobuf->data;

	/* Parse message header */
	switch ( message->request ) {

	case cpu_to_le16 ( CDC_NETWORK_CONNECTION ) :
		if ( message->value && ! netdev_link_ok ( netdev ) ) {
			DBGC ( ecm, "ECM %p link up\n", ecm );
			netdev_link_up ( netdev );
		} else if ( netdev_link_ok ( netdev ) && ! message->value ) {
			DBGC ( ecm, "ECM %p link down\n", ecm );
			netdev_link_down ( netdev );
		}
		break;

	case cpu_to_le16 ( CDC_CONNECTION_SPEED_CHANGE ) :
		/* Ignore */
		break;

	default:
		DBGC ( ecm, "ECM %p unrecognised interrupt:\n", ecm );
		DBGC_HDA ( ecm, 0, iobuf->data, iob_len ( iobuf ) );
		rc = -ENOTSUP;
		goto error;
	}

	/* Free I/O buffer */
	free_iob ( iobuf );
	profile_stop ( &ecm_intr_profiler );

	return;

 error:
	netdev_rx_err ( netdev, iob_disown ( iobuf ), rc );
 ignore:
	free_iob ( iobuf );
	return;
}

/** Interrupt endpoint operations */
static struct usb_endpoint_driver_operations ecm_intr_operations = {
	.complete = ecm_intr_complete,
};

/******************************************************************************
 *
 * CDC-ECM data interface
 *
 ******************************************************************************
 */

/**
 * Complete bulk IN transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void ecm_in_complete ( struct usb_endpoint *ep, struct io_buffer *iobuf,
			      int rc ) {
	struct ecm_device *ecm = container_of ( ep, struct ecm_device,
						usbnet.in );
	struct net_device *netdev = ecm->netdev;

	/* Profile receive completions */
	profile_start ( &ecm_in_profiler );

	/* Ignore packets cancelled when the endpoint closes */
	if ( ! ep->open )
		goto ignore;

	/* Record USB errors against the network device */
	if ( rc != 0 ) {
		DBGC ( ecm, "ECM %p bulk IN failed: %s\n",
		       ecm, strerror ( rc ) );
		goto error;
	}

	/* Hand off to network stack */
	netdev_rx ( netdev, iob_disown ( iobuf ) );

	profile_stop ( &ecm_in_profiler );
	return;

 error:
	netdev_rx_err ( netdev, iob_disown ( iobuf ), rc );
 ignore:
	free_iob ( iobuf );
}

/** Bulk IN endpoint operations */
static struct usb_endpoint_driver_operations ecm_in_operations = {
	.complete = ecm_in_complete,
};

/**
 * Transmit packet
 *
 * @v ecm		CDC-ECM device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int ecm_out_transmit ( struct ecm_device *ecm,
			      struct io_buffer *iobuf ) {
	int rc;

	/* Profile transmissions */
	profile_start ( &ecm_out_profiler );

	/* Enqueue I/O buffer */
	if ( ( rc = usb_stream ( &ecm->usbnet.out, iobuf, 1 ) ) != 0 )
		return rc;

	profile_stop ( &ecm_out_profiler );
	return 0;
}

/**
 * Complete bulk OUT transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void ecm_out_complete ( struct usb_endpoint *ep, struct io_buffer *iobuf,
			       int rc ) {
	struct ecm_device *ecm = container_of ( ep, struct ecm_device,
						usbnet.out );
	struct net_device *netdev = ecm->netdev;

	/* Report TX completion */
	netdev_tx_complete_err ( netdev, iobuf, rc );
}

/** Bulk OUT endpoint operations */
static struct usb_endpoint_driver_operations ecm_out_operations = {
	.complete = ecm_out_complete,
};

/******************************************************************************
 *
 * Network device interface
 *
 ******************************************************************************
 */

/**
 * Open network device
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int ecm_open ( struct net_device *netdev ) {
	struct ecm_device *ecm = netdev->priv;
	struct usb_device *usb = ecm->usb;
	unsigned int filter;
	int rc;

	/* Open USB network device */
	if ( ( rc = usbnet_open ( &ecm->usbnet ) ) != 0 ) {
		DBGC ( ecm, "ECM %p could not open: %s\n",
		       ecm, strerror ( rc ) );
		goto err_open;
	}

	/* Set packet filter */
	filter = ( ECM_PACKET_TYPE_PROMISCUOUS |
		   ECM_PACKET_TYPE_ALL_MULTICAST |
		   ECM_PACKET_TYPE_DIRECTED |
		   ECM_PACKET_TYPE_BROADCAST );
	if ( ( rc = usb_control ( usb, ECM_SET_ETHERNET_PACKET_FILTER,
				  filter, ecm->usbnet.comms, NULL, 0 ) ) != 0 ){
		DBGC ( ecm, "ECM %p could not set packet filter: %s\n",
		       ecm, strerror ( rc ) );
		goto err_set_filter;
	}

	return 0;

 err_set_filter:
	usbnet_close ( &ecm->usbnet );
 err_open:
	return rc;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
static void ecm_close ( struct net_device *netdev ) {
	struct ecm_device *ecm = netdev->priv;

	/* Close USB network device */
	usbnet_close ( &ecm->usbnet );
}

/**
 * Transmit packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int ecm_transmit ( struct net_device *netdev,
			  struct io_buffer *iobuf ) {
	struct ecm_device *ecm = netdev->priv;
	int rc;

	/* Transmit packet */
	if ( ( rc = ecm_out_transmit ( ecm, iobuf ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Poll for completed and received packets
 *
 * @v netdev		Network device
 */
static void ecm_poll ( struct net_device *netdev ) {
	struct ecm_device *ecm = netdev->priv;
	int rc;

	/* Poll USB bus */
	usb_poll ( ecm->bus );

	/* Refill endpoints */
	if ( ( rc = usbnet_refill ( &ecm->usbnet ) ) != 0 )
		netdev_rx_err ( netdev, NULL, rc );
}

/** CDC-ECM network device operations */
static struct net_device_operations ecm_operations = {
	.open		= ecm_open,
	.close		= ecm_close,
	.transmit	= ecm_transmit,
	.poll		= ecm_poll,
};

/******************************************************************************
 *
 * USB interface
 *
 ******************************************************************************
 */

/**
 * Probe device
 *
 * @v func		USB function
 * @v config		Configuration descriptor
 * @ret rc		Return status code
 */
static int ecm_probe ( struct usb_function *func,
		       struct usb_configuration_descriptor *config ) {
	struct usb_device *usb = func->usb;
	struct net_device *netdev;
	struct ecm_device *ecm;
	struct usb_interface_descriptor *comms;
	struct ecm_ethernet_descriptor *ethernet;
	int rc;

	/* Allocate and initialise structure */
	netdev = alloc_etherdev ( sizeof ( *ecm ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	netdev_init ( netdev, &ecm_operations );
	netdev->dev = &func->dev;
	ecm = netdev->priv;
	memset ( ecm, 0, sizeof ( *ecm ) );
	ecm->usb = usb;
	ecm->bus = usb->port->hub->bus;
	ecm->netdev = netdev;
	usbnet_init ( &ecm->usbnet, func, &ecm_intr_operations,
		      &ecm_in_operations, &ecm_out_operations );
	usb_refill_init ( &ecm->usbnet.intr, 0, ECM_INTR_MAX_FILL );
	usb_refill_init ( &ecm->usbnet.in, ECM_IN_MTU, ECM_IN_MAX_FILL );
	DBGC ( ecm, "ECM %p on %s\n", ecm, func->name );

	/* Describe USB network device */
	if ( ( rc = usbnet_describe ( &ecm->usbnet, config ) ) != 0 ) {
		DBGC ( ecm, "ECM %p could not describe: %s\n",
		       ecm, strerror ( rc ) );
		goto err_describe;
	}

	/* Locate Ethernet descriptor */
	comms = usb_interface_descriptor ( config, ecm->usbnet.comms, 0 );
	assert ( comms != NULL );
	ethernet = ecm_ethernet_descriptor ( config, comms );
	if ( ! ethernet ) {
		DBGC ( ecm, "ECM %p has no Ethernet descriptor\n", ecm );
		rc = -EINVAL;
		goto err_ethernet;
	}

	/* Fetch MAC address */
	if ( ( rc = ecm_fetch_mac ( usb, ethernet, netdev->hw_addr ) ) != 0 ) {
		DBGC ( ecm, "ECM %p could not fetch MAC address: %s\n",
		       ecm, strerror ( rc ) );
		goto err_fetch_mac;
	}

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register;

	usb_func_set_drvdata ( func, ecm );
	return 0;

	unregister_netdev ( netdev );
 err_register:
 err_fetch_mac:
 err_ethernet:
 err_describe:
	netdev_nullify ( netdev );
	netdev_put ( netdev );
 err_alloc:
	return rc;
}

/**
 * Remove device
 *
 * @v func		USB function
 */
static void ecm_remove ( struct usb_function *func ) {
	struct ecm_device *ecm = usb_func_get_drvdata ( func );
	struct net_device *netdev = ecm->netdev;

	unregister_netdev ( netdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/** CDC-ECM device IDs */
static struct usb_device_id ecm_ids[] = {
	{
		.name = "cdc-ecm",
		.vendor = USB_ANY_ID,
		.product = USB_ANY_ID,
		.class = {
			.class = USB_CLASS_CDC,
			.subclass = USB_SUBCLASS_CDC_ECM,
			.protocol = 0,
		},
	},
};

/** CDC-ECM driver */
struct usb_driver ecm_driver __usb_driver = {
	.ids = ecm_ids,
	.id_count = ( sizeof ( ecm_ids ) / sizeof ( ecm_ids[0] ) ),
	.probe = ecm_probe,
	.remove = ecm_remove,
};
