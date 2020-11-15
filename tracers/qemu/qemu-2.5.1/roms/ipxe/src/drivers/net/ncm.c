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

#include <string.h>
#include <errno.h>
#include <ipxe/netdevice.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/profile.h>
#include <ipxe/usb.h>
#include <ipxe/usbnet.h>
#include "ecm.h"
#include "ncm.h"

/** @file
 *
 * CDC-NCM USB Ethernet driver
 *
 */

/** Interrupt completion profiler */
static struct profiler ncm_intr_profiler __profiler =
	{ .name = "ncm.intr" };

/** Bulk IN completion profiler */
static struct profiler ncm_in_profiler __profiler =
	{ .name = "ncm.in" };

/** Bulk IN per-datagram profiler */
static struct profiler ncm_in_datagram_profiler __profiler =
	{ .name = "ncm.in_dgram" };

/** Bulk OUT profiler */
static struct profiler ncm_out_profiler __profiler =
	{ .name = "ncm.out" };

/******************************************************************************
 *
 * CDC-NCM communications interface
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
static void ncm_intr_complete ( struct usb_endpoint *ep,
				struct io_buffer *iobuf, int rc ) {
	struct ncm_device *ncm = container_of ( ep, struct ncm_device,
						usbnet.intr );
	struct net_device *netdev = ncm->netdev;
	struct usb_setup_packet *message;
	size_t len = iob_len ( iobuf );

	/* Profile completions */
	profile_start ( &ncm_intr_profiler );

	/* Ignore packets cancelled when the endpoint closes */
	if ( ! ep->open )
		goto ignore;

	/* Ignore packets with errors */
	if ( rc != 0 ) {
		DBGC ( ncm, "NCM %p interrupt failed: %s\n",
		       ncm, strerror ( rc ) );
		DBGC_HDA ( ncm, 0, iobuf->data, iob_len ( iobuf ) );
		goto error;
	}

	/* Extract message header */
	if ( len < sizeof ( *message ) ) {
		DBGC ( ncm, "NCM %p underlength interrupt:\n", ncm );
		DBGC_HDA ( ncm, 0, iobuf->data, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto error;
	}
	message = iobuf->data;

	/* Parse message header */
	switch ( message->request ) {

	case cpu_to_le16 ( CDC_NETWORK_CONNECTION ) :
		if ( message->value ) {
			DBGC ( ncm, "NCM %p link up\n", ncm );
			netdev_link_up ( netdev );
		} else {
			DBGC ( ncm, "NCM %p link down\n", ncm );
			netdev_link_down ( netdev );
		}
		break;

	case cpu_to_le16 ( CDC_CONNECTION_SPEED_CHANGE ) :
		/* Ignore */
		break;

	default:
		DBGC ( ncm, "NCM %p unrecognised interrupt:\n", ncm );
		DBGC_HDA ( ncm, 0, iobuf->data, iob_len ( iobuf ) );
		goto error;
	}

	/* Free I/O buffer */
	free_iob ( iobuf );
	profile_stop ( &ncm_intr_profiler );

	return;

 error:
	netdev_rx_err ( netdev, iob_disown ( iobuf ), rc );
 ignore:
	free_iob ( iobuf );
	return;
}

/** Interrupt endpoint operations */
static struct usb_endpoint_driver_operations ncm_intr_operations = {
	.complete = ncm_intr_complete,
};

/******************************************************************************
 *
 * CDC-NCM data interface
 *
 ******************************************************************************
 */

/**
 * Prefill bulk IN endpoint
 *
 * @v ncm		CDC-NCM device
 * @ret rc		Return status code
 */
static int ncm_in_prefill ( struct ncm_device *ncm ) {
	struct usb_bus *bus = ncm->bus;
	size_t mtu;
	unsigned int count;
	int rc;

	/* Some devices have a very small number of internal buffers,
	 * and rely on being able to pack multiple packets into each
	 * buffer.  We therefore want to use large buffers if
	 * possible.  However, large allocations have a reasonable
	 * chance of failure, especially if this is not the first or
	 * only device to be opened.
	 *
	 * We therefore attempt to find a usable buffer size, starting
	 * large and working downwards until allocation succeeds.
	 * Smaller buffers will still work, albeit with a higher
	 * chance of packet loss and so lower overall throughput.
	 */
	for ( mtu = ncm->mtu ; mtu >= NCM_MIN_NTB_INPUT_SIZE ; mtu >>= 1 ) {

		/* Attempt allocation at this MTU */
		if ( mtu > NCM_MAX_NTB_INPUT_SIZE )
			continue;
		if ( mtu > bus->mtu )
			continue;
		count = ( NCM_IN_MIN_SIZE / mtu );
		if ( count < NCM_IN_MIN_COUNT )
			count = NCM_IN_MIN_COUNT;
		if ( ( count * mtu ) > NCM_IN_MAX_SIZE )
			continue;
		usb_refill_init ( &ncm->usbnet.in, mtu, count );
		if ( ( rc = usb_prefill ( &ncm->usbnet.in ) ) != 0 ) {
			DBGC ( ncm, "NCM %p could not prefill %dx %zd-byte "
			       "buffers for bulk IN\n", ncm, count, mtu );
			continue;
		}

		DBGC ( ncm, "NCM %p using %dx %zd-byte buffers for bulk IN\n",
		       ncm, count, mtu );
		return 0;
	}

	DBGC ( ncm, "NCM %p could not prefill bulk IN endpoint\n", ncm );
	return -ENOMEM;
}

/**
 * Complete bulk IN transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void ncm_in_complete ( struct usb_endpoint *ep, struct io_buffer *iobuf,
			      int rc ) {
	struct ncm_device *ncm = container_of ( ep, struct ncm_device,
						usbnet.in );
	struct net_device *netdev = ncm->netdev;
	struct ncm_transfer_header *nth;
	struct ncm_datagram_pointer *ndp;
	struct ncm_datagram_descriptor *desc;
	struct io_buffer *pkt;
	unsigned int remaining;
	size_t ndp_offset;
	size_t ndp_len;
	size_t pkt_offset;
	size_t pkt_len;
	size_t headroom;
	size_t len;

	/* Profile overall bulk IN completion */
	profile_start ( &ncm_in_profiler );

	/* Ignore packets cancelled when the endpoint closes */
	if ( ! ep->open )
		goto ignore;

	/* Record USB errors against the network device */
	if ( rc != 0 ) {
		DBGC ( ncm, "NCM %p bulk IN failed: %s\n",
		       ncm, strerror ( rc ) );
		goto error;
	}

	/* Locate transfer header */
	len = iob_len ( iobuf );
	if ( sizeof ( *nth ) > len ) {
		DBGC ( ncm, "NCM %p packet too short for NTH:\n", ncm );
		rc = -EINVAL;
		goto error;
	}
	nth = iobuf->data;

	/* Locate datagram pointer */
	ndp_offset = le16_to_cpu ( nth->offset );
	if ( ( ndp_offset + sizeof ( *ndp ) ) > len ) {
		DBGC ( ncm, "NCM %p packet too short for NDP:\n", ncm );
		rc = -EINVAL;
		goto error;
	}
	ndp = ( iobuf->data + ndp_offset );
	ndp_len = le16_to_cpu ( ndp->header_len );
	if ( ndp_len < offsetof ( typeof ( *ndp ), desc ) ) {
		DBGC ( ncm, "NCM %p NDP header length too short:\n", ncm );
		rc = -EINVAL;
		goto error;
	}
	if ( ( ndp_offset + ndp_len ) > len ) {
		DBGC ( ncm, "NCM %p packet too short for NDP:\n", ncm );
		rc = -EINVAL;
		goto error;
	}

	/* Process datagrams */
	remaining = ( ( ndp_len - offsetof ( typeof ( *ndp ), desc ) ) /
		      sizeof ( ndp->desc[0] ) );
	for ( desc = ndp->desc ; remaining && desc->offset ; remaining-- ) {

		/* Profile individual datagrams */
		profile_start ( &ncm_in_datagram_profiler );

		/* Locate datagram */
		pkt_offset = le16_to_cpu ( desc->offset );
		pkt_len = le16_to_cpu ( desc->len );
		if ( pkt_len < ETH_HLEN ) {
			DBGC ( ncm, "NCM %p underlength datagram:\n", ncm );
			rc = -EINVAL;
			goto error;
		}
		if ( ( pkt_offset + pkt_len ) > len ) {
			DBGC ( ncm, "NCM %p datagram exceeds packet:\n", ncm );
			rc = -EINVAL;
			goto error;
		}

		/* Move to next descriptor */
		desc++;

		/* Copy data to a new I/O buffer.  Our USB buffers may
		 * be very large and so we choose to recycle the
		 * buffers directly rather than attempt reallocation
		 * while the device is running.  We therefore copy the
		 * data to a new I/O buffer even if this is the only
		 * (or last) packet within the buffer.
		 *
		 * We reserve enough space at the start of each buffer
		 * to allow for our own transmission header, to
		 * support protocols such as ARP which may modify the
		 * received packet and reuse the same I/O buffer for
		 * transmission.
		 */
		headroom = ( sizeof ( struct ncm_ntb_header ) + ncm->padding );
		pkt = alloc_iob ( headroom + pkt_len );
		if ( ! pkt ) {
			/* Record error and continue */
			netdev_rx_err ( netdev, NULL, -ENOMEM );
			continue;
		}
		iob_reserve ( pkt, headroom );
		memcpy ( iob_put ( pkt, pkt_len ),
			 ( iobuf->data + pkt_offset ), pkt_len );

		/* Strip CRC, if present */
		if ( ndp->magic & cpu_to_le32 ( NCM_DATAGRAM_POINTER_MAGIC_CRC))
			iob_unput ( pkt, 4 /* CRC32 */ );

		/* Hand off to network stack */
		netdev_rx ( netdev, pkt );
		profile_stop ( &ncm_in_datagram_profiler );
	}

	/* Recycle I/O buffer */
	usb_recycle ( &ncm->usbnet.in, iobuf );
	profile_stop ( &ncm_in_profiler );

	return;

 error:
	/* Record error against network device */
	DBGC_HDA ( ncm, 0, iobuf->data, iob_len ( iobuf ) );
	netdev_rx_err ( netdev, NULL, rc );
 ignore:
	usb_recycle ( &ncm->usbnet.in, iobuf );
}

/** Bulk IN endpoint operations */
static struct usb_endpoint_driver_operations ncm_in_operations = {
	.complete = ncm_in_complete,
};

/**
 * Transmit packet
 *
 * @v ncm		CDC-NCM device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int ncm_out_transmit ( struct ncm_device *ncm,
			      struct io_buffer *iobuf ) {
	struct ncm_ntb_header *header;
	size_t len = iob_len ( iobuf );
	size_t header_len = ( sizeof ( *header ) + ncm->padding );
	int rc;

	/* Profile transmissions */
	profile_start ( &ncm_out_profiler );

	/* Prepend header */
	if ( ( rc = iob_ensure_headroom ( iobuf, header_len ) ) != 0 )
		return rc;
	header = iob_push ( iobuf, header_len );

	/* Populate header */
	header->nth.magic = cpu_to_le32 ( NCM_TRANSFER_HEADER_MAGIC );
	header->nth.header_len = cpu_to_le16 ( sizeof ( header->nth ) );
	header->nth.sequence = cpu_to_le16 ( ncm->sequence );
	header->nth.len = cpu_to_le16 ( iob_len ( iobuf ) );
	header->nth.offset =
		cpu_to_le16 ( offsetof ( typeof ( *header ), ndp ) );
	header->ndp.magic = cpu_to_le32 ( NCM_DATAGRAM_POINTER_MAGIC );
	header->ndp.header_len = cpu_to_le16 ( sizeof ( header->ndp ) +
					       sizeof ( header->desc ) );
	header->ndp.offset = cpu_to_le16 ( 0 );
	header->desc[0].offset = cpu_to_le16 ( header_len );
	header->desc[0].len = cpu_to_le16 ( len );
	memset ( &header->desc[1], 0, sizeof ( header->desc[1] ) );

	/* Enqueue I/O buffer */
	if ( ( rc = usb_stream ( &ncm->usbnet.out, iobuf, 0 ) ) != 0 )
		return rc;

	/* Increment sequence number */
	ncm->sequence++;

	profile_stop ( &ncm_out_profiler );
	return 0;
}

/**
 * Complete bulk OUT transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void ncm_out_complete ( struct usb_endpoint *ep, struct io_buffer *iobuf,
			       int rc ) {
	struct ncm_device *ncm = container_of ( ep, struct ncm_device,
						usbnet.out );
	struct net_device *netdev = ncm->netdev;

	/* Report TX completion */
	netdev_tx_complete_err ( netdev, iobuf, rc );
}

/** Bulk OUT endpoint operations */
static struct usb_endpoint_driver_operations ncm_out_operations = {
	.complete = ncm_out_complete,
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
static int ncm_open ( struct net_device *netdev ) {
	struct ncm_device *ncm = netdev->priv;
	struct usb_device *usb = ncm->usb;
	struct ncm_set_ntb_input_size size;
	int rc;

	/* Reset sequence number */
	ncm->sequence = 0;

	/* Prefill I/O buffers */
	if ( ( rc = ncm_in_prefill ( ncm ) ) != 0 )
		goto err_prefill;

	/* Set maximum input size */
	memset ( &size, 0, sizeof ( size ) );
	size.mtu = cpu_to_le32 ( ncm->usbnet.in.len );
	if ( ( rc = usb_control ( usb, NCM_SET_NTB_INPUT_SIZE, 0,
				  ncm->usbnet.comms, &size,
				  sizeof ( size ) ) ) != 0 ) {
		DBGC ( ncm, "NCM %p could not set input size to %zd: %s\n",
		       ncm, ncm->usbnet.in.len, strerror ( rc ) );
		goto err_set_ntb_input_size;
	}

	/* Open USB network device */
	if ( ( rc = usbnet_open ( &ncm->usbnet ) ) != 0 ) {
		DBGC ( ncm, "NCM %p could not open: %s\n",
		       ncm, strerror ( rc ) );
		goto err_open;
	}

	return 0;

	usbnet_close ( &ncm->usbnet );
 err_open:
 err_set_ntb_input_size:
	usb_flush ( &ncm->usbnet.in );
 err_prefill:
	return rc;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
static void ncm_close ( struct net_device *netdev ) {
	struct ncm_device *ncm = netdev->priv;

	/* Close USB network device */
	usbnet_close ( &ncm->usbnet );
}

/**
 * Transmit packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int ncm_transmit ( struct net_device *netdev,
			  struct io_buffer *iobuf ) {
	struct ncm_device *ncm = netdev->priv;
	int rc;

	/* Transmit packet */
	if ( ( rc = ncm_out_transmit ( ncm, iobuf ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Poll for completed and received packets
 *
 * @v netdev		Network device
 */
static void ncm_poll ( struct net_device *netdev ) {
	struct ncm_device *ncm = netdev->priv;
	int rc;

	/* Poll USB bus */
	usb_poll ( ncm->bus );

	/* Refill endpoints */
	if ( ( rc = usbnet_refill ( &ncm->usbnet ) ) != 0 )
		netdev_rx_err ( netdev, NULL, rc );

}

/** CDC-NCM network device operations */
static struct net_device_operations ncm_operations = {
	.open		= ncm_open,
	.close		= ncm_close,
	.transmit	= ncm_transmit,
	.poll		= ncm_poll,
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
static int ncm_probe ( struct usb_function *func,
		       struct usb_configuration_descriptor *config ) {
	struct usb_device *usb = func->usb;
	struct net_device *netdev;
	struct ncm_device *ncm;
	struct usb_interface_descriptor *comms;
	struct ecm_ethernet_descriptor *ethernet;
	struct ncm_ntb_parameters params;
	int rc;

	/* Allocate and initialise structure */
	netdev = alloc_etherdev ( sizeof ( *ncm ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	netdev_init ( netdev, &ncm_operations );
	netdev->dev = &func->dev;
	ncm = netdev->priv;
	memset ( ncm, 0, sizeof ( *ncm ) );
	ncm->usb = usb;
	ncm->bus = usb->port->hub->bus;
	ncm->netdev = netdev;
	usbnet_init ( &ncm->usbnet, func, &ncm_intr_operations,
		      &ncm_in_operations, &ncm_out_operations );
	usb_refill_init ( &ncm->usbnet.intr, 0, NCM_INTR_COUNT );
	DBGC ( ncm, "NCM %p on %s\n", ncm, func->name );

	/* Describe USB network device */
	if ( ( rc = usbnet_describe ( &ncm->usbnet, config ) ) != 0 ) {
		DBGC ( ncm, "NCM %p could not describe: %s\n",
		       ncm, strerror ( rc ) );
		goto err_describe;
	}

	/* Locate Ethernet descriptor */
	comms = usb_interface_descriptor ( config, ncm->usbnet.comms, 0 );
	assert ( comms != NULL );
	ethernet = ecm_ethernet_descriptor ( config, comms );
	if ( ! ethernet ) {
		DBGC ( ncm, "NCM %p has no Ethernet descriptor\n", ncm );
		rc = -EINVAL;
		goto err_ethernet;
	}

	/* Fetch MAC address */
	if ( ( rc = ecm_fetch_mac ( usb, ethernet, netdev->hw_addr ) ) != 0 ) {
		DBGC ( ncm, "NCM %p could not fetch MAC address: %s\n",
		       ncm, strerror ( rc ) );
		goto err_fetch_mac;
	}

	/* Get NTB parameters */
	if ( ( rc = usb_control ( usb, NCM_GET_NTB_PARAMETERS, 0,
				  ncm->usbnet.comms, &params,
				  sizeof ( params ) ) ) != 0 ) {
		DBGC ( ncm, "NCM %p could not get NTB parameters: %s\n",
		       ncm, strerror ( rc ) );
		goto err_ntb_parameters;
	}

	/* Get maximum supported input size */
	ncm->mtu = le32_to_cpu ( params.in.mtu );
	DBGC2 ( ncm, "NCM %p maximum IN size is %zd bytes\n", ncm, ncm->mtu );

	/* Calculate transmit padding */
	ncm->padding = ( ( le16_to_cpu ( params.out.remainder ) -
			   sizeof ( struct ncm_ntb_header ) - ETH_HLEN ) &
			 ( le16_to_cpu ( params.out.divisor ) - 1 ) );
	DBGC2 ( ncm, "NCM %p using %zd-byte transmit padding\n",
		ncm, ncm->padding );
	assert ( ( ( sizeof ( struct ncm_ntb_header ) + ncm->padding +
		     ETH_HLEN ) % le16_to_cpu ( params.out.divisor ) ) ==
		 le16_to_cpu ( params.out.remainder ) );

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register;

	usb_func_set_drvdata ( func, ncm );
	return 0;

	unregister_netdev ( netdev );
 err_register:
 err_ntb_parameters:
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
static void ncm_remove ( struct usb_function *func ) {
	struct ncm_device *ncm = usb_func_get_drvdata ( func );
	struct net_device *netdev = ncm->netdev;

	unregister_netdev ( netdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/** CDC-NCM device IDs */
static struct usb_device_id ncm_ids[] = {
	{
		.name = "cdc-ncm",
		.vendor = USB_ANY_ID,
		.product = USB_ANY_ID,
		.class = {
			.class = USB_CLASS_CDC,
			.subclass = USB_SUBCLASS_CDC_NCM,
			.protocol = 0,
		},
	},
};

/** CDC-NCM driver */
struct usb_driver ncm_driver __usb_driver = {
	.ids = ncm_ids,
	.id_count = ( sizeof ( ncm_ids ) / sizeof ( ncm_ids[0] ) ),
	.probe = ncm_probe,
	.remove = ncm_remove,
};
