/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <unistd.h>
#include <errno.h>
#include <ipxe/ethernet.h>
#include <ipxe/usb.h>
#include <ipxe/usbnet.h>
#include "dm96xx.h"

/** @file
 *
 * Davicom DM96xx USB Ethernet driver
 *
 */

/******************************************************************************
 *
 * Register operations
 *
 ******************************************************************************
 */

/**
 * Reset device
 *
 * @v dm96xx		DM96xx device
 * @ret rc		Return status code
 */
static int dm96xx_reset ( struct dm96xx_device *dm96xx ) {
	int ncr;
	int rc;

	/* Reset device */
	if ( ( rc = dm96xx_write_register ( dm96xx, DM96XX_NCR,
					    DM96XX_NCR_RST ) ) != 0 ) {
		DBGC ( dm96xx, "DM96XX %p could not reset: %s\n",
		       dm96xx, strerror ( rc ) );
		return rc;
	}

	/* Wait for reset to complete */
	udelay ( DM96XX_RESET_DELAY_US );

	/* Check that reset has completed */
	ncr = dm96xx_read_register ( dm96xx, DM96XX_NCR );
	if ( ncr < 0 ) {
		rc = ncr;
		DBGC ( dm96xx, "DM96XX %p failed to reset: %s\n",
		       dm96xx, strerror ( rc ) );
		return rc;
	}
	if ( ncr & DM96XX_NCR_RST ) {
		DBGC ( dm96xx, "DM96XX %p failed to reset (NCR=%#02x)\n",
		       dm96xx, ncr );
		return -EIO;
	}

	return 0;
}

/**
 * Read MAC address
 *
 * @v dm96xx		DM96xx device
 * @v mac		MAC address to fill in
 * @ret rc		Return status code
 */
static int dm96xx_read_mac ( struct dm96xx_device *dm96xx, uint8_t *mac ) {
	int rc;

	/* Read MAC address */
	if ( ( rc = dm96xx_read_registers ( dm96xx, DM96XX_PAR, mac,
					    ETH_ALEN ) ) != 0 ) {
		DBGC ( dm96xx, "DM96XX %p could not read MAC address: %s\n",
		       dm96xx, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Write MAC address
 *
 * @v dm96xx		DM96xx device
 * @v mac		MAC address
 * @ret rc		Return status code
 */
static int dm96xx_write_mac ( struct dm96xx_device *dm96xx, uint8_t *mac ) {
	int rc;

	/* Write MAC address */
	if ( ( rc = dm96xx_write_registers ( dm96xx, DM96XX_PAR, mac,
					     ETH_ALEN ) ) != 0 ) {
		DBGC ( dm96xx, "DM96XX %p could not write MAC address: %s\n",
		       dm96xx, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/**
 * Update link status based on network status register
 *
 * @v dm96xx		DM96xx device
 * @v nsr		Network status register
 */
static void dm96xx_link_nsr ( struct dm96xx_device *dm96xx, unsigned int nsr ) {
	struct net_device *netdev = dm96xx->netdev;

	if ( nsr & DM96XX_NSR_LINKST ) {
		if ( ! netdev_link_ok ( netdev ) )
			netdev_link_up ( netdev );
	} else {
		if ( netdev_link_ok ( netdev ) )
			netdev_link_down ( netdev );
	}
}

/**
 * Get link status
 *
 * @v dm96xx		DM96xx device
 * @ret rc		Return status code
 */
static int dm96xx_check_link ( struct dm96xx_device *dm96xx ) {
	int nsr;
	int rc;

	/* Read network status register */
	nsr = dm96xx_read_register ( dm96xx, DM96XX_NSR );
	if ( nsr < 0 ) {
		rc = nsr;
		DBGC ( dm96xx, "DM96XX %p could not read network status: %s\n",
		       dm96xx, strerror ( rc ) );
		return rc;
	}

	/* Update link status */
	dm96xx_link_nsr ( dm96xx, nsr );

	return 0;
}

/**
 * Set DM9601-compatible RX header mode
 *
 * @v dm96xx		DM96xx device
 * @ret rc		Return status code
 */
static int dm96xx_rx_mode ( struct dm96xx_device *dm96xx ) {
	int chipr;
	int mode_ctl;
	int rc;

	/* Get chip revision */
	chipr = dm96xx_read_register ( dm96xx, DM96XX_CHIPR );
	if ( chipr < 0 ) {
		rc = chipr;
		DBGC ( dm96xx, "DM96XX %p could not read chip revision: %s\n",
		       dm96xx, strerror ( rc ) );
		return rc;
	}

	/* Do nothing if device is a DM9601 anyway */
	if ( chipr == DM96XX_CHIPR_9601 )
		return 0;

	/* Read current mode control */
	mode_ctl = dm96xx_read_register ( dm96xx, DM96XX_MODE_CTL );
	if ( mode_ctl < 0 ) {
		rc = mode_ctl;
		DBGC ( dm96xx, "DM96XX %p could not read mode control: %s\n",
		       dm96xx, strerror ( rc ) );
		return rc;
	}

	/* Write mode control */
	mode_ctl &= ~DM96XX_MODE_CTL_MODE;
	if ( ( rc = dm96xx_write_register ( dm96xx, DM96XX_MODE_CTL,
					    mode_ctl ) ) != 0 ) {
		DBGC ( dm96xx, "DM96XX %p could not write mode control: %s\n",
		       dm96xx, strerror ( rc ) );
		return rc;
	}

	return 0;
}

/******************************************************************************
 *
 * Endpoint operations
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
static void dm96xx_intr_complete ( struct usb_endpoint *ep,
				   struct io_buffer *iobuf, int rc ) {
	struct dm96xx_device *dm96xx = container_of ( ep, struct dm96xx_device,
						      usbnet.intr );
	struct net_device *netdev = dm96xx->netdev;
	struct dm96xx_interrupt *intr;
	size_t len = iob_len ( iobuf );

	/* Ignore packets cancelled when the endpoint closes */
	if ( ! ep->open )
		goto done;

	/* Record USB errors against the network device */
	if ( rc != 0 ) {
		DBGC ( dm96xx, "DM96XX %p interrupt failed: %s\n",
		       dm96xx, strerror ( rc ) );
		DBGC_HDA ( dm96xx, 0, iobuf->data, iob_len ( iobuf ) );
		netdev_rx_err ( netdev, NULL, rc );
		goto done;
	}

	/* Extract message header */
	if ( len < sizeof ( *intr ) ) {
		DBGC ( dm96xx, "DM96XX %p underlength interrupt:\n", dm96xx );
		DBGC_HDA ( dm96xx, 0, iobuf->data, iob_len ( iobuf ) );
		netdev_rx_err ( netdev, NULL, -EINVAL );
		goto done;
	}
	intr = iobuf->data;

	/* Update link status */
	dm96xx_link_nsr ( dm96xx, intr->nsr );

 done:
	/* Free I/O buffer */
	free_iob ( iobuf );
}

/** Interrupt endpoint operations */
static struct usb_endpoint_driver_operations dm96xx_intr_operations = {
	.complete = dm96xx_intr_complete,
};

/**
 * Complete bulk IN transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void dm96xx_in_complete ( struct usb_endpoint *ep,
				 struct io_buffer *iobuf, int rc ) {
	struct dm96xx_device *dm96xx = container_of ( ep, struct dm96xx_device,
						      usbnet.in );
	struct net_device *netdev = dm96xx->netdev;
	struct dm96xx_rx_header *header;

	/* Ignore packets cancelled when the endpoint closes */
	if ( ! ep->open ) {
		free_iob ( iobuf );
		return;
	}

	/* Record USB errors against the network device */
	if ( rc != 0 ) {
		DBGC ( dm96xx, "DM96XX %p bulk IN failed: %s\n",
		       dm96xx, strerror ( rc ) );
		goto err;
	}

	/* Sanity check */
	if ( iob_len ( iobuf ) < ( sizeof ( *header ) + 4 /* CRC */ ) ) {
		DBGC ( dm96xx, "DM96XX %p underlength bulk IN\n", dm96xx );
		DBGC_HDA ( dm96xx, 0, iobuf->data, iob_len ( iobuf ) );
		rc = -EINVAL;
		goto err;
	}

	/* Strip header and CRC */
	header = iobuf->data;
	iob_pull ( iobuf, sizeof ( *header ) );
	iob_unput ( iobuf, 4 /* CRC */ );

	/* Check status */
	if ( header->rsr & ~DM96XX_RSR_MF ) {
		DBGC ( dm96xx, "DM96XX %p receive error %02x:\n",
		       dm96xx, header->rsr );
		DBGC_HDA ( dm96xx, 0, iobuf->data, iob_len ( iobuf ) );
		rc = -EIO;
		goto err;
	}

	/* Hand off to network stack */
	netdev_rx ( netdev, iob_disown ( iobuf ) );
	return;

 err:
	/* Hand off to network stack */
	netdev_rx_err ( netdev, iob_disown ( iobuf ), rc );
}

/** Bulk IN endpoint operations */
static struct usb_endpoint_driver_operations dm96xx_in_operations = {
	.complete = dm96xx_in_complete,
};

/**
 * Transmit packet
 *
 * @v dm96xx		DM96xx device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int dm96xx_out_transmit ( struct dm96xx_device *dm96xx,
				 struct io_buffer *iobuf ) {
	struct dm96xx_tx_header *header;
	size_t len = iob_len ( iobuf );
	int rc;

	/* Prepend header */
	if ( ( rc = iob_ensure_headroom ( iobuf, sizeof ( *header ) ) ) != 0 )
		return rc;
	header = iob_push ( iobuf, sizeof ( *header ) );
	header->len = cpu_to_le16 ( len );

	/* Enqueue I/O buffer */
	if ( ( rc = usb_stream ( &dm96xx->usbnet.out, iobuf, 0 ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Complete bulk OUT transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void dm96xx_out_complete ( struct usb_endpoint *ep,
				  struct io_buffer *iobuf, int rc ) {
	struct dm96xx_device *dm96xx = container_of ( ep, struct dm96xx_device,
						      usbnet.out );
	struct net_device *netdev = dm96xx->netdev;

	/* Report TX completion */
	netdev_tx_complete_err ( netdev, iobuf, rc );
}

/** Bulk OUT endpoint operations */
static struct usb_endpoint_driver_operations dm96xx_out_operations = {
	.complete = dm96xx_out_complete,
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
static int dm96xx_open ( struct net_device *netdev ) {
	struct dm96xx_device *dm96xx = netdev->priv;
	unsigned int rcr;
	int rc;

	/* Set DM9601-compatible RX header mode */
	if ( ( rc = dm96xx_rx_mode ( dm96xx ) ) != 0 )
		goto err_rx_mode;

	/* Write MAC address */
	if ( ( rc = dm96xx_write_mac ( dm96xx, netdev->ll_addr ) ) != 0 )
		goto err_write_mac;

	/* Open USB network device */
	if ( ( rc = usbnet_open ( &dm96xx->usbnet ) ) != 0 ) {
		DBGC ( dm96xx, "DM96XX %p could not open: %s\n",
		       dm96xx, strerror ( rc ) );
		goto err_open;
	}

	/* Set receive filters */
	rcr = ( DM96XX_RCR_ALL | DM96XX_RCR_RUNT | DM96XX_RCR_PRMSC |
		DM96XX_RCR_RXEN );
	if ( ( rc = dm96xx_write_register ( dm96xx, DM96XX_RCR, rcr ) ) != 0 ) {
		DBGC ( dm96xx, "DM96XX %p could not write receive filters: "
		       "%s\n", dm96xx, strerror ( rc ) );
		goto err_write_rcr;
	}

	/* Update link status */
	if ( ( rc = dm96xx_check_link ( dm96xx ) ) != 0 )
		goto err_check_link;

	return 0;

 err_check_link:
 err_write_rcr:
	usbnet_close ( &dm96xx->usbnet );
 err_open:
 err_write_mac:
 err_rx_mode:
	return rc;
}

/**
 * Close network device
 *
 * @v netdev		Network device
 */
static void dm96xx_close ( struct net_device *netdev ) {
	struct dm96xx_device *dm96xx = netdev->priv;

	/* Close USB network device */
	usbnet_close ( &dm96xx->usbnet );

	/* Reset device */
	dm96xx_reset ( dm96xx );
}

/**
 * Transmit packet
 *
 * @v netdev		Network device
 * @v iobuf		I/O buffer
 * @ret rc		Return status code
 */
static int dm96xx_transmit ( struct net_device *netdev,
			     struct io_buffer *iobuf ) {
	struct dm96xx_device *dm96xx = netdev->priv;
	int rc;

	/* Transmit packet */
	if ( ( rc = dm96xx_out_transmit ( dm96xx, iobuf ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Poll for completed and received packets
 *
 * @v netdev		Network device
 */
static void dm96xx_poll ( struct net_device *netdev ) {
	struct dm96xx_device *dm96xx = netdev->priv;
	int rc;

	/* Poll USB bus */
	usb_poll ( dm96xx->bus );

	/* Refill endpoints */
	if ( ( rc = usbnet_refill ( &dm96xx->usbnet ) ) != 0 )
		netdev_rx_err ( netdev, NULL, rc );
}

/** DM96xx network device operations */
static struct net_device_operations dm96xx_operations = {
	.open		= dm96xx_open,
	.close		= dm96xx_close,
	.transmit	= dm96xx_transmit,
	.poll		= dm96xx_poll,
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
static int dm96xx_probe ( struct usb_function *func,
		       struct usb_configuration_descriptor *config ) {
	struct usb_device *usb = func->usb;
	struct net_device *netdev;
	struct dm96xx_device *dm96xx;
	int rc;

	/* Allocate and initialise structure */
	netdev = alloc_etherdev ( sizeof ( *dm96xx ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	netdev_init ( netdev, &dm96xx_operations );
	netdev->dev = &func->dev;
	dm96xx = netdev->priv;
	memset ( dm96xx, 0, sizeof ( *dm96xx ) );
	dm96xx->usb = usb;
	dm96xx->bus = usb->port->hub->bus;
	dm96xx->netdev = netdev;
	usbnet_init ( &dm96xx->usbnet, func, &dm96xx_intr_operations,
		      &dm96xx_in_operations, &dm96xx_out_operations );
	usb_refill_init ( &dm96xx->usbnet.intr, 0, DM96XX_INTR_MAX_FILL );
	usb_refill_init ( &dm96xx->usbnet.in, DM96XX_IN_MTU,
			  DM96XX_IN_MAX_FILL );
	DBGC ( dm96xx, "DM96XX %p on %s\n", dm96xx, func->name );

	/* Describe USB network device */
	if ( ( rc = usbnet_describe ( &dm96xx->usbnet, config ) ) != 0 ) {
		DBGC ( dm96xx, "DM96XX %p could not describe: %s\n",
		       dm96xx, strerror ( rc ) );
		goto err_describe;
	}

	/* Reset device */
	if ( ( rc = dm96xx_reset ( dm96xx ) ) != 0 )
		goto err_reset;

	/* Read MAC address */
	if ( ( rc = dm96xx_read_mac ( dm96xx, netdev->hw_addr ) ) != 0 )
		goto err_read_mac;

	/* Get initial link status */
	if ( ( rc = dm96xx_check_link ( dm96xx ) ) != 0 )
		goto err_check_link;

	/* Register network device */
	if ( ( rc = register_netdev ( netdev ) ) != 0 )
		goto err_register;

	usb_func_set_drvdata ( func, netdev );
	return 0;

	unregister_netdev ( netdev );
 err_register:
 err_check_link:
 err_read_mac:
 err_reset:
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
static void dm96xx_remove ( struct usb_function *func ) {
	struct net_device *netdev = usb_func_get_drvdata ( func );

	unregister_netdev ( netdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

/** DM96xx device IDs */
static struct usb_device_id dm96xx_ids[] = {
	{
		.name = "dm9601-corega",
		.vendor = 0x07aa,
		.product = 0x9601,
	},
	{
		.name = "dm9601",
		.vendor = 0x0a46,
		.product = 0x9601,
	},
	{
		.name = "zt6688",
		.vendor = 0x0a46,
		.product = 0x6688,
	},
	{
		.name = "st268",
		.vendor = 0x0a46,
		.product = 0x0268,
	},
	{
		.name = "adm8515",
		.vendor = 0x0a46,
		.product = 0x8515,
	},
	{
		.name = "dm9601-hirose",
		.vendor = 0x0a47,
		.product = 0x9601,
	},
	{
		.name = "dm9601-8101",
		.vendor = 0x0fe6,
		.product = 0x8101,
	},
	{
		.name = "dm9601-9700",
		.vendor = 0x0fe6,
		.product = 0x9700,
	},
	{
		.name = "dm9000e",
		.vendor = 0x0a46,
		.product = 0x9000,
	},
	{
		.name = "dm9620",
		.vendor = 0x0a46,
		.product = 0x9620,
	},
	{
		.name = "dm9621A",
		.vendor = 0x0a46,
		.product = 0x9621,
	},
	{
		.name = "dm9622",
		.vendor = 0x0a46,
		.product = 0x9622,
	},
	{
		.name = "dm962Oa",
		.vendor = 0x0a46,
		.product = 0x0269,
	},
	{
		.name = "dm9621a",
		.vendor = 0x0a46,
		.product = 0x1269,
	},
};

/** Davicom DM96xx driver */
struct usb_driver dm96xx_driver __usb_driver = {
	.ids = dm96xx_ids,
	.id_count = ( sizeof ( dm96xx_ids ) / sizeof ( dm96xx_ids[0] ) ),
	.probe = dm96xx_probe,
	.remove = dm96xx_remove,
};
