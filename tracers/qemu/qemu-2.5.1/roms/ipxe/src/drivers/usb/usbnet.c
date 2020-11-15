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
#include <errno.h>
#include <ipxe/usb.h>
#include <ipxe/usbnet.h>

/** @file
 *
 * USB network devices
 *
 * USB network devices use a variety of packet formats and interface
 * descriptors, but tend to have several features in common:
 *
 *  - a single interrupt endpoint using the generic refill mechanism
 *
 *  - a single bulk IN endpoint using the generic refill mechanism
 *
 *  - a single bulk OUT endpoint
 *
 *  - optional use of an alternate setting to enable the data interface
 *
 */

/**
 * Open USB network device
 *
 * @v usbnet		USB network device
 * @ret rc		Return status code
 */
int usbnet_open ( struct usbnet_device *usbnet ) {
	struct usb_device *usb = usbnet->func->usb;
	int rc;

	/* Open interrupt endpoint */
	if ( ( rc = usb_endpoint_open ( &usbnet->intr ) ) != 0 ) {
		DBGC ( usbnet, "USBNET %s could not open interrupt: %s\n",
		       usbnet->func->name, strerror ( rc ) );
		goto err_open_intr;
	}

	/* Refill interrupt endpoint */
	if ( ( rc = usb_refill ( &usbnet->intr ) ) != 0 ) {
		DBGC ( usbnet, "USBNET %s could not refill interrupt: %s\n",
		       usbnet->func->name, strerror ( rc ) );
		goto err_refill_intr;
	}

	/* Select alternate setting for data interface, if applicable */
	if ( usbnet->alternate &&
	     ( ( rc = usb_set_interface ( usb, usbnet->data,
					  usbnet->alternate ) ) != 0 ) ) {
		DBGC ( usbnet, "USBNET %s could not set alternate interface "
		       "%d: %s\n", usbnet->func->name, usbnet->alternate,
		       strerror ( rc ) );
		goto err_set_interface;
	}

	/* Open bulk IN endpoint */
	if ( ( rc = usb_endpoint_open ( &usbnet->in ) ) != 0 ) {
		DBGC ( usbnet, "USBNET %s could not open bulk IN: %s\n",
		       usbnet->func->name, strerror ( rc ) );
		goto err_open_in;
	}

	/* Open bulk OUT endpoint */
	if ( ( rc = usb_endpoint_open ( &usbnet->out ) ) != 0 ) {
		DBGC ( usbnet, "USBNET %s could not open bulk OUT: %s\n",
		       usbnet->func->name, strerror ( rc ) );
		goto err_open_out;
	}

	/* Refill bulk IN endpoint */
	if ( ( rc = usb_refill ( &usbnet->in ) ) != 0 ) {
		DBGC ( usbnet, "USBNET %s could not refill bulk IN: %s\n",
		       usbnet->func->name, strerror ( rc ) );
		goto err_refill_in;
	}

	return 0;

 err_refill_in:
	usb_endpoint_close ( &usbnet->out );
 err_open_out:
	usb_endpoint_close ( &usbnet->in );
 err_open_in:
	if ( usbnet->alternate )
		usb_set_interface ( usb, usbnet->data, 0 );
 err_set_interface:
 err_refill_intr:
	usb_endpoint_close ( &usbnet->intr );
 err_open_intr:
	return rc;
}

/**
 * Close USB network device
 *
 * @v usbnet		USB network device
 */
void usbnet_close ( struct usbnet_device *usbnet ) {
	struct usb_device *usb = usbnet->func->usb;

	/* Close bulk OUT endpoint */
	usb_endpoint_close ( &usbnet->out );

	/* Close bulk IN endpoint */
	usb_endpoint_close ( &usbnet->in );

	/* Reset alternate setting for data interface, if applicable */
	if ( usbnet->alternate )
		usb_set_interface ( usb, usbnet->data, 0 );

	/* Close interrupt endpoint */
	usb_endpoint_close ( &usbnet->intr );
}

/**
 * Refill USB network device bulk IN and interrupt endpoints
 *
 * @v usbnet		USB network device
 * @ret rc		Return status code
 */
int usbnet_refill ( struct usbnet_device *usbnet ) {
	int rc;

	/* Refill bulk IN endpoint */
	if ( ( rc = usb_refill ( &usbnet->in ) ) != 0 )
		return rc;

	/* Refill interrupt endpoint */
	if ( ( rc = usb_refill ( &usbnet->intr ) ) != 0 )
		return rc;

	return 0;
}

/**
 * Describe communications interface and interrupt endpoint
 *
 * @v usbnet		USB network device
 * @v config		Configuration descriptor
 * @ret rc		Return status code
 */
static int usbnet_comms_describe ( struct usbnet_device *usbnet,
				   struct usb_configuration_descriptor *config){
	struct usb_interface_descriptor *desc;
	unsigned int comms;
	unsigned int i;
	int rc;

	/* Iterate over all available interfaces */
	for ( i = 0 ; i < usbnet->func->count ; i++ ) {

		/* Get interface number */
		comms = usbnet->func->interface[i];

		/* Locate interface descriptor */
		desc = usb_interface_descriptor ( config, comms, 0 );
		if ( ! desc )
			continue;

		/* Describe interrupt endpoint */
		if ( ( rc = usb_endpoint_described ( &usbnet->intr, config,
						     desc, USB_INTERRUPT_IN,
						     0 ) ) != 0 )
			continue;

		/* Record communications interface */
		usbnet->comms = comms;
		DBGC ( usbnet, "USBNET %s found communications interface %d\n",
		       usbnet->func->name, comms );
		return 0;
	}

	DBGC ( usbnet, "USBNET %s found no communications interface\n",
	       usbnet->func->name );
	return -ENOENT;
}

/**
 * Describe data interface and bulk endpoints
 *
 * @v usbnet		USB network device
 * @v config		Configuration descriptor
 * @ret rc		Return status code
 */
static int usbnet_data_describe ( struct usbnet_device *usbnet,
				  struct usb_configuration_descriptor *config ){
	struct usb_interface_descriptor *desc;
	unsigned int data;
	unsigned int alt;
	unsigned int i;
	int rc;

	/* Iterate over all available interfaces */
	for ( i = 0 ; i < usbnet->func->count ; i++ ) {

		/* Get interface number */
		data = usbnet->func->interface[i];

		/* Iterate over all existent alternate settings */
		for ( alt = 0 ; ; alt++ ) {

			/* Locate interface descriptor */
			desc = usb_interface_descriptor ( config, data, alt );
			if ( ! desc )
				break;

			/* Describe bulk IN endpoint */
			if ( ( rc = usb_endpoint_described ( &usbnet->in,
							     config, desc,
							     USB_BULK_IN,
							     0 ) ) != 0 )
				continue;

			/* Describe bulk OUT endpoint */
			if ( ( rc = usb_endpoint_described ( &usbnet->out,
							     config, desc,
							     USB_BULK_OUT,
							     0 ) ) != 0 )
				continue;

			/* Record data interface and alternate setting */
			usbnet->data = data;
			usbnet->alternate = alt;
			DBGC ( usbnet, "USBNET %s found data interface %d",
			       usbnet->func->name, data );
			if ( alt )
				DBGC ( usbnet, " using alternate %d", alt );
			DBGC ( usbnet, "\n" );
			return 0;
		}
	}

	DBGC ( usbnet, "USBNET %s found no data interface\n",
	       usbnet->func->name );
	return -ENOENT;
}

/**
 * Describe USB network device interfaces
 *
 * @v usbnet		USB network device
 * @v config		Configuration descriptor
 * @ret rc		Return status code
 */
int usbnet_describe ( struct usbnet_device *usbnet,
		      struct usb_configuration_descriptor *config ) {
	int rc;

	/* Describe communications interface */
	if ( ( rc = usbnet_comms_describe ( usbnet, config ) ) != 0 )
		return rc;

	/* Describe data interface */
	if ( ( rc = usbnet_data_describe ( usbnet, config ) ) != 0 )
		return rc;

	return 0;
}
