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
#include <ipxe/usbhid.h>

/** @file
 *
 * USB human interface devices (HID)
 *
 */

/**
 * Open USB human interface device
 *
 * @v hid		USB human interface device
 * @ret rc		Return status code
 */
int usbhid_open ( struct usb_hid *hid ) {
	int rc;

	/* Open interrupt IN endpoint */
	if ( ( rc = usb_endpoint_open ( &hid->in ) ) != 0 ) {
		DBGC ( hid, "HID %s could not open interrupt IN: %s\n",
		       hid->func->name, strerror ( rc ) );
		goto err_open_in;
	}

	/* Refill interrupt IN endpoint */
	if ( ( rc = usb_refill ( &hid->in ) ) != 0 ) {
		DBGC ( hid, "HID %s could not refill interrupt IN: %s\n",
		       hid->func->name, strerror ( rc ) );
		goto err_refill_in;
	}

	/* Open interrupt OUT endpoint, if applicable */
	if ( hid->out.usb &&
	     ( ( rc = usb_endpoint_open ( &hid->out ) ) != 0 ) ) {
		DBGC ( hid, "HID %s could not open interrupt OUT: %s\n",
		       hid->func->name, strerror ( rc ) );
		goto err_open_out;
	}

	return 0;

	usb_endpoint_close ( &hid->out );
 err_open_out:
 err_refill_in:
	usb_endpoint_close ( &hid->in );
 err_open_in:
	return rc;
}

/**
 * Close USB human interface device
 *
 * @v hid		USB human interface device
 */
void usbhid_close ( struct usb_hid *hid ) {

	/* Close interrupt OUT endpoint, if applicable */
	if ( hid->out.usb )
		usb_endpoint_close ( &hid->out );

	/* Close interrupt IN endpoint */
	usb_endpoint_close ( &hid->in );
}

/**
 * Refill USB human interface device endpoints
 *
 * @v hid		USB human interface device
 * @ret rc		Return status code
 */
int usbhid_refill ( struct usb_hid *hid ) {
	int rc;

	/* Refill interrupt IN endpoint */
	if ( ( rc = usb_refill ( &hid->in ) ) != 0 )
		return rc;

	/* Refill interrupt OUT endpoint, if applicable */
	if ( hid->out.usb && ( ( rc = usb_refill ( &hid->out ) ) != 0 ) )
		return rc;

	return 0;
}

/**
 * Describe USB human interface device
 *
 * @v hid		USB human interface device
 * @v config		Configuration descriptor
 * @ret rc		Return status code
 */
int usbhid_describe ( struct usb_hid *hid,
		      struct usb_configuration_descriptor *config ) {
	struct usb_interface_descriptor *desc;
	int rc;

	/* Locate interface descriptor */
	desc = usb_interface_descriptor ( config, hid->func->interface[0], 0 );
	if ( ! desc ) {
		DBGC ( hid, "HID %s has no interface descriptor\n",
		       hid->func->name );
		return -EINVAL;
	}

	/* Describe interrupt IN endpoint */
	if ( ( rc = usb_endpoint_described ( &hid->in, config, desc,
					     USB_INTERRUPT_IN, 0 ) ) != 0 ) {
		DBGC ( hid, "HID %s could not describe interrupt IN: %s\n",
		       hid->func->name, strerror ( rc ) );
		return rc;
	}

	/* Describe interrupt OUT endpoint, if applicable */
	if ( hid->out.usb &&
	     ( ( rc = usb_endpoint_described ( &hid->out, config, desc,
					       USB_INTERRUPT_OUT, 0 ) ) != 0 )){
		DBGC ( hid, "HID %s could not describe interrupt OUT: %s\n",
		       hid->func->name, strerror ( rc ) );
		return rc;
	}

	return 0;
}
