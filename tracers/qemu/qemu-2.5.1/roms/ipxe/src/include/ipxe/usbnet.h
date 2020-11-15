#ifndef _IPXE_USBNET_H
#define _IPXE_USBNET_H

/** @file
 *
 * USB network devices
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/usb.h>

/** A USB network device */
struct usbnet_device {
	/** USB function */
	struct usb_function *func;

	/** Communications interface */
	unsigned int comms;
	/** Data interface */
	unsigned int data;
	/** Alternate setting for data interface */
	unsigned int alternate;

	/** Interrupt endpoint */
	struct usb_endpoint intr;
	/** Bulk IN endpoint */
	struct usb_endpoint in;
	/** Bulk OUT endpoint */
	struct usb_endpoint out;
};

/**
 * Initialise USB network device
 *
 * @v usbnet		USB network device
 * @v func		USB function
 * @v intr		Interrupt endpoint operations
 * @v in		Bulk IN endpoint operations
 * @v out		Bulk OUT endpoint operations
 */
static inline __attribute__ (( always_inline )) void
usbnet_init ( struct usbnet_device *usbnet, struct usb_function *func,
	      struct usb_endpoint_driver_operations *intr,
	      struct usb_endpoint_driver_operations *in,
	      struct usb_endpoint_driver_operations *out ) {
	struct usb_device *usb = func->usb;

	usbnet->func = func;
	usb_endpoint_init ( &usbnet->intr, usb, intr );
	usb_endpoint_init ( &usbnet->in, usb, in );
	usb_endpoint_init ( &usbnet->out, usb, out );
}

extern int usbnet_open ( struct usbnet_device *usbnet );
extern void usbnet_close ( struct usbnet_device *usbnet );
extern int usbnet_refill ( struct usbnet_device *usbnet );
extern int usbnet_describe ( struct usbnet_device *usbnet,
			     struct usb_configuration_descriptor *config );

#endif /* _IPXE_USBNET_H */
