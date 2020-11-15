/*
 * Driver for USB ported from CoreBoot
 *
 * Copyright (C) 2014 BALATON Zoltan
 *
 * This file was part of the libpayload project.
 *
 * Copyright (C) 2008-2010 coresystems GmbH
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"
#include "drivers/usb.h"
#include "usb.h"
#include "timer.h"
#include "libc/byteorder.h"

hci_t *usb_hcs = 0;

static void usb_nop_init (usbdev_t *dev);

static void
usb_nop_destroy (usbdev_t *dev)
{
	if (dev->descriptor != 0)
		free (dev->descriptor);
	usb_nop_init (dev);
	dev->address = -1;
	dev->hub = -1;
	dev->port = -1;
}

static void
usb_nop_poll (usbdev_t *dev)
{
	return;
}

static void
usb_nop_init (usbdev_t *dev)
{
	dev->descriptor = 0;
	dev->destroy = usb_nop_destroy;
	dev->poll = usb_nop_poll;
}

hci_t *
new_controller (void)
{
	hci_t *controller = malloc (sizeof (hci_t));

	if (controller) {
		/* atomic */
		controller->next = usb_hcs;
		usb_hcs = controller;
		/* atomic end */
	}

	return controller;
}

void
detach_controller (hci_t *controller)
{
	if (controller == NULL)
		return;
	if (usb_hcs == controller) {
		usb_hcs = controller->next;
	} else {
		hci_t *it = usb_hcs;
		while (it != NULL) {
			if (it->next == controller) {
				it->next = controller->next;
				return;
			}
			it = it->next;
		}
	}
}

/**
 * Shut down all controllers
 */
int
usb_exit (void)
{
	while (usb_hcs != NULL) {
		usb_hcs->shutdown(usb_hcs);
	}
	return 0;
}

/**
 * Polls all hubs on all USB controllers, to find out about device changes
 */
void
usb_poll (void)
{
	if (usb_hcs == 0)
		return;
	hci_t *controller = usb_hcs;
	while (controller != NULL) {
		int i;
		for (i = 0; i < 128; i++) {
			if (controller->devices[i] != 0) {
				controller->devices[i]->poll (controller->devices[i]);
			}
		}
		controller = controller->next;
	}
}

void
init_device_entry (hci_t *controller, int i)
{
	if (controller->devices[i] != 0)
		usb_debug("warning: device %d reassigned?\n", i);
	controller->devices[i] = malloc(sizeof(usbdev_t));
	controller->devices[i]->controller = controller;
	controller->devices[i]->address = -1;
	controller->devices[i]->hub = -1;
	controller->devices[i]->port = -1;
	controller->devices[i]->init = usb_nop_init;
	controller->devices[i]->init (controller->devices[i]);
}

void
set_feature (usbdev_t *dev, int endp, int feature, int rtype)
{
	dev_req_t dr;

	dr.bmRequestType = rtype;
	dr.data_dir = host_to_device;
	dr.bRequest = SET_FEATURE;
	dr.wValue = __cpu_to_le16(feature);
	dr.wIndex = __cpu_to_le16(endp);
	dr.wLength = 0;
	dev->controller->control (dev, OUT, sizeof (dr), &dr, 0, 0);
}

void
get_status (usbdev_t *dev, int intf, int rtype, int len, void *data)
{
	dev_req_t dr;

	dr.bmRequestType = rtype;
	dr.data_dir = device_to_host;
	dr.bRequest = GET_STATUS;
	dr.wValue = 0;
	dr.wIndex = __cpu_to_le16(intf);
	dr.wLength = __cpu_to_le16(len);
	dev->controller->control (dev, IN, sizeof (dr), &dr, len, data);
}

u8 *
get_descriptor (usbdev_t *dev, unsigned char bmRequestType, int descType,
		int descIdx, int langID)
{
	u8 buf[8];
	u8 *result;
	dev_req_t dr;
	int size;

	dr.bmRequestType = bmRequestType;
	dr.data_dir = device_to_host;	// always like this for descriptors
	dr.bRequest = GET_DESCRIPTOR;
	dr.wValue = __cpu_to_le16((descType << 8) | descIdx);
	dr.wIndex = __cpu_to_le16(langID);
	dr.wLength = __cpu_to_le16(8);
	if (dev->controller->control (dev, IN, sizeof (dr), &dr, 8, buf)) {
		usb_debug ("getting descriptor size (type %x) failed\n",
			descType);
	}

	if (descType == 1) {
		device_descriptor_t *dd = (device_descriptor_t *) buf;
		usb_debug ("maxPacketSize0: %x\n", dd->bMaxPacketSize0);
		if (dd->bMaxPacketSize0 != 0)
			dev->endpoints[0].maxpacketsize = dd->bMaxPacketSize0;
	}

	/* special case for configuration descriptors: they carry all their
	   subsequent descriptors with them, and keep the entire size at a
	   different location */
	size = buf[0];
	if (buf[1] == 2) {
		int realsize = __le16_to_cpu(((unsigned short *) (buf + 2))[0]);
		size = realsize;
	}
	result = malloc (size);
	memset (result, 0, size);
	dr.wLength = __cpu_to_le16(size);
	if (dev->controller->
	    control (dev, IN, sizeof (dr), &dr, size, result)) {
		usb_debug ("getting descriptor (type %x, size %x) failed\n",
			descType, size);
	}

	return result;
}

void
set_configuration (usbdev_t *dev)
{
	dev_req_t dr;

	dr.bmRequestType = 0;
	dr.bRequest = SET_CONFIGURATION;
	dr.wValue = __cpu_to_le16(dev->configuration[5]);
	dr.wIndex = 0;
	dr.wLength = 0;
	dev->controller->control (dev, OUT, sizeof (dr), &dr, 0, 0);
}

int
clear_feature (usbdev_t *dev, int endp, int feature, int rtype)
{
	dev_req_t dr;

	dr.bmRequestType = rtype;
	dr.data_dir = host_to_device;
	dr.bRequest = CLEAR_FEATURE;
	dr.wValue = __cpu_to_le16(feature);
	dr.wIndex = __cpu_to_le16(endp);
	dr.wLength = 0;
	return dev->controller->control (dev, OUT, sizeof (dr), &dr, 0, 0);
}

int
clear_stall (endpoint_t *ep)
{
	usbdev_t *dev = ep->dev;
	int endp = ep->endpoint;
	int rtype = gen_bmRequestType (host_to_device, standard_type,
					endp ? endp_recp : dev_recp);

	int ret = clear_feature (dev, endp, ENDPOINT_HALT, rtype);
	ep->toggle = 0;
	return ret;
}

/* returns free address or -1 */
static int
get_free_address (hci_t *controller)
{
	int i;
	for (i = 1; i < 128; i++) {
		if (controller->devices[i] == 0)
			return i;
	}
	usb_debug ("no free address found\n");
	return -1;		// no free address
}

int
generic_set_address (hci_t *controller, int speed, int hubport, int hubaddr)
{
	int adr = get_free_address (controller);	// address to set
	dev_req_t dr;

	memset (&dr, 0, sizeof (dr));
	dr.data_dir = host_to_device;
	dr.req_type = standard_type;
	dr.req_recp = dev_recp;
	dr.bRequest = SET_ADDRESS;
	dr.wValue = __cpu_to_le16(adr);
	dr.wIndex = 0;
	dr.wLength = 0;

	init_device_entry(controller, adr);
	usbdev_t *dev = controller->devices[adr];
	// dummy values for registering the address
	dev->address = 0;
	dev->hub = hubaddr;
	dev->port = hubport;
	dev->speed = speed;
	dev->endpoints[0].dev = dev;
	dev->endpoints[0].endpoint = 0;
	dev->endpoints[0].maxpacketsize = 8;
	dev->endpoints[0].toggle = 0;
	dev->endpoints[0].direction = SETUP;
	mdelay (50);
	if (dev->controller->control (dev, OUT, sizeof (dr), &dr, 0, 0)) {
		return -1;
	}
	mdelay (50);

	return adr;
}

/* Normalize bInterval to log2 of microframes */
static int
usb_decode_interval(const int speed, const endpoint_type type, const unsigned char bInterval)
{
#define LOG2(a) ((sizeof(unsigned) << 3) - __builtin_clz(a) - 1)
	switch (speed) {
	case LOW_SPEED:
		switch (type) {
		case ISOCHRONOUS: case INTERRUPT:
			return LOG2(bInterval) + 3;
		default:
			return 0;
		}
	case FULL_SPEED:
		switch (type) {
		case ISOCHRONOUS:
			return (bInterval - 1) + 3;
		case INTERRUPT:
			return LOG2(bInterval) + 3;
		default:
			return 0;
		}
	case HIGH_SPEED:
		switch (type) {
		case ISOCHRONOUS: case INTERRUPT:
			return bInterval - 1;
		default:
			return LOG2(bInterval);
		}
	case SUPER_SPEED:
		switch (type) {
		case ISOCHRONOUS: case INTERRUPT:
			return bInterval - 1;
		default:
			return 0;
		}
	default:
		return 0;
	}
#undef LOG2
}

static int
set_address (hci_t *controller, int speed, int hubport, int hubaddr)
{
	int adr = controller->set_address(controller, speed, hubport, hubaddr);
	if (adr < 0 || !controller->devices[adr]) {
		usb_debug ("set_address failed\n");
		return -1;
	}
	configuration_descriptor_t *cd;
	device_descriptor_t *dd;

	usbdev_t *dev = controller->devices[adr];
	dev->address = adr;
	dev->hub = hubaddr;
	dev->port = hubport;
	dev->speed = speed;
	dev->descriptor = get_descriptor (dev, gen_bmRequestType
		(device_to_host, standard_type, dev_recp), 1, 0, 0);
	dd = (device_descriptor_t *) dev->descriptor;

	usb_debug ("* found device (0x%04x:0x%04x, USB %x.%x)",
		 __le16_to_cpu(dd->idVendor), __le16_to_cpu(dd->idProduct),
		 __le16_to_cpu(dd->bcdUSB) >> 8, __le16_to_cpu(dd->bcdUSB) & 0xff);
	dev->quirks = USB_QUIRK_NONE;

	usb_debug ("\ndevice has %x configurations\n", dd->bNumConfigurations);
	if (dd->bNumConfigurations == 0) {
		/* device isn't usable */
		usb_debug ("... no usable configuration!\n");
		dev->address = 0;
		return -1;
	}

	dev->configuration = get_descriptor (dev, gen_bmRequestType
		(device_to_host, standard_type, dev_recp), 2, 0, 0);
	cd = (configuration_descriptor_t *) dev->configuration;
	interface_descriptor_t *interface =
		(interface_descriptor_t *) (((char *) cd) + cd->bLength);
	{
		int i;
		int num = cd->bNumInterfaces;
		interface_descriptor_t *current = interface;
		usb_debug ("device has %x interfaces\n", num);
		if (num > 1) {
			usb_debug ("\nNOTICE: This driver defaults to using the first interface.\n"
				   "This might be the wrong choice and lead to limited functionality\n"
				   "of the device.\n");
			 /* we limit to the first interface, as there was no need to
			 * implement something else for the time being. If you need
			 * it, see the SetInterface and GetInterface functions in
			 * the USB specification, and adapt appropriately.
			 */
			num = (num > 1) ? 1 : num;
		}
		for (i = 0; i < num; i++) {
			int j;
			usb_debug (" #%x has %x endpoints, interface %x:%x, protocol %x\n",
					current->bInterfaceNumber, current->bNumEndpoints, current->bInterfaceClass, current->bInterfaceSubClass, current->bInterfaceProtocol);
			endpoint_descriptor_t *endp =
				(endpoint_descriptor_t *) (((char *) current)
							   + current->bLength);
			/* Skip any non-endpoint descriptor */
			if (endp->bDescriptorType != 0x05)
				endp = (endpoint_descriptor_t *)(((char *)endp) + ((char *)endp)[0]);

			memset (dev->endpoints, 0, sizeof (dev->endpoints));
			dev->num_endp = 1;	// 0 always exists
			dev->endpoints[0].dev = dev;
			dev->endpoints[0].maxpacketsize = dd->bMaxPacketSize0;
			dev->endpoints[0].direction = SETUP;
			dev->endpoints[0].type = CONTROL;
			dev->endpoints[0].interval = usb_decode_interval(dev->speed, CONTROL, endp->bInterval);
			for (j = 1; j <= current->bNumEndpoints; j++) {
#ifdef CONFIG_DEBUG_USB
				static const char *transfertypes[4] = {
					"control", "isochronous", "bulk", "interrupt"
				};
				usb_debug ("   #%x: Endpoint %x (%s), max packet size %x, type %s\n", j, endp->bEndpointAddress & 0x7f, ((endp->bEndpointAddress & 0x80) != 0) ? "in" : "out", __le16_to_cpu(endp->wMaxPacketSize), transfertypes[endp->bmAttributes]);
#endif
				endpoint_t *ep =
					&dev->endpoints[dev->num_endp++];
				ep->dev = dev;
				ep->endpoint = endp->bEndpointAddress;
				ep->toggle = 0;
				ep->maxpacketsize = __le16_to_cpu(endp->wMaxPacketSize);
				ep->direction =
					((endp->bEndpointAddress & 0x80) ==
					 0) ? OUT : IN;
				ep->type = endp->bmAttributes;
				ep->interval = usb_decode_interval(dev->speed, ep->type, endp->bInterval);
				endp = (endpoint_descriptor_t
					*) (((char *) endp) + endp->bLength);
			}
			current = (interface_descriptor_t *) endp;
		}
	}

	if (controller->finish_device_config &&
			controller->finish_device_config(dev))
		return adr; /* Device isn't configured correctly,
			       only control transfers may work. */

	set_configuration(dev);

	int class = dd->bDeviceClass;
	if (class == 0)
		class = interface->bInterfaceClass;

	usb_debug(", class: ");
	switch (class) {
	case audio_device:
		usb_debug("audio\n");
		break;
	case comm_device:
		usb_debug("communication\n");
		break;
	case hid_device:
		usb_debug ("HID\n");
#ifdef CONFIG_USB_HID
		controller->devices[adr]->init = usb_hid_init;
		return adr;
#else
		usb_debug ("NOTICE: USB HID support not compiled in\n");
#endif
		break;
	case physical_device:
		usb_debug("physical\n");
		break;
	case imaging_device:
		usb_debug("camera\n");
		break;
	case printer_device:
		usb_debug("printer\n");
		break;
	case msc_device:
		usb_debug ("MSC\n");
#ifdef CONFIG_USB_MSC
		controller->devices[adr]->init = usb_msc_init;
		return adr;
#else
		usb_debug ("NOTICE: USB MSC support not compiled in\n");
#endif
		break;
	case hub_device:
		usb_debug ("hub\n");
#ifdef CONFIG_USB_HUB
		controller->devices[adr]->init = usb_hub_init;
		return adr;
#else
		usb_debug ("NOTICE: USB hub support not compiled in.\n");
#endif
		break;
	case cdc_device:
		usb_debug("CDC\n");
		break;
	case ccid_device:
		usb_debug("smartcard / CCID\n");
		break;
	case security_device:
		usb_debug("content security\n");
		break;
	case video_device:
		usb_debug("video\n");
		break;
	case healthcare_device:
		usb_debug("healthcare\n");
		break;
	case diagnostic_device:
		usb_debug("diagnostic\n");
		break;
	case wireless_device:
		usb_debug("wireless\n");
		break;
	default:
		usb_debug("unsupported class %x\n", class);
		break;
	}
	controller->devices[adr]->init = usb_generic_init;
	return adr;
}

/*
 * Should be called by the hub drivers whenever a physical detach occurs
 * and can be called by usb class drivers if they are unsatisfied with a
 * malfunctioning device.
 */
void
usb_detach_device(hci_t *controller, int devno)
{
	/* check if device exists, as we may have
	   been called yet by the usb class driver */
	if (controller->devices[devno]) {
		controller->devices[devno]->destroy (controller->devices[devno]);
		free(controller->devices[devno]);
		controller->devices[devno] = NULL;
		if (controller->destroy_device)
			controller->destroy_device(controller, devno);
	}
}

int
usb_attach_device(hci_t *controller, int hubaddress, int port, int speed)
{
#ifdef CONFIG_USB_DEBUG
	static const char* speeds[] = { "full", "low", "high" };
	usb_debug ("%sspeed device\n", (speed <= 2) ? speeds[speed] : "invalid value - no");
#endif
	int newdev = set_address (controller, speed, port, hubaddress);
	if (newdev == -1)
		return -1;
	usbdev_t *newdev_t = controller->devices[newdev];
	// determine responsible driver - current done in set_address
	newdev_t->init (newdev_t);
	/* init() may have called usb_detach_device() yet, so check */
	return controller->devices[newdev] ? newdev : -1;
}

static void
usb_generic_destroy (usbdev_t *dev)
{
	if (usb_generic_remove)
		usb_generic_remove(dev);
}

void
usb_generic_init (usbdev_t *dev)
{
	dev->data = NULL;
	dev->destroy = usb_generic_destroy;

	if (usb_generic_create)
		usb_generic_create(dev);
}
