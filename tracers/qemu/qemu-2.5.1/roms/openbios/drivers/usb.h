/*
 * Driver for USB ported from CoreBoot
 *
 * Copyright (C) 2014 BALATON Zoltan
 *
 * This file was part of the libpayload project.
 *
 * Copyright (C) 2008 coresystems GmbH
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

#ifndef __USB_H
#define __USB_H
#include <drivers/pci.h>

typedef enum { host_to_device = 0, device_to_host = 1 } dev_req_dir;
typedef enum { standard_type = 0, class_type = 1, vendor_type =
		2, reserved_type = 3
} dev_req_type;
typedef enum { dev_recp = 0, iface_recp = 1, endp_recp = 2, other_recp = 3
} dev_req_recp;

typedef enum {
	GET_STATUS = 0,
	CLEAR_FEATURE = 1,
	SET_FEATURE = 3,
	SET_ADDRESS = 5,
	GET_DESCRIPTOR = 6,
	SET_DESCRIPTOR = 7,
	GET_CONFIGURATION = 8,
	SET_CONFIGURATION = 9,
	GET_INTERFACE = 10,
	SET_INTERFACE = 11,
	SYNCH_FRAME = 12
} bRequest_Codes;

typedef enum {
	ENDPOINT_HALT = 0,
	DEVICE_REMOTE_WAKEUP = 1,
	TEST_MODE = 2
} feature_selectors;

enum {
	audio_device      = 0x01,
	comm_device       = 0x02,
	hid_device        = 0x03,
	physical_device   = 0x05,
	imaging_device    = 0x06,
	printer_device    = 0x07,
	msc_device        = 0x08,
	hub_device        = 0x09,
	cdc_device        = 0x0a,
	ccid_device       = 0x0b,
	security_device   = 0x0d,
	video_device      = 0x0e,
	healthcare_device = 0x0f,
	diagnostic_device = 0xdc,
	wireless_device   = 0xe0,
	misc_device       = 0xef,
};

enum { hid_subclass_none = 0, hid_subclass_boot = 1 };

enum {
	hid_boot_proto_none = 0,
	hid_boot_proto_keyboard = 1,
	hid_boot_proto_mouse = 2
};

typedef struct {
	union {
		struct {
#ifdef CONFIG_BIG_ENDIAN
			dev_req_dir data_dir:1;
			dev_req_type req_type:2;
			dev_req_recp req_recp:5;
#else
			dev_req_recp req_recp:5;
			dev_req_type req_type:2;
			dev_req_dir data_dir:1;
#endif
		} __attribute__ ((packed));
		unsigned char bmRequestType;
	} __attribute__ ((packed));
	unsigned char bRequest;
	unsigned short wValue;
	unsigned short wIndex;
	unsigned short wLength;
} __attribute__ ((packed)) dev_req_t;

struct usbdev_hc;
typedef struct usbdev_hc hci_t;

struct usbdev;
typedef struct usbdev usbdev_t;

typedef enum { SETUP, IN, OUT } direction_t;
typedef enum { CONTROL = 0, ISOCHRONOUS = 1, BULK = 2, INTERRUPT = 3
} endpoint_type;

typedef struct {
	usbdev_t *dev;
	int endpoint;
	direction_t direction;
	int toggle;
	int maxpacketsize;
	endpoint_type type;
	int interval; /* expressed as binary logarithm of the number
			 of microframes (i.e. t = 125us * 2^interval) */
} endpoint_t;

enum { FULL_SPEED = 0, LOW_SPEED = 1, HIGH_SPEED = 2, SUPER_SPEED = 3 };

struct usbdev {
	hci_t *controller;
	endpoint_t endpoints[32];
	int num_endp;
	int address;		// usb address
	int hub;		// hub, device is attached to
	int port;		// port where device is attached
	int speed;		// 1: lowspeed, 0: fullspeed, 2: highspeed
	u32 quirks;		// quirks field. got to love usb
	void *data;
	u8 *descriptor;
	u8 *configuration;
	void (*init) (usbdev_t *dev);
	void (*destroy) (usbdev_t *dev);
	void (*poll) (usbdev_t *dev);
};

typedef enum { OHCI = 0, UHCI = 1, EHCI = 2, XHCI = 3} hc_type;

struct usbdev_hc {
	hci_t *next;
	u32 reg_base;
	hc_type type;
	usbdev_t *devices[128];	// dev 0 is root hub, 127 is last addressable

	/* start():     Resume operation. */
	void (*start) (hci_t *controller);
	/* stop():      Stop operation but keep controller initialized. */
	void (*stop) (hci_t *controller);
	/* reset():     Perform a controller reset. The controller needs to
	                be (re)initialized afterwards to work (again). */
	void (*reset) (hci_t *controller);
	/* init():      Initialize a (previously reset) controller
	                to a working state. */
	void (*init) (hci_t *controller);
	/* shutdown():  Stop operation, detach host controller and shutdown
	                this driver instance. After calling shutdown() any
			other usage of this hci_t* is invalid. */
	void (*shutdown) (hci_t *controller);

	int (*bulk) (endpoint_t *ep, int size, u8 *data, int finalize);
	int (*control) (usbdev_t *dev, direction_t pid, int dr_length,
			void *devreq, int data_length, u8 *data);
	void* (*create_intr_queue) (endpoint_t *ep, int reqsize, int reqcount, int reqtiming);
	void (*destroy_intr_queue) (endpoint_t *ep, void *queue);
	u8* (*poll_intr_queue) (void *queue);
	void *instance;

	/* set_address():		Tell the usb device its address and
					return it. xHCI controllers want to
					do this by themself. Also, the usbdev
					structure has to be allocated and
					initialized. */
	int (*set_address) (hci_t *controller, int speed, int hubport, int hubaddr);
	/* finish_device_config():	Another hook for xHCI,
					returns 0 on success. */
	int (*finish_device_config) (usbdev_t *dev);
	/* destroy_device():		Finally, destroy all structures that
					were allocated during set_address()
					and finish_device_config(). */
	void (*destroy_device) (hci_t *controller, int devaddr);
};

typedef struct {
	unsigned char bDescLength;
	unsigned char bDescriptorType;
	unsigned char bNbrPorts;
	union {
		struct {
#ifdef CONFIG_BIG_ENDIAN
			unsigned long:8;
			unsigned long arePortIndicatorsSupported:1;
			unsigned long ttThinkTime:2;
			unsigned long overcurrentProtectionMode:2;
			unsigned long isCompoundDevice:1;
			unsigned long logicalPowerSwitchingMode:2;
#else
			unsigned long logicalPowerSwitchingMode:2;
			unsigned long isCompoundDevice:1;
			unsigned long overcurrentProtectionMode:2;
			unsigned long ttThinkTime:2;
			unsigned long arePortIndicatorsSupported:1;
			unsigned long:8;
#endif
		} __attribute__ ((packed));
		unsigned short wHubCharacteristics;
	} __attribute__ ((packed));
	unsigned char bPowerOn2PwrGood;
	unsigned char bHubContrCurrent;
	char DeviceRemovable[];
} __attribute__ ((packed)) hub_descriptor_t;

typedef struct {
	unsigned char bLength;
	unsigned char bDescriptorType;
	unsigned short bcdUSB;
	unsigned char bDeviceClass;
	unsigned char bDeviceSubClass;
	unsigned char bDeviceProtocol;
	unsigned char bMaxPacketSize0;
	unsigned short idVendor;
	unsigned short idProduct;
	unsigned short bcdDevice;
	unsigned char iManufacturer;
	unsigned char iProduct;
	unsigned char iSerialNumber;
	unsigned char bNumConfigurations;
} __attribute__ ((packed)) device_descriptor_t;

typedef struct {
	unsigned char bLength;
	unsigned char bDescriptorType;
	unsigned short wTotalLength;
	unsigned char bNumInterfaces;
	unsigned char bConfigurationValue;
	unsigned char iConfiguration;
	unsigned char bmAttributes;
	unsigned char bMaxPower;
} __attribute__ ((packed)) configuration_descriptor_t;

typedef struct {
	unsigned char bLength;
	unsigned char bDescriptorType;
	unsigned char bInterfaceNumber;
	unsigned char bAlternateSetting;
	unsigned char bNumEndpoints;
	unsigned char bInterfaceClass;
	unsigned char bInterfaceSubClass;
	unsigned char bInterfaceProtocol;
	unsigned char iInterface;
} __attribute__ ((packed)) interface_descriptor_t;

typedef struct {
	unsigned char bLength;
	unsigned char bDescriptorType;
	unsigned char bEndpointAddress;
	unsigned char bmAttributes;
	unsigned short wMaxPacketSize;
	unsigned char bInterval;
} __attribute__ ((packed)) endpoint_descriptor_t;

typedef struct {
	unsigned char bLength;
	unsigned char bDescriptorType;
	unsigned short bcdHID;
	unsigned char bCountryCode;
	unsigned char bNumDescriptors;
	unsigned char bReportDescriptorType;
	unsigned short wReportDescriptorLength;
} __attribute__ ((packed)) hid_descriptor_t;

hci_t *new_controller (void);
void detach_controller (hci_t *controller);
void usb_poll (void);
void init_device_entry (hci_t *controller, int num);

void set_feature (usbdev_t *dev, int endp, int feature, int rtype);
void get_status (usbdev_t *dev, int endp, int rtype, int len, void *data);
void set_configuration (usbdev_t *dev);
int clear_feature (usbdev_t *dev, int endp, int feature, int rtype);
int clear_stall (endpoint_t *ep);

void usb_hub_init (usbdev_t *dev);
void usb_hid_init (usbdev_t *dev);
void usb_msc_init (usbdev_t *dev);
void usb_generic_init (usbdev_t *dev);

u8 *get_descriptor (usbdev_t *dev, unsigned char bmRequestType,
		    int descType, int descIdx, int langID);

static inline unsigned char
gen_bmRequestType (dev_req_dir dir, dev_req_type type, dev_req_recp recp)
{
	return (dir << 7) | (type << 5) | recp;
}

/* default "set address" handler */
int generic_set_address (hci_t *controller, int speed, int hubport, int hubaddr);

void usb_detach_device(hci_t *controller, int devno);
int usb_attach_device(hci_t *controller, int hubaddress, int port, int speed);

u32 usb_quirk_check(u16 vendor, u16 device);
int usb_interface_check(u16 vendor, u16 device);

#define USB_QUIRK_MSC_FORCE_PROTO_SCSI		(1 <<  0)
#define USB_QUIRK_MSC_FORCE_PROTO_ATAPI		(1 <<  1)
#define USB_QUIRK_MSC_FORCE_PROTO_UFI		(1 <<  2)
#define USB_QUIRK_MSC_FORCE_PROTO_RBC		(1 <<  3)
#define USB_QUIRK_MSC_FORCE_TRANS_BBB		(1 <<  4)
#define USB_QUIRK_MSC_FORCE_TRANS_CBI		(1 <<  5)
#define USB_QUIRK_MSC_FORCE_TRANS_CBI_I		(1 <<  6)
#define USB_QUIRK_MSC_NO_TEST_UNIT_READY	(1 <<  7)
#define USB_QUIRK_MSC_SHORT_INQUIRY		(1 <<  8)
#define USB_QUIRK_TEST				(1 << 31)
#define USB_QUIRK_NONE				 0

#ifdef CONFIG_DEBUG_USB
#define usb_debug(fmt, args...)  do { printk(fmt , ##args); } while (0)
#else
#define usb_debug(fmt, args...)
#endif

/**
 * To be implemented by libpayload-client. It's called by the USB stack
 * when a new USB device is found which isn't claimed by a built in driver,
 * so the client has the chance to know about it.
 *
 * @param dev descriptor for the USB device
 */
void __attribute__((weak)) usb_generic_create (usbdev_t *dev);

/**
 * To be implemented by libpayload-client. It's called by the USB stack
 * when it finds out that a USB device is removed which wasn't claimed by a
 * built in driver.
 *
 * @param dev descriptor for the USB device
 */
void __attribute__((weak)) usb_generic_remove (usbdev_t *dev);

#endif
