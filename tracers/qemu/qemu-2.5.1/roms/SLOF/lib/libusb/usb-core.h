/*****************************************************************************
 * Copyright (c) 2013 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef __USB_CORE_H
#define __USB_CORE_H

#include <stdio.h>
#include <stdbool.h>
#include "helpers.h"
#include "usb.h"
#include "tools.h"

enum usb_hcd_type {
	USB_OHCI = 1,
	USB_EHCI = 2,
	USB_XHCI = 3,
};

struct usb_hcd_dev;

struct usb_hcd_dev {
	void *base;
	long type;
	long num;
	struct usb_hcd_ops *ops;
	void *priv; /* hcd owned structure */
	long nextaddr; /* address for devices */
};

struct usb_pipe;

/*******************************************/
/* Standard Endpoint Descriptor            */
/*******************************************/
/* bmAttributes */
#define USB_EP_TYPE_MASK          0x03
#define USB_EP_TYPE_CONTROL       0
#define USB_EP_TYPE_ISOC          1
#define USB_EP_TYPE_BULK          2
#define USB_EP_TYPE_INTR          3

struct usb_ep_descr {
	uint8_t		bLength;		/* size of descriptor */
	uint8_t		bDescriptorType;	/* Type = 5 */
	uint8_t		bEndpointAddress;
	uint8_t		bmAttributes;
	uint16_t	wMaxPacketSize;
	uint8_t		bInterval;
} __attribute__((packed));

#define	DEV_HID_KEYB            0x030101	/* class=HIB,	protocol=Keyboard */
#define	DEV_HID_MOUSE           0x030102	/* class=HIB,	protocol=Mouse */
#define	DEV_HUB                 0x090000	/* class=HUB, subclass, protocol */
#define	DEV_MASS_RBC            0x080150	/* MassStorage, RBC, Bulk */
#define	DEV_CDROM_ATAPI         0x080250	/* MassStorage, SFF-8020i , Bulk */
#define	DEV_MASS_FLOPPY         0x080450	/* MassStorage, UFI, Bulk */
#define	DEV_MASS_ATAPI          0x080550	/* MassStorage, SFF-8070i , Bulk */
#define	DEV_MASS_SCSI           0x080650	/* MassStorage, SCSI, Bulk */

enum USB_SPEED_TYPE {
	USB_LOW_SPEED = 0,
	USB_FULL_SPEED = 1,
	USB_HIGH_SPEED = 2,
	USB_SUPER_SPEED = 3,
};

/* Max number of endpoints supported in a device */
#define USB_DEV_EP_MAX 4
#define USB_TIMEOUT    5000 /* 5 sec usb timeout */

struct usb_dev {
	struct usb_dev     *next;
	struct usb_hcd_dev *hcidev;
	struct usb_pipe    *intr;
	struct usb_pipe    *control;
	struct usb_pipe    *bulk_in;
	struct usb_pipe    *bulk_out;
	struct usb_ep_descr ep[USB_DEV_EP_MAX];
	void *priv;
	uint32_t ep_cnt;
	uint32_t class;
	uint32_t speed;
	uint32_t addr;
	uint32_t mps0;
	uint32_t port;
	uint16_t intf_num;
};

#define DEVICE_KEYBOARD    1
#define DEVICE_MOUSE       2
#define DEVICE_DISK        3
#define DEVICE_HUB         4

/* Structure in sync with FORTH code */
struct slof_usb_dev {
	void     *udev;
	uint32_t port;
	uint32_t addr;
	uint32_t hcitype;
	uint32_t num;
	uint32_t devtype;
} __attribute__((packed));

enum USB_PIPE_DIR {
	USB_PIPE_OUT = 0,
	USB_PIPE_IN,
};

struct usb_pipe {
	struct usb_dev *dev;
	struct usb_pipe *next;
	uint32_t type;
	uint32_t speed;
	uint32_t dir;
	uint16_t epno;
	uint16_t mps;
} __attribute__((packed));

#define	REQ_GET_STATUS		     0	/* see Table 9-4 */
#define	REQ_CLEAR_FEATURE	     1
#define	REQ_GET_STATE		     2	/* HUB specific */
#define	REQ_SET_FEATURE		     3
#define	REQ_SET_ADDRESS		     5
#define	REQ_GET_DESCRIPTOR	     6
#define	REQ_SET_DESCRIPTOR	     7
#define	REQ_GET_CONFIGURATION	     8
#define	REQ_SET_CONFIGURATION	     9
#define	REQ_GET_INTERFACE	     10
#define	REQ_SET_INTERFACE	     11
#define	REQ_SYNCH_FRAME              12

#define FEATURE_DEVICE_REMOTE_WAKEUP 1
#define FEATURE_ENDPOINT_HALT        0

#define REQT_REC_DEVICE              0
#define REQT_REC_INTERFACE           1
#define REQT_REC_EP                  2
#define REQT_REC_OTHER               3
#define REQT_TYPE_STANDARD           (0 << 5)
#define REQT_TYPE_CLASS              (1 << 5)
#define REQT_TYPE_VENDOR             (2 << 5)
#define REQT_TYPE_RSRVD              (3 << 5)
#define REQT_DIR_OUT                 (0 << 7) /* host -> device */
#define REQT_DIR_IN                  (1 << 7) /* device -> host */

#define	DESCR_TYPE_DEVICE		1	/* see Table 9-5 */
#define	DESCR_TYPE_CONFIGURATION	2
#define	DESCR_TYPE_STRING		3
#define	DESCR_TYPE_INTERFACE		4
#define	DESCR_TYPE_ENDPOINT		5
#define	DESCR_TYPE_HUB			0x29	/* Class Descriptor HUB */
#define DESCR_TYPE_HID			0x21	/* Class Descriptor HID */
#define DESCR_TYPE_REPORT		0x22	/* Class Descriptor HID */
#define DESCR_TYPE_PHYSICAL		0x23	/* Class Descriptor HID */

struct usb_dev_req {
	uint8_t		bmRequestType;		/* direction, recipient */
	uint8_t		bRequest;		/* see spec: Table 9-3 */
	uint16_t	wValue;
	uint16_t	wIndex;
	uint16_t	wLength;		/* number of bytes to transfer */
} __attribute__((packed));

/* Standard Device Descriptor (18 Bytes)   */
/*******************************************/
struct usb_dev_descr {
	uint8_t		bLength;
	uint8_t		bDescriptorType;
	uint16_t	bcdUSB;
	uint8_t		bDeviceClass;
	uint8_t		bDeviceSubClass;
	uint8_t		bDeviceProtocol;
	uint8_t		bMaxPacketSize0;
	uint16_t	idVendor;
	uint16_t	idProduct;
	uint16_t	bcdDevice;
	uint8_t		iManufacturer;
	uint8_t		iProduct;
	uint8_t		iSerialNumber;
	uint8_t		bNumConfigurations;
} __attribute__((packed));

/*******************************************/
/* Standard Configuration Descriptor       */
/*******************************************/
struct usb_dev_config_descr {
	uint8_t		bLength;		/* size of descriptor */
	uint8_t		bDescriptorType;	/* Type = 2 */
	uint16_t	wTotalLength;		/* total returned data */
	uint8_t		bNumInterfaces;		/* interfaces supported by this config */
	uint8_t		bConfigurationValue;	/* Configuration-ID for SetConfiguration */
	uint8_t		iConfiguration;		/* index of string descriptor */
	uint8_t		bmAttributes;		/* configuration characteristics */
	uint8_t		bMaxPower;		/* in 2mA units */
} __attribute__((packed));

/*******************************************/
/* Standard Interface Descriptor */
/*******************************************/
struct usb_dev_intf_descr {
	uint8_t		bLength;		/* size of descriptor */
	uint8_t		bDescriptorType;	/* Type = 4 */
	uint8_t		bInterfaceNumber;
	uint8_t		bAlternateSetting;
	uint8_t		bNumEndpoints;
	uint8_t		bInterfaceClass;
	uint8_t		bInterfaceSubClass;
	uint8_t		bInterfaceProtocol;	/* protocol code */
	uint8_t		iInterface;		/* index to string descriptor */
} __attribute__((packed));

/*******************************************/
/* HUB-Class Descriptor                    */
/*******************************************/
struct usb_dev_hub_descr {
	uint8_t		bLength;		/* size of complete descriptor */
	uint8_t		bDescriptorType;	/* type = 0x29 for HUB */
	uint8_t		bNbrPorts;		/* number of downstream ports */
	uint8_t		wHubCharacteristics;	/* mode bits	7..0 */
	uint8_t		reserved;		/* mode bits 15..8 */
	uint8_t		bPwrOn2PwrGood;		/* in 2ms units */
	uint8_t		bHubContrCurrent;	/* current requirement in mA */
	uint8_t		DeviceTable;	        /* length depends on number of ports */
} __attribute__((packed));

/*******************************************/
/* HID-Class Descriptor                    */
/*******************************************/
struct usb_dev_hid_descr {
	uint8_t		bLength;		/* size of this descriptor */
	uint8_t		bDescriptorType;	/* type = 0x21 for HID     */
	uint16_t	bcdHID;			/* Sample: 0x0102 for 2.01  */
	uint8_t		bCountryCode;		/* Hardware target country */
	uint8_t		bNumDescriptors;	/* Number of HID class descr. */
	uint8_t		bReportType;		/* Report Descriptor Type */
	uint16_t	wReportLength;		/* Total Length of Report Descr. */
} __attribute__((packed));

struct usb_hcd_ops {
	const char *name;
	void (*init)(struct usb_hcd_dev *);
	void (*exit)(struct usb_hcd_dev *);
	void (*detect)(void);
	void (*disconnect)(void);
	int  (*send_ctrl)(struct usb_pipe *pipe, struct usb_dev_req *req, void *data);
	struct usb_pipe* (*get_pipe)(struct usb_dev *dev, struct usb_ep_descr *ep,
				char *buf, size_t len);
	int  (*transfer_bulk)(struct usb_pipe *pipe, void *td, void *td_phys, void *data, int size);
	void (*put_pipe)(struct usb_pipe *);
	int (*poll_intr)(struct usb_pipe *, uint8_t *);
	struct usb_hcd_ops *next;
	unsigned int usb_type;
};

extern void usb_hcd_register(struct usb_hcd_ops *ops);
extern struct usb_pipe *usb_get_pipe(struct usb_dev *dev, struct usb_ep_descr *ep,
				char *buf, size_t len);
extern void usb_put_pipe(struct usb_pipe *pipe);
extern int usb_poll_intr(struct usb_pipe *pipe, uint8_t *buf);
extern int usb_send_ctrl(struct usb_pipe *pipe, struct usb_dev_req *req, void *data);
extern struct usb_dev *usb_devpool_get(void);
extern void usb_devpool_put(struct usb_dev *);
extern int setup_new_device(struct usb_dev *dev, unsigned int port);
extern int slof_usb_handle(struct usb_dev *dev);
extern int usb_dev_populate_pipe(struct usb_dev *dev, struct usb_ep_descr *ep,
				void *buf, size_t len);
extern int usb_hid_kbd_init(struct usb_dev *dev);
extern int usb_hid_kbd_exit(struct usb_dev *dev);
extern void usb_msc_resetrecovery(struct usb_dev *dev);
#endif
