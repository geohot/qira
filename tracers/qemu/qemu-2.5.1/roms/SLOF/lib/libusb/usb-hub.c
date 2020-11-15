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

#include <stdio.h>
#include <string.h>
#include "usb-core.h"

#undef HUB_DEBUG
//#define HUB_DEBUG
#ifdef HUB_DEBUG
#define dprintf(_x ...) do { printf(_x); } while(0)
#else
#define dprintf(_x ...)
#endif

/*
 * USB Spec 1.1
 *            11.16.2 Class-specific Requests
 */
struct usb_hub_ps {
	uint16_t wPortStatus;
	uint16_t wPortChange;
} __attribute__((packed));

#define HUB_PS_CONNECTION            (1 << 0)
#define HUB_PS_ENABLE                (1 << 1)
#define HUB_PS_SUSPEND               (1 << 2)
#define HUB_PS_OVER_CURRENT          (1 << 3)
#define HUB_PS_RESET                 (1 << 4)
#define HUB_PS_POWER                 (1 << 8)
#define HUB_PS_LOW_SPEED             (1 << 9)

#define HUB_PF_CONNECTION        0
#define HUB_PF_ENABLE            1
#define HUB_PF_SUSPEND           2
#define HUB_PF_OVER_CURRENT      3
#define HUB_PF_RESET             4
#define HUB_PF_POWER             8
#define HUB_PF_LOWSPEED          9
#define HUB_PF_C_CONNECTION      16
#define HUB_PF_C_ENABLE          17
#define HUB_PF_C_SUSPEND         18
#define HUB_PF_C_OVER_CURRENT    19
#define HUB_PF_C_RESET           20

static int usb_get_hub_desc(struct usb_dev *dev, void *data, size_t size)
{
	struct usb_dev_req req;
	if (!dev)
		return false;
	req.bmRequestType = REQT_DIR_IN | REQT_TYPE_CLASS | REQT_REC_DEVICE;
	req.bRequest = REQ_GET_DESCRIPTOR;
	req.wIndex = 0;
	req.wLength = cpu_to_le16((uint16_t) size);
	req.wValue = cpu_to_le16(DESCR_TYPE_HUB << 8);
	return usb_send_ctrl(dev->control, &req, data);
}

static int hub_get_port_status(struct usb_dev *dev, int port, void *data, size_t size)
{
	struct usb_dev_req req;
	if (!dev)
		return false;
	req.bmRequestType = REQT_DIR_IN | REQT_TYPE_CLASS | REQT_REC_OTHER;
	req.bRequest = REQ_GET_STATUS;
	req.wValue = 0;
	req.wIndex = cpu_to_le16((uint16_t)(port + 1));
	req.wLength = cpu_to_le16((uint16_t)size);
	return usb_send_ctrl(dev->control, &req, data);
}

static int hub_set_port_feature(struct usb_dev *dev, int port, int feature)
{
	struct usb_dev_req req;
	if (!dev)
		return false;
	req.bmRequestType = REQT_DIR_OUT | REQT_TYPE_CLASS | REQT_REC_OTHER;
	req.bRequest = REQ_SET_FEATURE;
	req.wLength = 0;
	req.wValue = cpu_to_le16((uint16_t)feature);
	req.wIndex = cpu_to_le16((uint16_t)(port + 1));
	return usb_send_ctrl(dev->control, &req, NULL);
}

#if 0
static int hub_clear_port_feature(struct usb_dev *dev, int port, int feature)
{
	struct usb_dev_req req;
	if (!dev)
		return false;
	req.bmRequestType = REQT_DIR_OUT | REQT_TYPE_CLASS | REQT_REC_OTHER;
	req.bRequest = REQ_CLEAR_FEATURE;
	req.wLength = 0;
	req.wValue = cpu_to_le16((uint16_t)feature);
	req.wIndex = cpu_to_le16((uint16_t)(port + 1));
	return usb_send_ctrl(dev->control, &req, NULL);
}
#endif

static int hub_check_port(struct usb_dev *dev, int port)
{
	struct usb_hub_ps ps;
	uint32_t time;

	if (!hub_get_port_status(dev, port, &ps, sizeof(ps)))
		return false;
	dprintf("Port Status %04X Port Change %04X\n",
		le16_to_cpu(ps.wPortStatus),
		le16_to_cpu(ps.wPortChange));

	if (!(le16_to_cpu(ps.wPortStatus) & HUB_PS_POWER)) {
		hub_set_port_feature(dev, port, HUB_PF_POWER);
		SLOF_msleep(100);
		time = SLOF_GetTimer() + USB_TIMEOUT;
		while (time > SLOF_GetTimer()) {
			cpu_relax();
			hub_get_port_status(dev, port, &ps, sizeof(ps));
			if (le16_to_cpu(ps.wPortStatus) & HUB_PS_CONNECTION) {
				dprintf("power on Port Status %04X Port Change %04X\n",
					le16_to_cpu(ps.wPortStatus),
					le16_to_cpu(ps.wPortChange));
				break;
			}
		}
	}

	if (le16_to_cpu(ps.wPortStatus) & HUB_PS_CONNECTION) {
		hub_set_port_feature(dev, port, HUB_PF_RESET);
		SLOF_msleep(100);
		time = SLOF_GetTimer() + USB_TIMEOUT;
		while (time > SLOF_GetTimer()) {
			cpu_relax();
			hub_get_port_status(dev, port, &ps, sizeof(ps));
			if (!(le16_to_cpu(ps.wPortStatus) & HUB_PS_RESET)) {
				dprintf("reset Port Status %04X Port Change %04X\n",
					le16_to_cpu(ps.wPortStatus),
					le16_to_cpu(ps.wPortChange));
				return true;
			}
		}
	}
	return false;
}

unsigned int usb_hub_init(void *hubdev)
{
	struct usb_dev *dev = hubdev;
	struct usb_dev_hub_descr hub;
	struct usb_dev *newdev;
	int i;

	dprintf("%s: enter %p\n", __func__, dev);
	if (!dev) {
		printf("usb-hub: NULL\n");
		return false;
	}
	memset(&hub, 0, sizeof(hub));
	usb_get_hub_desc(dev, &hub, sizeof(hub));
	dprintf("usb-hub: ports connected %d\n", hub.bNbrPorts);
	for (i = 0; i < hub.bNbrPorts; i++) {
		dprintf("usb-hub: ports scanning %d\n", i);
		if (hub_check_port(dev, i)) {
			dprintf("***********************************************\n");
			dprintf("\t\tusb-hub: device found %d\n", i);
			dprintf("***********************************************\n");
			newdev = usb_devpool_get();
			dprintf("usb-hub: allocated device %p\n", newdev);
			newdev->hcidev = dev->hcidev;
			if (!setup_new_device(newdev, i))
				printf("usb-hub: unable to setup device on port %d\n", i);
		}
	}
	return true;
}
