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

#include <string.h>
#include "usb-core.h"

#undef DEBUG
//#define DEBUG
#ifdef DEBUG
#define dprintf(_x ...) do { printf(_x); } while(0)
#else
#define dprintf(_x ...)
#endif

#define __unused __attribute__((unused))

struct usb_hcd_ops *head;
struct usb_dev *devpool;
#define USB_DEVPOOL_SIZE 4096

static struct usb_dev *usb_alloc_devpool(void)
{
	struct usb_dev *head, *curr, *prev;
	unsigned int dev_count = 0, i;

	head = SLOF_alloc_mem(USB_DEVPOOL_SIZE);
	if (!head)
		return NULL;

	dev_count = USB_DEVPOOL_SIZE/sizeof(struct usb_dev);
	dprintf("%s: %d number of devices\n", __func__, dev_count);
	/* Although an array, link them*/
	for (i = 0, curr = head, prev = NULL; i < dev_count; i++, curr++) {
		if (prev)
			prev->next = curr;
		curr->next = NULL;
		prev = curr;
	}

#ifdef DEBUG
	for (i = 0, curr = head; curr; curr = curr->next)
		printf("%s: %d dev %p\n", __func__, i++, curr);
#endif

	return head;
}

struct usb_dev *usb_devpool_get(void)
{
	struct usb_dev *new;

	if (!devpool) {
		devpool = usb_alloc_devpool();
		if (!devpool)
			return NULL;
	}

	new = devpool;
	devpool = devpool->next;
	memset(new, 0, sizeof(*new));
	new->next = NULL;
	return new;
}

void usb_devpool_put(struct usb_dev *dev)
{
	struct usb_dev *curr;
	if (!dev && !devpool)
		return;

	curr = devpool;
	while (curr->next)
		curr = curr->next;
	curr->next = dev;
	dev->next = NULL;
}

#ifndef DEBUG
#define validate_hcd_ops(dev) (dev && dev->hcidev && dev->hcidev->ops)
#else
int validate_hcd_ops(struct usb_dev *dev)
{
	int ret = true;

	if (!dev) {
		printf("dev is NULL\n");
		ret = false;
	} else if (!dev->hcidev) {
		printf("hcidev is NULL\n");
		ret = false;
	} else if (!dev->hcidev->ops)  {
		printf("ops is NULL\n");
		ret = false;
	}
	return ret;
}
#endif

struct usb_pipe *usb_get_pipe(struct usb_dev *dev, struct usb_ep_descr *ep,
			char *buf, size_t len)
{
	if (validate_hcd_ops(dev) && dev->hcidev->ops->get_pipe)
		return dev->hcidev->ops->get_pipe(dev, ep, buf, len);
	else {
		printf("%s: Failed\n", __func__);
		return NULL;
	}
}

void usb_put_pipe(struct usb_pipe *pipe)
{
	struct usb_dev *dev = NULL;
	if (pipe && pipe->dev) {
		dev = pipe->dev;
		if (validate_hcd_ops(dev) && dev->hcidev->ops->put_pipe)
			dev->hcidev->ops->put_pipe(pipe);
	}
}

int usb_poll_intr(struct usb_pipe *pipe, uint8_t *buf)
{
	struct usb_dev *dev = NULL;
	if (pipe && pipe->dev) {
		dev = pipe->dev;
		if (validate_hcd_ops(dev) && dev->hcidev->ops->poll_intr)
			return dev->hcidev->ops->poll_intr(pipe, buf);
	}
	return 0;
}

void usb_hcd_register(struct usb_hcd_ops *ops)
{
	struct usb_hcd_ops *list;

	if (!ops)
		printf("Error");
	dprintf("Registering %s %d\n", ops->name, ops->usb_type);

	if (head) {
		list = head;
		while (list->next)
			list = list->next;
		list->next = ops;
	} else
		head = ops;
}

void usb_hcd_init(void *hcidev)
{
	struct usb_hcd_dev *dev = hcidev;
	struct usb_hcd_ops *list = head;

	if (!dev) {
		printf("Device Error");
		return;
	}

	while (list) {
		if (list->usb_type == dev->type) {
			dprintf("usb_ops(%p) for the controller found\n", list);
			dev->ops = list;
			dev->ops->init(dev);
			return;
		}
		list = list->next;
	}

	dprintf("usb_ops for the controller not found\n");
}

void usb_hcd_exit(void *_hcidev)
{
	struct usb_hcd_dev *hcidev = _hcidev;

	dprintf("%s: enter \n", __func__);
	if (!hcidev) {
		printf("Device Error");
		return;
	}

	if (hcidev->ops->exit)
		hcidev->ops->exit(hcidev);
}

int usb_send_ctrl(struct usb_pipe *pipe, struct usb_dev_req *req, void *data)
{
	struct usb_dev *dev = NULL;
	if (!pipe)
		return false;
	dev = pipe->dev;
	if (validate_hcd_ops(dev) && dev->hcidev->ops->send_ctrl)
		return dev->hcidev->ops->send_ctrl(pipe, req, data);
	else {
		printf("%s: Failed\n", __func__);
		return false;
	}
}

int usb_transfer_ctrl(void *dev, void *req, void *data)
{
	struct usb_pipe *pipe = NULL;
	struct usb_dev *usbdev;

	if (!dev)
		return false;
	usbdev = (struct usb_dev *)dev;
	pipe = usbdev->control;
	return usb_send_ctrl(pipe, req, data);
}

int usb_transfer_bulk(void *dev, int dir, void *td, void *td_phys, void *data, int size)
{
	struct usb_pipe *pipe = NULL;
	struct usb_dev *usbdev;

	if (!dev)
		return false;
	usbdev = (struct usb_dev *)dev;
	pipe = (dir == USB_PIPE_OUT) ? usbdev->bulk_out : usbdev->bulk_in;
	if (!pipe)
		return false;
	if (validate_hcd_ops(usbdev) && usbdev->hcidev->ops->transfer_bulk)
		return usbdev->hcidev->ops->transfer_bulk(pipe, td, td_phys, data, size);
	else {
		printf("%s: Failed\n", __func__);
		return false;
	}
}

/*
 * USB Specification 1.1
 *     9.3 USB Device Requests
 *     9.4 Standard Device Requests
 */
static int usb_set_address(struct usb_dev *dev, uint32_t port)
{
	struct usb_dev_req req;
	struct usb_hcd_dev *hcidev;

	if (!dev)
		return false;

	hcidev = dev->hcidev;
	req.bmRequestType = 0;
	req.bRequest = REQ_SET_ADDRESS;
	req.wIndex = 0;
	req.wLength = 0;
	req.wValue = cpu_to_le16((uint16_t)(hcidev->nextaddr));
	if (usb_send_ctrl(dev->control, &req, NULL)) {
		dev->addr = hcidev->nextaddr++;
		return true;
	} else
		return false;
}

static int usb_get_device_descr(struct usb_dev *dev, void *data, size_t size)
{
	struct usb_dev_req req;

	if (!dev)
		return false;

	req.bmRequestType = 0x80;
	req.bRequest = REQ_GET_DESCRIPTOR;
	req.wIndex = 0;
	req.wLength = cpu_to_le16((uint16_t) size);
	req.wValue = cpu_to_le16(DESCR_TYPE_DEVICE << 8);
	return usb_send_ctrl(dev->control, &req, data);
}

static int usb_get_config_descr(struct usb_dev *dev, void *data, size_t size)
{
	struct usb_dev_req req;

	if (!dev)
		return false;

	req.bmRequestType = 0x80;
	req.bRequest = REQ_GET_DESCRIPTOR;
	req.wIndex = 0;
	req.wLength = cpu_to_le16((uint16_t) size);
	req.wValue = cpu_to_le16(DESCR_TYPE_CONFIGURATION << 8);
	return usb_send_ctrl(dev->control, &req, data);

}

static int usb_set_config(struct usb_dev *dev, uint8_t cfg_value)
{
	struct usb_dev_req req;

	if (!dev)
		return false;

	req.bmRequestType = 0x00;
	req.bRequest = REQ_SET_CONFIGURATION;
	req.wIndex = 0;
	req.wLength = 0;
	req.wValue = cpu_to_le16(0x00FF & cfg_value);
	return usb_send_ctrl(dev->control, &req, NULL);
}

static int usb_clear_halt(struct usb_pipe *pipe)
{
	struct usb_dev_req req;
	struct usb_dev *dev;

	if (pipe && pipe->dev) {
		dev = pipe->dev;
		dprintf("Clearing port %d dir %d type %d\n",
			pipe->epno, pipe->dir, pipe->type);
		req.bmRequestType = REQT_DIR_OUT | REQT_REC_EP;
		req.bRequest = REQ_CLEAR_FEATURE;
		req.wValue = FEATURE_ENDPOINT_HALT;
		req.wIndex = cpu_to_le16(pipe->epno | pipe->dir);
		req.wLength = 0;
		return usb_send_ctrl(dev->control, &req, NULL);
	}
	return false;
}

int usb_dev_populate_pipe(struct usb_dev *dev, struct usb_ep_descr *ep,
			void *buf, size_t len)
{
	uint8_t dir, type;

	dir = (ep->bEndpointAddress & 0x80) >> 7;
	type = ep->bmAttributes & USB_EP_TYPE_MASK;

	dprintf("EP: %s: %d size %d type %d\n", dir ? "IN " : "OUT",
		ep->bEndpointAddress & 0xF, le16_to_cpu(ep->wMaxPacketSize),
		type);
	if (type == USB_EP_TYPE_BULK) {
		if (dir)
			dev->bulk_in = usb_get_pipe(dev, ep, buf, len);
		else
			dev->bulk_out = usb_get_pipe(dev, ep, buf, len);
	} else if (type == USB_EP_TYPE_INTR)
		dev->intr = usb_get_pipe(dev, ep, buf, len);

	return true;
}

static void usb_dev_copy_epdesc(struct usb_dev *dev, struct usb_ep_descr *ep)
{
	uint32_t ep_cnt;

	ep_cnt = dev->ep_cnt;
	if (ep_cnt < USB_DEV_EP_MAX)
		memcpy((void *)&dev->ep[ep_cnt], ep, sizeof(*ep));
	else
		dprintf("usb-core: only %d EPs supported\n", USB_DEV_EP_MAX);
	dev->ep_cnt++;
}

int usb_hid_init(void *vdev)
{
	struct usb_dev *dev;
	dev = (struct usb_dev *) vdev;
	if (!dev)
		return false;
	if (dev->class == DEV_HID_KEYB)
		usb_hid_kbd_init(dev);
	return true;
}

int usb_hid_exit(void *vdev)
{
	struct usb_dev *dev;
	dev = (struct usb_dev *) vdev;
	if (!dev)
		return false;
	if (dev->class == DEV_HID_KEYB)
		usb_hid_kbd_exit(dev);
	return true;
}

#define usb_get_intf_class(x) ((x & 0x00FF0000) >> 16)

int usb_msc_init(void *vdev)
{
	struct usb_dev *dev;
	int i;

	dev = (struct usb_dev *) vdev;
	dprintf("%s: enter %x\n", __func__, dev->class);
	if (!dev)
		return false;
	if (usb_get_intf_class(dev->class) == 8) {
		for (i = 0; i < dev->ep_cnt; i++) {
			if ((dev->ep[i].bmAttributes & USB_EP_TYPE_MASK)
				== USB_EP_TYPE_BULK)
				usb_dev_populate_pipe(dev, &dev->ep[i], NULL, 0);
		}
	}
	return true;
}

int usb_msc_exit(void *vdev)
{
	struct  usb_dev *dev;
	dev = (struct usb_dev *) vdev;
	dprintf("%s: enter %x\n", __func__, dev->class);
	if (!dev)
		return false;
	if (usb_get_intf_class(dev->class) == 8) {
		if (dev->bulk_in)
			usb_put_pipe(dev->bulk_in);
		if (dev->bulk_out)
			usb_put_pipe(dev->bulk_out);
	}
	return true;
}

static int usb_msc_reset(struct usb_dev *dev)
{
	struct usb_dev_req req;

	if (!dev)
		return false;

	req.bmRequestType = REQT_TYPE_CLASS | REQT_REC_INTERFACE | REQT_DIR_OUT;
	req.bRequest = 0xFF;
	req.wLength = 0;
	req.wValue = 0;
	req.wIndex = cpu_to_le16(dev->intf_num);
	return usb_send_ctrl(dev->control, &req, NULL);
}

void usb_msc_resetrecovery(struct usb_dev *dev)
{
	// usb_msc_reset(dev);
	usb_clear_halt(dev->bulk_in);
	usb_clear_halt(dev->bulk_out);
	SLOF_msleep(2);
}

static int usb_handle_device(struct usb_dev *dev, struct usb_dev_config_descr *cfg,
		uint8_t *ptr, uint16_t len)
{
	struct usb_dev_intf_descr *intf = NULL;
	struct usb_ep_descr *ep = NULL;
	struct usb_dev_hid_descr *hid __unused = NULL;
	uint8_t desc_len, desc_type;

	len -= sizeof(struct usb_dev_config_descr);
	ptr = (uint8_t *)(ptr + sizeof(struct usb_dev_config_descr));

	while (len > 0) {
		desc_len = *ptr;
		desc_type = *(ptr + 1);
		switch (desc_type) {
		case DESCR_TYPE_INTERFACE:
			intf = (struct usb_dev_intf_descr *)ptr;
			dev->class = intf->bInterfaceClass << 16 |
				intf->bInterfaceSubClass << 8 |
				intf->bInterfaceProtocol;
			break;
		case DESCR_TYPE_ENDPOINT:
			ep = (struct usb_ep_descr *)ptr;
			dev->intf_num = intf->bInterfaceNumber;
			usb_dev_copy_epdesc(dev, ep);
			break;
		case DESCR_TYPE_HID:
			hid = (struct usb_dev_hid_descr *)ptr;
			dprintf("hid-report %d size %d\n",
				hid->bReportType, le16_to_cpu(hid->wReportLength));
			break;
		case DESCR_TYPE_HUB:
			break;
		default:
			printf("ptr %p desc_type %d\n", ptr, desc_type);
		}
		ptr += desc_len;
		len -= desc_len;
	}
	return true;
}

int setup_new_device(struct usb_dev *dev, unsigned int port)
{
	struct usb_dev_descr descr;
	struct usb_dev_config_descr cfg;
	struct usb_ep_descr ep;
	uint16_t len;
	void *data = NULL;

	dprintf("usb: %s - port %d\n", __func__, port);

	dev->addr = 0;
	dev->port = port;
	ep.bEndpointAddress = 0;
	ep.bmAttributes = USB_EP_TYPE_CONTROL;
	ep.wMaxPacketSize = cpu_to_le16(8);
	dev->control = usb_get_pipe(dev, &ep, NULL, 0);

	if (!usb_get_device_descr(dev, &descr, 8))
		goto fail;
	dev->control->mps = descr.bMaxPacketSize0;

	/*
	 * For USB3.0 ADDRESS-SLOT command takes care of setting
	 * address, skip this during generic device setup for USB3.0
	 * devices
	 */
	if (dev->speed != USB_SUPER_SPEED) {
		/*
		 * Qemu starts the port number from 1 which was
		 * revealed in bootindex and resulted in mismatch for
		 * storage devices names. Adjusting this here for
		 * compatibility.
		 */
		dev->port = port + 1;
		if(!usb_set_address(dev, dev->port))
			goto fail;
	}
	mb();
	SLOF_msleep(100);

	if (!usb_get_device_descr(dev, &descr, sizeof(struct usb_dev_descr)))
		goto fail;

	if (!usb_get_config_descr(dev, &cfg, sizeof(struct usb_dev_config_descr)))
		goto fail;

	len = le16_to_cpu(cfg.wTotalLength);
	/* No device config descriptor present */
	if (len == sizeof(struct usb_dev_config_descr))
		goto fail;

	data = SLOF_dma_alloc(len);
	if (!data) {
		printf("%s: alloc failed %d\n", __func__, port);
		goto fail;
	}

	if (!usb_get_config_descr(dev, data, len))
		goto fail_mem_free;
	if (!usb_set_config(dev, cfg.bConfigurationValue))
		goto fail_mem_free;
	mb();
	SLOF_msleep(100);

	if (!usb_handle_device(dev, &cfg, data, len))
		goto fail_mem_free;

	switch (usb_get_intf_class(dev->class)) {
	case 3:
		dprintf("HID found %06X\n", dev->class);
		slof_usb_handle(dev);
		break;
	case 8:
		dprintf("MASS STORAGE found %d %06X\n", dev->intf_num,
			dev->class);
		if ((dev->class & 0x50) != 0x50) { /* Bulk-only supported */
			printf("Device not supported %06X\n", dev->class);
			goto fail_mem_free;
		}

		if (!usb_msc_reset(dev)) {
			printf("%s: bulk reset failed\n", __func__);
			goto fail_mem_free;
		}
		SLOF_msleep(100);
		slof_usb_handle(dev);
		break;
	case 9:
		dprintf("HUB found\n");
		slof_usb_handle(dev);
		break;
	default:
		printf("USB Interface class -%x- Not supported\n", dev->class);
		break;
	}

	SLOF_dma_free(data, len);
	return true;
fail_mem_free:
	SLOF_dma_free(data, len);
fail:
	return false;
}
