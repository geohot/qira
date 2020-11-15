/******************************************************************************
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
/*
 * All functions concerning interface to slof
 */

#include <string.h>
#include "helpers.h"
#include "usb-core.h"
#include "paflof.h"

#undef SLOF_DEBUG
//#define SLOF_DEBUG
#ifdef SLOF_DEBUG
#define dprintf(_x ...) do { printf(_x); } while(0)
#else
#define dprintf(_x ...)
#endif

int slof_usb_handle(struct usb_dev *dev)
{
	struct slof_usb_dev sdev;
	sdev.port = dev->port;
	sdev.addr = dev->addr;
	sdev.hcitype = dev->hcidev->type;
	sdev.num  = dev->hcidev->num;
	sdev.udev  = dev;

	if (dev->class == DEV_HID_KEYB) {
		dprintf("Keyboard %ld %ld\n", dev->hcidev->type, dev->hcidev->num);
		sdev.devtype = DEVICE_KEYBOARD;
		forth_push((long)&sdev);
		forth_eval("s\" dev-keyb.fs\" INCLUDED");
	} else if (dev->class == DEV_HID_MOUSE) {
		dprintf("Mouse %ld %ld\n", dev->hcidev->type, dev->hcidev->num);
		sdev.devtype = DEVICE_MOUSE;
		forth_push((long)&sdev);
		forth_eval("s\" dev-mouse.fs\" INCLUDED");
	} else if ((dev->class >> 16 & 0xFF) == 8) {
		dprintf("MASS Storage device %ld %ld\n", dev->hcidev->type, dev->hcidev->num);
		sdev.devtype = DEVICE_DISK;
		forth_push((long)&sdev);
		forth_eval("s\" dev-storage.fs\" INCLUDED");
	} else if (dev->class == DEV_HUB) {
		dprintf("Generic hub device %ld %ld\n", dev->hcidev->type,
			dev->hcidev->num);
		sdev.devtype = DEVICE_HUB;
		forth_push((long)&sdev);
		forth_eval("s\" dev-hub.fs\" INCLUDED");
	}
	return true;
}
