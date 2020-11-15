/******************************************************************************
 * Copyright (c) 2006, 2012, 2013 IBM Corporation
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
 * prototypes for libusb implementation used in libusb.code
 */

#ifndef __LIBUSB_H
#define __LIBUSB_H

/*******************************************/
/* SLOF:  USB-OHCI-REGISTER                */
/*******************************************/
extern void usb_ohci_register(void);
/*******************************************/
/* SLOF:  USB-EHCI-REGISTER                */
/*******************************************/
extern void usb_ehci_register(void);
/*******************************************/
/* SLOF:  USB-XHCI-REGISTER                */
/*******************************************/
extern void usb_xhci_register(void);
/*******************************************/
/* SLOF:  USB-HCD-INIT                     */
/*******************************************/
extern void usb_hcd_init(void *hcidev);
/*******************************************/
/* SLOF:  USB-HCD-EXIT                     */
/*******************************************/
extern void usb_hcd_exit(void *hcidev);
/*******************************************/
/* SLOF:  USB-HID-INIT                     */
/*******************************************/
extern int usb_hid_init(void *dev);
/*******************************************/
/* SLOF:  USB-HID-EXIT                     */
/*******************************************/
extern int usb_hid_exit(void *dev);
/*******************************************/
/* SLOF:  USB-READ-KEYB                    */
/*******************************************/
extern unsigned char usb_read_keyb(void *dev);
/*******************************************/
/* SLOF:  USB-KEY-AVAILABLE                */
/*******************************************/
extern unsigned char usb_key_available(void *dev);
/*******************************************/
/* SLOF:  USB-HUB-INIT                     */
/*******************************************/
extern unsigned int usb_hub_init(void *dev);
/*******************************************/
/* SLOF:  USB-MSC-INIT                     */
/*******************************************/
extern int usb_msc_init(void *dev);
/*******************************************/
/* SLOF:  USB-MSC-EXIT                     */
/*******************************************/
extern int usb_msc_exit(void *dev);
/*******************************************/
/* SLOF:  USB-TRANSFER-CTRL                */
/*******************************************/
extern int usb_transfer_ctrl(void *dev, void *req, void *data);
/*******************************************/
/* SLOF:  USB-TRANSFER-BULK                */
/*******************************************/
extern int usb_transfer_bulk(void *dev, int dir, void *td,
			void *td_phys, void *data, int size);

#endif
