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
#include <termctrl.h>

#include "usb-core.h"
#include "usb-key.h"

/*
 * HID Spec Version 1.11
 */

#define HID_REQ_GET_REPORT              0x01
#define HID_REQ_GET_IDLE                0x02
#define HID_REQ_GET_PROTOCOL            0x03
#define HID_REQ_SET_REPORT              0x09
#define HID_REQ_SET_IDLE                0x0A
#define HID_REQ_SET_PROTOCOL            0x0B

//key position for latin letters
#define KEYP_LATIN_A 4
#define KEYP_LATIN_Z 29

//#define KEY_DEBUG

/* HID SPEC - 7.2.6 Set_Protocol Request */
static int usb_hid_set_protocol(struct usb_dev *dev, uint16_t value)
{
	struct usb_dev_req req;
	if (!dev)
		return false;
	req.bmRequestType = REQT_TYPE_CLASS | REQT_REC_INTERFACE | REQT_DIR_OUT;
	req.bRequest = HID_REQ_SET_PROTOCOL;
	req.wValue = cpu_to_le16(value);
	req.wIndex = cpu_to_le16(dev->intf_num);
	req.wLength = 0;
	return usb_send_ctrl(dev->control, &req, NULL);
}

/* HID SPEC - 7.2.4 Set_Idle Request */
static int usb_hid_set_idle(struct usb_dev *dev, uint16_t ms_delay)
{
	struct usb_dev_req req;
	if (!dev)
		return false;
	req.bmRequestType = REQT_TYPE_CLASS | REQT_REC_INTERFACE | REQT_DIR_OUT;
	req.bRequest = HID_REQ_SET_IDLE;
	req.wValue = cpu_to_le16((ms_delay/4) << 8);
	req.wIndex = cpu_to_le16(dev->intf_num);
	req.wLength = 0;
	return usb_send_ctrl(dev->control, &req, NULL);
}

/* HID SPEC - 7.2.1 Get Report Request */
static int usb_hid_get_report(struct usb_dev *dev, void *data, size_t size)
{
	struct usb_dev_req req;
	if (!dev)
		return false;
	req.bmRequestType = REQT_TYPE_CLASS | REQT_REC_INTERFACE | REQT_DIR_IN;
	req.bRequest = HID_REQ_GET_REPORT;
	req.wIndex = cpu_to_le16(dev->intf_num);

	req.wLength = cpu_to_le16((uint16_t)size);
	req.wValue = cpu_to_le16(1 << 8);
	return usb_send_ctrl(dev->control, &req, data);
}

/* ring buffer with RD/WR indices for key buffering */
static uint8_t keybuf[256];	/* size fixed to byte range !   */
uint8_t r_ptr = 0;		/* RD-index for Keyboard-Buffer */
uint8_t w_ptr = 0;		/* WR-index for Keyboard-Buffer */

/* variables for LED status */
uint8_t set_leds;
const uint8_t *key_std       = NULL;
const uint8_t *key_std_shift = NULL;

uint8_t ctrl; /* modifiers */

/**
 * read character from Keyboard-Buffer
 *
 * @param   -
 * @return  > 0  Keycode
 *          = 0  if no key available
 */
static int read_key(void)
{
	if (r_ptr != w_ptr)
		return (int)keybuf[r_ptr++];
	else
		return false;
}

/**
 * Store character into Keyboard-Buffer
 *
 * @param   Key = detected ASCII-Key (> 0)
 * @return  -
 */
static void write_key(uint8_t key)
{
	if ((w_ptr + 1) != r_ptr)
		keybuf[w_ptr++] = key;
}

/**
 * Checks if keypos is a latin key
 * @param  keypos
 * @return -
 */
static bool is_latin(uint8_t keypos)
{
	return keypos >= KEYP_LATIN_A && keypos <= KEYP_LATIN_Z;
}

/**
 * Convert keyboard usage-ID to ANSI-Code
 *
 * @param   Ctrl=Modifier Byte
 *          Key =Usage ID from USB Keyboard
 * @return  -
 */
static void get_char(uint8_t ctrl, uint8_t keypos)
{
	uint8_t ch;
	bool caps = false;

#ifdef KEY_DEBUG
	printf("pos %02X\n", keypos);
#endif

	if (set_leds & LED_CAPS_LOCK)	                /* is CAPS Lock set ? */
		caps = true;

	/* caps is a shift only for latin chars */
	if ((!caps && ctrl == 0) || (caps && !is_latin(keypos))) {
		ch = key_std[keypos];
		if (ch != 0)
			write_key(ch);
		return;
	}

	if ((ctrl & MODIFIER_SHIFT) || caps) {
		ch = key_std_shift[keypos];
		if (ch != 0)
			write_key(ch);
		return;
	}

	if (ctrl & MODIFIER_CTRL) {
		ch = keycodes_ctrl[keypos];
		if (ch != 0)
			write_key(ch);
		return;
	}

	if (ctrl == MODIFIER_ALT_GR) {
		ch = keycodes_alt_GR[keypos];
		if (ch != 0)
			write_key(ch);
		return;
	}
}

static void check_key_code(uint8_t *buf)
{
	static uint8_t key_last[6];	            /* list of processed keys */
	uint8_t i, j, key_pos;

	/* set translation table to defaults */
	if ((key_std == NULL) || (key_std_shift == NULL)) {
		key_std       = keycodes_std_US;
		key_std_shift = keycodes_shift_US;
	}

	if (buf[0] & MODIFIER_SHIFT)	   /* any shift key pressed ? */
		set_leds &= ~LED_CAPS_LOCK;	  /* CAPS-LOCK-LED always off */

	i = 2;	/* skip modifier byte and reserved byte */
	while (i < 8) {
		key_pos = buf[i];
		if ((key_pos != 0) && (key_pos <= 100)) {    /* support for 101 keys */
			j = 0;
			/* search if already processed */
			while ((j < 6) && (key_pos != key_last[j]))
				j++;

			if (j >= 6) {	       /* not found (= not processed) */
				switch (key_pos) {
				case 0x39:	           /* caps-lock key ? */
				case 0x32:	           /* caps-lock key ? */
					set_leds ^= LED_CAPS_LOCK;
					break;

				case 0x36:		                /*Shift pressed*/
					ctrl |= MODIFIER_SHIFT;
					break;
				case 0xb6:		                /*Shift unpressed*/
					ctrl &= ~MODIFIER_SHIFT;
					break;
				case 0x3a:	                        /* F1 */
					write_key(0x1b);
					write_key(0x5b);
					write_key(0x4f);
					write_key(0x50);
					break;

				case 0x3b:		                /* F2 */
					write_key(0x1b);
					write_key(0x5b);
					write_key(0x4f);
					write_key(0x51);
					break;

				case 0x3c:
					write_key(0x1b);               /* F3 */
					write_key(0x5b);
					write_key(0x4f);
					write_key(0x52);
					break;

				case 0x3d:
					write_key(0x1b);		/* F4 */
					write_key(0x5b);
					write_key(0x4f);
					write_key(0x53);
					break;

				case 0x3e:
					write_key(0x1b);		/* F5 */
					write_key(0x5b);
					write_key(0x31);
					write_key(0x35);
					write_key(0x7e);
					break;

				case 0x3f:
					write_key(0x1b);		/* F6 */
					write_key(0x5b);
					write_key(0x31);
					write_key(0x37);
					write_key(0x7e);
					break;

				case 0x40:
					write_key(0x1b);		/* F7 */
					write_key(0x5b);
					write_key(0x31);
					write_key(0x38);
					write_key(0x7e);
					break;

				case 0x41:
					write_key(0x1b);		/* F8 */
					write_key(0x5b);
					write_key(0x31);
					write_key(0x39);
					write_key(0x7e);
					break;

				case 0x42:
					write_key(0x1b);		/* F9 */
					write_key(0x5b);
					write_key(0x32);
					write_key(0x30);
					write_key(0x7e);
					break;

				case 0x43:
					write_key(0x1b);	       /* F10 */
					write_key(0x5b);
					write_key(0x32);
					write_key(0x31);
					write_key(0x7e);
					break;

				case 0x44:
					write_key(0x1b);	       /* F11 */
					write_key(0x5b);
					write_key(0x32);
					write_key(0x33);
					write_key(0x7e);
					break;

				case 0x45:
					write_key(0x1b);	       /* F12 */
					write_key(0x5b);
					write_key(0x32);
					write_key(0x34);
					write_key(0x7e);
					break;

				case 0x47:	         /* scroll-lock key ? */
					set_leds ^= LED_SCROLL_LOCK;
					break;

				case 0x49:
					write_key(0x1b);	       /* INS */
					write_key(0x5b);
					write_key(0x32);
					write_key(0x7e);
					break;

				case 0x4a:
					write_key(0x1b);	      /* HOME */
					write_key(0x4f);
					write_key(0x48);
					break;

				case 0x4b:
					write_key(0x1b);	      /* PgUp */
					write_key(0x5b);
					write_key(0x35);
					write_key(0x7e);
					break;

				case 0x4c:
					write_key(0x1b);	       /* DEL */
					write_key(0x5b);
					write_key(0x33);
					write_key(0x7e);
					break;

				case 0x4d:
					write_key(0x1b);	       /* END */
					write_key(0x4f);
					write_key(0x46);
					break;

				case 0x4e:
					write_key(0x1b);	      /* PgDn */
					write_key(0x5b);
					write_key(0x36);
					write_key(0x7e);
					break;

				case 0x4f:
					write_key(0x1b);	   /* R-Arrow */
					write_key(0x5b);
					write_key(0x43);
					break;

				case 0x50:
					write_key(0x1b);	   /* L-Arrow */
					write_key(0x5b);
					write_key(0x44);
					break;

				case 0x51:
					write_key(0x1b);	   /* D-Arrow */
					write_key(0x5b);
					write_key(0x42);
					break;

				case 0x52:
					write_key(0x1b);	   /* U-Arrow */
					write_key(0x5b);
					write_key(0x41);
					break;

				case 0x53:	            /* num-lock key ? */
					set_leds ^= LED_NUM_LOCK;
					break;

				default:
					/* convert key position to ASCII code */
					get_char(buf[0], key_pos);
					break;
				}
			}
		}
		i++;
	}
	/*****************************************/
	/* all keys are processed, create a copy */
	/* to flag them as processed             */
	/*****************************************/
	for (i = 2, j = 0; j < 6; i++, j++)
		key_last[j] = buf[i];      /* copy all actual keys to last */
}

#define USB_HID_SIZE 128
uint32_t *kbd_buffer;

int usb_hid_kbd_init(struct usb_dev *dev)
{
	int i;
	uint8_t key[8];

	usb_hid_set_protocol(dev, 0);
	usb_hid_set_idle(dev, 500);

	memset(key, 0, 8);
	if (usb_hid_get_report(dev, key, 8))
		check_key_code(key);

	kbd_buffer = SLOF_dma_alloc(USB_HID_SIZE);
	if (!kbd_buffer) {
		printf("%s: unable to allocate keyboard buffer\n", __func__);
		return false;
	}

#ifdef KEY_DEBUG
	printf("HID kbd init %d\n", dev->ep_cnt);
#endif
	for (i = 0; i < dev->ep_cnt; i++) {
		if ((dev->ep[i].bmAttributes & USB_EP_TYPE_MASK)
			== USB_EP_TYPE_INTR)
			usb_dev_populate_pipe(dev, &dev->ep[i], kbd_buffer, USB_HID_SIZE);
	}
	return true;
}

int usb_hid_kbd_exit(struct usb_dev *dev)
{
	if (dev->intr) {
		usb_put_pipe(dev->intr);
		dev->intr = NULL;
	}
	SLOF_dma_free(kbd_buffer, USB_HID_SIZE);
	return true;
}

static int usb_poll_key(void *vdev)
{
	struct usb_dev *dev = vdev;
	uint8_t key[8];
	int rc;

	memset(key, 0, 8);
	rc = usb_poll_intr(dev->intr, key);
	if (rc)
		check_key_code(key);
	return rc;
}

unsigned char usb_key_available(void *dev)
{
	if (!dev)
		return false;

	usb_poll_key(dev);
	if (r_ptr != w_ptr)
		return true;
	else
		return false;
}

unsigned char usb_read_keyb(void *vdev)
{
	if (usb_key_available(vdev))
		return read_key();
	else
		return 0;
}
