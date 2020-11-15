#ifndef _USB_KEYB_H
#define _USB_KEYB_H

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

#define BIT_0		1
#define BIT_1		(BIT_0 << 1)
#define BIT_2		(BIT_0 << 2)
#define BIT_3		(BIT_0 << 3)
#define BIT_4		(BIT_0 << 4)
#define BIT_5		(BIT_0 << 5)
#define BIT_6		(BIT_0 << 6)
#define BIT_7		(BIT_0 << 7)

/* bits from modifier input */
#define	MODIFIER_CTRL	(BIT_0 | BIT_4)
#define	MODIFIER_SHIFT	(BIT_1 | BIT_5)
#define	MODIFIER_ALT	(BIT_2 | BIT_6)
#define	MODIFIER_GUI	(BIT_3 | BIT_7)
#define	MODIFIER_ALT_GR	BIT_6

/* bits representing Keyboard-LEDs */
#define LED_NUM_LOCK	BIT_0
#define	LED_CAPS_LOCK	BIT_1
#define LED_SCROLL_LOCK	BIT_2

extern const uint8_t keycodes_std_US[];
extern const uint8_t keycodes_shift_US[];
extern const uint8_t keycodes_alt_GR[];
extern const uint8_t keycodes_ctrl[];

#endif
