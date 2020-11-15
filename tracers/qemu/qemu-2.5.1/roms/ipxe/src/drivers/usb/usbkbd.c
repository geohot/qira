/*
 * Copyright (C) 2015 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/console.h>
#include <ipxe/keys.h>
#include <ipxe/usb.h>
#include "usbkbd.h"

/** @file
 *
 * USB keyboard driver
 *
 */

/** List of USB keyboards */
static LIST_HEAD ( usb_keyboards );

/******************************************************************************
 *
 * Keyboard map
 *
 ******************************************************************************
 */

/**
 * Map USB keycode to iPXE key
 *
 * @v keycode		Keycode
 * @v modifiers		Modifiers
 * @ret key		iPXE key
 *
 * Key codes are defined in the USB HID Usage Tables Keyboard/Keypad
 * page.
 */
static unsigned int usbkbd_map ( unsigned int keycode,
				 unsigned int modifiers ) {
	unsigned int key;

	if ( keycode < USBKBD_KEY_A ) {
		/* Not keys */
		key = 0;
	} else if ( keycode <= USBKBD_KEY_Z ) {
		/* Alphabetic keys */
		key = ( keycode - USBKBD_KEY_A + 'a' );
		if ( modifiers & USBKBD_CTRL ) {
			key -= ( 'a' - CTRL_A );
		} else if ( modifiers & USBKBD_SHIFT ) {
			key -= ( 'a' - 'A' );
		}
	} else if ( keycode <= USBKBD_KEY_0 ) {
		/* Numeric key row */
		if ( modifiers & USBKBD_SHIFT ) {
			key = "!@#$%^&*()" [ keycode - USBKBD_KEY_1 ];
		} else {
			key = ( ( ( keycode - USBKBD_KEY_1 + 1 ) % 10 ) + '0' );
		}
	} else if ( keycode <= USBKBD_KEY_SPACE ) {
		/* Unmodifiable keys */
		static const uint8_t unmodifable[] =
			{ LF, ESC, BACKSPACE, TAB, ' ' };
		key = unmodifable[ keycode - USBKBD_KEY_ENTER ];
	} else if ( keycode <= USBKBD_KEY_SLASH ) {
		/* Punctuation keys */
		if ( modifiers & USBKBD_SHIFT ) {
			key = "_+{}|~:\"~<>?" [ keycode - USBKBD_KEY_MINUS ];
		} else {
			key = "-=[]\\#;'`,./" [ keycode - USBKBD_KEY_MINUS ];
		}
	} else if ( keycode <= USBKBD_KEY_UP ) {
		/* Special keys */
		static const uint16_t special[] = {
			0, 0, 0, 0, 0, KEY_F5, KEY_F6, KEY_F7, KEY_F8, KEY_F9,
			KEY_F10, KEY_F11, KEY_F12, 0, 0, 0, KEY_IC, KEY_HOME,
			KEY_PPAGE, KEY_DC, KEY_END, KEY_NPAGE, KEY_RIGHT,
			KEY_LEFT, KEY_DOWN, KEY_UP
		};
		key = special[ keycode - USBKBD_KEY_CAPSLOCK ];
	} else {
		key = 0;
	}

	return key;
}

/******************************************************************************
 *
 * Keyboard buffer
 *
 ******************************************************************************
 */

/**
 * Insert keypress into keyboard buffer
 *
 * @v kbd		USB keyboard
 * @v keycode		Keycode
 * @v modifiers		Modifiers
 */
static void usbkbd_produce ( struct usb_keyboard *kbd, unsigned int keycode,
			     unsigned int modifiers ) {
	unsigned int key;

	/* Map to iPXE key */
	key = usbkbd_map ( keycode, modifiers );

	/* Do nothing if this keycode has no corresponding iPXE key */
	if ( ! key ) {
		DBGC ( kbd, "KBD %s has no key for keycode %#02x:%#02x\n",
		       kbd->name, modifiers, keycode );
		return;
	}

	/* Check for buffer overrun */
	if ( usbkbd_fill ( kbd ) >= USBKBD_BUFSIZE ) {
		DBGC ( kbd, "KBD %s buffer overrun (key %#02x)\n",
		       kbd->name, key );
		return;
	}

	/* Insert into buffer */
	kbd->key[ ( kbd->prod++ ) % USBKBD_BUFSIZE ] = key;
	DBGC2 ( kbd, "KBD %s key %#02x produced\n", kbd->name, key );
}

/**
 * Consume character from keyboard buffer
 *
 * @v kbd		USB keyboard
 * @ret character	Character
 */
static unsigned int usbkbd_consume ( struct usb_keyboard *kbd ) {
	static char buf[] = "\x1b[xx~";
	char *tmp = &buf[2];
	unsigned int key;
	unsigned int character;
	unsigned int ansi_n;
	unsigned int len;

	/* Sanity check */
	assert ( usbkbd_fill ( kbd ) > 0 );

	/* Get current keypress */
	key = kbd->key[ kbd->cons % USBKBD_BUFSIZE ];

	/* If this is a straightforward key, just consume and return it */
	if ( key < KEY_MIN ) {
		kbd->cons++;
		DBGC2 ( kbd, "KBD %s key %#02x consumed\n", kbd->name, key );
		return key;
	}

	/* Construct ANSI sequence */
	ansi_n = KEY_ANSI_N ( key );
	if ( ansi_n )
		tmp += sprintf ( tmp, "%d", ansi_n );
	*(tmp++) = KEY_ANSI_TERMINATOR ( key );
	*tmp = '\0';
	len = ( tmp - buf );
	assert ( len < sizeof ( buf ) );
	if ( kbd->subcons == 0 ) {
		DBGC2 ( kbd, "KBD %s key %#02x consumed as ^[%s\n",
			kbd->name, key, &buf[1] );
	}

	/* Extract character from ANSI sequence */
	assert ( kbd->subcons < len );
	character = buf[ kbd->subcons++ ];

	/* Consume key if applicable */
	if ( kbd->subcons == len ) {
		kbd->cons++;
		kbd->subcons = 0;
	}

	return character;
}

/******************************************************************************
 *
 * Keyboard report
 *
 ******************************************************************************
 */

/**
 * Check for presence of keycode in report
 *
 * @v report		Keyboard report
 * @v keycode		Keycode (must be non-zero)
 * @ret has_keycode	Keycode is present in report
 */
static int usbkbd_has_keycode ( struct usb_keyboard_report *report,
				unsigned int keycode ) {
	unsigned int i;

	/* Check for keycode */
	for ( i = 0 ; i < ( sizeof ( report->keycode ) /
			    sizeof ( report->keycode[0] ) ) ; i++ ) {
		if ( report->keycode[i] == keycode )
			return keycode;
	}

	return 0;
}

/**
 * Handle keyboard report
 *
 * @v kbd		USB keyboard
 * @v new		New keyboard report
 */
static void usbkbd_report ( struct usb_keyboard *kbd,
			    struct usb_keyboard_report *new ) {
	struct usb_keyboard_report *old = &kbd->report;
	unsigned int keycode;
	unsigned int i;

	/* Check if current key has been released */
	if ( kbd->keycode && ! usbkbd_has_keycode ( new, kbd->keycode ) ) {
		DBGC2 ( kbd, "KBD %s keycode %#02x released\n",
			kbd->name, kbd->keycode );
		kbd->keycode = 0;
	}

	/* Decrement auto-repeat hold-off timer, if applicable */
	if ( kbd->holdoff )
		kbd->holdoff--;

	/* Check if a new key has been pressed */
	for ( i = 0 ; i < ( sizeof ( new->keycode ) /
			    sizeof ( new->keycode[0] ) ) ; i++ ) {

		/* Ignore keys present in the previous report */
		keycode = new->keycode[i];
		if ( ( keycode == 0 ) || usbkbd_has_keycode ( old, keycode ) )
			continue;
		DBGC2 ( kbd, "KBD %s keycode %#02x pressed\n",
			kbd->name, keycode );

		/* Insert keypress into keyboard buffer */
		usbkbd_produce ( kbd, keycode, new->modifiers );

		/* Record as most recent keycode */
		kbd->keycode = keycode;

		/* Start auto-repeat hold-off timer */
		kbd->holdoff = USBKBD_HOLDOFF;
	}

	/* Insert auto-repeated keypress into keyboard buffer, if applicable */
	if ( kbd->keycode && ! kbd->holdoff )
		usbkbd_produce ( kbd, kbd->keycode, new->modifiers );

	/* Record report */
	memcpy ( old, new, sizeof ( *old ) );
}

/******************************************************************************
 *
 * Interrupt endpoint
 *
 ******************************************************************************
 */

/**
 * Complete interrupt transfer
 *
 * @v ep		USB endpoint
 * @v iobuf		I/O buffer
 * @v rc		Completion status code
 */
static void usbkbd_complete ( struct usb_endpoint *ep,
			      struct io_buffer *iobuf, int rc ) {
	struct usb_keyboard *kbd = container_of ( ep, struct usb_keyboard,
						  hid.in );
	struct usb_keyboard_report *report;

	/* Ignore packets cancelled when the endpoint closes */
	if ( ! ep->open )
		goto drop;

	/* Ignore packets with errors */
	if ( rc != 0 ) {
		DBGC ( kbd, "KBD %s interrupt IN failed: %s\n",
		       kbd->name, strerror ( rc ) );
		goto drop;
	}

	/* Ignore underlength packets */
	if ( iob_len ( iobuf ) < sizeof ( *report ) ) {
		DBGC ( kbd, "KBD %s underlength report:\n", kbd->name );
		DBGC_HDA ( kbd, 0, iobuf->data, iob_len ( iobuf ) );
		goto drop;
	}
	report = iobuf->data;

	/* Handle keyboard report */
	usbkbd_report ( kbd, report );

 drop:
	/* Recycle I/O buffer */
	usb_recycle ( &kbd->hid.in, iobuf );
}

/** Interrupt endpoint operations */
static struct usb_endpoint_driver_operations usbkbd_operations = {
	.complete = usbkbd_complete,
};

/******************************************************************************
 *
 * USB interface
 *
 ******************************************************************************
 */

/**
 * Probe device
 *
 * @v func		USB function
 * @v config		Configuration descriptor
 * @ret rc		Return status code
 */
static int usbkbd_probe ( struct usb_function *func,
			  struct usb_configuration_descriptor *config ) {
	struct usb_device *usb = func->usb;
	struct usb_keyboard *kbd;
	int rc;

	/* Allocate and initialise structure */
	kbd = zalloc ( sizeof ( *kbd ) );
	if ( ! kbd ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	kbd->name = func->name;
	kbd->bus = usb->port->hub->bus;
	usbhid_init ( &kbd->hid, func, &usbkbd_operations, NULL );
	usb_refill_init ( &kbd->hid.in, sizeof ( kbd->report ),
			  USBKBD_INTR_MAX_FILL );

	/* Describe USB human interface device */
	if ( ( rc = usbhid_describe ( &kbd->hid, config ) ) != 0 ) {
		DBGC ( kbd, "KBD %s could not describe: %s\n",
		       kbd->name, strerror ( rc ) );
		goto err_describe;
	}
	DBGC ( kbd, "KBD %s using %s (len %zd)\n",
	       kbd->name, usb_endpoint_name ( &kbd->hid.in ), kbd->hid.in.mtu );

	/* Set boot protocol */
	if ( ( rc = usbhid_set_protocol ( usb, func->interface[0],
					  USBHID_PROTOCOL_BOOT ) ) != 0 ) {
		DBGC ( kbd, "KBD %s could not set boot protocol: %s\n",
		       kbd->name, strerror ( rc ) );
		goto err_set_protocol;
	}

	/* Set idle time */
	if ( ( rc = usbhid_set_idle ( usb, func->interface[0], 0,
				      USBKBD_IDLE_DURATION ) ) != 0 ) {
		DBGC ( kbd, "KBD %s could not set idle time: %s\n",
		       kbd->name, strerror ( rc ) );
		goto err_set_idle;
	}

	/* Open USB human interface device */
	if ( ( rc = usbhid_open ( &kbd->hid ) ) != 0 ) {
		DBGC ( kbd, "KBD %s could not open: %s\n",
		       kbd->name, strerror ( rc ) );
		goto err_open;
	}

	/* Add to list of USB keyboards */
	list_add_tail ( &kbd->list, &usb_keyboards );

	usb_func_set_drvdata ( func, kbd );
	return 0;

	usbhid_close ( &kbd->hid );
 err_open:
 err_set_idle:
 err_set_protocol:
 err_describe:
	free ( kbd );
 err_alloc:
	return rc;
}

/**
 * Remove device
 *
 * @v func		USB function
 */
static void usbkbd_remove ( struct usb_function *func ) {
	struct usb_keyboard *kbd = usb_func_get_drvdata ( func );

	/* Remove from list of USB keyboards */
	list_del ( &kbd->list );

	/* Close USB human interface device */
	usbhid_close ( &kbd->hid );

	/* Free device */
	free ( kbd );
}

/** USB keyboard device IDs */
static struct usb_device_id usbkbd_ids[] = {
	{
		.name = "kbd",
		.vendor = USB_ANY_ID,
		.product = USB_ANY_ID,
		.class = {
			.class = USB_CLASS_HID,
			.subclass = USB_SUBCLASS_HID_BOOT,
			.protocol = USBKBD_PROTOCOL,
		},
	},
};

/** USB keyboard driver */
struct usb_driver usbkbd_driver __usb_driver = {
	.ids = usbkbd_ids,
	.id_count = ( sizeof ( usbkbd_ids ) / sizeof ( usbkbd_ids[0] ) ),
	.probe = usbkbd_probe,
	.remove = usbkbd_remove,
};

/******************************************************************************
 *
 * Console interface
 *
 ******************************************************************************
 */

/**
 * Read a character from the console
 *
 * @ret character	Character read
 */
static int usbkbd_getchar ( void ) {
	struct usb_keyboard *kbd;

	/* Consume first available key */
	list_for_each_entry ( kbd, &usb_keyboards, list ) {
		if ( usbkbd_fill ( kbd ) )
			return usbkbd_consume ( kbd );
	}

	return 0;
}

/**
 * Check for available input
 *
 * @ret is_available	Input is available
 */
static int usbkbd_iskey ( void ) {
	struct usb_keyboard *kbd;
	unsigned int fill;

	/* Poll all USB keyboards and refill endpoints */
	list_for_each_entry ( kbd, &usb_keyboards, list ) {
		usb_poll ( kbd->bus );
		usb_refill ( &kbd->hid.in );
	}

	/* Check for a non-empty keyboard buffer */
	list_for_each_entry ( kbd, &usb_keyboards, list ) {
		fill = usbkbd_fill ( kbd );
		if ( fill )
			return fill;
	}

	return 0;
}

/** USB keyboard console */
struct console_driver usbkbd_console __console_driver = {
	.getchar = usbkbd_getchar,
	.iskey = usbkbd_iskey,
};
