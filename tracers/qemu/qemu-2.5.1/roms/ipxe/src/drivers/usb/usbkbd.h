#ifndef _USBKBD_H
#define _USBKBD_H

/** @file
 *
 * USB keyboard driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <assert.h>
#include <ipxe/usb.h>
#include <ipxe/usbhid.h>

/** Keyboard protocol */
#define USBKBD_PROTOCOL 1

/** A USB keyboard report */
struct usb_keyboard_report {
	/** Modifier keys */
	uint8_t modifiers;
	/** Reserved */
	uint8_t reserved;
	/** Keycodes */
	uint8_t keycode[6];
} __attribute__ (( packed ));

/** USB modifier keys */
enum usb_keyboard_modifier {
	/** Left Ctrl key */
	USBKBD_CTRL_LEFT = 0x01,
	/** Left Shift key */
	USBKBD_SHIFT_LEFT = 0x02,
	/** Left Alt key */
	USBKBD_ALT_LEFT = 0x04,
	/** Left GUI key */
	USBKBD_GUI_LEFT = 0x08,
	/** Right Ctrl key */
	USBKBD_CTRL_RIGHT = 0x10,
	/** Right Shift key */
	USBKBD_SHIFT_RIGHT = 0x20,
	/** Right Alt key */
	USBKBD_ALT_RIGHT = 0x40,
	/** Right GUI key */
	USBKBD_GUI_RIGHT = 0x80,
};

/** Either Ctrl key */
#define USBKBD_CTRL ( USBKBD_CTRL_LEFT | USBKBD_CTRL_RIGHT )

/** Either Shift key */
#define USBKBD_SHIFT ( USBKBD_SHIFT_LEFT | USBKBD_SHIFT_RIGHT )

/** Either Alt key */
#define USBKBD_ALT ( USBKBD_ALT_LEFT | USBKBD_ALT_RIGHT )

/** Either GUI key */
#define USBKBD_GUI ( USBKBD_GUI_LEFT | USBKBD_GUI_RIGHT )

/** USB keycodes */
enum usb_keycode {
	USBKBD_KEY_A = 0x04,
	USBKBD_KEY_Z = 0x1d,
	USBKBD_KEY_1 = 0x1e,
	USBKBD_KEY_0 = 0x27,
	USBKBD_KEY_ENTER = 0x28,
	USBKBD_KEY_SPACE = 0x2c,
	USBKBD_KEY_MINUS = 0x2d,
	USBKBD_KEY_SLASH = 0x38,
	USBKBD_KEY_CAPSLOCK = 0x39,
	USBKBD_KEY_UP = 0x52,
};

/** Keyboard idle duration (in 4ms units)
 *
 * This is a policy decision.  We choose to use an autorepeat rate of
 * approximately 40ms.
 */
#define USBKBD_IDLE_DURATION 10 /* 10 x 4ms = 40ms */

/** Keyboard auto-repeat hold-off (in units of USBKBD_IDLE_DURATION)
 *
 * This is a policy decision.  We choose to use an autorepeat delay of
 * approximately 500ms.
 */
#define USBKBD_HOLDOFF 12 /* 12 x 40ms = 480ms */

/** Interrupt endpoint maximum fill level
 *
 * When idling, we are likely to poll the USB endpoint at only the
 * 18.2Hz system timer tick rate.  With a typical observed bInterval
 * of 10ms (which will be rounded down to 8ms by the HCI drivers),
 * this gives approximately 7 completions per poll.
 */
#define USBKBD_INTR_MAX_FILL 8

/** Keyboard buffer size
 *
 * Must be a power of two.
 */
#define USBKBD_BUFSIZE 8

/** A USB keyboard device */
struct usb_keyboard {
	/** Name */
	const char *name;
	/** List of all USB keyboards */
	struct list_head list;

	/** USB bus */
	struct usb_bus *bus;
	/** USB human interface device */
	struct usb_hid hid;

	/** Most recent keyboard report */
	struct usb_keyboard_report report;
	/** Most recently pressed non-modifier key (if any) */
	unsigned int keycode;
	/** Autorepeat hold-off time (in number of completions reported) */
	unsigned int holdoff;

	/** Keyboard buffer
	 *
	 * This stores iPXE key values.
	 */
	unsigned int key[USBKBD_BUFSIZE];
	/** Keyboard buffer producer counter */
	unsigned int prod;
	/** Keyboard buffer consumer counter */
	unsigned int cons;
	/** Keyboard buffer sub-consumer counter
	 *
	 * This represents the index within the ANSI escape sequence
	 * corresponding to an iPXE key value.
	 */
	unsigned int subcons;
};

/**
 * Calculate keyboard buffer fill level
 *
 * @v kbd		USB keyboard
 * @ret fill		Keyboard buffer fill level
 */
static inline __attribute__ (( always_inline )) unsigned int
usbkbd_fill ( struct usb_keyboard *kbd ) {
	unsigned int fill = ( kbd->prod - kbd->cons );

	assert ( fill <= USBKBD_BUFSIZE );
	return fill;
}

#endif /* _USBKBD_H */
