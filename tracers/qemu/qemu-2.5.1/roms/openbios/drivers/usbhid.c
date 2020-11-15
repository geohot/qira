/*
 * Driver for HID devices ported from CoreBoot
 *
 * Copyright (C) 2014 BALATON Zoltan
 *
 * This file was part of the libpayload project.
 *
 * Copyright (C) 2008-2010 coresystems GmbH
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

#include "config.h"
#include "libopenbios/bindings.h"
#include <libc/string.h>
#include "libc/byteorder.h"
#include "libc/vsprintf.h"
#include "drivers/usb.h"
#include "usb.h"

DECLARE_UNNAMED_NODE(usb_kbd, INSTALL_OPEN, sizeof(int));

static void
keyboard_open(int *idx)
{
	RET(-1);
}

static void
keyboard_close(int *idx)
{
}

static void keyboard_read(void);

NODE_METHODS( usb_kbd ) = {
	{ "open",		keyboard_open		},
	{ "close",		keyboard_close		},
	{ "read",               keyboard_read		},
};

#ifdef CONFIG_USB_DEBUG
static const char *boot_protos[3] = { "(none)", "keyboard", "mouse" };
#endif
typedef enum { hid_proto_boot = 0, hid_proto_report = 1 } hid_proto;
enum { GET_REPORT = 0x1, GET_IDLE = 0x2, GET_PROTOCOL = 0x3, SET_REPORT =
		0x9, SET_IDLE = 0xa, SET_PROTOCOL = 0xb
};

typedef union {
	struct {
		u8 modifiers;
		u8 repeats;
		u8 keys[6];
	};
	u8 buffer[8];
} usb_hid_keyboard_event_t;

typedef struct {
	void* queue;
	hid_descriptor_t *descriptor;

	usb_hid_keyboard_event_t previous;
	int lastkeypress;
	int repeat_delay;
} usbhid_inst_t;

#define HID_INST(dev) ((usbhid_inst_t*)(dev)->data)

static void
usb_hid_destroy (usbdev_t *dev)
{
	if (HID_INST(dev)->queue) {
		int i;
		for (i = 0; i <= dev->num_endp; i++) {
			if (dev->endpoints[i].endpoint == 0)
				continue;
			if (dev->endpoints[i].type != INTERRUPT)
				continue;
			if (dev->endpoints[i].direction != IN)
				continue;
			break;
		}
		dev->controller->destroy_intr_queue(
				&dev->endpoints[i], HID_INST(dev)->queue);
		HID_INST(dev)->queue = NULL;
	}
	free (dev->data);
}

/* keybuffer is global to all USB keyboards */
static int keycount;
#define KEYBOARD_BUFFER_SIZE 16
static short keybuffer[KEYBOARD_BUFFER_SIZE];

const char *countries[36][2] = {
	{ "unknown", "us" },
	{ "Arabic", "ae" },
	{ "Belgian", "be" },
	{ "Canadian-Bilingual", "ca" },
	{ "Canadian-French", "ca" },
	{ "Czech Republic", "cz" },
	{ "Danish", "dk" },
	{ "Finnish", "fi" },
	{ "French", "fr" },
	{ "German", "de" },
	{ "Greek", "gr" },
	{ "Hebrew", "il" },
	{ "Hungary", "hu" },
	{ "International (ISO)", "iso" },
	{ "Italian", "it" },
	{ "Japan (Katakana)", "jp" },
	{ "Korean", "us" },
	{ "Latin American", "us" },
	{ "Netherlands/Dutch", "nl" },
	{ "Norwegian", "no" },
	{ "Persian (Farsi)", "ir" },
	{ "Poland", "pl" },
	{ "Portuguese", "pt" },
	{ "Russia", "ru" },
	{ "Slovakia", "sl" },
	{ "Spanish", "es" },
	{ "Swedish", "se" },
	{ "Swiss/French", "ch" },
	{ "Swiss/German", "ch" },
	{ "Switzerland", "ch" },
	{ "Taiwan", "tw" },
	{ "Turkish-Q", "tr" },
	{ "UK", "uk" },
	{ "US", "us" },
	{ "Yugoslavia", "yu" },
	{ "Turkish-F", "tr" },
	/* 36 - 255: Reserved */
};



struct layout_maps {
	const char *country;
	const short map[4][0x80];
};

static const struct layout_maps *map;

#define KEY_BREAK     0x101  /* Not on PC KBD */
#define KEY_DOWN      0x102  /* Down arrow key */
#define KEY_UP        0x103  /* Up arrow key */
#define KEY_LEFT      0x104  /* Left arrow key */
#define KEY_RIGHT     0x105  /* Right arrow key */
#define KEY_HOME      0x106  /* home key */
#define KEY_BACKSPACE 0x107  /* not on pc */
#define KEY_F0        0x108  /* function keys; 64 reserved */
#define KEY_F(n)      (KEY_F0 + (n))

#define KEY_DC        0x14a  /* delete character */
#define KEY_IC        0x14b  /* insert char or enter ins mode */

#define KEY_NPAGE     0x152  /* next page */
#define KEY_PPAGE     0x153  /* previous page */

#define KEY_ENTER     0x157  /* enter or send (unreliable) */

#define KEY_PRINT     0x15a  /* print/copy */

#define KEY_END       0x166  /* end key */

static const struct layout_maps keyboard_layouts[] = {
// #ifdef CONFIG_PC_KEYBOARD_LAYOUT_US
{ .country = "us", .map = {
	{ /* No modifier */
	-1, -1, -1, -1, 'a', 'b', 'c', 'd',
	'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
	/* 0x10 */
	'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
	'u', 'v', 'w', 'x', 'y', 'z', '1', '2',
	/* 0x20 */
	'3', '4', '5', '6', '7', '8', '9', '0',
	'\n', '\e', '\b', '\t', ' ', '-', '=', '[',
	/* 0x30 */
	']', '\\', -1, ';', '\'', '`', ',', '.',
	'/', -1 /* CapsLk */, KEY_F(1), KEY_F(2), KEY_F(3), KEY_F(4), KEY_F(5), KEY_F(6),
	/* 0x40 */
	KEY_F(7), KEY_F(8), KEY_F(9), KEY_F(10), KEY_F(11), KEY_F(12), KEY_PRINT, -1 /* ScrLk */,
	KEY_BREAK, KEY_IC, KEY_HOME, KEY_PPAGE, KEY_DC, KEY_END, KEY_NPAGE, KEY_RIGHT,
	/* 50 */
	KEY_LEFT, KEY_DOWN, KEY_UP, -1 /*NumLck*/, '/', '*', '-' /* = ? */, '+',
	KEY_ENTER, KEY_END, KEY_DOWN, KEY_NPAGE, KEY_LEFT, -1, KEY_RIGHT, KEY_HOME,
	/* 60 */
	KEY_UP, KEY_PPAGE, -1, KEY_DC, -1 /* < > | */, -1 /* Win Key Right */, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	/* 70 */
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	 },
	{ /* Shift modifier */
	-1, -1, -1, -1, 'A', 'B', 'C', 'D',
	'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
	/* 0x10 */
	'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z', '!', '@',
	/* 0x20 */
	'#', '$', '%', '^', '&', '*', '(', ')',
	'\n', '\e', '\b', '\t', ' ', '_', '+', '{',
	/* 0x30 */
	'}', '|', -1, ':', '"', '~', '<', '>',
	'?', -1 /* CapsLk */, KEY_F(1), KEY_F(2), KEY_F(3), KEY_F(4), KEY_F(5), KEY_F(6),
	/* 0x40 */
	KEY_F(7), KEY_F(8), KEY_F(9), KEY_F(10), KEY_F(11), KEY_F(12), KEY_PRINT, -1 /* ScrLk */,
	KEY_BREAK, KEY_IC, KEY_HOME, KEY_PPAGE, KEY_DC, KEY_END, KEY_NPAGE, KEY_RIGHT,
	/* 50 */
	KEY_LEFT, KEY_DOWN, KEY_UP, -1 /*NumLck*/, '/', '*', '-' /* = ? */, '+',
	KEY_ENTER, KEY_END, KEY_DOWN, KEY_NPAGE, KEY_LEFT, -1, KEY_RIGHT, KEY_HOME,
	/* 60 */
	KEY_UP, KEY_PPAGE, -1, KEY_DC, -1 /* < > | */, -1 /* Win Key Right */, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	/* 70 */
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	 },
	{ /* Alt */
	-1, -1, -1, -1, 'a', 'b', 'c', 'd',
	'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
	/* 0x10 */
	'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
	'u', 'v', 'w', 'x', 'y', 'z', '1', '2',
	/* 0x20 */
	'3', '4', '5', '6', '7', '8', '9', '0',
	'\n', '\e', '\b', '\t', ' ', '-', '=', '[',
	/* 0x30 */
	']', '\\', -1, ';', '\'', '`', ',', '.',
	'/', -1 /* CapsLk */, KEY_F(1), KEY_F(2), KEY_F(3), KEY_F(4), KEY_F(5), KEY_F(6),
	/* 0x40 */
	KEY_F(7), KEY_F(8), KEY_F(9), KEY_F(10), KEY_F(11), KEY_F(12), KEY_PRINT, -1 /* ScrLk */,
	KEY_BREAK, KEY_IC, KEY_HOME, KEY_PPAGE, KEY_DC, KEY_END, KEY_NPAGE, KEY_RIGHT,
	/* 50 */
	KEY_LEFT, KEY_DOWN, KEY_UP, -1 /*NumLck*/, '/', '*', '-' /* = ? */, '+',
	KEY_ENTER, KEY_END, KEY_DOWN, KEY_NPAGE, KEY_LEFT, -1, KEY_RIGHT, KEY_HOME,
	/* 60 */
	KEY_UP, KEY_PPAGE, -1, KEY_DC, -1 /* < > | */, -1 /* Win Key Right */, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	/* 70 */
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	 },
	{ /* Shift+Alt modifier */
	-1, -1, -1, -1, 'A', 'B', 'C', 'D',
	'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
	/* 0x10 */
	'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z', '!', '@',
	/* 0x20 */
	'#', '$', '%', '^', '&', '*', '(', ')',
	'\n', '\e', '\b', '\t', ' ', '-', '=', '[',
	/* 0x30 */
	']', '\\', -1, ':', '\'', '`', ',', '.',
	'/', -1 /* CapsLk */, KEY_F(1), KEY_F(2), KEY_F(3), KEY_F(4), KEY_F(5), KEY_F(6),
	/* 0x40 */
	KEY_F(7), KEY_F(8), KEY_F(9), KEY_F(10), KEY_F(11), KEY_F(12), KEY_PRINT, -1 /* ScrLk */,
	KEY_BREAK, KEY_IC, KEY_HOME, KEY_PPAGE, KEY_DC, KEY_END, KEY_NPAGE, KEY_RIGHT,
	/* 50 */
	KEY_LEFT, KEY_DOWN, KEY_UP, -1 /*NumLck*/, '/', '*', '-' /* = ? */, '+',
	KEY_ENTER, KEY_END, KEY_DOWN, KEY_NPAGE, KEY_LEFT, -1, KEY_RIGHT, KEY_HOME,
	/* 60 */
	KEY_UP, KEY_PPAGE, -1, KEY_DC, -1 /* < > | */, -1 /* Win Key Right */, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	/* 70 */
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	 }
}},
//#endif
};

#define MOD_SHIFT    (1 << 0)
#define MOD_ALT      (1 << 1)
#define MOD_CTRL     (1 << 2)

static void usb_hid_keyboard_queue(int ch) {
	/* ignore key presses if buffer full */
	if (keycount < KEYBOARD_BUFFER_SIZE)
		keybuffer[keycount++] = ch;
}

#define KEYBOARD_REPEAT_MS	30
#define INITIAL_REPEAT_DELAY	10
#define REPEAT_DELAY		 2

static void
usb_hid_process_keyboard_event(usbhid_inst_t *const inst,
		const usb_hid_keyboard_event_t *const current)
{
	const usb_hid_keyboard_event_t *const previous = &inst->previous;

	int i, keypress = 0, modifiers = 0;

	if (current->modifiers & 0x01) /* Left-Ctrl */   modifiers |= MOD_CTRL;
	if (current->modifiers & 0x02) /* Left-Shift */  modifiers |= MOD_SHIFT;
	if (current->modifiers & 0x04) /* Left-Alt */    modifiers |= MOD_ALT;
	if (current->modifiers & 0x08) /* Left-GUI */    ;
	if (current->modifiers & 0x10) /* Right-Ctrl */  modifiers |= MOD_CTRL;
	if (current->modifiers & 0x20) /* Right-Shift */ modifiers |= MOD_SHIFT;
	if (current->modifiers & 0x40) /* Right-AltGr */ modifiers |= MOD_ALT;
	if (current->modifiers & 0x80) /* Right-GUI */   ;

	/* Did the event change at all? */
	if (inst->lastkeypress &&
			!memcmp(current, previous, sizeof(*current))) {
		/* No. Then it's a key repeat event. */
		if (inst->repeat_delay) {
			inst->repeat_delay--;
		} else {
			usb_hid_keyboard_queue(inst->lastkeypress);
			inst->repeat_delay = REPEAT_DELAY;
		}

		return;
	}

	inst->lastkeypress = 0;

	for (i=0; i<6; i++) {
		int j;
		int skip = 0;
		// No more keys? skip
		if (current->keys[i] == 0)
			return;

		for (j=0; j<6; j++) {
			if (current->keys[i] == previous->keys[j]) {
				skip = 1;
				break;
			}
		}
		if (skip)
			continue;


		/* Mask off MOD_CTRL */
		keypress = map->map[modifiers & 0x03][current->keys[i]];

		if (modifiers & MOD_CTRL) {
			switch (keypress) {
			case 'a' ... 'z':
				keypress &= 0x1f;
				break;
			default:
				continue;
			}
		}

		if (keypress == -1) {
			/* Debug: Print unknown keys */
			usb_debug ("usbhid: <%x> %x [ %x %x %x %x %x %x ] %d\n",
				current->modifiers, current->repeats,
			current->keys[0], current->keys[1],
			current->keys[2], current->keys[3],
			current->keys[4], current->keys[5], i);

			/* Unknown key? Try next one in the queue */
			continue;
		}

		usb_hid_keyboard_queue(keypress);

		/* Remember for authentic key repeat */
		inst->lastkeypress = keypress;
		inst->repeat_delay = INITIAL_REPEAT_DELAY;
	}
}

static void
usb_hid_poll (usbdev_t *dev)
{
	usb_hid_keyboard_event_t current;
	const u8 *buf;

	while ((buf=dev->controller->poll_intr_queue (HID_INST(dev)->queue))) {
		memcpy(&current.buffer, buf, 8);
		usb_hid_process_keyboard_event(HID_INST(dev), &current);
		HID_INST(dev)->previous = current;
	}
}

static void
usb_hid_set_idle (usbdev_t *dev, interface_descriptor_t *interface, u16 duration)
{
	dev_req_t dr;
	dr.data_dir = host_to_device;
	dr.req_type = class_type;
	dr.req_recp = iface_recp;
	dr.bRequest = SET_IDLE;
	dr.wValue = __cpu_to_le16((duration >> 2) << 8);
	dr.wIndex = __cpu_to_le16(interface->bInterfaceNumber);
	dr.wLength = 0;
	dev->controller->control (dev, OUT, sizeof (dev_req_t), &dr, 0, 0);
}

static void
usb_hid_set_protocol (usbdev_t *dev, interface_descriptor_t *interface, hid_proto proto)
{
	dev_req_t dr;
	dr.data_dir = host_to_device;
	dr.req_type = class_type;
	dr.req_recp = iface_recp;
	dr.bRequest = SET_PROTOCOL;
	dr.wValue = __cpu_to_le16(proto);
	dr.wIndex = __cpu_to_le16(interface->bInterfaceNumber);
	dr.wLength = 0;
	dev->controller->control (dev, OUT, sizeof (dev_req_t), &dr, 0, 0);
}

static int usb_hid_set_layout (const char *country)
{
	/* FIXME should be per keyboard */
	int i;

	for (i=0; i<sizeof(keyboard_layouts)/sizeof(keyboard_layouts[0]); i++) {
		if (strncmp(keyboard_layouts[i].country, country,
					strlen(keyboard_layouts[i].country)))
			continue;

		/* Found, changing keyboard layout */
		map = &keyboard_layouts[i];
		usb_debug("  Keyboard layout '%s'\n", map->country);
		return 0;
	}

	usb_debug("  Keyboard layout '%s' not found, using '%s'\n",
			country, map->country);

	/* Nothing found, not changed */
	return -1;
}

void
usb_hid_init (usbdev_t *dev)
{
	configuration_descriptor_t *cd = (configuration_descriptor_t*)dev->configuration;
	interface_descriptor_t *interface = (interface_descriptor_t*)(((char *) cd) + cd->bLength);

	if (interface->bInterfaceSubClass == hid_subclass_boot) {
		u8 countrycode = 0;
		usb_debug ("  supports boot interface..\n");
		usb_debug ("  it's a %s\n",
			boot_protos[interface->bInterfaceProtocol]);
		switch (interface->bInterfaceProtocol) {
		case hid_boot_proto_keyboard:
			dev->data = malloc (sizeof (usbhid_inst_t));
			if (!dev->data) {
				printk("Not enough memory for USB HID device.\n");
				return;
                        }
			memset(&HID_INST(dev)->previous, 0x00,
			       sizeof(HID_INST(dev)->previous));
			usb_debug ("  configuring...\n");
			usb_hid_set_protocol(dev, interface, hid_proto_boot);
			usb_hid_set_idle(dev, interface, KEYBOARD_REPEAT_MS);
			usb_debug ("  activating...\n");
#if 0
			HID_INST (dev)->descriptor =
				(hid_descriptor_t *)
					get_descriptor(dev, gen_bmRequestType
					(device_to_host, standard_type, iface_recp),
					0x21, 0, 0);
			countrycode = HID_INST(dev)->descriptor->bCountryCode;
#endif
			/* 35 countries defined: */
			if (countrycode > 35)
				countrycode = 0;
			usb_debug ("  Keyboard has %s layout (country code %02x)\n",
					countries[countrycode][0], countrycode);

			/* Set keyboard layout accordingly */
			usb_hid_set_layout(countries[countrycode][1]);

			// only add here, because we only support boot-keyboard HID devices
			dev->destroy = usb_hid_destroy;
			dev->poll = usb_hid_poll;
			int i;
			for (i = 0; i <= dev->num_endp; i++) {
				if (dev->endpoints[i].endpoint == 0)
					continue;
				if (dev->endpoints[i].type != INTERRUPT)
					continue;
				if (dev->endpoints[i].direction != IN)
					continue;
				break;
			}
			usb_debug ("  found endpoint %x for interrupt-in\n", i);
			/* 20 buffers of 8 bytes, for every 10 msecs */
			HID_INST(dev)->queue = dev->controller->create_intr_queue (&dev->endpoints[i], 8, 20, 10);
			keycount = 0;
			usb_debug ("  configuration done.\n");
			break;
		default:
			usb_debug("NOTICE: HID interface protocol %d%s not supported.\n",
				 interface->bInterfaceProtocol,
				 (interface->bInterfaceProtocol == hid_boot_proto_mouse ?
				 " (USB mouse)" : ""));
			break;
		}
	}
}

static int usbhid_havechar (void)
{
	return (keycount != 0);
}

static int usbhid_getchar (void)
{
	short ret;

	if (keycount == 0)
		return 0;
	ret = keybuffer[0];
	memmove(keybuffer, keybuffer + 1, --keycount);

	return (int)ret;
}

/* ( addr len -- actual ) */
static void keyboard_read(void)
{
	char *addr;
	int len, key, i;

	usb_poll();
	len=POP();
	addr=(char *)cell2pointer(POP());

	for (i = 0; i < len; i++) {
	    if (!usbhid_havechar())
			break;
		key = usbhid_getchar();
		*addr++ = (char)key;
	}
	PUSH(i);
}

void ob_usb_hid_add_keyboard(const char *path)
{
	char name[128];
	phandle_t aliases;

	snprintf(name, sizeof(name), "%s/keyboard", path);
	usb_debug("Found keyboard at %s\n", name);
	REGISTER_NAMED_NODE(usb_kbd, name);

	push_str(name);
	fword("find-device");

	push_str("keyboard");
	fword("device-type");

	aliases = find_dev("/aliases");
	set_property(aliases, "adb-keyboard", name, strlen(name) + 1);
}
