/*
 *
 * Open Hack'Ware BIOS ADB keyboard support, ported to OpenBIOS
 *
 *  Copyright (c) 2005 Jocelyn Mayer
 *  Copyright (c) 2005 Stefan Reinauer
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License V2
 *   as published by the Free Software Foundation
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA, 02110-1301 USA
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "libc/byteorder.h"
#include "libc/vsprintf.h"
#include "kbd.h"

#include "adb_bus.h"
#include "adb_kbd.h"

DECLARE_UNNAMED_NODE( keyboard, INSTALL_OPEN, sizeof(int));

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
static void keyboard_getkeymap(void);

NODE_METHODS( keyboard ) = {
	{ "open",		keyboard_open		},
	{ "close",		keyboard_close		},
	{ "read",               keyboard_read		},
	{ "get-key-map",	keyboard_getkeymap	},
};

/* VT100 escape sequences */

enum {
	KEY_UP = 0, KEY_DOWN, KEY_RIGHT, KEY_LEFT, KEY_PAGE_UP, KEY_PAGE_DOWN,
	KEY_DELETE, KEY_HOME, KEY_END, KEY_HELP,
	KEY_F1, KEY_F2, KEY_F3, KEY_F4, KEY_F5, KEY_F6, KEY_F7, KEY_F8,
	KEY_F9, KEY_F10, KEY_F11, KEY_F12, KEY_F13, KEY_F14, KEY_F15, KEY_F16
};

#define ADB_MAX_SEQUENCE_LEN	16

static const char *ADB_sequences[] = {
	[KEY_UP] = "A[",
	[KEY_DOWN] = "B[",
	[KEY_RIGHT] = "C[",
	[KEY_LEFT] = "D[",
	[KEY_PAGE_UP] = "~5[",
	[KEY_PAGE_DOWN] = "~6[",
	[KEY_DELETE] = "~3[",
	[KEY_HOME] = "HO",
	[KEY_END] = "FO",
	[KEY_HELP] = "~2[",
	[KEY_F1] = "PO",
	[KEY_F2] = "QO",
	[KEY_F3] = "RO",
	[KEY_F4] = "SO",
	[KEY_F5] = "~15[",
	[KEY_F6] = "~17[",
	[KEY_F7] = "~18[",
	[KEY_F8] = "~19[",
	[KEY_F9] = "~20[",
	[KEY_F10] = "~21[",
	[KEY_F11] = "~23[",
	[KEY_F12] = "~24[",
	[KEY_F13] = "~25[",
	[KEY_F14] = "~26[",
	[KEY_F15] = "~28[",
	[KEY_F15] = "~29[",
};

/* ADB US keyboard translation map */

static const keymap_t ADB_kbd_us[] = {
    /* 0x00 */
    { KBD_SH_CAPS, { 0x61, 0x41, 0x01,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x73, 0x53, 0x13,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x64, 0x44, 0x04,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x66, 0x46, 0x06,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x68, 0x48, 0x08,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x67, 0x47, 0x07,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x7A, 0x5A, 0x1A,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x78, 0x58, 0x18,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    /* 0x08 */
    { KBD_SH_CAPS, { 0x63, 0x43, 0x03,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x76, 0x56, 0x16,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x60, 0x40, 0x00,   -1,   -1,   -1,   -1,   -1, /* ? */
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x62, 0x42, 0x02,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x71, 0x51, 0x11,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x77, 0x57, 0x17,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x65, 0x45, 0x05,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x72, 0x52, 0x12,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    /* 0x10 */
    { KBD_SH_CAPS, { 0x79, 0x59, 0x19,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x74, 0x54, 0x14,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x31, 0x21,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x32, 0x40, 0x00,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x33, 0x23,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x34, 0x24,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x36, 0x5E, 0x1E,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x35, 0x25,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    /* 0x18 */
    { KBD_SH_CAPS, { 0x3D, 0x2B,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x39, 0x28,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x37, 0x26,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x2D, 0x5F, 0x1F,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x38, 0x2A,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x30, 0x29,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x5D, 0x7D,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x6F, 0x4F, 0x0F,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    /* 0x20 */
    { KBD_SH_CAPS, { 0x75, 0x55, 0x15,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x5B, 0x7B,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x69, 0x49, 0x09,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x70, 0x50, 0x10,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_MOD_MAP(0x0D), },
    { KBD_SH_CAPS, { 0x6C, 0x4C, 0x0C,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x6A, 0x4A, 0x0A,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x27, 0x22,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    /* 0x28 */
    { KBD_SH_CAPS, { 0x6B, 0x4B, 0x0B,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x3B, 0x3A,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x5C, 0x7C,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x2C, 0x3C,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x2F, 0x3F,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x6E, 0x4E, 0x0E,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x6D, 0x4D, 0x0D,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_CAPS, { 0x2E, 0x3E,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    /* 0x30 : tab */
    { KBD_MOD_MAP(0x09), },
    /* 0x31 : space */
    { KBD_MOD_MAP(0x20), },
    /* 0x32 : '<' '>' */
    { KBD_SH_CAPS, { 0x3C, 0x3E,   -1,   -1,   -1,   -1,   -1,   -1, /* ? */
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    /* 0x33 : backspace */
    { KBD_MOD_MAP(0x08), },
    { KBD_MAP_NONE, },
    /* 0x35 : ESC */
    { KBD_MOD_MAP(0x1B), },
    /* 0x36 : control */
    { KBD_MOD_MAP_LCTRL, },
    /* 0x37 : command */
    { KBD_MOD_MAP_LCMD,   },
    /* 0x38 : left shift */
    { KBD_MOD_MAP_LSHIFT, },
    /* 0x39 : caps-lock */
    { KBD_MOD_MAP_CAPS,   },
    /* 0x3A : option */
    { KBD_MOD_MAP_LOPT,   },
    /* 0x3B : left */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_LEFT)), },
    /* 0x3C : right */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_RIGHT)), },
    /* 0x3D : down */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_DOWN)), },
    /* 0x3E : up */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_UP)), },
    { KBD_MAP_NONE, },
    /* 0x40 */
    { KBD_MAP_NONE, },
    { KBD_SH_NUML, { 0x7F, 0x2E,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_MAP_NONE, },
    { KBD_SH_NONE, { 0x2A, 0x2A,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_MAP_NONE, },
    { KBD_SH_NONE, { 0x2B, 0x2B,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_MAP_NONE, },
    { KBD_MOD_MAP(0x7F), },
    /* 0x48 */
    { KBD_MAP_NONE, },
    { KBD_MAP_NONE, },
    { KBD_MAP_NONE, },
    { KBD_SH_NONE, { 0x2F, 0x2F,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_MOD_MAP(0x0D), },
    { KBD_MAP_NONE, },
    { KBD_SH_NONE, { 0x2D, 0x2D,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_MAP_NONE, },
    /* 0x50 */
    { KBD_MAP_NONE, },
    { KBD_SH_NONE, { 0x3D, 0x3D,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_NUML, {   -1, 0x30,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_NUML, {   -1, 0x31,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_NUML, {   -1, 0x32,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_NUML, {   -1, 0x33,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_NUML, {   -1, 0x34,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_NUML, {   -1, 0x35,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    /* 0x58 */
    { KBD_SH_NUML, {   -1, 0x36,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_NUML, {   -1, 0x37,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_MAP_NONE, },
    { KBD_SH_NUML, {   -1, 0x38,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_SH_NUML, {   -1, 0x39,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
                       -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1, }, },
    { KBD_MAP_NONE, },
    { KBD_MOD_MAP(0x2F), },
    { KBD_MAP_NONE, },
    /* 0x60 : F5 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F5)), },
    /* 0x61 : F6 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F6)), },
    /* 0x62 : F7 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F7)), },
    /* 0x63 : F3 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F3)), },
    /* 0x64 : F8 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F8)), },
    /* 0x65 : F9 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F9)), },
    { KBD_MAP_NONE, },
    /* 0x67 : F11 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F11)), },
    /* 0x68 */
    { KBD_MAP_NONE, },
    /* 0x69 : F13 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F13)), },
    { KBD_MAP_NONE, },
    /* 0x6B : F14 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F14)), },
    { KBD_MAP_NONE, },
    /* 0x6D : F10 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F10)), },
    { KBD_MAP_NONE, },
    /* 0x6F : F12 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F12)), },
    /* 0x70 */
    { KBD_MAP_NONE, },
    /* 0x71 : F15 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F15)), },
    /* 0x72 : help */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_HELP)), },
    /* 0x73 : home */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_HOME)), },
    /* 0x74 : page up */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_PAGE_UP)), },
    /* 0x75 : del */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_DELETE)), },
    /* 0x76 : F4 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F4)), },
    /* 0x77 : end */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_END)), },
    /* 0x78 : F2 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F2)), },
    /* 0x79 : page down */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_PAGE_UP)), },
    /* 0x7A : F1 */
    { KBD_MOD_MAP(KBD_SEQUENCE(KEY_F1)), },
    /* 0x7B : right shift */
    { KBD_MOD_MAP_RSHIFT, },
    /* 0x7C : right option */
    { KBD_MOD_MAP_ROPT,   },
    /* 0x7D : right control */
    { KBD_MOD_MAP_RCTRL, },
    { KBD_MAP_NONE, },
    /* 0x7F : power */
    { KBD_MAP_NONE, },
};

typedef struct adb_kbd_t adb_kbd_t;
struct adb_kbd_t {
    kbd_t kbd;
    int next_key;
    char sequence[ADB_MAX_SEQUENCE_LEN];
    int len;
    char keytable[32];
};

static adb_dev_t *my_adb_dev = NULL;

static int adb_kbd_read (void *private)
{
    uint8_t buffer[ADB_BUF_SIZE];
    adb_dev_t *dev = private;
    adb_kbd_t *kbd;
    int key;
    int ret;

    kbd = dev->state;

    if (kbd->len > 0) {
        ret = kbd->sequence[kbd->len-- - 1];
        ADB_DPRINTF("Buffered %d (%02x)\n", ret, ret);
	return ret;
    }

    /* Get saved state */
    ret = -1;
    for (key = -1; key == -1; ) {
        if (kbd->next_key != -1) {
            key = kbd->next_key;
            kbd->next_key = -1;
        } else {
            if (adb_reg_get(dev, 0, buffer) != 2)
		break;
            kbd->next_key = buffer[1] == 0xFF ? -1 : buffer[1];
            key = buffer[0];
        }
        ret = kbd_translate_key(&kbd->kbd, key & 0x7F, key >> 7, kbd->sequence);
	if (ret > 0) {
		kbd->len = ret;
        	ret = kbd->sequence[kbd->len-- - 1];
	}
		
        ADB_DPRINTF("Translated %d (%02x) into %d (%02x)\n",
                    key, key, ret, ret);
    }

    return ret;
}


void *adb_kbd_new (char *path, void *private)
{
	char buf[64];
	int props[1];
	phandle_t ph, aliases;
    adb_kbd_t *kbd;
    adb_dev_t *dev = private;
    kbd = (adb_kbd_t*)malloc(sizeof(adb_kbd_t));
    if (kbd != NULL) {
        memset(kbd, 0, sizeof(adb_kbd_t));
        kbd_set_keymap(&kbd->kbd, sizeof(ADB_kbd_us) / sizeof(keymap_t),
			ADB_kbd_us, ADB_sequences);
        kbd->next_key = -1;
        kbd->len = 0;
	
	/* Debugging BootX: the lines below force get-key-map to report that
	 * cmd-V is being held down, which forces BootX to run in verbose mode
	 * for debugging.
	 *
	 * TODO: if we can find a mapping between the get-key-map bitmap and
	 * ADB scancodes, the keyboard driver should be altered to update this
	 * accordingly.
	 */
	
	/*
	kbd->keytable[3] = 0x40;
	kbd->keytable[28] = 0x10;
	*/
	
	dev->state = kbd;
	my_adb_dev = dev;
    }

        snprintf(buf, sizeof(buf), "%s/keyboard", path);
	REGISTER_NAMED_NODE( keyboard, buf);

	ph = find_dev(buf);

	set_property(ph, "device_type", "keyboard", 9);
	props[0] = __cpu_to_be32(dev->addr);
	set_property(ph, "reg", (char *)&props, sizeof(props));

	aliases = find_dev("/aliases");
	set_property(aliases, "adb-keyboard", buf, strlen(buf) + 1);

    return kbd;
}

/* ( addr len -- actual ) */
static void keyboard_read(void)
{
	char *addr;
	int len, key, i;
	len=POP();
	addr=(char *)cell2pointer(POP());

	for (i = 0; i < len; i++) {
		key = adb_kbd_read(my_adb_dev);
		if (key == -1 || key == -2)
			break;
		*addr++ = (char)key;
	}
	PUSH(i);
}

/* ( -- keymap ) (?) */
/* should return a pointer to an array with 32 bytes (256 bits) */
static void keyboard_getkeymap(void)
{
	adb_kbd_t *kbd = my_adb_dev->state;
	
	PUSH( pointer2cell(kbd->keytable) );
}
