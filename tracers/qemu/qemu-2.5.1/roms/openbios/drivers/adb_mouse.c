/*
 *
 * Open Hack'Ware BIOS ADB mouse support, ported to OpenBIOS
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

#include "adb_bus.h"
#include "adb_mouse.h"

DECLARE_UNNAMED_NODE( mouse, INSTALL_OPEN, sizeof(int));

static void
mouse_open(int *idx)
{
	RET(-1);
}

static void
mouse_close(int *idx)
{
}

NODE_METHODS( mouse ) = {
	{ "open",		mouse_open		},
	{ "close",		mouse_close		},
};

void adb_mouse_new (char *path, void *private)
{
	char buf[64];
	int props[1];
	phandle_t ph, aliases;
	adb_dev_t *dev = private;

        snprintf(buf, sizeof(buf), "%s/mouse", path);
	REGISTER_NAMED_NODE( mouse, buf);

	ph = find_dev(buf);

	set_property(ph, "device_type", "mouse", 6);
	props[0] = __cpu_to_be32(dev->addr);
	set_property(ph, "reg", (char *)&props, sizeof(props));
	set_int_property(ph, "#buttons", 3);

	aliases = find_dev("/aliases");
	set_property(aliases, "adb-mouse", buf, strlen(buf) + 1);
}
