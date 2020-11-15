/*
 * Copyright (C) 2010 Piotr Jaroszyński <p.jaroszynski@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _IPXE_LINUX_H
#define _IPXE_LINUX_H

FILE_LICENCE(GPL2_OR_LATER);

/** @file
 *
 * Linux devices, drivers and device requests.
 */

#include <ipxe/list.h>
#include <ipxe/device.h>
#include <ipxe/settings.h>

/**
 * Convert a Linux error number to an iPXE status code
 *
 * @v errno		Linux error number
 * @ret rc		iPXE status code (before negation)
 */
#define ELINUX( errno ) EPLATFORM ( EINFO_EPLATFORM, errno )

/** A linux device */
struct linux_device {
	/** Generic device */
	struct device dev;
	/** Driver that's handling the device */
	struct linux_driver *driver;
	/** Private data used by drivers */
	void *priv;
};

struct linux_device_request;

/** A linux driver */
struct linux_driver {
	/** Name */
	char *name;
	/** Probe function */
	int (*probe)(struct linux_device *device, struct linux_device_request *request);
	/** Remove function */
	void (*remove)(struct linux_device *device);
	/** Can the driver probe any more devices? */
	int can_probe;
};

/** Linux driver table */
#define LINUX_DRIVERS __table(struct linux_driver, "linux_drivers")

/** Declare a Linux driver */
#define __linux_driver __table_entry(LINUX_DRIVERS, 01)

/**
 * Set linux device driver-private data
 *
 * @v device	Linux device
 * @v priv		Private data
 */
static inline void linux_set_drvdata(struct linux_device * device, void *priv)
{
	device->priv = priv;
}

/**
 * Get linux device driver-private data
 *
 * @v device	Linux device
 * @ret priv	Private data
 */
static inline void *linux_get_drvdata(struct linux_device *device)
{
	return device->priv;
}

/**
 * A device request.
 *
 * To be created and filled by the UI code.
 */
struct linux_device_request {
	/** Driver name. Compared to the linux drivers' names */
	char *driver;
	/** List node */
	struct list_head list;
	/** List of settings */
	struct list_head settings;
};

/** A device request setting */
struct linux_setting {
	/** Name */
	char *name;
	/** Value */
	char *value;
	/** Was the setting already applied? */
	int applied;
	/** List node */
	struct list_head list;
};

/**
 * List of requested devices.
 *
 * Filled by the UI code. Linux root_driver walks over this list looking for an
 * appropriate driver to handle each request by matching the driver's name.
 */
extern struct list_head linux_device_requests;

/**
 * List of global settings to apply.
 *
 * Filled by the UI code. Linux root_driver applies these settings.
 */
extern struct list_head linux_global_settings;

/**
 * Look for the last occurrence of a setting with the specified name
 *
 * @v name     Name of the setting to look for
 * @v settings List of the settings to look through
 */
struct linux_setting *linux_find_setting(char *name, struct list_head *settings);

/**
 * Apply a list of linux settings to a settings block
 *
 * @v new_settings     List of linux_setting's to apply
 * @v settings_block   Settings block to apply the settings to
 * @ret rc             0 on success
 */
extern void linux_apply_settings(struct list_head *new_settings, struct settings *settings_block);


#endif /* _IPXE_LINUX_H */
