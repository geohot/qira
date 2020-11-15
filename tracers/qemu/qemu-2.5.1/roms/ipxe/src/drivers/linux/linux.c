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

FILE_LICENCE(GPL2_OR_LATER);

/** @file
 *
 * Linux root_device and root_driver.
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ipxe/linux.h>
#include <ipxe/malloc.h>
#include <ipxe/settings.h>

LIST_HEAD(linux_device_requests);
LIST_HEAD(linux_global_settings);

/** Go over the device requests looking for a matching linux driver to handle them. */
static int linux_probe(struct root_device *rootdev)
{
	struct linux_device_request *request;
	struct linux_driver *driver;
	struct linux_device *device = NULL;
	int rc;

	/* Apply global settings */
	linux_apply_settings(&linux_global_settings, NULL);

	list_for_each_entry(request, &linux_device_requests, list) {
		if (! device)
			device = zalloc(sizeof(*device));

		if (! device)
			return -ENOMEM;

		rc = 1;

		for_each_table_entry(driver, LINUX_DRIVERS) {
			if ((rc = strcmp(driver->name, request->driver)) == 0)
				break;
		}

		if (rc != 0) {
			printf("Linux driver '%s' not found\n", request->driver);
			continue;
		}

		if (! driver->can_probe) {
			printf("Driver '%s' cannot handle any more devices\n", driver->name);
			continue;
		}

		/* We found a matching driver so add the device to the hierarchy */
		list_add(&device->dev.siblings, &rootdev->dev.children);
		device->dev.parent = &rootdev->dev;
		INIT_LIST_HEAD(&device->dev.children);

		if (driver->probe(device, request) == 0) {
			device->driver = driver;
			device->dev.driver_name = driver->name;
			/* Driver handled the device so release ownership */
			device = NULL;
		} else {
			/* Driver failed to handle the device so remove it from the hierarchy
			 * and reuse the object */
			list_del(&device->dev.siblings);
		}
	};

	free(device);

	return 0;
}

/** Remove all the linux devices registered in probe() */
static void linux_remove(struct root_device *rootdev)
{
	struct linux_device *device;
	struct linux_device *tmp;

	list_for_each_entry_safe(device, tmp, &rootdev->dev.children, dev.siblings) {
		list_del(&device->dev.siblings);
		device->driver->remove(device);
		free(device);
	}
}

/** Linux root driver */
static struct root_driver linux_root_driver = {
	.probe = linux_probe,
	.remove = linux_remove,
};

/** Linux root device */
struct root_device linux_root_device __root_device = {
	.dev = { .name = "linux" },
	.driver = &linux_root_driver,
};

struct linux_setting *linux_find_setting(char *name, struct list_head *settings)
{
	struct linux_setting *setting;
	struct linux_setting *result = NULL;

	/* Find the last occurrence of a setting with the specified name */
	list_for_each_entry(setting, settings, list) {
		if (strcmp(setting->name, name) == 0) {
			result = setting;
		}
	}

	return result;
}

void linux_apply_settings(struct list_head *new_settings, struct settings *settings_block)
{
	struct linux_setting *setting;
	int rc;

	list_for_each_entry(setting, new_settings, list) {
		/* Skip already applied settings */
		if (setting->applied)
			continue;

		struct setting *s = find_setting(setting->name);
		if (s) {
			rc = storef_setting(settings_block, find_setting(setting->name), setting->value);
			if (rc != 0)
				DBG("linux storing setting '%s' = '%s' failed\n", setting->name, setting->value);
			setting->applied = 1;
		} else {
			DBG("linux unknown setting '%s'\n", setting->name);
		}
	}
}
