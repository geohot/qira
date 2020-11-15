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

#include <hci/linux_args.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <ipxe/settings.h>
#include <ipxe/linux.h>
#include <ipxe/malloc.h>
#include <ipxe/init.h>

/** Saved argc */
static int saved_argc = 0;
/** Saved argv */
static char ** saved_argv;

/**
 * Save argc and argv for later access.
 *
 * To be called by linuxprefix
 */
__asmcall void save_args(int argc, char **argv)
{
	saved_argc = argc;
	saved_argv = argv;
}

/** Supported command-line options */
static struct option options[] = {
	{"net", 1, NULL, 'n'},
	{"settings", 1, NULL, 's'},
	{NULL, 0, NULL, 0}
};

/**
 * Parse k1=v1[,k2=v2]* into linux_settings
 */
static int parse_kv(char *kv, struct list_head *list)
{
	char *token;
	char *name;
	char *value;
	struct linux_setting *setting;

	while ((token = strsep(&kv, ",")) != NULL) {
		name = strsep(&token, "=");
		if (name == NULL)
			continue;
		value = token;
		if (value == NULL) {
			DBG("Bad parameter: '%s'\n", name);
			continue;
		}

		setting = malloc(sizeof(*setting));

		if (! setting)
			return -1;

		setting->name = name;
		setting->value = value;
		setting->applied = 0;
		list_add(&setting->list, list);
	}

	return 0;
}

/**
 * Parse --net arguments
 *
 * Format is --net driver_name[,name=value]*
 */
static int parse_net_args(char *args)
{
	char *driver;
	struct linux_device_request *dev_request;
	int rc;

	driver = strsep(&args, ",");

	if (strlen(driver) == 0) {
		printf("Missing driver name");
		return -1;
	}

	dev_request = malloc(sizeof(*dev_request));

	dev_request->driver = driver;
	INIT_LIST_HEAD(&dev_request->settings);
	list_add_tail(&dev_request->list, &linux_device_requests);

	/* Parse rest of the settings */
	rc = parse_kv(args, &dev_request->settings);

	if (rc)
		printf("Parsing net settings failed");

	return rc;
}

/**
 * Parse --settings arguments
 *
 * Format is --settings name=value[,name=value]*
 */
static int parse_settings_args(char *args)
{
	return parse_kv(args, &linux_global_settings);
}


/** Parse passed command-line arguments */
void linux_args_parse()
{
	int c;
	int rc;

	reset_getopt();
	while (1) {
		int option_index = 0;

		c = getopt_long(saved_argc, saved_argv, "", options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'n':
			if ((rc = parse_net_args(optarg)) != 0)
				return;
			break;
		case 's':
			if ((rc = parse_settings_args(optarg)) != 0)
				return;
			break;
		default:
			return;
		}
	}

	return;
}

/** Clean up requests and settings */
void linux_args_cleanup(int flags __unused)
{
	struct linux_device_request *request;
	struct linux_device_request *rtmp;
	struct linux_setting *setting;
	struct linux_setting *stmp;

	/* Clean up requests and their settings */
	list_for_each_entry_safe(request, rtmp, &linux_device_requests, list) {
		list_for_each_entry_safe(setting, stmp, &request->settings, list) {
			list_del(&setting->list);
			free(setting);
		}
		list_del(&request->list);
		free(request);
	}

	/* Clean up global settings */
	list_for_each_entry_safe(setting, stmp, &linux_global_settings, list) {
		list_del(&setting->list);
		free(setting);
	}
}

struct startup_fn startup_linux_args __startup_fn(STARTUP_EARLY) = {
	.startup = linux_args_parse,
	.shutdown = linux_args_cleanup,
};
