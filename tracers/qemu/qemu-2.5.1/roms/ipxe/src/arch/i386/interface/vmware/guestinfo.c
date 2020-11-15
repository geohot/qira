/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

/** @file
 *
 * VMware GuestInfo settings
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ipxe/init.h>
#include <ipxe/settings.h>
#include <ipxe/netdevice.h>
#include <ipxe/guestrpc.h>

/** GuestInfo GuestRPC channel */
static int guestinfo_channel;

/**
 * Fetch value of typed GuestInfo setting
 *
 * @v settings		Settings block
 * @v setting		Setting to fetch
 * @v type		Setting type to attempt (or NULL for default)
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret found		Setting found in GuestInfo
 * @ret len		Length of setting data, or negative error
 */
static int guestinfo_fetch_type ( struct settings *settings,
				  struct setting *setting,
				  const struct setting_type *type,
				  void *data, size_t len, int *found ) {
	const char *parent_name = settings->parent->name;
	char command[ 24 /* "info-get guestinfo.ipxe." */ +
		      strlen ( parent_name ) + 1 /* "." */ +
		      strlen ( setting->name ) + 1 /* "." */ +
		      ( type ? strlen ( type->name ) : 0 ) + 1 /* NUL */ ];
	struct setting *predefined;
	char *info;
	int info_len;
	int check_len;
	int ret;

	/* Construct info-get command */
	snprintf ( command, sizeof ( command ),
		   "info-get guestinfo.ipxe.%s%s%s%s%s",
		   parent_name, ( parent_name[0] ? "." : "" ), setting->name,
		   ( type ? "." : "" ), ( type ? type->name : "" ) );

	/* Check for existence and obtain length of GuestInfo value */
	info_len = guestrpc_command ( guestinfo_channel, command, NULL, 0 );
	if ( info_len < 0 ) {
		ret = info_len;
		goto err_get_info_len;
	}

	/* Mark as found */
	*found = 1;

	/* Determine default type if necessary */
	if ( ! type ) {
		predefined = find_setting ( setting->name );
		type = ( predefined ? predefined->type : &setting_type_string );
	}
	assert ( type != NULL );

	/* Allocate temporary block to hold GuestInfo value */
	info = zalloc ( info_len + 1 /* NUL */ );
	if ( ! info ) {
		DBGC ( settings, "GuestInfo %p could not allocate %d bytes\n",
		       settings, info_len );
		ret = -ENOMEM;
		goto err_alloc;
	}
	info[info_len] = '\0';

	/* Fetch GuestInfo value */
	check_len = guestrpc_command ( guestinfo_channel, command,
				       info, info_len );
	if ( check_len < 0 ) {
		ret = check_len;
		goto err_get_info;
	}
	if ( check_len != info_len ) {
		DBGC ( settings, "GuestInfo %p length mismatch (expected %d, "
		       "got %d)\n", settings, info_len, check_len );
		ret = -EIO;
		goto err_get_info;
	}
	DBGC2 ( settings, "GuestInfo %p found %s = \"%s\"\n",
		settings, &command[9] /* Skip "info-get " */, info );

	/* Parse GuestInfo value according to type */
	ret = setting_parse ( type, info, data, len );
	if ( ret < 0 ) {
		DBGC ( settings, "GuestInfo %p could not parse \"%s\" as %s: "
		       "%s\n", settings, info, type->name, strerror ( ret ) );
		goto err_parse;
	}

 err_parse:
 err_get_info:
	free ( info );
 err_alloc:
 err_get_info_len:
	return ret;
}

/**
 * Fetch value of GuestInfo setting
 *
 * @v settings		Settings block
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int guestinfo_fetch ( struct settings *settings,
			     struct setting *setting,
			     void *data, size_t len ) {
	struct setting_type *type;
	int found = 0;
	int ret;

	/* Try default type first */
	ret = guestinfo_fetch_type ( settings, setting, NULL,
				     data, len, &found );
	if ( found )
		return ret;

	/* Otherwise, try all possible types */
	for_each_table_entry ( type, SETTING_TYPES ) {
		ret = guestinfo_fetch_type ( settings, setting, type,
					     data, len, &found );
		if ( found )
			return ret;
	}

	/* Not found */
	return -ENOENT;
}

/** GuestInfo settings operations */
static struct settings_operations guestinfo_settings_operations = {
	.fetch = guestinfo_fetch,
};

/** GuestInfo settings */
static struct settings guestinfo_settings = {
	.refcnt = NULL,
	.siblings = LIST_HEAD_INIT ( guestinfo_settings.siblings ),
	.children = LIST_HEAD_INIT ( guestinfo_settings.children ),
	.op = &guestinfo_settings_operations,
};

/** Initialise GuestInfo settings */
static void guestinfo_init ( void ) {
	int rc;

	/* Open GuestRPC channel */
	guestinfo_channel = guestrpc_open();
	if ( guestinfo_channel < 0 ) {
		rc = guestinfo_channel;
		DBG ( "GuestInfo could not open channel: %s\n",
		      strerror ( rc ) );
		return;
	}

	/* Register root GuestInfo settings */
	if ( ( rc = register_settings ( &guestinfo_settings, NULL,
					"vmware" ) ) != 0 ) {
		DBG ( "GuestInfo could not register settings: %s\n",
		      strerror ( rc ) );
		return;
	}
}

/** GuestInfo settings initialiser */
struct init_fn guestinfo_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = guestinfo_init,
};

/**
 * Create per-netdevice GuestInfo settings
 *
 * @v netdev		Network device
 * @ret rc		Return status code
 */
static int guestinfo_net_probe ( struct net_device *netdev ) {
	struct settings *settings;
	int rc;

	/* Do nothing unless we have a GuestInfo channel available */
	if ( guestinfo_channel < 0 )
		return 0;

	/* Allocate and initialise settings block */
	settings = zalloc ( sizeof ( *settings ) );
	if ( ! settings ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	settings_init ( settings, &guestinfo_settings_operations, NULL, NULL );

	/* Register settings */
	if ( ( rc = register_settings ( settings, netdev_settings ( netdev ),
					"vmware" ) ) != 0 ) {
		DBGC ( settings, "GuestInfo %p could not register for %s: %s\n",
		       settings, netdev->name, strerror ( rc ) );
		goto err_register;
	}
	DBGC ( settings, "GuestInfo %p registered for %s\n",
	       settings, netdev->name );

	return 0;

 err_register:
	free ( settings );
 err_alloc:
	return rc;
}

/**
 * Remove per-netdevice GuestInfo settings
 *
 * @v netdev		Network device
 */
static void guestinfo_net_remove ( struct net_device *netdev ) {
	struct settings *parent = netdev_settings ( netdev );
	struct settings *settings;

	list_for_each_entry ( settings, &parent->children, siblings ) {
		if ( settings->op == &guestinfo_settings_operations ) {
			DBGC ( settings, "GuestInfo %p unregistered for %s\n",
			       settings, netdev->name );
			unregister_settings ( settings );
			free ( settings );
			return;
		}
	}
}

/** GuestInfo per-netdevice driver */
struct net_driver guestinfo_net_driver __net_driver = {
	.name = "GuestInfo",
	.probe = guestinfo_net_probe,
	.remove = guestinfo_net_remove,
};
