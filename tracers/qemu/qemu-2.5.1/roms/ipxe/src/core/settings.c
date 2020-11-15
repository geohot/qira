/*
 * Copyright (C) 2008 Michael Brown <mbrown@fensystems.co.uk>.
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
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <byteswap.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/in.h>
#include <ipxe/ip.h>
#include <ipxe/ipv6.h>
#include <ipxe/vsprintf.h>
#include <ipxe/dhcp.h>
#include <ipxe/uuid.h>
#include <ipxe/uri.h>
#include <ipxe/base16.h>
#include <ipxe/base64.h>
#include <ipxe/pci.h>
#include <ipxe/init.h>
#include <ipxe/version.h>
#include <ipxe/settings.h>

/** @file
 *
 * Configuration settings
 *
 */

/******************************************************************************
 *
 * Generic settings blocks
 *
 ******************************************************************************
 */

/**
 * A generic setting
 *
 */
struct generic_setting {
	/** List of generic settings */
	struct list_head list;
	/** Setting */
	struct setting setting;
	/** Size of setting name */
	size_t name_len;
	/** Size of setting data */
	size_t data_len;
};

/**
 * Get generic setting name
 *
 * @v generic		Generic setting
 * @ret name		Generic setting name
 */
static inline void * generic_setting_name ( struct generic_setting *generic ) {
	return ( ( ( void * ) generic ) + sizeof ( *generic ) );
}

/**
 * Get generic setting data
 *
 * @v generic		Generic setting
 * @ret data		Generic setting data
 */
static inline void * generic_setting_data ( struct generic_setting *generic ) {
	return ( ( ( void * ) generic ) + sizeof ( *generic ) +
		 generic->name_len );
}

/**
 * Find generic setting
 *
 * @v generics		Generic settings block
 * @v setting		Setting to find
 * @ret generic		Generic setting, or NULL
 */
static struct generic_setting *
find_generic_setting ( struct generic_settings *generics,
		       const struct setting *setting ) {
	struct generic_setting *generic;

	list_for_each_entry ( generic, &generics->list, list ) {
		if ( setting_cmp ( &generic->setting, setting ) == 0 )
			return generic;
	}
	return NULL;
}

/**
 * Store value of generic setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v data		Setting data, or NULL to clear setting
 * @v len		Length of setting data
 * @ret rc		Return status code
 */
int generic_settings_store ( struct settings *settings,
			     const struct setting *setting,
			     const void *data, size_t len ) {
	struct generic_settings *generics =
		container_of ( settings, struct generic_settings, settings );
	struct generic_setting *old;
	struct generic_setting *new = NULL;
	size_t name_len;

	/* Identify existing generic setting, if any */
	old = find_generic_setting ( generics, setting );

	/* Create new generic setting, if required */
	if ( len ) {
		/* Allocate new generic setting */
		name_len = ( strlen ( setting->name ) + 1 );
		new = zalloc ( sizeof ( *new ) + name_len + len );
		if ( ! new )
			return -ENOMEM;

		/* Populate new generic setting */
		new->name_len = name_len;
		new->data_len = len;
		memcpy ( &new->setting, setting, sizeof ( new->setting ) );
		new->setting.name = generic_setting_name ( new );
		memcpy ( generic_setting_name ( new ),
			 setting->name, name_len );
		memcpy ( generic_setting_data ( new ), data, len );
	}

	/* Delete existing generic setting, if any */
	if ( old ) {
		list_del ( &old->list );
		free ( old );
	}

	/* Add new setting to list, if any */
	if ( new )
		list_add ( &new->list, &generics->list );

	return 0;
}

/**
 * Fetch value of generic setting
 *
 * @v settings		Settings block
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
int generic_settings_fetch ( struct settings *settings,
			     struct setting *setting,
			     void *data, size_t len ) {
	struct generic_settings *generics =
		container_of ( settings, struct generic_settings, settings );
	struct generic_setting *generic;

	/* Find generic setting */
	generic = find_generic_setting ( generics, setting );
	if ( ! generic )
		return -ENOENT;

	/* Copy out generic setting data */
	if ( len > generic->data_len )
		len = generic->data_len;
	memcpy ( data, generic_setting_data ( generic ), len );

	/* Set setting type, if not yet specified */
	if ( ! setting->type )
		setting->type = generic->setting.type;

	return generic->data_len;
}

/**
 * Clear generic settings block
 *
 * @v settings		Settings block
 */
void generic_settings_clear ( struct settings *settings ) {
	struct generic_settings *generics =
		container_of ( settings, struct generic_settings, settings );
	struct generic_setting *generic;
	struct generic_setting *tmp;

	list_for_each_entry_safe ( generic, tmp, &generics->list, list ) {
		list_del ( &generic->list );
		free ( generic );
	}
	assert ( list_empty ( &generics->list ) );
}

/** Generic settings operations */
struct settings_operations generic_settings_operations = {
	.store = generic_settings_store,
	.fetch = generic_settings_fetch,
	.clear = generic_settings_clear,
};

/******************************************************************************
 *
 * Registered settings blocks
 *
 ******************************************************************************
 */

/** Root generic settings block */
struct generic_settings generic_settings_root = {
	.settings = {
		.refcnt = NULL,
		.name = "",
		.siblings =
		    LIST_HEAD_INIT ( generic_settings_root.settings.siblings ),
		.children =
		    LIST_HEAD_INIT ( generic_settings_root.settings.children ),
		.op = &generic_settings_operations,
	},
	.list = LIST_HEAD_INIT ( generic_settings_root.list ),
};

/** Root settings block */
#define settings_root generic_settings_root.settings

/** Autovivified settings block */
struct autovivified_settings {
	/** Reference count */
	struct refcnt refcnt;
	/** Generic settings block */
	struct generic_settings generic;
};

/**
 * Free autovivified settings block
 *
 * @v refcnt		Reference count
 */
static void autovivified_settings_free ( struct refcnt *refcnt ) {
	struct autovivified_settings *autovivified =
		container_of ( refcnt, struct autovivified_settings, refcnt );

	generic_settings_clear ( &autovivified->generic.settings );
	free ( autovivified );
}

/**
 * Find child settings block
 *
 * @v parent		Parent settings block
 * @v name		Name within this parent
 * @ret settings	Settings block, or NULL
 */
struct settings * find_child_settings ( struct settings *parent,
					const char *name ) {
	struct settings *settings;

	/* Find target parent settings block */
	parent = settings_target ( parent );

	/* Treat empty name as meaning "this block" */
	if ( ! *name )
		return parent;

	/* Look for child with matching name */
	list_for_each_entry ( settings, &parent->children, siblings ) {
		if ( strcmp ( settings->name, name ) == 0 )
			return settings_target ( settings );
	}

	return NULL;
}

/**
 * Find or create child settings block
 *
 * @v parent		Parent settings block
 * @v name		Name within this parent
 * @ret settings	Settings block, or NULL
 */
struct settings * autovivify_child_settings ( struct settings *parent,
					      const char *name ) {
	struct {
		struct autovivified_settings autovivified;
		char name[ strlen ( name ) + 1 /* NUL */ ];
	} *new_child;
	struct settings *settings;

	/* Find target parent settings block */
	parent = settings_target ( parent );

	/* Return existing settings, if existent */
	if ( ( settings = find_child_settings ( parent, name ) ) != NULL )
		return settings;

	/* Create new generic settings block */
	new_child = zalloc ( sizeof ( *new_child ) );
	if ( ! new_child ) {
		DBGC ( parent, "Settings %p could not create child %s\n",
		       parent, name );
		return NULL;
	}
	memcpy ( new_child->name, name, sizeof ( new_child->name ) );
	ref_init ( &new_child->autovivified.refcnt,
		   autovivified_settings_free );
	generic_settings_init ( &new_child->autovivified.generic,
				&new_child->autovivified.refcnt );
	settings = &new_child->autovivified.generic.settings;
	register_settings ( settings, parent, new_child->name );
	return settings;
}

/**
 * Return settings block name
 *
 * @v settings		Settings block
 * @ret name		Settings block name
 */
const char * settings_name ( struct settings *settings ) {
	static char buf[16];
	char tmp[ 1 /* '.' */ + sizeof ( buf ) ];

	/* Find target settings block */
	settings = settings_target ( settings );

	/* Construct name */
	buf[0] = '\0';
	tmp[0] = '\0';
	for ( ; settings->parent ; settings = settings->parent ) {
		memcpy ( ( tmp + 1 ), buf, ( sizeof ( tmp ) - 1 ) );
		snprintf ( buf, sizeof ( buf ), "%s%s", settings->name, tmp );
		tmp[0] = '.';
	}
	return buf;
}

/**
 * Parse settings block name
 *
 * @v name		Name
 * @v get_child		Function to find or create child settings block
 * @ret settings	Settings block, or NULL
 */
static struct settings *
parse_settings_name ( const char *name, get_child_settings_t get_child ) {
	struct settings *settings = &settings_root;
	char name_copy[ strlen ( name ) + 1 ];
	char *subname;
	char *remainder;

	/* Create modifiable copy of name */
	memcpy ( name_copy, name, sizeof ( name_copy ) );
	remainder = name_copy;

	/* Parse each name component in turn */
	while ( remainder ) {
		subname = remainder;
		remainder = strchr ( subname, '.' );
		if ( remainder )
			*(remainder++) = '\0';
		settings = get_child ( settings, subname );
		if ( ! settings )
			break;
	}

	return settings;
}

/**
 * Find settings block
 *
 * @v name		Name
 * @ret settings	Settings block, or NULL
 */
struct settings * find_settings ( const char *name ) {

	return parse_settings_name ( name, find_child_settings );
}

/**
 * Apply all settings
 *
 * @ret rc		Return status code
 */
static int apply_settings ( void ) {
	struct settings_applicator *applicator;
	int rc;

	/* Call all settings applicators */
	for_each_table_entry ( applicator, SETTINGS_APPLICATORS ) {
		if ( ( rc = applicator->apply() ) != 0 ) {
			DBG ( "Could not apply settings using applicator "
			      "%p: %s\n", applicator, strerror ( rc ) );
			return rc;
		}
	}

	return 0;
}

/**
 * Reprioritise settings
 *
 * @v settings		Settings block
 *
 * Reorders the settings block amongst its siblings according to its
 * priority.
 */
static void reprioritise_settings ( struct settings *settings ) {
	struct settings *parent = settings->parent;
	long priority;
	struct settings *tmp;
	long tmp_priority;

	/* Stop when we reach the top of the tree */
	if ( ! parent )
		return;

	/* Read priority, if present */
	priority = fetch_intz_setting ( settings, &priority_setting );

	/* Remove from siblings list */
	list_del ( &settings->siblings );

	/* Reinsert after any existing blocks which have a higher priority */
	list_for_each_entry ( tmp, &parent->children, siblings ) {
		tmp_priority = fetch_intz_setting ( tmp, &priority_setting );
		if ( priority > tmp_priority )
			break;
	}
	list_add_tail ( &settings->siblings, &tmp->siblings );

	/* Recurse up the tree */
	reprioritise_settings ( parent );
}

/**
 * Register settings block
 *
 * @v settings		Settings block
 * @v parent		Parent settings block, or NULL
 * @v name		Settings block name
 * @ret rc		Return status code
 */
int register_settings ( struct settings *settings, struct settings *parent,
			const char *name ) {
	struct settings *old_settings;

	/* Sanity check */
	assert ( settings != NULL );

	/* Find target parent settings block */
	parent = settings_target ( parent );

	/* Apply settings block name */
	settings->name = name;

	/* Remove any existing settings with the same name */
	if ( ( old_settings = find_child_settings ( parent, settings->name ) ))
		unregister_settings ( old_settings );

	/* Add to list of settings */
	ref_get ( settings->refcnt );
	ref_get ( parent->refcnt );
	settings->parent = parent;
	list_add_tail ( &settings->siblings, &parent->children );
	DBGC ( settings, "Settings %p (\"%s\") registered\n",
	       settings, settings_name ( settings ) );

	/* Fix up settings priority */
	reprioritise_settings ( settings );

	/* Apply potentially-updated settings */
	apply_settings();

	return 0;
}

/**
 * Unregister settings block
 *
 * @v settings		Settings block
 */
void unregister_settings ( struct settings *settings ) {
	struct settings *child;

	/* Unregister child settings */
	while ( ( child = list_first_entry ( &settings->children,
					     struct settings, siblings ) ) ) {
		unregister_settings ( child );
	}

	DBGC ( settings, "Settings %p (\"%s\") unregistered\n",
	       settings, settings_name ( settings ) );

	/* Remove from list of settings */
	ref_put ( settings->parent->refcnt );
	settings->parent = NULL;
	list_del ( &settings->siblings );
	ref_put ( settings->refcnt );

	/* Apply potentially-updated settings */
	apply_settings();
}

/******************************************************************************
 *
 * Core settings routines
 *
 ******************************************************************************
 */

/**
 * Redirect to target settings block
 *
 * @v settings		Settings block, or NULL
 * @ret settings	Underlying settings block
 */
struct settings * settings_target ( struct settings *settings ) {

	/* NULL settings implies the global settings root */
	if ( ! settings )
		settings = &settings_root;

	/* Redirect to underlying settings block, if applicable */
	if ( settings->op->redirect )
		return settings->op->redirect ( settings );

	/* Otherwise, return this settings block */
	return settings;
}

/**
 * Check applicability of setting
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @ret applies		Setting applies within this settings block
 */
int setting_applies ( struct settings *settings,
		      const struct setting *setting ) {

	/* Find target settings block */
	settings = settings_target ( settings );

	/* Check applicability of setting */
	return ( settings->op->applies ?
		 settings->op->applies ( settings, setting ) : 1 );
}

/**
 * Find setting applicable to settings block, if any
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @ret setting		Applicable setting, if any
 */
static const struct setting *
applicable_setting ( struct settings *settings, const struct setting *setting ){
	const struct setting *applicable;

	/* If setting is already applicable, use it */
	if ( setting_applies ( settings, setting ) )
		return setting;

	/* Otherwise, look for a matching predefined setting which does apply */
	for_each_table_entry ( applicable, SETTINGS ) {
		if ( ( setting_cmp ( setting, applicable ) == 0 ) &&
		     ( setting_applies ( settings, applicable ) ) )
			return applicable;
	}

	return NULL;
}

/**
 * Store value of setting
 *
 * @v settings		Settings block, or NULL
 * @v setting		Setting to store
 * @v data		Setting data, or NULL to clear setting
 * @v len		Length of setting data
 * @ret rc		Return status code
 */
int store_setting ( struct settings *settings, const struct setting *setting,
		    const void *data, size_t len ) {
	int rc;

	/* Find target settings block */
	settings = settings_target ( settings );

	/* Fail if setting does not apply to this settings block */
	if ( ! setting_applies ( settings, setting ) )
		return -ENOTTY;

	/* Sanity check */
	if ( ! settings->op->store )
		return -ENOTSUP;

	/* Store setting */
	if ( ( rc = settings->op->store ( settings, setting,
					  data, len ) ) != 0 )
		return rc;

	/* Reprioritise settings if necessary */
	if ( setting_cmp ( setting, &priority_setting ) == 0 )
		reprioritise_settings ( settings );

	/* If these settings are registered, apply potentially-updated
	 * settings
	 */
	for ( ; settings ; settings = settings->parent ) {
		if ( settings == &settings_root ) {
			if ( ( rc = apply_settings() ) != 0 )
				return rc;
			break;
		}
	}

	return 0;
}

/**
 * Fetch setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v origin		Origin of setting to fill in, or NULL
 * @v fetched		Fetched setting to fill in, or NULL
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 *
 * The actual length of the setting will be returned even if
 * the buffer was too small.
 */
int fetch_setting ( struct settings *settings, const struct setting *setting,
		    struct settings **origin, struct setting *fetched,
		    void *data, size_t len ) {
	const struct setting *applicable;
	struct settings *child;
	struct setting tmp;
	int ret;

	/* Avoid returning uninitialised data on error */
	memset ( data, 0, len );
	if ( origin )
		*origin = NULL;
	if ( fetched )
		memcpy ( fetched, setting, sizeof ( *fetched ) );

	/* Find target settings block */
	settings = settings_target ( settings );

	/* Sanity check */
	if ( ! settings->op->fetch )
		return -ENOTSUP;

	/* Try this block first, if an applicable setting exists */
	if ( ( applicable = applicable_setting ( settings, setting ) ) ) {

		/* Create modifiable copy of setting */
		memcpy ( &tmp, applicable, sizeof ( tmp ) );
		if ( ( ret = settings->op->fetch ( settings, &tmp,
						   data, len ) ) >= 0 ) {

			/* Default to string type, if not yet specified */
			if ( ! tmp.type )
				tmp.type = &setting_type_string;

			/* Record origin, if applicable */
			if ( origin )
				*origin = settings;

			/* Record fetched setting, if applicable */
			if ( fetched )
				memcpy ( fetched, &tmp, sizeof ( *fetched ) );

			return ret;
		}
	}

	/* Recurse into each child block in turn */
	list_for_each_entry ( child, &settings->children, siblings ) {
		if ( ( ret = fetch_setting ( child, setting, origin, fetched,
					     data, len ) ) >= 0 )
			return ret;
	}

	return -ENOENT;
}

/**
 * Fetch allocated copy of setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v origin		Origin of setting to fill in, or NULL
 * @v fetched		Fetched setting to fill in, or NULL
 * @v data		Buffer to allocate and fill with setting data
 * @v alloc		Allocation function
 * @ret len		Length of setting, or negative error
 *
 * The caller is responsible for eventually freeing the allocated
 * buffer.
 */
static int fetch_setting_alloc ( struct settings *settings,
				 const struct setting *setting,
				 struct settings **origin,
				 struct setting *fetched,
				 void **data,
				 void * ( * alloc ) ( size_t len ) ) {
	struct settings *tmp_origin;
	struct setting tmp_fetched;
	int len;
	int check_len;

	/* Use local buffers if necessary */
	if ( ! origin )
		origin = &tmp_origin;
	if ( ! fetched )
		fetched = &tmp_fetched;

	/* Avoid returning uninitialised data on error */
	*data = NULL;

	/* Check existence, and fetch setting length */
	len = fetch_setting ( settings, setting, origin, fetched, NULL, 0 );
	if ( len < 0 )
		return len;

	/* Allocate buffer */
	*data = alloc ( len );
	if ( ! *data )
		return -ENOMEM;

	/* Fetch setting value */
	check_len = fetch_setting ( *origin, fetched, NULL, NULL, *data, len );
	assert ( check_len == len );
	return len;
}

/**
 * Fetch copy of setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v origin		Origin of setting to fill in, or NULL
 * @v fetched		Fetched setting to fill in, or NULL
 * @v data		Buffer to allocate and fill with setting data
 * @ret len		Length of setting, or negative error
 *
 * The caller is responsible for eventually freeing the allocated
 * buffer.
 */
int fetch_setting_copy ( struct settings *settings,
			 const struct setting *setting,
			 struct settings **origin, struct setting *fetched,
			 void **data ) {

	return fetch_setting_alloc ( settings, setting, origin, fetched,
				     data, malloc );
}

/**
 * Fetch value of setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting string data
 * @v len		Length of buffer
 * @ret len		Length of setting, or negative error
 */
int fetch_raw_setting ( struct settings *settings,
			const struct setting *setting,
			void *data, size_t len ) {

	return fetch_setting ( settings, setting, NULL, NULL, data, len );
}

/**
 * Fetch value of setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v data		Buffer to allocate and fill with setting data
 * @ret len		Length of setting, or negative error
 *
 * The caller is responsible for eventually freeing the allocated
 * buffer.
 */
int fetch_raw_setting_copy ( struct settings *settings,
			     const struct setting *setting,
			     void **data ) {

	return fetch_setting_copy ( settings, setting, NULL, NULL, data );
}

/**
 * Fetch value of string setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting string data
 * @v len		Length of buffer
 * @ret len		Length of string setting, or negative error
 *
 * The resulting string is guaranteed to be correctly NUL-terminated.
 * The returned length will be the length of the underlying setting
 * data.
 */
int fetch_string_setting ( struct settings *settings,
			   const struct setting *setting,
			   char *data, size_t len ) {

	memset ( data, 0, len );
	return fetch_raw_setting ( settings, setting, data,
				   ( ( len > 0 ) ? ( len - 1 ) : 0 ) );
}

/**
 * Allocate memory for copy of string setting
 *
 * @v len		Length of setting
 * @ret ptr		Allocated memory
 */
static void * fetch_string_setting_copy_alloc ( size_t len ) {
	return zalloc ( len + 1 /* NUL */ );
}

/**
 * Fetch value of string setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v data		Buffer to allocate and fill with setting string data
 * @ret len		Length of string setting, or negative error
 *
 * The resulting string is guaranteed to be correctly NUL-terminated.
 * The returned length will be the length of the underlying setting
 * data.  The caller is responsible for eventually freeing the
 * allocated buffer.
 */
int fetch_string_setting_copy ( struct settings *settings,
				const struct setting *setting, char **data ) {

	return fetch_setting_alloc ( settings, setting, NULL, NULL,
				     ( ( void ** ) data ),
				     fetch_string_setting_copy_alloc );
}

/**
 * Fetch value of IPv4 address setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v inp		IPv4 addresses to fill in
 * @v count		Maximum number of IPv4 addresses
 * @ret len		Length of setting, or negative error
 */
int fetch_ipv4_array_setting ( struct settings *settings,
			       const struct setting *setting,
			       struct in_addr *inp, unsigned int count ) {
	int len;

	len = fetch_raw_setting ( settings, setting, inp,
				  ( sizeof ( *inp ) * count ) );
	if ( len < 0 )
		return len;
	if ( ( len % sizeof ( *inp ) ) != 0 )
		return -ERANGE;
	return len;
}

/**
 * Fetch value of IPv4 address setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v inp		IPv4 address to fill in
 * @ret len		Length of setting, or negative error
 */
int fetch_ipv4_setting ( struct settings *settings,
			 const struct setting *setting,
			 struct in_addr *inp ) {

	return fetch_ipv4_array_setting ( settings, setting, inp, 1 );
}

/**
 * Fetch value of IPv6 address setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v inp		IPv6 addresses to fill in
 * @v count		Maximum number of IPv6 addresses
 * @ret len		Length of setting, or negative error
 */
int fetch_ipv6_array_setting ( struct settings *settings,
			       const struct setting *setting,
			       struct in6_addr *inp, unsigned int count ) {
	int len;

	len = fetch_raw_setting ( settings, setting, inp,
				  ( sizeof ( *inp ) * count ) );
	if ( len < 0 )
		return len;
	if ( ( len % sizeof ( *inp ) ) != 0 )
		return -ERANGE;
	return len;
}

/**
 * Fetch value of IPv6 address setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v inp		IPv6 address to fill in
 * @ret len		Length of setting, or negative error
 */
int fetch_ipv6_setting ( struct settings *settings,
			 const struct setting *setting,
			 struct in6_addr *inp ) {

	return fetch_ipv6_array_setting ( settings, setting, inp, 1 );
}

/**
 * Extract numeric value of setting
 *
 * @v is_signed		Treat value as a signed integer
 * @v raw		Raw setting data
 * @v len		Length of raw setting data
 * @ret value		Numeric value
 * @ret len		Length of setting, or negative error
 */
static int numeric_setting_value ( int is_signed, const void *raw, size_t len,
				   unsigned long *value ) {
	const uint8_t *unsigned_bytes = raw;
	const int8_t *signed_bytes = raw;
	int is_negative;
	unsigned int i;
	uint8_t pad;
	uint8_t byte;

	/* Convert to host-ordered longs */
	is_negative = ( len && ( signed_bytes[0] < 0 ) );
	*value = ( ( is_signed && is_negative ) ? -1L : 0 );
	pad = *value;
	for ( i = 0 ; i < len ; i++ ) {
		byte = unsigned_bytes[i];
		*value = ( ( *value << 8 ) | byte );
		if ( ( ( i + sizeof ( *value ) ) < len ) && ( byte != pad ) )
			return -ERANGE;
	}

	return len;
}

/**
 * Fetch value of numeric setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v value		Integer value to fill in
 * @ret len		Length of setting, or negative error
 */
int fetch_numeric_setting ( struct settings *settings,
			    const struct setting *setting,
			    unsigned long *value, int is_signed ) {
	unsigned long tmp;
	int len;

	/* Avoid returning uninitialised data on error */
	*value = 0;

	/* Fetch raw (network-ordered, variable-length) setting */
	len = fetch_raw_setting ( settings, setting, &tmp, sizeof ( tmp ) );
	if ( len < 0 )
		return len;

	/* Extract numeric value */
	return numeric_setting_value ( is_signed, &tmp, len, value );
}

/**
 * Fetch value of signed integer setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v value		Integer value to fill in
 * @ret len		Length of setting, or negative error
 */
int fetch_int_setting ( struct settings *settings,
			const struct setting *setting,
			long *value ) {

	return fetch_numeric_setting ( settings, setting,
				       ( ( unsigned long * ) value ), 1 );
}

/**
 * Fetch value of unsigned integer setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v value		Integer value to fill in
 * @ret len		Length of setting, or negative error
 */
int fetch_uint_setting ( struct settings *settings,
			 const struct setting *setting,
			 unsigned long *value ) {

	return fetch_numeric_setting ( settings, setting, value, 0 );
}

/**
 * Fetch value of signed integer setting, or zero
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @ret value		Setting value, or zero
 */
long fetch_intz_setting ( struct settings *settings,
			  const struct setting *setting ) {
	unsigned long value;

	fetch_numeric_setting ( settings, setting, &value, 1 );
	return value;
}

/**
 * Fetch value of unsigned integer setting, or zero
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @ret value		Setting value, or zero
 */
unsigned long fetch_uintz_setting ( struct settings *settings,
				    const struct setting *setting ) {
	unsigned long value;

	fetch_numeric_setting ( settings, setting, &value, 0 );
	return value;
}

/**
 * Fetch value of UUID setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v uuid		UUID to fill in
 * @ret len		Length of setting, or negative error
 */
int fetch_uuid_setting ( struct settings *settings,
			 const struct setting *setting,
			 union uuid *uuid ) {
	int len;

	len = fetch_raw_setting ( settings, setting, uuid, sizeof ( *uuid ) );
	if ( len < 0 )
		return len;
	if ( len != sizeof ( *uuid ) )
		return -ERANGE;
	return len;
}

/**
 * Clear settings block
 *
 * @v settings		Settings block
 */
void clear_settings ( struct settings *settings ) {

	/* Find target settings block */
	settings = settings_target ( settings );

	/* Clear settings, if applicable */
	if ( settings->op->clear )
		settings->op->clear ( settings );
}

/**
 * Compare two settings
 *
 * @v a			Setting to compare
 * @v b			Setting to compare
 * @ret 0		Settings are the same
 * @ret non-zero	Settings are not the same
 */
int setting_cmp ( const struct setting *a, const struct setting *b ) {

	/* If the settings have tags, compare them */
	if ( a->tag && ( a->tag == b->tag ) && ( a->scope == b->scope ) )
		return 0;

	/* Otherwise, if the settings have names, compare them */
	if ( a->name && b->name && a->name[0] )
		return strcmp ( a->name, b->name );

	/* Otherwise, return a non-match */
	return ( ! 0 );
}

/******************************************************************************
 *
 * Formatted setting routines
 *
 ******************************************************************************
 */

/**
 * Format setting value as a string
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
int setting_format ( const struct setting_type *type, const void *raw,
		     size_t raw_len, char *buf, size_t len ) {

	/* Sanity check */
	if ( ! type->format )
		return -ENOTSUP;

	return type->format ( type, raw, raw_len, buf, len );
}

/**
 * Parse formatted string to setting value
 *
 * @v type		Setting type
 * @v value		Formatted setting value
 * @v buf		Buffer to contain raw value
 * @v len		Length of buffer
 * @ret len		Length of raw value, or negative error
 */
int setting_parse ( const struct setting_type *type, const char *value,
		    void *buf, size_t len ) {

	/* Sanity check */
	if ( ! type->parse )
		return -ENOTSUP;

	return type->parse ( type, value, buf, len );
}

/**
 * Convert setting value to number
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @ret value		Numeric value
 * @ret rc		Return status code
 */
int setting_numerate ( const struct setting_type *type, const void *raw,
		       size_t raw_len, unsigned long *value ) {

	/* Sanity check */
	if ( ! type->numerate )
		return -ENOTSUP;

	return type->numerate ( type, raw, raw_len, value );
}

/**
 * Convert number to setting value
 *
 * @v type		Setting type
 * @v value		Numeric value
 * @v buf		Buffer to contain raw value
 * @v len		Length of buffer
 * @ret len		Length of raw value, or negative error
 */
int setting_denumerate ( const struct setting_type *type, unsigned long value,
			 void *buf, size_t len ) {

	/* Sanity check */
	if ( ! type->denumerate )
		return -ENOTSUP;

	return type->denumerate ( type, value, buf, len );
}

/**
 * Fetch formatted value of setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v origin		Origin of setting to fill in, or NULL
 * @v fetched		Fetched setting to fill in, or NULL
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
int fetchf_setting ( struct settings *settings, const struct setting *setting,
		     struct settings **origin, struct setting *fetched,
		     char *buf, size_t len ) {
	struct setting tmp_fetched;
	void *raw;
	int raw_len;
	int ret;

	/* Use local buffers if necessary */
	if ( ! fetched )
		fetched = &tmp_fetched;

	/* Fetch raw value */
	raw_len = fetch_setting_copy ( settings, setting, origin, fetched,
				       &raw );
	if ( raw_len < 0 ) {
		ret = raw_len;
		goto err_fetch_copy;
	}

	/* Sanity check */
	assert ( fetched->type != NULL );

	/* Format setting */
	if ( ( ret = setting_format ( fetched->type, raw, raw_len, buf,
				      len ) ) < 0 )
		goto err_format;

 err_format:
	free ( raw );
 err_fetch_copy:
	return ret;
}

/**
 * Fetch copy of formatted value of setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v origin		Origin of setting to fill in, or NULL
 * @v fetched		Fetched setting to fill in, or NULL
 * @v value		Buffer to allocate and fill with formatted value
 * @ret len		Length of formatted value, or negative error
 *
 * The caller is responsible for eventually freeing the allocated
 * buffer.
 */
int fetchf_setting_copy ( struct settings *settings,
			  const struct setting *setting,
			  struct settings **origin, struct setting *fetched,
			  char **value ) {
	struct settings *tmp_origin;
	struct setting tmp_fetched;
	int len;
	int check_len;

	/* Use local buffers if necessary */
	if ( ! origin )
		origin = &tmp_origin;
	if ( ! fetched )
		fetched = &tmp_fetched;

	/* Avoid returning uninitialised data on error */
	*value = NULL;

	/* Check existence, and fetch formatted value length */
	len = fetchf_setting ( settings, setting, origin, fetched, NULL, 0 );
	if ( len < 0 )
		return len;

	/* Allocate buffer */
	*value = zalloc ( len + 1 /* NUL */ );
	if ( ! *value )
		return -ENOMEM;

	/* Fetch formatted value */
	check_len = fetchf_setting ( *origin, fetched, NULL, NULL, *value,
				     ( len + 1 /* NUL */ ) );
	assert ( check_len == len );
	return len;
}

/**
 * Store formatted value of setting
 *
 * @v settings		Settings block
 * @v setting		Setting to store
 * @v value		Formatted setting data, or NULL
 * @ret rc		Return status code
 */
int storef_setting ( struct settings *settings, const struct setting *setting,
		     const char *value ) {
	void *raw;
	int raw_len;
	int check_len;
	int rc;

	/* NULL value or empty string implies deletion */
	if ( ( ! value ) || ( ! value[0] ) )
		return delete_setting ( settings, setting );

	/* Sanity check */
	assert ( setting->type != NULL );

	/* Get raw value length */
	raw_len = setting_parse ( setting->type, value, NULL, 0 );
	if ( raw_len < 0 ) {
		rc = raw_len;
		goto err_raw_len;
	}

	/* Allocate buffer for raw value */
	raw = malloc ( raw_len );
	if ( ! raw ) {
		rc = -ENOMEM;
		goto err_alloc_raw;
	}

	/* Parse formatted value */
	check_len = setting_parse ( setting->type, value, raw, raw_len );
	assert ( check_len == raw_len );

	/* Store raw value */
	if ( ( rc = store_setting ( settings, setting, raw, raw_len ) ) != 0 )
		goto err_store;

 err_store:
	free ( raw );
 err_alloc_raw:
 err_raw_len:
	return rc;
}

/**
 * Fetch numeric value of setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @v origin		Origin of setting to fill in, or NULL
 * @v fetched		Fetched setting to fill in, or NULL
 * @v value		Numeric value to fill in
 * @ret rc		Return status code
 */
int fetchn_setting ( struct settings *settings, const struct setting *setting,
		     struct settings **origin, struct setting *fetched,
		     unsigned long *value ) {
	struct setting tmp_fetched;
	void *raw;
	int raw_len;
	int rc;

	/* Use local buffers if necessary */
	if ( ! fetched )
		fetched = &tmp_fetched;

	/* Fetch raw value */
	raw_len = fetch_setting_copy ( settings, setting, origin, fetched,
				       &raw );
	if ( raw_len < 0 ) {
		rc = raw_len;
		goto err_fetch_copy;
	}

	/* Sanity check */
	assert ( fetched->type != NULL );

	/* Numerate setting */
	if ( ( rc = setting_numerate ( fetched->type, raw, raw_len,
				       value ) ) < 0 )
		goto err_numerate;

 err_numerate:
	free ( raw );
 err_fetch_copy:
	return rc;
}

/**
 * Store numeric value of setting
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @v value		Numeric value
 * @ret rc		Return status code
 */
int storen_setting ( struct settings *settings, const struct setting *setting,
		     unsigned long value ) {
	void *raw;
	int raw_len;
	int check_len;
	int rc;

	/* Sanity check */
	assert ( setting->type != NULL );

	/* Get raw value length */
	raw_len = setting_denumerate ( setting->type, value, NULL, 0 );
	if ( raw_len < 0 ) {
		rc = raw_len;
		goto err_raw_len;
	}

	/* Allocate buffer for raw value */
	raw = malloc ( raw_len );
	if ( ! raw ) {
		rc = -ENOMEM;
		goto err_alloc_raw;
	}

	/* Denumerate value */
	check_len = setting_denumerate ( setting->type, value, raw, raw_len );
	assert ( check_len == raw_len );

	/* Store raw value */
	if ( ( rc = store_setting ( settings, setting, raw, raw_len ) ) != 0 )
		goto err_store;

 err_store:
	free ( raw );
 err_alloc_raw:
 err_raw_len:
	return rc;
}

/******************************************************************************
 *
 * Named settings
 *
 ******************************************************************************
 */

/**
 * Find predefined setting
 *
 * @v name		Name
 * @ret setting		Setting, or NULL
 */
struct setting * find_setting ( const char *name ) {
	struct setting *setting;

	for_each_table_entry ( setting, SETTINGS ) {
		if ( strcmp ( name, setting->name ) == 0 )
			return setting;
	}
	return NULL;
}

/**
 * Parse setting name as tag number
 *
 * @v name		Name
 * @ret tag		Tag number, or 0 if not a valid number
 */
static unsigned int parse_setting_tag ( const char *name ) {
	char *tmp = ( ( char * ) name );
	unsigned int tag = 0;

	while ( 1 ) {
		tag = ( ( tag << 8 ) | strtoul ( tmp, &tmp, 0 ) );
		if ( *tmp == 0 )
			return tag;
		if ( *tmp != '.' )
			return 0;
		tmp++;
	}
}

/**
 * Find setting type
 *
 * @v name		Name
 * @ret type		Setting type, or NULL
 */
static const struct setting_type * find_setting_type ( const char *name ) {
	const struct setting_type *type;

	for_each_table_entry ( type, SETTING_TYPES ) {
		if ( strcmp ( name, type->name ) == 0 )
			return type;
	}
	return NULL;
}

/**
 * Parse setting name
 *
 * @v name		Name of setting
 * @v get_child		Function to find or create child settings block
 * @v settings		Settings block to fill in
 * @v setting		Setting to fill in
 * @ret rc		Return status code
 *
 * Interprets a name of the form
 * "[settings_name/]tag_name[:type_name]" and fills in the appropriate
 * fields.
 *
 * Note that on success, this function will have modified the original
 * setting @c name.
 */
int parse_setting_name ( char *name, get_child_settings_t get_child,
			 struct settings **settings, struct setting *setting ) {
	char *settings_name;
	char *setting_name;
	char *type_name;
	struct setting *predefined;
	int rc;

	/* Set defaults */
	*settings = &settings_root;
	memset ( setting, 0, sizeof ( *setting ) );
	setting->name = "";

	/* Split name into "[settings_name/]setting_name[:type_name]" */
	if ( ( setting_name = strchr ( name, '/' ) ) != NULL ) {
		*(setting_name++) = 0;
		settings_name = name;
	} else {
		setting_name = name;
		settings_name = NULL;
	}
	if ( ( type_name = strchr ( setting_name, ':' ) ) != NULL )
		*(type_name++) = 0;

	/* Identify settings block, if specified */
	if ( settings_name ) {
		*settings = parse_settings_name ( settings_name, get_child );
		if ( *settings == NULL ) {
			DBG ( "Unrecognised settings block \"%s\" in \"%s\"\n",
			      settings_name, name );
			rc = -ENODEV;
			goto err;
		}
	}

	/* Identify setting */
	setting->tag = parse_setting_tag ( setting_name );
	setting->scope = (*settings)->default_scope;
	setting->name = setting_name;
	for_each_table_entry ( predefined, SETTINGS ) {
		/* Matches a predefined setting; use that setting */
		if ( setting_cmp ( predefined, setting ) == 0 ) {
			memcpy ( setting, predefined, sizeof ( *setting ) );
			break;
		}
	}

	/* Identify setting type, if specified */
	if ( type_name ) {
		setting->type = find_setting_type ( type_name );
		if ( setting->type == NULL ) {
			DBG ( "Invalid setting type \"%s\" in \"%s\"\n",
			      type_name, name );
			rc = -ENOTSUP;
			goto err;
		}
	}

	return 0;

 err:
	/* Restore original name */
	if ( settings_name )
		*( setting_name - 1 ) = '/';
	if ( type_name )
		*( type_name - 1 ) = ':';
	return rc;
}

/**
 * Return full setting name
 *
 * @v settings		Settings block, or NULL
 * @v setting		Setting
 * @v buf		Buffer
 * @v len		Length of buffer
 * @ret len		Length of setting name, or negative error
 */
int setting_name ( struct settings *settings, const struct setting *setting,
		   char *buf, size_t len ) {
	const char *name;

	settings = settings_target ( settings );
	name = settings_name ( settings );
	return snprintf ( buf, len, "%s%s%s:%s", name, ( name[0] ? "/" : "" ),
			  setting->name, setting->type->name );
}

/******************************************************************************
 *
 * Setting types
 *
 ******************************************************************************
 */

/**
 * Parse string setting value
 *
 * @v type		Setting type
 * @v value		Formatted setting value
 * @v buf		Buffer to contain raw value
 * @v len		Length of buffer
 * @ret len		Length of raw value, or negative error
 */
static int parse_string_setting ( const struct setting_type *type __unused,
				  const char *value, void *buf, size_t len ) {
	size_t raw_len = strlen ( value ); /* Exclude terminating NUL */

	/* Copy string to buffer */
	if ( len > raw_len )
		len = raw_len;
	memcpy ( buf, value, len );

	return raw_len;
}

/**
 * Format string setting value
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int format_string_setting ( const struct setting_type *type __unused,
				   const void *raw, size_t raw_len, char *buf,
				   size_t len ) {

	/* Copy string to buffer, and terminate */
	memset ( buf, 0, len );
	if ( len > raw_len )
		len = raw_len;
	memcpy ( buf, raw, len );

	return raw_len;
}

/** A string setting type */
const struct setting_type setting_type_string __setting_type = {
	.name = "string",
	.parse = parse_string_setting,
	.format = format_string_setting,
};

/** A URI-encoded string setting type
 *
 * This setting type is obsolete; the name ":uristring" is retained to
 * avoid breaking existing scripts.
 */
const struct setting_type setting_type_uristring __setting_type = {
	.name = "uristring",
	.parse = parse_string_setting,
	.format = format_string_setting,
};

/**
 * Parse IPv4 address setting value (when IPv4 support is not present)
 *
 * @v type		Setting type
 * @v value		Formatted setting value
 * @v buf		Buffer to contain raw value
 * @v len		Length of buffer
 * @ret len		Length of raw value, or negative error
 */
__weak int parse_ipv4_setting ( const struct setting_type *type __unused,
				const char *value __unused, void *buf __unused,
				size_t len __unused ) {
	return -ENOTSUP;
}

/**
 * Format IPv4 address setting value (when IPv4 support is not present)
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
__weak int format_ipv4_setting ( const struct setting_type *type __unused,
				 const void *raw __unused,
				 size_t raw_len __unused, char *buf __unused,
				 size_t len __unused ) {
	return -ENOTSUP;
}

/** An IPv4 address setting type */
const struct setting_type setting_type_ipv4 __setting_type = {
	.name = "ipv4",
	.parse = parse_ipv4_setting,
	.format = format_ipv4_setting,
};

/**
 * Parse IPv6 address setting value (when IPv6 support is not present)
 *
 * @v type		Setting type
 * @v value		Formatted setting value
 * @v buf		Buffer to contain raw value
 * @v len		Length of buffer
 * @ret len		Length of raw value, or negative error
 */
__weak int parse_ipv6_setting ( const struct setting_type *type __unused,
				const char *value __unused, void *buf __unused,
				size_t len __unused ) {
	return -ENOTSUP;
}

/**
 * Format IPv6 address setting value (when IPv6 support is not present)
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
__weak int format_ipv6_setting ( const struct setting_type *type __unused,
				 const void *raw __unused,
				 size_t raw_len __unused, char *buf __unused,
				 size_t len __unused ) {
	return -ENOTSUP;
}

/** An IPv6 address setting type */
const struct setting_type setting_type_ipv6 __setting_type = {
	.name = "ipv6",
	.parse = parse_ipv6_setting,
	.format = format_ipv6_setting,
};

/** IPv6 settings scope */
const struct settings_scope ipv6_scope;

/**
 * Integer setting type indices
 *
 * These indexes are defined such that (1<<index) gives the width of
 * the integer, in bytes.
 */
enum setting_type_int_index {
	SETTING_TYPE_INT8 = 0,
	SETTING_TYPE_INT16 = 1,
	SETTING_TYPE_INT32 = 2,
};

/**
 * Integer setting type names
 *
 * These names exist as a static array in order to allow the type's
 * integer size and signedness to be determined from the type's name.
 * Note that there are no separate entries for the signed integer
 * types: the name pointers simply point to the second character of
 * the relevant string.
 */
static const char setting_type_int_name[][8] = {
	[SETTING_TYPE_INT8] = "uint8",
	[SETTING_TYPE_INT16] = "uint16",
	[SETTING_TYPE_INT32] = "uint32",
};

/**
 * Get unsigned integer setting type name
 *
 * @v index		Integer setting type index
 * @ret name		Setting type name
 */
#define SETTING_TYPE_UINT_NAME( index ) setting_type_int_name[index]

/**
 * Get signed integer setting type name
 *
 * @v index		Integer setting type index
 * @ret name		Setting type name
 */
#define SETTING_TYPE_INT_NAME( index ) ( setting_type_int_name[index] + 1 )

/**
 * Get integer setting type index
 *
 * @v type		Setting type
 * @ret index		Integer setting type index
 */
static unsigned int setting_type_int_index ( const struct setting_type *type ) {

	return ( ( type->name - setting_type_int_name[0] ) /
		 sizeof ( setting_type_int_name[0] ) );
}

/**
 * Get integer setting type width
 *
 * @v type		Setting type
 * @ret index		Integer setting type width
 */
static unsigned int setting_type_int_width ( const struct setting_type *type ) {

	return ( 1 << setting_type_int_index ( type ) );
}

/**
 * Get integer setting type signedness
 *
 * @v type		Setting type
 * @ret is_signed	Integer setting type is signed
 */
static int setting_type_int_is_signed ( const struct setting_type *type ) {
	return ( ( type->name - setting_type_int_name[0] ) & 1 );
}

/**
 * Convert number to setting value
 *
 * @v type		Setting type
 * @v value		Numeric value
 * @v buf		Buffer to contain raw value
 * @v len		Length of buffer
 * @ret len		Length of raw value, or negative error
 */
static int denumerate_int_setting ( const struct setting_type *type,
				    unsigned long value, void *buf,
				    size_t len ) {
	unsigned int size = setting_type_int_width ( type );
	union {
		uint32_t num;
		uint8_t bytes[4];
	} u;

	u.num = htonl ( value );
	if ( len > size )
		len = size;
	memcpy ( buf, &u.bytes[ sizeof ( u ) - size ], len );

	return size;
}

/**
 * Convert setting value to number
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v value		Numeric value to fill in
 * @ret rc		Return status code
 */
static int numerate_int_setting ( const struct setting_type *type,
				  const void *raw, size_t raw_len,
				  unsigned long *value ) {
	int is_signed = setting_type_int_is_signed ( type );
	int check_len;

	/* Extract numeric value */
	check_len = numeric_setting_value ( is_signed, raw, raw_len, value );
	if ( check_len < 0 )
		return check_len;
	assert ( check_len == ( int ) raw_len );

	return 0;
}

/**
 * Parse integer setting value
 *
 * @v type		Setting type
 * @v value		Formatted setting value
 * @v buf		Buffer to contain raw value
 * @v len		Length of buffer
 * @ret len		Length of raw value, or negative error
 */
static int parse_int_setting ( const struct setting_type *type,
			       const char *value, void *buf, size_t len ) {
	char *endp;
	unsigned long num_value;

	/* Parse value */
	num_value = strtoul ( value, &endp, 0 );
	if ( *endp )
		return -EINVAL;

	return type->denumerate ( type, num_value, buf, len );
}

/**
 * Format signed integer setting value
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int format_int_setting ( const struct setting_type *type,
				const void *raw, size_t raw_len,
				char *buf, size_t len ) {
	unsigned long value;
	int ret;

	/* Extract numeric value */
	if ( ( ret = type->numerate ( type, raw, raw_len, &value ) ) < 0 )
		return ret;

	/* Format value */
	return snprintf ( buf, len, "%ld", value );
}

/**
 * Format unsigned integer setting value
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int format_uint_setting ( const struct setting_type *type,
				 const void *raw, size_t raw_len,
				 char *buf, size_t len ) {
	unsigned long value;
	int ret;

	/* Extract numeric value */
	if ( ( ret = type->numerate ( type, raw, raw_len, &value ) ) < 0 )
		return ret;

	/* Format value */
	return snprintf ( buf, len, "%#lx", value );
}

/**
 * Define a signed integer setting type
 *
 * @v index		Integer setting type index
 * @ret type		Setting type
 */
#define SETTING_TYPE_INT( index ) {				\
	.name = SETTING_TYPE_INT_NAME ( index ),		\
	.parse = parse_int_setting,				\
	.format = format_int_setting,				\
	.denumerate = denumerate_int_setting,			\
	.numerate = numerate_int_setting,			\
}

/**
 * Define an unsigned integer setting type
 *
 * @v index		Integer setting type index
 * @ret type		Setting type
 */
#define SETTING_TYPE_UINT( index ) {				\
	.name = SETTING_TYPE_UINT_NAME ( index ),		\
	.parse = parse_int_setting,				\
	.format = format_uint_setting,				\
	.denumerate = denumerate_int_setting,			\
	.numerate = numerate_int_setting,			\
}

/** A signed 8-bit integer setting type */
const struct setting_type setting_type_int8 __setting_type =
	SETTING_TYPE_INT ( SETTING_TYPE_INT8 );

/** A signed 16-bit integer setting type */
const struct setting_type setting_type_int16 __setting_type =
	SETTING_TYPE_INT ( SETTING_TYPE_INT16 );

/** A signed 32-bit integer setting type */
const struct setting_type setting_type_int32 __setting_type =
	SETTING_TYPE_INT ( SETTING_TYPE_INT32 );

/** An unsigned 8-bit integer setting type */
const struct setting_type setting_type_uint8 __setting_type =
	SETTING_TYPE_UINT ( SETTING_TYPE_INT8 );

/** An unsigned 16-bit integer setting type */
const struct setting_type setting_type_uint16 __setting_type =
	SETTING_TYPE_UINT ( SETTING_TYPE_INT16 );

/** An unsigned 32-bit integer setting type */
const struct setting_type setting_type_uint32 __setting_type =
	SETTING_TYPE_UINT ( SETTING_TYPE_INT32 );

/**
 * Parse hex string setting value (using colon delimiter)
 *
 * @v type		Setting type
 * @v value		Formatted setting value
 * @v buf		Buffer to contain raw value
 * @v len		Length of buffer
 * @v size		Integer size, in bytes
 * @ret len		Length of raw value, or negative error
 */
static int parse_hex_setting ( const struct setting_type *type __unused,
			       const char *value, void *buf, size_t len ) {
	return hex_decode ( ':', value, buf, len );
}

/**
 * Format hex string setting value (using colon delimiter)
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int format_hex_colon_setting ( const struct setting_type *type __unused,
				      const void *raw, size_t raw_len,
				      char *buf, size_t len ) {
	return hex_encode ( ':', raw, raw_len, buf, len );
}

/**
 * Parse hex string setting value (using hyphen delimiter)
 *
 * @v type		Setting type
 * @v value		Formatted setting value
 * @v buf		Buffer to contain raw value
 * @v len		Length of buffer
 * @v size		Integer size, in bytes
 * @ret len		Length of raw value, or negative error
 */
static int parse_hex_hyphen_setting ( const struct setting_type *type __unused,
				      const char *value, void *buf,
				      size_t len ) {
	return hex_decode ( '-', value, buf, len );
}

/**
 * Format hex string setting value (using hyphen delimiter)
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int format_hex_hyphen_setting ( const struct setting_type *type __unused,
				       const void *raw, size_t raw_len,
				       char *buf, size_t len ) {
	return hex_encode ( '-', raw, raw_len, buf, len );
}

/**
 * Parse hex string setting value (using no delimiter)
 *
 * @v type		Setting type
 * @v value		Formatted setting value
 * @v buf		Buffer to contain raw value
 * @v len		Length of buffer
 * @v size		Integer size, in bytes
 * @ret len		Length of raw value, or negative error
 */
static int parse_hex_raw_setting ( const struct setting_type *type __unused,
				   const char *value, void *buf, size_t len ) {
	return hex_decode ( 0, value, buf, len );
}

/**
 * Format hex string setting value (using no delimiter)
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int format_hex_raw_setting ( const struct setting_type *type __unused,
				    const void *raw, size_t raw_len,
				    char *buf, size_t len ) {
	return hex_encode ( 0, raw, raw_len, buf, len );
}

/** A hex-string setting (colon-delimited) */
const struct setting_type setting_type_hex __setting_type = {
	.name = "hex",
	.parse = parse_hex_setting,
	.format = format_hex_colon_setting,
};

/** A hex-string setting (hyphen-delimited) */
const struct setting_type setting_type_hexhyp __setting_type = {
	.name = "hexhyp",
	.parse = parse_hex_hyphen_setting,
	.format = format_hex_hyphen_setting,
};

/** A hex-string setting (non-delimited) */
const struct setting_type setting_type_hexraw __setting_type = {
	.name = "hexraw",
	.parse = parse_hex_raw_setting,
	.format = format_hex_raw_setting,
};

/**
 * Parse Base64-encoded setting value
 *
 * @v type		Setting type
 * @v value		Formatted setting value
 * @v buf		Buffer to contain raw value
 * @v len		Length of buffer
 * @v size		Integer size, in bytes
 * @ret len		Length of raw value, or negative error
 */
static int parse_base64_setting ( const struct setting_type *type __unused,
				  const char *value, void *buf, size_t len ) {

	return base64_decode ( value, buf, len );
}

/**
 * Format Base64-encoded setting value
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int format_base64_setting ( const struct setting_type *type __unused,
				   const void *raw, size_t raw_len,
				   char *buf, size_t len ) {

	return base64_encode ( raw, raw_len, buf, len );
}

/** A Base64-encoded setting */
const struct setting_type setting_type_base64 __setting_type = {
	.name = "base64",
	.parse = parse_base64_setting,
	.format = format_base64_setting,
};

/**
 * Format UUID setting value
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int format_uuid_setting ( const struct setting_type *type __unused,
				 const void *raw, size_t raw_len, char *buf,
				 size_t len ) {
	const union uuid *uuid = raw;

	/* Range check */
	if ( raw_len != sizeof ( *uuid ) )
		return -ERANGE;

	/* Format value */
	return snprintf ( buf, len, "%s", uuid_ntoa ( uuid ) );
}

/** UUID setting type */
const struct setting_type setting_type_uuid __setting_type = {
	.name = "uuid",
	.format = format_uuid_setting,
};

/**
 * Format PCI bus:dev.fn setting value
 *
 * @v type		Setting type
 * @v raw		Raw setting value
 * @v raw_len		Length of raw setting value
 * @v buf		Buffer to contain formatted value
 * @v len		Length of buffer
 * @ret len		Length of formatted value, or negative error
 */
static int format_busdevfn_setting ( const struct setting_type *type __unused,
				     const void *raw, size_t raw_len, char *buf,
				     size_t len ) {
	unsigned long busdevfn;
	int check_len;

	/* Extract numeric value */
	check_len = numeric_setting_value ( 0, raw, raw_len, &busdevfn );
	if ( check_len < 0 )
		return check_len;
	assert ( check_len == ( int ) raw_len );

	/* Format value */
	return snprintf ( buf, len, "%02lx:%02lx.%lx", PCI_BUS ( busdevfn ),
			  PCI_SLOT ( busdevfn ), PCI_FUNC ( busdevfn ) );
}

/** PCI bus:dev.fn setting type */
const struct setting_type setting_type_busdevfn __setting_type = {
	.name = "busdevfn",
	.format = format_busdevfn_setting,
};

/******************************************************************************
 *
 * Setting expansion
 *
 ******************************************************************************
 */

/**
 * Expand variables within string
 *
 * @v string		String
 * @ret expstr		Expanded string
 *
 * The expanded string is allocated with malloc() and the caller must
 * eventually free() it.
 */
char * expand_settings ( const char *string ) {
	struct settings *settings;
	struct setting setting;
	char *expstr;
	char *start;
	char *end;
	char *head;
	char *name;
	char *tail;
	char *value;
	char *tmp;
	int new_len;
	int rc;

	/* Obtain temporary modifiable copy of string */
	expstr = strdup ( string );
	if ( ! expstr )
		return NULL;

	/* Expand while expansions remain */
	while ( 1 ) {

		head = expstr;

		/* Locate setting to be expanded */
		start = NULL;
		end = NULL;
		for ( tmp = expstr ; *tmp ; tmp++ ) {
			if ( ( tmp[0] == '$' ) && ( tmp[1] == '{' ) )
				start = tmp;
			if ( start && ( tmp[0] == '}' ) ) {
				end = tmp;
				break;
			}
		}
		if ( ! end )
			break;
		*start = '\0';
		name = ( start + 2 );
		*end = '\0';
		tail = ( end + 1 );

		/* Expand setting */
		if ( ( rc = parse_setting_name ( name, find_child_settings,
						 &settings,
						 &setting ) ) != 0 ) {
			/* Treat invalid setting names as empty */
			value = NULL;
		} else {
			/* Fetch and format setting value.  Ignore
			 * errors; treat non-existent settings as empty.
			 */
			fetchf_setting_copy ( settings, &setting, NULL, NULL,
					      &value );
		}

		/* Construct expanded string and discard old string */
		tmp = expstr;
		new_len = asprintf ( &expstr, "%s%s%s",
				     head, ( value ? value : "" ), tail );
		free ( value );
		free ( tmp );
		if ( new_len < 0 )
			return NULL;
	}

	return expstr;
}

/******************************************************************************
 *
 * Settings
 *
 ******************************************************************************
 */

/** Hostname setting */
const struct setting hostname_setting __setting ( SETTING_HOST, hostname ) = {
	.name = "hostname",
	.description = "Host name",
	.tag = DHCP_HOST_NAME,
	.type = &setting_type_string,
};

/** Domain name setting */
const struct setting domain_setting __setting ( SETTING_IP_EXTRA, domain ) = {
	.name = "domain",
	.description = "DNS domain",
	.tag = DHCP_DOMAIN_NAME,
	.type = &setting_type_string,
};

/** TFTP server setting */
const struct setting next_server_setting __setting ( SETTING_BOOT,next-server)={
	.name = "next-server",
	.description = "TFTP server",
	.tag = DHCP_EB_SIADDR,
	.type = &setting_type_ipv4,
};

/** Filename setting */
const struct setting filename_setting __setting ( SETTING_BOOT, filename ) = {
	.name = "filename",
	.description = "Boot filename",
	.tag = DHCP_BOOTFILE_NAME,
	.type = &setting_type_string,
};

/** Root path setting */
const struct setting root_path_setting __setting ( SETTING_SANBOOT, root-path)={
	.name = "root-path",
	.description = "SAN root path",
	.tag = DHCP_ROOT_PATH,
	.type = &setting_type_string,
};

/** Username setting */
const struct setting username_setting __setting ( SETTING_AUTH, username ) = {
	.name = "username",
	.description = "User name",
	.tag = DHCP_EB_USERNAME,
	.type = &setting_type_string,
};

/** Password setting */
const struct setting password_setting __setting ( SETTING_AUTH, password ) = {
	.name = "password",
	.description = "Password",
	.tag = DHCP_EB_PASSWORD,
	.type = &setting_type_string,
};

/** Priority setting */
const struct setting priority_setting __setting ( SETTING_MISC, priority ) = {
	.name = "priority",
	.description = "Settings priority",
	.tag = DHCP_EB_PRIORITY,
	.type = &setting_type_int8,
};

/** DHCP user class setting */
const struct setting user_class_setting __setting ( SETTING_HOST_EXTRA,
						    user-class ) = {
	.name = "user-class",
	.description = "DHCP user class",
	.tag = DHCP_USER_CLASS_ID,
	.type = &setting_type_string,
};

/******************************************************************************
 *
 * Built-in settings block
 *
 ******************************************************************************
 */

/** Built-in setting scope */
const struct settings_scope builtin_scope;

/**
 * Fetch error number setting
 *
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int errno_fetch ( void *data, size_t len ) {
	uint32_t content;

	/* Return current error */
	content = htonl ( errno );
	if ( len > sizeof ( content ) )
		len = sizeof ( content );
	memcpy ( data, &content, len );
	return sizeof ( content );
}

/** Error number setting */
const struct setting errno_setting __setting ( SETTING_MISC, errno ) = {
	.name = "errno",
	.description = "Last error",
	.type = &setting_type_uint32,
	.scope = &builtin_scope,
};

/** Error number built-in setting */
struct builtin_setting errno_builtin_setting __builtin_setting = {
	.setting = &errno_setting,
	.fetch = errno_fetch,
};

/**
 * Fetch build architecture setting
 *
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int buildarch_fetch ( void *data, size_t len ) {
	static const char buildarch[] = _S2 ( ARCH );

	strncpy ( data, buildarch, len );
	return ( sizeof ( buildarch ) - 1 /* NUL */ );
}

/** Build architecture setting */
const struct setting buildarch_setting __setting ( SETTING_MISC, buildarch ) = {
	.name = "buildarch",
	.description = "Build architecture",
	.type = &setting_type_string,
	.scope = &builtin_scope,
};

/** Build architecture built-in setting */
struct builtin_setting buildarch_builtin_setting __builtin_setting = {
	.setting = &buildarch_setting,
	.fetch = buildarch_fetch,
};

/**
 * Fetch platform setting
 *
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int platform_fetch ( void *data, size_t len ) {
	static const char platform[] = _S2 ( PLATFORM );

	strncpy ( data, platform, len );
	return ( sizeof ( platform ) - 1 /* NUL */ );
}

/** Platform setting */
const struct setting platform_setting __setting ( SETTING_MISC, platform ) = {
	.name = "platform",
	.description = "Platform",
	.type = &setting_type_string,
	.scope = &builtin_scope,
};

/** Platform built-in setting */
struct builtin_setting platform_builtin_setting __builtin_setting = {
	.setting = &platform_setting,
	.fetch = platform_fetch,
};

/**
 * Fetch version setting
 *
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int version_fetch ( void *data, size_t len ) {
	strncpy ( data, product_version, len );
	return ( strlen ( product_version ) );
}

/** Version setting */
const struct setting version_setting __setting ( SETTING_MISC, version ) = {
	.name = "version",
	.description = "Version",
	.type = &setting_type_string,
	.scope = &builtin_scope,
};

/** Version built-in setting */
struct builtin_setting version_builtin_setting __builtin_setting = {
	.setting = &version_setting,
	.fetch = version_fetch,
};

/**
 * Fetch built-in setting
 *
 * @v settings		Settings block
 * @v setting		Setting to fetch
 * @v data		Buffer to fill with setting data
 * @v len		Length of buffer
 * @ret len		Length of setting data, or negative error
 */
static int builtin_fetch ( struct settings *settings __unused,
			   struct setting *setting,
			   void *data, size_t len ) {
	struct builtin_setting *builtin;

	for_each_table_entry ( builtin, BUILTIN_SETTINGS ) {
		if ( setting_cmp ( setting, builtin->setting ) == 0 )
			return builtin->fetch ( data, len );
	}
	return -ENOENT;
}

/**
 * Check applicability of built-in setting
 *
 * @v settings		Settings block
 * @v setting		Setting
 * @ret applies		Setting applies within this settings block
 */
static int builtin_applies ( struct settings *settings __unused,
			     const struct setting *setting ) {

	return ( setting->scope == &builtin_scope );
}

/** Built-in settings operations */
static struct settings_operations builtin_settings_operations = {
	.applies = builtin_applies,
	.fetch = builtin_fetch,
};

/** Built-in settings */
static struct settings builtin_settings = {
	.refcnt = NULL,
	.siblings = LIST_HEAD_INIT ( builtin_settings.siblings ),
	.children = LIST_HEAD_INIT ( builtin_settings.children ),
	.op = &builtin_settings_operations,
};

/** Initialise built-in settings */
static void builtin_init ( void ) {
	int rc;

	if ( ( rc = register_settings ( &builtin_settings, NULL,
					"builtin" ) ) != 0 ) {
		DBG ( "Could not register built-in settings: %s\n",
		      strerror ( rc ) );
		return;
	}
}

/** Built-in settings initialiser */
struct init_fn builtin_init_fn __init_fn ( INIT_NORMAL ) = {
	.initialise = builtin_init,
};
