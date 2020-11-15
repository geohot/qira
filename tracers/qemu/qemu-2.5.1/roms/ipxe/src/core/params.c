/*
 * Copyright (C) 2013 Michael Brown <mbrown@fensystems.co.uk>.
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

/** @file
 *
 * Form parameters
 *
 */

#include <stdlib.h>
#include <string.h>
#include <ipxe/params.h>

/** List of all parameter lists */
static LIST_HEAD ( parameters );

/**
 * Free form parameter list
 *
 * @v refcnt		Reference count
 */
static void free_parameters ( struct refcnt *refcnt ) {
	struct parameters *params =
		container_of ( refcnt, struct parameters, refcnt );
	struct parameter *param;
	struct parameter *tmp;

	DBGC ( params, "PARAMS \"%s\" destroyed\n", params->name );

	/* Free all parameters */
	list_for_each_entry_safe ( param, tmp, &params->entries, list ) {
		list_del ( &param->list );
		free ( param );
	}

	/* Free parameter list */
	free ( params );
}

/**
 * Find form parameter list by name
 *
 * @v name		Parameter list name (may be NULL)
 * @ret params		Parameter list, or NULL if not found
 */
struct parameters * find_parameters ( const char *name ) {
	struct parameters *params;

	list_for_each_entry ( params, &parameters, list ) {
		if ( ( params->name == name ) ||
		     ( strcmp ( params->name, name ) == 0 ) ) {
			return params;
		}
	}
	return NULL;
}

/**
 * Create form parameter list
 *
 * @v name		Parameter list name (may be NULL)
 * @ret params		Parameter list, or NULL on failure
 */
struct parameters * create_parameters ( const char *name ) {
	struct parameters *params;
	size_t name_len;
	char *name_copy;

	/* Destroy any existing parameter list of this name */
	params = find_parameters ( name );
	if ( params ) {
		claim_parameters ( params );
		params_put ( params );
	}

	/* Allocate parameter list */
	name_len = ( name ? ( strlen ( name ) + 1 /* NUL */ ) : 0 );
	params = zalloc ( sizeof ( *params ) + name_len );
	if ( ! params )
		return NULL;
	ref_init ( &params->refcnt, free_parameters );
	name_copy = ( ( void * ) ( params + 1 ) );

	/* Populate parameter list */
	if ( name ) {
		strcpy ( name_copy, name );
		params->name = name_copy;
	}
	INIT_LIST_HEAD ( &params->entries );

	/* Add to list of parameter lists */
	list_add_tail ( &params->list, &parameters );

	DBGC ( params, "PARAMS \"%s\" created\n", params->name );
	return params;
}

/**
 * Add form parameter
 *
 * @v params		Parameter list
 * @v key		Parameter key
 * @v value		Parameter value
 * @ret param		Parameter, or NULL on failure
 */
struct parameter * add_parameter ( struct parameters *params,
				   const char *key, const char *value ) {
	struct parameter *param;
	size_t key_len;
	size_t value_len;
	char *key_copy;
	char *value_copy;

	/* Allocate parameter */
	key_len = ( strlen ( key ) + 1 /* NUL */ );
	value_len = ( strlen ( value ) + 1 /* NUL */ );
	param = zalloc ( sizeof ( *param ) + key_len + value_len );
	if ( ! param )
		return NULL;
	key_copy = ( ( void * ) ( param + 1 ) );
	value_copy = ( key_copy + key_len );

	/* Populate parameter */
	strcpy ( key_copy, key );
	param->key = key_copy;
	strcpy ( value_copy, value );
	param->value = value_copy;

	/* Add to list of parameters */
	list_add_tail ( &param->list, &params->entries );

	DBGC ( params, "PARAMS \"%s\" added \"%s\"=\"%s\"\n",
	       params->name, param->key, param->value );
	return param;
}
