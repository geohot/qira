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
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * Menu selection
 *
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ipxe/list.h>
#include <ipxe/menu.h>

/** List of all menus */
static LIST_HEAD ( menus );

/**
 * Create menu
 *
 * @v name		Menu name, or NULL
 * @v title		Menu title, or NULL
 * @ret menu		Menu, or NULL on failure
 */
struct menu * create_menu ( const char *name, const char *title ) {
	size_t name_len;
	size_t title_len;
	size_t len;
	struct menu *menu;
	char *name_copy;
	char *title_copy;

	/* Destroy any existing menu of this name */
	menu = find_menu ( name );
	if ( menu )
		destroy_menu ( menu );

	/* Use empty title if none given */
	if ( ! title )
		title = "";

	/* Allocate menu */
	name_len = ( name ? ( strlen ( name ) + 1 /* NUL */ ) : 0 );
	title_len = ( strlen ( title ) + 1 /* NUL */ );
	len = ( sizeof ( *menu ) + name_len + title_len );
	menu = zalloc ( len );
	if ( ! menu )
		return NULL;
	name_copy = ( ( void * ) ( menu + 1 ) );
	title_copy = ( name_copy + name_len );

	/* Initialise menu */
	if ( name ) {
		strcpy ( name_copy, name );
		menu->name = name_copy;
	}
	strcpy ( title_copy, title );
	menu->title = title_copy;
	INIT_LIST_HEAD ( &menu->items );

	/* Add to list of menus */
	list_add_tail ( &menu->list, &menus );

	DBGC ( menu, "MENU %s created with title \"%s\"\n",
	       menu->name, menu->title );

	return menu;
}

/**
 * Add menu item
 *
 * @v menu		Menu
 * @v label		Label, or NULL
 * @v text		Text, or NULL
 * @v shortcut		Shortcut key
 * @v is_default	Item is the default item
 * @ret item		Menu item, or NULL on failure
 */
struct menu_item * add_menu_item ( struct menu *menu, const char *label,
				   const char *text, int shortcut,
				   int is_default ) {
	size_t label_len;
	size_t text_len;
	size_t len;
	struct menu_item *item;
	char *label_copy;
	char *text_copy;

	/* Use empty text if none given */
	if ( ! text )
		text = "";

	/* Allocate item */
	label_len = ( label ? ( strlen ( label ) + 1 /* NUL */ ) : 0 );
	text_len = ( strlen ( text ) + 1 /* NUL */ );
	len = ( sizeof ( *item ) + label_len + text_len );
	item = zalloc ( len );
	if ( ! item )
		return NULL;
	label_copy = ( ( void * ) ( item + 1 ) );
	text_copy = ( label_copy + label_len );

	/* Initialise item */
	if ( label ) {
		strcpy ( label_copy, label );
		item->label = label_copy;
	}
	strcpy ( text_copy, text );
	item->text = text_copy;
	item->shortcut = shortcut;
	item->is_default = is_default;

	/* Add to list of items */
	list_add_tail ( &item->list, &menu->items );

	return item;
}

/**
 * Destroy menu
 *
 * @v menu		Menu
 */
void destroy_menu ( struct menu *menu ) {
	struct menu_item *item;
	struct menu_item *tmp;

	/* Remove from list of menus */
	list_del ( &menu->list );

	/* Free items */
	list_for_each_entry_safe ( item, tmp, &menu->items, list ) {
		list_del ( &item->list );
		free ( item );
	}

	/* Free menu */
	free ( menu );
}

/**
 * Find menu
 *
 * @v name		Menu name, or NULL
 * @ret menu		Menu, or NULL if not found
 */
struct menu * find_menu ( const char *name ) {
	struct menu *menu;

	list_for_each_entry ( menu, &menus, list ) {
		if ( ( menu->name == name ) ||
		     ( strcmp ( menu->name, name ) == 0 ) ) {
			return menu;
		}
	}

	return NULL;
}
