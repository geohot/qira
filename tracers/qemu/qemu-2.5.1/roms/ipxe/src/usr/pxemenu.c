/*
 * Copyright (C) 2009 Michael Brown <mbrown@fensystems.co.uk>.
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
#include <errno.h>
#include <ctype.h>
#include <byteswap.h>
#include <curses.h>
#include <ipxe/console.h>
#include <ipxe/dhcp.h>
#include <ipxe/keys.h>
#include <ipxe/timer.h>
#include <ipxe/uri.h>
#include <ipxe/ansicol.h>
#include <usr/dhcpmgmt.h>
#include <usr/autoboot.h>

/** @file
 *
 * PXE Boot Menus
 *
 */

/** A PXE boot menu item */
struct pxe_menu_item {
	/** Boot Server type */
	unsigned int type;
	/** Description */
	char *desc;
};

/**
 * A PXE boot menu
 *
 * This structure encapsulates the menu information provided via DHCP
 * options.
 */
struct pxe_menu {
	/** Prompt string (optional) */
	const char *prompt;
	/** Timeout (in seconds)
	 *
	 * Negative indicates no timeout (i.e. wait indefinitely)
	 */
	int timeout;
	/** Number of menu items */
	unsigned int num_items;
	/** Selected menu item */
	unsigned int selection;
	/** Menu items */
	struct pxe_menu_item items[0];
};

/**
 * Parse and allocate PXE boot menu
 *
 * @v menu		PXE boot menu to fill in
 * @ret rc		Return status code
 *
 * It is the callers responsibility to eventually free the allocated
 * boot menu.
 */
static int pxe_menu_parse ( struct pxe_menu **menu ) {
	struct setting pxe_boot_menu_prompt_setting =
		{ .tag = DHCP_PXE_BOOT_MENU_PROMPT };
	struct setting pxe_boot_menu_setting =
		{ .tag = DHCP_PXE_BOOT_MENU };
	uint8_t raw_menu[256];
	int raw_prompt_len;
	int raw_menu_len;
	struct dhcp_pxe_boot_menu *raw_menu_item;
	struct dhcp_pxe_boot_menu_prompt *raw_menu_prompt;
	void *raw_menu_end;
	unsigned int num_menu_items;
	unsigned int i;
	int rc;

	/* Fetch raw menu */
	memset ( raw_menu, 0, sizeof ( raw_menu ) );
	if ( ( raw_menu_len = fetch_raw_setting ( NULL, &pxe_boot_menu_setting,
						  raw_menu,
						  sizeof ( raw_menu ) ) ) < 0 ){
		rc = raw_menu_len;
		DBG ( "Could not retrieve raw PXE boot menu: %s\n",
		      strerror ( rc ) );
		return rc;
	}
	if ( raw_menu_len >= ( int ) sizeof ( raw_menu ) ) {
		DBG ( "Raw PXE boot menu too large for buffer\n" );
		return -ENOSPC;
	}
	raw_menu_end = ( raw_menu + raw_menu_len );

	/* Fetch raw prompt length */
	raw_prompt_len =
		fetch_raw_setting ( NULL, &pxe_boot_menu_prompt_setting,
				    NULL, 0 );
	if ( raw_prompt_len < 0 )
		raw_prompt_len = 0;

	/* Count menu items */
	num_menu_items = 0;
	raw_menu_item = ( ( void * ) raw_menu );
	while ( 1 ) {
		if ( ( ( ( void * ) raw_menu_item ) +
		       sizeof ( *raw_menu_item ) ) > raw_menu_end )
			break;
		if ( ( ( ( void * ) raw_menu_item ) +
		       sizeof ( *raw_menu_item ) +
		       raw_menu_item->desc_len ) > raw_menu_end )
			break;
		num_menu_items++;
		raw_menu_item = ( ( ( void * ) raw_menu_item ) +
				  sizeof ( *raw_menu_item ) +
				  raw_menu_item->desc_len );
	}

	/* Allocate space for parsed menu */
	*menu = zalloc ( sizeof ( **menu ) +
			 ( num_menu_items * sizeof ( (*menu)->items[0] ) ) +
			 raw_menu_len + 1 /* NUL */ +
			 raw_prompt_len + 1 /* NUL */ );
	if ( ! *menu ) {
		DBG ( "Could not allocate PXE boot menu\n" );
		return -ENOMEM;
	}

	/* Fill in parsed menu */
	(*menu)->num_items = num_menu_items;
	raw_menu_item = ( ( ( void * ) (*menu) ) + sizeof ( **menu ) +
			  ( num_menu_items * sizeof ( (*menu)->items[0] ) ) );
	memcpy ( raw_menu_item, raw_menu, raw_menu_len );
	for ( i = 0 ; i < num_menu_items ; i++ ) {
		(*menu)->items[i].type = le16_to_cpu ( raw_menu_item->type );
		(*menu)->items[i].desc = raw_menu_item->desc;
		/* Set type to 0; this ensures that the description
		 * for the previous menu item is NUL-terminated.
		 * (Final item is NUL-terminated anyway.)
		 */
		raw_menu_item->type = 0;
		raw_menu_item = ( ( ( void * ) raw_menu_item ) +
				  sizeof ( *raw_menu_item ) +
				  raw_menu_item->desc_len );
	}
	if ( raw_prompt_len ) {
		raw_menu_prompt = ( ( ( void * ) raw_menu_item ) +
				    1 /* NUL */ );
		fetch_raw_setting ( NULL, &pxe_boot_menu_prompt_setting,
				    raw_menu_prompt, raw_prompt_len );
		(*menu)->timeout =
			( ( raw_menu_prompt->timeout == 0xff ) ?
			  -1 : raw_menu_prompt->timeout );
		(*menu)->prompt = raw_menu_prompt->prompt;
	} else {
		(*menu)->timeout = -1;
	}

	return 0;
}

/**
 * Draw PXE boot menu item
 *
 * @v menu		PXE boot menu
 * @v index		Index of item to draw
 * @v selected		Item is selected
 */
static void pxe_menu_draw_item ( struct pxe_menu *menu,
				 unsigned int index, int selected ) {
	char buf[COLS+1];
	size_t len;
	unsigned int row;

	/* Prepare space-padded row content */
	len = snprintf ( buf, sizeof ( buf ), " %c. %s",
			 ( 'A' + index ), menu->items[index].desc );
	while ( len < ( sizeof ( buf ) - 1 ) )
		buf[len++] = ' ';
	buf[ sizeof ( buf ) - 1 ] = '\0';

	/* Draw row */
	row = ( LINES - menu->num_items + index );
	color_set ( ( selected ? CPAIR_PXE : CPAIR_DEFAULT ), NULL );
	mvprintw ( row, 0, "%s", buf );
	move ( row, 1 );
}

/**
 * Make selection from PXE boot menu
 *
 * @v menu		PXE boot menu
 * @ret rc		Return status code
 */
static int pxe_menu_select ( struct pxe_menu *menu ) {
	int key;
	unsigned int key_selection;
	unsigned int i;
	int rc = 0;

	/* Initialise UI */
	initscr();
	start_color();
	color_set ( CPAIR_DEFAULT, NULL );

	/* Draw initial menu */
	for ( i = 0 ; i < menu->num_items ; i++ )
		printf ( "\n" );
	for ( i = 0 ; i < menu->num_items ; i++ )
		pxe_menu_draw_item ( menu, ( menu->num_items - i - 1 ), 0 );

	while ( 1 ) {

		/* Highlight currently selected item */
		pxe_menu_draw_item ( menu, menu->selection, 1 );

		/* Wait for keyboard input */
		key = getkey ( 0 );

		/* Unhighlight currently selected item */
		pxe_menu_draw_item ( menu, menu->selection, 0 );

		/* Act upon key */
		if ( ( key == CR ) || ( key == LF ) ) {
			pxe_menu_draw_item ( menu, menu->selection, 1 );
			break;
		} else if ( ( key == CTRL_C ) || ( key == ESC ) ) {
			rc = -ECANCELED;
			break;
		} else if ( key == KEY_UP ) {
			if ( menu->selection > 0 )
				menu->selection--;
		} else if ( key == KEY_DOWN ) {
			if ( menu->selection < ( menu->num_items - 1 ) )
				menu->selection++;
		} else if ( ( key < KEY_MIN ) &&
			    ( ( key_selection = ( toupper ( key ) - 'A' ) )
			      < menu->num_items ) ) {
			menu->selection = key_selection;
			pxe_menu_draw_item ( menu, menu->selection, 1 );
			break;
		}
	}

	/* Shut down UI */
	endwin();

	return rc;
}

/**
 * Prompt for (and make selection from) PXE boot menu
 *
 * @v menu		PXE boot menu
 * @ret rc		Return status code
 */
static int pxe_menu_prompt_and_select ( struct pxe_menu *menu ) {
	unsigned long start = currticks();
	unsigned long now;
	unsigned long elapsed;
	size_t len = 0;
	int key;
	int rc = 0;

	/* Display menu immediately, if specified to do so */
	if ( menu->timeout < 0 ) {
		if ( menu->prompt )
			printf ( "%s\n", menu->prompt );
		return pxe_menu_select ( menu );
	}

	/* Display prompt, if specified */
	if ( menu->prompt )
		printf ( "%s", menu->prompt );

	/* Wait for timeout, if specified */
	while ( menu->timeout > 0 ) {
		if ( ! len )
			len = printf ( " (%d)", menu->timeout );
		if ( iskey() ) {
			key = getkey ( 0 );
			if ( key == KEY_F8 ) {
				/* Display menu */
				printf ( "\n" );
				return pxe_menu_select ( menu );
			} else if ( ( key == CTRL_C ) || ( key == ESC ) ) {
				/* Abort */
				rc = -ECANCELED;
				break;
			} else {
				/* Stop waiting */
				break;
			}
		}
		now = currticks();
		elapsed = ( now - start );
		if ( elapsed >= TICKS_PER_SEC ) {
			menu->timeout -= 1;
			do {
				printf ( "\b \b" );
			} while ( --len );
			start = now;
		}
	}

	/* Return with default option selected */
	printf ( "\n" );
	return rc;
}

/**
 * Boot using PXE boot menu
 *
 * @ret rc		Return status code
 *
 * Note that a success return status indicates that a PXE boot menu
 * item has been selected, and that the DHCP session should perform a
 * boot server request/ack.
 */
int pxe_menu_boot ( struct net_device *netdev ) {
	struct pxe_menu *menu;
	unsigned int pxe_type;
	struct settings *pxebs_settings;
	struct uri *uri;
	int rc;

	/* Parse and allocate boot menu */
	if ( ( rc = pxe_menu_parse ( &menu ) ) != 0 )
		return rc;

	/* Make selection from boot menu */
	if ( ( rc = pxe_menu_prompt_and_select ( menu ) ) != 0 ) {
		free ( menu );
		return rc;
	}
	pxe_type = menu->items[menu->selection].type;

	/* Free boot menu */
	free ( menu );

	/* Return immediately if local boot selected */
	if ( ! pxe_type )
		return 0;

	/* Attempt PXE Boot Server Discovery */
	if ( ( rc = pxebs ( netdev, pxe_type ) ) != 0 )
		return rc;

	/* Fetch next server and filename */
	pxebs_settings = find_settings ( PXEBS_SETTINGS_NAME );
	assert ( pxebs_settings );
	uri = fetch_next_server_and_filename ( pxebs_settings );
	if ( ! uri )
		return -ENOMEM;

	/* Attempt boot */
	rc = uriboot ( uri, NULL, 0, URIBOOT_NO_SAN );
	uri_put ( uri );
	return rc;
}
