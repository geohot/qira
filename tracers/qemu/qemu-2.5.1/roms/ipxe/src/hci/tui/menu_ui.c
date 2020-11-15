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
 * Menu interface
 *
 */

#include <string.h>
#include <errno.h>
#include <curses.h>
#include <ipxe/keys.h>
#include <ipxe/timer.h>
#include <ipxe/console.h>
#include <ipxe/ansicol.h>
#include <ipxe/jumpscroll.h>
#include <ipxe/menu.h>

/* Screen layout */
#define TITLE_ROW	1U
#define MENU_ROW	3U
#define MENU_COL	1U
#define MENU_ROWS	( LINES - 2U - MENU_ROW )
#define MENU_COLS	( COLS - 2U )
#define MENU_PAD	2U

/** A menu user interface */
struct menu_ui {
	/** Menu */
	struct menu *menu;
	/** Jump scroller */
	struct jump_scroller scroll;
	/** Timeout (0=indefinite) */
	unsigned long timeout;
};

/**
 * Return a numbered menu item
 *
 * @v menu		Menu
 * @v index		Index
 * @ret item		Menu item, or NULL
 */
static struct menu_item * menu_item ( struct menu *menu, unsigned int index ) {
	struct menu_item *item;

	list_for_each_entry ( item, &menu->items, list ) {
		if ( index-- == 0 )
			return item;
	}

	return NULL;
}

/**
 * Draw a numbered menu item
 *
 * @v ui		Menu user interface
 * @v index		Index
 */
static void draw_menu_item ( struct menu_ui *ui, unsigned int index ) {
	struct menu_item *item;
	unsigned int row_offset;
	char buf[ MENU_COLS + 1 /* NUL */ ];
	char timeout_buf[6]; /* "(xxx)" + NUL */
	size_t timeout_len;
	size_t max_len;
	size_t len;

	/* Move to start of row */
	row_offset = ( index - ui->scroll.first );
	move ( ( MENU_ROW + row_offset ), MENU_COL );

	/* Get menu item */
	item = menu_item ( ui->menu, index );
	if ( item ) {

		/* Draw separators in a different colour */
		if ( ! item->label )
			color_set ( CPAIR_SEPARATOR, NULL );

		/* Highlight if this is the selected item */
		if ( index == ui->scroll.current ) {
			color_set ( CPAIR_SELECT, NULL );
			attron ( A_BOLD );
		}

		/* Construct row */
		memset ( buf, ' ', ( sizeof ( buf ) - 1 ) );
		buf[ sizeof ( buf ) -1 ] = '\0';
		len = strlen ( item->text );
		max_len = ( sizeof ( buf ) - 1 /* NUL */ - ( 2 * MENU_PAD ) );
		if ( len > max_len )
			len = max_len;
		memcpy ( ( buf + MENU_PAD ), item->text, len );

		/* Add timeout if applicable */
		timeout_len =
			snprintf ( timeout_buf, sizeof ( timeout_buf ), "(%ld)",
				   ( ( ui->timeout + TICKS_PER_SEC - 1 ) /
				     TICKS_PER_SEC ) );
		if ( ( index == ui->scroll.current ) && ( ui->timeout != 0 ) ) {
			memcpy ( ( buf + MENU_COLS - MENU_PAD - timeout_len ),
				 timeout_buf, timeout_len );
		}

		/* Print row */
		printw ( "%s", buf );

		/* Reset attributes */
		color_set ( CPAIR_NORMAL, NULL );
		attroff ( A_BOLD );

	} else {
		/* Clear row if there is no corresponding menu item */
		clrtoeol();
	}

	/* Move cursor back to start of row */
	move ( ( MENU_ROW + row_offset ), MENU_COL );
}

/**
 * Draw the current block of menu items
 *
 * @v ui		Menu user interface
 */
static void draw_menu_items ( struct menu_ui *ui ) {
	unsigned int i;

	/* Draw ellipses before and/or after the list as necessary */
	color_set ( CPAIR_SEPARATOR, NULL );
	mvaddstr ( ( MENU_ROW - 1 ), ( MENU_COL + MENU_PAD ),
		   ( jump_scroll_is_first ( &ui->scroll ) ? "   " : "..." ) );
	mvaddstr ( ( MENU_ROW + MENU_ROWS ), ( MENU_COL + MENU_PAD ),
		   ( jump_scroll_is_last ( &ui->scroll ) ? "   " : "..." ) );
	color_set ( CPAIR_NORMAL, NULL );

	/* Draw visible items */
	for ( i = 0 ; i < MENU_ROWS ; i++ )
		draw_menu_item ( ui, ( ui->scroll.first + i ) );
}

/**
 * Menu main loop
 *
 * @v ui		Menu user interface
 * @ret selected	Selected item
 * @ret rc		Return status code
 */
static int menu_loop ( struct menu_ui *ui, struct menu_item **selected ) {
	struct menu_item *item;
	unsigned long timeout;
	unsigned int previous;
	int key;
	int i;
	int move;
	int chosen = 0;
	int rc = 0;

	do {
		/* Record current selection */
		previous = ui->scroll.current;

		/* Calculate timeout as remainder of current second */
		timeout = ( ui->timeout % TICKS_PER_SEC );
		if ( ( timeout == 0 ) && ( ui->timeout != 0 ) )
			timeout = TICKS_PER_SEC;
		ui->timeout -= timeout;

		/* Get key */
		move = 0;
		key = getkey ( timeout );
		if ( key < 0 ) {
			/* Choose default if we finally time out */
			if ( ui->timeout == 0 )
				chosen = 1;
		} else {
			/* Cancel any timeout */
			ui->timeout = 0;

			/* Handle scroll keys */
			move = jump_scroll_key ( &ui->scroll, key );

			/* Handle other keys */
			switch ( key ) {
			case ESC:
			case CTRL_C:
				rc = -ECANCELED;
				break;
			case CR:
			case LF:
				chosen = 1;
				break;
			default:
				i = 0;
				list_for_each_entry ( item, &ui->menu->items,
						      list ) {
					if ( ! ( item->shortcut &&
						 ( item->shortcut == key ) ) ) {
						i++;
						continue;
					}
					ui->scroll.current = i;
					if ( item->label ) {
						chosen = 1;
					} else {
						move = +1;
					}
				}
				break;
			}
		}

		/* Move selection, if applicable */
		while ( move ) {
			move = jump_scroll_move ( &ui->scroll, move );
			item = menu_item ( ui->menu, ui->scroll.current );
			if ( item->label )
				break;
		}

		/* Redraw selection if necessary */
		if ( ( ui->scroll.current != previous ) || ( timeout != 0 ) ) {
			draw_menu_item ( ui, previous );
			if ( jump_scroll ( &ui->scroll ) )
				draw_menu_items ( ui );
			draw_menu_item ( ui, ui->scroll.current );
		}

		/* Record selection */
		item = menu_item ( ui->menu, ui->scroll.current );
		assert ( item != NULL );
		assert ( item->label != NULL );
		*selected = item;

	} while ( ( rc == 0 ) && ! chosen );

	return rc;
}

/**
 * Show menu
 *
 * @v menu		Menu
 * @v timeout		Timeout period, in ticks (0=indefinite)
 * @ret selected	Selected item
 * @ret rc		Return status code
 */
int show_menu ( struct menu *menu, unsigned long timeout,
		const char *select, struct menu_item **selected ) {
	struct menu_item *item;
	struct menu_ui ui;
	char buf[ MENU_COLS + 1 /* NUL */ ];
	int labelled_count = 0;
	int rc;

	/* Initialise UI */
	memset ( &ui, 0, sizeof ( ui ) );
	ui.menu = menu;
	ui.scroll.rows = MENU_ROWS;
	ui.timeout = timeout;
	list_for_each_entry ( item, &menu->items, list ) {
		if ( item->label ) {
			if ( ! labelled_count )
				ui.scroll.current = ui.scroll.count;
			labelled_count++;
			if ( select ) {
				if ( strcmp ( select, item->label ) == 0 )
					ui.scroll.current = ui.scroll.count;
			} else {
				if ( item->is_default )
					ui.scroll.current = ui.scroll.count;
			}
		}
		ui.scroll.count++;
	}
	if ( ! labelled_count ) {
		/* Menus with no labelled items cannot be selected
		 * from, and will seriously confuse the navigation
		 * logic.  Refuse to display any such menus.
		 */
		return -ENOENT;
	}

	/* Initialise screen */
	initscr();
	start_color();
	color_set ( CPAIR_NORMAL, NULL );
	curs_set ( 0 );
	erase();

	/* Draw initial content */
	attron ( A_BOLD );
	snprintf ( buf, sizeof ( buf ), "%s", ui.menu->title );
	mvprintw ( TITLE_ROW, ( ( COLS - strlen ( buf ) ) / 2 ), "%s", buf );
	attroff ( A_BOLD );
	jump_scroll ( &ui.scroll );
	draw_menu_items ( &ui );
	draw_menu_item ( &ui, ui.scroll.current );

	/* Enter main loop */
	rc = menu_loop ( &ui, selected );
	assert ( *selected );

	/* Clear screen */
	endwin();

	return rc;
}
