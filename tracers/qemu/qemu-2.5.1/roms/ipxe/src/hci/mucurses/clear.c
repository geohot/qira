#include <curses.h>
#include "mucurses.h"
#include "cursor.h"

/** @file
 *
 * MuCurses clearing functions
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Clear a window to the bottom from current cursor position
 *
 * @v *win	subject window
 * @ret rc	return status code
 */
int wclrtobot ( WINDOW *win ) {
	struct cursor_pos pos;

	_store_curs_pos( win, &pos );
	do {
		_wputc( win, ' ', WRAP );
	} while ( win->curs_y + win->curs_x );
	_restore_curs_pos( win, &pos );

	return OK;
}

/**
 * Clear a window to the end of the current line
 *
 * @v *win	subject window
 * @ret rc	return status code
 */
int wclrtoeol ( WINDOW *win ) {
	struct cursor_pos pos;

	_store_curs_pos( win, &pos );
	while ( ( win->curs_y - pos.y ) == 0 ) {
		_wputc( win, ' ', WRAP );
	}
	_restore_curs_pos( win, &pos );

	return OK;
}

/**
 * Delete character under the cursor in a window
 *
 * @v *win	subject window
 * @ret rc	return status code
 */
int wdelch ( WINDOW *win ) {
	_wputc( win, ' ', NOWRAP );
	_wcursback( win );

	return OK;
}

/**
 * Delete line under a window's cursor
 *
 * @v *win	subject window
 * @ret rc	return status code
 */
int wdeleteln ( WINDOW *win ) {
	struct cursor_pos pos;

	_store_curs_pos( win, &pos );
	/* let's just set the cursor to the beginning of the line and
	   let wclrtoeol do the work :) */
	wmove( win, win->curs_y, 0 );
	wclrtoeol( win );
	_restore_curs_pos( win, &pos );
	return OK;
}

/**
 * Completely clear a window
 *
 * @v *win	subject window
 * @ret rc	return status code
 */
int werase ( WINDOW *win ) {
	wmove( win, 0, 0 );
	wclrtobot( win );
	return OK;
}

/**
 * Completely clear the screen
 *
 * @ret rc	return status code
 */
int erase ( void ) {
	stdscr->scr->erase( stdscr->scr, stdscr->attrs );
	return OK;
}
