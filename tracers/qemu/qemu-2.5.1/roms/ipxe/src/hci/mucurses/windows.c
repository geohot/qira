#include <curses.h>
#include <stddef.h>
#include <stdlib.h>
#include "mucurses.h"

/** @file
 *
 * MuCurses windows instance functions
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Delete a window
 *
 * @v *win	pointer to window being deleted
 * @ret rc	return status code
 */
int delwin ( WINDOW *win ) {
	if ( win == NULL )
		return ERR;

	/* I think we should blank the region covered by the window -
	   ncurses doesn't do this, but they have a buffer, so they
	   may just be deleting from an offscreen context whereas we
	   are guaranteed to be deleting something onscreen */
	wmove( win, 0, 0 );
	chtype killch = (chtype)' ';
	do {
		_wputch( win, killch, WRAP );
	} while ( win->curs_x + win->curs_y );

	free( win );

	wmove ( stdscr, 0, 0 );

	return OK;
}

/**
 * Create a new derived window
 *
 * @v parent	parent window
 * @v nlines	window height
 * @v ncols	window width
 * @v begin_y	window y origin (relative to parent)
 * @v begin_x	window x origin (relative to parent)
 * @ret ptr	return pointer to child window
 */
WINDOW *derwin ( WINDOW *parent, int nlines, int ncols,
	     		  	 int begin_y, int begin_x ) {
	WINDOW *child;
	if ( parent == NULL )
		return NULL;
	if ( ( child = malloc( sizeof( WINDOW ) ) ) == NULL )
		return NULL;
	if ( ( (unsigned)ncols > parent->width ) || 
	     ( (unsigned)nlines > parent->height ) )
		return NULL;
	child->ori_y = parent->ori_y + begin_y;
	child->ori_x = parent->ori_x + begin_x;
	child->height = nlines;
	child->width = ncols;
	child->parent = parent;
	child->scr = parent->scr;
	return child;
}

/**
 * Create a duplicate of the specified window
 *
 * @v orig	original window
 * @ret ptr	pointer to duplicate window
 */
WINDOW *dupwin ( WINDOW *orig ) {
	WINDOW *copy;
	if ( orig == NULL )
		return NULL;
	if ( ( copy = malloc( sizeof( WINDOW ) ) ) == NULL )
		return NULL;
	copy->scr = orig->scr;
	copy->attrs = orig->attrs;
	copy->ori_y = orig->ori_y;
	copy->ori_x = orig->ori_x;
	copy->curs_y = orig->curs_y;
	copy->curs_x = orig->curs_x;
	copy->height = orig->height;
	copy->width = orig->width;
	return copy;
}

/**
 * Move window origin to specified coordinates
 *
 * @v *win	window to move
 * @v y		Y position
 * @v x		X position
 * @ret rc	return status code
 */
int mvwin ( WINDOW *win, int y, int x ) {
	if ( win == NULL )
		return ERR;
	if ( ( ( (unsigned)y + win->height ) > LINES ) ||
	     ( ( (unsigned)x + win->width ) > COLS ) )
		return ERR;

	win->ori_y = y;
	win->ori_x = x;

	return OK;
}

/**
 * Create new WINDOW
 *
 * @v nlines	number of lines
 * @v ncols	number of columns
 * @v begin_y	column origin
 * @v begin_x	line origin
 * @ret *win	return pointer to new window
 */
WINDOW *newwin ( int nlines, int ncols, int begin_y, int begin_x ) {
	WINDOW *win;
	if ( ( win = malloc( sizeof(WINDOW) ) ) == NULL )
		return NULL;
	if ( ( (unsigned)( begin_y + nlines ) > stdscr->height ) &&
	     ( (unsigned)( begin_x + ncols ) > stdscr->width ) )
		return NULL;
	win->ori_y = begin_y;
	win->ori_x = begin_x;
	win->height = nlines;
	win->width = ncols;
	win->scr = stdscr->scr;
	win->parent = stdscr;
	return win;
}

/**
 * Create a new sub-window
 *
 * @v orig	parent window
 * @v nlines	window height
 * @v ncols	window width
 * @v begin_y	window y origin (absolute)
 * @v begin_x	window x origin (absolute)
 * @ret ptr	return pointer to child window
 */
WINDOW *subwin ( WINDOW *parent, int nlines, int ncols,
			         int begin_y, int begin_x ) {
	WINDOW *child;
	if ( parent == NULL )
		return NULL;
	if ( ( child = malloc( sizeof( WINDOW ) ) ) == NULL )
		return NULL;
	child = newwin( nlines, ncols, begin_y, begin_x );
	child->parent = parent;
	child->scr = parent->scr;
	return child;
}
