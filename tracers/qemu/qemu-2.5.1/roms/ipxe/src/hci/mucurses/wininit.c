#include <stddef.h>
#include <curses.h>

/** @file
 *
 * MuCurses initialisation functions
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Initialise console environment
 *
 * @ret *win	return pointer to stdscr
 */
WINDOW *initscr ( void ) {
	/* determine console size */
	/* initialise screen */
	stdscr->scr->init( stdscr->scr );
	stdscr->height = LINES;
	stdscr->width = COLS;
	move ( 0, 0 );
	return stdscr;
}

/**
 * Finalise console environment
 *
 */
int endwin ( void ) {
	attrset ( 0 );
	color_set ( 0, NULL );
	curs_set ( 1 );
	mvprintw ( ( LINES - 1 ), 0, "\n" );
	stdscr->scr->exit( stdscr->scr );
	return OK;
}
