#include <curses.h>
#include "mucurses.h"
#include "cursor.h"

/** @file
 *
 * MuCurses edging functions
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Draw borders from single-byte characters and renditions around a
 * window
 *
 * @v *win	window to be bordered
 * @v verch	vertical chtype
 * @v horch	horizontal chtype
 * @ret rc	return status code
 */
int box ( WINDOW *win, chtype verch, chtype horch ) {
	chtype corner = '+' | win->attrs; /* default corner character */
	return wborder( win, verch, verch, horch, horch,
			corner, corner, corner, corner );
}

/**
 * Draw borders from single-byte characters and renditions around a
 * window
 *
 * @v *win	window to be bordered
 * @v ls	left side
 * @v rs	right side
 * @v ts	top
 * @v bs	bottom
 * @v tl	top left corner
 * @v tr	top right corner
 * @v bl	bottom left corner
 * @v br	bottom right corner
 * @ret rc	return status code
 */
int wborder ( WINDOW *win, chtype ls, chtype rs,
	      chtype ts, chtype bs, chtype tl,
	      chtype tr, chtype bl, chtype br ) {
	struct cursor_pos pos;

	_store_curs_pos( win, &pos );
	wmove(win,0,0);

	_wputch(win,tl,WRAP);
	while ( ( win->width - 1 ) - win->curs_x ) {
		_wputch(win,ts,WRAP);
	}
	_wputch(win,tr,WRAP);

	while ( ( win->height - 1 ) - win->curs_y ) {
		_wputch(win,ls,WRAP);
		wmove(win,win->curs_y,(win->width)-1);
		_wputch(win,rs,WRAP);
	}

	_wputch(win,bl,WRAP);
	while ( ( win->width -1 ) - win->curs_x ) {
		_wputch(win,bs,WRAP);
	}
	_wputch(win,br,NOWRAP); /* do not wrap last char to leave
				   cursor in last position */
	_restore_curs_pos( win, &pos );

	return OK;
}

/**
 * Create a horizontal line in a window
 *
 * @v *win	subject window
 * @v ch	rendition and character
 * @v n		max number of chars (wide) to render
 * @ret rc	return status code
 */
int whline ( WINDOW *win, chtype ch, int n ) {
	struct cursor_pos pos;

	_store_curs_pos ( win, &pos );
	while ( ( win->curs_x - win->width ) && n-- ) {
		_wputch ( win, ch, NOWRAP );
	}
	_restore_curs_pos ( win, &pos );

	return OK;
}

/**
 * Create a vertical line in a window
 *
 * @v *win	subject window
 * @v ch	rendition and character
 * @v n		max number of chars (high) to render
 * @ret rc	return status code
 */
int wvline ( WINDOW *win, chtype ch, int n ) {
	struct cursor_pos pos;

	_store_curs_pos ( win, &pos );
	while ( ( win->curs_y - win->height ) && n-- ) {
		_wputch ( win, ch, NOWRAP );
		wmove( win, ++(win->curs_y), pos.x);
	}
	_restore_curs_pos ( win, &pos );

	return OK;
}
