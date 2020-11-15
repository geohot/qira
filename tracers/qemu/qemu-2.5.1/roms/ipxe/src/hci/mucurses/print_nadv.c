#include <curses.h>
#include "mucurses.h"
#include "cursor.h"

/** @file
 *
 * MuCurses printing functions (no cursor advance)
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Add string of single-byte characters and renditions to a window
 *
 * @v *win	window to be rendered in
 * @v *chstr	pointer to first chtype in "string"
 * @v n		max number of chars from chstr to render
 * @ret rc	return status code
 */
int waddchnstr ( WINDOW *win, const chtype *chstr, int n ) {
	struct cursor_pos pos;	

	_store_curs_pos( win, &pos );
	_wputchstr( win, chstr, NOWRAP, n );
	_restore_curs_pos( win, &pos );
	return OK;
}
