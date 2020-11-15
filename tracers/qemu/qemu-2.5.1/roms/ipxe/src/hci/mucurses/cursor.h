#ifndef CURSOR_H
#define CURSOR_H

/** @file
 *
 * MuCurses cursor implementation specific header file
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

struct cursor_pos {
	unsigned int y, x;
};

/**
 * Restore cursor position from encoded backup variable
 *
 * @v *win	window on which to operate
 * @v *pos	pointer to struct in which original cursor position is stored
 */
static inline void _restore_curs_pos ( WINDOW *win, struct cursor_pos *pos ) {
	wmove ( win, pos->y, pos->x );
}

/**
 * Store cursor position for later restoration
 *
 * @v *win	window on which to operate
 * @v *pos	pointer to struct in which to store cursor position
 */
static inline void _store_curs_pos ( WINDOW *win, struct cursor_pos *pos ) {
	pos->y = win->curs_y;
	pos->x = win->curs_x;
}

#endif /* CURSOR_H */
