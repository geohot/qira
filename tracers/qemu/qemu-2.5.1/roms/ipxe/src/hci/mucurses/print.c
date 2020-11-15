#include <curses.h>
#include <stdio.h>
#include <stddef.h>
#include <ipxe/vsprintf.h>
#include "mucurses.h"

/** @file
 *
 * MuCurses printing functions
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/**
 * Add a single-byte character and rendition to a window and advance
 * the cursor
 *
 * @v *win	window to be rendered in
 * @v ch	character to be added at cursor
 * @ret rc	return status code
 */
int waddch ( WINDOW *win, const chtype ch ) {
	_wputch( win, ch, WRAP );
	return OK;
}

/**
 * Add string of single-byte characters to a window
 *
 * @v *win	window to be rendered in
 * @v *str	standard c-style string
 * @v n		max number of chars from string to render
 * @ret rc	return status code
 */
int waddnstr ( WINDOW *win, const char *str, int n ) {
	_wputstr( win, str, WRAP, n );
	return OK;
}

struct printw_context {
	struct printf_context ctx;
	WINDOW *win;
};

static void _printw_handler ( struct printf_context *ctx, unsigned int c ) {
	struct printw_context *wctx =
		container_of ( ctx, struct printw_context, ctx );

	_wputch( wctx->win, c | wctx->win->attrs, WRAP );
}

/**
 * Print formatted output in a window
 *
 * @v *win	subject window
 * @v *fmt	formatted string
 * @v varglist	argument list
 * @ret rc	return status code
 */
int vw_printw ( WINDOW *win, const char *fmt, va_list varglist ) {
	struct printw_context wctx;

	wctx.win = win;
	wctx.ctx.handler = _printw_handler;
	vcprintf ( &(wctx.ctx), fmt, varglist );
	return OK;
}

/**
 * Print formatted output to a window
 *
 * @v *win	subject window
 * @v *fmt	formatted string
 * @v ...	string arguments
 * @ret rc	return status code
 */
int wprintw ( WINDOW *win, const char *fmt, ... ) {
	va_list args;
	int i;

	va_start ( args, fmt );
	i = vw_printw ( win, fmt, args );
	va_end ( args );
	return i;
}
