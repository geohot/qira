#include <stdio.h>
#include <curses.h>
#include <ipxe/ansicol.h>
#include <ipxe/console.h>

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

static void ansiscr_reset(struct _curses_screen *scr) __nonnull;
static void ansiscr_movetoyx(struct _curses_screen *scr,
                               unsigned int y, unsigned int x) __nonnull;
static void ansiscr_putc(struct _curses_screen *scr, chtype c) __nonnull;

static unsigned int saved_usage;

static void ansiscr_attrs ( struct _curses_screen *scr, attr_t attrs ) {
	int bold = ( attrs & A_BOLD );
	attr_t cpair = PAIR_NUMBER ( attrs );

	if ( scr->attrs != attrs ) {
		scr->attrs = attrs;
		/* Reset attributes and set/clear bold as appropriate */
		printf ( "\033[0;%dm", ( bold ? 1 : 22 ) );
		/* Set foreground and background colours */
		ansicol_set_pair ( cpair );
	}
}

static void ansiscr_reset ( struct _curses_screen *scr ) {
	/* Reset terminal attributes and clear screen */
	scr->attrs = 0;
	scr->curs_x = 0;
	scr->curs_y = 0;
	printf ( "\0330m" );
	ansicol_set_pair ( CPAIR_DEFAULT );
	printf ( "\033[2J" );
}

static void ansiscr_init ( struct _curses_screen *scr ) {
	saved_usage = console_set_usage ( CONSOLE_USAGE_TUI );
	ansiscr_reset ( scr );
}

static void ansiscr_exit ( struct _curses_screen *scr ) {
	ansiscr_reset ( scr );
	console_set_usage ( saved_usage );
}

static void ansiscr_erase ( struct _curses_screen *scr, attr_t attrs ) {
	ansiscr_attrs ( scr, attrs );
	printf ( "\033[2J" );
}

static void ansiscr_movetoyx ( struct _curses_screen *scr,
			       unsigned int y, unsigned int x ) {
	if ( ( x != scr->curs_x ) || ( y != scr->curs_y ) ) {
		/* ANSI escape sequence to update cursor position */
		printf ( "\033[%d;%dH", ( y + 1 ), ( x + 1 ) );
		scr->curs_x = x;
		scr->curs_y = y;
	}
}

static void ansiscr_putc ( struct _curses_screen *scr, chtype c ) {
	unsigned int character = ( c & A_CHARTEXT );
	attr_t attrs = ( c & ( A_ATTRIBUTES | A_COLOR ) );

	/* Update attributes if changed */
	ansiscr_attrs ( scr, attrs );

	/* Print the actual character */
	putchar ( character );

	/* Update expected cursor position */
	if ( ++(scr->curs_x) == COLS ) {
		scr->curs_x = 0;
		++scr->curs_y;
	}
}

static int ansiscr_getc ( struct _curses_screen *scr __unused ) {
	return getchar();
}

static bool ansiscr_peek ( struct _curses_screen *scr __unused ) {
	return iskey();
}

static void ansiscr_cursor ( struct _curses_screen *scr __unused,
			     int visibility ) {
	printf ( "\033[?25%c", ( visibility ? 'h' : 'l' ) );
}

SCREEN _ansi_screen = {
	.init		= ansiscr_init,
	.exit		= ansiscr_exit,
	.erase		= ansiscr_erase,
	.movetoyx	= ansiscr_movetoyx,
	.putc		= ansiscr_putc,
	.getc		= ansiscr_getc,
	.peek		= ansiscr_peek,
	.cursor		= ansiscr_cursor,
};
