#ifndef CURSES_H
#define CURSES_H

#include <stdint.h>
#include <stdarg.h>
#include <ipxe/console.h>

/** @file
 *
 * MuCurses header file
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#undef  ERR
#define ERR	(-1)

#undef  FALSE
#define FALSE	(0)

#undef  OK
#define OK	(0)

#undef  TRUE
#define TRUE	(1)

typedef int bool;
typedef uint32_t chtype;
typedef uint32_t attr_t;

/** Curses SCREEN object */
typedef struct _curses_screen {
	/** Current cursor position */
	unsigned int curs_x, curs_y;
	/** Current attribute */
	attr_t attrs;

	void ( *init ) ( struct _curses_screen *scr );
	void ( *exit ) ( struct _curses_screen *scr );
	/**
	 * Erase screen
	 *
	 * @v scr	screen on which to operate
	 * @v attrs	attributes
	 */
	void ( * erase ) ( struct _curses_screen *scr, attr_t attrs );
	/**
	 * Move cursor to position specified by x,y coords
	 *
	 * @v scr	screen on which to operate
	 * @v y		Y position
	 * @v x		X position
	 */
	void ( * movetoyx ) ( struct _curses_screen *scr,
			      unsigned int y, unsigned int x );
	/**
	 * Write character to current cursor position
	 *
	 * @v scr	screen on which to operate
	 * @v c		character to be written
	 */
	void ( * putc ) ( struct _curses_screen *scr, chtype c );
	/**
	 * Pop a character from the keyboard input stream
	 *
	 * @v scr	screen on which to operate
	 * @ret c	popped character
	 */
	int ( * getc ) ( struct _curses_screen *scr );
	/**
	 * Checks to see whether a character is waiting in the input stream
	 *
	 * @v scr	screen on which to operate
	 * @ret TRUE	character waiting in stream
	 * @ret FALSE	no character waiting in stream
	 */
	bool ( *peek ) ( struct _curses_screen *scr );
	/**
	 * Set cursor visibility
	 *
	 * @v scr	screen on which to operate
	 * @v visibility cursor visibility
	 */
	void ( * cursor ) ( struct _curses_screen *scr, int visibility );
} SCREEN;

/** Curses Window struct */
typedef struct _curses_window {
	/** screen with which window associates */
	SCREEN *scr;
	/** window attributes */
	attr_t attrs;
	/** window origin coordinates */
	unsigned int ori_x, ori_y;
	/** window cursor position */
	unsigned int curs_x, curs_y;
	/** window dimensions */
	unsigned int width, height;
	/** parent window */
	struct _curses_window *parent;
	/** windows that share the same parent as this one */
	//struct list_head siblings;
	/** windows der'd or sub'd from this one */
	//struct list_head children;
} WINDOW;

extern WINDOW _stdscr;

#define stdscr ( &_stdscr )
#define COLS console_width
#define LINES console_height

#define MUCURSES_BITS( mask, shift ) (( mask ) << (shift))
#define CPAIR_SHIFT	8
#define ATTRS_SHIFT	16

#define WA_DEFAULT	( 0x0000 << ATTRS_SHIFT )
#define WA_ALTCHARSET	( 0x0001 << ATTRS_SHIFT )
#define WA_BLINK	( 0x0002 << ATTRS_SHIFT )
#define WA_BOLD		( 0x0004 << ATTRS_SHIFT )
#define WA_DIM		( 0x0008 << ATTRS_SHIFT )
#define WA_INVIS	( 0x0010 << ATTRS_SHIFT )
#define WA_PROTECT	( 0x0020 << ATTRS_SHIFT )
#define WA_REVERSE	( 0x0040 << ATTRS_SHIFT )
#define WA_STANDOUT	( 0x0080 << ATTRS_SHIFT )
#define WA_UNDERLINE	( 0x0100 << ATTRS_SHIFT )
#define WA_HORIZONTAL	( 0x0200 << ATTRS_SHIFT )
#define WA_VERTICAL	( 0x0400 << ATTRS_SHIFT )
#define WA_LEFT		( 0x0800 << ATTRS_SHIFT )
#define WA_RIGHT	( 0x1000 << ATTRS_SHIFT )
#define WA_LOW		( 0x2000 << ATTRS_SHIFT )
#define WA_TOP		( 0x4000 << ATTRS_SHIFT )

#define A_DEFAULT	WA_DEFAULT
#define A_ALTCHARSET	WA_ALTCHARSET
#define A_BLINK		WA_BLINK
#define A_BOLD		WA_BOLD
#define A_DIM		WA_DIM
#define A_INVIS		WA_INVIS
#define A_PROTECT	WA_PROTECT
#define A_REVERSE	WA_REVERSE
#define A_STANDOUT	WA_STANDOUT
#define A_UNDERLINE	WA_UNDERLINE

#define A_ATTRIBUTES	( 0xffff << ATTRS_SHIFT )
#define A_CHARTEXT	( 0xff )
#define A_COLOUR	( 0xff << CPAIR_SHIFT )
#define A_COLOR		A_COLOUR

#define COLOUR_PAIR(n)	( (n) << CPAIR_SHIFT )
#define COLOR_PAIR(n)	COLOUR_PAIR(n)
#define PAIR_NUMBER(attrs) ( ( (attrs) & A_COLOUR ) >> CPAIR_SHIFT )

#define COLOUR_PAIRS	8 /* Arbitrary limit */
#define COLOR_PAIRS	COLOUR_PAIRS

#define ACS_ULCORNER	'+'
#define ACS_LLCORNER	'+'
#define ACS_URCORNER	'+'
#define ACS_LRCORNER	'+'
#define ACS_RTEE	'+'
#define ACS_LTEE	'+'
#define ACS_BTEE	'+'
#define ACS_TTEE	'+'
#define ACS_HLINE	'-'
#define ACS_VLINE	'|'
#define ACS_PLUS	'+'
#define ACS_S1		'-'
#define ACS_S9		'_'
#define ACS_DIAMOND	'+'
#define ACS_CKBOARD	':'
#define ACS_DEGREE	'\''
#define ACS_PLMINUS	'#'
#define ACS_BULLET	'o'
#define ACS_LARROW	'<'
#define ACS_RARROW	'>'
#define ACS_DARROW	'v'
#define ACS_UARROW	'^'
#define ACS_BOARD	'#'
#define ACS_LANTERN	'#'
#define ACS_BLOCK	'#'

#define COLOUR_BLACK	0
#define COLOUR_RED	1
#define COLOUR_GREEN	2
#define COLOUR_YELLOW	3
#define COLOUR_BLUE	4
#define COLOUR_MAGENTA	5
#define COLOUR_CYAN	6
#define COLOUR_WHITE	7
#define COLOURS		7

#define COLOUR_FG	30
#define COLOUR_BG	40
#define COLOR_FG	COLOUR_FG
#define COLOR_BG	COLOUR_BG

#define COLOR_BLACK	COLOUR_BLACK
#define COLOR_BLUE	COLOUR_BLUE
#define COLOR_GREEN	COLOUR_GREEN
#define COLOR_CYAN	COLOUR_CYAN
#define COLOR_RED	COLOUR_RED
#define COLOR_MAGENTA	COLOUR_MAGENTA
#define COLOR_YELLOW	COLOUR_YELLOW
#define COLOR_WHITE	COLOUR_WHITE
#define COLORS		COLOURS

/*
 * KEY code constants are define in ipxe/keys.h
 */
#include <ipxe/keys.h>

//extern int addch ( const chtype * );
//extern int addchnstr ( const chtype *, int );
//extern int addchstr ( const chtype * );
//extern int addnstr ( const char *, int );
//extern int addstr ( const char * );
//extern int attroff ( int );
//extern int attron ( int );
//extern int attrset ( int );
//extern int attr_get ( attr_t *, short *, void * );
//extern int attr_off ( attr_t, void * );
//extern int attr_on ( attr_t, void * );
//extern int attr_set ( attr_t, short, void * );
extern int baudrate ( void );
extern int beep ( void );
//extern void bkgdset ( chtype );
/*extern int border ( chtype, chtype, chtype, chtype, chtype, chtype, chtype,
  chtype );*/
extern int box ( WINDOW *, chtype, chtype ) __nonnull;
//extern bool can_change_colour ( void );
#define can_change_color() can_change_colour()
extern int cbreak ( void ); 
//extern int clrtobot ( void );
//extern int clrtoeol ( void );
extern int colour_content ( short, short *, short *, short * ) __nonnull;
#define color_content( c, r, g, b ) colour_content( (c), (r), (g), (b) )
//extern int colour_set ( short, void * );
#define color_set( cpno, opts ) colour_set( (cpno), (opts) )
extern int copywin ( const WINDOW *, WINDOW *, int, int, int, 
		     int, int, int, int );
extern int curs_set ( int );
extern int def_prog_mode ( void );
extern int def_shell_mode ( void );
extern int delay_output ( int );
//extern int delch ( void );
//extern int deleteln ( void );
extern void delscreen ( SCREEN * );
extern int delwin ( WINDOW * ) __nonnull;
extern WINDOW *derwin ( WINDOW *, int, int, int, int ) __nonnull;
//extern int doupdate ( void );
extern WINDOW *dupwin ( WINDOW * ) __nonnull;
extern int echo ( void );
extern int echochar ( const chtype );
extern int endwin ( void );
extern char erasechar ( void );
extern int erase ( void );
extern void filter ( void );
extern int flash ( void );
extern int flushinp ( void );
extern __pure chtype getbkgd ( WINDOW * ) __nonnull;
//extern int getch ( void );
//extern int getnstr ( char *, int );
//extern int getstr ( char * );
extern int halfdelay ( int );
//extern bool has_colors ( void );
extern bool has_ic ( void );
extern bool has_il ( void );
//extern int hline ( chtype, int );
extern void idcok ( WINDOW *, bool );
extern int idlok ( WINDOW *, bool );
//extern void immedok ( WINDOW *, bool );
//extern chtype inch ( void );
//extern int inchnstr ( chtype *, int );
//extern int inchstr ( chtype * );
extern WINDOW *initscr ( void );
extern int init_colour ( short, short, short, short );
#define init_color ( c, r, g, b ) init_colour ( (c), (r), (g), (b) )
extern int init_pair ( short, short, short );
//extern int innstr ( char *, int );
//extern int insch ( chtype );
//extern int insnstr ( const char *, int );
//extern int insstr ( const char * );
//extern int instr ( char * );
extern int intrflush ( WINDOW *, bool );
extern bool isendwin ( void );
//extern bool is_linetouched ( WINDOW *, int );
//extern bool is_wintouched ( WINDOW * );
extern char *keyname ( int );
extern int keypad ( WINDOW *, bool );
extern char killchar ( void );
extern int leaveok ( WINDOW *, bool );
extern char *longname ( void );
extern int meta ( WINDOW *, bool );
//extern int move ( int, int );
//extern int mvaddch ( int, int, const chtype );
//extern int mvaddchnstr ( int, int, const chtype *, int );
//extern int mvaddchstr ( int, int, const chtype * );
//extern int mvaddnstr ( int, int, const char *, int );
//extern int mvaddstr ( int, int, const char * );
extern int mvcur ( int, int, int, int );
//extern int mvdelch ( int, int );
extern int mvderwin ( WINDOW *, int, int );
//extern int mvgetch ( int, int );
//extern int mvgetnstr ( int, int, char *, int );
//extern int mvgetstr ( int, int, char * );
//extern int mvhline ( int, int, chtype, int );
//extern chtype mvinch ( int, int );
//extern int mvinchnstr ( int, int, chtype *, int );
//extern int mvinchstr ( int, int, chtype * );
//extern int mvinnstr ( int, int, char *, int );
//extern int mvinsch ( int, int, chtype );
//extern int mvinsnstr ( int, int, const char *, int );
//extern int mvinsstr ( int, int, const char * );
//extern int mvinstr ( int, int, char * );
//extern int mvprintw ( int, int, char *,  ... );
//extern int mvscanw ( int, int, char *, ... );
//extern int mvvline ( int, int, chtype, int );
//extern int mvwaddch ( WINDOW *, int, int, const chtype );
//extern int mvwaddchnstr ( WINDOW *, int, int, const chtype *, int );
//extern int mvwaddchstr ( WINDOW *, int, int, const chtype * );
//extern int mvwaddnstr ( WINDOW *, int, int, const char *, int );
//extern int mvwaddstr ( WINDOW *, int, int, const char * );
//extern int mvwdelch ( WINDOW *, int, int );
//extern int mvwgetch ( WINDOW *, int, int );
//extern int mvwgetnstr ( WINDOW *, int, int, char *, int );
//extern int mvwgetstr ( WINDOW *, int, int, char * );
//extern int mvwhline ( WINDOW *, int, int, chtype, int );
extern int mvwin ( WINDOW *, int, int ) __nonnull;
//extern chtype mvwinch ( WINDOW *, int, int );
//extern int mvwinchnstr ( WINDOW *, int, int, chtype *, int );
//extern int mvwinchstr ( WINDOW *, int, int, chtype * );
//extern int mvwinnstr ( WINDOW *, int, int, char *, int );
//extern int mvwinsch ( WINDOW *, int, int, chtype );
//extern int mvwinsnstr ( WINDOW *, int, int, const char *, int );
//extern int mvwinsstr ( WINDOW *, int, int, const char * );
//extern int mvwinstr ( WINDOW *, int, int, char * );
//extern int mvwprintw ( WINDOW *, int, int, char *, ... );
//extern int mvwscanw ( WINDOW *, int, int, char *, ... );
//extern int mvwvline ( WINDOW *, int, int, chtype, int );
extern int napms ( int );
//extern WINDOW *newpad ( int, int );
extern WINDOW *newwin ( int, int, int, int );
extern int nl ( void );
extern int nocbreak ( void );
extern int nodelay ( WINDOW *, bool );
extern int noecho ( void );
extern int nonl ( void );
extern void noqiflush ( void );
extern int noraw ( void );
extern int notimeout ( WINDOW *, bool );
extern int overlay ( const WINDOW *, WINDOW * );
extern int overwrite ( const WINDOW *, WINDOW * );
extern int pair_content ( short, short *, short * ) __nonnull;
//extern int pechochar ( WINDOW *, chtype );
//extern int pnoutrefresh ( WINDOW *, int, int, int, int, int, int );
//extern int prefresh ( WINDOW *, int, int, int, int, int, int );
extern int printw ( char *, ... );
extern int putp ( const char * );
extern void qiflush ( void );
extern int raw ( void );
//extern int redrawwin ( WINDOW * );
//extern int refresh ( void );
extern int reset_prog_mode ( void );
extern int reset_shell_mode ( void );
extern int resetty ( void );
extern int ripoffline ( int, int  (*) ( WINDOW *, int) );
extern int savetty ( void );
//extern int scanw ( char *, ... );
//extern int scrl ( int );
//extern int scroll ( WINDOW * );
//extern int scrollok ( WINDOW *, bool );
//extern int setscrreg ( int, int );
extern SCREEN *set_term ( SCREEN * );
extern int setupterm ( char *, int, int * );
extern int slk_attr_off ( const attr_t, void * );
extern int slk_attroff ( const chtype );
extern int slk_attr_on ( const attr_t, void * );
extern int slk_attron ( const chtype );
extern int slk_attr_set ( const attr_t, short, void * );
extern int slk_attrset ( const chtype );
extern int slk_clear ( void );
extern int slk_colour ( short );
#define slk_color( c ) slk_colour( (c) )
extern int slk_init ( int );
extern char *slk_label ( int );
extern int slk_noutrefresh ( void );
//extern int slk_refresh ( void );
extern int slk_restore ( void );
extern int slk_set ( int, const char *, int ) __nonnull;
extern int slk_touch ( void );
extern int standend ( void );
extern int standout ( void );
//extern int start_colour ( void );
#define start_color() start_colour()
//extern WINDOW *subpad ( WINDOW *, int, int, int, int );
extern WINDOW *subwin ( WINDOW *, int, int, int, int ) __nonnull;
extern int syncok ( WINDOW *, bool );
extern chtype termattrs ( void );
extern attr_t term_attrs ( void );
extern char *termname ( void );
extern int tigetflag ( char * );
extern int tigetnum ( char * );
extern char *tigetstr ( char * );
extern void timeout ( int );
//extern int touchline ( WINDOW *, int, int );
//extern int touchwin ( WINDOW * );
extern char *tparm ( char *, long, long, long, long, long, long, long, long,
		   long );
extern int typeahead ( int );
//extern int ungetch ( int );
//extern int untouchwin ( WINDOW * );
extern void use_env ( bool );
extern int vid_attr ( attr_t, short, void * );
extern int vidattr ( chtype );
extern int vid_puts ( attr_t, short, void *, int  ( *) ( int) );
extern int vidputs ( chtype, int  ( *) ( int) );
//extern int vline ( chtype, int );
//extern int vwprintw ( WINDOW *, const char *, va_list );
extern int vw_printw ( WINDOW *, const char *, va_list ) __nonnull;
//extern int vwscanw ( WINDOW *, char *, va_list );
//extern int vw_scanw ( WINDOW *, char *, va_list );
extern int waddch ( WINDOW *, const chtype ) __nonnull;
extern int waddchnstr ( WINDOW *, const chtype *, int ) __nonnull;
//extern int waddchstr ( WINDOW *, const chtype * );
extern int waddnstr ( WINDOW *, const char *, int ) __nonnull;
//extern int waddstr ( WINDOW *, const char * );
extern int wattroff ( WINDOW *, int ) __nonnull;
extern int wattron ( WINDOW *, int ) __nonnull;
extern int wattrset ( WINDOW *, int ) __nonnull;
extern int wattr_get ( WINDOW *, attr_t *, short *, void * )
	__attribute__ (( nonnull (1, 2, 3)));
extern int wattr_off ( WINDOW *, attr_t, void * )
	__attribute__ (( nonnull (1)));
extern int wattr_on ( WINDOW *, attr_t, void * )
	__attribute__ (( nonnull (1)));
extern int wattr_set ( WINDOW *, attr_t, short, void * )
	__attribute__ (( nonnull (1)));
//extern void wbkgdset ( WINDOW *, chtype );
extern int wborder ( WINDOW *, chtype, chtype, chtype, chtype, chtype, chtype,
		   chtype, chtype ) __nonnull;
extern int wclrtobot ( WINDOW * ) __nonnull;
extern int wclrtoeol ( WINDOW * ) __nonnull;
extern void wcursyncup ( WINDOW * );
extern int wcolour_set ( WINDOW *, short, void * ) __nonnull;
#define wcolor_set(w,s,v) wcolour_set((w),(s),(v))
extern int wdelch ( WINDOW * ) __nonnull;
extern int wdeleteln ( WINDOW * ) __nonnull;
extern int wechochar ( WINDOW *, const chtype );
extern int werase ( WINDOW * ) __nonnull;
extern int wgetch ( WINDOW * );
extern int wgetnstr ( WINDOW *, char *, int );
//extern int wgetstr ( WINDOW *, char * );
extern int whline ( WINDOW *, chtype, int ) __nonnull;
//extern chtype winch ( WINDOW * );
//extern int winchnstr ( WINDOW *, chtype *, int );
//extern int winchstr ( WINDOW *, chtype * );
//extern int winnstr ( WINDOW *, char *, int );
//extern int winsch ( WINDOW *, chtype );
//extern int winsnstr ( WINDOW *, const char *, int );
//extern int winsstr ( WINDOW *, const char * );
//extern int winstr ( WINDOW *, char * );
extern int wmove ( WINDOW *, int, int );
//extern int wnoutrefresh ( WINDOW * );
extern int wprintw ( WINDOW *, const char *, ... ) __nonnull;
//extern int wredrawln ( WINDOW *, int, int );
//extern int wrefresh ( WINDOW * );
//extern int wscanw ( WINDOW *, char *, ... );
//extern int wscrl ( WINDOW *, int );
//extern int wsetscrreg ( WINDOW *, int, int );
//extern int wstandend ( WINDOW * );
//extern int wstandout ( WINDOW * );
extern void wsyncup ( WINDOW * );
extern void wsyncdown ( WINDOW * );
extern void wtimeout ( WINDOW *, int );
//extern int wtouchln ( WINDOW *, int, int, int );
extern int wvline ( WINDOW *, chtype, int ) __nonnull;

/*
 * There is frankly a ridiculous amount of redundancy within the
 * curses API - ncurses decided to get around this by using #define
 * macros, but I've decided to be type-safe and implement them all as
 * static inlines instead...
 */

static inline int addch ( const chtype ch ) {
	return waddch( stdscr, ch );
}

static inline int addchnstr ( const chtype *chstr, int n ) {
	return waddchnstr ( stdscr, chstr, n );
}

static inline int addchstr ( const chtype *chstr ) {
	return waddchnstr ( stdscr, chstr, -1 );
}

static inline int addnstr ( const char *str, int n ) {
	return waddnstr ( stdscr, str, n );
}

static inline int addstr ( const char *str ) {
	return waddnstr ( stdscr, str, -1 );
}

static inline int attroff ( int attrs ) {
	return wattroff ( stdscr, attrs );
}

static inline int attron ( int attrs ) {
	return wattron ( stdscr, attrs );
}

static inline int attrset ( int attrs ) {
	return wattrset ( stdscr, attrs );
}

static inline int attr_get ( attr_t *attrs, short *pair, void *opts ) {
	return wattr_get ( stdscr, attrs, pair, opts );
}

static inline int attr_off ( attr_t attrs, void *opts ) {
	return wattr_off ( stdscr, attrs, opts );
}

static inline int attr_on ( attr_t attrs, void *opts ) {
	return wattr_on ( stdscr, attrs, opts );
}

static inline int attr_set ( attr_t attrs, short cpair, void *opts ) {
	return wattr_set ( stdscr, attrs, cpair, opts );
}

static inline void bkgdset ( chtype ch ) {
	wattrset ( stdscr, ch );
}

static inline int border ( chtype ls, chtype rs, chtype ts, chtype bs,
			   chtype tl, chtype tr, chtype bl, chtype br ) {
	return wborder ( stdscr, ls, rs, ts, bs, tl, tr, bl, br );
}

static inline bool can_change_colour ( void ) {
	return FALSE;
}

static inline int clrtobot ( void ) {
	return wclrtobot( stdscr );
}

static inline int clrtoeol ( void ) {
	return wclrtoeol( stdscr );
}

static inline int colour_set ( short colour_pair_number, void *opts ) {
	return wcolour_set ( stdscr, colour_pair_number, opts );
}

static inline int delch ( void ) {
	return wdelch ( stdscr );
}

static inline int deleteln ( void ) {
	return wdeleteln( stdscr );
}

static inline int getch ( void ) {
	return wgetch ( stdscr );
}

static inline int getnstr ( char *str, int n ) {
	return wgetnstr ( stdscr, str, n );
}

static inline int getstr ( char *str ) {
	return wgetnstr ( stdscr, str, -1 );
}

static inline bool has_colors ( void ) {
	return TRUE;
}

static inline int has_key ( int kc __unused ) {
	return TRUE;
}

static inline int hline ( chtype ch, int n ) {
	return whline ( stdscr, ch, n );
}

static inline int move ( int y, int x ) {
	return wmove ( stdscr, y, x );
}

static inline int mvaddch ( int y, int x, const chtype ch ) {
	return ( wmove ( stdscr, y, x ) == OK
		 ? waddch( stdscr, ch ) : ERR );
}

static inline int mvaddchnstr ( int y, int x, const chtype *chstr, int n ) {
	return ( wmove ( stdscr, y, x ) == OK
		 ? waddchnstr ( stdscr, chstr, n ) : ERR );
}

static inline int mvaddchstr ( int y, int x, const chtype *chstr ) {
	return ( wmove ( stdscr, y, x ) == OK
		 ? waddchnstr ( stdscr, chstr, -1 ) : ERR );
}

static inline int mvaddnstr ( int y, int x, const char *str, int n ) {
	return ( wmove ( stdscr, y, x ) == OK
		 ? waddnstr ( stdscr, str, n ) : ERR );
}

static inline int mvaddstr ( int y, int x, const char *str ) {
	return ( wmove ( stdscr, y, x ) == OK
		 ? waddnstr ( stdscr, str, -1 ) : ERR );
}

static inline int mvdelch ( int y, int x ) {
	return ( wmove ( stdscr, y, x ) == OK
		 ? wdelch ( stdscr ) : ERR );
}

static inline int mvgetch ( int y, int x ) {
	return ( wmove ( stdscr, y, x ) == OK
		 ? wgetch ( stdscr ) : ERR );
}

static inline int mvgetnstr ( int y, int x, char *str, int n ) {
	return ( wmove ( stdscr, y, x ) == OK
		 ? wgetnstr ( stdscr, str, n ) : ERR );
}

static inline int mvgetstr ( int y, int x, char *str ) {
	return ( wmove ( stdscr, y, x ) == OK
		 ? wgetnstr ( stdscr, str, -1 ) : ERR );
}

static inline int mvhline ( int y, int x, chtype ch, int n ) {
	return ( wmove ( stdscr, y, x ) == OK
		 ? whline ( stdscr, ch, n ) : ERR );
}

// OK, so maybe a few I did with macros...
#define mvprintw( y, x, fmt, ... ) \
	( wmove(stdscr,(y),(x)) == OK \
	  ? wprintw( stdscr,(fmt), ## __VA_ARGS__ ) : ERR )

static inline int mvvline ( int y, int x, chtype ch, int n ) {
	return ( wmove ( stdscr, y, x ) == OK
		 ? wvline ( stdscr, ch, n ) : ERR );
}

static inline int mvwaddch ( WINDOW *win, int y, int x, const chtype ch ) {
	return ( wmove( win, y, x ) == OK
		 ? waddch ( win, ch ) : ERR );
}

static inline int mvwaddchnstr ( WINDOW *win, int y, int x, const chtype *chstr, int n ) {
	return ( wmove ( win, y, x ) == OK
		 ? waddchnstr ( win, chstr, n ) : ERR );
}

static inline int mvwaddchstr ( WINDOW *win, int y, int x, const chtype *chstr ) {
	return ( wmove ( win, y, x ) == OK
		 ? waddchnstr ( win, chstr, -1 ) : ERR );
}

static inline int mvwaddnstr ( WINDOW *win, int y, int x, const char *str, int n ) {
	return ( wmove ( win, y, x ) == OK
		 ? waddnstr ( win, str, n ) : ERR );
}

static inline int mvwaddstr ( WINDOW *win, int y, int x, const char *str ) {
	return ( wmove ( win, y, x ) == OK
		 ? waddnstr ( win, str, -1 ) : ERR );
}

static inline int mvwdelch ( WINDOW *win, int y, int x ) {
	return ( wmove ( win, y, x ) == OK
		 ? wdelch ( win ) : ERR );
}

static inline int mvwgetch ( WINDOW *win, int y, int x ) {
	return ( wmove ( win, y, x ) == OK
		 ? wgetch ( win ) : ERR );
}

static inline int mvwgetnstr ( WINDOW *win, int y, int x, char *str, int n ) {
	return ( wmove ( win, y, x ) == OK
		 ? wgetnstr ( win, str, n ) : ERR );
}

static inline int mvwgetstr ( WINDOW *win, int y, int x, char *str ) {
	return ( wmove ( win, y, x ) == OK
		 ? wgetnstr ( win, str, -1 ) : ERR );
}

static inline int mvwhline ( WINDOW *win, int y, int x, chtype ch, int n ) {
	return ( wmove ( win, y, x ) == OK
		 ? whline ( win, ch, n ) : ERR );
}

#define mvwprintw( win, y, x, fmt, ... ) \
	( wmove((win),(y),(x)) == OK \
	  ? wprintw((win),(fmt), ## __VA_ARGS__) : ERR )

static inline int mvwvline ( WINDOW *win, int y, int x, chtype ch, int n ) {
	return ( wmove ( win, y, x ) == OK
		 ? wvline ( win, ch, n ) : ERR );
}

#define printw( fmt, ... ) wprintw(stdscr,(fmt), ## __VA_ARGS__ )

static inline int slk_refresh ( void ) {
	if ( slk_clear() == OK )
		return slk_restore();
	else
		return ERR;
}

#define standend() wstandend( stdscr )
#define standout() wstandout( stdscr )

static inline int start_colour ( void ) {
	return OK;
}

static inline int vline ( chtype ch, int n ) {
	return wvline ( stdscr, ch, n );
}

// marked for removal
static inline int vwprintw ( WINDOW *win, const char *fmt, va_list varglist ) {
	return vw_printw ( win, fmt, varglist );
}

static inline int waddchstr ( WINDOW *win, const chtype *chstr ) {
	return waddchnstr ( win, chstr, -1 );
}

static inline int waddstr ( WINDOW *win, const char *str ) {
	return waddnstr ( win, str, -1 );
}

static inline int wbkgdset ( WINDOW *win, chtype ch ) {
	return wattrset( win, ch );
}

static inline int wgetstr ( WINDOW *win, char *str ) {
	return wgetnstr ( win, str, -1 );
}

static inline int wstandend ( WINDOW *win ) {
	return wattrset ( win, A_DEFAULT );
}

static inline int wstandout ( WINDOW *win ) {
	return wattrset ( win, A_STANDOUT );
}

#endif /* CURSES_H */
