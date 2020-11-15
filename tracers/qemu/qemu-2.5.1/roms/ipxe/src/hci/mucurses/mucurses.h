#ifndef _MUCURSES_H
#define _MUCURSES_H

/** @file
 *
 * MuCurses core implementation specific header file
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#define WRAP 0
#define NOWRAP 1

extern SCREEN _ansi_screen;

extern void _wputch ( WINDOW *win, chtype ch, int wrap ) __nonnull;
extern void _wputc ( WINDOW *win, char c, int wrap ) __nonnull;
extern void _wputchstr ( WINDOW *win, const chtype *chstr, int wrap, int n ) __nonnull;
extern void _wputstr ( WINDOW *win, const char *str, int wrap, int n ) __nonnull;
extern void _wcursback ( WINDOW *win ) __nonnull;

#endif /* _MUCURSES_H */
