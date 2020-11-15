/*
 *   Creation Date: <2003/12/28 14:16:31 samuel>
 *   Time-stamp: <2004/01/07 10:37:40 samuel>
 *
 *	<cmdline.c>
 *
 *	OpenFirmwware User Interface
 *
 *   Copyright (C) 2003, 2004 Samuel Rydh (samuel@ibrium.se)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   version 2
 *
 */

#include "config.h"
#include "libopenbios/bindings.h"
#include "packages.h"
#include "libc/vsprintf.h"

typedef struct {
	char	*buf;		/* size: ncol+1 */
	char	*killbuf;	/* size: ncol+1 */
	char	*history;
	int	hsize;		/* size of history buffer */
	int	ncol;		/* #columns */
} cmdline_info_t;

DECLARE_NODE( cmdline, INSTALL_OPEN, sizeof(cmdline_info_t),
	      "+/packages/cmdline" );

static void
emit( int ch )
{
	PUSH( ch );
	fword("emit");
}

static int
emit_str( const char *str )
{
	int n = 0;
	while( *str ) {
		n++;
		emit( *str++ );
	}
	return n;
}

static void
move_cursor( int n )
{
	if( n >= 0 ) {
		while( n-- )
			emit( '\f' );
	} else {
		while( n++ )
			emit( 8 );
	}
}

static void
clear( int n )
{
	int i;
	for( i=0; i<n; i++ )
		emit(' ');
	move_cursor( -n );
}

static void
clearline( int pos, int n )
{
	move_cursor( -pos );
	clear( n );
}

static int
key( void )
{
	fword("key");
	return POP();
}

/* ( -- flag ) */
static void
cmdline_open( cmdline_info_t *ci )
{
	ci->ncol = 80;
	ci->buf = malloc( ci->ncol + 1 );
	ci->killbuf = malloc( ci->ncol + 1 );

	ci->hsize = 40;
	ci->history = malloc( ci->hsize );
	ci->history[0] = 0;

	RET( -1 );
}

/* ( -- ) */
static void
cmdline_close( cmdline_info_t *ci )
{
	free( ci->buf );
	free( ci->killbuf );
	free( ci->history );
}


static char *
history_get( cmdline_info_t *ci, int n )
{
	char *p = ci->history;
	int len;

	while( n-- && p )
		if( (p=strchr(p,'\n')) )
			p++;

	ci->buf[0] = 0;
	if( !p )
                return NULL;

	for( len=0; len <= ci->ncol && p[len] != '\n' && p[len] ; len++ )
		;
	memcpy( ci->buf, p, len );
	ci->buf[len] = 0;
	return p;
}

static int
history_remove( cmdline_info_t *ci, int line )
{
	char *s, *p = history_get( ci, line );

	if( !p || !(s=strchr(p, '\n')) )
		return 1;
	s++;
	memmove( p, s, strlen(s)+1 );
	return 0;
}

static int /* ( -- ) */
add_to_history( cmdline_info_t *ci, char *str )
{
	int n, len;

	if( !ci->history )
		return 0;
	len = strlen(str);
	if( !len )
		return 0;

	/* make room for line in history */
	for( ;; ) {
		char *p;
		n = strlen(ci->history) + 1;

		if( n + len + 1 <= ci->hsize )
			break;

		if( !(p=strrchr(ci->history,'\n')) )
			return 0;
		*p = 0;
		if( !(p=strrchr(ci->history, '\n')) )
			p = ci->history-1;
		p[1] = 0;
	}

	memmove( ci->history + len + 1, ci->history, n );
	memcpy( ci->history, str, len );
	ci->history[ len ] = '\n';
	return 1;
}

static void /* ( -- ) */
cmdline_prompt( cmdline_info_t *ci )
{
	int cur_added=0, histind=0, ch, i, pos=0, n=0, prompt=1;
        char *buf;
	int terminate = 0;

	buf = ci->buf;
	selfword("prepare");

	emit('\n');
#ifdef NOLEAVE
	for (;;)
#else
	while (rstackcnt && !terminate)
#endif
	{
		int drop = 0;
		terminate = 0;

		if( prompt ) {
			fword("print-prompt");
			buf[0] = 0;
			cur_added = prompt = histind = pos = n = 0;
		}

		ch = key();
		switch( ch ) {
		case 27:
			switch( key() ) {
			case 'f':
				while( buf[pos] == ' ' )
					emit( buf[pos++] );
				while( buf[pos] && buf[pos] != ' ' )
					emit( buf[pos++] );
				break;

			case 'b':
				while( pos && buf[pos-1] == ' ' ) {
					move_cursor( -1 );
					pos--;
				}
				while( pos && buf[pos-1] != ' ' ) {
					move_cursor( -1 );
					pos--;
				}
				break;
			case '[':
				switch( key() ) {
				case 'A':
					goto go_up;
				case 'B':
					goto go_down;
				case 'C':
					goto go_right;
				case 'D':
					goto go_left;
				case '3':
					key();
					goto delete;
				}
				break;
			case 'O':
				switch(key()) {
				case 'F':
					goto go_end;
				case 'H':
					goto go_home;
				}
				break;
			}
			break;
		case '\n':
		case '\r':
			if( cur_added )
				history_remove( ci, 0 );
			add_to_history( ci, ci->buf );

			emit_str( &buf[pos] );
			emit(' ');
			PUSH( feval(buf) );
			fword("print-status");

			/* Leave the interpreter if terminate? value set */
			fword("terminate?");
			if (POP())
				terminate = 1;

			prompt = 1;
			break;

		case 3: /* ^c */
			emit_str("\n");
			prompt = 1;
			if( cur_added )
				history_remove( ci, 0 );
			break;

		case 4: /* ^d */
delete:
			if( pos == n )
				break;
			emit( buf[pos++] );
			/* fall through */

		case 8: /* ^h */
		case 127: /* backspace */
			drop = 1;
			if( !pos )
				break;
			move_cursor( -1 );
			emit_str( &buf[pos] );
			emit(' ');
			memmove( &buf[pos-1], &buf[pos], n+1-pos );
			move_cursor( pos-n-1 );
			pos--;
			n--;
			break;

		case 1: /* ^a */
go_home:
			move_cursor( -pos );
			pos = 0;
			break;

		case 5: /* ^e */
go_end:
			pos += emit_str( &buf[pos] );
			break;

		//case 68: /* left */
		//	drop = 1;
		case 2: /* ^b */
go_left:
			if( pos ) {
				move_cursor( -1 );
				pos--;
			}
			break;

		//case 67: /* right */
		//	drop = 1;
		case 6: /* ^f */
go_right:
			if( pos < n )
				emit( buf[pos++] );
			break;

		case 11: /* ^k */
			strcpy( ci->killbuf, &buf[pos] );
			clear( n-pos );
			n = pos;
			buf[pos] = 0;
			break;

		case 25: /* ^y */
			for( i=0; n < ci->ncol && ci->killbuf[i] ; i++, n++ ) {
				memmove( &buf[pos+1], &buf[pos], n+1-pos );
				buf[pos] = ci->killbuf[i];
				move_cursor( 1-emit_str(&buf[pos++]) );
			}
			break;

		case 9: /* TAB */
			for( i=0; n < ci->ncol && (!i || (pos%4)) ; i++, n++ ) {
				memmove( &buf[pos+1], &buf[pos], n+1-pos );
				buf[pos] = ' ';
				move_cursor( 1-emit_str(&buf[pos++]) );
			}
			break;

		case 12: /* ^l */
			move_cursor( -ci->ncol -pos );
			fword("print-prompt");
			move_cursor( pos-emit_str(buf) );
			break;

		//case 66: /* down */
		//	drop = 1;
		case 14: /* ^n */
go_down:
			if( !histind )
				break;
			history_get( ci, --histind - 1);
			clearline( pos, n );
			emit_str( buf );
			pos = n = strlen( buf );
			if( !histind && cur_added ) {
				cur_added = 0;
				history_remove( ci, 0 );
			}
			break;

		//case 65: /* up */
		//	drop = 1;
		case 16: /* ^p */
go_up:
			if( !histind && add_to_history(ci, ci->buf) ) {
				cur_added = 1;
				histind++;
			}
			if( history_get(ci, histind) )
				histind++;
			clearline( pos, n );
			emit_str( buf );
			pos = n = strlen( buf );
			break;
		}
		if( (unsigned int)ch < 32 )
			drop = 1;

		if( !drop && n < ci->ncol ) {
			memmove( &buf[pos+1], &buf[pos], n+1-pos );
			n++;
			buf[pos] = ch;
			move_cursor( 1-emit_str(&buf[pos++]) );
		}
	}

	/* we only get here if terminate? is non-zero; this should
         * only ever be done for a subordinate forth interpreter 
         * e.g. for debugging */

	/* Reset stack and terminate? */
	rstackcnt = dbgrstackcnt;
	feval("0 to terminate?");
}

NODE_METHODS( cmdline ) = {
	{ "open",       cmdline_open      },
	{ "close",      cmdline_close       },
	{ "cmdline",     cmdline_prompt      },
};

void
cmdline_init( void )
{
	REGISTER_NODE( cmdline );
}
