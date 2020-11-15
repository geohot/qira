/*
 *   Creation Date: <2004/08/28 18:38:22 greg>
 *   Time-stamp: <2004/08/28 18:38:22 greg>
 *
 *	<methods.c>
 *
 *	Misc device node methods
 *
 *   Copyright (C) 2004 Greg Watson
 *
 *   Based on MOL specific code which is
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
#include "libc/string.h"
// #include "libopenbios/ofmem.h"

/************************************************************************/
/*	stdout								*/
/************************************************************************/

DECLARE_NODE( video_stdout, INSTALL_OPEN, 0, "Tdisplay" );

/* ( addr len -- actual ) */
static void
stdout_write( void )
{
	int len = POP();
	char *addr = (char*)POP();

	printk( "%s", s );
	//vfd_draw_str( s );
        console_draw_fstr(addr, len);

	PUSH( len );
}

NODE_METHODS( video_stdout ) = {
	{ "write",	stdout_write	},
};


/************************************************************************/
/*	tty								*/
/************************************************************************/

DECLARE_NODE( tty, INSTALL_OPEN, 0, "/packages/terminal-emulator" );

/* ( addr len -- actual ) */
static void
tty_read( void )
{
	int ch, len = POP();
	char *p = (char*)POP();
	int ret=0;

	if( len > 0 ) {
		ret = 1;
		ch = getchar();
		if( ch >= 0 ) {
			*p = ch;
		} else {
			ret = 0;
		}
	}
	PUSH( ret );
}

/* ( addr len -- actual ) */
static void
tty_write( void )
{
	int i, len = POP();
	char *p = (char*)POP();
	for( i=0; i<len; i++ )
		putchar( *p++ );
	RET( len );
}

NODE_METHODS( tty ) = {
	{ "read",	tty_read	},
	{ "write",	tty_write	},
};

/************************************************************************/
/*	init								*/
/************************************************************************/

void
node_methods_init( void )
{
	REGISTER_NODE( video_stdout );
	REGISTER_NODE( tty );
}
